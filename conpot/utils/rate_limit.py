# Copyright (C) 2026  IronMonkey
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

"""Per-source token bucket for the connectionless protocol handlers.

Phase 2 step H10c. H10 put BACnet/IP (47808/udp) and EtherNet/IP (44818/udp)
on the internet with no ceiling of any kind. Both are single greenlets that
answer every datagram inline -- parse, build a reply, `sendto` -- so a flood
does not merely waste bandwidth, it pins the one CPU the droplet has and
starves every other protocol on the sensor, including the HTTP credential
bait the SIR-006-05 capture depends on. Both are also classic reflection
amplifiers (a 12-byte Who-Is draws a 25-byte I-Am; a 24-byte ListIdentity
draws ~60 bytes), so an unlimited responder is a weapon pointed at a third
party as well as a liability for us.

The TCP handlers are deliberately NOT wrapped: Conpot already bounds those
through its own connection limits, and a token bucket in front of a stream
protocol would cut sessions in half mid-exchange, which destroys exactly the
capture the sensor exists for.

Design notes:

- A bucket is created on first sight of a source and refilled continuously,
  so a scanner that sends one Who-Is a minute is never affected and a burst
  of `burst` datagrams always passes. Only sustained traffic above `rate` is
  dropped.
- Dropping is SILENT on the wire. An ICMP unreachable or an error PDU would
  tell a scanner exactly where the limit sits and how to stay under it, and
  would also make us the amplifier again.
- Logging is at most one line per source per minute, carrying the number of
  drops since the last line. A per-datagram log during a flood is the same
  denial of service in a different resource -- the disk on a node already at
  40% NVMe wear.
- The source table is LRU-bounded. Without that, a spoofed-source flood
  turns the limiter itself into the memory exhaustion it was added to
  prevent.
- `allow()` never raises. It sits on the receive path of a live honeypot: a
  bug here must degrade to "let the datagram through", never to a handler
  that stops answering.
"""

import logging
import time
from collections import OrderedDict

logger = logging.getLogger(__name__)

# Sustained datagrams per second per source IP, and the burst a source may
# spend at once. 10/s sustained with a 30 burst passes every legitimate
# scanner (`nmap --script bacnet-info` sends one datagram; a full BACnet
# object-list walk of this persona is a few dozen over several seconds) while
# capping one source at a few hundred bytes per second of reflected traffic.
DEFAULT_RATE = 10.0
DEFAULT_BURST = 30

# Distinct source addresses tracked at once. 4096 buckets is ~1 MB of Python
# objects and is far more than the sensor sees in a day.
DEFAULT_MAX_SOURCES = 4096

# Seconds between drop reports for one source.
REPORT_INTERVAL = 60.0


class _Bucket(object):
    __slots__ = ("tokens", "updated", "dropped", "reported")

    def __init__(self, tokens, now):
        self.tokens = tokens
        self.updated = now
        self.dropped = 0
        self.reported = now


class UdpRateLimiter(object):
    """Token bucket keyed by source address.

    :param rate: sustained datagrams per second per source. ``0`` (or any
        non-positive value) disables the limiter entirely, which is the
        documented way to turn it off in a template.
    :param burst: bucket depth in datagrams.
    :param max_sources: LRU ceiling on tracked sources.
    :param name: protocol name, used only in the log line.
    :param clock: injectable monotonic clock, so the tests do not sleep.
    """

    def __init__(
        self,
        rate=DEFAULT_RATE,
        burst=DEFAULT_BURST,
        max_sources=DEFAULT_MAX_SOURCES,
        name="udp",
        clock=time.monotonic,
    ):
        self.rate = float(rate)
        self.burst = float(burst)
        self.max_sources = int(max_sources)
        self.name = name
        self._clock = clock
        self._buckets = OrderedDict()

    @property
    def enabled(self):
        return self.rate > 0 and self.burst > 0

    @classmethod
    def from_dom(cls, dom, xpath_root, name):
        """Build a limiter from an optional ``<rate_limit>`` template block.

        ::

            <rate_limit>
                <datagrams_per_second>10</datagrams_per_second>
                <burst>30</burst>
            </rate_limit>

        Absent, malformed or partially specified, the code defaults above
        apply -- a template must not be able to remove the ceiling by
        accident, only on purpose with an explicit ``0``.
        """
        rate, burst = DEFAULT_RATE, DEFAULT_BURST
        try:
            found = dom.xpath("%s/rate_limit/datagrams_per_second/text()" % xpath_root)
            if found:
                rate = float(found[0])
            found = dom.xpath("%s/rate_limit/burst/text()" % xpath_root)
            if found:
                burst = float(found[0])
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "%s rate limit: unreadable <rate_limit> block (%s); using defaults",
                name,
                exc,
            )
            rate, burst = DEFAULT_RATE, DEFAULT_BURST
        limiter = cls(rate=rate, burst=burst, name=name)
        if limiter.enabled:
            logger.info(
                "%s rate limit: %.3g datagrams/s per source, burst %.3g",
                name,
                limiter.rate,
                limiter.burst,
            )
        else:
            logger.warning(
                "%s rate limit DISABLED by template; an internet flood will "
                "pin this sensor's CPU",
                name,
            )
        return limiter

    def allow(self, source):
        """True if this datagram may be handled, False if it must be dropped.

        `source` is anything hashable that identifies the peer; the callers
        pass the source IP, not (ip, port), so a scanner cannot buy extra
        budget by walking its own ephemeral ports.
        """
        if not self.enabled:
            return True
        try:
            return self._allow(source)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("%s rate limit failed open: %s", self.name, exc)
            return True

    def _allow(self, source):
        now = self._clock()
        bucket = self._buckets.get(source)
        if bucket is None:
            bucket = _Bucket(self.burst, now)
            self._buckets[source] = bucket
            self._evict(now)
        else:
            self._buckets.move_to_end(source)
            elapsed = now - bucket.updated
            if elapsed > 0:
                bucket.tokens = min(self.burst, bucket.tokens + elapsed * self.rate)
            bucket.updated = now

        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return True

        bucket.dropped += 1
        self._report(source, bucket, now)
        return False

    def _report(self, source, bucket, now):
        if now - bucket.reported < REPORT_INTERVAL:
            return
        logger.warning(
            "%s rate limit: dropped %d datagram(s) from %s in the last %.0fs "
            "(limit %.3g/s, burst %.3g)",
            self.name,
            bucket.dropped,
            source,
            now - bucket.reported,
            self.rate,
            self.burst,
        )
        bucket.dropped = 0
        bucket.reported = now

    def _evict(self, now):
        """Drop least-recently-seen sources once the table is full.

        Full buckets (a source that has spent nothing) are indistinguishable
        from a source we have never seen, so evicting them costs no accuracy.
        """
        while len(self._buckets) > self.max_sources:
            self._buckets.popitem(last=False)
