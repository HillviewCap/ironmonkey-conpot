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

"""Per-source UDP token bucket (Phase 2 step H10c).

H10 opened 47808/udp and 44818/udp on an internet-exposed droplet with no
ceiling at all. Both handlers answer inline in one greenlet and both amplify
(a 12-byte Who-Is draws a 25-byte I-Am), so an unlimited responder pins the
sensor's only CPU and points a reflector at a third party.

The clock is injected throughout: a test that sleeps to prove a rate limit is
a test that is slow when it passes and flaky when it fails.
"""

import logging
import os
import unittest

from lxml import etree

import conpot
from conpot.utils import rate_limit
from conpot.utils.rate_limit import UdpRateLimiter


class FakeClock(object):
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class TestUdpRateLimiter(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()

    def limiter(self, **kwargs):
        kwargs.setdefault("rate", 10.0)
        kwargs.setdefault("burst", 5)
        return UdpRateLimiter(name="test", clock=self.clock, **kwargs)

    def test_a_burst_passes_and_the_next_datagram_is_dropped(self):
        limiter = self.limiter(burst=5)
        self.assertEqual([True] * 5, [limiter.allow("1.2.3.4") for _ in range(5)])
        self.assertFalse(limiter.allow("1.2.3.4"))

    def test_the_bucket_refills_over_time(self):
        limiter = self.limiter(rate=10.0, burst=5)
        for _ in range(5):
            limiter.allow("1.2.3.4")
        self.assertFalse(limiter.allow("1.2.3.4"))
        self.clock.advance(0.5)  # 10/s x 0.5s = 5 tokens
        self.assertEqual([True] * 5, [limiter.allow("1.2.3.4") for _ in range(5)])
        self.assertFalse(limiter.allow("1.2.3.4"))

    def test_the_bucket_never_refills_past_the_burst(self):
        limiter = self.limiter(rate=10.0, burst=5)
        limiter.allow("1.2.3.4")
        self.clock.advance(3600)
        self.assertEqual([True] * 5, [limiter.allow("1.2.3.4") for _ in range(5)])
        self.assertFalse(limiter.allow("1.2.3.4"))

    def test_sources_do_not_spend_each_others_budget(self):
        """One scanner must not be able to silence the sensor for everyone
        else -- that would turn the mitigation into the outage."""
        limiter = self.limiter(burst=3)
        for _ in range(3):
            self.assertTrue(limiter.allow("1.2.3.4"))
        self.assertFalse(limiter.allow("1.2.3.4"))
        self.assertTrue(limiter.allow("5.6.7.8"))

    def test_a_slow_scanner_is_never_touched(self):
        limiter = self.limiter(rate=10.0, burst=30)
        for _ in range(200):
            self.clock.advance(1.0)
            self.assertTrue(limiter.allow("1.2.3.4"))

    def test_rate_zero_disables_the_limiter_entirely(self):
        limiter = self.limiter(rate=0)
        self.assertFalse(limiter.enabled)
        self.assertTrue(all(limiter.allow("1.2.3.4") for _ in range(1000)))

    def test_the_source_table_is_bounded(self):
        """A spoofed-source flood must not turn the limiter into the memory
        exhaustion it was added to prevent."""
        limiter = self.limiter(max_sources=16)
        for i in range(1000):
            limiter.allow("10.0.0.%d" % i)
        self.assertLessEqual(len(limiter._buckets), 16)

    def test_an_active_source_survives_eviction(self):
        limiter = self.limiter(burst=2, max_sources=4)
        limiter.allow("1.2.3.4")
        limiter.allow("1.2.3.4")
        for i in range(3):
            limiter.allow("10.0.0.%d" % i)
            limiter.allow("1.2.3.4")  # keeps it most-recently-used
        self.assertIn("1.2.3.4", limiter._buckets)

    def test_a_flood_logs_at_most_one_line_per_source_per_minute(self):
        """Logging every drop is the same denial of service in a different
        resource: the disk of a node already at 40% NVMe wear."""
        limiter = self.limiter(rate=1.0, burst=1)
        limiter.allow("1.2.3.4")
        with self.assertLogs(rate_limit.logger, level=logging.WARNING) as captured:
            # First drop is inside the report interval of the bucket's
            # creation, so it stays quiet; after a minute exactly one line.
            for _ in range(500):
                limiter.allow("1.2.3.4")
            self.clock.advance(rate_limit.REPORT_INTERVAL + 1)
            for _ in range(500):
                limiter.allow("1.2.3.4")
        self.assertEqual(1, len(captured.output), captured.output)
        self.assertIn("1.2.3.4", captured.output[0])

    def test_allow_fails_open(self):
        """This sits on the receive path of a live honeypot. A bug here must
        degrade to "handle the datagram", never to a silent sensor."""

        def explode():
            raise RuntimeError("clock is on fire")

        limiter = UdpRateLimiter(rate=1.0, burst=1, name="test", clock=explode)
        self.assertTrue(limiter.allow("1.2.3.4"))


class TestRateLimitTemplateConfig(unittest.TestCase):
    @staticmethod
    def _dom(body):
        return etree.ElementTree(etree.fromstring(body))

    def test_defaults_apply_when_the_block_is_absent(self):
        limiter = UdpRateLimiter.from_dom(
            self._dom(b"<bacnet><device_info/></bacnet>"), "//bacnet", "bacnet"
        )
        self.assertEqual(rate_limit.DEFAULT_RATE, limiter.rate)
        self.assertEqual(rate_limit.DEFAULT_BURST, limiter.burst)

    def test_a_template_can_set_both_knobs(self):
        limiter = UdpRateLimiter.from_dom(
            self._dom(
                b"<enip><rate_limit><datagrams_per_second>2.5"
                b"</datagrams_per_second><burst>7</burst></rate_limit></enip>"
            ),
            "//enip",
            "enip",
        )
        self.assertEqual(2.5, limiter.rate)
        self.assertEqual(7, limiter.burst)

    def test_a_half_specified_block_keeps_the_other_default(self):
        limiter = UdpRateLimiter.from_dom(
            self._dom(b"<enip><rate_limit><burst>7</burst></rate_limit></enip>"),
            "//enip",
            "enip",
        )
        self.assertEqual(rate_limit.DEFAULT_RATE, limiter.rate)
        self.assertEqual(7, limiter.burst)

    def test_an_unparseable_value_falls_back_to_the_defaults(self):
        """A typo must not be able to remove the ceiling; only an explicit
        0 does that."""
        limiter = UdpRateLimiter.from_dom(
            self._dom(
                b"<enip><rate_limit><datagrams_per_second>fast"
                b"</datagrams_per_second></rate_limit></enip>"
            ),
            "//enip",
            "enip",
        )
        self.assertEqual(rate_limit.DEFAULT_RATE, limiter.rate)
        self.assertTrue(limiter.enabled)

    def test_the_shipped_templates_parse_and_are_limited(self):
        """Every persona that exposes a UDP OT protocol comes out limited,
        whether or not its template mentions the block."""
        conpot_dir = os.path.dirname(conpot.__file__)
        for template, protocol, root in (
            ("s7-315-substation", "bacnet", "//bacnet"),
            ("s7-315-substation", "enip", "//enip"),
            ("default", "bacnet", "//bacnet"),
        ):
            path = os.path.join(
                conpot_dir, "templates", template, protocol, "%s.xml" % protocol
            )
            if not os.path.exists(path):
                continue
            limiter = UdpRateLimiter.from_dom(etree.parse(path), root, protocol)
            self.assertTrue(
                limiter.enabled, "%s/%s came out unlimited" % (template, protocol)
            )


if __name__ == "__main__":
    unittest.main()
