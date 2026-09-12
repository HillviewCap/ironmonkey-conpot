# Wire-level peek at an inbound SNMP message (Phase 2 step H10).
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
"""Decode the version and community of an SNMP datagram before pysnmp sees it.

Why this exists
---------------
``conpot_extension.log`` (``conpot_cmdrsp.py``) is the only place an SNMP
exchange reaches an ``AttackSession``, and by the time it runs the community
string the client actually put on the wire is gone:

* ``_getStateInfo`` can recover pysnmp's *mapped* ``securityName``
  (``"public-read"``), not the octets received; and
* a message whose community does not match is rejected inside the security
  model, so no responder runs at all and nothing whatsoever is logged.

The second point is the one that matters on an internet-exposed sensor. An
attacker walking ``private``, ``cisco``, ``admin`` or a vendor default -- the
SNMP form of the default-credential question -- would otherwise leave no
record of having tried, which reads downstream as "nobody touched SNMP"
rather than "somebody guessed twelve communities and missed".

This module decodes only the first three fields of an SNMP message straight
off the datagram::

    SEQUENCE { version INTEGER, community OCTET STRING, ... }

That is the whole of what v1 and v2c need. SNMPv3 replaces ``community`` with
a SEQUENCE (``msgGlobalData``), which this deliberately does not parse: the
USM user name is already available to the responder as ``securityName``.

Concurrency
-----------
``_current`` is a single module-level slot. That is safe because Conpot is
single-threaded gevent and exactly one greenlet -- ``GeventDispatcher.
run_dispatcher`` -- reads the SNMP socket: while a datagram is being processed
that greenlet is blocked inside the pysnmp callback, so a second SNMP datagram
cannot be in flight. A tarpit sleep yields to *other* protocols, not to another
iteration of that loop. Every read is nevertheless matched on the transport
address anyway, so a stale slot can never be attributed to a different peer.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

_TAG_SEQUENCE = 0x30
_TAG_INTEGER = 0x02
_TAG_OCTET_STRING = 0x04

# Community strings are short in practice. Anything longer is padding or an
# attempt to make us carry an unbounded attacker-supplied string into a STIX
# SCO, a JSONB column and an LLM prompt -- the same reasoning as the
# forwarder's `_MAX_HTTP_TEXT_CHARS` cap.
MAX_COMMUNITY_CHARS = 64

# Wire version number -> the name a human uses. 2 is not a legal wire value
# (SNMPv2c encodes as 1), so it is absent on purpose.
_VERSION_LABELS = {0: "1", 1: "2c", 3: "3"}

#: How many unanswered datagrams from one source IP get their own event per
#: minute. A community brute force is bounded by attacker effort, but the
#: sensor must not become a log amplifier for one, so the tail is dropped.
UNANSWERED_PER_IP_PER_MINUTE = 10


def version_label(wire_version):
    """``'1'`` / ``'2c'`` / ``'3'`` for a wire version number, else ``None``."""
    if wire_version is None:
        return None
    return _VERSION_LABELS.get(wire_version)


def _read_length(data, i):
    """BER definite length starting at ``data[i]``.

    Returns ``(length, next_index)``, or ``None`` when the encoding is not a
    definite length we are willing to honour. The indefinite form (``0x80``)
    and lengths needing more than four bytes are rejected rather than guessed:
    a datagram that uses either is not an SNMP message this device would have
    answered, and inventing a length is how a peek turns into a parser bug.
    """
    if i >= len(data):
        return None
    first = data[i]
    i += 1
    if first < 0x80:
        return first, i
    count = first & 0x7F
    if count == 0 or count > 4 or i + count > len(data):
        return None
    return int.from_bytes(data[i : i + count], "big"), i + count


def peek(data):
    """``(version, community)`` for an SNMP datagram.

    Either element is ``None`` when it cannot be read. Never raises: a
    truncated or malformed datagram is ordinary honeypot traffic, not an
    exceptional case, and a peek failure must never stop the SNMP engine from
    processing the message normally.
    """
    try:
        if not data or data[0] != _TAG_SEQUENCE:
            return None, None
        read = _read_length(data, 1)
        if read is None:
            return None, None
        _, i = read

        if i >= len(data) or data[i] != _TAG_INTEGER:
            return None, None
        read = _read_length(data, i + 1)
        if read is None:
            return None, None
        vlen, i = read
        if vlen < 1 or vlen > 4 or i + vlen > len(data):
            return None, None
        version = int.from_bytes(data[i : i + vlen], "big")
        i += vlen
        if version not in _VERSION_LABELS:
            return None, None
        if version == 3:
            # msgGlobalData is a SEQUENCE here, not a community OCTET STRING.
            return version, None

        if i >= len(data) or data[i] != _TAG_OCTET_STRING:
            return version, None
        read = _read_length(data, i + 1)
        if read is None:
            return version, None
        clen, i = read
        if i + clen > len(data):
            return version, None
        raw = bytes(data[i : i + clen])
        return version, raw.decode("utf-8", errors="replace")[:MAX_COMMUNITY_CHARS]
    except Exception:  # pragma: no cover - defensive; a peek must never fail
        return None, None


@dataclass
class Peeked:
    """One datagram's peeked header, plus whether a responder logged it."""

    addr: tuple | None
    version: int | None
    community: str | None
    answered: bool = False


_current: Peeked | None = None


def _normalize(addr):
    if not addr:
        return None
    try:
        return tuple(addr[:2])
    except TypeError:
        return None


def observe(data, addr) -> Peeked:
    """Peek ``data`` and make the result the current datagram's context."""
    global _current
    version, community = peek(data)
    _current = Peeked(addr=_normalize(addr), version=version, community=community)
    return _current


def current_for(addr) -> Peeked | None:
    """The peek for ``addr``, or ``None``.

    Address-matched so that a slot left over from a previous datagram -- or
    one never set at all, as in a unit test that calls the responder directly
    -- can never be attributed to the wrong peer.
    """
    cur = _current
    if cur is None:
        return None
    normalized = _normalize(addr)
    if normalized is None or cur.addr != normalized:
        return None
    return cur


def clear():
    """Drop the current datagram's context."""
    global _current
    _current = None


class UnansweredBudget:
    """Per-source-IP, per-minute cap on unanswered-datagram events.

    Same epoch-minute shape as ``DatabusMediator.update_evasion_table``: the
    whole table is discarded when the minute rolls over, so it cannot grow
    without bound no matter how many source addresses are seen.
    """

    def __init__(self, limit=UNANSWERED_PER_IP_PER_MINUTE):
        self.limit = limit
        self._minute = None
        self._counts = {}

    def allow(self, source_ip, now=None):
        now = now or datetime.utcnow()
        minute = (now.year, now.month, now.day, now.hour, now.minute)
        if minute != self._minute:
            self._minute = minute
            self._counts = {}
        count = self._counts.get(source_ip, 0)
        if count >= self.limit:
            return False
        self._counts[source_ip] = count + 1
        return True
