# Copyright (C) 2026  IronMonkey
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
"""Unit tests for the SNMP wire peek (Phase 2 step H10).

No server and no socket: these exercise the BER decode and the per-IP budget
directly, so a regression in either points at this file rather than at a
timing-dependent integration test.
"""

import datetime
import unittest

from pyasn1.codec.ber import encoder
from pysnmp.proto import api

from conpot.protocols.snmp import message_peek


def _v1arch_get(version, community, oid="1.3.6.1.2.1.1.1.0"):
    """A real SNMPv1 or v2c GetRequest, encoded by pysnmp."""
    module = api.PROTOCOL_MODULES[version]
    pdu = module.GetRequestPDU()
    module.apiPDU.set_defaults(pdu)
    module.apiPDU.set_varbinds(pdu, ((oid, module.Null("")),))
    message = module.Message()
    module.apiMessage.set_defaults(message)
    module.apiMessage.set_community(message, community)
    module.apiMessage.set_pdu(message, pdu)
    return encoder.encode(message)


class TestSnmpMessagePeek(unittest.TestCase):
    def test_v2c_community_is_read_off_the_wire(self):
        version, community = message_peek.peek(
            _v1arch_get(api.SNMP_VERSION_2C, "public")
        )
        self.assertEqual(1, version)
        self.assertEqual("public", community)
        self.assertEqual("2c", message_peek.version_label(version))

    def test_v1_community_is_read_off_the_wire(self):
        version, community = message_peek.peek(
            _v1arch_get(api.SNMP_VERSION_1, "private")
        )
        self.assertEqual(0, version)
        self.assertEqual("private", community)
        self.assertEqual("1", message_peek.version_label(version))

    def test_long_community_survives_and_is_capped(self):
        """A community is attacker-supplied text and rides into a JSONB column.

        The cap has to hold here rather than downstream, and the value must
        still be reported -- an over-long community is a probe, not a reason
        to report nothing.
        """
        long_community = "A" * (message_peek.MAX_COMMUNITY_CHARS + 50)
        _, community = message_peek.peek(
            _v1arch_get(api.SNMP_VERSION_2C, long_community)
        )
        self.assertEqual(message_peek.MAX_COMMUNITY_CHARS, len(community))

    def test_v3_reports_its_version_and_no_community(self):
        """v3 puts a SEQUENCE where v1/v2c put the community octets.

        Reporting the third field as a community would publish an SNMPv3
        header fragment as though an attacker had typed it.
        """
        # SEQUENCE { INTEGER 3, SEQUENCE { ... } } -- the start of any v3 msg.
        v3 = bytes([0x30, 0x0A, 0x02, 0x01, 0x03, 0x30, 0x05, 0x02, 0x03, 0x01, 0x02, 0x03])
        version, community = message_peek.peek(v3)
        self.assertEqual(3, version)
        self.assertIsNone(community)

    def test_garbage_never_raises_and_invents_no_community(self):
        """Malformed datagrams are ordinary honeypot traffic, not a fault.

        Every case here must come back with no community. Returning a
        plausible-looking string from a truncated frame would put bytes an
        attacker never sent in front of an analyst.
        """
        for payload in (
            b"",
            b"\x00",
            b"\x30",
            b"\x30\x80\x02\x01\x01",  # indefinite length: rejected, not guessed
            b"\x30\x05\x02\x01",  # truncated mid-integer
            b"\x30\x06\x02\x01\x01\x04\x7f",  # community length past the end
            b"\x30\x06\x02\x01\x01\x02\x01\x05",  # INTEGER where community goes
            b"GET / HTTP/1.1\r\n\r\n",
            bytes(range(256)),
        ):
            version, community = message_peek.peek(payload)
            self.assertIsNone(community, payload)

    def test_unknown_version_is_rejected(self):
        # SEQUENCE { INTEGER 7, ... } -- 7 is not an SNMP version.
        payload = bytes([0x30, 0x06, 0x02, 0x01, 0x07, 0x04, 0x01, 0x41])
        self.assertEqual((None, None), message_peek.peek(payload))

    def test_current_is_matched_on_the_peer_address(self):
        """A slot left over from another peer must never be handed out."""
        message_peek.clear()
        self.assertIsNone(message_peek.current_for(("10.0.0.1", 1234)))

        message_peek.observe(_v1arch_get(api.SNMP_VERSION_2C, "public"),
                             ("10.0.0.1", 1234))
        self.assertIsNotNone(message_peek.current_for(("10.0.0.1", 1234)))
        self.assertIsNone(message_peek.current_for(("10.0.0.2", 1234)))
        message_peek.clear()
        self.assertIsNone(message_peek.current_for(("10.0.0.1", 1234)))

    def test_unanswered_budget_caps_per_ip_per_minute(self):
        budget = message_peek.UnansweredBudget(limit=3)
        now = datetime.datetime(2026, 9, 12, 6, 30, 0)
        self.assertEqual(
            [True, True, True, False, False],
            [budget.allow("203.0.113.9", now=now) for _ in range(5)],
        )
        # A different source has its own budget within the same minute.
        self.assertTrue(budget.allow("203.0.113.10", now=now))
        # The next minute discards the whole table rather than ageing entries.
        self.assertTrue(budget.allow("203.0.113.9", now=now + datetime.timedelta(minutes=1)))
