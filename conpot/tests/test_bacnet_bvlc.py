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

"""BACnet/IP link-layer framing (Phase 2 step H10c).

H10 put a BACnet persona on 47808/udp and taught `indication()` to record the
service an attacker asked for. Verification against the deployed New York
sensor on 2026-09-12 then found that real-world capture on it was ~0: the
server decoded each datagram as a BARE APDU, and nothing on a BACnet/IP
network sends one. `nmap --script bacnet-info`, every commercial scanner and
a hand-built `81 0a ... 01 04 ...` ReadProperty all hit `DecodingError` on
byte 0, leaving a session with a `NEW_CONNECTION` event and nothing else --
which never becomes a `honeypot_sessions` row.

Every fixture here is built with **bacpypes' own encoder**, so these tests
check `conpot.protocols.bacnet.bvlc` against a real BACnet stack rather than
against itself. `bvlc` deliberately imports no bacpypes; if it agreed with
bacpypes only because it shared its code, this file would prove nothing.
"""

from gevent import monkey

monkey.patch_all()

import unittest

from gevent import socket

from bacpypes.apdu import (
    APDU,
    IAmRequest,
    ReadPropertyACK,
    ReadPropertyRequest,
    WhoIsRequest,
)
from bacpypes.bvll import BVLPDU
from bacpypes.constructeddata import Any
from bacpypes.npdu import NPDU
from bacpypes.pdu import PDU, GlobalBroadcast, RemoteStation
from bacpypes.primitivedata import CharacterString, Real

import conpot.core as conpot_core
from conpot.protocols.bacnet import bacnet_server, bvlc
from conpot.utils.greenlet import spawn_test_server, teardown_test_server

TEMPLATE = "s7-315-substation"
DEVICE_INSTANCE = 1101
DEVICE_NAME = "SUBSTATION-01-BMS"

# BACnet property identifiers used below, by number, the way a scanner sends
# them: 77 objectName, 85 presentValue.
OBJECT_NAME = 77
PRESENT_VALUE = 85


# ── Fixture builders, all bacpypes ───────────────────────────────────────────


def encode_apdu(request):
    """The bare APDU bytes of a bacpypes request."""
    apdu = APDU()
    request.encode(apdu)
    pdu = PDU()
    apdu.encode(pdu)
    return bytes(pdu.pduData)


def encode_npdu(apdu_bytes, source=None, expecting_reply=0):
    """Wrap an APDU in an NPDU, optionally with a source specifier."""
    npdu = NPDU(apdu_bytes)
    npdu.npduVersion = 1
    npdu.npduControl = None
    npdu.npduDADR = None
    npdu.npduSADR = source
    npdu.npduHopCount = None
    npdu.npduNetMessage = None
    npdu.npduVendorID = None
    npdu.npduExpectingReply = expecting_reply
    npdu.npduNetworkPriority = 0
    out = PDU()
    npdu.encode(out)
    return bytes(out.pduData)


def encode_bvlc(payload, function):
    bvlpdu = BVLPDU(payload)
    bvlpdu.bvlciFunction = function
    bvlpdu.bvlciLength = len(payload) + 4
    out = PDU()
    bvlpdu.encode(out)
    return bytes(out.pduData)


def frame(request, function=bvlc.ORIGINAL_UNICAST_NPDU, source=None, expecting_reply=0):
    """A full BACnet/IP datagram exactly as a real client emits it."""
    return encode_bvlc(
        encode_npdu(encode_apdu(request), source, expecting_reply), function
    )


def split_bvlc(data):
    """Decode a datagram back into (function, apdu_bytes) with bacpypes."""
    pdu = PDU()
    pdu.pduData = bytearray(data)
    bvlpdu = BVLPDU()
    bvlpdu.decode(pdu)

    inner = PDU()
    inner.pduData = bytearray(bvlpdu.pduData)
    npdu = NPDU()
    npdu.decode(inner)
    return bvlpdu.bvlciFunction, bytes(npdu.pduData)


# ── The codec on its own ─────────────────────────────────────────────────────


class TestBvlcCodec(unittest.TestCase):
    def test_a_bare_apdu_is_passed_through_unframed(self):
        """Conpot's own BACnet tests have always sent a bare APDU.

        Keeping that path is not nostalgia: it is the only way the framed and
        unframed cases stay distinguishable, since a reply must be wrapped
        exactly when the request was.
        """
        raw = encode_apdu(WhoIsRequest())
        decoded = bvlc.unwrap(raw)
        self.assertEqual(raw, decoded.apdu)
        self.assertIsNone(decoded.link)
        self.assertIsNone(decoded.reply)

    def test_original_unicast_npdu_yields_the_apdu(self):
        request = ReadPropertyRequest(
            objectIdentifier=("analogInput", 12), propertyIdentifier=PRESENT_VALUE
        )
        request.apduMaxResp = 1024
        request.apduInvokeID = 7
        raw = encode_apdu(request)
        decoded = bvlc.unwrap(frame(request))
        self.assertEqual(raw, decoded.apdu)
        self.assertEqual(bvlc.ORIGINAL_UNICAST_NPDU, decoded.link.function)
        self.assertFalse(decoded.link.is_broadcast)
        self.assertEqual("OriginalUnicastNPDU", decoded.service)

    def test_original_broadcast_npdu_is_marked_broadcast(self):
        decoded = bvlc.unwrap(
            frame(WhoIsRequest(), function=bvlc.ORIGINAL_BROADCAST_NPDU)
        )
        self.assertEqual(encode_apdu(WhoIsRequest()), decoded.apdu)
        self.assertTrue(decoded.link.is_broadcast)

    def test_a_routed_request_keeps_the_source_network_and_address(self):
        """Without SNET/SADR the reply cannot be addressed back through the
        router the request came through, and a routed client hears nothing."""
        decoded = bvlc.unwrap(
            frame(
                WhoIsRequest(),
                function=bvlc.ORIGINAL_BROADCAST_NPDU,
                source=RemoteStation(2001, 5),
            )
        )
        self.assertEqual(2001, decoded.link.source_network)
        self.assertEqual(b"\x05", decoded.link.source_address)

    def test_expecting_reply_is_carried(self):
        decoded = bvlc.unwrap(frame(WhoIsRequest(), expecting_reply=1))
        self.assertTrue(decoded.link.expecting_reply)

    def test_forwarded_npdu_skips_the_originating_address(self):
        inner = encode_npdu(encode_apdu(WhoIsRequest()))
        origin = bytes([10, 0, 0, 7, 0xBA, 0xC0])  # 10.0.0.7:47808
        decoded = bvlc.unwrap(
            encode_bvlc(origin + inner, bvlc.FORWARDED_NPDU)
        )
        self.assertEqual(encode_apdu(WhoIsRequest()), decoded.apdu)
        self.assertEqual("ForwardedNPDU", decoded.service)

    def test_a_truncated_forwarded_npdu_is_rejected(self):
        with self.assertRaises(bvlc.BvlcError):
            bvlc.unwrap(encode_bvlc(b"\x0a\x00\x00", bvlc.FORWARDED_NPDU))

    def test_register_foreign_device_is_refused_with_a_nak(self):
        """Foreign-device registration is how an attacker gets a BACnet
        internetwork to forward ITS broadcast traffic. The emulated device is
        a field controller, not a BBMD, so the truthful answer and the safe
        answer are the same one."""
        decoded = bvlc.unwrap(
            encode_bvlc(b"\x00\x3c", bvlc.REGISTER_FOREIGN_DEVICE)
        )
        self.assertIsNone(decoded.apdu)
        self.assertEqual(bvlc.build_result(0x0030), decoded.reply)
        self.assertEqual("RegisterForeignDevice", decoded.service)

    def test_every_bbmd_function_gets_its_own_result_code(self):
        for function, code in (
            (bvlc.WRITE_BDT, 0x0010),
            (bvlc.READ_BDT, 0x0020),
            (bvlc.REGISTER_FOREIGN_DEVICE, 0x0030),
            (bvlc.READ_FDT, 0x0040),
            (bvlc.DELETE_FDT_ENTRY, 0x0050),
            (bvlc.DISTRIBUTE_BROADCAST_TO_NETWORK, 0x0060),
        ):
            decoded = bvlc.unwrap(encode_bvlc(b"", function))
            self.assertEqual(
                bvlc.build_result(code), decoded.reply, "function 0x%02x" % function
            )

    def test_a_result_datagram_draws_no_answer(self):
        """A Result is a response to a request we never made. Answering it
        would confirm the listener and hand a scanner a reflection target."""
        decoded = bvlc.unwrap(bvlc.build_result(bvlc.RESULT_SUCCESS))
        self.assertIsNone(decoded.apdu)
        self.assertIsNone(decoded.reply)
        self.assertEqual("Result", decoded.service)

    def test_a_network_layer_message_is_named_but_not_answered(self):
        """Who-Is-Router-To-Network and friends are NSDUs, not APDUs. Worth
        recording -- it is how a scanner maps the internetwork -- but a field
        controller has nothing to say back."""
        body = bytes([0x01, 0x80, 0x00])  # version, net-message, message type 0
        decoded = bvlc.unwrap(encode_bvlc(body, bvlc.ORIGINAL_BROADCAST_NPDU))
        self.assertIsNone(decoded.apdu)
        self.assertIsNone(decoded.reply)
        self.assertIsNotNone(decoded.link)
        self.assertEqual("NetworkLayerMessage", decoded.service)

    def test_a_length_that_does_not_fit_the_datagram_is_rejected(self):
        good = frame(WhoIsRequest())
        lying = good[:2] + (len(good) + 40).to_bytes(2, "big") + good[4:]
        with self.assertRaises(bvlc.BvlcError):
            bvlc.unwrap(lying)

    def test_a_short_or_absurd_npdu_is_rejected_not_raised_raw(self):
        for body in (b"", b"\x01", b"\x02\x00", b"\x01\x20\x00"):
            with self.assertRaises(bvlc.BvlcError):
                bvlc.unwrap(encode_bvlc(body, bvlc.ORIGINAL_UNICAST_NPDU))

    def test_wrap_produces_a_datagram_bacpypes_can_decode(self):
        i_am = IAmRequest()
        i_am.pduDestination = GlobalBroadcast()
        i_am.iAmDeviceIdentifier = DEVICE_INSTANCE
        i_am.maxAPDULengthAccepted = 1476
        i_am.segmentationSupported = "segmentedBoth"
        i_am.vendorID = 7
        apdu_bytes = encode_apdu(i_am)

        link = bvlc.unwrap(
            frame(WhoIsRequest(), function=bvlc.ORIGINAL_BROADCAST_NPDU)
        ).link
        wire = bvlc.wrap(apdu_bytes, link, broadcast=True)

        function, decoded_apdu = split_bvlc(wire)
        self.assertEqual(bvlc.ORIGINAL_BROADCAST_NPDU, function)
        self.assertEqual(apdu_bytes, decoded_apdu)

    def test_wrap_uses_the_unicast_function_for_a_directed_reply(self):
        link = bvlc.unwrap(frame(WhoIsRequest())).link
        function, _ = split_bvlc(bvlc.wrap(b"\x10\x08", link, broadcast=False))
        self.assertEqual(bvlc.ORIGINAL_UNICAST_NPDU, function)

    def test_wrap_addresses_a_routed_reply_back_the_way_it_came(self):
        link = bvlc.unwrap(
            frame(WhoIsRequest(), source=RemoteStation(2001, 5))
        ).link
        wire = bvlc.wrap(b"\x10\x08", link)

        pdu = PDU()
        pdu.pduData = bytearray(wire)
        bvlpdu = BVLPDU()
        bvlpdu.decode(pdu)
        inner = PDU()
        inner.pduData = bytearray(bvlpdu.pduData)
        npdu = NPDU()
        npdu.decode(inner)

        self.assertEqual(RemoteStation(2001, 5), npdu.npduDADR)
        self.assertEqual(255, npdu.npduHopCount)
        self.assertEqual(b"\x10\x08", bytes(npdu.pduData))

    def test_wrap_without_a_link_returns_the_bare_apdu(self):
        self.assertEqual(b"\x10\x08", bvlc.wrap(b"\x10\x08", None))


# ── The server, over a real socket, with real framing ────────────────────────


class TestFramedBacnetServer(unittest.TestCase):
    """The persona answering datagrams shaped the way the internet sends them."""

    def setUp(self):
        self.bacnet_server, self.greenlet = spawn_test_server(
            bacnet_server.BacnetServer, TEMPLATE, "bacnet"
        )
        self.address = (self.bacnet_server.host, self.bacnet_server.port)
        self._drain()

    def tearDown(self):
        teardown_test_server(self.bacnet_server, self.greenlet)

    @staticmethod
    def _drain():
        queue = conpot_core.get_sessionManager().log_queue
        while not queue.empty():
            queue.get_nowait()

    @staticmethod
    def _requests():
        queue = conpot_core.get_sessionManager().log_queue
        out = []
        while not queue.empty():
            data = queue.get_nowait()["data"]
            if "request" in data:
                out.append(data["request"])
        return out

    def _exchange(self, datagram):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        try:
            s.sendto(datagram, self.address)
            try:
                return s.recvfrom(1024)[0]
            except Exception:
                return None
        finally:
            s.close()

    # ── Who-Is / I-Am ────────────────────────────────────────────────────

    def test_a_framed_who_is_is_answered_with_a_framed_i_am(self):
        reply = self._exchange(
            frame(WhoIsRequest(), function=bvlc.ORIGINAL_BROADCAST_NPDU)
        )
        self.assertIsNotNone(reply, "a standards-framed Who-Is drew no I-Am")

        function, apdu_bytes = split_bvlc(reply)
        self.assertEqual(
            bvlc.ORIGINAL_BROADCAST_NPDU,
            function,
            "I-Am is a broadcast service and must keep its BVLL function",
        )

        expected = IAmRequest()
        expected.pduDestination = GlobalBroadcast()
        expected.iAmDeviceIdentifier = DEVICE_INSTANCE
        expected.maxAPDULengthAccepted = 1476
        expected.segmentationSupported = "segmentedBoth"
        expected.vendorID = 7
        self.assertEqual(encode_apdu(expected), apdu_bytes)

    # ── ReadProperty ─────────────────────────────────────────────────────

    def test_a_framed_read_property_is_answered_unicast(self):
        request = ReadPropertyRequest(
            objectIdentifier=("analogInput", 12), propertyIdentifier=PRESENT_VALUE
        )
        request.apduMaxResp = 1024
        request.apduInvokeID = 101
        reply = self._exchange(frame(request, expecting_reply=1))
        self.assertIsNotNone(reply, "a standards-framed ReadProperty drew no ACK")

        function, apdu_bytes = split_bvlc(reply)
        self.assertEqual(bvlc.ORIGINAL_UNICAST_NPDU, function)

        expected = ReadPropertyACK()
        expected.apduInvokeID = 101
        expected.objectIdentifier = ("analogInput", 12)
        expected.propertyIdentifier = PRESENT_VALUE
        expected.propertyValue = Any(Real(24.5))
        self.assertEqual(encode_apdu(expected), apdu_bytes)

    def test_the_device_objects_name_is_readable(self):
        """The single most common BACnet fingerprint request.

        `nmap --script bacnet-info` reads the DEVICE object's objectName,
        vendorName and modelName. Three separate defects made that time out
        while the analog and binary points answered: the device object was
        never registered in `objectIdentifier` (the superclass constructor
        wipes the dict it was written into), `objectList.value[2:]` skipped
        it anyway, and `ast.literal_eval("SUBSTATION-01-BMS")` raised
        ValueError straight out of the datagram handler.
        """
        request = ReadPropertyRequest(
            objectIdentifier=("device", DEVICE_INSTANCE),
            propertyIdentifier=OBJECT_NAME,
        )
        request.apduMaxResp = 1024
        request.apduInvokeID = 55
        reply = self._exchange(frame(request, expecting_reply=1))
        self.assertIsNotNone(reply, "device objectName still draws no answer")

        _, apdu_bytes = split_bvlc(reply)

        expected = ReadPropertyACK()
        expected.apduInvokeID = 55
        expected.objectIdentifier = ("device", DEVICE_INSTANCE)
        expected.propertyIdentifier = OBJECT_NAME
        expected.propertyValue = Any(CharacterString(DEVICE_NAME))
        self.assertEqual(encode_apdu(expected), apdu_bytes)

    def test_the_device_object_name_also_answers_a_bare_apdu(self):
        """Same fix, unframed, so a regression in either path is separable."""
        request = ReadPropertyRequest(
            objectIdentifier=("device", DEVICE_INSTANCE),
            propertyIdentifier=OBJECT_NAME,
        )
        request.apduMaxResp = 1024
        request.apduInvokeID = 56
        self.assertIsNotNone(self._exchange(encode_apdu(request)))

    def test_an_object_name_read_of_a_point_answers_too(self):
        request = ReadPropertyRequest(
            objectIdentifier=("binaryInput", 15), propertyIdentifier=OBJECT_NAME
        )
        request.apduMaxResp = 1024
        request.apduInvokeID = 57
        reply = self._exchange(frame(request))
        self.assertIsNotNone(reply)
        _, apdu_bytes = split_bvlc(reply)

        expected = ReadPropertyACK()
        expected.apduInvokeID = 57
        expected.objectIdentifier = ("binaryInput", 15)
        expected.propertyIdentifier = OBJECT_NAME
        expected.propertyValue = Any(CharacterString("BI_DOOR_CONTACT"))
        self.assertEqual(encode_apdu(expected), apdu_bytes)

    def test_an_unknown_object_gets_an_error_not_the_previous_clients_answer(self):
        """`_response` is instance state that outlives the request that built
        it. An unmatched object used to leave it untouched, so the server
        re-sent whatever it had answered the previous caller."""
        first = ReadPropertyRequest(
            objectIdentifier=("analogInput", 12), propertyIdentifier=PRESENT_VALUE
        )
        first.apduMaxResp = 1024
        first.apduInvokeID = 1
        good = self._exchange(frame(first))
        self.assertIsNotNone(good)

        second = ReadPropertyRequest(
            objectIdentifier=("analogInput", 999), propertyIdentifier=PRESENT_VALUE
        )
        second.apduMaxResp = 1024
        second.apduInvokeID = 2
        reply = self._exchange(frame(second))
        self.assertIsNotNone(reply, "an unknown object drew no reply at all")
        _, apdu_bytes = split_bvlc(reply)
        self.assertNotEqual(
            split_bvlc(good)[1],
            apdu_bytes,
            "the previous client's ReadProperty ACK was re-sent",
        )
        self.assertEqual(0x50, apdu_bytes[0] & 0xF0, "expected an ErrorPDU")

    # ── What reaches the session, and therefore the forwarder ────────────

    def test_a_framed_request_records_what_the_h10b_normaliser_reads(self):
        """The point of the whole step.

        A framed request used to produce a NEW_CONNECTION-only session, which
        never becomes a `honeypot_sessions` row. These four keys are exactly
        what the forwarder's `_BACNET_FIELDS` renames into `protocol_data`.
        """
        request = ReadPropertyRequest(
            objectIdentifier=("analogInput", 13), propertyIdentifier=PRESENT_VALUE
        )
        request.apduMaxResp = 1024
        request.apduInvokeID = 12
        self._exchange(frame(request))

        requests = self._requests()
        self.assertTrue(requests, "a framed ReadProperty reached no session event")
        self.assertEqual("ReadPropertyRequest", requests[0]["service"])
        self.assertEqual("ConfirmedRequestPDU", requests[0]["pdu_type"])
        self.assertEqual("analogInput", requests[0]["object_type"])
        self.assertEqual(13, requests[0]["object_instance"])
        self.assertEqual("presentValue", requests[0]["property"])

    def test_a_framed_who_is_is_recorded(self):
        self._exchange(frame(WhoIsRequest(), function=bvlc.ORIGINAL_BROADCAST_NPDU))
        requests = self._requests()
        self.assertTrue(requests)
        self.assertEqual("WhoIsRequest", requests[0]["service"])
        self.assertEqual("UnconfirmedRequestPDU", requests[0]["pdu_type"])

    def test_a_refused_bbmd_function_is_answered_and_recorded(self):
        reply = self._exchange(
            encode_bvlc(b"\x00\x3c", bvlc.REGISTER_FOREIGN_DEVICE)
        )
        self.assertEqual(bvlc.build_result(0x0030), reply)

        requests = self._requests()
        self.assertTrue(requests, "a foreign-device registration left no record")
        self.assertEqual("BVLC", requests[0]["pdu_type"])
        self.assertEqual("RegisterForeignDevice", requests[0]["service"])

    def test_a_malformed_frame_does_not_take_the_server_down(self):
        self.assertIsNone(self._exchange(b"\x81\x0a\xff\xff\x01\x00\x10\x08"))
        # Still answering afterwards.
        self.assertIsNotNone(
            self._exchange(frame(WhoIsRequest(), function=bvlc.ORIGINAL_BROADCAST_NPDU))
        )


if __name__ == "__main__":
    unittest.main()
