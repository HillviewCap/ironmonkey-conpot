# Copyright (C) 2015  Peter Sooky <xsooky00@stud.fit.vutbr.cz>
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

from gevent import monkey

monkey.patch_all()

import unittest
from gevent import socket, Timeout

from bacpypes.pdu import GlobalBroadcast, PDU
from bacpypes.apdu import (
    APDU,
    WhoIsRequest,
    IAmRequest,
    IHaveRequest,
    WhoHasObject,
    WhoHasRequest,
    ReadPropertyRequest,
    ReadPropertyACK,
    WritePropertyRequest,
)
from bacpypes.constructeddata import Any
from bacpypes.primitivedata import Real

import conpot.core as conpot_core
from conpot.protocols.bacnet import bacnet_server
from conpot.utils.greenlet import spawn_test_server, teardown_test_server


class TestBACnetServer(unittest.TestCase):
    """
    All tests are executed in a similar way. We initiate a service request to the BACnet server and wait for response.
    Instead of decoding the response, we create an expected response. We encode the expected response and compare the
    two encoded data.
    """

    def setUp(self):
        self.bacnet_server, self.greenlet = spawn_test_server(
            bacnet_server.BacnetServer, "default", "bacnet"
        )

        self.address = (self.bacnet_server.host, self.bacnet_server.port)

    def tearDown(self):
        teardown_test_server(self.bacnet_server, self.greenlet)

    def test_whoIs(self):
        request = WhoIsRequest(
            deviceInstanceRangeLowLimit=500, deviceInstanceRangeHighLimit=50000
        )
        apdu = APDU()
        request.encode(apdu)
        pdu = PDU()
        apdu.encode(pdu)
        buf_size = 1024
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(pdu.pduData, self.address)
        data = s.recvfrom(buf_size)
        s.close()
        received_data = data[0]

        expected = IAmRequest()
        expected.pduDestination = GlobalBroadcast()
        expected.iAmDeviceIdentifier = 36113
        expected.maxAPDULengthAccepted = 1024
        expected.segmentationSupported = "segmentedBoth"
        expected.vendorID = 15

        exp_apdu = APDU()
        expected.encode(exp_apdu)
        exp_pdu = PDU()
        exp_apdu.encode(exp_pdu)

        self.assertEqual(exp_pdu.pduData, received_data)

    def test_whoHas(self):
        request_object = WhoHasObject()
        request_object.objectIdentifier = ("binaryInput", 12)
        request = WhoHasRequest(object=request_object)
        apdu = APDU()
        request.encode(apdu)
        pdu = PDU()
        apdu.encode(pdu)
        buf_size = 1024
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(pdu.pduData, self.address)
        data = s.recvfrom(buf_size)
        s.close()
        received_data = data[0]

        expected = IHaveRequest()
        expected.pduDestination = GlobalBroadcast()
        expected.deviceIdentifier = 36113
        expected.objectIdentifier = 12
        expected.objectName = "BI 01"

        exp_apdu = APDU()
        expected.encode(exp_apdu)
        exp_pdu = PDU()
        exp_apdu.encode(exp_pdu)
        self.assertEqual(exp_pdu.pduData, received_data)

    def test_readProperty(self):
        request = ReadPropertyRequest(
            objectIdentifier=("analogInput", 14), propertyIdentifier=85
        )
        request.apduMaxResp = 1024
        request.apduInvokeID = 101
        apdu = APDU()
        request.encode(apdu)
        pdu = PDU()
        apdu.encode(pdu)
        buf_size = 1024
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(pdu.pduData, self.address)
        data = s.recvfrom(buf_size)
        s.close()
        received_data = data[0]

        expected = ReadPropertyACK()
        expected.pduDestination = GlobalBroadcast()
        expected.apduInvokeID = 101
        expected.objectIdentifier = 14
        expected.objectName = "AI 01"
        expected.propertyIdentifier = 85
        expected.propertyValue = Any(Real(68.0))

        exp_apdu = APDU()
        expected.encode(exp_apdu)
        exp_pdu = PDU()
        exp_apdu.encode(exp_pdu)

        self.assertEqual(exp_pdu.pduData, received_data)

    def test_no_response_requests(self):
        """When the request has apduType not 0x01, no reply should be returned from Conpot"""
        request = ReadPropertyRequest(
            objectIdentifier=("analogInput", 14), propertyIdentifier=85
        )
        request.pduData = bytearray(b"test_data")
        request.apduMaxResp = 1024
        request.apduInvokeID = 101
        # Build requests - Confirmed, simple ack pdu, complex ack pdu, error pdu - etc.
        test_requests = list()

        for i in range(2, 8):
            if i not in {1, 3, 4}:
                request.apduType = i
                if i == 2:
                    # when apdu.apduType is 2 - we have SimpleAckPDU
                    # set the apduInvokeID and apduService
                    request.apduService = 8
                elif i == 5:
                    # when apdu.apduType is 5 - we have ErrorPDU
                    # set the apduInvokeID and apduService
                    request.apduService = 8
                elif i == 6:
                    # when apdu.apduType is 6 - we have RejectPDU
                    # set the apduInvokeID and apduAbortRejectReason
                    request.apduAbortRejectReason = 9
                else:
                    # when apdu.apduType is 7 - we have AbortPDU
                    # set the apduInvokeID and apduAbortRejectReason
                    request.apduAbortRejectReason = 9

                test_requests.append(request)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        buf_size = 1024
        [s.sendto(i.pduData, self.address) for i in test_requests]
        results = None
        with Timeout(1, False):
            results = [s.recvfrom(buf_size) for i in range(len(test_requests))]
        self.assertIsNone(results)


class TestBACnetSubstationCapture(unittest.TestCase):
    """BACnet session capture on the substation persona (Phase 2 step H10).

    Before this step the only event a BACnet session carried was
    NEW_CONNECTION, so a Who-Is sweep and a WriteProperty against the plant
    left byte-identical records. `indication()` now logs the service on the
    way IN, which is also why the WriteProperty case below is the important
    one: Conpot implements no writeProperty handler, so a write falls straight
    through to "Not implemented Bacnet command" and would be invisible if the
    event were emitted after dispatch instead of before it.
    """

    def setUp(self):
        self.bacnet_server, self.greenlet = spawn_test_server(
            bacnet_server.BacnetServer, "s7-315-substation", "bacnet"
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

    def _send(self, request):
        apdu = APDU()
        request.encode(apdu)
        pdu = PDU()
        apdu.encode(pdu)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        try:
            s.sendto(pdu.pduData, self.address)
            try:
                return s.recvfrom(1024)[0]
            except Exception:
                return None
        finally:
            s.close()

    def test_who_is_is_recorded(self):
        self._send(WhoIsRequest())
        requests = self._requests()
        self.assertTrue(requests, "a Who-Is sweep reached no session event")
        self.assertEqual("WhoIsRequest", requests[0]["service"])
        self.assertEqual("UnconfirmedRequestPDU", requests[0]["pdu_type"])

    def test_read_property_records_object_and_property(self):
        request = ReadPropertyRequest(
            objectIdentifier=("analogInput", 12), propertyIdentifier=85
        )
        request.apduMaxResp = 1024
        request.apduInvokeID = 101
        self.assertIsNotNone(
            self._send(request), "the persona did not answer a ReadProperty"
        )
        requests = self._requests()
        self.assertTrue(requests)
        self.assertEqual("ReadPropertyRequest", requests[0]["service"])
        self.assertEqual("analogInput", requests[0]["object_type"])
        self.assertEqual(12, requests[0]["object_instance"])
        self.assertEqual("presentValue", requests[0]["property"])

    def test_write_property_is_recorded_although_unimplemented(self):
        request = WritePropertyRequest(
            objectIdentifier=("analogInput", 12), propertyIdentifier=85
        )
        request.apduMaxResp = 1024
        request.apduInvokeID = 102
        request.propertyValue = Any(Real(99.0))
        self._send(request)
        requests = self._requests()
        self.assertTrue(
            requests, "a WriteProperty attempt left no record at all"
        )
        self.assertEqual("WritePropertyRequest", requests[0]["service"])
        self.assertEqual("analogInput", requests[0]["object_type"])
        self.assertEqual(12, requests[0]["object_instance"])

    def test_persona_object_list_is_reachable(self):
        """Every object in the template answers, not just the last two.

        BACnetApp.readProperty walks `device.objectList.value[2:]`, so an
        object list that grows or shrinks can silently drop its first entries
        -- the emulated device would advertise points it then refuses to read.
        """
        for object_id in (
            ("analogInput", 12),
            ("analogInput", 13),
            ("binaryInput", 14),
            ("binaryInput", 15),
        ):
            request = ReadPropertyRequest(
                objectIdentifier=object_id, propertyIdentifier=85
            )
            request.apduMaxResp = 1024
            request.apduInvokeID = 103
            self.assertIsNotNone(
                self._send(request), "no answer for %r" % (object_id,)
            )
