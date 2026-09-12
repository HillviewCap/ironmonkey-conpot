# Copyright (C) 2013  Lukas Rist <glaslos@gmail.com>
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

import shutil
import tempfile
import unittest
from collections import namedtuple

import gevent
from gevent import socket
from pysnmp.proto import rfc1902

import conpot.core as conpot_core
from conpot.protocols.snmp.snmp_server import SNMPServer
from conpot.tests.helpers import snmp_client
from conpot.utils.greenlet import spawn_test_server, teardown_test_server


class TestSNMPServer(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

        args = namedtuple("FakeArgs", "mibcache")
        args.mibcache = self.tmp_dir

        self.snmp_server, self.greenlet = spawn_test_server(
            SNMPServer, template="default", protocol="snmp", args=args
        )

        self.host = "127.0.0.1"
        self.port = self.snmp_server.get_port()

    def tearDown(self):
        teardown_test_server(self.snmp_server, self.greenlet)
        shutil.rmtree(self.tmp_dir)

    def test_snmp_get(self):
        """
        Objective: Test if we can get data via snmp_get
        """
        client = snmp_client.SNMPClient(self.host, self.port)
        oid = ((1, 3, 6, 1, 2, 1, 1, 1, 0), None)
        client.get_command(oid, callback=self.mock_callback)
        self.assertEqual("Siemens, SIMATIC, S7-200", self.result)

    def test_snmp_set(self):
        """
        Objective: Test if we can set data via snmp_set
        """
        client = snmp_client.SNMPClient(self.host, self.port)
        # syslocation
        oid = ((1, 3, 6, 1, 2, 1, 1, 6, 0), rfc1902.OctetString("TESTVALUE"))
        client.set_command(oid, callback=self.mock_callback)
        databus = conpot_core.get_databus()
        self.assertEqual("TESTVALUE", databus.get_value("sysLocation"))

    def mock_callback(
        self,
        snmpEngine,
        sendRequestHandle,
        errorIndication,
        errorStatus,
        errorIndex,
        varBindTable,
        cbCtx,
    ):
        self.result = None
        if errorIndication:
            self.result = errorIndication
        elif errorStatus:
            self.result = errorStatus.prettyPrint()
        else:
            for oid, val in varBindTable:
                self.result = val.prettyPrint()


class TestSNMPSubstationCapture(unittest.TestCase):
    """SNMP capture on the substation persona (Phase 2 step H10).

    Two facts are load-bearing on an internet-exposed sensor and neither was
    recorded before this step:

      * the community an answered request actually carried, as opposed to the
        securityName pysnmp maps it to; and
      * the community a REJECTED request carried, which produced no record at
        all -- the security model drops the message before any responder runs,
        so a brute force over `private`, `cisco`, a vendor default read
        downstream as nobody having touched SNMP.

    These drive raw v1arch datagrams rather than the v3-only test client in
    conpot.tests.helpers, because the community is exactly what v3 does not
    have.
    """

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        args = namedtuple("FakeArgs", "mibcache")
        args.mibcache = self.tmp_dir
        self.snmp_server, self.greenlet = spawn_test_server(
            SNMPServer, template="s7-315-substation", protocol="snmp", args=args
        )
        self.host = "127.0.0.1"
        self.port = self.snmp_server.get_port()
        self._drain()

    def tearDown(self):
        teardown_test_server(self.snmp_server, self.greenlet)
        shutil.rmtree(self.tmp_dir)

    @staticmethod
    def _drain():
        queue = conpot_core.get_sessionManager().log_queue
        while not queue.empty():
            queue.get_nowait()

    @staticmethod
    def _events():
        queue = conpot_core.get_sessionManager().log_queue
        out = []
        while not queue.empty():
            out.append(queue.get_nowait()["data"])
        return out

    def _v2c_get(self, community, oid="1.3.6.1.2.1.1.1.0"):
        from pyasn1.codec.ber import encoder
        from pysnmp.proto import api

        module = api.PROTOCOL_MODULES[api.SNMP_VERSION_2C]
        pdu = module.GetRequestPDU()
        module.apiPDU.set_defaults(pdu)
        module.apiPDU.set_varbinds(pdu, ((oid, module.Null("")),))
        message = module.Message()
        module.apiMessage.set_defaults(message)
        module.apiMessage.set_community(message, community)
        module.apiMessage.set_pdu(message, pdu)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        try:
            sock.sendto(encoder.encode(message), (self.host, self.port))
            try:
                return sock.recvfrom(4096)[0]
            except socket.timeout:
                return None
        finally:
            sock.close()

    def test_answered_request_records_the_wire_community(self):
        self.assertIsNotNone(
            self._v2c_get("public"), "the accepted community got no answer"
        )
        gevent.sleep(0.2)
        requests = [e["request"] for e in self._events() if "request" in e]
        self.assertTrue(requests, "no SNMP exchange reached the session")
        request = requests[0]
        self.assertEqual("public", request["community"])
        self.assertEqual("2c", request["version"])
        self.assertEqual("Get", request["command"])
        self.assertTrue(request["answered"])
        self.assertEqual("1.3.6.1.2.1.1.1.0", request["oid"])

    def test_rejected_community_is_recorded_as_unanswered(self):
        self.assertIsNone(
            self._v2c_get("private"),
            "a community the engine does not accept must not be answered",
        )
        gevent.sleep(0.2)
        requests = [e["request"] for e in self._events() if "request" in e]
        self.assertTrue(
            requests, "a rejected community left no record of the guess"
        )
        request = requests[0]
        self.assertEqual("private", request["community"])
        self.assertEqual("2c", request["version"])
        self.assertFalse(request["answered"])

    def test_persona_answers_the_substation_identity(self):
        """The values served are the persona's, not upstream Conpot's.

        The default template answers sysDescr "Siemens, SIMATIC, S7-200" and
        sysLocation "Venus"; both identify a Conpot instance rather than a
        PLC, which is why the persona carries its own.
        """
        client = snmp_client.SNMPClient(self.host, self.port)
        seen = {}

        def collect(engine, handle, err_ind, err_status, err_idx, varbinds, ctx):
            for oid, value in varbinds:
                seen[str(oid)] = value.prettyPrint()

        for oid in (
            (1, 3, 6, 1, 2, 1, 1, 1, 0),  # sysDescr
            (1, 3, 6, 1, 2, 1, 1, 2, 0),  # sysObjectID
            (1, 3, 6, 1, 2, 1, 1, 5, 0),  # sysName
            (1, 3, 6, 1, 2, 1, 1, 6, 0),  # sysLocation
        ):
            client.get_command((oid, None), callback=collect)

        self.assertIn("S7-315-2 PN/DP", seen["1.3.6.1.2.1.1.1.0"])
        # Siemens AG's IANA enterprise arc, not a Conpot default.
        self.assertEqual("1.3.6.1.4.1.4196", seen["1.3.6.1.2.1.1.2.0"])
        self.assertEqual("S7-315-SUBSTATION-01", seen["1.3.6.1.2.1.1.5.0"])
        # Present and empty on purpose: siting is not disclosed, but a device
        # that has no sysLocation object at all is odder than one that has an
        # unset it.
        self.assertEqual("", seen["1.3.6.1.2.1.1.6.0"])
        self.assertNotIn("S7-200", seen["1.3.6.1.2.1.1.1.0"])
