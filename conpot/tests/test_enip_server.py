# Copyright (C) 2017  Yuru Shao <shaoyuru@gmail.com>
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
import os
import unittest

import pytest
from cpppo.server.enip import client
from gevent import socket

from cpppo.server.enip import device

import conpot
import conpot.core as conpot_core
from conpot.protocols.enip import enip_server
from conpot.protocols.enip.enip_server import EnipServer
from conpot.utils.greenlet import spawn_test_server, teardown_test_server


# In lieu of creating dedicated test templates we modify
# EnipServer config through inheritance
class EnipServerTCP(EnipServer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.addr = "127.0.0.1"
        self.port = 50002
        self.config.mode = "tcp"


class EnipServerUDP(EnipServer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.addr = "127.0.0.1"
        self.port = 60002
        self.config.mode = "udp"


@pytest.fixture(scope="class")
def enip_test_servers(request):
    """One TCP + UDP ENIP server pair for the whole test class (avoids ~10× spawn cost)."""
    tcp_server, tcp_greenlet = spawn_test_server(
        EnipServerTCP, "default", "enip", port=50002
    )
    udp_server, udp_greenlet = spawn_test_server(
        EnipServerUDP, "default", "enip", port=60002
    )
    request.cls.enip_server_tcp = tcp_server
    request.cls.server_greenlet_tcp = tcp_greenlet
    request.cls.enip_server_udp = udp_server
    request.cls.server_greenlet_udp = udp_greenlet
    yield
    teardown_test_server(udp_server, udp_greenlet)
    teardown_test_server(tcp_server, tcp_greenlet)


@pytest.mark.usefixtures("enip_test_servers")
class TestENIPServer(unittest.TestCase):

    @staticmethod
    def attribute_operations(paths, int_type=None, **kwds):
        for op in client.parse_operations(paths, int_type=int_type or "SINT", **kwds):
            path_end = op["path"][-1]
            if "instance" in path_end:
                op["method"] = "get_attributes_all"
                assert (
                    "data" not in op
                ), "All Attributes cannot be operated on using Set Attribute services"
            elif "symbolic" in path_end or "attribute" in path_end or "element":
                op["method"] = (
                    "set_attribute_single" if "data" in op else "get_attribute_single"
                )
            else:
                raise AssertionError(
                    "Path invalid for Attribute services: %r", op["path"]
                )
            yield op

    @staticmethod
    def await_cpf_response(connection, command):
        response, _ = client.await_response(connection, timeout=4.0)
        return response["enip"]["CIP"][command]["CPF"]

    def test_read_tags(self):
        with client.connector(
            host=self.enip_server_tcp.addr, port=self.enip_server_tcp.port, timeout=4.0
        ) as connection:
            tags = ["@22/1/1"]
            ops = self.attribute_operations(tags)
            for _, _, _, _, _, val in connection.pipeline(operations=ops):
                self.assertEqual(100, val[0])

    def test_write_tags(self):
        with client.connector(
            host=self.enip_server_tcp.addr, port=self.enip_server_tcp.port, timeout=4.0
        ) as connection:
            tags = ["@22/1/1=(SINT)50", "@22/1/1"]
            ops = self.attribute_operations(tags)
            for idx, _, _, _, _, val in connection.pipeline(operations=ops):
                if idx == 0:
                    self.assertEqual(True, val)
                elif idx == 1:
                    self.assertEqual(50, val[0])

    def test_list_services_tcp(self):
        with client.connector(
            host=self.enip_server_tcp.addr,
            port=self.enip_server_tcp.port,
            timeout=4.0,
            udp=False,
            broadcast=False,
        ) as connection:
            connection.list_services()
            connection.shutdown()
            response = self.await_cpf_response(connection, "list_services")

            self.assertEqual(
                "Communications",
                response["item"][0]["communications_service"]["service_name"],
            )

    def test_list_services_udp(self):
        with client.connector(
            host=self.enip_server_udp.addr,
            port=self.enip_server_udp.port,
            timeout=4.0,
            udp=True,
            broadcast=True,
        ) as connection:
            connection.list_services()
            response = self.await_cpf_response(connection, "list_services")

            self.assertEqual(
                "Communications",
                response["item"][0]["communications_service"]["service_name"],
            )

    def test_list_identity_tcp(self):
        with client.connector(
            host=self.enip_server_tcp.addr,
            port=self.enip_server_tcp.port,
            timeout=4.0,
            udp=False,
            broadcast=False,
        ) as connection:
            connection.list_identity()
            connection.shutdown()
            response = self.await_cpf_response(connection, "list_identity")

            expected = self.enip_server_tcp.config.product_name
            self.assertEqual(
                expected, response["item"][0]["identity_object"]["product_name"]
            )

    def test_list_identity_udp(self):
        with client.connector(
            host=self.enip_server_udp.addr,
            port=self.enip_server_udp.port,
            timeout=4.0,
            udp=True,
            broadcast=True,
        ) as connection:
            connection.list_identity()
            response = self.await_cpf_response(connection, "list_identity")

            expected = self.enip_server_tcp.config.product_name
            self.assertEqual(
                expected, response["item"][0]["identity_object"]["product_name"]
            )

    def test_list_interfaces_tcp(self):
        with client.connector(
            host=self.enip_server_tcp.addr,
            port=self.enip_server_tcp.port,
            timeout=4.0,
            udp=False,
            broadcast=False,
        ) as conn:
            conn.list_interfaces()
            conn.shutdown()
            response = self.await_cpf_response(conn, "list_interfaces")

            self.assertDictEqual({"count": 0}, response)

    def test_list_interfaces_udp(self):
        with client.connector(
            host=self.enip_server_udp.addr,
            port=self.enip_server_udp.port,
            timeout=4.0,
            udp=True,
            broadcast=True,
        ) as conn:
            conn.list_interfaces()
            response = self.await_cpf_response(conn, "list_interfaces")

            self.assertDictEqual({"count": 0}, response)

    # Tests related to restart of ENIP device..
    # def test_send_NOP(self):
    #     # test tcp
    #     pass

    def test_malformend_request_tcp(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(4.0)
            s.connect((self.enip_server_tcp.addr, self.enip_server_tcp.port))
            s.send(
                b"e\x00\x04\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                + b"x00\x00\x01\x00\x00\x00"
            )  # test the help command
            try:
                _ = s.recv(1024)
            except socket.timeout:
                pass
        finally:
            s.close()
        # TODO: verify data packet?

    def test_malformend_request_udp(self):
        pass


class EnipServerSubstation(EnipServer):
    """The substation persona's ENIP server, on a fixed test port."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.addr = "127.0.0.1"
        self.port = 50003


@pytest.fixture(scope="class")
def enip_substation_server(request):
    # cpppo builds the Identity Object once per interpreter, lazily, on the
    # first request, and reads Object.config_loader at that moment. An earlier
    # ENIP server in this same process (the default-template fixture above,
    # or test_protocols.py) will already have built it from ITS template, so
    # without this reset the identity asserted below would be whichever
    # template happened to run first. Production never hits this: one Conpot
    # process serves one template and constructs its server before any
    # request. Reset BEFORE spawning, so apply_identity runs after the
    # directory is empty.
    device.lookup_reset()
    server, greenlet = spawn_test_server(
        EnipServerSubstation, "s7-315-substation", "enip", port=50003
    )
    request.cls.server = server
    request.cls.greenlet = greenlet
    yield
    teardown_test_server(server, greenlet)


@pytest.mark.usefixtures("enip_substation_server")
class TestENIPSubstationCapture(unittest.TestCase):
    """ENIP identity and session capture (Phase 2 step H10).

    Two separate gaps closed here. The template's <device_info> was
    decorative -- EnipConfig parsed it and only two logger.debug lines read
    it, so every Conpot ENIP endpoint answered ListIdentity with cpppo's
    built-in Rockwell 1756-L61/B LOGIX5561 defaults. And the session carried
    only NEW_CONNECTION / CONNECTION_CLOSED, so a banner grab, a tag read and
    a tag WRITE were the same empty record.
    """

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

    @staticmethod
    def _operations(paths):
        for op in client.parse_operations(paths, int_type="SINT"):
            path_end = op["path"][-1]
            if "instance" in path_end:
                op["method"] = "get_attributes_all"
            else:
                op["method"] = (
                    "set_attribute_single" if "data" in op else "get_attribute_single"
                )
            yield op

    def test_identity_comes_from_the_template_not_cpppo(self):
        self._drain()
        with client.connector(
            host=self.server.addr, port=self.server.port, timeout=4.0,
            udp=False, broadcast=False,
        ) as connection:
            connection.list_identity()
            connection.shutdown()
            response, _ = client.await_response(connection, timeout=4.0)
        identity = response["enip"]["CIP"]["list_identity"]["CPF"]["item"][0][
            "identity_object"
        ]
        self.assertEqual("1769-AENTR/B", identity["product_name"])
        self.assertEqual(12, identity["device_type"])
        self.assertEqual(191, identity["product_code"])
        self.assertEqual(771, identity["product_revision"])
        self.assertEqual(12841381, identity["serial_number"])
        # cpppo's own defaults, which every unmodified Conpot serves.
        self.assertNotEqual(0x006C061A, identity["serial_number"])
        self.assertNotEqual(0x3160, identity["status_word"])

    def test_tag_read_records_the_cip_service_and_path(self):
        self._drain()
        with client.connector(
            host=self.server.addr, port=self.server.port, timeout=4.0
        ) as connection:
            for _ in connection.pipeline(
                operations=self._operations(["@100/1/1"])
            ):
                pass
        reads = [r for r in self._requests() if "cip_service" in r]
        self.assertTrue(reads, "a CIP read reached no session event")
        self.assertEqual(0x0E, reads[0]["cip_service"])
        self.assertEqual("get_attribute_single", reads[0]["cip_service_name"])
        self.assertEqual(100, reads[0]["cip_class"])
        self.assertEqual("@0x64/1/1", reads[0]["cip_path"])
        # The response payload is written back into the request sub-dict, so a
        # read must not report our own answer as the attacker's input.
        self.assertNotIn("cip_written_values", reads[0])

    def test_tag_write_records_the_value_written(self):
        self._drain()
        with client.connector(
            host=self.server.addr, port=self.server.port, timeout=4.0
        ) as connection:
            for _ in connection.pipeline(
                operations=self._operations(["@100/1/1=(SINT)7"])
            ):
                pass
        writes = [r for r in self._requests() if "cip_written_values" in r]
        self.assertTrue(writes, "a CIP write reached no session event")
        # cpppo ORs 0x80 into `service` while building the reply; the request
        # code is what has to be recorded.
        self.assertEqual(0x10, writes[0]["cip_service"])
        self.assertEqual("set_attribute_single", writes[0]["cip_service_name"])
        self.assertEqual([7], writes[0]["cip_written_values"])
        self.assertEqual("@0x64/1/1", writes[0]["cip_path"])

    def test_register_session_is_recorded_as_its_own_exchange(self):
        self._drain()
        with client.connector(
            host=self.server.addr, port=self.server.port, timeout=4.0
        ) as connection:
            for _ in connection.pipeline(
                operations=self._operations(["@100/1/1"])
            ):
                pass
        commands = [r.get("enip_command_name") for r in self._requests()]
        self.assertIn("register_session", commands)
        self.assertIn("send_rr_data", commands)


class TestENIPModeParsing(unittest.TestCase):
    """`mode` may name one transport or both (Phase 2 step H10).

    A real EtherNet/IP device answers explicit messaging on 44818/tcp and
    ListIdentity discovery on 44818/udp; serving only one of the two is itself
    a tell. The single-value spellings have to keep working unchanged -- the
    fixtures above set `config.mode` directly.
    """

    def _config(self, template):
        conpot_dir = os.path.dirname(conpot.__file__)
        return enip_server.EnipConfig(
            f"{conpot_dir}/templates/{template}/enip/enip.xml"
        )

    def test_substation_template_serves_both_transports(self):
        config = self._config("s7-315-substation")
        self.assertEqual({"tcp", "udp"}, set(config.modes))

    def test_default_template_still_serves_tcp_only(self):
        config = self._config("default")
        self.assertEqual({"tcp"}, set(config.modes))

    def test_assigning_mode_recomputes_the_parsed_set(self):
        config = self._config("default")
        config.mode = "udp"
        self.assertEqual({"udp"}, set(config.modes))
        config.mode = "tcp, udp"
        self.assertEqual({"tcp", "udp"}, set(config.modes))
