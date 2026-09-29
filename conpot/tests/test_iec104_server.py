# Copyright (C) 2017  Patrick Reichenberger (University of Passau) <patrick.reichenberger@t-online.de>
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
import socket
import time
import unittest
from unittest.mock import patch
import conpot.core as conpot_core
from types import SimpleNamespace
from conpot.protocols.IEC104 import IEC104_server, frames
from conpot.protocols.IEC104.IEC104 import IEC104
from conpot.utils.greenlet import spawn_test_server, teardown_test_server


class TestIEC104Server(unittest.TestCase):
    def setUp(self):
        self.databus = conpot_core.get_databus()

        self.iec104_inst, self.greenlet = spawn_test_server(
            IEC104_server.IEC104Server, "IEC104", "IEC104", port=2404
        )

        self.coa = self.iec104_inst.device_data_controller.common_address

    def tearDown(self):
        teardown_test_server(self.iec104_inst, self.greenlet)

    def test_startdt(self):
        """
        Objective: Test if answered correctly to STARTDT act
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("127.0.0.1", 2404))
        s.send(frames.STARTDT_act.build())
        data = s.recv(6)
        self.assertSequenceEqual(data, frames.STARTDT_con.build())

    def test_testfr(self):
        """
        Objective: Test if answered correctly to TESTFR act
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("127.0.0.1", 2404))
        s.send(frames.TESTFR_act.build())
        data = s.recv(6)
        self.assertEqual(data, frames.TESTFR_con.build())

    def test_partial_header_then_close_does_not_wedge_server(self):
        """
        Objective: A peer that sends a partial header and disconnects must not
        starve the gevent hub.

        Regression test for the unguarded `while request and len(request) < 2`
        recv loop. At EOF recv() returns b'' immediately, so `request` never
        grew and the loop spun at 100% CPU. Because an EOF recv never blocks it
        also never yielded to the hub, so the T_3 timeout could not fire and
        every other Conpot protocol (Modbus, S7comm, HTTP) stopped accepting.
        Observed in production 2026-08-07: one probe took the OT sensor dark
        for three days.
        """
        half_open = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        half_open.settimeout(1)
        half_open.connect(("127.0.0.1", 2404))
        half_open.send(b"\x68")  # one byte of a two-byte header, then EOF
        half_open.close()

        # Give the handler greenlet room to spin if the guard ever regresses.
        time.sleep(0.2)

        # The hub must still be scheduling: a fresh session gets served.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(("127.0.0.1", 2404))
        s.send(frames.STARTDT_act.build())
        self.assertSequenceEqual(s.recv(6), frames.STARTDT_con.build())
        s.close()

    def test_write_for_non_existing(self):
        """
        Objective: Test answer for a command to a device that doesn't exist
        (Correct behaviour of the IEC104 protocol is not known exactly. Other case is test for no answer)
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("127.0.0.1", 2404))

        s.send(frames.STARTDT_act.build())
        s.recv(6)

        single_command = (
            frames.i_frame()
            / frames.asdu_head(COA=self.coa, COT=6)
            / frames.asdu_infobj_45(IOA=0xEEEEEE, SCS=1)
        )
        s.send(single_command.build())
        data = s.recv(16)

        bad_addr = (
            frames.i_frame(RecvSeq=0x0002)
            / frames.asdu_head(COA=self.coa, COT=47)
            / frames.asdu_infobj_45(IOA=0xEEEEEE, SCS=1)
        )
        self.assertSequenceEqual(data, bad_addr.build())

    def test_write_relation_for_existing(self):
        """
        Objective: Test answer for a correct command to a device that does exist and has a related sensor
        (Actuator 22_20 (Type 45: Single Command) will be tested,
        the corresponding(!) sensor 13_20 (Type 1: Single Point Information) changes the value
        and the termination confirmation is returned)
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("127.0.0.1", 2404))

        s.send(frames.STARTDT_act.build())
        s.recv(6)

        self.databus.set_value("22_20", 0)  # Must be in template and relation to 13_20
        self.databus.set_value("13_20", 0)  # Must be in template

        single_command = (
            frames.i_frame()
            / frames.asdu_head(COA=self.coa, COT=6)
            / frames.asdu_infobj_45(IOA=0x141600, SCS=1)
        )
        s.send(single_command.build())

        data = s.recv(16)
        act_conf = (
            frames.i_frame(RecvSeq=0x0002)
            / frames.asdu_head(COA=self.coa, COT=7)
            / frames.asdu_infobj_45(IOA=0x141600, SCS=1)
        )
        self.assertSequenceEqual(data, act_conf.build())

        data = s.recv(16)
        info = (
            frames.i_frame(SendSeq=0x0002, RecvSeq=0x0002)
            / frames.asdu_head(COA=self.coa, COT=11)
            / frames.asdu_infobj_1(IOA=0x140D00)
        )
        info.SIQ = frames.SIQ(SPI=1)
        self.assertSequenceEqual(data, info.build())

        data = s.recv(16)
        act_term = (
            frames.i_frame(SendSeq=0x0004, RecvSeq=0x0002)
            / frames.asdu_head(COA=self.coa, COT=10)
            / frames.asdu_infobj_45(IOA=0x141600, SCS=1)
        )
        self.assertSequenceEqual(data, act_term.build())

    def test_write_no_relation_for_existing(self):
        """
        Objective: Test answer for a correct command to a device that does exist and has no related sensor
        (Actuator 22_19 (Type 45: Single Command) will be tested, the corresponding(!) sensor is not existent)
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("127.0.0.1", 2404))

        s.send(frames.STARTDT_act.build())
        s.recv(6)

        self.databus.set_value("22_19", 0)  # Must be in template and no relation

        single_command = (
            frames.i_frame()
            / frames.asdu_head(COA=self.coa, COT=6)
            / frames.asdu_infobj_45(IOA=0x131600, SCS=0)
        )
        s.send(single_command.build())

        data = s.recv(16)
        act_conf = (
            frames.i_frame(RecvSeq=0x0002)
            / frames.asdu_head(COA=self.coa, COT=7)
            / frames.asdu_infobj_45(IOA=0x131600, SCS=0)
        )
        self.assertSequenceEqual(data, act_conf.build())

        data = s.recv(16)
        act_term = (
            frames.i_frame(SendSeq=0x0002, RecvSeq=0x0002)
            / frames.asdu_head(COA=self.coa, COT=10)
            / frames.asdu_infobj_45(IOA=0x131600, SCS=0)
        )
        self.assertSequenceEqual(data, act_term.build())

    def test_write_wrong_type_for_existing(self):
        """
        Objective: Test answer for a command of wrong type to a device that does exist
        (Actuator 22_20 (Type 45: Single Command) will be tested,
        but a wrong command type (Double Commands instead of Single Command) is sent to device)
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("127.0.0.1", 2404))

        s.send(frames.STARTDT_act.build())
        s.recv(6)

        self.databus.set_value("22_20", 0)  # Must be in template

        single_command = (
            frames.i_frame()
            / frames.asdu_head(COA=self.coa, COT=6)
            / frames.asdu_infobj_46(IOA=0x141600, DCS=1)
        )
        s.send(single_command.build())

        data = s.recv(16)
        act_conf = (
            frames.i_frame(RecvSeq=0x0002)
            / frames.asdu_head(COA=self.coa, PN=1, COT=7)
            / frames.asdu_infobj_46(IOA=0x141600, DCS=1)
        )
        self.assertSequenceEqual(data, act_conf.build())

    def test_i_frame_logs_asdu_event(self):
        """OT-IEC104 capture.

        Before this, handle_i_frame never called add_event() with anything
        but NEW_CONNECTION/CONNECTION_LOST -- every touch to the exposed
        IEC-104 bait port vanished before reaching the forwarder, which has
        had a branch expecting {"type_id", "cot", "ioa"} since it was
        written, with nothing upstream ever populating it. Reuses the exact
        write-command fixture from test_write_no_relation_for_existing (a
        proven-working request/response pair) and additionally asserts on
        the session event queue.

        Searches the next few queue items rather than asserting the ASDU
        event is the very first one: lifecycle events (NEW_CONNECTION) and
        this event share one queue, and this test only cares that the ASDU
        got logged at all, not its exact position relative to them.
        """
        log_queue = conpot_core.get_sessionManager().log_queue
        while not log_queue.empty():  # drop anything left over from a prior test
            log_queue.get_nowait()

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("127.0.0.1", 2404))

        s.send(frames.STARTDT_act.build())
        s.recv(6)

        self.databus.set_value("22_19", 0)  # Must be in template and no relation

        single_command = (
            frames.i_frame()
            / frames.asdu_head(COA=self.coa, COT=6)
            / frames.asdu_infobj_45(IOA=0x131600, SCS=0)
        )
        s.send(single_command.build())
        s.recv(16)  # ACT_CONF -- proven by test_write_no_relation_for_existing

        request = None
        for _ in range(5):
            data = log_queue.get(timeout=2)["data"]
            if "request" in data:
                request = data["request"]
                break
        self.assertIsNotNone(request, "no ASDU event reached the session log_queue")
        self.assertEqual(45, request["type_id"])  # C_SC_NA_1, single command
        self.assertEqual(6, request["cot"])  # activation
        self.assertEqual(0x131600, request["ioa"])
        # W1-09: the I-frame itself, as received.
        self.assertEqual(single_command.build().hex(), request["raw"])

        s.close()

    @patch("conpot.protocols.IEC104.IEC104_server.gevent._socket3.socket.recv")
    def test_failing_connection_connection_lost_event(self, mock_timeout):
        """
        Objective: Test if correct exception is executed when a socket.error
        with EPIPE occurs
        """
        mock_timeout.side_effect = OSError(32, "Socket Error")
        conpot_core.get_sessionManager().purge_sessions()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 2404))
        time.sleep(0.1)
        log_queue = conpot_core.get_sessionManager().log_queue
        con_new_event = log_queue.get()
        con_lost_event = log_queue.get(timeout=1)

        self.assertEqual("NEW_CONNECTION", con_new_event["data"]["type"])
        self.assertEqual("CONNECTION_LOST", con_lost_event["data"]["type"])

        s.close()


# IEC-104 I-frames from the c104 2.2.1 (lib60870-C) client, captured on
# loopback through a logging proxy on 2026-09-29 against a c104 server with
# common address 1 (the same frames the forwarder tests use). The single
# command's point is SELECT_AND_EXECUTE, so the client sent a select (S/E = 1)
# and, after the positive ACT_CON, an execute (S/E = 0).
C104_C_SC_NA_1_SELECT = "680e000000002d010600010088130081"
C104_C_SC_NA_1_EXECUTE = "680e020002002d010600010088130001"
C104_C_DC_NA_1_ON = "680e040006002e010600010089130002"
C104_C_SE_NC_1 = "6812060008003201060001008a13000000dd4200"  # 110.5
C104_C_SE_NB_1 = "681008000a003101060001008b13002efb00"  # -1234
C104_C_IC_NA_1 = "680e0a000c0064010600010000000014"  # QOI 20


class _RecordingSession:
    def __init__(self):
        self.events = []

    def add_event(self, event):
        self.events.append(event)


def _logged_request(frame_hex):
    """What `_record_asdu_event` logs for one real I-frame, no socket needed."""
    frame = bytes.fromhex(frame_hex)
    container = frames.i_frame(frame)
    handler = SimpleNamespace(session=_RecordingSession())
    IEC104._record_asdu_event(
        handler, container, container.getfieldval("TypeID"), frame
    )
    (event,) = handler.session.events
    return event["request"]


class TestRecordAsduEvent(unittest.TestCase):
    """The logged ASDU record, from real client frames (Wave 1, W1-09)."""

    def test_raw_is_the_i_frame_as_lowercase_hex(self):
        for frame_hex in (
            C104_C_SC_NA_1_SELECT,
            C104_C_SC_NA_1_EXECUTE,
            C104_C_SE_NC_1,
            C104_C_IC_NA_1,
        ):
            request = _logged_request(frame_hex)
            self.assertEqual(frame_hex, request["raw"])

    def test_existing_fields_are_unchanged(self):
        request = _logged_request(C104_C_SC_NA_1_SELECT)
        self.assertEqual(45, request["type_id"])
        self.assertEqual(6, request["cot"])
        self.assertEqual(5000, request["ioa"])

    def test_no_frame_no_raw(self):
        """The old two-argument call still works and logs no `raw`."""
        frame = bytes.fromhex(C104_C_IC_NA_1)
        container = frames.i_frame(frame)
        handler = SimpleNamespace(session=_RecordingSession())
        IEC104._record_asdu_event(handler, container, 100)
        self.assertNotIn("raw", handler.session.events[0]["request"])
