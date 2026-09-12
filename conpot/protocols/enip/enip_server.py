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

import logging
import re
import socket
import cpppo
import contextlib
import time
import sys
import traceback

from lxml import etree
from cpppo.server import network
from cpppo.server.enip import logix
from cpppo.server.enip import parser
from cpppo.server.enip import device
from conpot.core.protocol_wrapper import conpot_protocol
import conpot.core as conpot_core
from conpot.utils.networking import get_interface_ip

logger = logging.getLogger(__name__)

# ── Identity (Phase 2 step H10) ───────────────────────────────────────────
#
# The <device_info> block in enip.xml was decorative: EnipConfig parses vendor
# id, product name, serial number and the rest, and then nothing but two
# logger.debug lines ever reads them. The identity actually served comes from
# cpppo's own class defaults in `device.Identity` -- a Rockwell 1756-L61/B
# LOGIX5561, vendor 1, serial 0x006C061A, status word 0x3160 -- so every
# Conpot ENIP endpoint on the internet answers ListIdentity with the same
# byte-for-byte fingerprint, and the template's own values were fiction.
#
# cpppo's supported way to change them is `Object.config_loader`, read once
# per Object at construction. Populating it from the template makes the
# template mean what it says (and makes H11's per-persona templates able to
# vary the identity at all).
#
# Element name -> cpppo config key, in the [Identity] section.
_IDENTITY_CONFIG_KEYS = (
    ("vendor_id", "Vendor Number"),
    ("device_type", "Device Type"),
    ("product_code", "Product Code Number"),
    ("product_rev", "Product Revision"),
    ("serial_number", "Serial Number"),
    ("product_name", "Product Name"),
    ("status_word", "Status Word"),
)

_VALID_MODES = frozenset({"tcp", "udp"})

# ── Session capture (Phase 2 step H10) ────────────────────────────────────
#
# Before this, an ENIP session carried NEW_CONNECTION, CONNECTION_CLOSED and
# CONNECTION_FAILED and nothing else -- the same blind spot the IEC-104 fork
# patch closed for port 2404 (c8e4b31). A ListIdentity banner grab, a tag read
# and a tag WRITE all left byte-identical records.

# EtherNet/IP encapsulation commands (CIP Vol 2, ch. 2).
_ENIP_COMMANDS = {
    0x0000: "nop",
    0x0004: "list_services",
    0x0063: "list_identity",
    0x0064: "list_interfaces",
    0x0065: "register_session",
    0x0066: "unregister_session",
    0x006F: "send_rr_data",
    0x0070: "send_unit_data",
}

# CIP service codes, request side. Common services plus the Logix tag services
# an attacker's tooling actually uses.
_CIP_SERVICES = {
    0x01: "get_attributes_all",
    0x02: "set_attributes_all",
    0x03: "get_attribute_list",
    0x04: "set_attribute_list",
    0x05: "reset",
    0x06: "start",
    0x07: "stop",
    0x08: "create",
    0x09: "delete",
    0x0A: "multiple_service_packet",
    0x0D: "apply_attributes",
    0x0E: "get_attribute_single",
    0x10: "set_attribute_single",
    0x14: "restore",
    0x15: "save",
    0x16: "nop",
    0x4C: "read_tag",
    0x4D: "write_tag",
    0x4E: "read_modify_write_tag",
    0x52: "read_tag_fragmented",
    0x53: "write_tag_fragmented",
    0x54: "forward_open",
}

# Services whose payload is the value the ATTACKER supplied. For every other
# service cpppo writes the response payload back into the same request
# sub-dict while it builds the reply, so reporting `.data` for a read would
# publish our own answer as though the attacker had sent it.
_CIP_WRITE_SERVICES = frozenset(
    {0x02, 0x04, 0x05, 0x06, 0x07, 0x0D, 0x10, 0x4D, 0x4E, 0x53}
)

# Same 64-element ceiling the forwarder puts on a Modbus write list, for the
# same reason: this rides in a STIX SCO, a JSONB column and an LLM prompt.
_MAX_CIP_VALUES = 64

_SEGMENT_RE = re.compile(r"\.path\.segment\[(\d+)\]\.(\w+)$")


class EnipConfig(object):
    """
    Configurations parsed from template
    """

    def __init__(self, template):
        self.template = template
        self._mode = ""
        self.modes = frozenset()
        self.status_word = None
        self.parse_template()

    # `mode` stays a plain attribute from the outside -- the test suite sets
    # `self.config.mode = "tcp"` directly -- but a write now recomputes the
    # parsed set, so a template saying "tcp,udp" serves both without the
    # caller having to know which spelling it got.
    @property
    def mode(self):
        return self._mode

    @mode.setter
    def mode(self, value):
        self._mode = value
        self.modes = frozenset(
            part
            for part in str(value or "").replace(",", " ").lower().split()
            if part
        )

    class Tag(object):
        """
        Represents device tag setting parsed from template
        """

        def __init__(self, name, type, size, value, addr=None):
            self.name = name
            self.type = str(type).upper()
            self.size = size
            self.value = value
            self.addr = addr

    def parse_template(self):
        dom = etree.parse(self.template)
        self.server_addr = dom.xpath("//enip/@host")[0]
        self.server_port = int(dom.xpath("//enip/@port")[0])
        self.vendor_id = int(dom.xpath("//enip/device_info/VendorId/text()")[0])
        self.device_type = int(dom.xpath("//enip/device_info/DeviceType/text()")[0])
        self.product_rev = int(
            dom.xpath("//enip/device_info/ProductRevision/text()")[0]
        )
        self.product_code = int(dom.xpath("//enip/device_info/ProductCode/text()")[0])
        self.product_name = dom.xpath("//enip/device_info/ProductName/text()")[0]
        self.serial_number = dom.xpath("//enip/device_info/SerialNumber/text()")[0]
        # Optional (step H10). Absent leaves cpppo's 0x3160 default, which is
        # itself a Conpot fingerprint -- see the note at _IDENTITY_CONFIG_KEYS.
        status_word = dom.xpath("//enip/device_info/StatusWord/text()")
        self.status_word = int(status_word[0], 0) if status_word else None
        self.mode = dom.xpath("//enip/mode/text()")[0]
        assert self.modes and self.modes <= _VALID_MODES, (
            "Invalid ENIP mode %r; expected tcp, udp, or both" % (self._mode,)
        )
        self.timeout = float(dom.xpath("//enip/timeout/text()")[0])
        self.latency = float(dom.xpath("//enip/latency/text()")[0])

        # parse device tags, these tags will be further processed by the ENIP server
        self.dtags = []
        for t in dom.xpath("//enip/tags/tag"):
            name = t.xpath("@name")[0]
            type = t.xpath("type/text()")[0]
            value = t.xpath("value/text()")[0]
            addr = t.xpath("addr/text()")[0]
            size = 1
            try:
                size = int(t.xpath("size/text()")[0])
            except:
                raise AssertionError("Invalid tag size: %r" % size)

            self.dtags.append(self.Tag(name, type, size, value, addr))


@conpot_protocol
class EnipServer(object):
    """
    Ethernet/IP server
    """

    def __init__(self, template, template_directory, args):
        self.config = EnipConfig(template)
        self.addr = self.config.server_addr
        self.port = self.config.server_port
        self.connections = cpppo.dotdict()
        self.control = None

        # Before any tag is created, so the Identity Object picks the
        # template's values up when cpppo constructs it.
        self.apply_identity()

        # all known tags
        self.tags = cpppo.dotdict()
        self.set_tags()

        logger.debug("ENIP server serial number: " + self.config.serial_number)
        logger.debug("ENIP server product name: " + self.config.product_name)

    def apply_identity(self):
        """Push the template's <device_info> into cpppo's Identity Object.

        `Object.config_loader` is cpppo's own extension point and is read once
        per Object at construction, so this has to run before the first ENIP
        request builds the Identity instance. It is class-level and therefore
        process-global: one Conpot process serves one ENIP template, which is
        the only configuration Conpot's loader can produce.

        Fails open. A cpppo release that renames a config key would otherwise
        stop the ENIP server from starting, and a wrong banner is a smaller
        problem than a dead bait port.
        """
        values = {}
        for attr, key in _IDENTITY_CONFIG_KEYS:
            value = getattr(self.config, attr, None)
            if value is None:
                continue
            values[key] = str(value)
        if not values:
            return
        try:
            device.Object.config_loader.read_dict({"Identity": values})
        except Exception as exc:
            logger.warning(
                "ENIP identity not applied; serving cpppo defaults: %s", exc
            )

    @staticmethod
    def _cip_request_facts(data):
        """Pull the CIP service and target path out of cpppo's parsed request.

        Read AFTER `enip_process` has run, because that is what parses the CIP
        layer at all -- before the call there is only `request.enip.input`, an
        opaque bytearray.

        Two consequences of reading after, both handled here rather than left
        for a reader to trip over:

        * cpppo ORs 0x80 into `service` when it turns the parsed request into
          the reply, so the request's own service code is `service & 0x7F`.
          Masking is idempotent for any real request code (all < 0x80), so it
          is safe whether or not the reply has been built yet.
        * the reply's payload is written back into the *request* sub-dict, so
          `.data` under a read service is our answer, not the attacker's
          input. Only the write services in `_CIP_WRITE_SERVICES` report it.
        """
        facts = {}
        try:
            keys = list(data.keys())
        except Exception:  # pragma: no cover - defensive
            return facts

        prefix = "request.enip.CIP."
        cip_keys = [k for k in keys if k.startswith(prefix)]
        if not cip_keys:
            return facts

        service_keys = sorted(k for k in cip_keys if k.endswith(".request.service"))
        if not service_keys:
            return facts
        service_key = service_keys[0]
        request_prefix = service_key[: -len(".service")]

        try:
            service = int(data.get(service_key)) & 0x7F
        except (TypeError, ValueError):
            return facts
        facts["cip_service"] = service
        name = _CIP_SERVICES.get(service)
        if name:
            facts["cip_service_name"] = name

        segments = {}
        segment_prefix = request_prefix + ".path.segment["
        for key in cip_keys:
            if not key.startswith(segment_prefix):
                continue
            found = _SEGMENT_RE.search(key)
            if not found:
                continue
            segments.setdefault(int(found.group(1)), {})[found.group(2)] = data.get(key)

        symbols = []
        for index in sorted(segments):
            for seg_name, seg_value in segments[index].items():
                if seg_name == "symbolic":
                    symbols.append(str(seg_value))
                elif seg_name in ("class", "instance", "attribute", "element"):
                    try:
                        facts.setdefault("cip_" + seg_name, int(seg_value))
                    except (TypeError, ValueError):
                        pass
        if symbols:
            facts["cip_symbol"] = ".".join(symbols)

        # One rendered target for the analyst, alongside the parts the rules
        # match on. Symbolic addressing wins when present: that is how the
        # attacker wrote it.
        if "cip_symbol" in facts:
            path = facts["cip_symbol"]
            if "cip_element" in facts:
                path += "[%d]" % facts["cip_element"]
            facts["cip_path"] = path
        elif "cip_class" in facts:
            path = "@0x%02X" % facts["cip_class"]
            if "cip_instance" in facts:
                path += "/%d" % facts["cip_instance"]
            if "cip_attribute" in facts:
                path += "/%d" % facts["cip_attribute"]
            facts["cip_path"] = path

        if service in _CIP_WRITE_SERVICES:
            for key in cip_keys:
                if not key.startswith(request_prefix + "."):
                    continue
                if not key.endswith(".data"):
                    continue
                value = data.get(key)
                if not isinstance(value, (list, tuple)):
                    continue
                values = list(value)
                if len(values) > _MAX_CIP_VALUES:
                    facts["cip_values_truncated"] = True
                    values = values[:_MAX_CIP_VALUES]
                facts["cip_written_values"] = values
                break

        return facts

    def _record_request_event(self, session, data, enip_command):
        """Log one ENIP transaction onto the AttackSession.

        Fails open: an observability write must never stop the bait port
        answering, so anything unexpected degrades to no event rather than
        raising into the request loop.
        """
        if session is None:
            return
        try:
            facts = {}
            if enip_command is not None:
                try:
                    command = int(enip_command)
                except (TypeError, ValueError):
                    command = None
                if command is not None:
                    facts["enip_command"] = command
                    name = _ENIP_COMMANDS.get(command)
                    if name:
                        facts["enip_command_name"] = name
            facts.update(self._cip_request_facts(data))
            if facts:
                session.add_event({"request": facts})
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("ENIP session capture failed: %s", exc)

    def stats_for(self, peer):
        if peer is None:
            return None, None
        connkey = "%s_%d" % (peer[0].replace(".", "_"), peer[1])
        stats = self.connections.get(connkey)
        if stats is not None:
            return stats, connkey
        stats = cpppo.apidict(timeout=self.config.timeout)
        self.connections[connkey] = stats
        stats["requests"] = 0
        stats["received"] = 0
        stats["eof"] = False
        stats["interface"] = peer[0]
        stats["port"] = peer[1]
        return stats, connkey

    def handle(self, conn, address, enip_process=None, delay=None, **kwds):
        """
        Handle an incoming connection
        """
        host, port = address if address else ("UDP", "UDP")
        name = "ENIP_%s" % port
        session = conpot_core.get_session(
            "enip", host, port, conn.getsockname()[0], conn.getsockname()[1]
        )
        logger.debug("ENIP server %s begins serving client %s", name, address)

        tcp = conn.family == socket.AF_INET and conn.type == socket.SOCK_STREAM
        udp = conn.family == socket.AF_INET and conn.type == socket.SOCK_DGRAM

        if tcp:
            session.add_event({"type": "NEW_CONNECTION"})
        else:
            # Step H10: the UDP branch is handed the one listening socket for
            # every peer, so `address` is None and this session's source_ip is
            # the literal string "UDP". Announcing that as a connection would
            # ship a session whose source is not an address at all; handle_udp
            # opens a real per-peer session once a datagram says who sent it.
            logger.debug("ENIP UDP listener ready; sessions open per datagram")

        if tcp:
            try:
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception as e:
                logger.error(
                    "%s unable to set TCP_NODELAY for client %r: %s", name, address, e
                )
            try:
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            except Exception as e:
                logger.error(
                    "%s unable to set SO_KEEPALIVE for client %r: %s", name, address, e
                )
            self.handle_tcp(
                conn,
                address,
                session,
                name=name,
                enip_process=enip_process,
                delay=delay,
                **kwds,
            )
        elif udp:
            self.handle_udp(
                conn, name=name, enip_process=enip_process, session=session, **kwds
            )
        else:
            raise NotImplementedError("Unknown socket protocol for EtherNet/IP CIP")

    def handle_tcp(
        self, conn, address, session, name, enip_process, delay=None, **kwds
    ):
        """
        Handle a TCP client
        """
        source = cpppo.rememberable()
        with parser.enip_machine(name=name, context="enip") as machine:
            try:
                assert (
                    address
                ), "EtherNet/IP CIP server for TCP/IP must be provided a peer address"
                stats, connkey = self.stats_for(address)
                while not stats.eof:
                    data = cpppo.dotdict()
                    source.forget()
                    # If no/partial EtherNet/IP header received, parsing will fail with a NonTerminal
                    # Exception (dfa exits in non-terminal state).  Build data.request.enip:
                    begun = cpppo.timer()
                    with contextlib.closing(
                        machine.run(path="request", source=source, data=data)
                    ) as engine:
                        # PyPy compatibility; avoid deferred destruction of generators
                        for _, sta in engine:
                            if sta is not None:
                                continue
                            # No more transitions available.  Wait for input.  EOF (b'') will lead to
                            # termination.  We will simulate non-blocking by looping on None (so we can
                            # check our options, in case they've been changed).  If we still have input
                            # available to process right now in 'source', we'll just check (0 timeout);
                            # otherwise, use the specified server.control.latency.
                            msg = None
                            while msg is None and not stats.eof:
                                wait = (
                                    kwds["server"]["control"]["latency"]
                                    if source.peek() is None
                                    else 0
                                )
                                brx = cpppo.timer()
                                msg = network.recv(conn, timeout=wait)
                                now = cpppo.timer()
                                (logger.info if msg else logger.debug)(
                                    "Transaction receive after %7.3fs (%5s bytes in %7.3f/%7.3fs)",
                                    now - begun,
                                    len(msg) if msg is not None else "None",
                                    now - brx,
                                    wait,
                                )

                                # After each block of input (or None), check if the server is being
                                # signalled done/disabled; we need to shut down so signal eof.  Assumes
                                # that (shared) server.control.{done,disable} dotdict be in kwds.  We do
                                # *not* read using attributes here, to avoid reporting completion to
                                # external APIs (eg. web) awaiting reception of these signals.
                                if (
                                    kwds["server"]["control"]["done"]
                                    or kwds["server"]["control"]["disable"]
                                ):
                                    logger.info(
                                        "%s done, due to server done/disable",
                                        machine.name_centered(),
                                    )
                                    stats["eof"] = True
                                if msg is not None:
                                    stats["received"] += len(msg)
                                    stats["eof"] = stats["eof"] or not len(msg)
                                    if logger.getEffectiveLevel() <= logging.INFO:
                                        logger.info(
                                            "%s recv: %5d: %s",
                                            machine.name_centered(),
                                            len(msg),
                                            cpppo.reprlib.repr(msg),
                                        )
                                    source.chain(msg)
                                else:
                                    # No input.  If we have symbols available, no problem; continue.
                                    # This can occur if the state machine cannot make a transition on
                                    # the input symbol, indicating an unacceptable sentence for the
                                    # grammar.  If it cannot make progress, the machine will terminate
                                    # in a non-terminal state, rejecting the sentence.
                                    if source.peek() is not None:
                                        break
                                        # We're at a None (can't proceed), and no input is available.  This
                                        # is where we implement "Blocking"; just loop.

                    logger.info(
                        "Transaction parsed  after %7.3fs", cpppo.timer() - begun
                    )
                    # Terminal state and EtherNet/IP header recognized, or clean EOF (no partial
                    # message); process and return response
                    if "request" in data:
                        stats["requests"] += 1
                    try:
                        # enip_process must be able to handle no request (empty data), indicating the
                        # clean termination of the session if closed from this end (not required if
                        # enip_process returned False, indicating the connection was terminated by
                        # request.)
                        delayseconds = 0  # response delay (if any)
                        # Step H10: the encapsulation command is read before
                        # the call and the CIP layer after it, because
                        # enip_process is what parses CIP at all. The event is
                        # recorded whichever way the call goes, so a request
                        # that ends the session is captured like any other.
                        enip_command = data.get("request.enip.command")
                        processed = enip_process(address, data=data, **kwds)
                        self._record_request_event(session, data, enip_command)
                        if processed:
                            # Produce an EtherNet/IP response carrying the encapsulated response data.
                            # If no encapsulated data, ensure we also return a non-zero EtherNet/IP
                            # status.  A non-zero status indicates the end of the session.
                            assert (
                                "response.enip" in data
                            ), "Expected EtherNet/IP response; none found"
                            if (
                                "input" not in data.response.enip
                                or not data.response.enip.input
                            ):
                                logger.warning(
                                    "Expected EtherNet/IP response encapsulated message; none found"
                                )
                                assert (
                                    data.response.enip.status
                                ), "If no/empty response payload, expected non-zero EtherNet/IP status"

                            rpy = parser.enip_encode(data.response.enip)
                            if logger.getEffectiveLevel() <= logging.INFO:
                                logger.info(
                                    "%s send: %5d: %s %s",
                                    machine.name_centered(),
                                    len(rpy),
                                    cpppo.reprlib.repr(rpy),
                                    ("delay: %r" % delay) if delay else "",
                                )
                            if delay:
                                # A delay (anything with a delay.value attribute) == #[.#] (converible
                                # to float) is ok; may be changed via web interface.
                                try:
                                    delayseconds = float(
                                        delay.value
                                        if hasattr(delay, "value")
                                        else delay
                                    )
                                    if delayseconds > 0:
                                        time.sleep(delayseconds)
                                except Exception as exc:
                                    logger.info(
                                        "Unable to delay; invalid seconds: %r", delay
                                    )
                            try:
                                conn.send(rpy)
                            except socket.error as exc:
                                logger.info("Session ended (client abandoned): %s", exc)
                                stats["eof"] = True
                            if data.response.enip.status:
                                logger.warning(
                                    "Session ended (server EtherNet/IP status: 0x%02x == %d)",
                                    data.response.enip.status,
                                    data.response.enip.status,
                                )
                                stats["eof"] = True
                        else:
                            # Session terminated.  No response, just drop connection.
                            if logger.getEffectiveLevel() <= logging.INFO:
                                logger.info(
                                    "Session ended (client initiated): %s",
                                    parser.enip_format(data),
                                )
                            stats["eof"] = True
                        logger.info(
                            "Transaction complete after %7.3fs (w/ %7.3fs delay)",
                            cpppo.timer() - begun,
                            delayseconds,
                        )
                        session.add_event({"type": "CONNECTION_CLOSED"})
                    except:
                        logger.error("Failed request: %s", parser.enip_format(data))
                        enip_process(address, data=cpppo.dotdict())  # Terminate.
                        raise

                stats["processed"] = source.sent
            except:
                # Parsing failure.
                stats["processed"] = source.sent
                memory = bytes(bytearray(source.memory))
                pos = len(source.memory)
                future = bytes(bytearray(b for b in source))
                where = "at %d total bytes:\n%s\n%s (byte %d)" % (
                    stats.processed,
                    repr(memory + future),
                    "-" * (len(repr(memory)) - 1) + "^",
                    pos,
                )
                logger.error(
                    "EtherNet/IP error %s\n\nFailed with exception:\n%s\n",
                    where,
                    "".join(traceback.format_exception(*sys.exc_info())),
                )
                raise
            finally:
                # Not strictly necessary to close (network.server_main will discard the socket,
                # implicitly closing it), but we'll do it explicitly here in case the thread doesn't die
                # for some other reason.  Clean up the connections entry for this connection address.
                self.connections.pop(connkey, None)
                logger.info(
                    "%s done; processed %3d request%s over %5d byte%s/%5d received (%d connections remain)",
                    name,
                    stats.requests,
                    " " if stats.requests == 1 else "s",
                    stats.processed,
                    " " if stats.processed == 1 else "s",
                    stats.received,
                    len(self.connections),
                )
                sys.stdout.flush()
                conn.close()

    def handle_udp(self, conn, name, enip_process, session, **kwds):
        """
        Process UDP packets from multiple clients
        """
        with parser.enip_machine(name=name, context="enip") as machine:
            while (
                not kwds["server"]["control"]["done"]
                and not kwds["server"]["control"]["disable"]
            ):
                try:
                    source = cpppo.rememberable()
                    data = cpppo.dotdict()

                    # If no/partial EtherNet/IP header received, parsing will fail with a NonTerminal
                    # Exception (dfa exits in non-terminal state).  Build data.request.enip:
                    begun = cpppo.timer()  # waiting for next transaction
                    addr, stats = None, None
                    peer_session = None
                    with contextlib.closing(
                        machine.run(path="request", source=source, data=data)
                    ) as engine:
                        # PyPy compatibility; avoid deferred destruction of generators
                        for _, sta in engine:
                            if sta is not None:
                                # No more transitions available.  Wait for input.
                                continue
                            assert not addr, "Incomplete UDP request from client %r" % (
                                addr
                            )
                            msg = None
                            while msg is None:
                                # For UDP, we'll allow no input only at the start of a new request parse
                                # (addr is None); anything else will be considered a failed request Back
                                # to the trough for more symbols, after having already received a packet
                                # from a peer?  No go!
                                wait = (
                                    kwds["server"]["control"]["latency"]
                                    if source.peek() is None
                                    else 0
                                )
                                brx = cpppo.timer()
                                msg, frm = network.recvfrom(conn, timeout=wait)
                                now = cpppo.timer()
                                if not msg:
                                    if (
                                        kwds["server"]["control"]["done"]
                                        or kwds["server"]["control"]["disable"]
                                    ):
                                        return
                                (logger.info if msg else logger.debug)(
                                    "Transaction receive after %7.3fs (%5s bytes in %7.3f/%7.3fs): %r",
                                    now - begun,
                                    len(msg) if msg is not None else "None",
                                    now - brx,
                                    wait,
                                    self.stats_for(frm)[0],
                                )
                                # If we're at a None (can't proceed), and we haven't yet received input,
                                # then this is where we implement "Blocking"; we just loop for input.

                            # We have received exactly one packet from an identified peer!
                            begun = now
                            addr = frm
                            stats, _ = self.stats_for(addr)
                            # Step H10: a real session for THIS peer. The
                            # outer `session` belongs to the shared listening
                            # socket and carries source_ip "UDP" -- every UDP
                            # peer would otherwise share one session whose
                            # source is not an address.
                            peer_session = conpot_core.get_session(
                                "enip",
                                addr[0],
                                addr[1],
                                get_interface_ip(addr[0]),
                                conn.getsockname()[1],
                            )
                            # For UDP, we don't ever receive incoming EOF, or set stats['eof'].
                            # However, we can respond to a manual eof (eg. from web interface) by
                            # ignoring the peer's packets.
                            assert stats and not stats.get(
                                "eof"
                            ), "Ignoring UDP request from client %r: %r" % (addr, msg)
                            stats["received"] += len(msg)
                            logger.debug(
                                "%s recv: %5d: %s",
                                machine.name_centered(),
                                len(msg),
                                cpppo.reprlib.repr(msg),
                            )
                            source.chain(msg)

                    # Terminal state and EtherNet/IP header recognized; process and return response
                    assert stats
                    if "request" in data:
                        stats["requests"] += 1
                    # enip_process must be able to handle no request (empty data), indicating the
                    # clean termination of the session if closed from this end (not required if
                    # enip_process returned False, indicating the connection was terminated by
                    # request.)
                    enip_command = data.get("request.enip.command")
                    processed = enip_process(addr, data=data, **kwds)
                    self._record_request_event(peer_session, data, enip_command)
                    if processed:
                        # Produce an EtherNet/IP response carrying the encapsulated response data.
                        # If no encapsulated data, ensure we also return a non-zero EtherNet/IP
                        # status.  A non-zero status indicates the end of the session.
                        assert (
                            "response.enip" in data
                        ), "Expected EtherNet/IP response; none found"
                        if (
                            "input" not in data.response.enip
                            or not data.response.enip.input
                        ):
                            logger.warning(
                                "Expected EtherNet/IP response encapsulated message; none found"
                            )
                            assert (
                                data.response.enip.status
                            ), "If no/empty response payload, expected non-zero EtherNet/IP status"

                        rpy = parser.enip_encode(data.response.enip)
                        logger.debug(
                            "%s send: %5d: %s",
                            machine.name_centered(),
                            len(rpy),
                            cpppo.reprlib.repr(rpy),
                        )
                        conn.sendto(rpy, addr)

                    logger.debug(
                        "Transaction complete after %7.3fs", cpppo.timer() - begun
                    )
                    (peer_session or session).add_event({"type": "CONNECTION_CLOSED"})
                    stats["processed"] = source.sent
                except:
                    # Parsing failure.  Suck out some remaining input to give us some context, but don't re-raise
                    if stats:
                        stats["processed"] = source.sent
                    memory = bytes(bytearray(source.memory))
                    pos = len(source.memory)
                    future = bytes(bytearray(b for b in source))
                    where = "at %d total bytes:\n%s\n%s (byte %d)" % (
                        stats.get("processed", 0) if stats else 0,
                        repr(memory + future),
                        "-" * (len(repr(memory)) - 1) + "^",
                        pos,
                    )
                    logger.error(
                        "Client %r EtherNet/IP error %s\n\nFailed with exception:\n%s\n",
                        addr,
                        where,
                        "".join(traceback.format_exception(*sys.exc_info())),
                    )
                    (peer_session or session).add_event({"type": "CONNECTION_FAILED"})

    def set_tags(self):
        typenames = {
            "BOOL": (parser.BOOL, 0, lambda v: bool(v)),
            "INT": (parser.INT, 0, lambda v: int(v)),
            "DINT": (parser.DINT, 0, lambda v: int(v)),
            "SINT": (parser.SINT, 0, lambda v: int(v)),
            "REAL": (parser.REAL, 0.0, lambda v: float(v)),
            "SSTRING": (parser.SSTRING, "", lambda v: str(v)),
            "STRING": (parser.STRING, "", lambda v: str(v)),
        }

        for t in self.config.dtags:
            tag_name = t.name
            tag_type = t.type
            tag_size = t.size

            assert tag_type in typenames, "Invalid tag type; must be one of %r" % list(
                typenames
            )
            tag_class, _, f = typenames[tag_type]
            tag_value = f(t.value)

            tag_address = t.addr
            logger.debug("tag address: %s", tag_address)

            path, attribute = None, None
            if tag_address:
                # Resolve the @cls/ins/att, and optionally [elm] or /elm
                segments, _, cnt = device.parse_path_elements("@" + tag_address)
                assert (
                    not cnt or cnt == 1
                ), "A Tag may be specified to indicate a single element: %s" % (
                    tag_address
                )
                path = {"segment": segments}
                cls, ins, att = device.resolve(path, attribute=True)
                assert ins > 0, "Cannot specify the Class' instance for a tag's address"
                elm = device.resolve_element(path)
                # Look thru defined tags for one assigned to same cls/ins/att (maybe different elm);
                # must be same type/size.
                for tn, te in dict.items(self.tags):
                    if not te["path"]:
                        continue  # Ignore tags w/o pre-defined path...
                    if device.resolve(te["path"], attribute=True) == (cls, ins, att):
                        assert (
                            te.attribute.parser.__class__ is tag_class
                            and len(te.attribute) == tag_size
                        ), "Incompatible Attribute types for tags %r and %r" % (
                            tn,
                            tag_name,
                        )
                        attribute = te.attribute
                        break

            if not attribute:
                # No Attribute found
                attribute = device.Attribute(
                    tag_name,
                    tag_class,
                    default=(tag_value if tag_size == 1 else [tag_value] * tag_size),
                )

            # Ready to create the tag and its Attribute (and error code to return, if any).  If tag_size
            # is 1, it will be a scalar Attribute.  Since the tag_name may contain '.', we don't want
            # the normal dotdict.__setitem__ resolution to parse it; use plain dict.__setitem__.
            logger.debug(
                "Creating tag: %-14s%-10s %10s[%4d]",
                tag_name,
                "@" + tag_address if tag_address else "",
                attribute.parser.__class__.__name__,
                len(attribute),
            )
            tag_entry = cpppo.dotdict()
            tag_entry.attribute = (
                attribute  # The Attribute (may be shared by multiple tags)
            )
            tag_entry.path = (
                path  # Desired Attribute path (may include element), or None
            )
            tag_entry.error = 0x00
            dict.__setitem__(self.tags, tag_name, tag_entry)

    def start(self, host, port):
        srv_ctl = cpppo.dotdict()
        srv_ctl.control = cpppo.apidict(timeout=self.config.timeout)
        srv_ctl.control["done"] = False
        srv_ctl.control["disable"] = False
        srv_ctl.control.setdefault("latency", self.config.latency)

        options = cpppo.dotdict()
        options.setdefault("enip_process", logix.process)
        kwargs = dict(options, tags=self.tags, server=srv_ctl)

        # Step H10: `mode` may name both. A real EtherNet/IP device answers
        # explicit messaging on 44818/tcp AND ListIdentity discovery on
        # 44818/udp, and the discovery half is what scanners actually send;
        # serving only one of the two is itself a tell.
        tcp_mode = "tcp" in self.config.modes
        udp_mode = "udp" in self.config.modes

        self.control = srv_ctl.control

        logger.debug(
            "ENIP server started on: %s:%d, mode: %s" % (host, port, self.config.mode)
        )
        while not self.control["done"]:
            network.server_main(
                address=(host, port),
                target=self.handle,
                kwargs=kwargs,
                udp=udp_mode,
                tcp=tcp_mode,
            )

    def stop(self):
        logger.debug("Stopping ENIP server")
        self.control["done"] = True
