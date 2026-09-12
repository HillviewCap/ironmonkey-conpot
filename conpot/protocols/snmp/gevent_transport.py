# Gevent UDP transport + dispatcher for PySNMP 7.x (asyncio is default; conpot uses gevent).
import logging
import socket

from pysnmp.carrier.asyncio.dgram.udp import UdpTransportAddress
from pysnmp.carrier.base import AbstractTransport, AbstractTransportDispatcher

import conpot.core as conpot_core
from conpot.protocols.snmp import message_peek
from conpot.utils.networking import get_interface_ip

logger = logging.getLogger(__name__)


class GeventDispatcher(AbstractTransportDispatcher):
    """Drive PySNMP with a blocking gevent-cooperative UDP recv loop."""

    #: Community strings the SNMP engine will actually answer. Set by
    #: ``CommandResponder`` once the transport is registered; ``None`` -- the
    #: default, and what the client dispatcher keeps -- disables
    #: unanswered-datagram logging entirely.
    accepted_communities = None

    def __init__(self):
        super().__init__()
        self.socket = None
        self._running = False
        self._udp_transport = None
        self._unanswered_budget = message_peek.UnansweredBudget()

    def register_transport(self, tDomain, transport):
        super().register_transport(tDomain, transport)
        self._udp_transport = transport
        self.socket = transport.sock

    def register_timer_callback(self, timerCbFun, tickInterval=None):
        # Match legacy conpot/pysnmp4 behavior: timers were not wired to the gevent loop.
        pass

    def unregister_timer_callback(self, timerCbFun=None):
        pass

    def run_dispatcher(self, timeout=0.0):
        self._running = True
        sock = self._udp_transport.sock
        while self._running:
            try:
                msg, addr = sock.recvfrom(65507)
            except OSError:
                break
            # Step H10: read the version and community off the wire before
            # pysnmp gets the message. The responder that answers it consumes
            # this (conpot_cmdrsp.conpot_extension.log); one that is never
            # reached leaves it unconsumed, which is the only trace a rejected
            # community ever produces.
            peeked = message_peek.observe(msg, addr)
            try:
                self._callback_function(
                    self._udp_transport, UdpTransportAddress(addr), msg
                )
            finally:
                self._log_unanswered(peeked, sock)
                message_peek.clear()

    def _log_unanswered(self, peeked, sock):
        """Record a datagram the SNMP engine never answered.

        Fires only for a community the engine does not accept. That is a
        credential guess, and it is the one SNMP fact that otherwise leaves no
        trace at all: the security model drops the message before any
        responder runs, so nothing downstream ever learns it happened.

        A datagram carrying an ACCEPTED community that still went unanswered
        was refused by the DoS-evasion table
        (``DatabusMediator.update_evasion_table``). That is a flood, and
        turning a flood of datagrams into a flood of events would make the
        sensor amplify it into our own pipeline, so it is deliberately not
        logged -- the first requests of that same flood were logged normally
        before the threshold tripped.

        Fails open. An observability write must never take down a protocol.
        """
        if self.accepted_communities is None:
            return
        if peeked is None or peeked.answered or peeked.addr is None:
            return
        community = peeked.community
        if community is None or community in self.accepted_communities:
            return
        if not self._unanswered_budget.allow(peeked.addr[0]):
            return
        try:
            session = conpot_core.get_session(
                "snmp",
                peeked.addr[0],
                peeked.addr[1],
                get_interface_ip(peeked.addr[0]),
                sock.getsockname()[1],
            )
            label = message_peek.version_label(peeked.version) or "?"
            session.add_event(
                {
                    "type": "SNMPv{0} Unanswered".format(label),
                    "request": {
                        "community": community,
                        "version": label,
                        "answered": False,
                    },
                }
            )
        except Exception as exc:
            logger.warning("SNMP unanswered-datagram logging failed: %s", exc)

    def close_dispatcher(self):
        self._running = False
        super().close_dispatcher()

    def serve_forever(self):
        self.run_dispatcher()

    def stop(self):
        self._running = False
        if self.socket:
            try:
                self.socket.close()
            except OSError:
                pass


class ClientGeventDispatcher(GeventDispatcher):
    """Like GeventDispatcher but stops when the SNMP engine has no pending jobs (client I/O)."""

    def run_dispatcher(self, timeout=0.0):
        self._running = True
        sock = self._udp_transport.sock
        # SNMPv3 may need multiple round-trips (e.g. discovery + command); drain until idle.
        for _ in range(32):
            if not self._running:
                break
            try:
                msg, addr = sock.recvfrom(65507)
            except OSError:
                break
            self._callback_function(self._udp_transport, UdpTransportAddress(addr), msg)
            if not self.jobs_are_pending():
                break


class GeventUdpTransport(AbstractTransport):
    """UDP transport using an already-bound gevent socket."""

    PROTO_TRANSPORT_DISPATCHER = GeventDispatcher
    ADDRESS_TYPE = UdpTransportAddress

    def __init__(self, sock: socket.socket):
        super().__init__()
        self.sock = sock

    def open_server_mode(self, iface=None, sock=None):
        return self

    def send_message(self, outgoingMessage, transportAddress):
        if isinstance(transportAddress, UdpTransportAddress):
            addr = tuple(transportAddress[:2])
        else:
            addr = tuple(transportAddress[:2])
        self.sock.sendto(outgoingMessage, addr)

    def close_transport(self):
        try:
            self.sock.close()
        except OSError:
            pass
        super().close_transport()


class GeventClientUdpTransport(GeventUdpTransport):
    """UDP client transport: dispatcher exits after one request/response cycle."""

    PROTO_TRANSPORT_DISPATCHER = ClientGeventDispatcher
