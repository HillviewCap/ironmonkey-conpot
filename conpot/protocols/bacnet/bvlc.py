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

"""BACnet/IP link layer: BVLC (ASHRAE 135 Annex J) and NPDU (clause 6.2).

Phase 2 step H10c, and the reason real-world BACnet capture on this persona
was ~0 after H10 shipped.

`BacnetServer.handle` decoded every datagram as a BARE APDU. Nothing on a
BACnet/IP network ever sends one: every standards-conforming client wraps its
APDU in an NPDU and that in a BVLC header, so `nmap --script bacnet-info`,
every commercial scanner and a hand-built ReadProperty all hit `DecodingError`
on byte 0 (`0x81`, the BVLC type, is APDU type 8 = reserved). The session that
datagram opened therefore carried a `NEW_CONNECTION` event and nothing else,
and a `NEW_CONNECTION`-only session never becomes a `honeypot_sessions` row.
Verified against the deployed New York sensor on 2026-09-12: the bare-APDU
form of a ReadProperty answered and was recorded, the framed form of the same
request logged `DecodingError` and vanished.

This module is deliberately a pure bytes-in/bytes-out codec with no bacpypes
import, for two reasons. It is the part an attacker reaches first, so it must
be readable end to end and total -- no input may raise past `unwrap`. And the
tests can then build their fixtures with bacpypes' own encoder and check this
implementation against a real BACnet stack rather than against itself.

Wire format, for the two headers this strips:

    BVLC   0x81 | function | length (2, big-endian, INCLUDING these 4 bytes)
    NPDU   version | control | [DNET DLEN DADR] | [SNET SLEN SADR] | [hop]

    control bits: 0x80 network-layer message   0x20 destination specifier
                  0x08 source specifier        0x04 expecting reply
                  0x03 priority
"""

import logging

logger = logging.getLogger(__name__)

BVLC_TYPE = 0x81

# BVLL functions (Annex J.2).
RESULT = 0x00
WRITE_BDT = 0x01
READ_BDT = 0x02
READ_BDT_ACK = 0x03
FORWARDED_NPDU = 0x04
REGISTER_FOREIGN_DEVICE = 0x05
READ_FDT = 0x06
READ_FDT_ACK = 0x07
DELETE_FDT_ENTRY = 0x08
DISTRIBUTE_BROADCAST_TO_NETWORK = 0x09
ORIGINAL_UNICAST_NPDU = 0x0A
ORIGINAL_BROADCAST_NPDU = 0x0B
SECURE_BVLL = 0x0C

FUNCTION_NAMES = {
    RESULT: "Result",
    WRITE_BDT: "WriteBroadcastDistributionTable",
    READ_BDT: "ReadBroadcastDistributionTable",
    READ_BDT_ACK: "ReadBroadcastDistributionTableAck",
    FORWARDED_NPDU: "ForwardedNPDU",
    REGISTER_FOREIGN_DEVICE: "RegisterForeignDevice",
    READ_FDT: "ReadForeignDeviceTable",
    READ_FDT_ACK: "ReadForeignDeviceTableAck",
    DELETE_FDT_ENTRY: "DeleteForeignDeviceTableEntry",
    DISTRIBUTE_BROADCAST_TO_NETWORK: "DistributeBroadcastToNetwork",
    ORIGINAL_UNICAST_NPDU: "OriginalUnicastNPDU",
    ORIGINAL_BROADCAST_NPDU: "OriginalBroadcastNPDU",
    SECURE_BVLL: "SecureBVLL",
}

# BVLC-Result codes (Annex J.2.1.1). The emulated device is a Desigo-class
# field controller, not a BBMD, so every BBMD-only function is refused --
# which is both the truthful answer for this persona and the safe one:
# accepting a foreign-device registration would sign us up to forward
# broadcast traffic on the registrant's behalf.
RESULT_SUCCESS = 0x0000
_NAK_FOR_FUNCTION = {
    WRITE_BDT: 0x0010,
    READ_BDT: 0x0020,
    REGISTER_FOREIGN_DEVICE: 0x0030,
    READ_FDT: 0x0040,
    DELETE_FDT_ENTRY: 0x0050,
    DISTRIBUTE_BROADCAST_TO_NETWORK: 0x0060,
}

# Functions that carry an NPDU we should hand to the application.
_NPDU_BEARING = frozenset(
    (ORIGINAL_UNICAST_NPDU, ORIGINAL_BROADCAST_NPDU, FORWARDED_NPDU)
)

# NPDU control bits.
_NET_MESSAGE = 0x80
_DEST_SPECIFIER = 0x20
_SRC_SPECIFIER = 0x08
_EXPECTING_REPLY = 0x04

# A Forwarded-NPDU prefixes the NPDU with the 6-byte B/IP address
# (4 octets of IPv4 + 2 of port) of the originating device.
_FORWARDED_ADDRESS_LEN = 6


class BvlcError(ValueError):
    """A datagram that claims to be BVLC but is not decodable as one."""


class LinkLayer(object):
    """What a reply needs to reach the client that sent the request.

    A bare-APDU request produces no ``LinkLayer`` at all (``None``), which is
    how the framed and unframed paths stay separable: the reply is wrapped
    only if the request was.
    """

    __slots__ = ("function", "source_network", "source_address", "expecting_reply")

    def __init__(
        self,
        function,
        source_network=None,
        source_address=None,
        expecting_reply=False,
    ):
        self.function = function
        self.source_network = source_network
        self.source_address = source_address
        self.expecting_reply = expecting_reply

    @property
    def name(self):
        return FUNCTION_NAMES.get(self.function, "0x%02x" % self.function)

    @property
    def is_broadcast(self):
        return self.function in (
            ORIGINAL_BROADCAST_NPDU,
            DISTRIBUTE_BROADCAST_TO_NETWORK,
        )

    def __repr__(self):  # pragma: no cover - debugging aid
        return "LinkLayer(%s, snet=%r, sadr=%r)" % (
            self.name,
            self.source_network,
            self.source_address,
        )


class Decoded(object):
    """Result of `unwrap`.

    Exactly one of the three outcomes is populated:

    ``apdu``   bytes to hand to `BACnetApp.indication`, with ``link`` set to
               the framing to mirror on the reply (``None`` = bare APDU).
    ``reply``  a complete datagram to send straight back -- today only a
               BVLC-Result NAK for a BBMD function.
    neither    nothing to do; the datagram was a response, a network-layer
               message or a BVLL function with no sane answer.

    ``service`` always carries a human name for the session record, so even
    the do-nothing outcomes are visible to an analyst.
    """

    __slots__ = ("apdu", "link", "reply", "service")

    def __init__(self, apdu=None, link=None, reply=None, service=None):
        self.apdu = apdu
        self.link = link
        self.reply = reply
        self.service = service


def build_result(code):
    """A BVLC-Result datagram carrying `code` (Annex J.2.1.1)."""
    return bytes([BVLC_TYPE, RESULT, 0x00, 0x06]) + code.to_bytes(2, "big")


def looks_framed(data):
    """True if `data` should be read as BVLC rather than as a bare APDU.

    The discriminator is the BVLC type byte. It is unambiguous: 0x81 as the
    first byte of an APDU is PDU type 8, which ASHRAE 135 reserves and this
    server already ignores.
    """
    return len(data) >= 4 and data[0] == BVLC_TYPE


def unwrap(data):
    """Strip BVLC + NPDU from a received datagram.

    Never raises on attacker input except `BvlcError`, which the caller
    treats as "log and drop".
    """
    data = bytes(data)
    if not looks_framed(data):
        # Bare APDU. Kept because Conpot's own BACnet tests have always sent
        # one and because a malformed-but-unframed probe is still worth
        # handing to the APDU decoder, which will record what it can.
        return Decoded(apdu=data, link=None, service=None)

    function = data[1]
    length = int.from_bytes(data[2:4], "big")
    if length < 4 or length > len(data):
        raise BvlcError(
            "BVLC length %d does not fit a %d byte datagram" % (length, len(data))
        )
    body = data[4:length]
    name = FUNCTION_NAMES.get(function, "0x%02x" % function)

    if function in _NAK_FOR_FUNCTION:
        return Decoded(reply=build_result(_NAK_FOR_FUNCTION[function]), service=name)

    if function not in _NPDU_BEARING:
        # Result, the two table ACKs, Secure-BVLL and anything unassigned.
        # All of them are either responses to a request we never made or
        # functions with no defined refusal; answering would only confirm the
        # listener and hand a scanner a reflection target.
        return Decoded(service=name)

    if function == FORWARDED_NPDU:
        if len(body) < _FORWARDED_ADDRESS_LEN:
            raise BvlcError("Forwarded-NPDU shorter than its originating address")
        body = body[_FORWARDED_ADDRESS_LEN:]

    apdu, link = _strip_npdu(body, function)
    if apdu is None:
        # The BVLL function name would be misleading in the record: what
        # arrived was a network-layer message, not a service request.
        name = "NetworkLayerMessage"
    return Decoded(apdu=apdu, link=link, service=name)


def _strip_npdu(body, function):
    """Strip the NPCI, returning (apdu_bytes_or_None, LinkLayer)."""
    if len(body) < 2:
        raise BvlcError("NPDU shorter than its two mandatory octets")
    version, control = body[0], body[1]
    if version != 0x01:
        raise BvlcError("unsupported NPDU version %d" % version)

    offset = 2
    has_destination = bool(control & _DEST_SPECIFIER)
    source_network = source_address = None

    if has_destination:
        # DNET/DLEN/DADR are read and discarded: this device is not a router,
        # so a datagram addressed through it is answered as if it had arrived
        # directly, which is what a non-routing device on the far side of a
        # BBMD looks like anyway.
        offset = _skip_specifier(body, offset, "destination")
    if control & _SRC_SPECIFIER:
        offset, source_network, source_address = _read_specifier(body, offset, "source")
    if has_destination:
        if offset >= len(body):
            raise BvlcError("NPDU declares a destination but carries no hop count")
        offset += 1  # hop count

    link = LinkLayer(
        function=function,
        source_network=source_network,
        source_address=source_address,
        expecting_reply=bool(control & _EXPECTING_REPLY),
    )

    if control & _NET_MESSAGE:
        # A network-layer message (Who-Is-Router-To-Network and friends) is
        # not an APDU. Recording it matters -- it is how a scanner maps the
        # internetwork -- but a field controller has nothing to say back.
        return None, link

    return body[offset:], link


def _read_specifier(body, offset, which):
    """Read NET(2) + LEN(1) + ADR(LEN); return (new_offset, net, address)."""
    if offset + 3 > len(body):
        raise BvlcError("NPDU %s specifier runs past the end" % which)
    network = int.from_bytes(body[offset : offset + 2], "big")
    length = body[offset + 2]
    end = offset + 3 + length
    if end > len(body):
        raise BvlcError("NPDU %s address runs past the end" % which)
    # DLEN/SLEN of 0 means "broadcast on that network" and carries no address.
    return end, network, (body[offset + 3 : end] if length else None)


def _skip_specifier(body, offset, which):
    return _read_specifier(body, offset, which)[0]


def wrap(apdu_bytes, link, broadcast=False):
    """Wrap an APDU for the client described by `link`.

    `broadcast` is the APDU's OWN addressing -- an I-Am or an I-Have is a
    broadcast service, a ComplexAck is not -- and it picks the BVLL function.
    The UDP destination stays the requester either way: on a public sensor a
    genuine subnet broadcast reaches nobody, and a scanner accepts an I-Am
    that arrives unicast (it is byte-identical to one a BBMD forwarded).
    """
    if link is None:
        return bytes(apdu_bytes)

    npdu = bytearray([0x01, 0x00])
    if link.source_address is not None and link.source_network is not None:
        # The request came in routed, so the reply is addressed back to the
        # network and MAC it came from, with a full hop count.
        npdu[1] |= _DEST_SPECIFIER
        npdu += link.source_network.to_bytes(2, "big")
        npdu.append(len(link.source_address))
        npdu += link.source_address
        npdu.append(0xFF)
    npdu += bytes(apdu_bytes)

    function = ORIGINAL_BROADCAST_NPDU if broadcast else ORIGINAL_UNICAST_NPDU
    total = len(npdu) + 4
    return bytes([BVLC_TYPE, function]) + total.to_bytes(2, "big") + bytes(npdu)
