# Copyright (C) 2015  Peter Sooky <xsooky00@stud.fit.vubtr.cz>
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

# Author: Peter Sooky <xsooky00@stud.fit.vubtr.cz>
# Brno University of Technology, Faculty of Information Technology

import socket
from lxml import etree
from gevent.server import DatagramServer
from bacpypes.local.device import LocalDeviceObject
from bacpypes.apdu import APDU
from bacpypes.pdu import PDU
from bacpypes.errors import DecodingError
import conpot.core as conpot_core
from conpot.protocols.bacnet import bvlc
from conpot.protocols.bacnet.bacnet_app import BACnetApp
from conpot.core.protocol_wrapper import conpot_protocol
from conpot.utils.networking import get_interface_ip
from conpot.utils.rate_limit import UdpRateLimiter
import logging

logger = logging.getLogger(__name__)


@conpot_protocol
class BacnetServer(object):
    def __init__(self, template, template_directory, args):
        self.dom = etree.parse(template)
        device_info_root = self.dom.xpath("//bacnet/device_info")[0]
        name_key = device_info_root.xpath("./device_name/text()")[0]
        id_key = device_info_root.xpath("./device_identifier/text()")[0]
        vendor_name_key = device_info_root.xpath("./vendor_name/text()")[0]
        vendor_identifier_key = device_info_root.xpath("./vendor_identifier/text()")[0]
        apdu_length_key = device_info_root.xpath("./max_apdu_length_accepted/text()")[0]
        segmentation_key = device_info_root.xpath("./segmentation_supported/text()")[0]

        self.thisDevice = LocalDeviceObject(
            objectName=name_key,
            objectIdentifier=int(id_key),
            maxApduLengthAccepted=int(apdu_length_key),
            segmentationSupported=segmentation_key,
            vendorName=vendor_name_key,
            vendorIdentifier=int(vendor_identifier_key),
        )
        self.bacnet_app = None
        self.server = None  # Initialize later
        # Step H10c. 47808/udp answers every datagram inline in one greenlet
        # and a 12-byte Who-Is draws a 25-byte I-Am, so an unlimited
        # responder is both a way to pin this sensor's only CPU and a
        # reflection amplifier pointed at a third party.
        self.rate_limiter = UdpRateLimiter.from_dom(self.dom, "//bacnet", "bacnet")
        logger.info("Conpot Bacnet initialized using the %s template.", template)

    @staticmethod
    def _record_link_event(session, decoded):
        """Record a BVLL function that never becomes an APDU.

        Register-Foreign-Device and Distribute-Broadcast-To-Network are how
        an attacker gets a BACnet internetwork to send ITS broadcast traffic
        somewhere, so the attempt is worth a session event even though the
        answer is a refusal. Reuses the `pdu_type`/`service` keys the
        forwarder's `_BACNET_FIELDS` already allows -- a new key name would
        be dropped there and in IronPot's allow-list downstream.
        """
        if session is None or decoded.service is None:
            return
        try:
            session.add_event(
                {"request": {"pdu_type": "BVLC", "service": decoded.service}}
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Bacnet BVLC session capture failed: %s", exc)

    def handle(self, data, address):
        # Before the session, so a flood costs one dict lookup rather than a
        # session object and a log line per datagram.
        if not self.rate_limiter.allow(address[0]):
            return

        session = conpot_core.get_session(
            "bacnet",
            address[0],
            address[1],
            get_interface_ip(address[0]),
            self.server.server_port,
        )
        logger.info(
            "New Bacnet connection from %s:%d. (%s)", address[0], address[1], session.id
        )
        session.add_event({"type": "NEW_CONNECTION"})
        # I'm not sure if gevent DatagramServer handles issues where the
        # received data is over the MTU -> fragmentation
        if data:
            # Step H10c: strip the BACnet/IP link layer. Every real client
            # sends BVLC + NPDU + APDU; decoding the datagram as a bare APDU
            # meant `nmap --script bacnet-info` and every commercial scanner
            # produced a DecodingError and a NEW_CONNECTION-only session,
            # which never becomes a honeypot_sessions row. The bare-APDU path
            # survives below for Conpot's own tests.
            try:
                decoded = bvlc.unwrap(data)
            except bvlc.BvlcError as exc:
                logger.warning(
                    "Bacnet BVLC decode failed from %s: %s", address[0], exc
                )
                session.add_event({"type": "CONNECTION_FAILED"})
                return

            if decoded.reply is not None:
                self._record_link_event(session, decoded)
                self.server.sendto(decoded.reply, address)
                return
            if decoded.apdu is None:
                self._record_link_event(session, decoded)
                return

            pdu = PDU()
            pdu.pduData = bytearray(decoded.apdu)
            apdu = APDU()
            try:
                apdu.decode(pdu)
            except DecodingError:
                logger.warning("DecodingError - PDU: {}".format(pdu))
                return
            # A response is instance state on the app and survives the
            # request that built it, so clear it first: a service that
            # produces no reply would otherwise re-send the previous
            # client's answer to this one.
            self.bacnet_app._response = None
            # Step H10: `session` reaches the app so `indication()` can log the
            # service the attacker actually asked for. Before this, the only
            # event a BACnet session ever carried was the NEW_CONNECTION above
            # -- a Who-Is sweep and a WriteProperty against the plant left
            # identical, empty records by the time they reached the forwarder.
            self.bacnet_app.indication(
                apdu, address, self.thisDevice, session=session
            )
            # send an appropriate response from BACnet app to the attacker
            self.bacnet_app.response(
                self.bacnet_app._response, address, link=decoded.link
            )
        logger.info(
            "Bacnet client disconnected %s:%d. (%s)", address[0], address[1], session.id
        )

    def start(self, host, port):
        connection = (host, port)
        self.server = DatagramServer(connection, self.handle)
        # start to init the socket
        self.server.start()
        self.server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.host = self.server.server_host
        self.port = self.server.server_port
        # create application instance
        # not too beautiful, but the BACnetApp needs access to the socket's sendto method
        # this could properly be refactored in a way such that sending operates on it's own
        # (non-bound) socket.
        self.bacnet_app = BACnetApp(self.thisDevice, self.server)
        # get object_list and properties
        self.bacnet_app.get_objects_and_properties(self.dom)

        logger.info("Bacnet server started on: %s", (self.host, self.port))
        self.server.serve_forever()

    def stop(self):
        self.server.stop()
