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

import logging
import re
import sys
from bacpypes.pdu import GlobalBroadcast, LocalBroadcast
import bacpypes.object
from bacpypes.app import BIPSimpleApplication
from bacpypes.constructeddata import Any
from bacpypes.constructeddata import InvalidParameterDatatype
from bacpypes.primitivedata import CharacterString
from bacpypes.apdu import (
    APDU,
    apdu_types,
    confirmed_request_types,
    unconfirmed_request_types,
    ErrorPDU,
    RejectPDU,
    IAmRequest,
    IHaveRequest,
    ReadPropertyACK,
    ConfirmedServiceChoice,
    UnconfirmedServiceChoice,
)
from bacpypes.pdu import PDU
import ast

from conpot.protocols.bacnet import bvlc

logger = logging.getLogger(__name__)


class BACnetApp(BIPSimpleApplication):
    """
    BACnet device emulation class. BACnet properties are populated from the template file. Services are defined.
    Conpot implements a smart sensor and hence
    - DM-RP-B (execute ReadProperty)
    - DM-DDB-B (execute Who-Is, initiate I-Am)
    - DM-DOB-B (execute Who-Has, initiate I-Have)
    services are supported.
    """

    def __init__(self, device, datagram_server):
        self._request = None
        self._response = None
        self._response_service = None
        self.localDevice = device
        self.datagram_server = datagram_server
        self.deviceIdentifier = None
        super(BIPSimpleApplication, self).__init__()
        # Step H10c: registered AFTER the superclass constructor, which
        # assigns both dictionaries fresh. Registering before it -- as this
        # did from 2015 until now -- meant the device object was in neither
        # map, so `device:<instance>` resolved to nothing and a ReadProperty
        # of it produced no reply at all. `nmap --script bacnet-info` reads
        # the DEVICE object's objectName, vendorName and modelName, so the
        # single most common BACnet fingerprint request timed out while the
        # analog and binary points answered normally.
        #
        # It also puts the device first in `objectIdentifier`, which is what
        # `whoIs`/`whoHas` index with `list(...keys())[0][1]` when they range
        # check a Who-Is: that read the first TEMPLATE object's instance
        # before, not the device's.
        self.objectName = {device.objectName: device}
        self.objectIdentifier = {device.objectIdentifier: device}

    def get_objects_and_properties(self, dom):
        """
        parse the bacnet template for objects and their properties
        """
        self.deviceIdentifier = int(dom.xpath("//bacnet/device_info/*")[1].text)
        device_property_list = dom.xpath("//bacnet/device_info/*")
        for prop in device_property_list:
            prop_key = prop.tag.lower().title()
            prop_key = re.sub("['_','-']", "", prop_key)
            prop_key = prop_key[0].lower() + prop_key[1:]
            if (
                prop_key not in self.localDevice.propertyList.value
                and prop_key not in ["deviceIdentifier", "deviceName"]
            ):
                self.add_property(prop_key, prop.text)

        object_list = dom.xpath("//bacnet/object_list/object/@name")
        for obj in object_list:
            property_list = dom.xpath(
                '//bacnet/object_list/object[@name="%s"]/properties/*' % obj
            )
            for prop in property_list:
                if prop.tag == "object_type":
                    object_type = re.sub("-", " ", prop.text).lower().title()
                    object_type = re.sub(" ", "", object_type) + "Object"
            try:
                device_object = getattr(bacpypes.object, object_type)()
                device_object.propertyList = list()
            except NameError:
                logger.critical("Non-existent BACnet object type")
                sys.exit(3)
            for prop in property_list:
                prop_key = prop.tag.lower().title()
                prop_key = re.sub("['_','-']", "", prop_key)
                prop_key = prop_key[0].lower() + prop_key[1:]
                if prop_key == "objectType":
                    prop_val = prop.text.lower().title()
                    prop_val = re.sub(" ", "", prop_val)
                    prop_val = prop_val[0].lower() + prop_val[1:]
                prop_val = prop.text
                try:
                    if prop_key == "objectIdentifier":
                        device_object.objectIdentifier = int(prop_val)
                    else:
                        setattr(device_object, prop_key, prop_val)
                        device_object.propertyList.append(prop_key)
                except bacpypes.object.PropertyError:
                    logger.critical("Non-existent BACnet property type")
                    sys.exit(3)
            self.add_object(device_object)

    def add_object(self, obj):
        object_name = obj.objectName
        if not object_name:
            raise RuntimeError("object name required")
        object_identifier = obj.objectIdentifier
        if not object_identifier:
            raise RuntimeError("object identifier required")
        if object_name in self.objectName:
            raise RuntimeError("object already added with the same name")
        if object_identifier in self.objectIdentifier:
            raise RuntimeError("object already added with the same identifier")

        # Keep dictionaries -- for name and identifiers
        self.objectName[object_name] = obj
        self.objectIdentifier[object_identifier] = obj
        self.localDevice.objectList.append(object_identifier)

    def add_property(self, prop_name, prop_value):
        if not prop_name:
            raise RuntimeError("property name required")
        if not prop_value:
            raise RuntimeError("property value required")

        setattr(self.localDevice, prop_name, prop_value)
        self.localDevice.propertyList.append(prop_name)

    def iAm(self, *args):
        self._response = None
        return

    def iHave(self, *args):
        self._response = None
        return

    def whoIs(self, request, address, invoke_key, device):
        # Limits are optional (but if used, must be paired)
        execute = False
        try:
            if (request.deviceInstanceRangeLowLimit is not None) and (
                request.deviceInstanceRangeHighLimit is not None
            ):
                if (
                    request.deviceInstanceRangeLowLimit
                    > list(self.objectIdentifier.keys())[0][1]
                    > request.deviceInstanceRangeHighLimit
                ):
                    logger.info("Bacnet WhoHasRequest out of range")
                else:
                    execute = True
            else:
                execute = True
        except AttributeError:
            execute = True

        if execute:
            self._response_service = "IAmRequest"
            self._response = IAmRequest()
            self._response.pduDestination = GlobalBroadcast()
            self._response.iAmDeviceIdentifier = self.deviceIdentifier
            # self._response.objectIdentifier = list(self.objectIdentifier.keys())[0][1]
            self._response.maxAPDULengthAccepted = int(
                getattr(self.localDevice, "maxApduLengthAccepted")
            )
            self._response.segmentationSupported = getattr(
                self.localDevice, "segmentationSupported"
            )
            self._response.vendorID = int(getattr(self.localDevice, "vendorIdentifier"))

    def whoHas(self, request, address, invoke_key, device):
        execute = False
        try:
            if (request.deviceInstanceRangeLowLimit is not None) and (
                request.deviceInstanceRangeHighLimit is not None
            ):
                if (
                    request.deviceInstanceRangeLowLimit
                    > list(self.objectIdentifier.keys())[0][1]
                    > request.deviceInstanceRangeHighLimit
                ):
                    logger.info("Bacnet WhoHasRequest out of range")
                else:
                    execute = True
            else:
                execute = True
        except AttributeError:
            execute = True

        if execute:
            target = getattr(request, "object", None)
            obj = self._resolve_object(
                getattr(target, "objectIdentifier", None), device
            )
            if obj is None:
                logger.info("Bacnet WhoHasRequest: no object found")
                return
            self._response_service = "IHaveRequest"
            self._response = IHaveRequest()
            self._response.pduDestination = GlobalBroadcast()
            self._response.deviceIdentifier = self.deviceIdentifier
            # Instance only, not the (type, instance) pair. That is wrong on
            # the wire -- binaryInput:12 encodes as analogInput:12 -- but it
            # is what this server has always sent and what upstream Conpot's
            # own test pins, and a Who-Has reply is not on the path step H10c
            # exists to repair. Noted rather than changed.
            self._response.objectIdentifier = obj.objectIdentifier[1]
            self._response.objectName = obj.objectName

    # ── Object and property resolution (Phase 2 step H10c) ────────────────

    def _resolve_object(self, object_identifier, device):
        """Find the emulated object a request names, or None.

        `device.objectList.value` is a bacpypes array whose element 0 is the
        array LENGTH and whose element 1 is the device object itself, which
        is why every walk here used to start at `[2:]`. That slice is what
        made the device object unaddressable. Skipping non-pair entries
        instead of slicing a fixed offset keeps that from depending on the
        array layout at all.
        """
        if object_identifier is None:
            return None
        try:
            wanted_type = object_identifier[0]
            wanted_instance = int(object_identifier[1])
        except (TypeError, ValueError, IndexError, KeyError):
            return None
        for entry in device.objectList.value:
            if not (isinstance(entry, (tuple, list)) and len(entry) == 2):
                continue  # the array length at element 0
            try:
                if entry[0] != wanted_type or int(entry[1]) != wanted_instance:
                    continue
            except (TypeError, ValueError):
                continue
            return self.objectIdentifier.get(tuple(entry))
        return None

    @staticmethod
    def _find_property(obj, identifier):
        """Look a property up by its BACnet identifier.

        bacpypes' `Object.properties` is only the list the object's OWN class
        declares; everything inherited lives in the merged `_properties` dict
        its metaclass builds. Walking `.properties` is the second half of the
        objectName defect: `LocalDeviceObject.properties` holds exactly three
        entries (localDate, localTime, protocolServicesSupported), so the
        device could not answer objectName even once it was addressable.
        """
        merged = getattr(obj, "_properties", None)
        if merged:
            prop = merged.get(identifier)
            if prop is not None:
                return prop
        for prop in getattr(obj, "properties", []):
            if prop.identifier == identifier:
                return prop
        return None

    @staticmethod
    def _property_value(prop_value, prop_type):
        """Turn a template's text into the property's own datatype.

        Every value in a template is text, so `present_value` has to be run
        through `ast.literal_eval` to become the float BACnet needs. Doing
        that to EVERY property is the third half of the objectName defect:
        `literal_eval("SUBSTATION-01-BMS")` raises ValueError, and the
        exception escaped `indication()` and the datagram handler, so the
        client got nothing back rather than an error PDU.

        Keying on the declared datatype rather than on whether the text
        happens to parse: an object named "1" must stay the string "1".
        """
        if not isinstance(prop_value, str) or isinstance(prop_type, CharacterString):
            return prop_value
        try:
            return ast.literal_eval(prop_value)
        except (ValueError, SyntaxError, MemoryError, RecursionError):
            return prop_value

    def _error_response(self, address, invoke_key, service=0x0C):
        self._response_service = "ErrorPDU"
        self._response = ErrorPDU()
        self._response.pduDestination = address
        self._response.apduInvokeID = invoke_key
        self._response.apduService = service

    def readProperty(self, request, address, invoke_key, device):
        # Read Property
        # TODO: add support for PropertyArrayIndex handling;
        object_identifier = getattr(request, "objectIdentifier", None)
        obj = self._resolve_object(object_identifier, device)
        if obj is None:
            # Previously this fell out of the loop leaving `self._response`
            # untouched, so the server re-sent whatever it had answered the
            # PREVIOUS caller -- a cross-client leak as well as a wrong reply.
            logger.info(
                "Bacnet ReadProperty: no such object %s", (object_identifier,)
            )
            self._error_response(address, invoke_key)
            return

        prop = self._find_property(obj, request.propertyIdentifier)
        if prop is None:
            logger.info(
                "Bacnet ReadProperty: object has no property %s",
                request.propertyIdentifier,
            )
            self._error_response(address, invoke_key)
            return

        try:
            prop_value = prop.ReadProperty(obj)
            prop_type = prop.datatype()
            # get the property type
            for p in dir(sys.modules[prop_type.__module__]):
                _obj = getattr(sys.modules[prop_type.__module__], p)
                try:
                    if type(prop_type) == _obj:
                        break
                except TypeError:
                    pass
            encoded = Any(_obj(self._property_value(prop_value, prop_type)))
        except Exception as exc:
            # A property whose value will not encode (an array, a bit string
            # the template never filled in) must answer an error, not raise
            # into the datagram handler and leave the client hanging.
            logger.info(
                "Bacnet ReadProperty: %s is not encodable (%s)",
                request.propertyIdentifier,
                exc,
            )
            self._error_response(address, invoke_key)
            return

        self._response_service = "ComplexAckPDU"
        self._response = ReadPropertyACK()
        self._response.pduDestination = address
        self._response.apduInvokeID = invoke_key
        # The (type, instance) pair, not the bare instance: a client checks
        # the ACK against what it asked for, and a bare instance re-encodes
        # as analogInput:<n> whatever the real type was. For the analogInput
        # objects the two forms are byte-identical, which is why the existing
        # tests never caught it and why they still pass.
        self._response.objectIdentifier = obj.objectIdentifier
        self._response.objectName = obj.objectName
        self._response.propertyIdentifier = prop.identifier
        self._response.propertyValue = encoded

    # ── Session capture (Phase 2 step H10) ────────────────────────────────
    #
    # Wrapped under a "request" key to match the shape the Conpot forwarder
    # already expects from every other OT protocol -- modbus, s7comm, IEC-104
    # and http all wrap their captured request the same way.
    #
    # Recorded BEFORE the service is dispatched, for the same reason the
    # IEC-104 fork patch records before dispatch (c8e4b31): Conpot implements
    # only ReadProperty, Who-Is and Who-Has, so a WriteProperty or a
    # ReinitializeDevice -- the two requests an analyst most wants to see --
    # falls straight through to "Not implemented Bacnet command" and returns.
    # Logging on the way in captures the attempt; logging on the way out would
    # capture only the three services we happen to emulate.

    @staticmethod
    def _object_identifier_facts(value, facts):
        """Split a BACnet object identifier into type and instance."""
        if value is None:
            return
        # bacpypes yields ('analogInput', 14) once decoded, but an
        # unrecognised type can stay an int. Keep whichever half we were
        # actually given rather than inventing the other one.
        if isinstance(value, (tuple, list)) and len(value) == 2:
            facts["object_type"] = str(value[0])
            try:
                facts["object_instance"] = int(value[1])
            except (TypeError, ValueError):
                facts["object_instance"] = str(value[1])
        else:
            try:
                facts["object_instance"] = int(value)
            except (TypeError, ValueError):
                facts["object_instance"] = str(value)

    def _record_request_event(self, session, apdu_type, apdu_service, request):
        """Log the decoded BACnet service onto the AttackSession.

        Fails open: an observability write must never stop the protocol
        answering, so an unexpected shape degrades to whatever was extracted
        instead of raising into the datagram handler.
        """
        if session is None:
            return
        try:
            facts = {}
            if apdu_type is not None:
                facts["pdu_type"] = apdu_type.__name__
            if apdu_service is not None:
                facts["service"] = apdu_service.__name__
                choice = getattr(apdu_service, "serviceChoice", None)
                if choice is not None:
                    facts["service_choice"] = int(choice)
            if request is not None:
                self._object_identifier_facts(
                    getattr(request, "objectIdentifier", None), facts
                )
                # Who-Has carries its target one level down, inside a
                # WhoHasObject element rather than on the request itself.
                target = getattr(request, "object", None)
                if target is not None and "object_instance" not in facts:
                    self._object_identifier_facts(
                        getattr(target, "objectIdentifier", None), facts
                    )
                prop = getattr(request, "propertyIdentifier", None)
                if prop is not None:
                    facts["property"] = str(prop)
            if facts:
                session.add_event({"request": facts})
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Bacnet session capture failed: %s", exc)

    def indication(self, apdu, address, device, session=None):
        """logging the received PDU type and Service request"""
        request = None
        apdu_type = apdu_types.get(apdu.apduType)
        if apdu_type is None:
            # Types 0x8-0xF are reserved. The branch below that means to
            # ignore them reads `apdu_type.pduType`, so it was never reached:
            # the `apdu_type.__name__` on the log line under it raised
            # AttributeError first, straight out of the datagram handler.
            logger.info(
                "Bacnet reserved PDU type %s from %s:%d",
                apdu.apduType,
                address[0],
                address[1],
            )
            self._response = None
            return
        invoke_key = apdu.apduInvokeID
        logger.info(
            "Bacnet PDU received from %s:%d. (%s)",
            address[0],
            address[1],
            apdu_type.__name__,
        )
        if apdu_type.pduType == 0x0:
            # Confirmed request handling
            apdu_service = confirmed_request_types.get(apdu.apduService)
            logger.info(
                "Bacnet indication from %s:%d. (%s)",
                address[0],
                address[1],
                apdu_service.__name__,
            )
            try:
                request = apdu_service()
                request.decode(apdu)
            except (AttributeError, RuntimeError, InvalidParameterDatatype) as e:
                logger.warning("Bacnet indication: Invalid service. Error: %s" % e)
                # A body we cannot decode is still a service somebody asked
                # for; record the name before giving up on the rest.
                self._record_request_event(session, apdu_type, apdu_service, None)
                return
            except bacpypes.errors.DecodingError:
                pass

            self._record_request_event(session, apdu_type, apdu_service, request)

            for key, value in list(ConfirmedServiceChoice.enumerations.items()):
                if apdu_service.serviceChoice == value:
                    try:
                        getattr(self, key)(request, address, invoke_key, device)
                        break
                    except AttributeError:
                        logger.error("Not implemented Bacnet command")
                        self._response = None
                        return
            else:
                logger.info(
                    "Bacnet indication: Invalid confirmed service choice (%s)",
                    apdu_service.__name__,
                )
                self._response = None
                return

        # Unconfirmed request handling
        elif apdu_type.pduType == 0x1:
            apdu_service = unconfirmed_request_types.get(apdu.apduService)
            logger.info(
                "Bacnet indication from %s:%d. (%s)",
                address[0],
                address[1],
                apdu_service.__name__,
            )
            try:
                request = apdu_service()
                request.decode(apdu)
            except (AttributeError, RuntimeError):
                logger.exception("Bacnet indication: Invalid service.")
                self._response = None
                self._record_request_event(session, apdu_type, apdu_service, None)
                return
            except bacpypes.errors.DecodingError:
                pass

            self._record_request_event(session, apdu_type, apdu_service, request)

            for key, value in list(UnconfirmedServiceChoice.enumerations.items()):
                if apdu_service.serviceChoice == value:
                    try:
                        getattr(self, key)(request, address, invoke_key, device)
                        break
                    except AttributeError:
                        logger.error("Not implemented Bacnet command")
                        self._response = None
                        return
            else:
                # Unrecognized services
                logger.info(
                    "Bacnet indication: Invalid unconfirmed service choice (%s)",
                    apdu_service,
                )
                self._response_service = "ErrorPDU"
                self._response = ErrorPDU()
                self._response.pduDestination = address
                return
        # ignore the following
        elif apdu_type.pduType == 0x2:
            # simple ack pdu
            self._response = None
            return
        elif apdu_type.pduType == 0x3:
            # complex ack pdu
            self._response = None
            return
        elif apdu_type.pduType == 0x4:
            # segment ack
            self._response = None
            return
        elif apdu_type.pduType == 0x5:
            # error pdu
            self._response = None
            return
        elif apdu_type.pduType == 0x6:
            # reject pdu
            self._response = None
            return
        elif apdu_type.pduType == 0x7:
            # abort pdu
            self._response = None
            return
        elif 0x8 <= apdu_type.pduType <= 0xF:
            # reserved
            self._response = None
            return
        else:
            # non-BACnet PDU types
            logger.info("Bacnet Unrecognized service")
            self._response = None
            return

    # socket not actually socket, but DatagramServer with sendto method
    def response(self, response_apdu, address, link=None):
        """Send the built response.

        `link` is the BVLC/NPDU framing the REQUEST arrived under (step
        H10c). When it is None the request was a bare APDU and the reply is
        one too, which is the path Conpot's own tests have always used. When
        it is set, the reply carries the same link layer back -- without it a
        standards-conforming client discards the answer as malformed, which
        is the other half of why real BACnet traffic produced no sessions.
        """
        if response_apdu is None:
            return
        apdu = APDU()
        response_apdu.encode(apdu)
        pdu = PDU()
        apdu.encode(pdu)

        if link is not None:
            # I-Am and I-Have are broadcast services and carry a broadcast
            # destination; a ComplexAck or an error is unicast. The BVLL
            # function follows that, while the UDP destination stays the
            # requester either way -- a real subnet broadcast from a sensor
            # on a public address reaches nobody.
            broadcast = isinstance(
                getattr(response_apdu, "pduDestination", None),
                (GlobalBroadcast, LocalBroadcast),
            )
            self.datagram_server.sendto(
                bvlc.wrap(bytes(pdu.pduData), link, broadcast=broadcast), address
            )
            logger.info(
                "Bacnet response sent to %s:%s (%s, %s) over %s",
                address[0],
                address[1],
                apdu_types.get(response_apdu.apduType).__name__
                if apdu_types.get(response_apdu.apduType)
                else response_apdu.apduType,
                self._response_service,
                "Original-Broadcast-NPDU" if broadcast else "Original-Unicast-NPDU",
            )
            return

        if isinstance(response_apdu, RejectPDU) or isinstance(response_apdu, ErrorPDU):
            self.datagram_server.sendto(pdu.pduData, address)
        else:
            apdu_type = apdu_types.get(response_apdu.apduType)
            if pdu.pduDestination == "*:*":
                # broadcast
                # sendto operates under lock
                self.datagram_server.sendto(pdu.pduData, ("", address[1]))
            else:
                # sendto operates under lock
                self.datagram_server.sendto(pdu.pduData, address)
            logger.info(
                "Bacnet response sent to %s (%s:%s)",
                response_apdu.pduDestination,
                apdu_type.__name__,
                self._response_service,
            )
