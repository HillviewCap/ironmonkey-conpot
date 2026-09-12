# Copyright (C) 2026  IronMonkey
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
"""Structural checks on the s7-315-substation persona (Phase 2 step H10).

This is the template that ships to every OT sensor, and the loader validates
it only at Conpot start-up on the sensor itself -- a broken protocol file is
therefore discovered as a dead bait port on an internet-exposed box, hours
after a deploy, rather than here. These checks run the same validation
`bin/conpot` does, plus the two shape rules the loader does NOT check and
which each cost a debugging session to find:

* a comment as a direct child of <mib> kills the SNMP greenlet at start-up
  (SNMPServer.xml_mib_config iterates the element's children with a plain
  `for`, which yields lxml comment nodes, and then reads .attrib["name"]);
* the port a protocol binds inside the container has to stay above 1024,
  because Conpot runs as a non-root user.
"""

import os
import unittest

from lxml import etree

import conpot

PACKAGE_DIR = os.path.dirname(conpot.__file__)
TEMPLATE_DIR = os.path.join(PACKAGE_DIR, "templates", "s7-315-substation")

# Every protocol the persona serves, and the port it binds INSIDE the
# container. sensors/docker-compose.sensor.yml in ironmonkey-unified publishes
# these; the forwarder's _PORT_MAP translates them back to the port the
# attacker actually hit. Three files agree on these numbers and nothing else
# holds them together, so this list is the anchor.
EXPECTED_PROTOCOLS = {
    "modbus": 5020,
    "s7comm": 10201,
    "IEC104": 2404,
    "http": 8800,
    "snmp": 16100,
    "bacnet": 47808,
    "enip": 44818,
}


def _protocol_file(name):
    return os.path.join(TEMPLATE_DIR, name, "%s.xml" % name)


class TestSubstationTemplate(unittest.TestCase):
    def test_every_expected_protocol_is_present_and_enabled(self):
        """A protocol is served iff its directory holds <name>/<name>.xml."""
        for name, port in EXPECTED_PROTOCOLS.items():
            path = _protocol_file(name)
            self.assertTrue(os.path.isfile(path), "missing %s" % path)
            root = etree.parse(path).getroot()
            self.assertEqual(
                "True", root.get("enabled"), "%s is present but disabled" % name
            )
            self.assertEqual(port, int(root.get("port")), "%s port drifted" % name)

    def test_protocol_files_validate_against_their_xsd(self):
        """Same validation bin/conpot runs, before a sensor ever sees it."""
        for name in EXPECTED_PROTOCOLS:
            xsd_path = os.path.join(
                PACKAGE_DIR, "protocols", name, "%s.xsd" % name
            )
            schema = etree.XMLSchema(etree.parse(xsd_path))
            document = etree.parse(_protocol_file(name))
            self.assertTrue(
                schema.validate(document),
                "%s.xml does not validate: %s" % (name, schema.error_log),
            )

    def test_root_template_validates(self):
        schema = etree.XMLSchema(
            etree.parse(os.path.join(PACKAGE_DIR, "template.xsd"))
        )
        document = etree.parse(os.path.join(TEMPLATE_DIR, "template.xml"))
        self.assertTrue(
            schema.validate(document),
            "template.xml does not validate: %s" % schema.error_log,
        )

    def test_bind_ports_are_unprivileged(self):
        """Conpot runs as a non-root user; a port under 1024 will not bind."""
        for name, port in EXPECTED_PROTOCOLS.items():
            self.assertGreater(port, 1024, "%s binds a privileged port" % name)

    def test_snmp_mib_has_no_comment_children(self):
        """A comment one level too high kills the SNMP greenlet at start-up.

        xml_mib_config iterates a <mib>'s children directly and reads
        .attrib["name"] off each, so an lxml comment node raises KeyError
        inside the greenlet -- the port stays open via docker-proxy and
        captures nothing, which is the failure mode the supervisor exists for.
        """
        root = etree.parse(_protocol_file("snmp")).getroot()
        for mib in root.iter("mib"):
            for child in mib:
                self.assertNotIsInstance(
                    child.tag,
                    type(etree.Comment),
                    "comment inside <mib name=%r>" % mib.get("name"),
                )
                self.assertIn("name", child.attrib)

    def test_snmp_symbols_resolve_to_databus_keys(self):
        """Every <value> names a key template.xml actually seeds.

        A missing key resolves to None on the databus and the OID then answers
        with nothing, which looks like a MIB the device does not implement
        rather than the template typo it is.
        """
        databus_keys = {
            key.get("name")
            for key in etree.parse(
                os.path.join(TEMPLATE_DIR, "template.xml")
            ).getroot().iter("key")
        }
        symbols = etree.parse(_protocol_file("snmp")).getroot().iter("symbol")
        referenced = {symbol.findtext("value") for symbol in symbols}
        self.assertTrue(referenced)
        self.assertLessEqual(referenced, databus_keys)

    def test_enip_identity_is_not_the_cpppo_default(self):
        """The values cpppo ships are the same on every Conpot on the internet.

        EnipServer.apply_identity makes <device_info> load-bearing, so a
        template that repeats a cpppo default now actively advertises one.
        """
        root = etree.parse(_protocol_file("enip")).getroot()
        self.assertNotEqual(
            "1756-L61/B LOGIX5561", root.findtext("device_info/ProductName")
        )
        self.assertNotEqual(
            0x006C061A, int(root.findtext("device_info/SerialNumber"))
        )
        self.assertNotEqual(
            0x3160, int(root.findtext("device_info/StatusWord"), 0)
        )

    def test_bacnet_device_name_is_not_the_upstream_literal(self):
        """Conpot reads <device_name> as a literal, not as a databus key.

        The upstream template's value is therefore the string "SystemName",
        which is a Conpot tell on its own.
        """
        root = etree.parse(_protocol_file("bacnet")).getroot()
        self.assertNotEqual(
            "SystemName", root.findtext("device_info/device_name")
        )

    def test_bacnet_object_identifiers_are_unique(self):
        """BACnetApp.add_object raises RuntimeError on a duplicate.

        It raises at start-up, inside the greenlet, so a duplicate is another
        way to ship a bait port that answers TCP and captures nothing.
        """
        root = etree.parse(_protocol_file("bacnet")).getroot()
        identifiers = [
            int(node.text)
            for node in root.iter("object_identifier")
        ]
        self.assertEqual(len(identifiers), len(set(identifiers)))
        self.assertNotIn(
            int(root.findtext("device_info/device_identifier")), identifiers
        )
