# Copyright (C) 2026  IronMonkey
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
"""Structural checks on every IronMonkey sector persona (Phase 2 step H11).

These are the templates that ship to an OT sensor, and the loader validates
them only at Conpot start-up on the sensor itself -- a broken protocol file is
therefore discovered as a dead bait port on an internet-exposed box, hours
after a deploy, rather than here.

`test_substation_template.py` pins the substation persona and the loader
gotchas H10 found. This module runs the same structural contract across ALL
personas, plus the rules that only become checkable once there is more than
one of them:

* every persona serves the same seven protocols on the same seven ports,
  because the sensor's published ports and the ufw rules in
  `ironmonkey-unified/scripts/sensor-bootstrap.sh` are fleet-wide;
* every persona carries a complete `http/statuscodes/` set, so an unmatched
  path answers with a page instead of a `FileNotFoundError` and a zero-length
  body (the defect this step folds in);
* every persona carries the H4 credential bait, because SIR-006-05 is
  answerable only from sensors that issue a challenge;
* no two personas share a device identity, because `asset_type`/`vendor`/
  `model` seed the uuid5 of the `x-ics-asset` node and two sensors answering
  alike would merge into one graph identity.
"""

import json
import os
import unittest

from lxml import etree

import conpot

PACKAGE_DIR = os.path.dirname(conpot.__file__)
TEMPLATES_DIR = os.path.join(PACKAGE_DIR, "templates")

# Every persona sensor-deploy.sh --template will accept. The deploy script
# discovers personas by globbing */ironmonkey/persona.json, so a directory
# added there without being added here is deployable but untested; the
# unified registry's `personas:` catalogue is the third place that must agree.
#
# s7-317-substation-de is the DACH regional VARIANT of s7-315-substation
# (step H13, Decision 19): same sector, every device identity distinct.
PERSONAS = (
    "s7-315-substation",
    "water-utility",
    "oil-gas-pipeline",
    "s7-317-substation-de",
)

# Protocol -> port bound INSIDE the container. Identical for every persona on
# purpose: sensors/docker-compose.sensor.yml publishes these, the forwarder's
# _PORT_MAP translates them back to the port the attacker hit, and
# sensor-bootstrap.sh opens them in ufw. Four files agree on these numbers and
# nothing holds them together at runtime, so this list is the anchor.
EXPECTED_PROTOCOLS = {
    "modbus": 5020,
    "s7comm": 10201,
    "IEC104": 2404,
    "http": 8800,
    "snmp": 16100,
    "bacnet": 47808,
    "enip": 44818,
}

# load_status opens <template>/http/statuscodes/<code>.status. A code declared
# in http.xml without a file logs a traceback per probe and answers empty.
EXPECTED_STATUS_CODES = ("400", "403", "404", "501", "503")


def _template_dir(persona):
    return os.path.join(TEMPLATES_DIR, persona)


def _protocol_file(persona, name):
    return os.path.join(_template_dir(persona), name, "%s.xml" % name)


def _manifest(persona):
    path = os.path.join(_template_dir(persona), "ironmonkey", "persona.json")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


class TestSectorPersonas(unittest.TestCase):

    def test_every_persona_directory_exists(self):
        for persona in PERSONAS:
            self.assertTrue(
                os.path.isfile(os.path.join(_template_dir(persona), "template.xml")),
                "missing persona %s" % persona,
            )

    def test_every_persona_serves_every_protocol_on_the_agreed_port(self):
        """A protocol is served iff its directory holds <name>/<name>.xml."""
        for persona in PERSONAS:
            for name, port in EXPECTED_PROTOCOLS.items():
                path = _protocol_file(persona, name)
                self.assertTrue(os.path.isfile(path), "missing %s" % path)
                root = etree.parse(path).getroot()
                self.assertEqual("True", root.get("enabled"))
                self.assertEqual(port, int(root.get("port")))

    def test_protocol_files_validate_against_their_xsd(self):
        """Same validation bin/conpot runs, before a sensor ever sees it."""
        for persona in PERSONAS:
            for name in EXPECTED_PROTOCOLS:
                schema = etree.XMLSchema(
                    etree.parse(
                        os.path.join(
                            PACKAGE_DIR, "protocols", name, "%s.xsd" % name
                        )
                    )
                )
                document = etree.parse(_protocol_file(persona, name))
                self.assertTrue(
                    schema.validate(document),
                    "%s/%s.xml does not validate: %s"
                    % (persona, name, schema.error_log),
                )

    def test_root_templates_validate(self):
        schema = etree.XMLSchema(
            etree.parse(os.path.join(PACKAGE_DIR, "template.xsd"))
        )
        for persona in PERSONAS:
            document = etree.parse(
                os.path.join(_template_dir(persona), "template.xml")
            )
            self.assertTrue(
                schema.validate(document),
                "%s template.xml: %s" % (persona, schema.error_log),
            )

    def test_bind_ports_are_unprivileged(self):
        """Conpot runs as a non-root user; a port under 1024 will not bind."""
        for name, port in EXPECTED_PROTOCOLS.items():
            self.assertGreater(port, 1024, "%s binds a privileged port" % name)

    # ── The statuscodes gap this step closes ─────────────────────────────────

    def test_every_declared_status_code_has_a_file(self):
        """An un-backed status code is a traceback per scanner probe.

        `load_status` (command_responder.py:266-276) opens
        `<docpath>/statuscodes/<code>.status` and logs the IOError before
        answering with a zero-length body. The substation persona shipped the
        XML block and none of the files, so every request for a nonexistent
        path -- the single most common thing a scanner does -- produced one.
        """
        for persona in PERSONAS:
            root = etree.parse(_protocol_file(persona, "http")).getroot()
            # xpath, not iter(): an htdocs <node> also has a <status>
            # child (the 302/401/403 the node answers with) and it carries no
            # name attribute.
            declared = {
                status.get("name")
                for status in root.xpath("//http/statuscodes/status")
            }
            self.assertEqual(
                set(EXPECTED_STATUS_CODES),
                declared,
                "%s declares %s" % (persona, sorted(declared)),
            )
            for code in declared:
                path = os.path.join(
                    _template_dir(persona),
                    "http",
                    "statuscodes",
                    "%s.status" % code,
                )
                self.assertTrue(os.path.isfile(path), "missing %s" % path)
                self.assertGreater(
                    os.path.getsize(path), 0, "%s is empty" % path
                )

    def test_status_pages_are_pure_ascii(self):
        """Same `str_to_bytes` trap as htdocs: the payload is ASCII-encoded
        after the headers have gone out, so a stray em dash truncates the body
        and leaves only a traceback in the container log."""
        for persona in PERSONAS:
            directory = os.path.join(_template_dir(persona), "http", "statuscodes")
            for name in sorted(os.listdir(directory)):
                with open(os.path.join(directory, name), "rb") as fh:
                    body = fh.read()
                try:
                    body.decode("ascii")
                except UnicodeDecodeError as exc:
                    self.fail("%s/%s: %s" % (persona, name, exc))

    def test_htdocs_pages_are_pure_ascii(self):
        """Conpot's GET path encodes the body with `.encode("ascii")`; a
        single non-ASCII byte anywhere under htdocs raises UnicodeEncodeError
        AFTER the status line and headers have already been sent. Use an HTML
        entity (&mdash;, &bull;) instead."""
        for persona in PERSONAS:
            htdocs = os.path.join(_template_dir(persona), "http", "htdocs")
            for root, _dirs, files in os.walk(htdocs):
                for name in files:
                    path = os.path.join(root, name)
                    with open(path, "rb") as fh:
                        body = fh.read()
                    try:
                        body.decode("ascii")
                    except UnicodeDecodeError as exc:
                        self.fail("%s: %s" % (path, exc))

    # ── The H4 credential bait, on every persona ─────────────────────────────

    def test_every_persona_challenges_for_credentials(self):
        """SIR-006-05 counts sessions that attempted default-credential HMI
        access. A persona with no 401 makes that unanswerable on any sensor
        running it, no matter what the pipeline behind it does."""
        for persona in PERSONAS:
            root = etree.parse(_protocol_file(persona, "http")).getroot()
            nodes = {node.get("name"): node for node in root.iter("node")}
            self.assertIn("/hmi/index.html", nodes, persona)
            challenge = nodes["/hmi/index.html"]
            self.assertEqual("401", challenge.findtext("status"))
            realms = [
                entity.text
                for entity in challenge.iter("entity")
                if entity.get("name") == "WWW-Authenticate"
            ]
            self.assertEqual(1, len(realms), persona)
            self.assertTrue(realms[0].startswith('Basic realm="'), realms)
            # The form POST target must exist, or every credential typed
            # into the start page is thrown away and the 404 tells the
            # attacker the page is scenery.
            self.assertIn("/login", nodes, persona)

    def test_start_page_form_action_matches_a_node_that_exists(self):
        for persona in PERSONAS:
            index = os.path.join(
                _template_dir(persona), "http", "htdocs", "index.html"
            )
            with open(index, encoding="ascii") as fh:
                page = fh.read()
            self.assertIn('action="/login"', page)
            self.assertIn('name="username"', page)
            self.assertIn('name="password"', page)

    def test_realms_are_distinct_across_personas(self):
        """Two sensors answering with the same realm correlate the fleet on a
        single unauthenticated GET."""
        realms = {}
        for persona in PERSONAS:
            root = etree.parse(_protocol_file(persona, "http")).getroot()
            for entity in root.iter("entity"):
                if entity.get("name") == "WWW-Authenticate":
                    realms.setdefault(entity.text, persona)
        self.assertEqual(len(realms), len(PERSONAS), realms)

    # ── Loader gotchas, applied to every persona ─────────────────────────────

    def test_snmp_mib_has_no_comment_children(self):
        """A comment one level too high kills the SNMP greenlet at start-up:
        xml_mib_config iterates a <mib>'s children directly and reads
        .attrib["name"] off each, so an lxml comment node raises KeyError
        inside the greenlet. The port stays open via docker-proxy and captures
        nothing."""
        for persona in PERSONAS:
            root = etree.parse(_protocol_file(persona, "snmp")).getroot()
            for mib in root.iter("mib"):
                for child in mib:
                    with self.subTest(persona=persona, mib=mib.get("name")):
                        self.assertNotIsInstance(child.tag, type(etree.Comment))
                        self.assertIn("name", child.attrib)

    def test_every_databus_reference_resolves(self):
        """SNMP symbols, IEC-104 registers and Modbus block names all name a
        databus key. A missing key resolves to None and the protocol answers
        with nothing, which reads as a feature the device does not implement
        rather than the template typo it is."""
        for persona in PERSONAS:
            keys = {
                key.get("name")
                for key in etree.parse(
                    os.path.join(_template_dir(persona), "template.xml")
                )
                .getroot()
                .iter("key")
            }
            referenced = {
                symbol.findtext("value")
                for symbol in etree.parse(
                    _protocol_file(persona, "snmp")
                ).getroot().iter("symbol")
            }
            referenced |= {
                register.findtext("value")
                for register in etree.parse(
                    _protocol_file(persona, "IEC104")
                ).getroot().iter("register")
            }
            referenced |= {
                block.get("name")
                for block in etree.parse(
                    _protocol_file(persona, "modbus")
                ).getroot().iter("block")
            }
            self.assertTrue(referenced)
            self.assertLessEqual(referenced, keys, referenced - keys)

    def test_modbus_block_sizes_match_their_backing_list(self):
        """The mediator does databus.get_value(block_name); a list shorter
        than <size> raises inside the greenlet on the first FC-3."""
        for persona in PERSONAS:
            root = etree.parse(
                os.path.join(_template_dir(persona), "template.xml")
            ).getroot()
            lengths = {}
            for key in root.iter("key"):
                text = (key.findtext("value") or "").strip()
                if text.startswith("[") and text.endswith("]"):
                    lengths[key.get("name")] = len(
                        [part for part in text[1:-1].split(",") if part.strip()]
                    )
            for block in etree.parse(
                _protocol_file(persona, "modbus")
            ).getroot().iter("block"):
                name = block.get("name")
                self.assertIn(name, lengths)
                self.assertEqual(int(block.findtext("size")), lengths[name])

    def test_bacnet_object_identifiers_are_unique_within_a_persona(self):
        """BACnetApp.add_object raises RuntimeError on a duplicate, at
        start-up, inside the greenlet -- another way to ship a bait port that
        answers and captures nothing."""
        for persona in PERSONAS:
            root = etree.parse(_protocol_file(persona, "bacnet")).getroot()
            identifiers = [int(node.text) for node in root.iter("object_identifier")]
            self.assertEqual(len(identifiers), len(set(identifiers)))
            self.assertNotIn(
                int(root.findtext("device_info/device_identifier")), identifiers
            )

    def test_bacnet_device_instances_are_distinct_across_personas(self):
        """Two sensors answering Who-Is with the same device instance number
        correlate the fleet in one broadcast."""
        instances = [
            etree.parse(_protocol_file(persona, "bacnet"))
            .getroot()
            .findtext("device_info/device_identifier")
            for persona in PERSONAS
        ]
        self.assertEqual(len(instances), len(set(instances)), instances)

    def test_enip_identity_is_neither_a_cpppo_default_nor_shared(self):
        """EnipServer.apply_identity makes <device_info> load-bearing, so a
        template repeating a cpppo default actively advertises one -- and two
        personas repeating each other advertise one fleet."""
        serials = []
        for persona in PERSONAS:
            root = etree.parse(_protocol_file(persona, "enip")).getroot()
            self.assertNotEqual(
                "1756-L61/B LOGIX5561", root.findtext("device_info/ProductName")
            )
            self.assertNotEqual(
                0x006C061A, int(root.findtext("device_info/SerialNumber"))
            )
            self.assertNotEqual(
                0x3160, int(root.findtext("device_info/StatusWord"), 0)
            )
            serials.append(root.findtext("device_info/SerialNumber"))
        self.assertEqual(len(serials), len(set(serials)), serials)

    def test_no_persona_SERVES_an_upstream_conpot_seed_string(self):
        """The upstream default template's strings identify a Conpot rather
        than a device, and a persona that repeats one advertises itself.

        Scoped to what is actually SERVED: XML element text and attribute
        values with comments stripped, plus every htdocs and statuscodes body.
        A bare `grep -r` would fail on the prose -- several templates name the
        cpppo default identity in a comment precisely to explain why the
        values below had to be replaced.
        """
        forbidden = (
            "Siemens, SIMATIC, S7-200",
            "Mouser Factory",
            "Technodrome",
            "Original Siemens Equipment",
            "1756-L61/B LOGIX5561",
            "VAV-DD Controller",
        )
        for persona in PERSONAS:
            served = []
            for root, _dirs, files in os.walk(_template_dir(persona)):
                for name in files:
                    path = os.path.join(root, name)
                    if name.endswith(".xml"):
                        tree = etree.parse(path)
                        etree.strip_elements(
                            tree, etree.Comment, with_tail=False
                        )
                        for element in tree.getroot().iter():
                            if isinstance(element.tag, str):
                                served.append(element.text or "")
                                served.extend(element.attrib.values())
                    elif name.endswith((".html", ".status")):
                        with open(path, encoding="utf-8") as fh:
                            served.append(fh.read())
            blob = "\n".join(served)
            for needle in forbidden:
                self.assertNotIn(
                    needle, blob, "%s serves %r" % (persona, needle)
                )

    # ── The persona manifest the forwarder reads ─────────────────────────────

    def test_every_persona_carries_a_manifest_naming_itself(self):
        for persona in PERSONAS:
            manifest = _manifest(persona)
            self.assertEqual(persona, manifest["persona"])
            self.assertEqual(1, manifest["schema_version"])
            self.assertTrue(manifest["label"])
            self.assertTrue(manifest["sector"])

    def test_manifest_sectors_are_canonical_and_distinct(self):
        """Sector keys must be canonical keys from
        ironmonkey-unified/shared/sector_taxonomy.yaml -- a non-canonical
        value takes the PIR endpoints to 503 rather than being ignored. The
        list is duplicated here rather than read, because this repo does not
        mount that file; the unified repo's test_sensor_compose.sh checks the
        pair against the taxonomy itself.
        """
        canonical = {
            "energy",
            "water_wastewater",
            "chemical",
            "manufacturing",
            "transportation",
            "oil_gas",
            "mining",
            "food_agriculture",
            "nuclear",
            "defense",
            "healthcare",
            "communications",
            "government",
            "commercial",
            "information_technology",
            "financial",
            "emergency_services",
            "dams",
            "multiple",
        }
        manifests = {persona: _manifest(persona) for persona in PERSONAS}
        for manifest in manifests.values():
            self.assertIn(manifest["sector"], canonical)
        # One persona per sector, among BASE personas. A regional variant
        # (step H13) declares `variant_of` and inherits its base's sector:
        # it is the same site class in another region, not a second answer
        # to the same PIR. It must still be distinct on every device
        # identity, which the forwarder's manifest test enforces.
        base_sectors = [
            m["sector"] for m in manifests.values() if not m.get("variant_of")
        ]
        self.assertEqual(len(base_sectors), len(set(base_sectors)), base_sectors)
        for persona, manifest in manifests.items():
            base = manifest.get("variant_of")
            if base:
                self.assertIn(base, manifests, "%s: variant_of unknown persona" % persona)
                self.assertFalse(manifests[base].get("variant_of"), "variant of a variant")
                self.assertEqual(manifests[base]["sector"], manifest["sector"], persona)

    def test_manifest_assets_are_complete(self):
        """A partial entry is worse than none: IronPot's uuid5 is over the
        whole (asset_type, vendor, model) triple, so a missing field mints a
        new identity rather than falling back."""
        for persona in PERSONAS:
            manifest = _manifest(persona)
            entries = [manifest["assets"]["default"]]
            entries += list(manifest["assets"].get("services", {}).values())
            for entry in entries:
                for field in ("asset_type", "vendor", "model"):
                    self.assertTrue(entry.get(field), entry)

    def test_manifest_asset_types_are_in_the_stix_extension_enum(self):
        """asset_type must stay inside the enum in
        ironmonkey-unified/shared/stix-extensions/x-ics-asset.json, or the
        node IronPot writes fails validation on the other side of the tailnet.
        """
        enum = {
            "plc",
            "rtu",
            "dcs",
            "hmi",
            "scada_server",
            "engineering_workstation",
            "safety_system",
            "network_device",
            "historian",
        }
        for persona in PERSONAS:
            manifest = _manifest(persona)
            entries = [manifest["assets"]["default"]]
            entries += list(manifest["assets"].get("services", {}).values())
            for entry in entries:
                self.assertIn(entry["asset_type"], enum)

    def test_manifest_service_keys_are_forwarder_data_types(self):
        """The forwarder looks the roster up by its own `data_type`, which is
        Conpot's lowercase protocol name -- not the directory name and not the
        port. `iec-104` is listed because _map_record accepts both spellings.
        """
        allowed = {
            "modbus",
            "s7comm",
            "iec104",
            "iec-104",
            "http",
            "snmp",
            "bacnet",
            "enip",
        }
        for persona in PERSONAS:
            services = _manifest(persona)["assets"].get("services", {})
            for service in services:
                self.assertIn(service, allowed)

    def test_manifest_iec104_spellings_agree(self):
        """If a persona maps one spelling it must map both, or half the
        IEC-104 sessions silently get the persona's default asset."""
        for persona in PERSONAS:
            services = _manifest(persona)["assets"].get("services", {})
            self.assertEqual(
                "iec104" in services,
                "iec-104" in services,
                "%s maps only one IEC-104 spelling" % persona,
            )
            if "iec104" in services:
                self.assertEqual(services["iec104"], services["iec-104"])
if __name__ == "__main__":
    unittest.main()
