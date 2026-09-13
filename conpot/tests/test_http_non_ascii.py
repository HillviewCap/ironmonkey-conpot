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

"""Serving a template page that is not pure ASCII (Phase 2 step H10c).

`utils.networking.str_to_bytes` encoded with `.encode("ascii")`. `do_GET`
sends the status line and the headers and THEN encodes the body through it,
so one non-ASCII byte anywhere in an htdocs file raised UnicodeEncodeError
after the client had already been promised a 200: a truncated body on a
broken connection, with the only trace a traceback in the container log.

That is not hypothetical. The substation persona's start page shipped with an
em dash and eight U+2022 bullets in its password placeholder, so the front
door of the persona -- the page carrying the `/login` form the H4 credential
capture depends on -- had never once reached a client. H4 worked around it by
forbidding non-ASCII bytes in the template; this step fixes the encoder, and
this file pins the fix.

The fixture is a COPY of the substation tree in a temporary directory, not an
edit to a shipped template: the personas belong to step H11 in this same
wave, and a decoy page is the wrong place to keep a test fixture anyway.
"""

from gevent import monkey

monkey.patch_all()

import os
import shutil
import tempfile
import unittest

import requests
from gevent import sleep
from lxml import etree

import conpot
from conpot import core
from conpot.protocols.http import web_server
from conpot.utils.greenlet import spawn_startable_greenlet, teardown_test_server
from conpot.utils.networking import str_to_bytes

TEMPLATE = "s7-315-substation"

# An em dash, a bullet, a degree sign and a non-Latin script: three of these
# are what a realistic HMI page actually contains, and the fourth proves the
# path is not quietly Latin-1.
NON_ASCII_BODY = (
    "<html><head><title>Geräteübersicht</title></head><body>"
    "<h1>Transformer room — 24.5°C</h1>"
    "<p>Status：正常 • • •</p>"
    "</body></html>"
)


def _spawn_from_directory(server_class, template_directory, protocol, port=0):
    """`spawn_test_server`, but for a template tree outside the package.

    The helper in `conpot.utils.greenlet` builds its paths from
    `conpot/templates/<name>`, which would mean shipping the fixture inside
    the installed package.
    """
    core.get_databus().initialize(os.path.join(template_directory, "template.xml"))
    server = server_class(
        template=os.path.join(template_directory, protocol, "%s.xml" % protocol),
        template_directory=template_directory,
        args=None,
    )
    greenlet = spawn_startable_greenlet(server, "127.0.0.1", port)
    greenlet.scheduled_once.wait()
    return server, greenlet


class TestNonAsciiPageIsServed(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="conpot-h10c-")
        source = os.path.join(os.path.dirname(conpot.__file__), "templates", TEMPLATE)
        cls.template_directory = os.path.join(cls.tmpdir, TEMPLATE)
        shutil.copytree(source, cls.template_directory)

        htdocs = os.path.join(cls.template_directory, "http", "htdocs")
        with open(os.path.join(htdocs, "utf8.html"), "w", encoding="utf-8") as fh:
            fh.write(NON_ASCII_BODY)

        # A file that is not valid UTF-8 at all, the way a page saved out of
        # a Windows editor arrives.
        with open(os.path.join(htdocs, "latin1.html"), "wb") as fh:
            fh.write(b"<html><body>Ger\xe4te</body></html>")

        http_xml = os.path.join(cls.template_directory, "http", "http.xml")
        tree = etree.parse(http_xml)
        htdocs_node = tree.xpath("//http/htdocs")[0]
        for name in ("/utf8.html", "/latin1.html"):
            node = etree.SubElement(htdocs_node, "node")
            node.set("name", name)
            headers = etree.SubElement(node, "headers")
            entity = etree.SubElement(headers, "entity")
            entity.set("name", "Content-Type")
            entity.text = "text/html"
        tree.write(http_xml, encoding="utf-8", xml_declaration=False)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def setUp(self):
        self.http_server, self.http_worker = _spawn_from_directory(
            web_server.HTTPServer, self.template_directory, "http"
        )
        sleep(0.5)
        self.base = "http://127.0.0.1:{0}".format(self.http_server.server_port)

    def tearDown(self):
        teardown_test_server(self.http_server, self.http_worker)

    def test_a_page_with_non_ascii_characters_is_served_whole(self):
        ret = requests.get(self.base + "/utf8.html")
        self.assertEqual(200, ret.status_code)
        self.assertEqual(NON_ASCII_BODY.encode("utf-8"), ret.content)

    def test_the_content_length_matches_the_bytes_actually_sent(self):
        """A body measured in characters and sent in UTF-8 bytes is a body
        the client truncates at exactly the promised length. `requests`
        returns the short read without complaining, so a test that only
        looked for a 200 would have passed on a half-served page."""
        ret = requests.get(self.base + "/utf8.html")
        self.assertEqual(
            len(NON_ASCII_BODY.encode("utf-8")), int(ret.headers["Content-Length"])
        )
        self.assertEqual(len(ret.content), int(ret.headers["Content-Length"]))

    def test_a_file_that_is_not_utf8_at_all_still_serves(self):
        """Decoding and encoding both use `surrogateescape`, so bytes go out
        exactly as they sit on disk whatever encoding the file was saved in.
        A strict decode raised mid-response instead."""
        ret = requests.get(self.base + "/latin1.html")
        self.assertEqual(200, ret.status_code)
        self.assertEqual(b"<html><body>Ger\xe4te</body></html>", ret.content)

    def test_the_ascii_start_page_is_unchanged(self):
        """UTF-8 is a superset of ASCII, so nothing that worked before moves."""
        ret = requests.get(self.base + "/index.html")
        self.assertEqual(200, ret.status_code)
        self.assertIn('action="/login"', ret.text)


class TestStrToBytes(unittest.TestCase):
    """`str_to_bytes` sits on the response path of every protocol handler."""

    def test_ascii_is_byte_identical_to_the_old_behaviour(self):
        self.assertEqual(b"Siemens CP443-1", str_to_bytes("Siemens CP443-1"))

    def test_bytes_pass_through(self):
        self.assertEqual(b"\x81\x0a", str_to_bytes(b"\x81\x0a"))

    def test_non_ascii_encodes_as_utf8(self):
        self.assertEqual("24.5°C".encode("utf-8"), str_to_bytes("24.5°C"))

    def test_surrogates_round_trip_the_original_bytes(self):
        raw = b"Ger\xe4te"
        self.assertEqual(raw, str_to_bytes(raw.decode("utf-8", "surrogateescape")))

    def test_no_input_can_raise(self):
        """A raise here truncates a reply whose headers have already gone
        out, so the last resort must be a replacement character."""
        self.assertIsInstance(str_to_bytes("\ud800"), bytes)
        self.assertIsInstance(str_to_bytes(1476), bytes)

    def test_non_string_values_still_stringify(self):
        self.assertEqual(b"1476", str_to_bytes(1476))


if __name__ == "__main__":
    unittest.main()
