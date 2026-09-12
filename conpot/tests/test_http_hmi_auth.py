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

"""Credential-bait paths on the s7-315-substation persona (Phase 2 step H4).

SIR-006-05 asks which honeypot sessions attempted default-credential HMI
access. It was unanswerable by construction: the persona's `http.xml` never
issued a challenge, so no client ever volunteered a credential and the whole
downstream chain -- forwarder, IronPot allow-list, STIX session writer, the
`T0812` rule -- had nothing to carry.

Two paths now provoke one:

  GET  /hmi/   -> 401 + `WWW-Authenticate: Basic realm="SIMATIC HMI"`
  POST /login  -> 403 + a "sign-in failed" page

Both are static template nodes. Conpot 0.6.0's `load_entity` honours a
per-node `<status>` and `<headers>` for GET and POST alike, which is why no
protocol-handler patch was needed -- and these tests exist to pin that, since
the whole step rests on it. They also pin the property that matters more than
capture: NO input produces a success page. There is no credential comparison
anywhere in the path, so there is no pair that can get past the login.

Runs against the real persona template, not the upstream `default` one --
`spawn_test_server` takes the template name, and the substation tree is what
ships to a sensor.
"""

from gevent import monkey

monkey.patch_all()
import os
import unittest

import requests
from gevent import sleep
from lxml import etree

import conpot
from conpot.protocols.http import web_server
from conpot.utils.greenlet import spawn_test_server, teardown_test_server

TEMPLATE = "s7-315-substation"

# Anything here in a response body would tell the attacker the login worked.
# The persona must never emit one.
_SUCCESS_TELLS = (
    "logout",
    "runtime started",
    "welcome",
    "session established",
)


class TestSubstationHmiAuth(unittest.TestCase):
    def setUp(self):
        self.http_server, self.http_worker = spawn_test_server(
            web_server.HTTPServer, TEMPLATE, "http"
        )
        sleep(0.5)
        self.base = "http://127.0.0.1:{0}".format(self.http_server.server_port)

    def tearDown(self):
        teardown_test_server(self.http_server, self.http_worker)

    # ── The Basic challenge ──────────────────────────────────────────────────

    def test_hmi_get_without_credentials_challenges_with_the_simatic_realm(self):
        """The 401 is what makes a client volunteer a credential on the retry."""
        ret = requests.get(self.base + "/hmi/")
        self.assertEqual(401, ret.status_code)
        self.assertEqual(
            'Basic realm="SIMATIC HMI"',
            ret.headers.get("WWW-Authenticate"),
            "no challenge header -> curl -u sends nothing -> H4 captures nothing",
        )

    def test_hmi_challenge_keeps_the_persona_banner(self):
        ret = requests.get(self.base + "/hmi/")
        self.assertEqual(
            "Siemens CP443-1 Advanced V3.3.0", ret.headers.get("Server")
        )
        self.assertEqual("SIMATIC WinCC", ret.headers.get("X-Powered-By"))

    def test_hmi_challenge_is_not_cacheable(self):
        """A cached 401 breaks the challenge/retry the capture depends on."""
        ret = requests.get(self.base + "/hmi/")
        self.assertEqual("no-store", ret.headers.get("Cache-Control"))

    def test_hmi_challenge_body_carries_a_login_form(self):
        ret = requests.get(self.base + "/hmi/")
        self.assertIn('name="username"', ret.text)
        self.assertIn('name="password"', ret.text)

    def test_hmi_with_default_credentials_is_still_rejected(self):
        """`curl -u admin:admin` -- the step's own verification command."""
        ret = requests.get(self.base + "/hmi/", auth=("admin", "admin"))
        self.assertEqual(401, ret.status_code)
        body = ret.text.lower()
        for tell in _SUCCESS_TELLS:
            self.assertNotIn(tell, body, "the persona must never look logged-in")

    def test_hmi_post_is_rejected_the_same_way_as_get(self):
        """Conpot serves POST from the same node, so the static 401 covers it.
        If this ever regresses to 404 the login POST stops being an
        interaction and the H2 bot filter reasoning changes with it."""
        ret = requests.post(
            self.base + "/hmi/", data={"username": "admin", "password": "admin"}
        )
        self.assertEqual(401, ret.status_code)

    def test_hmi_aliases_resolve(self):
        for path in ("/hmi", "/hmi/", "/hmi/index.html"):
            ret = requests.get(self.base + path, allow_redirects=False)
            self.assertEqual(401, ret.status_code, "path {0}".format(path))

    # ── The form POST target ─────────────────────────────────────────────────

    def test_login_post_returns_403_not_404(self):
        """The start page has always advertised `action="/login"`. Until H4
        there was no node behind it: the form's own action 404'd, which both
        tells the attacker the page is scenery and threw away every credential
        typed into it."""
        ret = requests.post(
            self.base + "/login", data={"username": "operator", "password": "1234"}
        )
        self.assertEqual(403, ret.status_code)

    def test_login_rejection_says_the_credentials_were_wrong(self):
        ret = requests.post(
            self.base + "/login", data={"username": "admin", "password": "admin"}
        )
        body = ret.text.lower()
        self.assertIn("invalid user name or password", body)
        for tell in _SUCCESS_TELLS:
            self.assertNotIn(tell, body)

    def test_start_page_form_action_matches_the_node_that_exists(self):
        """Pins the pair. If either side moves, the credential path breaks
        silently -- the form still submits, the sensor still answers, and
        nothing is captured."""
        ret = requests.get(self.base + "/index.html")
        self.assertEqual(200, ret.status_code)
        self.assertIn('action="/login"', ret.text)

    # ── Template validity ────────────────────────────────────────────────────

    def test_http_template_validates_against_the_protocol_xsd(self):
        """The XSD orders a node's children (status, tarpit, triggers,
        headers, alias). Conpot rejects the whole template on a violation, so
        a misordered element takes the sensor's HTTP service down entirely."""
        conpot_dir = os.path.dirname(conpot.__file__)
        xml_path = "{0}/templates/{1}/http/http.xml".format(conpot_dir, TEMPLATE)
        xsd_path = "{0}/protocols/http/http.xsd".format(conpot_dir)
        schema = etree.XMLSchema(etree.parse(xsd_path))
        schema.assertValid(etree.parse(xml_path))


if __name__ == "__main__":
    unittest.main()
