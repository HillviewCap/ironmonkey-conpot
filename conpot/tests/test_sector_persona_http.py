# Copyright (C) 2026  IronMonkey
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
"""Served-HTTP behaviour of every sector persona (Phase 2 step H11).

`test_sector_personas.py` checks the template files. This module starts the
real HTTP server against each persona and asks it questions, because the two
things H11 has to get right are only observable from the wire:

1. **A missing path answers with a page.** Until this step the personas
   declared 400/404/501 in `http.xml` and shipped no `http/statuscodes/`
   directory at all, so `load_status` logged
   `FileNotFoundError .../http/statuscodes/404.status` and answered with a
   zero-length body -- once per scanner probe, which is the single most
   common request an internet-exposed sensor gets.

2. **Every persona still challenges for credentials.** SIR-006-05 is
   answerable only from a sensor that makes a client volunteer one.
   `test_http_hmi_auth.py` pins that on the substation persona; these pin it
   on the two H11 adds, so a new persona cannot ship as a silent sensor.

The `_SUCCESS_TELLS` property is the one that matters more than capture: no
input may produce a page that looks logged in. There is no credential
comparison anywhere in this path, so there is no pair -- default or otherwise
-- that can get past the login.
"""

from gevent import monkey

monkey.patch_all()
import unittest

import requests
from gevent import sleep

from conpot.protocols.http import web_server
from conpot.utils.greenlet import spawn_test_server, teardown_test_server

_SUCCESS_TELLS = (
    "logout",
    "runtime started",
    "welcome",
    "session established",
)


class _PersonaHttpCase(unittest.TestCase):
    """Base case. Subclasses set TEMPLATE, REALM, SERVER and SYS_NAME, and
    DENIED_TEXT when the persona's rejection page is not in English."""

    TEMPLATE = None
    REALM = None
    SERVER = None
    SYS_NAME = None
    # Lower-cased substring of the /login 403 body. Entities stay literal
    # (the body is ASCII on the wire), so a German page matches on
    # "ung&uuml;ltig", not on the rendered umlaut.
    DENIED_TEXT = "invalid user name or password"

    def setUp(self):
        if self.TEMPLATE is None:
            self.skipTest("base class")
        self.http_server, self.http_worker = spawn_test_server(
            web_server.HTTPServer, self.TEMPLATE, "http"
        )
        sleep(0.5)
        self.base = "http://127.0.0.1:{0}".format(self.http_server.server_port)

    def tearDown(self):
        if self.TEMPLATE is None:
            return
        teardown_test_server(self.http_server, self.http_worker)

    # ── The statuscodes gap ──────────────────────────────────────────────────

    def test_unknown_path_answers_404_with_a_body(self):
        ret = requests.get(self.base + "/cgi-bin/not-a-real-path")
        self.assertEqual(404, ret.status_code)
        self.assertGreater(
            len(ret.content),
            0,
            "empty 404 body: http/statuscodes/404.status is missing again",
        )

    def test_404_body_is_the_persona_not_a_conpot_default(self):
        """The page substitutes the persona's own databus keys, so a template
        that ships the upstream file would be visible here rather than only in
        a side-by-side diff."""
        ret = requests.get(self.base + "/cgi-bin/not-a-real-path")
        self.assertIn(self.SYS_NAME, ret.text)
        self.assertNotIn("This resource could not be found", ret.text)

    def test_404_is_stable_across_repeated_probes(self):
        """A scanner sends dozens. The old code path raised inside
        `load_status` every time and only the log showed it."""
        for _ in range(3):
            ret = requests.get(self.base + "/nope")
            self.assertEqual(404, ret.status_code)
            self.assertGreater(len(ret.content), 0)

    # ── The persona's front door ─────────────────────────────────────────────

    def test_root_redirects_to_the_start_page(self):
        ret = requests.get(self.base + "/", allow_redirects=False)
        self.assertEqual(302, ret.status_code)
        self.assertEqual("/index.html", ret.headers.get("Location"))
        self.assertEqual(self.SERVER, ret.headers.get("Server"))

    def test_start_page_serves_and_carries_the_login_form(self):
        """A non-ASCII byte under htdocs raises UnicodeEncodeError AFTER the
        headers have gone out, so the page 200s and the body is truncated.
        Fetching it is the only way to catch that."""
        ret = requests.get(self.base + "/index.html")
        self.assertEqual(200, ret.status_code)
        self.assertIn('action="/login"', ret.text)
        self.assertIn("</html>", ret.text)

    # ── The H4 credential bait ───────────────────────────────────────────────

    def test_hmi_challenges_with_the_persona_realm(self):
        ret = requests.get(self.base + "/hmi/")
        self.assertEqual(401, ret.status_code)
        self.assertEqual(
            'Basic realm="{0}"'.format(self.REALM),
            ret.headers.get("WWW-Authenticate"),
            "no challenge header -> curl -u sends nothing -> H4 captures nothing",
        )
        self.assertEqual("no-store", ret.headers.get("Cache-Control"))
        self.assertEqual(self.SERVER, ret.headers.get("Server"))

    def test_hmi_aliases_resolve(self):
        for path in ("/hmi", "/hmi/", "/hmi/index.html"):
            ret = requests.get(self.base + path, allow_redirects=False)
            self.assertEqual(401, ret.status_code, "path {0}".format(path))

    def test_default_credentials_are_rejected_and_never_look_accepted(self):
        ret = requests.get(self.base + "/hmi/", auth=("admin", "admin"))
        self.assertEqual(401, ret.status_code)
        body = ret.text.lower()
        for tell in _SUCCESS_TELLS:
            self.assertNotIn(tell, body, "the persona must never look logged-in")

    def test_login_post_returns_403_not_404(self):
        """Until H4 the form's own action had no node behind it, which both
        told the attacker the page was scenery and threw away every credential
        typed into it."""
        ret = requests.post(
            self.base + "/login",
            data={"username": "operator", "password": "1234"},
        )
        self.assertEqual(403, ret.status_code)
        self.assertIn(self.DENIED_TEXT, ret.text.lower())

    def test_hmi_post_is_rejected_the_same_way_as_get(self):
        ret = requests.post(
            self.base + "/hmi/", data={"username": "admin", "password": "admin"}
        )
        self.assertEqual(401, ret.status_code)


class TestWaterUtilityHttp(_PersonaHttpCase):
    TEMPLATE = "water-utility"
    REALM = "MicroLogix 1400"
    SERVER = "Rockwell Automation/MicroLogix 1400"
    SYS_NAME = "WTP-01-DOSING-CPU"


class TestOilGasPipelineHttp(_PersonaHttpCase):
    TEMPLATE = "oil-gas-pipeline"
    REALM = "S7-1500 Web Server"
    SERVER = "Siemens SIMATIC S7-1500 Webserver V2.9"
    SYS_NAME = "CS-07-UNIT-CPU"


class TestSubstationStatusCodes(_PersonaHttpCase):
    """The substation persona is already covered by test_http_hmi_auth.py for
    the credential path; it is here for the 404 body, which is the defect this
    step closes on the one persona that is actually deployed."""

    TEMPLATE = "s7-315-substation"
    REALM = "SIMATIC HMI"
    SERVER = "Siemens CP443-1 Advanced V3.3.0"
    SYS_NAME = "S7-315-SUBSTATION-01"


class TestSubstationDeHttp(_PersonaHttpCase):
    """The DACH variant (step H13). German page bodies are served as ASCII
    with HTML entities; a fetch is the only way to prove the entity route
    survived the `str_to_bytes` trap, and that the realm is its own."""

    TEMPLATE = "s7-317-substation-de"
    REALM = "WinCC Runtime UW-OST"
    SERVER = "Siemens CP343-1 Advanced V3.0.4"
    SYS_NAME = "UW-OST-S7-317"
    DENIED_TEXT = "benutzername oder kennwort ung&uuml;ltig"

    def test_german_page_renders_umlauts_as_entities(self):
        ret = requests.post(
            self.base + "/login", data={"username": "a", "password": "b"}
        )
        self.assertIn("&uuml;", ret.text)
        self.assertTrue(ret.content.isascii(), "non-ASCII byte reached the wire")


if __name__ == "__main__":
    unittest.main()
