#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
try:
    from .core import CVESearch
except ModuleNotFoundError:
    from ares import CVESearch

class TestCVEAPI(unittest.TestCase):

    def setUp(self):
        self.cve = CVESearch()

    def tearDown(self):
        self.cve.session.close()

    def test_init(self):
        self.assertTrue(isinstance(self.cve, CVESearch))

    def test_session_headers(self):
        user_agent = 'ares - python wrapper around cve.circl.lu (github.com/barnumbirr/ares)'
        self.assertEqual(self.cve.session.headers["Content-Type"], "application/json")
        self.assertEqual(self.cve.session.headers["User-agent"], user_agent)

    @unittest.skip("Test too aggressive for provider.")
    def test_empty_browse(self):
        response = self.cve.browse()
        self.assertIsNotNone(response)
        self.assertIsInstance(response, dict)
        self.assertIsNone(response["product"])
        self.assertIsInstance(response["vendor"], list)
        self.assertTrue(len(response["vendor"]) > 1000)

    def test_browse(self):
        response = self.cve.browse(param="python-requests")
        self.assertIsNotNone(response)
        self.assertIsInstance(response, dict)
        self.assertEqual(response["vendor"], "python-requests")

    def test_capec(self):
        response = self.cve.capec(param="13")
        self.assertIsNotNone(response)
        self.assertIsInstance(response, dict)
        self.assertEqual(response["name"], "Subverting Environment Variable Values")

    @unittest.skip("Endpoint disabled on cve.circl.lu")
    def test_cpe22(self):
        response = self.cve.cpe22('cpe:2.3:o:microsoft:windows_vista:6.0:sp1:-:-:home_premium:-:-:x64:-')
        self.assertIsNotNone(response)
        self.assertIsInstance(response, str)
        self.assertEqual(response, "cpe:/o:microsoft:windows_vista:6.0:sp1:~~home_premium~~x64~")

    @unittest.skip("Endpoint disabled on cve.circl.lu")
    def test_cpe23(self):
        response = self.cve.cpe23('cpe:/o:microsoft:windows_vista:6.0:sp1:~-~home_premium~-~x64~-')
        self.assertIsNotNone(response)
        self.assertIsInstance(response, str)
        self.assertEqual(response, "cpe:2.3:o:microsoft:windows_vista:6.0:sp1:-:-:home_premium:-:-:x64")

    @unittest.skip("Endpoint disabled on cve.circl.lu")
    def test_cvefor(self):
        response = self.cve.cvefor('cpe:/o:microsoft:windows_vista:6.0:sp1:~-~home_premium~-~x64~-')
        self.assertIsNotNone(response)
        self.assertIsInstance(response, dict)
        self.assertEqual(response["id"], "CVE-2005-0100")

    @unittest.skip("Test too aggressive for provider.")
    def test_cwe(self):
        response = self.cve.cwe()
        self.assertIsNotNone(response)
        self.assertIsInstance(response, dict)

    def test_db_info(self):
        response = self.cve.dbinfo()
        self.assertIsNotNone(response)
        self.assertIsInstance(response, dict)

    def test_id(self):
        response = self.cve.id(param="CVE-2015-2296")
        self.assertIsNotNone(response)
        self.assertIsInstance(response, dict)
        self.assertEqual(response["Published"], "2015-03-18T16:59:00")

    def test_bad_id(self):
        response = self.cve.id(param="CVE-not-real")
        self.assertIsNone(response)

    def test_last(self):
        response = self.cve.last()
        self.assertIsNotNone(response)
        self.assertIsInstance(response, list)
        self.assertEqual(len(response), 30)

    @unittest.skip("Endpoint disabled on cve.circl.lu")
    def test_link(self):
        response = self.cve.link(param="refmap.ms/CVE-2016-3309")
        self.assertIsNotNone(response)
        self.assertIsInstance(response, dict)
        self.assertEqual(response["cves"]["cwe"], "CWE-264")

    @unittest.skip("Endpoint disabled on cve.circl.lu")
    def test_search_vendor(self):
        response = self.cve.search(param="python-requests")
        self.assertIsNotNone(response)
        self.assertIsInstance(response, dict)
        self.assertIsInstance(response["data"], list)

if __name__ == "__main__":
    unittest.main()
