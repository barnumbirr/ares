#!/usr/bin/env python3
"""ares unit tests"""

import unittest

try:
    # So this works directly and with test discovery
    from core import CVESearch # type: ignore
except ModuleNotFoundError:
    from ares import CVESearch

class TestCVEAPI(unittest.TestCase):
    """Test the ares CVESearch interface"""

    def setUp(self) -> None:
        self.cve = CVESearch()

    def tearDown(self) -> None:
        self.cve.session.close()

    def test_init(self) -> None:
        """Check if we can initialise CVESearch"""
        self.assertTrue(isinstance(self.cve, CVESearch))

    def test_session_headers(self) -> None:
        """Check thet we set the application/json and user-agent request headers"""
        user_agent = 'ares - python wrapper around cve.circl.lu (github.com/mrsmn/ares)'
        self.assertEqual(self.cve.session.headers["Content-Type"], "application/json")
        self.assertEqual(self.cve.session.headers["User-agent"], user_agent)

    @unittest.skip("Long test")
    def test_empty_browse(self) -> None:
        """Make a browse request with no parameters"""
        response = self.cve.browse()
        self.assertIsNotNone(response)
        self.assertIsInstance(response, dict)
        self.assertIsNone(response["product"])
        self.assertIsInstance(response["vendor"], list)
        self.assertTrue(len(response["vendor"]) > 1000)

    def test_browse(self) -> None:
        """Make a browse request"""
        response = self.cve.browse(param="python-requests")
        self.assertIsNotNone(response)
        self.assertIsInstance(response, dict)
        self.assertEqual(response["vendor"], "python-requests")

    @unittest.skip("Long test")
    def test_search_vendor(self) -> None:
        """Search for a vendor"""
        # API returns way too much.
        response = self.cve.search(param="python-requests")
        self.assertIsNotNone(response)
        self.assertIsInstance(response, dict)
        self.assertIsInstance(response["data"], list)

    def test_search_vendor_product(self) -> None:
        """Search for a vendor/product"""
        response = self.cve.search(param="python-requests/requests")
        self.assertIsNotNone(response)
        self.assertIsInstance(response, list)
        self.assertTrue(len(response) > 0)

    def test_id(self) -> None:
        """Search for a CVE"""
        response = self.cve.id(param="CVE-2015-2296")
        self.assertIsNotNone(response)
        self.assertIsInstance(response, dict)

    def test_bad_id(self) -> None:
        """Search for a CVE that doesn't exist"""
        response = self.cve.id(param="CVE-not-real")
        self.assertIsNone(response)

    def test_last(self) -> None:
        """Request the last 30 CVEs"""
        response = self.cve.last()
        self.assertIsNotNone(response)
        self.assertIsInstance(response, list)
        self.assertEqual(len(response), 30)

    def test_db_info(self) -> None:
        """Get database information"""
        response = self.cve.dbinfo()
        self.assertIsNotNone(response)
        self.assertIsInstance(response, dict)

if __name__ == "__main__":
    unittest.main()
