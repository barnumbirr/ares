# -*- coding: utf-8 -*-

from urllib.parse import urljoin
from typing import Union, Optional, Any
import requests

class CVESearch:

    _DEFAULT_BASE_URL = 'https://cve.circl.lu/api/'
    _DEFAULT_TIMEOUT = 120

    def __init__(self, base_url: str = _DEFAULT_BASE_URL,
                 request_timeout: int = _DEFAULT_TIMEOUT) -> None:
        self.base_url = base_url
        self.request_timeout = request_timeout
        self.session = self._get_session()

    @staticmethod
    def _get_session() -> requests.Session:
        session = requests.Session()
        user_agent = 'ares - python wrapper around cve.circl.lu (github.com/mrsmn/ares)'
        session.headers.update({'Content-Type': 'application/json'})
        session.headers.update({'User-agent': user_agent})
        return session

    def _request(self, endpoint: str, query: Optional[str]) -> Any:
        response = self.session.get(urljoin(self.base_url + endpoint, query),
                                    timeout=self.request_timeout)
        response.raise_for_status()
        return response.json()

    def browse(self, param=None) -> dict:
        """ browse() returns a dict containing all the vendors
            browse(vendor) returns a dict containing all the products
            associated to a vendor
        """
        return self._request('browse/', query=param)

    def search(self, param: str) -> Union[list, dict]:
        """ search(vendor/product) returns a list containing all the
            vulnerabilities per product, search(vendor) returns a dict of lists
        """
        return self._request('search/', query=param)

    def id(self, param: str) -> dict:
        """ id(cve) returns a dict containing a specific CVE ID """
        return self._request('cve/', query=param)

    def last(self) -> list:
        """ last() returns a list containing the last 30 CVEs including CAPEC,
            CWE and CPE expansions
        """
        return self._request('last/', query=None)

    def dbinfo(self) -> dict:
        """ dbinfo() returns a dict containing more information about
            the current databases in use and when it was updated
        """
        return self._request('dbInfo', query=None)
