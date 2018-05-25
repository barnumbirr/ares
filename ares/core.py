#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import requests
from requests.compat import urljoin

class CVESearch(object):

	_session = None
	__DEFAULT_BASE_URL = 'https://cve.circl.lu/api/'
	__DEFAULT_TIMEOUT = 120

	def __init__(self, base_url = __DEFAULT_BASE_URL, request_timeout = __DEFAULT_TIMEOUT):
		self.base_url = base_url
		self.request_timeout = request_timeout

	@property
	def session(self):
		if not self._session:
			self._session = requests.Session()
			self._session.headers.update({'Content-Type': 'application/json'})
			self._session.headers.update({'User-agent': 'ares - python wrapper \
		around cve.circl.lu (github.com/mrsmn/ares)'})
		return self._session

	def __request(self, endpoint, query):
		response_object = self.session.get(requests.compat.urljoin(self.base_url + endpoint, query),
		                                   timeout = self.request_timeout)

		try:
			response = json.loads(response_object.text)
		except Exception as e:
			return e

		return response

	def browse(self, param=None):
		""" browse() returns a dict containing all the vendors
			browse(vendor) returns a dict containing all the products
			associated to a vendor
		"""
		response = self.__request('browse/', query=param)
		return response

	def search(self, param):
		""" search() returns a dict containing all the vulnerabilities per
			vendor and a specific product
		"""
		response = self.__request('search/', query=param)
		return response

	def id(self, param):
		""" id() returns a dict containing a specific CVE ID """
		response = self.__request('cve/', query=param)
		return response

	def last(self):
		""" last() returns a dict containing the last 30 CVEs including CAPEC,
			CWE and CPE expansions
		"""
		response = self.__request('last/', query=None)
		return response

	def dbinfo(self):
		""" dbinfo() returns a dict containing more information about
			the current databases in use and when it was updated
		"""
		response = self.__request('dbInfo', query=None)
		return response
