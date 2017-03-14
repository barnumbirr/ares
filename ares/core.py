#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
	from urlparse import urljoin
except ImportError:
	from urllib.parse import urljoin
try:
	import urllib.request as urllib2
except ImportError:
	import urllib2

class CVESearch(object):

	def __init__(self, base_url='https://cve.circl.lu/api/'):
		self.base_url = base_url
		self.opener = urllib2.build_opener()
		self.opener.addheaders.append(('Content-Type', 'application/json'))
		self.opener.addheaders.append(('User-agent', 'ares - python wrapper \
		around cve.circl.lu (github.com/mrsmn/ares)'))

	def _urljoin(self, *args):
		""" Internal urljoin function because urlparse.urljoin sucks """
		return "/".join(map(lambda x: str(x).rstrip('/'), args))

	def _http_get(self, api_call, query):
		url = self._urljoin(self.base_url, api_call)
		if query == None:
			response = self.opener.open(url).read()
		else:
			response_url = self._urljoin(url, query)
			response = self.opener.open(response_url).read()
		return response

	def browse(self, param=None):
		""" browse() returns a dict containing all the vendors
			browse(vendor) returns a dict containing all the products
			associated to a vendor
		"""
		data = self._http_get('browse/', query=param)
		return data

	def search(self, param):
		""" search() returns a dict containing all the vulnerabilities per
			vendor and a specific product
		"""
		data = self._http_get('search/', query=param)
		return data

	def id(self, param):
		""" id() returns a dict containing a specific CVE ID """
		data = self._http_get('cve/', query=param)
		return data

	def last(self):
		""" last() returns a dict containing the last 30 CVEs including CAPEC,
			CWE and CPE expansions
		"""
		data = self._http_get('last/', query=None)
		return data

	def dbinfo(self):
		""" dbinfo() returns a dict containing more information about
			the current databases in use and when it was updated
		"""
		data = self._http_get('dbInfo/', query=None)
		return data

	def cpe22(self, param):
		""" cpe22() returns a string containing the cpe2.2 ID of a
			cpe2.3 input
		"""
		data = self._http_get('cpe2.2/', query=param)
		return data

	def cpe23(self, param):
		""" cpe23() returns a string containing the cpe2.3 ID of a
			cpe2.2 input
		"""
		data = self._http_get('cpe2.3/', query=param)
		return data

	def cvefor(self, param):
		""" cvefor() returns a dict containing the CVE's for a given
			CPE ID
		"""
		data = self._http_get('cvefor/', query=param)
		return data
