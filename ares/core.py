#!/usr/bin/env python
# -*- coding: utf-8 -*-

import urllib2

class CVESearch(object):

	def __init__(self, base_url='https://cve.circl.lu/api/'):
		self.base_url = base_url
		self.opener = urllib2.build_opener()
		self.opener.addheaders.append(('Content-Type', 'application/json'))
		self.opener.addheaders.append(('User-agent', 'ares - python wrapper \
		around cve.circl.lu (github.com/mrsmn/ares)'))
	
	def _urljoin(self, *args):
		""" Internal urljoin function because urlparse.urljoin sucks. """
		return "/".join(map(lambda x: str(x).rstrip('/'), args))

	def browse(self, query=None):
		url = self._urljoin(self.base_url, 'browse/')
		if query == None:
			response = self.opener.open(url).read()
			return response
		else:
			response_url = self._urljoin(url, query)
			response = self.opener.open(response_url).read()
			return response

	def search(self, query):
		url = self._urljoin(self.base_url, 'search/')
		response_url = self._urljoin(url, query)
		response = self.opener.open(response_url).read()
		return response

	def id(self, query):
		url = self._urljoin(self.base_url, 'cve/')
		response_url = self._urljoin(url, query)
		response = self.opener.open(response_url).read()
		return response

	def last(self):
		url = self._urljoin(self.base_url, 'last/')
		response = self.opener.open(url).read()
		return response

	def cpe22(self, query):
		url = self._urljoin(self.base_url, 'cpe2.2/')
		response_url = self._urljoin(url, query)
		response = self.opener.open(response_url).read()
		return response

	def cpe23(self, query):
		url = self._urljoin(self.base_url, 'cpe2.3/')
		response_url = self._urljoin(url, query)
		response = self.opener.open(response_url).read()
		return response

	def cvefor(self, query):
		url = self._urljoin(self.base_url, 'cvefor/')
		response_url = self._urljoin(url, query)
		response = self.opener.open(response_url).read()
		return response
	