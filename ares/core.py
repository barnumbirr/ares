#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests

class CVESearch(object):

	_session = None
	__DEFAULT_BASE_URL = "https://cve.circl.lu/api/"
	__DEFAULT_TIMEOUT = 120

	def __init__(self, base_url = __DEFAULT_BASE_URL, request_timeout = __DEFAULT_TIMEOUT):
		self.base_url = base_url
		self.request_timeout = request_timeout
		self.session = self._create_session()

	@staticmethod
	def _create_session():
		session = requests.Session()
		user_agent = 'ares - python wrapper around cve.circl.lu (github.com/barnumbirr/ares)'
		session.headers.update({'Content-Type': 'application/json'})
		session.headers.update({'User-agent': user_agent})
		return session

	def __request(self, endpoint, query):
		# There is probably a more elegant way to do this ¯\_(ツ)_/¯
		if query:
			response = self.session.get(requests.compat.urljoin(self.base_url, endpoint + query),
		                                timeout = self.request_timeout)
		else:
			response = self.session.get(requests.compat.urljoin(self.base_url, endpoint),
		                                timeout = self.request_timeout)

		response.raise_for_status()
		return response.json()

	def browse(self, param=None):
		return self.__request('browse/', query=param)

	def capec(self, param):
		return self.__request('capec/', query=param)

	# def cpe22(self, param):
	# 	return self.__request('cpe2.2/', query=param)

	# def cpe23(self, param):
	# 	return self.__request('cpe2.3/', query=param)

	# def cvefor(self, param):
	# 	return self.__request('cvefor/', query=param)

	def cwe(self):
		""" Outputs a list of all CWEs (Common Weakness Enumeration). """
		return self.__request('cwe', query=None)

	def dbinfo(self):
		return self.__request('dbInfo', query=None)

	def id(self, param):
		return self.__request('cve/', query=param)

	def last(self, param=None):
		return self.__request('last/', query=param)

	# def link(self, param):
	# 	return self.__request('link/', query=param)

	# def search(self, param):
	# 	return self.__request('search/', query=param)
