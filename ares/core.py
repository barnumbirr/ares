#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import requests

class CVESearch(object):

	_session = None
	__DEFAULT_BASE_URL = "https://cve.circl.lu/api/"
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
		around cve.circl.lu (github.com/barnumbirr/ares)'})
		return self._session

	def __request(self, endpoint, query):
		# There is probably a more elegant way to do this ¯\_(ツ)_/¯
		if query:
			response_object = self.session.get(requests.compat.urljoin(self.base_url, endpoint + query),
		                                   timeout = self.request_timeout)
		else:
			response_object = self.session.get(requests.compat.urljoin(self.base_url, endpoint),
		                                   timeout = self.request_timeout)

		try:
			response = json.loads(response_object.text)
		except Exception as e:
			return e

		return response

	def browse(self, param=None):
		response = self.__request('browse/', query=param)
		return response

	def capec(self, param):
		response = self.__request('capec/', query=param)
		return response

	# def cpe22(self, param):
	# 	response = self.__request('cpe2.2/', query=param)
	# 	return response


	# def cpe23(self, param):
	# 	response = self.__request('cpe2.3/', query=param)
	# 	return response

	def cve(self, param):
		response = self.__request('cve/', query=param)
		return response

	# def cvefor(self, param):
	# 	response = self.__request('cvefor/', query=param)
	# 	return response

	def cwe(self):
		""" Outputs a list of all CWEs (Common Weakness Enumeration). """
		response = self.__request('cwe', query=None)
		return response

	def dbinfo(self):
		response = self.__request('dbInfo', query=None)
		return response

	def last(self, param):
		response = self.__request('last/', query=param)
		return response

	def link(self, param):
		response = self.__request('link/', query=param)
		return response

	# def search(self, param):
	# 	response = self.__request('search/', query=param)
	# 	return response
