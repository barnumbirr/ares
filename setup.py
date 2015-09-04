#!/usr/bin/env python
# -*- coding: utf-8 -*-

from distutils.core import setup

setup(
    name='ares',
    version='0.1',
    url='https://github.com/mrsmn/ares',
    download_url='https://github.com/mrsmn/ares/archive/master.zip',
    author='Martin Simon',
    author_email='me@martinsimon.me',
    license='Apache v2.0 License',
    packages=['whadup'],
    description='A python wrapper around cve.circl.lu',
    long_description=file('README.md','r').read(),
    keywords=['CVE', 'API', 'wrapper'],
)
