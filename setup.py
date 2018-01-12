#!/usr/bin/env python
# -*- coding: utf-8 -*-

from distutils.core import setup

setup(
    name='ares',
    version='0.4',
    url='https://github.com/mrsmn/ares',
    download_url='https://github.com/mrsmn/ares/archive/master.zip',
    author='Martin Simon',
    author_email='me@martinsimon.me',
    license='Apache v2.0 License',
    packages=['ares'],
    description='Python wrapper around the cve.circl.lu API',
    long_description=open('README.md','r').read(),
    install_requires=['requests'],
    keywords=['CVE', 'cybersecurity', 'vulnerability', 'circl.lu', 'API', 'wrapper'],
)
