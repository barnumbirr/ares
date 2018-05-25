#!/usr/bin/env python
# -*- coding: utf-8 -*-

# To use a consistent encoding
from os import path
from codecs import open
# Always prefer setuptools over distutils
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='ares',
    packages = ['ares'],
    version = '0.5',
    description = 'Python wrapper around https://cve.circl.lu.',
    author = 'Martin Simon',
    author_email = 'me@martinsimon.me',
    url = 'https://github.com/barnumbirr/ares',
    project_urls={
        'Bug Reports': 'https://github.com/barnumbirr/ares/issues',
        'Buy me a coffee': 'https://github.com/barnumbirr/ares#buy-me-a-coffee',
    },
    license = 'Apache v2.0 License',
    install_requires=[
    'requests>=2.18.4'
    ],
    keywords=['CVE', 'cybersecurity', 'vulnerability', 'circl.lu'],
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.6',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    long_description = long_description,
    long_description_content_type='text/markdown',
)
