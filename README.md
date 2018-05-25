# ![icon](https://raw.githubusercontent.com/barnumbirr/ares/master/doc/ares.png) ares

[![PyPi Version](http://img.shields.io/pypi/v/ares.svg)](https://pypi.python.org/pypi/ares/)

**ares** is an APACHE licensed library written in Python providing an easy to use wrapper around https://cve.circl.lu.
This library has been tested with Python 2.7.x and Python 3.6.x.

## Installation:

From source use

        $ python setup.py install

or install from PyPi

        $ pip install ares

## Documentation:

- **`GET /api/browse/`**
- **`GET /api/browse/vendor`**

```python
>>> from ares import CVESearch
>>> cve = CVESearch()
>>> cve.browse(<vendor>)
```

- **`GET /api/search/vendor/product`**

```python
>>> cve.search('microsoft/office')
```

- **`GET /api/cveid/cveid`**

```python
>>> cve.id('CVE-2014-0160')
```

- **`GET /api/last`**

```python
>>> cve.last()
```

- **`GET /api/dbInfo`**

```python
>>> cve.dbinfo()
```

## License:

```
Copyright 2014-2018 Martin Simon

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

```

## Buy me a coffee?

If you feel like buying me a coffee (or a beer?), donations are welcome:

```
BTC : 1BNFXHPNRtg7LrLUmQWwPUwzoicUi3uP8Q
ETH : 0xd061B7dD794F6EB357bf132172ce06D1B0E5b97B
BCH : qpcmv8vstulfhgdf29fd8sf2g769sszscvaktty2rv
```
