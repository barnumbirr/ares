# ![icon](https://raw.githubusercontent.com/barnumbirr/ares/master/doc/ares.png) ares

[![PyPi Version](http://img.shields.io/pypi/v/ares.svg)](https://pypi.python.org/pypi/ares/)

**ares** is an APACHE licensed library written in Python providing an easy to use wrapper around https://cve.circl.lu.
This library has been tested with Python 2.7.x and Python 3.6+.

## Installation:

From source use

```bash
$ python setup.py install
```

or install from PyPi

```bash
$ pip install ares
```

## Documentation:

#### **`GET /api/browse`**
#### **`GET /api/browse/<vendor>`**

##### Description

Returns a list of vendors or products of a specific vendor.
This API call can be used in two ways; With or without the vendor.
When the link is called without a vendor, it will return a list of possible vendors.
When the link is called with a vendor, it enumerates the products for said vendor.

| Argument            | Description         | Example              |
| :-------------------| :------------------ | :------------------- |
| vendor              | Vendor name         | `microsoft`          |

```python
>>> from ares import CVESearch
>>> cve = CVESearch()
>>> cve.browse('microsoft')
```

<br/>

#### **`GET /api/capec/<cpe> `**

##### Description

Outputs a list of CAPEC related to a CWE.
CAPEC (Common Attack Pattern Enumeration and Classification) are a list of attack types commonly used by attackers.

| Argument            | Description         | Example              |
| :-------------------| :------------------ | :------------------- |
| cweid               | CWE ID              | `200`                |


```python
>>> cve.capec('200')
```

<br/>

#### **`GET /api/cpe2.2/<cpe> `**

##### Description

**DISABLED ON cve.circl.lu**

Converts a CPE code to the CPE2.2 standard, stripped of appendices.
CPE2.2 is the old standard, and is a lot less uniform than the CPE2.3 standard.

| Argument            | Description                         | Example                                                                |
| :-------------------| :---------------------------------- | :--------------------------------------------------------------------- |
| cpe                 | CPE code in cpe2.2 or cpe2.3 format | `cpe:2.3:o:microsoft:windows_vista:6.0:sp1:-:-:home_premium:-:-:x64:-` |

```python
>>> cve.cpe22('cpe:2.3:a:microsoft:office:2011:-:mac')
```

<br/>

#### **`GET /api/cpe2.3/<cpe> `**

##### Description

**DISABLED ON cve.circl.lu**

Converts a CPE code to the CPE2.3 standard, stripped of appendices.
CPE2.3 is the newer standard, and is a lot more uniform and easier to read than the CPE2.2 standard.

| Argument            | Description                         | Example                                                          |
| :-------------------| :---------------------------------- | :--------------------------------------------------------------- |
| cpe                 | CPE code in cpe2.2 or cpe2.3 format | `cpe:/o:microsoft:windows_vista:6.0:sp1:~-~home_premium~-~x64~-` |

```python
>>> cve.cpe23('cpe:/a:microsoft:office:2011::mac')
```

<br/>

#### **`GET /api/cve/<cveid>`**

##### Description

Outputs all available information for the specified CVE (Common Vulnerability and Exposure), in JSON format.
This information includes basic CVE information like CVSS (Common Vulnerability Scoring System), related CPE (Common Product Enumeration),
CWE (Common Weakness Enumeration), ... as well as additional information (RedHat Advisories etc).

| Argument            | Description           | Example                  |
| :-------------------| :-------------------- | :----------------------- |
| cveid               | CVE number            | `CVE-2014-0160`          |

```python
>>> cve.id('CVE-2014-0160')
```

<br/>

#### **`GET /api/cvefor/<cpe> `**

##### Description

**DISABLED ON cve.circl.lu**

Outputs a list of CVEs related to the product.

| Argument            | Description                         | Example                                                          |
| :-------------------| :---------------------------------- | :--------------------------------------------------------------- |
| cpe                 | CPE code in cpe2.2 or cpe2.3 format | `cpe:/o:microsoft:windows_vista:6.0:sp1:~-~home_premium~-~x64~-` |


```python
>>> cve.cvefor('cpe:/o:microsoft:windows_vista:6.0:sp1:~-~home_premium~-~x64~-')
```

<br/>

#### **`GET /api/cwe `**

##### Description

Outputs a list of all CWEs (Common Weakness Enumeration).

```python
>>> cve.cwe()
```

<br/>

#### **`GET /api/dbInfo`**

##### Description

Returns the stats of the database. When the user authenticates, more information is returned. This information includes:

    Amount of whitelist and blacklist records
    Some server settings like the database name
    Some database information like disk usage

Unauthenticated queries return only collection information.

**Note: as of April 2020, authentication is disabled on cve.circl.lu.**

```python
>>> cve.dbinfo()
```

<br/>

#### **`GET /api/last`**
#### **`GET /api/last/<limit>`**

##### Description

Outputs the last `n` amount of vulnerabilities. If the limit is not specified, the default of 30 is used.

| Argument            | Description                         | Example                |
| :-------------------| :---------------------------------- | :--------------------- |
| limit               | The amount of CVEs to display       | `10`                   |

```python
>>> cve.last('10')
```

<br/>

#### **`GET /api/search/link/<key>/<value>`**

##### Description

**DISABLED ON cve.circl.lu**

Returns all CVEs that are linked by a given key/value pair.

| Argument            | Description                         | Example                     |
| :-------------------| :---------------------------------- | :-------------------------- |
| key                 | The key to link CVEs on             | `refmap.ms`                 |
| value               | The value for the given key         | `MS16-098`                  |

```python
>>> cve.link('refmap.ms/MS16-098')
```

<br/>

#### **`GET /api/search/<vendor>/<product>`**

##### Description

**DISABLED ON cve.circl.lu**

When vendor and product are specified, this API call returns a list of CVEs related to the product. The output of the browse call can be used for this.

| Argument            | Description                         | Example                     |
| :-------------------| :---------------------------------- | :-------------------------- |
| vendor              | Vendor name                         | `microsoft`                 |
| product             | Product name                        | `office`                    |

```python
>>> cve.search('microsoft/office')
```

## License:

```
Copyright 2014-2020 Martin Simon

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
