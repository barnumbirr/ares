# ![icon](https://raw.githubusercontent.com/barnumbirr/ares/master/doc/ares.png) ares

[![PyPi Version](http://img.shields.io/pypi/v/ares.svg)](https://pypi.python.org/pypi/ares/)
[![CI](https://github.com/barnumbirr/ares/actions/workflows/ci.yml/badge.svg)](https://github.com/barnumbirr/ares/actions/workflows/ci.yml)

**ares** is a Python wrapper and CLI for the
[Vulnerability-Lookup](https://vulnerability.circl.lu) API.
It lets you query CVEs, EPSS scores, KEV catalogs, CWEs, and more — from
Python code or directly from the terminal.

Requires Python 3.9+. Licensed under the Apache License 2.0.

## Installation

```bash
pip install ares
```

This installs both the Python library (`from ares import VulnLookup`) and the
`ares-cli` command-line tool.

For development:

```bash
pip install -e ".[dev]"
```

## CLI

The `ares-cli` tool gives you direct access to the Vulnerability-Lookup API
from your terminal. Output is JSON — pretty-printed to a terminal, compact when
piped.

### Examples

```bash
# Look up a specific vulnerability
ares-cli vuln get CVE-2024-1234

# Include metadata and comments
ares-cli vuln get CVE-2024-1234 --with-meta --with-comments

# Get the EPSS score for a CVE
ares-cli epss CVE-2024-1234

# Browse vendors, or products for a vendor
ares-cli browse
ares-cli browse apache

# Search vulnerabilities by vendor and product
ares-cli vuln search apache httpd --per-page 20

# Search by CPE string
ares-cli vuln cpe-search "cpe:2.3:a:apache:httpd"

# List CISA Known Exploited Vulnerabilities
ares-cli kev cisa

# Get CWE details
ares-cli cwe get 79

# View statistics
ares-cli stats vuln-count --state published --period 2024 --source cvelistv5
ares-cli stats most-sighted --limit 10

# Classify severity with VLAI
ares-cli classify "buffer overflow in the HTTP parser"

# Check database status
ares-cli system db-info
```

### Global options

| Option | Environment variable | Description |
|---|---|---|
| `--api-key KEY` | `ARES_API_KEY` | API key for authenticated endpoints |
| `--base-url URL` | | Custom API base URL |
| `--timeout N` | | Request timeout in seconds (default: 120) |
| `--compact` | | Force compact JSON output |
| `--version` | | Show version and exit |

```bash
# Authenticate (option or env var)
ares-cli --api-key YOUR_KEY user me
export ARES_API_KEY=YOUR_KEY && ares-cli user me

# Query a self-hosted Vulnerability-Lookup instance
ares-cli --base-url https://my-instance.example.com/api browse

# Compact output for scripting
ares-cli --compact vuln list --product flask | jq '.[] .cveMetadata.cveId'
```

### Command reference

Run `ares-cli --help` for the full command list, or
`ares-cli <command> --help` for details on any command.

| Command | Description |
|---|---|
| `browse [VENDOR]` | List vendors, or products for a vendor |
| `epss CVE-ID` | EPSS score for a vulnerability |
| `rulezet CVE-ID` | Detection rules for a vulnerability |
| `classify DESCRIPTION` | VLAI severity classification |
| **vuln** | |
| `vuln get CVE-ID` | Get a vulnerability (flags: `--with-meta`, `--with-comments`, `--with-linked`, `--with-bundles`, `--with-sightings`) |
| `vuln list` | List vulnerabilities (`--product`, `--source`, `--cwe`, `--since`, `--sort-order`, `--date-sort`) |
| `vuln search VENDOR PRODUCT` | Search by vendor and product |
| `vuln cpe-search CPE` | Search by CPE string |
| `vuln vendors` | List known vendors |
| `vuln assigners` | List known CNAs |
| **kev** | |
| `kev list` | List KEV entries (`--exploited`, `--status-reason`, `--vuln-id`) |
| `kev get UUID` | Get a KEV entry |
| `kev cisa` | CISA KEV catalog |
| `kev cnw` | CNW KEV catalog |
| **cwe** | |
| `cwe get CWE-ID` | Get CWE details |
| `cwe list` | List CWEs (`--vuln-id`) |
| **capec** | |
| `capec get CAPEC-ID` | Get CAPEC details |
| `capec list` | List CAPECs |
| **emb3d** | |
| `emb3d get ID` | Get EMB3D technique details |
| `emb3d list` | List EMB3D techniques (`--vuln-id`) |
| **stats** | |
| `stats vuln-count` | Vulnerability count (`--state`, `--period`, `--source`) |
| `stats most-sighted` | Most sighted vulns (`--sighting-type`, `--limit`, `--date-from`, `--date-to`) |
| `stats most-commented` | Most commented vulns (`--limit`, `--date-from`, `--date-to`) |
| `stats vendors-ranking` | Vendors ranking (`--limit`, `--period`, `--source`) |
| `stats assigners-ranking` | Assigners ranking (`--limit`, `--period`, `--source`) |
| `stats top-cwes` | Most used CWEs (`--limit`, `--period`) |
| **bundle** | |
| `bundle get UUID` | Get a bundle |
| `bundle list` | List bundles (`--vuln-id`, `--author`) |
| **comment** | |
| `comment get UUID` | Get a comment |
| `comment list` | List comments (`--vuln-id`, `--author`) |
| **sighting** | |
| `sighting get UUID` | Get a sighting |
| `sighting list` | List sightings (`--type`, `--vuln-id`, `--author`) |
| **gcve** | |
| `gcve registry` | List GNAs (`--short-name`) |
| `gcve integrity` | Verify registry integrity |
| **organization** | |
| `organization list` | List organizations (`--name`) |
| **product** | |
| `product list` | List products (`--name`, `--organization-name`) |
| **system** | |
| `system db-info` | Database information |
| `system config` | Configuration information |
| `system health` | Process heartbeats |
| `system pg-info` | PostgreSQL information |
| `system smtp` | SMTP status |
| `system valkey` | Valkey/Redis status |
| **user** | |
| `user me` | Current authenticated user |

All `list` commands support `--page` and `--per-page` for pagination.

## Python library

### Basic usage

```python
from ares import VulnLookup

# Use as a context manager (recommended — closes the HTTP session on exit)
with VulnLookup() as client:
    vuln = client.vulnerability("CVE-2024-1234")
    print(vuln["cveMetadata"]["state"])  # "PUBLISHED"

    epss = client.epss("CVE-2024-1234")
    print(epss["data"][0]["epss"])  # "0.064130000"

    vendors = client.browse()
    products = client.browse("apache")
```

### Authentication

Some endpoints (write operations, user info) require an API key:

```python
with VulnLookup(api_key="your-api-key") as client:
    me = client.me()
    print(me["login"])
```

### Custom instance

Point to a self-hosted Vulnerability-Lookup instance:

```python
client = VulnLookup(
    base_url="https://my-instance.example.com/api",
    timeout=30,
)
```

### Searching vulnerabilities

```python
with VulnLookup() as client:
    # List vulnerabilities with filters
    results = client.vulnerabilities(product="flask", source="cvelistv5", per_page=10)

    # Search by vendor and product
    results = client.search("apache", "httpd", per_page=20, since="2024-01-01")

    # Search by CPE
    results = client.cpe_search("cpe:2.3:a:apache:httpd")

    # Get a single vulnerability with extra data
    vuln = client.vulnerability(
        "CVE-2024-1234",
        with_meta=True,
        with_comments=True,
        with_sightings=True,
    )
```

### KEV, CWE, CAPEC, EPSS

```python
with VulnLookup() as client:
    # Known Exploited Vulnerabilities
    cisa = client.cisa_kev()
    cnw = client.cnw_kev()
    kevs = client.kevs(exploited=True)
    kev = client.kev("kev-uuid")

    # CWE / CAPEC / EMB3D details
    xss = client.cwe("79")
    capec = client.capec("1")
    technique = client.emb3d("T0001")

    # EPSS score
    epss = client.epss("CVE-2024-1234")
```

### Bundles, comments, and sightings

```python
with VulnLookup(api_key="your-api-key") as client:
    # Read
    bundles = client.bundles(vuln_id="CVE-2024-1234")
    comments = client.comments(vuln_id="CVE-2024-1234")
    sightings = client.sightings(type="exploited", vuln_id="CVE-2024-1234")

    # Write (require API key)
    client.create_bundle({"name": "my bundle", "description": "..."})
    client.create_comment({"title": "...", "vulnerability": "CVE-2024-1234"})
    client.create_sighting({"type": "seen", "vulnerability": "CVE-2024-1234"})
```

### Statistics

```python
with VulnLookup() as client:
    count = client.stats_vulnerability_count(
        state="published", period="2024", source="cvelistv5",
    )
    sighted = client.stats_most_sighted(sighting_type="exploited", limit=10)
    vendors = client.stats_vendors_ranking(period="2024")
    cwes = client.stats_most_used_cwes(limit=10)
```

### Error handling

All errors are subclasses of `AresError`:

```python
from ares import VulnLookup, AresError, HTTPError

with VulnLookup() as client:
    try:
        client.vulnerability("CVE-9999-0000")
    except HTTPError as e:
        print(e.status_code)  # 404
        print(e.message)      # response body
    except AresError as e:
        # Connection failures, timeouts, invalid JSON
        print(e)
```

### Logging

Enable debug logging to see HTTP requests and responses:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Now all requests are logged:
# DEBUG:ares:GET https://vulnerability.circl.lu/api/browse/ params=None
# DEBUG:ares:response 200 (1234 bytes)
```

### Full method reference

| Category | Methods |
|---|---|
| Browse | `browse([vendor])` |
| Vulnerability | `vulnerability(id, ...)`, `vulnerabilities(...)`, `search(vendor, product, ...)`, `cpe_search(cpe, ...)`, `vendors()`, `assigners()`, `create_vulnerability(data)`, `delete_vulnerability(id)` |
| Bundle | `bundles(...)`, `bundle(uuid)`, `create_bundle(data)`, `delete_bundle(uuid)` |
| Comment | `comments(...)`, `comment(uuid)`, `create_comment(data)`, `delete_comment(uuid)` |
| Sighting | `sightings(...)`, `sighting(uuid)`, `create_sighting(data)`, `delete_sighting(uuid)`, `delete_sightings(...)` |
| CWE | `cwes(...)`, `cwe(id)` |
| CAPEC | `capecs(...)`, `capec(id)` |
| EMB3D | `emb3d_techniques(...)`, `emb3d(id)` |
| Organization | `organizations(...)` |
| Product | `products(...)` |
| EPSS | `epss(vuln_id)` |
| KEV | `cisa_kev(...)`, `cnw_kev(...)`, `kevs(...)`, `kev(uuid)`, `create_kev(data)`, `update_kev(uuid, data)`, `delete_kev(uuid)` |
| GCVE | `gcve_registry(...)`, `gcve_registry_integrity()` |
| Rulezet | `rulezet(vuln_id)` |
| User | `me()`, `users(...)`, `create_user(...)`, `regenerate_api_key(data)`, `delete_user(id)` |
| Stats | `stats_vulnerability_count(...)`, `stats_most_sighted(...)`, `stats_most_commented(...)`, `stats_vendors_ranking(...)`, `stats_assigners_ranking(...)`, `stats_most_used_cwes(...)` |
| VLAI | `classify_severity(description, ...)` |
| System | `db_info()`, `pg_info()`, `config_info()`, `check_process()`, `check_smtp()`, `valkey_up()` |

All list methods accept `page` and `per_page` for pagination. Parameters set to
`None` are omitted from the request.

## License

```
Copyright 2014-2026 Martin Simon

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
