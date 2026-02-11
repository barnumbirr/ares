"""Vulnerability-Lookup API client.

A minimal Python wrapper around the vulnerability.circl.lu API.
"""

from __future__ import annotations

import logging
import typing as t

import requests

from .exceptions import AresError
from .exceptions import ConnectionError as ConnectionError
from .exceptions import HTTPError
from .exceptions import TimeoutError as TimeoutError

log = logging.getLogger("ares")

class VulnLookup:
    """Client for the Vulnerability-Lookup API.

    Can be used as a context manager::

        >>> from ares import VulnLookup
        >>> with VulnLookup() as client:
        ...     info = client.vulnerability("CVE-2024-1234")

    :param base_url: API base URL.  Defaults to the public instance.
    :param api_key: optional API key for authenticated endpoints.
    :param timeout: request timeout in seconds.
    """

    DEFAULT_BASE_URL = "https://vulnerability.circl.lu/api"

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: int = 120,
    ) -> None:
        self.base_url = (base_url or self.DEFAULT_BASE_URL).rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._session: requests.Session | None = None

    def __enter__(self) -> VulnLookup:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"<VulnLookup base_url={self.base_url!r}>"

    @property
    def session(self) -> requests.Session:
        """Lazily create and return the underlying HTTP session."""
        if self._session is None:
            self._session = self._make_session()
        return self._session

    def _make_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": "ares - python wrapper (github.com/barnumbirr/ares)",
        })
        if self.api_key is not None:
            session.headers["X-API-KEY"] = self.api_key
        return session

    def close(self) -> None:
        """Close the underlying HTTP session."""
        if self._session is not None:
            self._session.close()
            self._session = None

    def _request(
        self,
        method: str,
        path: str,
        params: dict[str, t.Any] | None = None,
        json: t.Any | None = None,
    ) -> t.Any:
        url = f"{self.base_url}/{path.lstrip('/')}"
        if params:
            params = {k: v for k, v in params.items() if v is not None}
        log.debug("%s %s params=%s", method, url, params)
        try:
            resp = self.session.request(
                method, url, params=params, json=json, timeout=self.timeout,
            )
            log.debug("response %s (%d bytes)", resp.status_code, len(resp.content))
            resp.raise_for_status()
        except requests.Timeout as exc:
            raise TimeoutError("request timed out") from exc
        except requests.ConnectionError as exc:
            raise ConnectionError(f"connection failed: {exc}") from exc
        except requests.HTTPError as exc:
            raise HTTPError(resp.status_code, resp.text[:2000]) from exc
        if resp.status_code == 204:
            return None
        try:
            return resp.json()
        except ValueError as exc:
            raise AresError(
                f"invalid JSON in response: {resp.text[:200]}"
            ) from exc

    def _get(self, path: str, **params: t.Any) -> t.Any:
        return self._request("GET", path, params=params)

    def _post(self, path: str, json: t.Any | None = None) -> t.Any:
        return self._request("POST", path, json=json)

    def _put(self, path: str, json: t.Any | None = None) -> t.Any:
        return self._request("PUT", path, json=json)

    def _delete(self, path: str, **params: t.Any) -> t.Any:
        return self._request("DELETE", path, params=params)

    def browse(self, vendor=None):
        """List known vendors, or products for a specific vendor."""
        if vendor is not None:
            return self._get(f"browse/{vendor}")
        return self._get("browse/")

    def vulnerability(self, vuln_id, *, with_meta=None, with_linked=None,
                      with_comments=None, with_bundles=None,
                      with_sightings=None):
        """Get a specific vulnerability by ID."""
        return self._get(
            f"vulnerability/{vuln_id}",
            with_meta=with_meta, with_linked=with_linked,
            with_comments=with_comments, with_bundles=with_bundles,
            with_sightings=with_sightings,
        )

    def vulnerabilities(self, *, product=None, light=None, cwe=None,
                        since=None, sort_order=None, date_sort=None,
                        per_page=None, page=None, source=None):
        """List vulnerabilities with optional filtering."""
        return self._get(
            "vulnerability/",
            product=product, light=light, cwe=cwe, since=since,
            sort_order=sort_order, date_sort=date_sort,
            per_page=per_page, page=page, source=source,
        )

    def create_vulnerability(self, data):
        """Create or edit a vulnerability in the local source."""
        return self._post("vulnerability/", json={"data": data})

    def delete_vulnerability(self, vuln_id):
        """Delete a vulnerability from the local source."""
        return self._delete(f"vulnerability/{vuln_id}")

    def vendors(self):
        """List known vendors (via vulnerability browse)."""
        return self._get("vulnerability/browse/")

    def assigners(self):
        """List known CNAs (Certificate Numbering Authorities)."""
        return self._get("vulnerability/browse/assigners")

    def search(self, vendor, product, *, page=None, per_page=None,
               since=None):
        """Search vulnerabilities by vendor and product."""
        return self._get(
            f"vulnerability/search/{vendor}/{product}",
            page=page, per_page=per_page, since=since,
        )

    def cpe_search(self, cpe, *, sort_order=None, date_sort=None,
                   per_page=None, page=None, source=None):
        """Search vulnerabilities by CPE string."""
        return self._get(
            f"vulnerability/cpesearch/{cpe}",
            sort_order=sort_order, date_sort=date_sort,
            per_page=per_page, page=page, source=source,
        )

    def bundles(self, *, page=None, per_page=None, uuid=None, author=None,
                vuln_id=None, meta=None, date_from=None, date_to=None):
        """List all bundles."""
        return self._get(
            "bundle/",
            page=page, per_page=per_page, uuid=uuid, author=author,
            vuln_id=vuln_id, meta=meta, date_from=date_from, date_to=date_to,
        )

    def bundle(self, uuid):
        """Get a bundle by UUID."""
        return self._get(f"bundle/{uuid}")

    def create_bundle(self, data):
        """Create a new bundle."""
        return self._post("bundle/", json=data)

    def delete_bundle(self, uuid):
        """Delete a bundle."""
        return self._delete(f"bundle/{uuid}")

    def comments(self, *, page=None, per_page=None, uuid=None, vuln_id=None,
                 author=None, meta=None, date_from=None, date_to=None):
        """List all comments."""
        return self._get(
            "comment/",
            page=page, per_page=per_page, uuid=uuid, vuln_id=vuln_id,
            author=author, meta=meta, date_from=date_from, date_to=date_to,
        )

    def comment(self, uuid):
        """Get a specific comment."""
        return self._get(f"comment/{uuid}")

    def create_comment(self, data):
        """Create a comment on a security advisory."""
        return self._post("comment/", json=data)

    def delete_comment(self, uuid):
        """Delete a comment."""
        return self._delete(f"comment/{uuid}")

    def sightings(self, *, page=None, per_page=None, uuid=None, type=None,
                  vuln_id=None, author=None, date_from=None, date_to=None,
                  source=None, advisory_status=None):
        """List all sightings."""
        return self._get(
            "sighting/",
            page=page, per_page=per_page, uuid=uuid, type=type,
            vuln_id=vuln_id, author=author, date_from=date_from,
            date_to=date_to, source=source, advisory_status=advisory_status,
        )

    def sighting(self, uuid):
        """Get a specific sighting."""
        return self._get(f"sighting/{uuid}")

    def create_sighting(self, data):
        """Create a new sighting."""
        return self._post("sighting/", json=data)

    def delete_sighting(self, uuid):
        """Delete a specific sighting."""
        return self._delete(f"sighting/{uuid}")

    def delete_sightings(self, *, author=None, source=None, date_from=None,
                         date_to=None):
        """Delete sightings matching the given filters."""
        return self._delete(
            "sighting/",
            author=author, source=source, date_from=date_from,
            date_to=date_to,
        )

    def cwes(self, *, vuln_id=None, page=None, per_page=None):
        """List all CWEs."""
        return self._get(
            "cwe/", vuln_id=vuln_id, page=page, per_page=per_page,
        )

    def cwe(self, cwe_id):
        """Get detailed CWE information."""
        return self._get(f"cwe/{cwe_id}")

    def capecs(self, *, page=None, per_page=None):
        """List all CAPECs."""
        return self._get("capec/", page=page, per_page=per_page)

    def capec(self, capec_id):
        """Get detailed CAPEC information."""
        return self._get(f"capec/{capec_id}")

    def emb3d_techniques(self, *, page=None, per_page=None, vuln_id=None):
        """List MITRE EMB3D adversarial techniques."""
        return self._get(
            "emb3d/", page=page, per_page=per_page, vuln_id=vuln_id,
        )

    def emb3d(self, emb3d_id):
        """Get detailed EMB3D technique information."""
        return self._get(f"emb3d/{emb3d_id}")

    def organizations(self, *, page=None, per_page=None, id=None, uuid=None,
                      name=None, gna_id=None):
        """List all organizations."""
        return self._get(
            "organization/",
            page=page, per_page=per_page, id=id, uuid=uuid,
            name=name, gna_id=gna_id,
        )

    def products(self, *, page=None, per_page=None, uuid=None, name=None,
                 organization_name=None, organization_id=None,
                 organization_uuid=None):
        """List all products."""
        return self._get(
            "product/",
            page=page, per_page=per_page, uuid=uuid, name=name,
            organization_name=organization_name,
            organization_id=organization_id,
            organization_uuid=organization_uuid,
        )

    def epss(self, vuln_id):
        """Get the EPSS score for a vulnerability."""
        return self._get(f"epss/{vuln_id}")

    def cisa_kev(self, *, page=None, per_page=None):
        """List CISA Known Exploited Vulnerabilities."""
        return self._get("cisa_kev/", page=page, per_page=per_page)

    def cnw_kev(self, *, page=None, per_page=None):
        """List CNW KEV entries."""
        return self._get("cnw_kev/", page=page, per_page=per_page)

    def kevs(self, *, page=None, per_page=None, vuln_id=None,
             status_reason=None, exploited=None,
             vulnerability_lookup_origin=None, date_from=None,
             date_to=None, author=None):
        """List KEV entries."""
        return self._get(
            "kev/",
            page=page, per_page=per_page, vuln_id=vuln_id,
            status_reason=status_reason, exploited=exploited,
            vulnerability_lookup_origin=vulnerability_lookup_origin,
            date_from=date_from, date_to=date_to, author=author,
        )

    def kev(self, uuid):
        """Get a KEV entry by UUID."""
        return self._get(f"kev/{uuid}")

    def create_kev(self, data):
        """Create a new KEV entry."""
        return self._post("kev/", json=data)

    def update_kev(self, uuid, data):
        """Update a KEV entry."""
        return self._put(f"kev/{uuid}", json=data)

    def delete_kev(self, uuid):
        """Delete a KEV entry."""
        return self._delete(f"kev/{uuid}")

    def delete_kev_catalog(self, catalog_uuid):
        """Delete all KEV entries from a specific catalog."""
        return self._delete(f"kev/catalog/{catalog_uuid}")

    def gcve_registry(self, *, page=None, per_page=None, short_name=None):
        """List GNAs from local GCVE registry."""
        return self._get(
            "gcve/registry",
            page=page, per_page=per_page, short_name=short_name,
        )

    def gcve_registry_integrity(self):
        """Verify local GCVE registry integrity."""
        return self._get("gcve/registry/integrity")

    def rulezet(self, vuln_id, *, page=None, per_page=None):
        """Get rules associated with a vulnerability."""
        return self._get(
            f"rulezet/search_rules_by_vulnerabilities/{vuln_id}",
            page=page, per_page=per_page,
        )

    def users(self, *, page=None, per_page=None):
        """List all users (admin only)."""
        return self._get("user/", page=page, per_page=per_page)

    def me(self):
        """Get the currently authenticated user."""
        return self._get("user/me")

    def create_user(self, *, login, name, organisation, email):
        """Register a new user account."""
        return self._post("user/", json={
            "login": login, "name": name,
            "organisation": organisation, "email": email,
        })

    def regenerate_api_key(self, data):
        """Regenerate the API key for the authenticated user."""
        return self._post("user/api_key", json=data)

    def delete_user(self, user_id):
        """Delete a user account."""
        return self._delete(f"user/{user_id}")

    def stats_vulnerability_count(self, *, state=None, period=None,
                                  source=None):
        """Get published/reserved vulnerability count."""
        return self._get(
            "stats/vulnerability/count",
            state=state, period=period, source=source,
        )

    def stats_most_sighted(self, *, date_from=None, date_to=None,
                           sighting_type=None, limit=None, output=None):
        """Get most sighted vulnerabilities."""
        return self._get(
            "stats/vulnerability/most_sighted",
            date_from=date_from, date_to=date_to,
            sighting_type=sighting_type, limit=limit, output=output,
        )

    def stats_most_commented(self, *, date_from=None, date_to=None,
                             limit=None, output=None):
        """Get most commented vulnerabilities."""
        return self._get(
            "stats/vulnerability/most_commented",
            date_from=date_from, date_to=date_to,
            limit=limit, output=output,
        )

    def stats_vendors_ranking(self, *, limit=None, output=None, period=None,
                              source=None):
        """Get vendors ranking."""
        return self._get(
            "stats/vendors/ranking",
            limit=limit, output=output, period=period, source=source,
        )

    def stats_assigners_ranking(self, *, limit=None, output=None, period=None,
                                source=None):
        """Get assigners ranking."""
        return self._get(
            "stats/assigners/ranking",
            limit=limit, output=output, period=period, source=source,
        )

    def stats_most_used_cwes(self, *, limit=None, output=None, period=None):
        """Get most used CWEs based on sightings."""
        return self._get(
            "stats/cwe/most_used",
            limit=limit, output=output, period=period,
        )

    def classify_severity(self, description, *, model=None):
        """Classify vulnerability severity from description."""
        payload = {"description": description}
        if model is not None:
            payload["model"] = model
        return self._post("vlai/severity-classification", json=payload)

    def check_process(self):
        """Check heartbeats of various processes."""
        return self._get("system/checkProcess")

    def check_smtp(self):
        """Check SMTP connection."""
        return self._get("system/checkSMTP")

    def config_info(self):
        """Get non-sensitive configuration information."""
        return self._get("system/configInfo")

    def db_info(self):
        """Get database information and update timestamps."""
        return self._get("system/dbInfo")

    def pg_info(self):
        """Get PostgreSQL database information."""
        return self._get("system/pgInfo")

    def valkey_up(self):
        """Check if Valkey/Redis is operational."""
        return self._get("system/valkey_up")
