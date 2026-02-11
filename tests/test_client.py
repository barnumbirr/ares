"""Tests for the ares client."""

from __future__ import annotations

import json

import pytest
import responses
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import Timeout as RequestsTimeout

from ares import VulnLookup
from ares.exceptions import AresError
from ares.exceptions import ConnectionError as AresConnectionError
from ares.exceptions import HTTPError
from ares.exceptions import TimeoutError as AresTimeoutError

BASE_URL = "https://vulnerability.circl.lu/api"

class TestInit:
    def test_defaults(self):
        c = VulnLookup()
        assert c.base_url == BASE_URL
        assert c.api_key is None
        assert c.timeout == 120

    def test_custom_base_url(self):
        c = VulnLookup(base_url="https://example.com/api")
        assert c.base_url == "https://example.com/api"

    def test_trailing_slash_stripped(self):
        c = VulnLookup(base_url="https://example.com/api/")
        assert c.base_url == "https://example.com/api"

    def test_api_key_stored(self):
        c = VulnLookup(api_key="secret")
        assert c.api_key == "secret"

    def test_custom_timeout(self):
        c = VulnLookup(timeout=30)
        assert c.timeout == 30

    def test_repr(self):
        c = VulnLookup()
        assert repr(c) == f"<VulnLookup base_url={BASE_URL!r}>"

    def test_empty_string_base_url_uses_default(self):
        c = VulnLookup(base_url="")
        assert c.base_url == BASE_URL

class TestSession:
    def test_lazy_creation(self):
        c = VulnLookup()
        assert c._session is None
        _ = c.session
        assert c._session is not None
        c.close()

    def test_reuses_same_session(self, client):
        s1 = client.session
        s2 = client.session
        assert s1 is s2

    def test_content_type_header(self, client):
        assert client.session.headers["Content-Type"] == "application/json"

    def test_user_agent_header(self, client):
        assert "ares" in client.session.headers["User-Agent"]
        assert "github.com/barnumbirr/ares" in client.session.headers["User-Agent"]

    def test_api_key_header_set(self, auth_client):
        assert auth_client.session.headers["X-API-KEY"] == "test-key"

    def test_api_key_header_absent_when_no_key(self, client):
        assert "X-API-KEY" not in client.session.headers

    def test_empty_string_api_key_still_sets_header(self):
        c = VulnLookup(api_key="")
        assert "X-API-KEY" in c.session.headers
        assert c.session.headers["X-API-KEY"] == ""
        c.close()

class TestContextManager:
    def test_closes_session_on_exit(self):
        with VulnLookup() as c:
            _ = c.session
            assert c._session is not None
        assert c._session is None

    def test_close_without_session_is_safe(self):
        c = VulnLookup()
        c.close()

    def test_double_close_is_safe(self):
        c = VulnLookup()
        _ = c.session
        c.close()
        c.close()

class TestRequest:
    @responses.activate
    def test_timeout_raises_timeout_error(self, client):
        """Timeout must be caught before ConnectionError (it's a subclass)."""
        responses.get(f"{BASE_URL}/browse/", body=RequestsTimeout("timed out"))
        with pytest.raises(AresTimeoutError, match="request timed out"):
            client.browse()

    @responses.activate
    def test_timeout_is_also_ares_error(self, client):
        responses.get(f"{BASE_URL}/browse/", body=RequestsTimeout("timed out"))
        with pytest.raises(AresError):
            client.browse()

    @responses.activate
    def test_connection_error_raises_connection_error(self, client):
        responses.get(
            f"{BASE_URL}/browse/",
            body=RequestsConnectionError("refused"),
        )
        with pytest.raises(AresConnectionError, match="connection failed"):
            client.browse()

    @responses.activate
    def test_connection_error_is_also_ares_error(self, client):
        responses.get(
            f"{BASE_URL}/browse/",
            body=RequestsConnectionError("refused"),
        )
        with pytest.raises(AresError):
            client.browse()

    @responses.activate
    @pytest.mark.parametrize("status", [400, 401, 403, 404, 500, 502, 503])
    def test_http_error_for_various_status_codes(self, client, status):
        responses.get(f"{BASE_URL}/browse/", status=status, body="err")
        with pytest.raises(HTTPError) as exc_info:
            client.browse()
        assert exc_info.value.status_code == status

    @responses.activate
    def test_http_error_preserves_response_body(self, client):
        responses.get(
            f"{BASE_URL}/browse/", status=422, body="validation failed",
        )
        with pytest.raises(HTTPError) as exc_info:
            client.browse()
        assert "validation failed" in exc_info.value.message

    @responses.activate
    def test_204_returns_none(self, client):
        responses.delete(f"{BASE_URL}/bundle/abc", status=204)
        assert client.delete_bundle("abc") is None

    @responses.activate
    def test_invalid_json_raises_ares_error(self, client):
        responses.get(f"{BASE_URL}/browse/", body="not json", status=200)
        with pytest.raises(AresError, match="invalid JSON"):
            client.browse()

    @responses.activate
    def test_none_params_excluded(self, client):
        responses.get(f"{BASE_URL}/vulnerability/", json=[])
        client.vulnerabilities(product="flask", cwe=None, source=None)
        qs = responses.calls[0].request.url.split("?", 1)[1]
        assert "product=flask" in qs
        assert "cwe" not in qs
        assert "source" not in qs

    @responses.activate
    def test_all_params_none_sends_clean_url(self, client):
        responses.get(f"{BASE_URL}/vulnerability/", json=[])
        client.vulnerabilities()
        assert "?" not in responses.calls[0].request.url

class TestExceptions:
    def test_http_error_is_an_ares_error(self):
        with pytest.raises(AresError):
            raise HTTPError(404, "not found")

    def test_http_error_attributes(self):
        err = HTTPError(403, "forbidden")
        assert err.status_code == 403
        assert err.message == "forbidden"

    def test_http_error_str_contains_status(self):
        assert "500" in str(HTTPError(500, "server error"))

    def test_connection_error_is_an_ares_error(self):
        assert issubclass(AresConnectionError, AresError)

    def test_timeout_error_is_an_ares_error(self):
        assert issubclass(AresTimeoutError, AresError)

ENDPOINTS = [
    # id, method_name, args, kwargs, http_method, path
    ("browse", "browse", (), {}, "GET", "browse/"),
    ("browse-vendor", "browse", ("apache",), {}, "GET", "browse/apache"),
    ("vulnerability", "vulnerability", ("CVE-2024-1",), {}, "GET", "vulnerability/CVE-2024-1"),
    ("vulnerabilities", "vulnerabilities", (), {}, "GET", "vulnerability/"),
    ("create_vulnerability", "create_vulnerability", ({"id": "X"},), {}, "POST", "vulnerability/"),
    ("delete_vulnerability", "delete_vulnerability", ("X",), {}, "DELETE", "vulnerability/X"),
    ("vendors", "vendors", (), {}, "GET", "vulnerability/browse/"),
    ("assigners", "assigners", (), {}, "GET", "vulnerability/browse/assigners"),
    ("search", "search", ("apache", "httpd"), {}, "GET", "vulnerability/search/apache/httpd"),
    ("cpe_search", "cpe_search", ("cpe:2.3:a:apache:httpd",), {}, "GET", "vulnerability/cpesearch/cpe:2.3:a:apache:httpd"),
    ("bundles", "bundles", (), {}, "GET", "bundle/"),
    ("bundle", "bundle", ("abc",), {}, "GET", "bundle/abc"),
    ("create_bundle", "create_bundle", ({"name": "x"},), {}, "POST", "bundle/"),
    ("delete_bundle", "delete_bundle", ("abc",), {}, "DELETE", "bundle/abc"),
    ("comments", "comments", (), {}, "GET", "comment/"),
    ("comment", "comment", ("abc",), {}, "GET", "comment/abc"),
    ("create_comment", "create_comment", ({"title": "x"},), {}, "POST", "comment/"),
    ("delete_comment", "delete_comment", ("abc",), {}, "DELETE", "comment/abc"),
    ("sightings", "sightings", (), {}, "GET", "sighting/"),
    ("sighting", "sighting", ("abc",), {}, "GET", "sighting/abc"),
    ("create_sighting", "create_sighting", ({"type": "seen"},), {}, "POST", "sighting/"),
    ("delete_sighting", "delete_sighting", ("abc",), {}, "DELETE", "sighting/abc"),
    ("delete_sightings", "delete_sightings", (), {}, "DELETE", "sighting/"),
    ("cwes", "cwes", (), {}, "GET", "cwe/"),
    ("cwe", "cwe", ("79",), {}, "GET", "cwe/79"),
    ("capecs", "capecs", (), {}, "GET", "capec/"),
    ("capec", "capec", ("1",), {}, "GET", "capec/1"),
    ("emb3d_techniques", "emb3d_techniques", (), {}, "GET", "emb3d/"),
    ("emb3d", "emb3d", ("T0001",), {}, "GET", "emb3d/T0001"),
    ("organizations", "organizations", (), {}, "GET", "organization/"),
    ("products", "products", (), {}, "GET", "product/"),
    ("epss", "epss", ("CVE-2024-1",), {}, "GET", "epss/CVE-2024-1"),
    ("cisa_kev", "cisa_kev", (), {}, "GET", "cisa_kev/"),
    ("cnw_kev", "cnw_kev", (), {}, "GET", "cnw_kev/"),
    ("kevs", "kevs", (), {}, "GET", "kev/"),
    ("kev", "kev", ("abc",), {}, "GET", "kev/abc"),
    ("create_kev", "create_kev", ({"vuln": "X"},), {}, "POST", "kev/"),
    ("update_kev", "update_kev", ("abc", {"exploited": True}), {}, "PUT", "kev/abc"),
    ("delete_kev", "delete_kev", ("abc",), {}, "DELETE", "kev/abc"),
    ("delete_kev_catalog", "delete_kev_catalog", ("cat-1",), {}, "DELETE", "kev/catalog/cat-1"),
    ("gcve_registry", "gcve_registry", (), {}, "GET", "gcve/registry"),
    ("gcve_registry_integrity", "gcve_registry_integrity", (), {}, "GET", "gcve/registry/integrity"),
    ("rulezet", "rulezet", ("CVE-2024-1",), {}, "GET", "rulezet/search_rules_by_vulnerabilities/CVE-2024-1"),
    ("users", "users", (), {}, "GET", "user/"),
    ("me", "me", (), {}, "GET", "user/me"),
    ("create_user", "create_user", (), {"login": "x", "name": "X", "organisation": "O", "email": "e@e.com"}, "POST", "user/"),
    ("regenerate_api_key", "regenerate_api_key", ({"key": "x"},), {}, "POST", "user/api_key"),
    ("delete_user", "delete_user", (42,), {}, "DELETE", "user/42"),
    ("stats_vulnerability_count", "stats_vulnerability_count", (), {}, "GET", "stats/vulnerability/count"),
    ("stats_most_sighted", "stats_most_sighted", (), {}, "GET", "stats/vulnerability/most_sighted"),
    ("stats_most_commented", "stats_most_commented", (), {}, "GET", "stats/vulnerability/most_commented"),
    ("stats_vendors_ranking", "stats_vendors_ranking", (), {}, "GET", "stats/vendors/ranking"),
    ("stats_assigners_ranking", "stats_assigners_ranking", (), {}, "GET", "stats/assigners/ranking"),
    ("stats_most_used_cwes", "stats_most_used_cwes", (), {}, "GET", "stats/cwe/most_used"),
    ("classify_severity", "classify_severity", ("test desc",), {}, "POST", "vlai/severity-classification"),
    ("check_process", "check_process", (), {}, "GET", "system/checkProcess"),
    ("check_smtp", "check_smtp", (), {}, "GET", "system/checkSMTP"),
    ("config_info", "config_info", (), {}, "GET", "system/configInfo"),
    ("db_info", "db_info", (), {}, "GET", "system/dbInfo"),
    ("pg_info", "pg_info", (), {}, "GET", "system/pgInfo"),
    ("valkey_up", "valkey_up", (), {}, "GET", "system/valkey_up"),
]

class TestEndpointRouting:
    @responses.activate
    @pytest.mark.parametrize(
        "method_name,args,kwargs,http_method,path",
        [e[1:] for e in ENDPOINTS],
        ids=[e[0] for e in ENDPOINTS],
    )
    def test_hits_correct_url_and_method(
        self, client, method_name, args, kwargs, http_method, path,
    ):
        url = f"{BASE_URL}/{path}"
        responses.add(http_method, url, json={})
        getattr(client, method_name)(*args, **kwargs)
        req = responses.calls[0].request
        assert req.method == http_method
        assert req.url.split("?")[0] == url

class TestRequestBodies:
    @responses.activate
    def test_create_vulnerability_wraps_in_data_key(self, client):
        responses.post(f"{BASE_URL}/vulnerability/", json={})
        client.create_vulnerability({"id": "LOCAL-001", "summary": "test"})
        body = json.loads(responses.calls[0].request.body)
        assert body == {"data": {"id": "LOCAL-001", "summary": "test"}}

    @responses.activate
    def test_create_bundle_sends_payload_directly(self, client):
        responses.post(f"{BASE_URL}/bundle/", json={})
        client.create_bundle({"name": "my bundle", "description": "d"})
        body = json.loads(responses.calls[0].request.body)
        assert body == {"name": "my bundle", "description": "d"}

    @responses.activate
    def test_create_user_sends_all_fields(self, client):
        responses.post(f"{BASE_URL}/user/", json={})
        client.create_user(
            login="jdoe", name="Jane Doe",
            organisation="ACME", email="jane@example.com",
        )
        body = json.loads(responses.calls[0].request.body)
        assert body == {
            "login": "jdoe",
            "name": "Jane Doe",
            "organisation": "ACME",
            "email": "jane@example.com",
        }

    @responses.activate
    def test_classify_severity_minimal_payload(self, client):
        responses.post(f"{BASE_URL}/vlai/severity-classification", json={})
        client.classify_severity("buffer overflow")
        body = json.loads(responses.calls[0].request.body)
        assert body == {"description": "buffer overflow"}
        assert "model" not in body

    @responses.activate
    def test_classify_severity_with_model(self, client):
        responses.post(f"{BASE_URL}/vlai/severity-classification", json={})
        client.classify_severity("buffer overflow", model="gpt-4")
        body = json.loads(responses.calls[0].request.body)
        assert body == {"description": "buffer overflow", "model": "gpt-4"}

    @responses.activate
    def test_update_kev_sends_json_body(self, client):
        responses.put(f"{BASE_URL}/kev/abc", json={})
        client.update_kev("abc", {"exploited": True})
        body = json.loads(responses.calls[0].request.body)
        assert body == {"exploited": True}

class TestQueryParams:
    @responses.activate
    def test_vulnerabilities_forwards_all_params(self, client):
        responses.get(f"{BASE_URL}/vulnerability/", json=[])
        client.vulnerabilities(
            product="flask", light="1", cwe="79", since="2024-01-01",
            sort_order="asc", date_sort="published", per_page=50, page=2,
            source="cvelistv5",
        )
        url = responses.calls[0].request.url
        for param in [
            "product=flask", "light=1", "cwe=79", "since=2024-01-01",
            "sort_order=asc", "date_sort=published", "per_page=50",
            "page=2", "source=cvelistv5",
        ]:
            assert param in url, f"{param!r} not in {url}"

    @responses.activate
    def test_vulnerability_with_flags(self, client):
        responses.get(f"{BASE_URL}/vulnerability/CVE-2024-1", json={})
        client.vulnerability(
            "CVE-2024-1",
            with_meta=True, with_linked=True, with_comments=True,
            with_bundles=True, with_sightings=True,
        )
        url = responses.calls[0].request.url
        for flag in [
            "with_meta", "with_linked", "with_comments",
            "with_bundles", "with_sightings",
        ]:
            assert flag in url, f"{flag!r} not in {url}"

    @responses.activate
    def test_search_with_pagination_and_since(self, client):
        responses.get(
            f"{BASE_URL}/vulnerability/search/apache/httpd", json=[],
        )
        client.search("apache", "httpd", page=3, per_page=20, since="2024-06-01")
        url = responses.calls[0].request.url
        assert "page=3" in url
        assert "per_page=20" in url
        assert "since=2024-06-01" in url

    @responses.activate
    def test_sightings_type_filter(self, client):
        responses.get(f"{BASE_URL}/sighting/", json=[])
        client.sightings(type="exploited", vuln_id="CVE-2024-1")
        url = responses.calls[0].request.url
        assert "type=exploited" in url
        assert "vuln_id=CVE-2024-1" in url

    @responses.activate
    def test_delete_sightings_sends_query_params(self, client):
        """DELETE with query params — not just a path-only DELETE."""
        responses.delete(f"{BASE_URL}/sighting/", json={"deleted": 3})
        client.delete_sightings(author="me", source="scanner")
        url = responses.calls[0].request.url
        assert "author=me" in url
        assert "source=scanner" in url

    @responses.activate
    def test_kevs_filters(self, client):
        responses.get(f"{BASE_URL}/kev/", json=[])
        client.kevs(
            exploited=True, status_reason="confirmed",
            date_from="2024-01-01", date_to="2024-12-31",
        )
        url = responses.calls[0].request.url
        assert "exploited=True" in url
        assert "status_reason=confirmed" in url
        assert "date_from=2024-01-01" in url

    @responses.activate
    def test_stats_vulnerability_count_params(self, client):
        responses.get(f"{BASE_URL}/stats/vulnerability/count", json={})
        client.stats_vulnerability_count(
            state="published", period="2024-06", source="cvelistv5",
        )
        url = responses.calls[0].request.url
        assert "state=published" in url
        assert "period=2024-06" in url
        assert "source=cvelistv5" in url

class TestAuthIntegration:
    @responses.activate
    def test_api_key_sent_in_request(self, auth_client):
        """Verify X-API-KEY actually arrives on the wire, not just in session."""
        responses.get(f"{BASE_URL}/user/me", json={"login": "admin"})
        auth_client.me()
        assert responses.calls[0].request.headers["X-API-KEY"] == "test-key"

    @responses.activate
    def test_no_api_key_in_unauthenticated_request(self, client):
        responses.get(f"{BASE_URL}/browse/", json=[])
        client.browse()
        assert "X-API-KEY" not in responses.calls[0].request.headers

class TestSessionLifecycle:
    @responses.activate
    def test_client_usable_after_close(self):
        """Lazy session recreation allows reuse after close()."""
        c = VulnLookup()
        _ = c.session
        old_session = c._session
        c.close()
        assert c._session is None
        responses.get(f"{BASE_URL}/browse/", json=["vendor1"])
        result = c.browse()
        assert result == ["vendor1"]
        assert c._session is not None
        assert c._session is not old_session
        c.close()

class TestCustomBaseUrl:
    @responses.activate
    def test_custom_base_url_used_in_requests(self):
        custom = "https://my-instance.example.com/api"
        responses.get(f"{custom}/browse/", json=["v1"])
        c = VulnLookup(base_url=custom)
        assert c.browse() == ["v1"]
        assert responses.calls[0].request.url.startswith(custom)
        c.close()

class TestErrorChaining:
    """Verify `raise X from exc` preserves the original exception as __cause__."""

    @responses.activate
    def test_connection_error_chains_cause(self, client):
        responses.get(
            f"{BASE_URL}/browse/",
            body=RequestsConnectionError("refused"),
        )
        with pytest.raises(AresConnectionError) as exc_info:
            client.browse()
        assert isinstance(exc_info.value.__cause__, RequestsConnectionError)

    @responses.activate
    def test_timeout_chains_cause(self, client):
        responses.get(f"{BASE_URL}/browse/", body=RequestsTimeout("slow"))
        with pytest.raises(AresTimeoutError) as exc_info:
            client.browse()
        assert isinstance(exc_info.value.__cause__, RequestsTimeout)

    @responses.activate
    def test_http_error_chains_cause(self, client):
        responses.get(f"{BASE_URL}/browse/", status=500, body="fail")
        with pytest.raises(HTTPError) as exc_info:
            client.browse()
        assert exc_info.value.__cause__ is not None

    @responses.activate
    def test_json_error_chains_cause(self, client):
        responses.get(f"{BASE_URL}/browse/", body="not json", status=200)
        with pytest.raises(AresError) as exc_info:
            client.browse()
        assert isinstance(exc_info.value.__cause__, ValueError)

class TestPackageAPI:
    def test_version(self):
        import ares
        from importlib.metadata import version
        assert ares.__version__ == version("ares")

    def test_all_exports(self):
        import ares
        assert set(ares.__all__) == {
            "VulnLookup", "AresError", "ConnectionError",
            "HTTPError", "TimeoutError",
        }

    def test_public_imports(self):
        from ares import VulnLookup, AresError, ConnectionError, HTTPError, TimeoutError
        assert issubclass(HTTPError, AresError)
        assert issubclass(ConnectionError, AresError)
        assert issubclass(TimeoutError, AresError)
        assert issubclass(AresError, Exception)

class TestTransport:
    @responses.activate
    def test_get_sends_no_body(self, client):
        responses.get(f"{BASE_URL}/browse/", json=[])
        client.browse()
        assert responses.calls[0].request.body is None

    @responses.activate
    def test_post_body_not_in_url(self, client):
        """POST payload must go in the body, not as query params."""
        responses.post(f"{BASE_URL}/bundle/", json={})
        client.create_bundle({"name": "test"})
        req = responses.calls[0].request
        assert "?" not in req.url
        body = json.loads(req.body)
        assert body == {"name": "test"}

    @responses.activate
    def test_put_body_not_in_url(self, client):
        responses.put(f"{BASE_URL}/kev/abc", json={})
        client.update_kev("abc", {"exploited": True})
        req = responses.calls[0].request
        assert "?" not in req.url
        body = json.loads(req.body)
        assert body == {"exploited": True}

    @responses.activate
    def test_delete_with_params_sends_no_body(self, client):
        """DELETE /sighting/ uses query params, not a body."""
        responses.delete(f"{BASE_URL}/sighting/", json={})
        client.delete_sightings(author="me")
        req = responses.calls[0].request
        assert "author=me" in req.url
        assert req.body is None

    @responses.activate
    def test_http_error_body_truncated(self, client):
        """Huge error responses shouldn't bloat the exception."""
        huge_body = "x" * 5000
        responses.get(f"{BASE_URL}/browse/", status=500, body=huge_body)
        with pytest.raises(HTTPError) as exc_info:
            client.browse()
        assert len(exc_info.value.message) <= 2000

class TestLogging:
    @responses.activate
    def test_debug_logs_request(self, client, caplog):
        import logging
        responses.get(f"{BASE_URL}/browse/", json=["vendor1"])
        with caplog.at_level(logging.DEBUG, logger="ares"):
            client.browse()
        assert any("GET" in m and "browse" in m for m in caplog.messages)

    @responses.activate
    def test_debug_logs_response_status(self, client, caplog):
        import logging
        responses.get(f"{BASE_URL}/browse/", json=["vendor1"])
        with caplog.at_level(logging.DEBUG, logger="ares"):
            client.browse()
        assert any("200" in m for m in caplog.messages)
