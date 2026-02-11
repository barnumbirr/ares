"""Tests for the ares CLI."""

from __future__ import annotations

import json

import responses

from ares import __version__
from ares.cli import cli

BASE_URL = "https://vulnerability.circl.lu/api"

class TestGlobalOptions:
    def test_help(self, runner):
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "ares-cli" in result.output

    def test_version(self, runner):
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.output

    @responses.activate
    def test_api_key_option(self, runner):
        responses.get(f"{BASE_URL}/user/me", json={"login": "admin"})
        result = runner.invoke(cli, ["--api-key", "secret", "user", "me"])
        assert result.exit_code == 0
        assert responses.calls[0].request.headers["X-API-KEY"] == "secret"

    @responses.activate
    def test_api_key_env_var(self, runner):
        responses.get(f"{BASE_URL}/user/me", json={"login": "admin"})
        result = runner.invoke(cli, ["user", "me"], env={"ARES_API_KEY": "env-key"})
        assert result.exit_code == 0
        assert responses.calls[0].request.headers["X-API-KEY"] == "env-key"

    @responses.activate
    def test_base_url_option(self, runner):
        custom = "https://custom.example.com/api"
        responses.get(f"{custom}/browse/", json=["vendor1"])
        result = runner.invoke(cli, ["--base-url", custom, "browse"])
        assert result.exit_code == 0
        assert responses.calls[0].request.url.startswith(custom)

    @responses.activate
    def test_compact_flag(self, runner):
        responses.get(f"{BASE_URL}/browse/", json=["vendor1", "vendor2"])
        result = runner.invoke(cli, ["--compact", "browse"])
        assert result.exit_code == 0
        assert result.output.strip() == '["vendor1","vendor2"]'

class TestBrowse:
    @responses.activate
    def test_browse_all(self, runner):
        responses.get(f"{BASE_URL}/browse/", json=["apache", "microsoft"])
        result = runner.invoke(cli, ["--compact", "browse"])
        assert result.exit_code == 0
        assert json.loads(result.output) == ["apache", "microsoft"]

    @responses.activate
    def test_browse_vendor(self, runner):
        responses.get(f"{BASE_URL}/browse/apache", json=["httpd", "tomcat"])
        result = runner.invoke(cli, ["--compact", "browse", "apache"])
        assert result.exit_code == 0
        assert json.loads(result.output) == ["httpd", "tomcat"]

class TestEpss:
    @responses.activate
    def test_epss(self, runner):
        payload = {"cve": "CVE-2024-1234", "epss": 0.5}
        responses.get(f"{BASE_URL}/epss/CVE-2024-1234", json=payload)
        result = runner.invoke(cli, ["--compact", "epss", "CVE-2024-1234"])
        assert result.exit_code == 0
        assert json.loads(result.output) == payload

class TestRulezet:
    @responses.activate
    def test_rulezet(self, runner):
        payload = {"rules": []}
        url = f"{BASE_URL}/rulezet/search_rules_by_vulnerabilities/CVE-2024-1234"
        responses.get(url, json=payload)
        result = runner.invoke(cli, ["--compact", "rulezet", "CVE-2024-1234"])
        assert result.exit_code == 0
        assert json.loads(result.output) == payload

class TestVuln:
    @responses.activate
    def test_get(self, runner):
        responses.get(f"{BASE_URL}/vulnerability/CVE-2024-1234", json={"id": "CVE-2024-1234"})
        result = runner.invoke(cli, ["--compact", "vuln", "get", "CVE-2024-1234"])
        assert result.exit_code == 0
        assert json.loads(result.output)["id"] == "CVE-2024-1234"

    @responses.activate
    def test_get_with_meta(self, runner):
        responses.get(f"{BASE_URL}/vulnerability/CVE-2024-1234", json={"id": "CVE-2024-1234"})
        result = runner.invoke(
            cli, ["--compact", "vuln", "get", "CVE-2024-1234", "--with-meta"],
        )
        assert result.exit_code == 0
        assert "with_meta=True" in responses.calls[0].request.url

    @responses.activate
    def test_list_with_product(self, runner):
        responses.get(f"{BASE_URL}/vulnerability/", json=[])
        result = runner.invoke(
            cli, ["--compact", "vuln", "list", "--product", "flask"],
        )
        assert result.exit_code == 0
        assert "product=flask" in responses.calls[0].request.url

    @responses.activate
    def test_search(self, runner):
        responses.get(
            f"{BASE_URL}/vulnerability/search/apache/httpd", json=[],
        )
        result = runner.invoke(
            cli, ["--compact", "vuln", "search", "apache", "httpd"],
        )
        assert result.exit_code == 0

    @responses.activate
    def test_cpe_search(self, runner):
        cpe = "cpe:2.3:a:apache:httpd"
        responses.get(f"{BASE_URL}/vulnerability/cpesearch/{cpe}", json=[])
        result = runner.invoke(
            cli, ["--compact", "vuln", "cpe-search", cpe],
        )
        assert result.exit_code == 0

    def test_help(self, runner):
        result = runner.invoke(cli, ["vuln", "--help"])
        assert result.exit_code == 0
        assert "get" in result.output
        assert "list" in result.output
        assert "search" in result.output

class TestStats:
    @responses.activate
    def test_vuln_count(self, runner):
        responses.get(f"{BASE_URL}/stats/vulnerability/count", json={"count": 42})
        result = runner.invoke(cli, ["--compact", "stats", "vuln-count"])
        assert result.exit_code == 0
        assert json.loads(result.output) == {"count": 42}

    @responses.activate
    def test_most_sighted(self, runner):
        responses.get(
            f"{BASE_URL}/stats/vulnerability/most_sighted", json=[],
        )
        result = runner.invoke(
            cli, ["--compact", "stats", "most-sighted", "--limit", "5"],
        )
        assert result.exit_code == 0
        assert "limit=5" in responses.calls[0].request.url

    @responses.activate
    def test_vendors_ranking(self, runner):
        responses.get(f"{BASE_URL}/stats/vendors/ranking", json=[])
        result = runner.invoke(
            cli, ["--compact", "stats", "vendors-ranking", "--period", "2024-06"],
        )
        assert result.exit_code == 0
        assert "period=2024-06" in responses.calls[0].request.url

class TestKev:
    @responses.activate
    def test_list(self, runner):
        responses.get(f"{BASE_URL}/kev/", json=[])
        result = runner.invoke(cli, ["--compact", "kev", "list"])
        assert result.exit_code == 0

    @responses.activate
    def test_cisa(self, runner):
        responses.get(f"{BASE_URL}/cisa_kev/", json=[])
        result = runner.invoke(cli, ["--compact", "kev", "cisa"])
        assert result.exit_code == 0

class TestCweCapec:
    @responses.activate
    def test_cwe_get(self, runner):
        responses.get(f"{BASE_URL}/cwe/79", json={"id": "79", "name": "XSS"})
        result = runner.invoke(cli, ["--compact", "cwe", "get", "79"])
        assert result.exit_code == 0
        assert json.loads(result.output)["id"] == "79"

    @responses.activate
    def test_capec_list(self, runner):
        responses.get(f"{BASE_URL}/capec/", json=[])
        result = runner.invoke(cli, ["--compact", "capec", "list"])
        assert result.exit_code == 0

class TestEmb3d:
    @responses.activate
    def test_get(self, runner):
        responses.get(f"{BASE_URL}/emb3d/T0001", json={"id": "T0001"})
        result = runner.invoke(cli, ["--compact", "emb3d", "get", "T0001"])
        assert result.exit_code == 0
        assert json.loads(result.output)["id"] == "T0001"

    @responses.activate
    def test_list(self, runner):
        responses.get(f"{BASE_URL}/emb3d/", json=[])
        result = runner.invoke(cli, ["--compact", "emb3d", "list"])
        assert result.exit_code == 0

    @responses.activate
    def test_list_with_vuln_id(self, runner):
        responses.get(f"{BASE_URL}/emb3d/", json=[])
        result = runner.invoke(
            cli, ["--compact", "emb3d", "list", "--vuln-id", "CVE-2024-1234"],
        )
        assert result.exit_code == 0
        assert "vuln_id=CVE-2024-1234" in responses.calls[0].request.url

class TestGcve:
    @responses.activate
    def test_registry(self, runner):
        responses.get(f"{BASE_URL}/gcve/registry", json=[])
        result = runner.invoke(cli, ["--compact", "gcve", "registry"])
        assert result.exit_code == 0

    @responses.activate
    def test_registry_with_short_name(self, runner):
        responses.get(f"{BASE_URL}/gcve/registry", json=[])
        result = runner.invoke(
            cli, ["--compact", "gcve", "registry", "--short-name", "CVE"],
        )
        assert result.exit_code == 0
        assert "short_name=CVE" in responses.calls[0].request.url

    @responses.activate
    def test_integrity(self, runner):
        responses.get(
            f"{BASE_URL}/gcve/registry/integrity", json={"valid": True},
        )
        result = runner.invoke(cli, ["--compact", "gcve", "integrity"])
        assert result.exit_code == 0
        assert json.loads(result.output)["valid"] is True

class TestOrganization:
    @responses.activate
    def test_list(self, runner):
        responses.get(f"{BASE_URL}/organization/", json=[])
        result = runner.invoke(cli, ["--compact", "organization", "list"])
        assert result.exit_code == 0

    @responses.activate
    def test_list_with_name(self, runner):
        responses.get(f"{BASE_URL}/organization/", json=[])
        result = runner.invoke(
            cli, ["--compact", "organization", "list", "--name", "apache"],
        )
        assert result.exit_code == 0
        assert "name=apache" in responses.calls[0].request.url

class TestProduct:
    @responses.activate
    def test_list(self, runner):
        responses.get(f"{BASE_URL}/product/", json=[])
        result = runner.invoke(cli, ["--compact", "product", "list"])
        assert result.exit_code == 0

    @responses.activate
    def test_list_with_filters(self, runner):
        responses.get(f"{BASE_URL}/product/", json=[])
        result = runner.invoke(
            cli, ["--compact", "product", "list",
                  "--name", "httpd", "--organization-name", "apache"],
        )
        assert result.exit_code == 0
        url = responses.calls[0].request.url
        assert "name=httpd" in url
        assert "organization_name=apache" in url

class TestClassify:
    @responses.activate
    def test_classify(self, runner):
        payload = {"severity": "high"}
        responses.post(
            f"{BASE_URL}/vlai/severity-classification", json=payload,
        )
        result = runner.invoke(
            cli, ["--compact", "classify", "buffer overflow"],
        )
        assert result.exit_code == 0
        assert json.loads(result.output) == payload

    @responses.activate
    def test_classify_with_model(self, runner):
        responses.post(
            f"{BASE_URL}/vlai/severity-classification", json={},
        )
        result = runner.invoke(
            cli, ["--compact", "classify", "buffer overflow",
                  "--model", "gpt-4"],
        )
        assert result.exit_code == 0
        body = json.loads(responses.calls[0].request.body)
        assert body["model"] == "gpt-4"

class TestBundleCommentSighting:
    @responses.activate
    def test_bundle_get(self, runner):
        responses.get(f"{BASE_URL}/bundle/abc-123", json={"uuid": "abc-123"})
        result = runner.invoke(cli, ["--compact", "bundle", "get", "abc-123"])
        assert result.exit_code == 0
        assert json.loads(result.output)["uuid"] == "abc-123"

    @responses.activate
    def test_comment_list(self, runner):
        responses.get(f"{BASE_URL}/comment/", json=[])
        result = runner.invoke(cli, ["--compact", "comment", "list"])
        assert result.exit_code == 0

    @responses.activate
    def test_sighting_list_with_type(self, runner):
        responses.get(f"{BASE_URL}/sighting/", json=[])
        result = runner.invoke(
            cli, ["--compact", "sighting", "list", "--type", "seen"],
        )
        assert result.exit_code == 0
        assert "type=seen" in responses.calls[0].request.url

class TestSystemUser:
    @responses.activate
    def test_system_db_info(self, runner):
        responses.get(f"{BASE_URL}/system/dbInfo", json={"status": "ok"})
        result = runner.invoke(cli, ["--compact", "system", "db-info"])
        assert result.exit_code == 0

    @responses.activate
    def test_system_health(self, runner):
        responses.get(f"{BASE_URL}/system/checkProcess", json={"up": True})
        result = runner.invoke(cli, ["--compact", "system", "health"])
        assert result.exit_code == 0

    @responses.activate
    def test_system_pg_info(self, runner):
        responses.get(f"{BASE_URL}/system/pgInfo", json={"version": "16"})
        result = runner.invoke(cli, ["--compact", "system", "pg-info"])
        assert result.exit_code == 0

    @responses.activate
    def test_system_smtp(self, runner):
        responses.get(f"{BASE_URL}/system/checkSMTP", json={"ok": True})
        result = runner.invoke(cli, ["--compact", "system", "smtp"])
        assert result.exit_code == 0

    @responses.activate
    def test_system_valkey(self, runner):
        responses.get(f"{BASE_URL}/system/valkey_up", json={"up": True})
        result = runner.invoke(cli, ["--compact", "system", "valkey"])
        assert result.exit_code == 0

    @responses.activate
    def test_user_me(self, runner):
        responses.get(f"{BASE_URL}/user/me", json={"login": "admin"})
        result = runner.invoke(
            cli, ["--compact", "--api-key", "key", "user", "me"],
        )
        assert result.exit_code == 0
        assert json.loads(result.output)["login"] == "admin"

class TestErrorHandling:
    @responses.activate
    def test_http_404(self, runner):
        responses.get(
            f"{BASE_URL}/vulnerability/CVE-9999-0000",
            status=404, body="not found",
        )
        result = runner.invoke(cli, ["vuln", "get", "CVE-9999-0000"])
        assert result.exit_code != 0
        assert "HTTP 404" in result.output

    @responses.activate
    def test_connection_error(self, runner):
        from requests.exceptions import ConnectionError as CE
        responses.get(f"{BASE_URL}/browse/", body=CE("refused"))
        result = runner.invoke(cli, ["browse"])
        assert result.exit_code != 0
        assert "connection failed" in result.output

    @responses.activate
    def test_timeout(self, runner):
        from requests.exceptions import Timeout
        responses.get(f"{BASE_URL}/browse/", body=Timeout("slow"))
        result = runner.invoke(cli, ["browse"])
        assert result.exit_code != 0
        assert "timed out" in result.output
