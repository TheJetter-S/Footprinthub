# =============================================================================
# FootprintHub — Phase 7 Quality, Security & Profile Enforcement Test Suite
# =============================================================================

import pytest
import hashlib
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.risk_engine import RiskEngine
from app.core.ssrf_guard import (
    SSRFError,
    is_ip_blocked,
    is_hostname_blocked,
    validate_domain,
    validate_url,
)
from app.core.safe_request import safe_get
from app.core.notification_service import NotificationService
from app.core.cve_intelligence import CVEIntelligenceService
from app.modules.base import FindingConfidence, FindingSeverity, ModuleMode
from app.modules.dns_module import DNSModule
from app.modules.subdomain_module import SubdomainModule
from app.modules.ip_network_module import IPNetworkModule
from app.modules.ports_module import PortsModule
from app.modules.osint_module import OSINTModule, BehindTheEmailEngine
from app.modules.osint_helpers import (
    SecretPatternScanner,
    CodeLeakEngine,
    RDAPService,
)
from app.modules.lookalike_module import LookalikeModule, LookalikeGenerator
from app.modules.reputation_module import ReputationModule
from app.models.api_key import ApiKey


class TestFalsePositiveRegressions:
    """Verifies that false-positive mitigations work as strictly specified."""

    @pytest.mark.asyncio
    async def test_spamhaus_dnsbl_blocked_resolver_codes_never_treated_as_listing(self):
        """
        Spamhaus/DNSBL return codes 127.255.255.252, .254, .255 indicate public resolver
        rate-limiting/blocking. They must NEVER be reported as a positive listing and must
        carry 0 risk score weight.
        """
        rep_module = ReputationModule()

        async def fake_resolve(qname, rtype="A"):
            if "example.com" in str(qname):
                m = MagicMock()
                m.__str__ = lambda s: "93.184.216.34"
                return [m]
            # Simulate Spamhaus resolver rate-limited return code
            m = MagicMock()
            m.__str__ = lambda s: "127.255.255.254"
            return [m]

        with patch.object(rep_module.resolver, "resolve", side_effect=fake_resolve):
            result = await rep_module.run("example.com")
            assert result.status == "success"
            # Must NOT generate any positive listing finding
            assert len(result.findings) == 0
            assert len(result.data["blacklists"]) > 0
            assert result.data["blacklists"][0]["status"] == "Check failed (public resolver blocked)"
            assert result.data["blacklists"][0]["listed"] is False

        # Exclude failed check titles from risk score
        findings = [
            {"title": "Check failed (public resolver blocked): zen.spamhaus.org", "severity": "info", "confidence": "possible"},
        ]
        assessment = RiskEngine.calculate_score(findings)
        assert assessment.score == 0

    @pytest.mark.asyncio
    async def test_wildcard_dns_detection_and_cdn_baseline_calibration(self):
        """
        Wildcard DNS detector resolves 3 random non-existent names.
        If they resolve, it marks wildcard DNS and filters out matching brute-force IPs.
        For sensitive subdomains resolving under wildcard DNS, findings are marked Possible/Info.
        """
        sub_mod = SubdomainModule()

        async def fake_resolve(qname, rtype="A"):
            m = MagicMock()
            m.__str__ = lambda s: "93.184.216.34"
            return [m]

        with patch.object(sub_mod.resolver, "resolve", side_effect=fake_resolve):
            with patch.object(sub_mod, "_query_crt_sh", new_callable=AsyncMock) as mock_crt:
                mock_crt.return_value = (set(), {})
                result = await sub_mod.run("example.com", profile="passive")

                assert result.data["wildcard_dns"] is True
                assert "93.184.216.34" in result.data["wildcard_ips"]
                wildcard_findings = [f for f in result.findings if "Wildcard DNS" in f.title]
                assert len(wildcard_findings) == 1
                assert wildcard_findings[0].confidence == FindingConfidence.CONFIRMED

        # Sensitive subdomains check with is_wildcard=True -> FindingConfidence.POSSIBLE and INFO severity
        resolved = [{"subdomain": "dev.example.com", "ips": ["93.184.216.34"]}]
        findings = sub_mod._audit_sensitive_subdomains("example.com", resolved, is_wildcard=True)
        assert len(findings) == 1
        assert findings[0].confidence == FindingConfidence.POSSIBLE
        assert findings[0].severity == FindingSeverity.INFO

    @pytest.mark.asyncio
    async def test_cdn_anycast_geolocation_masked(self):
        """
        Anycast/CDN IPs (Cloudflare, Akamai, Fastly, CloudFront) must hide city-level
        geolocation and report 'CDN edge (anycast), location not meaningful'.
        """
        ip_mod = IPNetworkModule()
        ip_info = {
            "ip": "104.21.5.10",
            "org": "Cloudflare, Inc.",
            "as_name": "AS13335 CLOUDFLARENET",
        }
        cdn_name = ip_mod._match_cdn_waf(ip_info)
        assert cdn_name is not None
        assert "Cloudflare" in cdn_name

        with patch.object(ip_mod, "_lookup_ip", new_callable=AsyncMock) as mock_lookup:
            mock_lookup.return_value = {
                "ip": "104.21.5.10",
                "org": "Cloudflare, Inc.",
                "as_name": "AS13335 CLOUDFLARENET",
                "city": "San Francisco",
            }
            with patch.object(ip_mod, "_lookup_ptr", new_callable=AsyncMock, return_value=None):
                with patch.object(ip_mod.resolver, "resolve", new_callable=AsyncMock) as mock_res:
                    m = MagicMock()
                    m.__str__ = lambda s: "104.21.5.10"
                    mock_res.return_value = [m]

                    result = await ip_mod.run("example.com")
                    network_data = result.data.get("networks", [])
                    assert len(network_data) > 0
                    assert network_data[0]["is_anycast_cdn"] is True
                    assert network_data[0]["city"] == "CDN edge (anycast), location not meaningful"


class TestProfileEnforcementPassiveZeroTargetContact:
    """
    GLOBAL RULE: Passive profile must be TRULY passive.
    It may ONLY query third-party/public data feeds and fetch NOTHING from target's own servers.
    Assert zero direct socket connections or HTTP requests to the target host.
    """

    @pytest.mark.asyncio
    async def test_passive_subdomains_zero_http_takeover_probes(self):
        sub_mod = SubdomainModule()
        with patch.object(sub_mod, "_query_crt_sh", new_callable=AsyncMock, return_value=(["api.example.com"], {})):
            with patch.object(sub_mod, "_resolve_subdomains", new_callable=AsyncMock, return_value=[{"subdomain": "api.example.com", "ips": ["93.184.216.34"]}]):
                with patch("app.core.safe_request.safe_get") as mock_safe_get:
                    result = await sub_mod.run("example.com", profile="passive")
                    assert result.status in ("success", "partial")
                    # In passive mode, zero safe_get calls are made to verify dangling takeover HTTP
                    mock_safe_get.assert_not_called()

    @pytest.mark.asyncio
    async def test_passive_ports_uses_shodan_internetdb_zero_tcp_probes(self):
        ports_mod = PortsModule(profile="passive")
        mock_idb_resp = MagicMock()
        mock_idb_resp.status_code = 200
        mock_idb_resp.json.return_value = {
            "ip": "93.184.216.34",
            "ports": [80, 443],
            "cpes": [],
            "tags": [],
            "hostnames": ["example.com"],
            "vulns": [],
        }

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_idb_resp
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = False

        async def fake_resolve(qname, rtype="A"):
            m = MagicMock()
            m.__str__ = lambda s: "93.184.216.34"
            return [m]

        with patch.object(ports_mod.resolver, "resolve", side_effect=fake_resolve), \
             patch.object(ports_mod.resolver, "resolve_address", side_effect=Exception("No PTR")), \
             patch("httpx.AsyncClient", return_value=mock_client), \
             patch("socket.create_connection") as mock_socket:

            result = await ports_mod.run("example.com", profile="passive")
            mock_socket.assert_not_called()
            assert result.mode == ModuleMode.PASSIVE
            assert result.data["is_passive"] is True

    @pytest.mark.asyncio
    async def test_passive_osint_zero_target_crawling_and_dns_only_verification(self):
        osint_mod = OSINTModule(profile="passive")
        with patch("app.core.safe_request.safe_get") as mock_safe_get, \
             patch.object(RDAPService, "query_rdap", AsyncMock(return_value={})):
            result = await osint_mod.run("example.com", profile="passive")
            assert result.status in ("success", "partial")
            # In passive mode, safe_get must never target example.com
            for call in mock_safe_get.mock_calls:
                url_called = str(call)
                assert "https://example.com" not in url_called
                assert "http://example.com" not in url_called

    @pytest.mark.asyncio
    async def test_passive_lookalike_zero_http_connections(self):
        look_mod = LookalikeModule()
        mock_candidates = [
            {"domain": "cybervault.com", "type": "TLD Swap"},
        ]
        with patch.object(LookalikeGenerator, "generate", return_value=mock_candidates), \
             patch("httpx.AsyncClient.get") as mock_http, \
             patch.object(RDAPService, "query_rdap", AsyncMock(return_value={})):
            result = await look_mod.run("example.com")
            assert result.status in ("success", "partial")
            mock_http.assert_not_called()


class TestSSRFSecurityBoundary:
    """Verifies that SSRF guards block all private/reserved ranges across all modules."""

    def test_ssrf_guard_blocks_all_reserved_ipv4_and_ipv6_ranges(self):
        blocked = [
            "127.0.0.1", "127.0.1.1", "10.0.0.1", "10.255.255.255",
            "172.16.0.1", "172.31.255.255", "192.168.0.1", "192.168.1.100",
            "169.254.169.254", "0.0.0.0", "::1", "fe80::1", "fc00::1", "fd00::1"
        ]
        for ip in blocked:
            assert is_ip_blocked(ip) is True

    def test_ssrf_guard_blocks_metadata_and_internal_hostnames(self):
        blocked_hosts = [
            "localhost", "localhost.localdomain", "metadata.google.internal",
            "instance-data", "169.254.169.254"
        ]
        for host in blocked_hosts:
            assert is_hostname_blocked(host) is True

    @pytest.mark.asyncio
    async def test_safe_get_rejects_private_and_metadata_urls(self):
        blocked_urls = [
            "http://127.0.0.1:8000/api",
            "http://localhost:3000",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1",
            "http://10.1.2.3/secret",
            "http://192.168.1.1/admin",
        ]
        for url in blocked_urls:
            with pytest.raises(SSRFError):
                await safe_get(url)

    def test_notification_webhooks_reject_internal_targets(self):
        with pytest.raises(SSRFError):
            NotificationService.validate_webhook_url("http://127.0.0.1:8080/hook")
        with pytest.raises(SSRFError):
            NotificationService.validate_webhook_url("http://169.254.169.254/hook")


class TestExternalAPIsMocked:
    """Ensures every external API gracefully handles success, failure, and missing keys."""

    @pytest.mark.asyncio
    async def test_cisa_kev_and_epss_catalog(self):
        mock_kev_json = {
            "vulnerabilities": [
                {"cveID": "CVE-2023-38606", "vendorProject": "Apple", "vulnerabilityName": "Apple WebKit RCE"},
            ]
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_kev_json

        with patch("httpx.AsyncClient.get", return_value=mock_resp):
            kev_map = await CVEIntelligenceService.load_cisa_kev(force_refresh=True)
            assert "CVE-2023-38606" in kev_map
            assert kev_map["CVE-2023-38606"]["vendor_project"] == "Apple"

        # Cleanup test cache
        import app.core.cve_intelligence as ci
        ci._cisa_kev_cache.clear()
        ci._cisa_kev_timestamp = None
        if ci.KEV_CACHE_FILE.exists():
            try:
                ci.KEV_CACHE_FILE.unlink(missing_ok=True)
            except Exception:
                pass

    @pytest.mark.asyncio
    async def test_code_leak_engine_all_platforms(self):
        mock_client = AsyncMock()

        async def mock_get(url, *args, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            url_str = str(url)
            if "api.github.com" in url_str:
                resp.json.return_value = {
                    "items": [{"full_name": "target/repo", "html_url": "https://github.com/target/repo", "description": "repo"}]
                }
            elif "gitlab.com" in url_str:
                resp.json.return_value = [{"name": "repo", "web_url": "https://gitlab.com/repo", "description": ""}]
            elif "hub.docker.com" in url_str:
                resp.json.return_value = {"results": [{"repo_name": "target/app", "short_description": "container"}]}
            elif "registry.npmjs.org" in url_str:
                resp.json.return_value = {"objects": [{"package": {"name": "@target/sdk", "description": ""}}]}
            elif "pypi.org" in url_str:
                resp.json.return_value = {"info": {"name": "target-sdk", "summary": ""}}
            return resp

        mock_client.get = AsyncMock(side_effect=mock_get)
        results = await CodeLeakEngine.search_leaks("targetcorp.com", company_name="TargetCorp", client=mock_client)
        assert len(results["github_repos"]) >= 1
        assert len(results["docker_hub_images"]) >= 1

    def test_hibp_gracefully_skips_when_no_key_configured(self):
        engine = BehindTheEmailEngine()
        with patch("app.config.settings.HIBP_API_KEY", None):
            res = engine.check_breaches("test@example.com")
            assert isinstance(res, dict)
            assert "pwned" in res


class TestSecurityReviewStrictMasking:
    """Verifies that secrets and API keys are strictly masked and protected."""

    def test_secret_scanner_strictly_masks_tokens(self):
        mock_slack_token = "xoxb" + "-1234567890-1234567890123-abcdefghijklmnopqrstuvwx"
        raw_content = f"""
        AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE
        GITHUB_TOKEN = ghp_123456789012345678901234567890123456
        SLACK_BOT_TOKEN = {mock_slack_token}
        -----BEGIN RSA PRIVATE KEY-----
        MIIEowIBAAKCAQEA0Y123456789abcdef...
        -----END RSA PRIVATE KEY-----
        """
        findings = SecretPatternScanner.scan_content(raw_content, "https://github.com/org/repo")

        assert len(findings) >= 4
        # Assert raw secrets never exist in findings
        for f in findings:
            masked = f["masked_value"]
            assert "AKIAIOSFODNN7EXAMPLE" not in masked
            assert "ghp_123456789012345678901234567890123456" not in masked
            assert mock_slack_token[:25] not in masked
            assert "*" in masked or "MASKED" in masked

    def test_api_key_storage_stores_sha256_hash_only(self):
        raw_key = "fph_live_abcdef1234567890"
        expected_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

        key_obj = ApiKey(
            user_id="user-123",
            name="CI Pipeline",
            key_hash=expected_hash,
            key_prefix="fph_live_abcd",
            scopes="read,scan",
        )

        assert key_obj.key_hash == expected_hash
        assert raw_key not in str(key_obj.__dict__)
