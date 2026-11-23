# =============================================================================
# FootprintHub — Phase 3 Active Profile Hardening Unit Test Suite
# =============================================================================
# Verifies safe curated port scanning (concurrency <= 20, banner grabbing,
# adaptive backoff), intelligent TLS probing (weak ciphers, ALPN, chain audit),
# WAF detection (headers, cookies, benign test probe), and technology confirmation.
# =============================================================================

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
import ssl

from app.modules.base import FindingConfidence, FindingSeverity, ModuleFinding, ModuleMode
from app.modules.ports_module import CURATED_TOP_PORTS, PortsModule, _clean_banner
from app.modules.ssl_module import SSLModule
from app.modules.webtech_module import WebTechModule


# =============================================================================
# 1. Safe Port Scanner: Curated Top Ports, Semaphore Bounding & Banner Grabbing
# =============================================================================

def test_ports_module_curated_top_ports_structure():
    """Curated port list must be bounded (~60-100 high-value ports), not full-range scan."""
    assert 60 <= len(CURATED_TOP_PORTS) <= 100
    port_numbers = [p["port"] for p in CURATED_TOP_PORTS]
    # Verify presence of essential attack-surface ports
    assert 22 in port_numbers     # SSH
    assert 23 in port_numbers     # Telnet
    assert 80 in port_numbers     # HTTP
    assert 443 in port_numbers    # HTTPS
    assert 445 in port_numbers    # SMB
    assert 1433 in port_numbers   # MS-SQL
    assert 3306 in port_numbers   # MySQL
    assert 3389 in port_numbers   # RDP
    assert 5432 in port_numbers   # PostgreSQL
    assert 6379 in port_numbers   # Redis
    assert 9200 in port_numbers   # Elasticsearch
    assert 11211 in port_numbers  # Memcached
    assert 27017 in port_numbers  # MongoDB


def test_clean_banner_sanitization():
    """Banner cleaner extracts HTTP Server header and strips unprintable characters."""
    # HTTP raw response
    http_raw = b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n"
    assert _clean_banner(http_raw) == "Server: nginx/1.24.0 (Ubuntu)"

    # SSH greeting
    ssh_raw = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"
    assert _clean_banner(ssh_raw) == "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"

    # Redis pong
    redis_raw = b"+PONG\r\n"
    assert _clean_banner(redis_raw) == "+PONG"

    # Raw non-printable junk
    junk_raw = b"\x00\x01\x02TestService\x03\x04\xff"
    cleaned = _clean_banner(junk_raw)
    assert cleaned == "TestService"


@pytest.mark.asyncio
async def test_ports_module_active_probe_banner_grabbing():
    """In active mode, open ports are probed, banners captured, and findings emitted with banners."""
    ports_mod = PortsModule(profile="full")

    async def fake_resolve(qname, rtype="A"):
        m = MagicMock()
        m.__str__ = lambda s: "93.184.216.34"
        return [m]

    # Mock _check_and_grab to report SSH 22 and Redis 6379 open with banners
    def fake_check_and_grab(target, port, service):
        if port == 22:
            return True, "SSH-2.0-OpenSSH_8.9p1 Ubuntu"
        if port == 6379:
            return True, "+PONG"
        return False, None

    with patch.object(ports_mod.resolver, "resolve", side_effect=fake_resolve):
        with patch.object(ports_mod.resolver, "resolve_address", side_effect=Exception("No PTR")):
            with patch("app.modules.ports_module._check_and_grab", side_effect=fake_check_and_grab):
                with patch("httpx.AsyncClient") as mock_http:
                    # Mock Shodan InternetDB empty response
                    mock_resp = MagicMock(status_code=404)
                    mock_client = AsyncMock()
                    mock_client.get.return_value = mock_resp
                    mock_client.__aenter__.return_value = mock_client
                    mock_client.__aexit__.return_value = False
                    mock_http.return_value = mock_client

                    result = await ports_mod.run("example.com", profile="full")

                    assert result.mode == ModuleMode.ACTIVE
                    assert result.data["total_open"] == 2
                    open_ports = result.data["ports"]
                    ssh_port = next(p for p in open_ports if p["port"] == 22)
                    redis_port = next(p for p in open_ports if p["port"] == 6379)

                    assert ssh_port["banner"] == "SSH-2.0-OpenSSH_8.9p1 Ubuntu"
                    assert redis_port["banner"] == "+PONG"

                    # Critical Redis finding generated with banner in evidence
                    redis_findings = [f for f in result.findings if "Redis" in f.title]
                    assert len(redis_findings) == 1
                    assert redis_findings[0].severity == FindingSeverity.CRITICAL
                    assert "+PONG" in redis_findings[0].evidence


@pytest.mark.asyncio
async def test_ports_module_ssrf_blocked_host():
    """PortsModule blocks restricted hostnames immediately without resolving or probing."""
    ports_mod = PortsModule(profile="full")
    result = await ports_mod.run("localhost")
    assert result.status == "error"
    assert "blocked by SSRF" in result.data.get("error", "")


# =============================================================================
# 2. Intelligent TLS Probe: Protocol Versions, Weak Ciphers & ALPN
# =============================================================================

@pytest.mark.asyncio
async def test_ssl_module_deprecated_tls_protocols_emit_findings():
    """SSLModule flags deprecated TLS 1.0 (HIGH) and TLS 1.1 (MEDIUM)."""
    ssl_mod = SSLModule()

    # Mock TCP 443 open
    with patch("socket.create_connection", return_value=MagicMock()):
        # Mock certificate info
        mock_cert_data = {
            "subject": {"commonName": "example.com"},
            "issuer": {"organizationName": "DigiCert", "commonName": "DigiCert CA"},
            "subject_alt_names": ["example.com"],
            "valid_from": "Jan 01 00:00:00 2026 GMT",
            "valid_to": "Dec 31 00:00:00 2026 GMT",
            "days_until_expiration": 120,
            "is_self_signed": False,
            "cipher_suite": ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128),
            "active_version": "TLSv1.2",
            "alpn": "h2",
        }
        with patch.object(ssl_mod, "_get_certificate_info", new_callable=AsyncMock, return_value=mock_cert_data):
            # Mock protocol support: TLS 1.0, 1.1, 1.2 supported
            async def fake_test_protocols(host, findings):
                findings.append(ModuleFinding(
                    severity=FindingSeverity.HIGH,
                    title="Deprecated TLS 1.0 Protocol Enabled",
                    description="TLS 1.0 is deprecated.",
                    remediation="Disable TLS 1.0",
                    confidence=FindingConfidence.CONFIRMED,
                    evidence="Handshake succeeded",
                ))
                findings.append(ModuleFinding(
                    severity=FindingSeverity.MEDIUM,
                    title="Deprecated TLS 1.1 Protocol Enabled",
                    description="TLS 1.1 is deprecated.",
                    remediation="Disable TLS 1.1",
                    confidence=FindingConfidence.CONFIRMED,
                    evidence="Handshake succeeded",
                ))
                return {"TLSv1.0": True, "TLSv1.1": True, "TLSv1.2": True, "TLSv1.3": False}

            with patch.object(ssl_mod, "_test_tls_protocols", side_effect=fake_test_protocols):
                with patch.object(ssl_mod, "_test_weak_ciphers", new_callable=AsyncMock, return_value=[]):
                    result = await ssl_mod.run("example.com")

                    assert result.data["port_443_open"] is True
                    assert result.data["alpn"] == "h2"
                    assert result.data["protocols"]["TLSv1.0"] is True
                    titles = [f.title for f in result.findings]
                    assert any("TLS 1.0" in t for t in titles)
                    assert any("TLS 1.1" in t for t in titles)


@pytest.mark.asyncio
async def test_ssl_module_weak_cipher_detection():
    """SSLModule detects legacy RC4 and 3DES Sweet32 cipher support."""
    ssl_mod = SSLModule()

    mock_cert_data = {
        "subject": {"commonName": "example.com"},
        "issuer": {"commonName": "DigiCert"},
        "subject_alt_names": ["example.com"],
        "days_until_expiration": 90,
        "is_self_signed": False,
        "cipher_suite": ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256),
    }

    with patch("socket.create_connection", return_value=MagicMock()):
        with patch.object(ssl_mod, "_get_certificate_info", new_callable=AsyncMock, return_value=mock_cert_data):
            with patch.object(ssl_mod, "_test_tls_protocols", new_callable=AsyncMock, return_value={"TLSv1.2": True, "TLSv1.3": True}):
                # Mock weak cipher test finding 3DES and RC4
                async def fake_weak_ciphers(host, findings):
                    findings.append(ModuleFinding(
                        severity=FindingSeverity.MEDIUM,
                        title="Weak Cipher Suite Supported: 3DES (Sweet32)",
                        description="3DES is weak.",
                        remediation="Disable 3DES",
                        confidence=FindingConfidence.CONFIRMED,
                        evidence="DES-CBC3-SHA accepted",
                    ))
                    findings.append(ModuleFinding(
                        severity=FindingSeverity.HIGH,
                        title="Weak Cipher Suite Supported: RC4",
                        description="RC4 is broken.",
                        remediation="Disable RC4",
                        confidence=FindingConfidence.CONFIRMED,
                        evidence="RC4-SHA accepted",
                    ))
                    return [
                        {"category": "3DES", "negotiated": "DES-CBC3-SHA"},
                        {"category": "RC4", "negotiated": "RC4-SHA"},
                    ]

                with patch.object(ssl_mod, "_test_weak_ciphers", side_effect=fake_weak_ciphers):
                    result = await ssl_mod.run("example.com")

                    assert len(result.data["weak_ciphers"]) == 2
                    titles = [f.title for f in result.findings]
                    assert any("3DES" in t for t in titles)
                    assert any("RC4" in t for t in titles)


# =============================================================================
# 3. Web Application Firewall (WAF) Detection & Benign Behavior Testing
# =============================================================================

@pytest.mark.asyncio
async def test_waf_detection_cloudflare_headers():
    """WebTechModule detects Cloudflare WAF from response headers and emits finding."""
    tech_mod = WebTechModule()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.url = "https://example.com"
    mock_resp.text = "<html><body>Welcome to Cloudflare protected site</body></html>"
    mock_resp.headers = {
        "server": "cloudflare",
        "cf-ray": "8934029d98fa-IAD",
        "cf-cache-status": "HIT",
    }
    mock_resp.cookies = MagicMock()
    mock_resp.cookies.items.return_value = [("__cfduid", "d123456789")]

    mock_client = AsyncMock()
    mock_client.get.return_value = mock_resp
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = False

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await tech_mod.run("example.com")

        waf = result.data.get("waf")
        assert waf is not None
        assert waf["detected"] is True
        assert waf["vendor"] == "Cloudflare"

        waf_findings = [f for f in result.findings if "WAF" in f.title]
        assert len(waf_findings) == 1
        assert "Cloudflare" in waf_findings[0].title
        assert waf_findings[0].confidence == FindingConfidence.CONFIRMED


@pytest.mark.asyncio
async def test_waf_detection_active_benign_blocking_probe():
    """WebTechModule triggers benign test probe and identifies AWS WAF on HTTP 403 block."""
    tech_mod = WebTechModule()

    # Initial homepage response without clear WAF headers
    resp_home = MagicMock()
    resp_home.status_code = 200
    resp_home.url = "https://example.com"
    resp_home.text = "<html><body>Standard Application</body></html>"
    resp_home.headers = {"server": "Apache"}
    resp_home.cookies = MagicMock()
    resp_home.cookies.items.return_value = []

    # Benign test probe triggers AWS WAF 403 block page
    resp_waf_probe = MagicMock()
    resp_waf_probe.status_code = 403
    resp_waf_probe.text = "<html><head><title>403 Forbidden</title></head><body>Request blocked by AWS WAF</body></html>"
    resp_waf_probe.headers = {"x-amzn-requestid": "abc-123", "server": "awselb/2.0"}

    mock_client = AsyncMock()
    # First call: homepage, Second call: test probe
    mock_client.get.side_effect = [resp_home, resp_waf_probe]
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = False

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await tech_mod.run("example.com")

        waf = result.data.get("waf")
        assert waf is not None
        assert waf["vendor"] == "AWS WAF"
        assert waf["blocked_test_payload"] is True


# =============================================================================
# 4. Active Technology Confirmation Probes
# =============================================================================

@pytest.mark.asyncio
async def test_technology_confirmation_wordpress():
    """When WordPress is suspected, probing /wp-login.php returning 200 confirms WordPress."""
    tech_mod = WebTechModule()

    resp_home = MagicMock()
    resp_home.status_code = 200
    resp_home.url = "https://example.com"
    resp_home.text = "<html><body>Check our blog: /wp-content/themes/twentytwenty/</body></html>"
    resp_home.headers = {"server": "nginx"}
    resp_home.cookies = MagicMock()
    resp_home.cookies.items.return_value = []

    resp_probe = MagicMock(status_code=200, text="<form name='loginform' id='loginform' action='...'>user_login</form>")

    mock_client = AsyncMock()
    # Sequence: homepage -> WAF test probe -> /wp-login.php confirmation probe
    mock_client.get.side_effect = [resp_home, MagicMock(status_code=200, text="OK"), resp_probe]
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = False

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await tech_mod.run("example.com")

        confirmed = result.data.get("confirmed_technologies", [])
        wp_confirmed = next((c for c in confirmed if c["name"] == "WordPress"), None)
        assert wp_confirmed is not None
        assert wp_confirmed["status"] == "Confirmed"
        assert "/wp-login.php" in wp_confirmed["probe_url"]
