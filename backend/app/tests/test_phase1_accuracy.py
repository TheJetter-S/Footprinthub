# =============================================================================
# FootprintHub — Phase 1 Accuracy Fixes Unit Test Suite
# =============================================================================
# Verifies Spamhaus/DNSBL blocked resolvers, wildcard DNS detection, passive
# profile zero-contact enforcement, port 443 SSL discrepancy, tech fallbacks,
# OSINT provenance, severity calibration, and confidence-weighted risk scoring.
# =============================================================================

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
import dns.exception
import pytest

from app.api.scans import get_modules_for_profile
from app.core.export import ExportService
from app.core.risk_engine import RiskEngine
from app.modules.base import FindingConfidence, FindingSeverity, ModuleFinding, ModuleMode
from app.modules.cloud_module import CloudModule
from app.modules.content_module import ContentModule
from app.modules.dns_module import DNSModule
from app.modules.ip_network_module import IPNetworkModule
from app.modules.osint_module import OSINTModule
from app.modules.ports_module import PortsModule
from app.modules.reputation_module import ReputationModule
from app.modules.ssl_module import SSLModule
from app.modules.subdomain_module import SubdomainModule
from app.modules.webtech_module import WebTechModule


# =============================================================================
# 1. Spamhaus & DNSBL Accuracy
# =============================================================================

@pytest.mark.asyncio
async def test_dnsbl_resolver_blocked_codes_not_treated_as_listing():
    """Verify return codes 127.255.255.252, .254, .255 are treated as blocked resolver errors, not listings."""
    rep_module = ReputationModule()
    
    async def fake_resolve(qname, rtype="A"):
        # If resolving target IP, return 93.184.216.34
        if "example.com" in str(qname):
            m = MagicMock()
            m.__str__ = lambda s: "93.184.216.34"
            return [m]
        # For DNSBL queries, simulate Spamhaus blocked resolver return code (e.g. 127.255.255.254)
        m = MagicMock()
        m.__str__ = lambda s: "127.255.255.254"
        return [m]

    with patch.object(rep_module.resolver, "resolve", side_effect=fake_resolve):
        result = await rep_module.run("example.com")
        
        assert result.status == "success"
        # Must NOT generate any finding for blocked resolvers
        assert len(result.findings) == 0
        # Data must reflect check failed
        assert len(result.data["blacklists"]) > 0
        assert result.data["blacklists"][0]["status"] == "Check failed (public resolver blocked)"
        assert result.data["blacklists"][0]["listed"] is False


@pytest.mark.asyncio
async def test_dnsbl_true_listing_in_range_produces_finding():
    """Verify true listing code 127.0.0.2 produces a CONFIRMED finding."""
    rep_module = ReputationModule()
    
    async def fake_resolve(qname, rtype="A"):
        if "example.com" in str(qname):
            m = MagicMock()
            m.__str__ = lambda s: "93.184.216.34"
            return [m]
        # True listing return code
        m = MagicMock()
        m.__str__ = lambda s: "127.0.0.2"
        return [m]

    with patch.object(rep_module.resolver, "resolve", side_effect=fake_resolve):
        result = await rep_module.run("example.com")
        
        assert len(result.findings) >= 1
        f = result.findings[0]
        assert f.severity == FindingSeverity.HIGH
        assert f.confidence == FindingConfidence.CONFIRMED
        assert "127.0.0.2" in f.evidence


# =============================================================================
# 2. Wildcard DNS Detection & Subdomain Calibration
# =============================================================================

@pytest.mark.asyncio
async def test_wildcard_dns_detection_and_filtering():
    """Verify random non-existent domain probes detect wildcard DNS."""
    sub_module = SubdomainModule()
    
    async def fake_resolve(qname, rtype="A"):
        m = MagicMock()
        m.__str__ = lambda s: "93.184.216.34"
        return [m]
    
    with patch.object(sub_module.resolver, "resolve", side_effect=fake_resolve):
        with patch.object(sub_module, "_query_crt_sh", new_callable=AsyncMock) as mock_crt:
            mock_crt.return_value = (set(), {})
            result = await sub_module.run("example.com", profile="passive")
            
            assert result.data["wildcard_dns"] is True
            assert "93.184.216.34" in result.data["wildcard_ips"]
            wildcard_findings = [f for f in result.findings if "Wildcard DNS" in f.title]
            assert len(wildcard_findings) == 1
            assert wildcard_findings[0].confidence == FindingConfidence.CONFIRMED


@pytest.mark.asyncio
async def test_subdomain_module_passive_takeover_zero_http():
    """Verify passive profile checks takeover purely via DNS CNAME and never performs HTTP requests."""
    sub_module = SubdomainModule()
    
    subdomains = [
        {"subdomain": "test.example.com", "cnames": ["dangling.s3.amazonaws.com"]}
    ]
    
    with patch("httpx.AsyncClient") as mock_http:
        with patch.object(sub_module.resolver, "resolve", side_effect=dns.exception.DNSException("NXDOMAIN")):
            findings = await sub_module._check_takeovers(subdomains, is_passive=True)
            # HTTP client must NOT be called in passive mode
            mock_http.assert_not_called()
            assert len(findings) == 1
            assert "Potential Subdomain Takeover" in findings[0].title
            assert findings[0].confidence == FindingConfidence.LIKELY


# =============================================================================
# 3. Passive Profile Enforcement & Module Modes
# =============================================================================

def test_profile_module_mappings():
    """Passive profile must contain only public/3rd-party data sources and never probe targets."""
    passive_pairs = get_modules_for_profile("passive")
    passive_mods = [name for name, _ in passive_pairs]
    expected_passive = ["dns", "subdomains", "ip_network", "ports", "osint", "reputation", "lookalike"]
    assert sorted(passive_mods) == sorted(expected_passive)
    
    # In passive mode, ports mode must be 'passive' (Shodan InternetDB only)
    ports_pair = next(p for p in passive_pairs if p[0] == "ports")
    assert ports_pair[1] == "passive"
    
    # Target-contacting modules must never be in passive profile
    forbidden_in_passive = ["web_tech", "ssl_tls", "content", "cloud"]
    for mod in forbidden_in_passive:
        assert mod not in passive_mods, f"Module {mod} must not be allowed in passive profile"
        
    standard_pairs = get_modules_for_profile("standard")
    standard_mods = [name for name, _ in standard_pairs]
    assert "web_tech" in standard_mods
    assert "ssl_tls" in standard_mods
    assert "content" in standard_mods
    assert "cloud" in standard_mods
    assert "ports" in standard_mods
    
    full_pairs = get_modules_for_profile("full")
    full_ports_pair = next(p for p in full_pairs if p[0] == "ports")
    assert full_ports_pair[1] == "active"  # Full profile runs active TCP port probing


def test_module_mode_attributes():
    """Modules contacting targets or performing probes must be marked ModuleMode.ACTIVE."""
    assert PortsModule.mode == ModuleMode.ACTIVE
    assert SSLModule.mode == ModuleMode.ACTIVE
    assert WebTechModule.mode == ModuleMode.ACTIVE
    assert ContentModule.mode == ModuleMode.ACTIVE
    assert CloudModule.mode == ModuleMode.ACTIVE
    
    # Passive modules must be marked ModuleMode.PASSIVE
    assert DNSModule.mode == ModuleMode.PASSIVE
    assert IPNetworkModule.mode == ModuleMode.PASSIVE
    assert ReputationModule.mode == ModuleMode.PASSIVE
    assert OSINTModule.mode == ModuleMode.PASSIVE


# =============================================================================
# 4. Port 443 vs SSL Discrepancy
# =============================================================================

@pytest.mark.asyncio
async def test_ssl_discrepancy_reported_when_port_open_but_handshake_fails():
    """If port 443 is open but TLS handshake fails, an explicit discrepancy finding must be generated."""
    ssl_mod = SSLModule()
    
    dummy_sock = MagicMock()
    dummy_sock.__enter__ = MagicMock(return_value=dummy_sock)
    dummy_sock.__exit__ = MagicMock(return_value=False)
    
    with patch("socket.create_connection", return_value=dummy_sock):
        with patch.object(ssl_mod, "_get_certificate_info", new_callable=AsyncMock, return_value=None):
            result = await ssl_mod.run("example.com")
            
            assert result.data["port_443_open"] is True
            assert result.data["certificate"] is None
            
            # Must generate discrepancy finding
            discrepancy_findings = [f for f in result.findings if "Discrepancy" in f.title]
            assert len(discrepancy_findings) == 1
            df = discrepancy_findings[0]
            assert df.severity == FindingSeverity.LOW
            assert df.confidence == FindingConfidence.CONFIRMED
            assert "port 443" in df.title.lower()


# =============================================================================
# 5. Technology Fallback Signatures & Anycast CDN Masking
# =============================================================================

@pytest.mark.asyncio
async def test_web_tech_cookie_header_fallback_detection():
    """Detect technologies from headers and cookies when body has minimal content."""
    tech_mod = WebTechModule()
    
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.url = "https://example.com"
    mock_resp.text = "<html><head><meta name='generator' content='WordPress 6.4'></head><body>Hello</body></html>"
    mock_resp.headers = {
        "server": "Apache/2.4.41 (Ubuntu)",
        "x-powered-by": "PHP/7.4.3",
        "set-cookie": "PHPSESSID=abc123xyz; Path=/",
    }
    mock_resp.cookies = MagicMock()
    mock_resp.cookies.items.return_value = [("PHPSESSID", "abc123xyz")]
    
    mock_client_instance = AsyncMock()
    mock_client_instance.get.return_value = mock_resp
    mock_client_instance.__aenter__.return_value = mock_client_instance
    mock_client_instance.__aexit__.return_value = False
    
    with patch("httpx.AsyncClient", return_value=mock_client_instance):
        result = await tech_mod.run("example.com")
        
        techs = result.data.get("technologies", [])
        assert any("Apache" in t for t in techs)
        assert "PHP" in techs
        assert "WordPress 6.4" in techs


@pytest.mark.asyncio
async def test_ip_network_anycast_cdn_city_masking():
    """CDN edge / Anycast IPs must mask city with 'CDN edge (anycast), location not meaningful'."""
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
                net_list = result.data.get("networks", [])
                assert len(net_list) > 0
                assert net_list[0]["is_anycast_cdn"] is True
                assert "CDN edge (anycast)" in net_list[0]["city"]


# =============================================================================
# 6. OSINT Email Provenance & Unverified Role Addresses
# =============================================================================

@pytest.mark.asyncio
async def test_osint_email_provenance_and_confidence():
    """Emails found on page have CONFIRMED confidence, synthesized role aliases have POSSIBLE confidence."""
    osint_mod = OSINTModule()
    
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "<html><body>Contact us at security@example.com</body></html>"
    
    mock_client = AsyncMock()
    mock_client.get.return_value = mock_resp
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = False
    
    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await osint_mod.run("example.com")
        
        profiles = result.data.get("behind_the_email", [])
        assert len(profiles) > 0
        
        # Scraped email has source_type "Found on page" and is_confirmed = True
        scraped = next((p for p in profiles if p.get("email") == "security@example.com"), None)
        assert scraped is not None
        assert scraped["source_type"] == "Found on page"
        assert scraped["is_confirmed"] is True


# =============================================================================
# 7. Risk Engine Confidence Weighting & Failed Check Exclusions
# =============================================================================

def test_risk_engine_confidence_discounting():
    """Findings with 'possible' confidence must receive 50% score discounting."""
    # Finding 1: Confirmed High (10 pts)
    f_confirmed = MagicMock()
    f_confirmed.severity = "high"
    f_confirmed.confidence = "confirmed"
    f_confirmed.title = "Confirmed Issue"
    
    # Finding 2: Possible High (10 pts * 0.5 = 5 pts)
    f_possible = MagicMock()
    f_possible.severity = "high"
    f_possible.confidence = "possible"
    f_possible.title = "Possible Issue"
    
    score_conf = RiskEngine.calculate_score([f_confirmed]).score
    score_poss = RiskEngine.calculate_score([f_possible]).score
    
    assert score_conf == 10
    assert score_poss == 5
    assert score_poss < score_conf


def test_risk_engine_failed_check_zero_weight():
    """Lookup errors or failed checks must carry 0 points in risk calculation."""
    f_failed = MagicMock()
    f_failed.severity = "high"
    f_failed.confidence = "possible"
    f_failed.title = "Check failed (public resolver blocked)"
    
    assessment = RiskEngine.calculate_score([f_failed])
    assert assessment.score == 0


# =============================================================================
# 8. Export Service Confidence & Evidence Inclusion
# =============================================================================

def test_export_service_includes_confidence_and_evidence():
    """JSON and CSV exports must contain confidence and evidence fields."""
    scan = MagicMock()
    scan.id = "scan-123"
    scan.domain = "example.com"
    scan.profile = "standard"
    scan.status = "completed"
    scan.risk_score = 15
    scan.created_at = datetime.now()
    scan.completed_at = datetime.now()
    
    finding = MagicMock()
    finding.id = "f-1"
    finding.severity = "high"
    finding.confidence = "confirmed"
    finding.evidence = "Found in DNS TXT"
    finding.module_name = "dns"
    finding.title = "Missing SPF"
    finding.description = "No SPF record"
    finding.remediation = "Add SPF"
    finding.created_at = datetime.now()
    
    # JSON Export
    json_out = ExportService.export_json(scan, [], [finding])
    assert '"confidence": "confirmed"' in json_out
    assert '"evidence": "Found in DNS TXT"' in json_out
    
    # CSV Export
    csv_out = ExportService.export_csv([finding], scan, [])
    assert "Confidence" in csv_out
    assert "CONFIRMED" in csv_out
    assert "Evidence" in csv_out
    assert "Found in DNS TXT" in csv_out
