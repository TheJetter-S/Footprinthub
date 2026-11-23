# =============================================================================
# FootprintHub — Phase 2 Free Passive Exposure Data Unit Test Suite
# =============================================================================
# Verifies Shodan InternetDB passive port & CVE discovery, CDN edge IP skipping,
# CISA KEV and EPSS caching and prioritization, AlienVault OTX passive DNS history,
# and crt.sh Certificate Transparency historical analysis.
# =============================================================================

import asyncio
from datetime import datetime, timezone
import json
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from app.core.cve_intelligence import CVEIntelligenceService, _cisa_kev_cache, _epss_cache
from app.modules.base import FindingConfidence, FindingSeverity, ModuleMode
from app.modules.dns_module import DNSModule
from app.modules.ports_module import PortsModule
from app.modules.subdomain_module import SubdomainModule


# =============================================================================
# 1. Shodan InternetDB Module (Passive Mode & Zero Target Connection)
# =============================================================================

@pytest.mark.asyncio
async def test_ports_module_passive_uses_shodan_internetdb_with_zero_socket_probe():
    """In passive mode, PortsModule queries Shodan InternetDB and creates ZERO direct TCP connections."""
    ports_mod = PortsModule(profile="passive")
    
    mock_idb_resp = MagicMock()
    mock_idb_resp.status_code = 200
    mock_idb_resp.json.return_value = {
        "ip": "93.184.216.34",
        "ports": [80, 443, 8080],
        "cpes": ["cpe:/a:apache:http_server:2.4.41"],
        "tags": ["web", "cloud"],
        "hostnames": ["example.com"],
        "vulns": ["CVE-2021-41773"],
    }
    
    mock_client = AsyncMock()
    mock_client.get.return_value = mock_idb_resp
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = False

    async def fake_resolve(qname, rtype="A"):
        m = MagicMock()
        m.__str__ = lambda s: "93.184.216.34"
        return [m]

    with patch.object(ports_mod.resolver, "resolve", side_effect=fake_resolve):
        with patch.object(ports_mod.resolver, "resolve_address", side_effect=Exception("No PTR")):
            with patch("httpx.AsyncClient", return_value=mock_client):
                with patch("socket.create_connection") as mock_socket:
                    result = await ports_mod.run("example.com", profile="passive")
                    
                    # Direct TCP socket must NEVER be called in passive mode
                    mock_socket.assert_not_called()
                    
                    assert result.mode == ModuleMode.PASSIVE
                    assert result.data["is_passive"] is True
                    assert "Shodan InternetDB" in result.data["source"]
                    
                    # Ports from Shodan
                    ports = [p["port"] for p in result.data["ports"]]
                    assert 80 in ports
                    assert 443 in ports
                    assert 8080 in ports
                    assert result.data["ports"][0]["source"] == "shodan_internetdb"
                    
                    # CPEs and tags
                    assert "cpe:/a:apache:http_server:2.4.41" in result.data["cpes"]
                    assert "web" in result.data["tags"]


@pytest.mark.asyncio
async def test_ports_module_cdn_edge_ip_skipping_and_noting():
    """When target resolves to a CDN edge IP (Cloudflare), passive port scan notes CDN and skips origin interpretation."""
    ports_mod = PortsModule(profile="passive")
    
    async def fake_resolve(qname, rtype="A"):
        m = MagicMock()
        m.__str__ = lambda s: "104.21.5.10"
        return [m]

    # Mock PTR returning cloudflare.net
    async def fake_ptr(ip):
        m = MagicMock()
        m.__str__ = lambda s: "104.21.5.10.cloudflare.net"
        return [m]

    with patch.object(ports_mod.resolver, "resolve", side_effect=fake_resolve):
        with patch.object(ports_mod.resolver, "resolve_address", side_effect=fake_ptr):
            result = await ports_mod.run("example.com", profile="passive")
            
            assert result.data["cdn_detected"] == "Cloudflare"
            assert result.data["cdn_note"] is not None
            assert "Cloudflare CDN/WAF" in result.data["cdn_note"]
            assert "edge infrastructure, not the origin server" in result.data["cdn_note"]


# =============================================================================
# 2. CISA KEV & EPSS Prioritization Service
# =============================================================================

@pytest.mark.asyncio
async def test_cisa_kev_and_epss_caching_and_prioritization():
    """CVEIntelligenceService loads KEV and EPSS feeds, caches them, and ranks KEV/high EPSS CVEs."""
    # Reset in-memory and disk test cache
    import app.core.cve_intelligence as ci
    ci._cisa_kev_cache.clear()
    ci._cisa_kev_timestamp = None
    ci._epss_cache.clear()
    if ci.KEV_CACHE_FILE.exists():
        try:
            ci.KEV_CACHE_FILE.unlink(missing_ok=True)
        except Exception:
            pass

    mock_kev_json = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-41773",
                "vendorProject": "Apache",
                "product": "HTTP Server",
                "vulnerabilityName": "Path Traversal & RCE",
                "dateAdded": "2021-11-03",
                "shortDescription": "Apache HTTP Server 2.4.49 path traversal vulnerability.",
                "requiredAction": "Apply vendor updates immediately.",
            }
        ]
    }
    mock_epss_json = {
        "data": [
            {"cve": "CVE-2021-41773", "epss": "0.9754", "percentile": "0.9998"},
            {"cve": "CVE-2023-99999", "epss": "0.0012", "percentile": "0.1500"},
        ]
    }

    mock_client = AsyncMock()
    
    async def fake_get(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "cisa.gov" in url:
            resp.json.return_value = mock_kev_json
        else:
            resp.json.return_value = mock_epss_json
        return resp

    mock_client.get = fake_get
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = False

    with patch("httpx.AsyncClient", return_value=mock_client):
        # 1. Load KEV and verify parsing
        kev_data = await CVEIntelligenceService.load_cisa_kev()
        assert "CVE-2021-41773" in kev_data
        assert kev_data["CVE-2021-41773"]["vendor_project"] == "Apache"
        
        # 2. Test in-memory cache: second call must not re-download
        with patch.object(mock_client, "get", side_effect=Exception("Should not be called due to cache")):
            cached_kev = await CVEIntelligenceService.load_cisa_kev()
            assert "CVE-2021-41773" in cached_kev

        # 3. Test prioritization ranking
        ranked = await CVEIntelligenceService.prioritize_cves(["CVE-2023-99999", "CVE-2021-41773"])
        assert len(ranked) == 2
        # KEV CVE must be ranked first
        assert ranked[0]["cve_id"] == "CVE-2021-41773"
        assert ranked[0]["known_exploited"] is True
        assert ranked[0]["risk_level"] == "Critical"
        assert ranked[0]["epss_score"] > 0.90

        # Non-exploited low-probability CVE ranked second
        assert ranked[1]["cve_id"] == "CVE-2023-99999"
        assert ranked[1]["known_exploited"] is False
        assert ranked[1]["risk_level"] == "Low"


@pytest.mark.asyncio
async def test_ports_module_cve_findings_generation():
    """CVEs reported by Shodan InternetDB are prioritized and generate KEV Critical findings."""
    ports_mod = PortsModule(profile="passive")
    
    mock_idb_resp = MagicMock()
    mock_idb_resp.status_code = 200
    mock_idb_resp.json.return_value = {
        "ip": "93.184.216.34",
        "ports": [80],
        "cpes": [],
        "tags": [],
        "hostnames": [],
        "vulns": ["CVE-2021-41773"],
    }
    
    mock_client = AsyncMock()
    mock_client.get.return_value = mock_idb_resp
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = False

    async def fake_resolve(qname, rtype="A"):
        m = MagicMock()
        m.__str__ = lambda s: "93.184.216.34"
        return [m]

    fake_prioritized = [
        {
            "cve_id": "CVE-2021-41773",
            "known_exploited": True,
            "epss_score": 0.97,
            "epss_percentile": 0.99,
            "risk_level": "Critical",
            "vulnerability_name": "Apache Path Traversal",
            "required_action": "Update Apache",
            "date_added": "2021-11-03",
        }
    ]

    with patch.object(ports_mod.resolver, "resolve", side_effect=fake_resolve):
        with patch.object(ports_mod.resolver, "resolve_address", side_effect=Exception("No PTR")):
            with patch("httpx.AsyncClient", return_value=mock_client):
                with patch.object(CVEIntelligenceService, "prioritize_cves", return_value=fake_prioritized):
                    result = await ports_mod.run("example.com", profile="passive")
                    
                    cve_findings = [f for f in result.findings if "CVE-2021-41773" in f.title]
                    assert len(cve_findings) == 1
                    cf = cve_findings[0]
                    assert cf.severity == FindingSeverity.CRITICAL
                    assert cf.confidence == FindingConfidence.CONFIRMED
                    assert "CISA KEV" in cf.title
                    assert "Update Apache" in cf.remediation


# =============================================================================
# 3. Passive DNS History via AlienVault OTX (DNSModule)
# =============================================================================

@pytest.mark.asyncio
async def test_alienvault_otx_passive_dns_history_and_churn_detection():
    """DNSModule queries AlienVault OTX, extracts past IPs, and highlights significant IP churn."""
    dns_mod = DNSModule()
    
    mock_otx_data = {
        "count": 6,
        "passive_dns": [
            {"address": "1.1.1.1", "first": "2022-01-01", "last": "2022-06-01", "record_type": "A", "asn": "AS13335"},
            {"address": "2.2.2.2", "first": "2022-06-02", "last": "2023-01-01", "record_type": "A", "asn": "AS15169"},
            {"address": "3.3.3.3", "first": "2023-01-02", "last": "2023-08-01", "record_type": "A", "asn": "AS16509"},
            {"address": "4.4.4.4", "first": "2023-08-02", "last": "2024-01-01", "record_type": "A", "asn": "AS8075"},
            {"address": "5.5.5.5", "first": "2024-01-02", "last": "2024-06-01", "record_type": "A", "asn": "AS16509"},
            {"address": "6.6.6.6", "first": "2024-06-02", "last": "2026-10-01", "record_type": "A", "asn": "AS13335"},
        ],
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_otx_data

    mock_client = AsyncMock()
    mock_client.get.return_value = mock_resp
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = False

    findings = []
    with patch("httpx.AsyncClient", return_value=mock_client):
        pdns_result = await dns_mod._query_passive_dns_otx("example.com", findings)
        
        assert pdns_result["total_records"] == 6
        assert pdns_result["unique_historical_ips"] == 6
        assert len(pdns_result["history"]) == 6
        assert pdns_result["recent_ips"][0] == "6.6.6.6"
        
        # When >= 5 historical IPs exist, a churn finding is generated
        churn_findings = [f for f in findings if "IP Churn" in f.title]
        assert len(churn_findings) == 1
        assert churn_findings[0].severity == FindingSeverity.LOW
        assert churn_findings[0].confidence == FindingConfidence.LIKELY


# =============================================================================
# 4. Certificate Transparency History via crt.sh (SubdomainModule)
# =============================================================================

@pytest.mark.asyncio
async def test_crtsh_certificate_transparency_history_extraction():
    """SubdomainModule extracts historical subdomains, expired certs count, CA issuers, and wildcards from crt.sh."""
    sub_mod = SubdomainModule()
    
    mock_crt_entries = [
        {
            "id": 1001,
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "name_value": "example.com\nwww.example.com",
            "entry_timestamp": "2023-01-01T00:00:00",
            "not_before": "2023-01-01T00:00:00",
            "not_after": "2023-04-01T00:00:00",  # Expired
            "common_name": "example.com",
        },
        {
            "id": 1002,
            "issuer_name": "C=US, O=DigiCert Inc, CN=DigiCert Global Root G2",
            "name_value": "*.example.com\nexample.com\nlegacy-dev.example.com",
            "entry_timestamp": "2024-01-01T00:00:00",
            "not_before": "2024-01-01T00:00:00",
            "not_after": "2027-01-01T00:00:00",  # Active
            "common_name": "*.example.com",
        },
    ]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_crt_entries

    mock_client = AsyncMock()
    mock_client.get.return_value = mock_resp
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = False

    with patch("httpx.AsyncClient", return_value=mock_client):
        subdomains, ct_history = await sub_mod._query_crt_sh("example.com")
        
        # Subdomains extracted
        assert "www.example.com" in subdomains
        assert "legacy-dev.example.com" in subdomains
        
        # CT History metrics
        assert ct_history["total_certificates"] == 2
        assert ct_history["expired_count"] >= 1
        assert "Let's Encrypt" in ct_history["issuers"]
        assert "DigiCert Inc" in ct_history["issuers"]
        assert "*.example.com" in ct_history["wildcards"]
        assert len(ct_history["recent_certs"]) == 2

