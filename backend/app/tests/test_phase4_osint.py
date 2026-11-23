# =============================================================================
# FootprintHub — Phase 4 OSINT & Entity Resolution Unit Test Suite
# =============================================================================
# Verifies zero-contact passive OSINT mode, active surface crawling for socials,
# regional/protocol-relative URL extraction, contact metadata parsing (phones/addresses),
# third-party RDAP resolution, optional HIBP API handling, and curated Google Dorks.
# =============================================================================

import asyncio
import urllib.parse
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from app.modules.base import FindingConfidence, FindingSeverity, ModuleFinding, ModuleMode
from app.modules.osint_helpers import (
    ContactMetadataExtractor,
    RDAPService,
    SocialMediaScraper,
)
from app.modules.osint_module import BehindTheEmailEngine, OSINTModule
from app.core.export import ExportService


# =============================================================================
# 1. Social Media Scraper: Regional Subdomains, Protocol-Relative, WhatsApp & YouTube
# =============================================================================

def test_social_media_scraper_handles_regional_and_relative_urls():
    """Scraper must extract regional subdomains (in.linkedin.com), protocol-relative links,
    WhatsApp numbers, and YouTube handles from raw HTML."""
    html_content = """
    <html>
      <body>
        <div class="footer">
          <a href="https://in.linkedin.com/company/cybervault-in">LinkedIn Profile</a>
          <a href="//www.facebook.com/cybervault.in">Facebook Page</a>
          <a href="https://wa.me/919876543210">WhatsApp Us</a>
          <a href="https://youtube.com/@CyberVaultSec">YouTube Channel</a>
          <a href="https://twitter.com/cybervault_sec">Follow on Twitter</a>
          <a href="https://instagram.com/cybervault_in">Instagram</a>
        </div>
      </body>
    </html>
    """
    profiles = SocialMediaScraper.extract_social_links(html_content)
    assert len(profiles) >= 5

    platforms = {p["platform"] for p in profiles}
    assert "LinkedIn" in platforms
    assert "Facebook" in platforms
    assert "WhatsApp" in platforms
    assert "YouTube" in platforms
    assert "Twitter / X" in platforms or "Twitter" in platforms

    # Check LinkedIn handle extraction from regional subdomain
    linkedin_prof = next(p for p in profiles if p["platform"] == "LinkedIn")
    assert "cybervault-in" in linkedin_prof["handle"]
    assert "in.linkedin.com" in linkedin_prof["url"]

    # Check WhatsApp handle is normalized phone number
    wa_prof = next(p for p in profiles if p["platform"] == "WhatsApp")
    assert "919876543210" in wa_prof["handle"]

    # Check YouTube channel handle
    yt_prof = next(p for p in profiles if p["platform"] == "YouTube")
    assert "CyberVaultSec" in yt_prof["handle"]


# =============================================================================
# 2. Contact Metadata Extractor: Phones and Physical Addresses
# =============================================================================

def test_contact_metadata_extractor_phones_and_addresses():
    """Extractor captures international phone formats, tel: links, <address> tags,
    and Schema.org JSON-LD PostalAddress."""
    html_content = """
    <html>
      <head>
        <script type="application/ld+json">
        {
          "@context": "https://schema.org",
          "@type": "PostalAddress",
          "streetAddress": "Level 4, Cyber Gateway",
          "addressLocality": "Pune",
          "addressRegion": "Maharashtra",
          "postalCode": "411001",
          "addressCountry": "IN"
        }
        </script>
      </head>
      <body>
        <header>
          <a href="tel:+912067890000">Call Us: +91 20 6789 0000</a>
        </header>
        <footer>
          <address>
            CyberVault Security HQ, Infotech Park, Hinjawadi, Pune 411057
          </address>
          <p>Sales: +1 (800) 555-0199</p>
        </footer>
      </body>
    </html>
    """
    # Extract phones
    phones = ContactMetadataExtractor.extract_phone_numbers(html_content)
    assert len(phones) >= 1
    raw_nums = [p["number"] for p in phones]
    assert any("91206789000" in n.replace(" ", "") or "+91" in n for n in raw_nums)

    # Extract addresses
    addresses = ContactMetadataExtractor.extract_physical_addresses(html_content)
    assert len(addresses) >= 1
    # Check that Schema.org or <address> content was parsed
    addr_texts = [str(a) for a in addresses]
    assert any("Pune" in a for a in addr_texts)


# =============================================================================
# 3. Third-Party RDAP Service Parsing
# =============================================================================

@pytest.mark.asyncio
async def test_rdap_service_parsing():
    """RDAP service parses standardized JSON without contacting the target server."""
    mock_rdap_response = {
        "ldhName": "example.com",
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["fn", {}, "text", "GoDaddy.com, LLC"],
                    ]
                ]
            }
        ],
        "events": [
            {"eventAction": "registration", "eventDate": "1997-09-15T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2028-09-13T04:00:00Z"},
        ],
        "status": ["clientTransferProhibited", "clientUpdateProhibited"],
        "nameservers": [{"ldhName": "ns1.example.com"}, {"ldhName": "ns2.example.com"}],
    }

    mock_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_rdap_response
    mock_client.get.return_value = mock_resp

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await RDAPService.query_rdap("example.com")

    assert result["domain"] == "example.com"
    assert result["registrar"] == "GoDaddy.com, LLC"
    assert "1997-09-15" in result["registered_date"]
    assert "2028-09-13" in result["expiration_date"]
    assert "clientTransferProhibited" in result["status"]
    assert "ns1.example.com" in result["nameservers"]


# =============================================================================
# 4. OSINT Passive Profile: 100% Zero Target Contact
# =============================================================================

@pytest.mark.asyncio
async def test_osint_module_passive_profile_zero_target_contact():
    """In passive mode, OSINT module must NEVER make HTTP requests to the target host."""
    module = OSINTModule(profile="passive")
    assert module.profile == "passive"

    mock_rdap_data = {
        "domain": "targetcorp.com",
        "registrar": "NameCheap, Inc.",
        "registered_date": "2015-06-01",
        "expiration_date": "2026-06-01",
        "status": ["ok"],
    }

    with patch.object(RDAPService, "query_rdap", AsyncMock(return_value=mock_rdap_data)), \
         patch("httpx.AsyncClient.get") as mock_http_get:

        res = await module.run("targetcorp.com")

        # Verify module succeeded
        assert res.status == "success"
        assert res.data["is_passive"] is True
        assert res.data["rdap"]["registrar"] == "NameCheap, Inc."

        # Verify Google Dorks were generated
        assert len(res.data["google_dorks"]) >= 8

        # In passive mode, the module should NOT request target host directly
        for call_args in mock_http_get.call_args_list:
            called_url = call_args[0][0] if call_args[0] else ""
            parsed_host = urllib.parse.urlparse(called_url).netloc.lower()
            assert parsed_host != "targetcorp.com" and not parsed_host.endswith(".targetcorp.com")


# =============================================================================
# 5. OSINT Active Profile: Crawls Target & Scrapes Socials & Contacts
# =============================================================================

@pytest.mark.asyncio
async def test_osint_module_active_profile_crawls_and_extracts_socials():
    """In standard/full mode, OSINT module crawls the target homepage and contact pages,
    extracting social profiles and phone numbers with 'Found on page' provenance."""
    module = OSINTModule(profile="active")

    mock_html = """
    <html>
      <body>
        <h1>Welcome to ExampleCorp</h1>
        <p>Contact security at security@examplecorp.com or call +91 99887 76655</p>
        <div class="socials">
          <a href="https://in.linkedin.com/company/examplecorp">LinkedIn</a>
          <a href="https://wa.me/919988776655">WhatsApp Support</a>
        </div>
      </body>
    </html>
    """

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = mock_html

    async def mock_get(url, *args, **kwargs):
        if "rdap.org" in str(url):
            r = MagicMock()
            r.status_code = 200
            r.json.return_value = {"ldhName": "examplecorp.com"}
            return r
        return mock_resp

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        res = await module.run("examplecorp.com")

        assert res.status == "success"
        assert res.data["is_passive"] is False

        # Verify social channels found on page
        socials = res.data["website_social_profiles"]
        assert len(socials) >= 2
        platforms = {s["platform"] for s in socials}
        assert "LinkedIn" in platforms
        assert "WhatsApp" in platforms

        # Verify on-page email has "Found on page" provenance
        email_details = res.data["email_details"]
        assert any(e["email"] == "security@examplecorp.com" and e["source_type"] == "Found on page" for e in email_details)


# =============================================================================
# 6. Optional HIBP Key Handling
# =============================================================================

def test_breach_check_optional_hibp_key():
    """BehindTheEmail engine gracefully handles breach checking with or without HIBP key."""
    engine = BehindTheEmailEngine()

    # When no key is set, check_breaches returns gracefully with simulated/clean result
    with patch("app.config.settings.HIBP_API_KEY", None):
        result = engine.check_breaches("testuser@example.com")
        assert isinstance(result, dict)
        assert "pwned" in result
        assert "breaches" in result


# =============================================================================
# 7. Google Dorks Generation: 8 High-Value Categories
# =============================================================================

@pytest.mark.asyncio
async def test_google_dorks_generated_categories():
    """Module must generate 8 categories of curated clickable search engine dorks."""
    module = OSINTModule(profile="passive")
    with patch.object(RDAPService, "query_rdap", AsyncMock(return_value={})):
        res = await module.run("example.com")

    dorks = res.data["google_dorks"]
    assert len(dorks) >= 8

    categories = [d["category"] for d in dorks]
    assert any("Employee" in c or "Executive" in c for c in categories)
    assert any("Social Media" in c for c in categories)
    assert any("Exposed Documents" in c for c in categories)
    assert any("Admin" in c or "Login" in c for c in categories)
    assert any("Directory" in c for c in categories)
    assert any("Configuration" in c or "Backup" in c for c in categories)
    assert any("Confidential" in c for c in categories)
    assert any("GitHub" in c for c in categories)

    for d in dorks:
        assert "dork" in d
        assert "url" in d
        assert d["url"].startswith("https://")


# =============================================================================
# 8. CSV & PDF Export Integration for OSINT Entity Resolution
# =============================================================================

def test_export_csv_and_pdf_osint_sections():
    """ExportService CSV and PDF outputs must include OSINT Entity Resolution,
    Registrar info, Social Channels, and Email Provenance."""
    mock_scan = MagicMock()
    mock_scan.id = "scan-osint-test"
    mock_scan.domain = "testentity.com"
    mock_scan.profile = "standard"
    mock_scan.status = "completed"
    mock_scan.risk_score = 15

    mock_osint_result = MagicMock()
    mock_osint_result.module_name = "osint"
    mock_osint_result.mode = "active"
    mock_osint_result.status = "success"
    mock_osint_result.duration_seconds = 1.25
    mock_osint_result.data = {
        "company_name": "Test Entity Technologies",
        "entity_resolution": {
            "company_name": "Test Entity Technologies",
            "registrar": "MarkMonitor Inc.",
            "registered_date": "2010-01-15",
            "expiration_date": "2029-01-15",
        },
        "rdap": {
            "registrar": "MarkMonitor Inc.",
            "registered_date": "2010-01-15",
            "expiration_date": "2029-01-15",
        },
        "phone_numbers": [{"number": "+91 20 12345678", "context": "Website"}],
        "physical_addresses": ["Tech Boulevard, Bangalore 560001, India"],
        "website_social_profiles": [
            {"platform": "LinkedIn", "handle": "test-entity", "url": "https://in.linkedin.com/company/test-entity", "type": "Corporate"}
        ],
        "email_details": [
            {"email": "contact@testentity.com", "source_type": "Found on page", "source_url": "https://testentity.com/contact"}
        ],
        "emails": ["contact@testentity.com"],
        "google_dorks": [
            {"category": "Exposed Documents", "dork": "site:testentity.com filetype:pdf"}
        ],
    }

    # CSV Export Check
    csv_out = ExportService.export_csv(findings=[], scan=mock_scan, results=[mock_osint_result])
    assert "[SECTION 12: OSINT INTELLIGENCE & ENTITY RESOLUTION]" in csv_out
    assert "MarkMonitor Inc." in csv_out
    assert "+91 20 12345678" in csv_out
    assert "Found on page" in csv_out
    assert "Social Channel (Linkedin)" in csv_out or "Social Channel (LinkedIn)" in csv_out

    # PDF Export Check
    pdf_bytes = ExportService.export_pdf(scan=mock_scan, results=[mock_osint_result], findings=[])
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF")
