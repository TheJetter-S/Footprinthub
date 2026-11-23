# =============================================================================
# FootprintHub — Phase 5 Brand Protection & Leaks Unit Test Suite
# =============================================================================
# Verifies lookalike domain permutation generator (typos, homoglyphs, TLD swaps,
# bit-flips, hyphenation), DNS & MX phishing detection, recent registration audits,
# official code/package leak engines, strict secret pattern masking, domain ownership
# verification for HIBP, and third-party tracker/SRI auditing.
# =============================================================================

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from app.modules.base import FindingConfidence, FindingSeverity, ModuleFinding, ModuleMode
from app.modules.lookalike_module import (
    LookalikeGenerator,
    LookalikeModule,
)
from app.modules.osint_helpers import (
    CodeLeakEngine,
    DomainOwnershipVerifier,
    RDAPService,
    SecretPatternScanner,
)
from app.modules.content_module import ContentModule
from app.core.export import ExportService


# =============================================================================
# 1. Lookalike Permutation Generator
# =============================================================================

def test_lookalike_generator_permutations():
    """Generator must produce typos, homoglyphs (IDN), TLD swaps, hyphenation,
    and bit-flips for the target domain."""
    domain = "cybervault.in"
    candidates = LookalikeGenerator.generate(domain, max_candidates=50)

    assert len(candidates) >= 20
    candidate_types = {c["type"] for c in candidates}
    candidate_domains = [c["domain"] for c in candidates]

    # Verify presence of multiple squatting vectors
    assert "TLD Swap" in candidate_types
    assert any("Typo" in t for t in candidate_types) or "Omission" in candidate_types or "Transposition" in candidate_types
    assert "Hyphenation" in candidate_types or any("Hyphenation" in t for t in candidate_types)

    # Verify TLD swap domains
    assert any(d.endswith(".com") for d in candidate_domains)
    assert any(d.endswith(".org") or d.endswith(".net") or d.endswith(".co") for d in candidate_domains)

    # All generated domains must be distinct from original
    assert domain not in candidate_domains


# =============================================================================
# 2. Lookalike Module: DNS, MX Phishing Readiness & Recent Registration
# =============================================================================

@pytest.mark.asyncio
async def test_lookalike_module_passive_resolution_and_mx_flags():
    """Lookalike module checks DNS resolution, flags domains with MX (phishing capable),
    and flags recently registered lookalikes (< 30 days)."""
    module = LookalikeModule()
    assert module.mode == ModuleMode.PASSIVE

    mock_candidates = [
        {"domain": "cybervaullt.in", "type": "Repetition"},
        {"domain": "cybervault.com", "type": "TLD Swap"},
        {"domain": "cyber-vault.in", "type": "Hyphenation"},
    ]

    async def mock_rdap(d, *args, **kwargs):
        if d == "cybervault.com":
            return {"registered_date": "2026-10-15T00:00:00Z", "domain": d}
        return {"registered_date": "2018-01-01T00:00:00Z", "domain": d}

    with patch.object(LookalikeGenerator, "generate", return_value=mock_candidates), \
         patch("app.modules.lookalike_module.HAS_DNS", False), \
         patch("asyncio.get_event_loop") as mock_loop_fn, \
         patch.object(RDAPService, "query_rdap", side_effect=mock_rdap):

        mock_loop = MagicMock()

        async def mock_getaddrinfo(host, port):
            if host in ["cybervaullt.in", "cybervault.com"]:
                return [(2, 1, 6, "", ("198.51.100.25", 0))]
            raise OSError("Name or service not known")

        mock_loop.getaddrinfo = AsyncMock(side_effect=mock_getaddrinfo)
        mock_loop_fn.return_value = mock_loop

        res = await module.run("cybervault.in")

        assert res.status == "success"
        assert res.data["total_registered_lookalikes"] >= 1
        live_list = res.data["live_lookalikes"]
        live_domains = [l["domain"] for l in live_list]
        assert "cybervaullt.in" in live_domains or "cybervault.com" in live_domains

        # Look for active lookalike finding
        assert len(res.findings) >= 1
        titles = [f.title for f in res.findings]
        assert any("Lookalike" in t for t in titles)


# =============================================================================
# 3. Secret Pattern Scanner: Strict Value Masking
# =============================================================================

def test_secret_pattern_scanner_masks_secrets():
    """SecretPatternScanner identifies tokens, keys, and credentials, but NEVER
    stores or exposes the raw secret value in output."""
    mock_slack_token = "xoxb" + "-1234567890-1234567890123-abcdefghijklmnopqrstuvwx"
    raw_content = f"""
    # Exposed server configuration
    AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE
    AWS_SECRET_ACCESS_KEY = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    GITHUB_TOKEN = ghp_123456789012345678901234567890123456
    SLACK_BOT_TOKEN = {mock_slack_token}
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEA0Y123456789abcdef...
    -----END RSA PRIVATE KEY-----
    """
    findings = SecretPatternScanner.scan_content(raw_content, "https://github.com/org/repo/blob/main/.env")

    assert len(findings) >= 4
    secret_types = {f["secret_type"] for f in findings}
    assert "AWS Access Key ID" in secret_types
    assert "GitHub Personal Access Token" in secret_types
    assert "Slack Token" in secret_types
    assert "Private Cryptographic Key" in secret_types

    # CRITICAL SECURITY CHECK: Raw secret strings must NOT exist in findings
    for f in findings:
        masked = f["masked_value"]
        assert "AKIAIOSFODNN7EXAMPLE" not in masked
        assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in masked
        assert "ghp_123456789012345678901234567890123456" not in masked
        assert mock_slack_token not in masked
        # Check that proper mask patterns were applied
        assert "*" in masked or "MASKED" in masked


# =============================================================================
# 4. Code Leak Engine: Official APIs (GitHub, GitLab, Docker, npm, PyPI)
# =============================================================================

@pytest.mark.asyncio
async def test_code_leak_engine_queries():
    """CodeLeakEngine queries official public endpoints and aggregates repos and packages."""
    mock_client = AsyncMock()

    async def mock_get(url, *args, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        url_str = str(url)
        if "api.github.com" in url_str:
            resp.json.return_value = {
                "items": [
                    {
                        "full_name": "targetcorp/internal-tooling",
                        "html_url": "https://github.com/targetcorp/internal-tooling",
                        "description": "Internal scripts. Contains AKIAIOSFODNN7EXAMPLE test key",
                        "stargazers_count": 5,
                        "updated_at": "2026-09-01T00:00:00Z",
                    }
                ]
            }
        elif "gitlab.com" in url_str:
            resp.json.return_value = [
                {
                    "name": "targetcorp/deployment",
                    "web_url": "https://gitlab.com/targetcorp/deployment",
                    "description": "GitLab CI manifests",
                    "star_count": 2,
                }
            ]
        elif "hub.docker.com" in url_str:
            resp.json.return_value = {
                "results": [
                    {
                        "repo_name": "targetcorp/app-worker",
                        "short_description": "Production worker container",
                        "pull_count": 1200,
                    }
                ]
            }
        elif "registry.npmjs.org" in url_str:
            resp.json.return_value = {
                "objects": [
                    {
                        "package": {
                            "name": "@targetcorp/sdk",
                            "version": "1.0.4",
                            "description": "Official JS SDK",
                        }
                    }
                ]
            }
        elif "pypi.org" in url_str:
            resp.json.return_value = {
                "info": {
                    "name": "targetcorp-client",
                    "version": "0.2.1",
                    "summary": "TargetCorp Python client",
                    "package_url": "https://pypi.org/project/targetcorp-client/",
                }
            }
        return resp

    mock_client.get = AsyncMock(side_effect=mock_get)

    result = await CodeLeakEngine.search_leaks("targetcorp.com", company_name="TargetCorp", client=mock_client)

    assert len(result["github_repos"]) == 1
    assert len(result["gitlab_projects"]) == 1
    assert len(result["docker_hub_images"]) == 1
    assert len(result["npm_packages"]) == 1
    assert len(result["pypi_packages"]) == 1
    assert len(result["postman_workspaces"]) == 1

    # Verify secret detected in GitHub repo description was masked
    assert len(result["detected_secrets"]) >= 1
    assert any("AWS" in s["secret_type"] for s in result["detected_secrets"])
    assert all("*" in s["masked_value"] for s in result["detected_secrets"])


# =============================================================================
# 5. Domain Ownership Verifier for HIBP
# =============================================================================

@pytest.mark.asyncio
async def test_domain_ownership_verifier_unverified_and_verified():
    """Domain search requires verified ownership via DNS TXT or /.well-known file."""
    mock_client = AsyncMock()

    # Case 1: Unverified domain (no DNS TXT, 404 HTTP file)
    resp_404 = MagicMock()
    resp_404.status_code = 404
    resp_404.text = "Not Found"
    mock_client.get.return_value = resp_404

    with patch("app.modules.osint_helpers.HAS_DNS", False):
        verified, reason = await DomainOwnershipVerifier.verify_ownership("unverified.com", client=mock_client)
        assert verified is False
        assert "unverified" in reason.lower()

    # Case 2: Verified domain via /.well-known HTTP file
    resp_200 = MagicMock()
    resp_200.status_code = 200
    resp_200.text = "footprinthub-verification=auth-token-12345"
    mock_client.get.return_value = resp_200

    verified, reason = await DomainOwnershipVerifier.verify_ownership("verifiedcorp.com", client=mock_client)
    assert verified is True
    assert "verified via http" in reason.lower()


# =============================================================================
# 6. Content Module: External Scripts, Missing SRI & Trackers
# =============================================================================

@pytest.mark.asyncio
async def test_content_module_external_scripts_sri_and_cookies():
    """ContentModule inventories external scripts, audits Subresource Integrity (SRI)
    on CDN resources, and catalogs tracking beacons and response cookies."""
    module = ContentModule()

    html_content = """
    <html>
      <head>
        <!-- Unprotected CDN Script (Missing SRI) -->
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
        <!-- Protected CDN Script (Has SRI) -->
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"
                integrity="sha384-ka7Sk0Gln4gmtz2MlQnikT1wXgYsOg+OMhuP+IlRH9sENBO0LRn5q+8nbTov4+1p"
                crossorigin="anonymous"></script>
        <!-- Tracker script -->
        <script src="https://www.google-analytics.com/analytics.js"></script>
      </head>
      <body>
        <h1>Content Test</h1>
      </body>
    </html>
    """

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = html_content
    mock_resp.cookies.jar = []

    # Mock cookie in jar
    cookie_mock = MagicMock()
    cookie_mock.name = "session_id"
    cookie_mock.secure = True
    cookie_mock.has_nonstandard_attr = lambda a: True
    mock_resp.cookies.jar.append(cookie_mock)

    async def mock_get(url, *args, **kwargs):
        return mock_resp

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        res = await module.run("example.com")

        assert res.status == "success"
        data = res.data

        # Verify scripts captured
        assert len(data["external_scripts"]) >= 2
        assert len(data["cdn_scripts"]) >= 2
        assert len(data["missing_sri_scripts"]) == 1
        assert "cdnjs.cloudflare.com" in data["missing_sri_scripts"][0]

        # Verify tracker captured
        assert "Google Analytics" in data["trackers"]

        # Verify SRI finding generated
        sri_findings = [f for f in res.findings if "Subresource Integrity" in f.title]
        assert len(sri_findings) == 1
        assert sri_findings[0].severity == FindingSeverity.LOW
        assert sri_findings[0].confidence == FindingConfidence.CONFIRMED


# =============================================================================
# 7. Relationship Graph: Multi-hop Correlation & Threat Nodes
# =============================================================================

@pytest.mark.asyncio
async def test_relationship_graph_links_lookalikes_ports_and_repos():
    """Relationship graph maps Domain -> Lookalikes (threats) -> Ports -> Repos."""
    from app.api.history import get_relationship_graph

    mock_db = AsyncMock()
    mock_scan = MagicMock()
    mock_scan.id = "scan-graph-123"
    mock_scan.domain = "testgraph.com"
    mock_scan.user_id = "user-123"

    mock_scan_res = MagicMock()
    mock_scan_res.scalar_one_or_none.return_value = mock_scan

    mock_res_port = MagicMock()
    mock_res_port.module_name = "ports"
    mock_res_port.data = {"ports": [{"port": 443, "service": "https"}]}

    mock_res_lk = MagicMock()
    mock_res_lk.module_name = "lookalike"
    mock_res_lk.data = {
        "live_lookalikes": [
            {"domain": "testgraph-phish.com", "has_mx": True, "type": "Hyphenation"}
        ]
    }

    mock_res_osint = MagicMock()
    mock_res_osint.module_name = "osint"
    mock_res_osint.data = {
        "code_leaks": {
            "github_repos": [{"name": "testgraph/api", "url": "https://github.com/testgraph/api"}]
        }
    }

    mock_results_query = MagicMock()
    mock_results_query.scalars().all.return_value = [mock_res_port, mock_res_lk, mock_res_osint]

    mock_db.execute.side_effect = [mock_scan_res, mock_results_query]

    graph = await get_relationship_graph("scan-graph-123", db=mock_db, current_user=MagicMock(id="user-123"))

    assert "nodes" in graph
    assert "edges" in graph
    node_types = {n["type"] for n in graph["nodes"]}
    assert "target" in node_types
    assert "port" in node_types
    assert "threat" in node_types
    assert "code" in node_types

    threat_node = next(n for n in graph["nodes"] if n["type"] == "threat")
    assert "Phishing Lookalike" in threat_node["data"]["category"]


# =============================================================================
# 8. CSV & PDF Export Integration for Phase 5 Data
# =============================================================================

def test_export_csv_and_pdf_phase5_sections():
    """CSV and PDF exports include Brand Protection (lookalikes), Code Leaks,
    and Third-Party Scripts/SRI."""
    mock_scan = MagicMock()
    mock_scan.id = "scan-p5-export"
    mock_scan.domain = "exportp5.com"
    mock_scan.profile = "standard"
    mock_scan.status = "completed"
    mock_scan.risk_score = 30

    mock_content_result = MagicMock()
    mock_content_result.module_name = "content"
    mock_content_result.mode = "active"
    mock_content_result.status = "success"
    mock_content_result.duration_seconds = 0.85
    mock_content_result.data = {
        "external_scripts": ["https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"],
        "cdn_scripts": [{"src": "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js", "host": "cdnjs.cloudflare.com", "has_sri": False}],
        "missing_sri_scripts": ["https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"],
        "trackers": ["Google Analytics"],
        "cookies": [{"name": "_ga", "secure": True, "httponly": False}],
    }

    mock_lookalike_result = MagicMock()
    mock_lookalike_result.module_name = "lookalike"
    mock_lookalike_result.mode = "passive"
    mock_lookalike_result.status = "success"
    mock_lookalike_result.duration_seconds = 1.10
    mock_lookalike_result.data = {
        "total_permutations_tested": 35,
        "live_lookalikes": [
            {
                "domain": "exportp5-security.com",
                "type": "Hyphenation",
                "ips": ["198.51.100.42"],
                "has_mx": True,
                "is_recently_registered": True,
                "age_days": 12,
                "registered_date": "2026-10-17",
            }
        ]
    }

    mock_osint_result = MagicMock()
    mock_osint_result.module_name = "osint"
    mock_osint_result.mode = "active"
    mock_osint_result.status = "success"
    mock_osint_result.duration_seconds = 1.45
    mock_osint_result.data = {
        "code_leaks": {
            "github_repos": [{"name": "exportp5/infra", "url": "https://github.com/exportp5/infra"}],
            "detected_secrets": [{"secret_type": "AWS Access Key ID", "location": "repo/config", "masked_value": "AKIA****************"}],
        }
    }

    # CSV Verification
    csv_out = ExportService.export_csv(
        findings=[],
        scan=mock_scan,
        results=[mock_content_result, mock_lookalike_result, mock_osint_result]
    )
    assert "[SECTION 15: BRAND PROTECTION & LOOKALIKE DOMAINS]" in csv_out
    assert "exportp5-security.com" in csv_out
    assert "ACTIVE MX (Phishing Capable)" in csv_out
    assert "MISSING SRI" in csv_out
    assert "AKIA****************" in csv_out

    # PDF Verification
    pdf_bytes = ExportService.export_pdf(
        scan=mock_scan,
        results=[mock_content_result, mock_lookalike_result, mock_osint_result],
        findings=[]
    )
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF")

