# =============================================================================
# FootprintHub — Phase 6 Platform Features Test Suite
# =============================================================================

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.delta_engine import DeltaEngine
from app.core.notification_service import NotificationService
from app.core.executive_summary import ExecutiveSummaryGenerator
from app.core.compliance import ComplianceMapper
from app.core.integrations import IntegrationsService
from app.core.risk_engine import RiskEngine
from app.core.ssrf_guard import SSRFError
from app.core.export import ExportService


class TestDeltaEngine:
    """Tests differential comparison between reconnaissance scans."""

    def test_delta_initial_baseline_when_no_prior_scan(self):
        curr_scan = MagicMock(domain="example.com", risk_score=25)
        curr_results = [
            MagicMock(module_name="subdomains", data={"subdomains": ["api.example.com", "dev.example.com"]}),
            MagicMock(module_name="ports", data={"open_ports": [{"port": 443, "service": "https"}]}),
        ]
        curr_findings = [MagicMock(title="Open Port 443", severity="info", confidence="likely")]

        delta = DeltaEngine.calculate_delta(
            current_scan=curr_scan,
            prior_scan=None,
            current_results=curr_results,
            current_findings=curr_findings,
        )

        assert delta["has_prior_baseline"] is False
        assert delta["posture"] == "baseline"
        assert delta["subdomains"]["total_current"] == 2
        assert "Initial reconnaissance baseline established" in delta["summary"]

    def test_delta_detects_new_subdomains_ports_and_cves(self):
        prior_scan = MagicMock(domain="example.com", risk_score=15)
        prior_results = [
            MagicMock(module_name="subdomains", data={"subdomains": ["api.example.com"]}),
            MagicMock(module_name="ports", data={"open_ports": [{"port": 80, "service": "http"}]}),
        ]
        prior_findings = []

        curr_scan = MagicMock(domain="example.com", risk_score=45)
        curr_results = [
            MagicMock(module_name="subdomains", data={"subdomains": ["api.example.com", "admin.example.com"]}),
            MagicMock(module_name="ports", data={
                "open_ports": [
                    {"port": 80, "service": "http"},
                    {"port": 8443, "service": "https-alt", "cves": [{"id": "CVE-2023-9999", "cisa_kev": True}]},
                ],
                "cves": [{"id": "CVE-2023-9999", "epss": 0.95, "cisa_kev": True}],
            }),
            MagicMock(module_name="lookalike", data={"registered_lookalikes": [{"domain": "examp1e.com"}]}),
        ]
        curr_findings = [
            MagicMock(title="Known Vulnerability Match: CVE-2023-9999", severity="critical", confidence="confirmed")
        ]

        delta = DeltaEngine.calculate_delta(
            current_scan=curr_scan,
            prior_scan=prior_scan,
            current_results=curr_results,
            prior_results=prior_results,
            current_findings=curr_findings,
            prior_findings=prior_findings,
        )

        assert delta["has_prior_baseline"] is True
        assert delta["has_changes"] is True
        assert delta["posture"] == "worsened"
        assert delta["risk_score_delta"] == 30
        assert "admin.example.com" in delta["subdomains"]["added"]
        assert len(delta["ports"]["opened"]) == 1
        assert delta["ports"]["opened"][0]["port"] == 8443
        assert len(delta["vulnerabilities"]["new_cves"]) == 1
        assert delta["vulnerabilities"]["new_cves"][0]["id"] == "CVE-2023-9999"
        assert "examp1e.com" in delta["lookalikes"]["new_registered"]

    def test_delta_certificate_expiry_alert(self):
        curr_scan = MagicMock(domain="example.com", risk_score=10)
        curr_results = [
            MagicMock(module_name="ssl_tls", data={"days_remaining": 5, "not_after": "2026-11-03T00:00:00Z"}),
        ]

        delta = DeltaEngine.calculate_delta(
            current_scan=curr_scan,
            prior_scan=None,
            current_results=curr_results,
        )

        assert delta["certificate_expiry"]["status"] == "critical_expiry"
        assert delta["certificate_expiry"]["alert_level"] == "critical"
        assert delta["certificate_expiry"]["requires_action"] is True


class TestNotificationServiceSSRF:
    """Verifies strict SSRF guards on webhook URLs."""

    def test_webhook_url_blocks_localhost_and_private_ips(self):
        blocked_urls = [
            "http://localhost:8080/webhook",
            "http://127.0.0.1:5000/webhook",
            "http://192.168.1.50/hook",
            "http://10.0.0.1/alert",
            "http://169.254.169.254/latest/meta-data",
            "http://metadata.google.internal/computeMetadata/v1",
        ]

        for url in blocked_urls:
            with pytest.raises(SSRFError):
                NotificationService.validate_webhook_url(url)

    @pytest.mark.asyncio
    async def test_slack_and_generic_webhook_ssrf_protection_return_error(self):
        res1 = await NotificationService.send_slack_alert("http://127.0.0.1:9000/slack", {"domain": "test.com"})
        assert res1["success"] is False
        assert "SSRF blocked" in res1["error"]

        res2 = await NotificationService.send_generic_webhook("http://169.254.169.254/hook", {"test": 1})
        assert res2["success"] is False
        assert "SSRF blocked" in res2["error"]

    def test_smtp_email_simulation_mode(self):
        res = NotificationService.send_smtp_email(
            to_email="security@example.com",
            subject="Test Alert",
            body_text="Test Body",
        )
        assert res["success"] is True
        assert res["recipient"] == "security@example.com"


class TestExecutiveSummaryGenerator:
    """Tests non-technical plain-language executive dossier synthesis."""

    def test_executive_grade_and_top_5_fixes(self):
        scan = MagicMock(domain="enterprise.com", risk_score=85)
        findings = [
            MagicMock(title="Missing DMARC Policy (Spoofable Email)", severity="high", confidence="confirmed", remediation="Configure DMARC reject policy."),
            MagicMock(title="Remote Code Execution Match: CVE-2023-38606", severity="critical", confidence="confirmed", remediation="Patch affected web service."),
            MagicMock(title="Subdomain Takeover on docs.enterprise.com", severity="critical", confidence="confirmed", remediation="Delete dangling CNAME."),
            MagicMock(title="Deprecated TLS 1.0 Enabled", severity="medium", confidence="likely", remediation="Disable TLS 1.0/1.1."),
            MagicMock(title="Open SSH Port 22", severity="low", confidence="likely", remediation="Restrict via security groups."),
            MagicMock(title="Missing Security.txt", severity="info", confidence="likely", remediation="Add security.txt."),
        ]
        results = [
            MagicMock(module_name="subdomains", data={"subdomains": ["api.enterprise.com", "docs.enterprise.com"]}),
            MagicMock(module_name="ports", data={"open_ports": [{"port": 22}, {"port": 443}]}),
            MagicMock(module_name="dns", data={"dmarc_verdict": "Spoofable"}),
        ]

        summary = ExecutiveSummaryGenerator.generate(scan, findings, results)

        assert summary["security_grade"] == "F"
        assert summary["risk_score"] == 85
        assert summary["risk_posture"] == "Critical Risk"
        assert "enterprise.com" in summary["executive_narrative"]
        assert len(summary["top_prioritized_fixes"]) == 5
        # Ensure highest severity/confidence items are at top
        top_titles = [f["title"] for f in summary["top_prioritized_fixes"]]
        assert "Remote Code Execution Match: CVE-2023-38606" in top_titles
        assert "Subdomain Takeover on docs.enterprise.com" in top_titles
        for fix in summary["top_prioritized_fixes"]:
            assert "business_impact" in fix
            assert "remediation_action" in fix


class TestComplianceMapper:
    """Tests mapping of reconnaissance findings to security frameworks."""

    def test_compliance_mapping_rules(self):
        f_dmarc = MagicMock(title="DMARC Policy Not Enforced", module_name="dns", description="Email spoofing risk")
        map_dmarc = ComplianceMapper.map_finding(f_dmarc)
        assert "A07:2021" in map_dmarc["owasp"]
        assert "Control 9" in map_dmarc["cis"]

        f_cve = MagicMock(title="Critical CVE-2024-1234 Vulnerability", module_name="ports", description="Known vulnerability")
        map_cve = ComplianceMapper.map_finding(f_cve)
        assert "A06:2021" in map_cve["owasp"]
        assert "A.8.8" in map_cve["iso"]

        f_tls = MagicMock(title="Deprecated TLS 1.0 Detected", module_name="ssl_tls", description="Weak cipher")
        map_tls = ComplianceMapper.map_finding(f_tls)
        assert "A02:2021" in map_tls["owasp"]
        assert "A.8.24" in map_tls["iso"]

    def test_scan_compliance_evaluation(self):
        findings = [
            MagicMock(title="DMARC Policy Not Enforced", severity="high", confidence="confirmed", module_name="dns", description=""),
            MagicMock(title="Missing Content-Security-Policy Header", severity="low", confidence="likely", module_name="content", description=""),
        ]
        eval_res = ComplianceMapper.evaluate_scan_compliance(findings)
        assert eval_res["total_active_findings"] == 2
        assert eval_res["overall_compliance_score"] <= 100
        assert "OWASP Top 10" in eval_res["frameworks"]
        assert "NIST CSF 2.0" in eval_res["frameworks"]
        assert "ISO 27001:2022" in eval_res["frameworks"]
        assert "CIS Controls v8" in eval_res["frameworks"]


class TestFindingLifecycleWorkflow:
    """Tests finding status workflow, suppression, and risk recalculation."""

    def test_risk_engine_excludes_accepted_risk_and_false_positive(self):
        findings = [
            {"title": "Critical Open DB", "severity": "critical", "confidence": "confirmed", "status": "open"},
            {"title": "Reported Vuln A", "severity": "critical", "confidence": "confirmed", "status": "accepted_risk"},
            {"title": "Reported Vuln B", "severity": "critical", "confidence": "confirmed", "status": "false_positive"},
        ]

        assessment = RiskEngine.calculate_score(findings)
        # Only the 1 open critical finding (weight 25) contributes
        assert assessment.score == 25
        assert assessment.counts["critical"] == 1


class TestIntegrationsAndCLI:
    """Tests issue export formatting and CLI parsing."""

    def test_github_and_jira_payload_generation(self):
        f = MagicMock(
            title="Dangling CNAME Points to AWS S3",
            severity="high",
            confidence="confirmed",
            description="Subdomain takeover potential.",
            evidence="cname -> defunct-bucket.s3.amazonaws.com",
            remediation="Delete DNS record.",
            module_name="subdomains",
        )

        issue_data = IntegrationsService.format_issue_payload(f, domain="target.com", scan_id="test-scan-123")
        assert "[FootprintHub][HIGH]" in issue_data["title"]
        assert "target.com" in issue_data["body"]
        assert "defunct-bucket.s3.amazonaws.com" in issue_data["body"]
        assert "OWASP:" in issue_data["body"]
        assert "NIST CSF:" in issue_data["body"]

    def test_export_pdf_and_csv_support_white_label(self):
        scan = MagicMock(id="scan-xyz", domain="corp.com", profile="passive", risk_score=20, created_at=datetime.now(timezone.utc), completed_at=datetime.now(timezone.utc), status="completed")
        results = [MagicMock(module_name="dns", mode="passive", status="success", duration_seconds=0.5, data={})]
        findings = [MagicMock(id="f1", title="Missing CAA", severity="low", confidence="likely", module_name="dns", description="No CAA record", remediation="Add CAA", status="open", created_at=datetime.now(timezone.utc))]

        white_label = MagicMock(
            company_name="Apex Cyber Defense",
            logo_url=None,
            accent_color="#4f46e5",
            footer_text="Custom Confidentiality Disclaimer",
        )

        pdf_bytes = ExportService.export_pdf(scan, results, findings, white_label=white_label)
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 1000

        csv_str = ExportService.export_csv(findings, scan, results)
        assert "SECTION 2: ALL PRIORITIZED SECURITY FINDINGS" in csv_str
        assert "Status" in csv_str
        assert "OWASP" in csv_str

