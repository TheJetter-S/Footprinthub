# =============================================================================
# FootprintHub — Core Unit Test Suite (Standard Library Unittest)
# =============================================================================

import sys
from pathlib import Path
import unittest

# Ensure backend root is on sys.path
backend_path = Path(__file__).resolve().parent.parent.parent
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

from app.core.ssrf_guard import (
    is_ip_blocked,
    is_hostname_blocked,
    validate_domain,
    validate_url,
    SSRFError,
)
from app.core.risk_engine import RiskEngine


class TestSSRFGuard(unittest.TestCase):
    """Test SSRF validation rules against internal/cloud IPs and metadata."""

    def test_private_ipv4_blocked(self):
        blocked_ips = [
            "127.0.0.1",
            "127.0.0.2",
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.1.100",
            "169.254.169.254",  # AWS metadata
            "0.0.0.0",
        ]
        for ip in blocked_ips:
            with self.subTest(ip=ip):
                self.assertTrue(is_ip_blocked(ip), f"Expected {ip} to be blocked")

    def test_public_ips_allowed(self):
        allowed_ips = [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "142.250.185.14",
        ]
        for ip in allowed_ips:
            with self.subTest(ip=ip):
                self.assertFalse(is_ip_blocked(ip), f"Expected {ip} to be allowed")

    def test_blocked_hostnames(self):
        blocked_hosts = [
            "localhost",
            "localhost.localdomain",
            "127.0.0.1",
            "::1",
            "metadata.google.internal",
            "instance-data",
        ]
        for host in blocked_hosts:
            with self.subTest(host=host):
                self.assertTrue(is_hostname_blocked(host), f"Expected {host} to be blocked")

    def test_domain_validation_valid(self):
        valid_cases = [
            ("example.com", "example.com"),
            ("sub.example.com", "sub.example.com"),
            ("my-domain.co.uk", "my-domain.co.uk"),
            ("target.org", "target.org"),
            ("http://example.com", "example.com"),
            ("https://example.com/some/path", "example.com"),
        ]
        for input_val, expected in valid_cases:
            with self.subTest(domain=input_val):
                self.assertEqual(validate_domain(input_val), expected)

    def test_domain_validation_invalid(self):
        invalid = [
            "",
            "   ",
            "-leading-dash.com",
            "no_tld",
            "a" * 256 + ".com",
            "127.0.0.1",
            "192.168.1.1",
        ]
        for d in invalid:
            with self.subTest(domain=d):
                with self.assertRaises(SSRFError):
                    validate_domain(d)


class TestRiskEngine(unittest.TestCase):
    """Test risk scoring engine calculations and severity weights."""

    def test_empty_findings_returns_zero(self):
        assessment = RiskEngine.calculate_score([])
        self.assertEqual(assessment.score, 0)
        self.assertEqual(assessment.grade, "A")
        self.assertEqual(assessment.level, "low")

    def test_critical_and_high_scoring(self):
        findings = [
            {"severity": "critical", "title": "Critical Issue 1", "description": "Desc"},
            {"severity": "critical", "title": "Critical Issue 2", "description": "Desc"},
            {"severity": "high", "title": "High Issue 1", "description": "Desc"},
        ]
        # 2 critical = 50 (capped at 50), 1 high = 10 -> Total 60 (High Risk)
        assessment = RiskEngine.calculate_score(findings)
        self.assertEqual(assessment.score, 60)
        self.assertEqual(assessment.level, "high")
        self.assertEqual(assessment.grade, "D")

    def test_score_capped_at_100(self):
        # Even with many findings, score never exceeds 100
        findings = [
            {"severity": "critical", "title": f"Crit {i}", "description": ""}
            for i in range(5)
        ] + [
            {"severity": "high", "title": f"High {i}", "description": ""}
            for i in range(5)
        ] + [
            {"severity": "medium", "title": f"Med {i}", "description": ""}
            for i in range(5)
        ]
        assessment = RiskEngine.calculate_score(findings)
        self.assertLessEqual(assessment.score, 100)
        self.assertEqual(assessment.grade, "F")
        self.assertEqual(assessment.level, "critical")


if __name__ == "__main__":
    unittest.main()
