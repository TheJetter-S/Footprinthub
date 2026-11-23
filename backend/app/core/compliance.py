# =============================================================================
# FootprintHub — Security Compliance Mapping Framework
# =============================================================================
# Automatically maps discovered reconnaissance findings and security posture to:
# - OWASP Top 10 (2021)
# - NIST Cybersecurity Framework 2.0 (NIST CSF)
# - ISO/IEC 27001:2022 Controls
# - CIS Controls v8
# =============================================================================

from typing import Any, Optional


class ComplianceMapper:
    """
    Tags security findings with multi-framework regulatory and governance controls.
    """

    FRAMEWORKS = ["OWASP Top 10", "NIST CSF 2.0", "ISO 27001:2022", "CIS Controls v8"]

    # Rule-based heuristics matching finding attributes to controls
    RULES = [
        {
            "id": "email_spoofing",
            "keywords": ["dmarc", "spf", "dkim", "bimi", "spoof", "mta-sts"],
            "owasp": "A07:2021 - Identification and Authentication Failures",
            "nist": "PR.AC-05 (Network & Identity Protections)",
            "iso": "A.8.20 (Network Security) / A.5.15 (Access Control)",
            "cis": "Control 9 (Email and Web Browser Protections)",
        },
        {
            "id": "tls_crypto",
            "keywords": ["tls", "ssl", "cipher", "hsts", "certificate", "https", "beast", "poodle", "sha-1"],
            "owasp": "A02:2021 - Cryptographic Failures",
            "nist": "PR.DS-01 (Data-in-Transit Cryptographic Protections)",
            "iso": "A.8.24 (Use of Cryptography)",
            "cis": "Control 4 (Secure Configuration of Enterprise Assets)",
        },
        {
            "id": "known_vulnerability",
            "keywords": ["cve-", "unpatched", "outdated", "vulnerability", "exploit", "cisa"],
            "owasp": "A06:2021 - Vulnerable and Outdated Components",
            "nist": "PR.PS-02 (Software Maintenance & Vulnerability Remediation)",
            "iso": "A.8.8 (Management of Technical Vulnerabilities)",
            "cis": "Control 7 (Continuous Vulnerability Management)",
        },
        {
            "id": "subdomain_takeover",
            "keywords": ["takeover", "dangling cname", "abandoned", "unclaimed"],
            "owasp": "A01:2021 - Broken Access Control",
            "nist": "ID.AM-01 (Asset Identification & Control)",
            "iso": "A.8.9 (Configuration Management)",
            "cis": "Control 4 (Secure Configuration of Enterprise Assets)",
        },
        {
            "id": "headers_and_config",
            "keywords": ["header", "content-security-policy", "x-frame-options", "caa", "security.txt", "dnssec"],
            "owasp": "A05:2021 - Security Misconfiguration",
            "nist": "PR.PS-01 (Platform & Configuration Hardening)",
            "iso": "A.8.9 (Configuration Management)",
            "cis": "Control 4 (Secure Configuration of Enterprise Assets)",
        },
        {
            "id": "open_ports_network",
            "keywords": ["open port", "telnet", "ftp", "smb", "rdp", "database port", "ports"],
            "owasp": "A05:2021 - Security Misconfiguration",
            "nist": "PR.AC-05 (Network Perimeter Interface Controls)",
            "iso": "A.8.20 (Network Security)",
            "cis": "Control 12 (Network Infrastructure Management)",
        },
        {
            "id": "script_integrity_trackers",
            "keywords": ["sri", "subresource integrity", "tracker", "cookie", "script"],
            "owasp": "A08:2021 - Software and Data Integrity Failures",
            "nist": "PR.DS-01 (Data Protection & Integrity)",
            "iso": "A.8.26 (Application Security Requirements)",
            "cis": "Control 9 (Email and Web Browser Protections)",
        },
        {
            "id": "credentials_and_secrets",
            "keywords": ["secret", "leak", "api key", "token", "password", "aws_key"],
            "owasp": "A01:2021 - Broken Access Control",
            "nist": "PR.AC-01 (Credential & Identity Management)",
            "iso": "A.8.24 (Use of Cryptography) / A.5.15 (Access Control)",
            "cis": "Control 6 (Access Control Management)",
        },
        {
            "id": "brand_and_reputation",
            "keywords": ["lookalike", "typosquat", "blacklist", "malicious", "reputation", "phishing"],
            "owasp": "A07:2021 - Identification and Authentication Failures",
            "nist": "DE.CM-01 (Continuous External Threat Monitoring)",
            "iso": "A.8.20 (Network Security) / A.8.8 (Vulnerability Management)",
            "cis": "Control 7 (Continuous Vulnerability Management)",
        },
    ]

    # Default fallback
    DEFAULT_MAPPING = {
        "owasp": "A05:2021 - Security Misconfiguration",
        "nist": "PR.PS-01 (Configuration Hardening)",
        "iso": "A.8.9 (Configuration Management)",
        "cis": "Control 4 (Secure Configuration)",
    }

    @classmethod
    def map_finding(cls, finding: Any) -> dict[str, str]:
        """
        Map an individual finding to regulatory controls based on title, module, and description.
        """
        title = getattr(finding, "title", finding.get("title") if isinstance(finding, dict) else "") or ""
        module = getattr(finding, "module_name", finding.get("module_name") if isinstance(finding, dict) else "") or ""
        desc = getattr(finding, "description", finding.get("description") if isinstance(finding, dict) else "") or ""

        search_text = f"{title} {module} {desc}".lower()

        for rule in cls.RULES:
            for kw in rule["keywords"]:
                if kw in search_text:
                    return {
                        "owasp": rule["owasp"],
                        "nist": rule["nist"],
                        "iso": rule["iso"],
                        "cis": rule["cis"],
                    }

        return cls.DEFAULT_MAPPING.copy()

    @classmethod
    def evaluate_scan_compliance(cls, findings: list[Any]) -> dict[str, Any]:
        """
        Aggregate compliance mappings across all active findings in a scan.
        """
        framework_tallies = {
            "OWASP Top 10": {},
            "NIST CSF 2.0": {},
            "ISO 27001:2022": {},
            "CIS Controls v8": {},
        }
        framework_findings: dict[str, dict[str, list[dict[str, Any]]]] = {
            "OWASP Top 10": {},
            "NIST CSF 2.0": {},
            "ISO 27001:2022": {},
            "CIS Controls v8": {},
        }

        tagged_findings = []

        for f in findings:
            # Skip accepted risks and false positives
            stat = getattr(f, "status", None)
            if stat is None and isinstance(f, dict):
                stat = f.get("status")
            if stat in ("accepted_risk", "false_positive"):
                continue

            mapping = cls.map_finding(f)

            f_dict = {
                "id": str(getattr(f, "id", f.get("id") if isinstance(f, dict) else "")),
                "title": getattr(f, "title", f.get("title") if isinstance(f, dict) else ""),
                "description": getattr(f, "description", f.get("description") if isinstance(f, dict) else ""),
                "remediation": getattr(f, "remediation", f.get("remediation") if isinstance(f, dict) else ""),
                "evidence": getattr(f, "evidence", f.get("evidence") if isinstance(f, dict) else ""),
                "module_name": getattr(f, "module_name", f.get("module_name") if isinstance(f, dict) else ""),
                "severity": getattr(f, "severity", f.get("severity") if isinstance(f, dict) else "info"),
                "confidence": getattr(f, "confidence", f.get("confidence") if isinstance(f, dict) else "likely"),
                "compliance": mapping,
            }
            tagged_findings.append(f_dict)

            # Record tallies
            framework_tallies["OWASP Top 10"][mapping["owasp"]] = (
                framework_tallies["OWASP Top 10"].get(mapping["owasp"], 0) + 1
            )
            framework_tallies["NIST CSF 2.0"][mapping["nist"]] = (
                framework_tallies["NIST CSF 2.0"].get(mapping["nist"], 0) + 1
            )
            framework_tallies["ISO 27001:2022"][mapping["iso"]] = (
                framework_tallies["ISO 27001:2022"].get(mapping["iso"], 0) + 1
            )
            framework_tallies["CIS Controls v8"][mapping["cis"]] = (
                framework_tallies["CIS Controls v8"].get(mapping["cis"], 0) + 1
            )

            # Record detailed findings per control
            for fw_name, map_key in [
                ("OWASP Top 10", "owasp"),
                ("NIST CSF 2.0", "nist"),
                ("ISO 27001:2022", "iso"),
                ("CIS Controls v8", "cis"),
            ]:
                ctrl = mapping[map_key]
                if ctrl not in framework_findings[fw_name]:
                    framework_findings[fw_name][ctrl] = []
                framework_findings[fw_name][ctrl].append(f_dict)

        # Calculate high-level compliance posture
        total_active_defects = len(tagged_findings)
        compliance_pct = max(0, 100 - (total_active_defects * 4))

        return {
            "overall_compliance_score": compliance_pct,
            "total_active_findings": total_active_defects,
            "frameworks": framework_tallies,
            "framework_findings": framework_findings,
            "findings_compliance_list": tagged_findings,
        }

