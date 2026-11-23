# =============================================================================
# FootprintHub — Executive Summary Dossier Generator
# =============================================================================
# Generates a non-technical, plain-language executive briefing:
# - Letter Grade (A, B, C, D, F) and risk posture
# - Single-paragraph non-technical executive narrative (no jargon)
# - Top 5 prioritized remediation actions with business impact
# - Severity distribution breakdown
# - Core perimeter KPI metrics
# =============================================================================

from typing import Any, Optional


class ExecutiveSummaryGenerator:
    """
    Synthesizes technical reconnaissance telemetry into an executive dossier.
    """

    GRADE_TIERS = [
        (15, "A", "Low Risk", "Robust perimeter defenses observed with negligible external exposure."),
        (35, "B", "Moderate Risk", "Acceptable baseline posture with minor hygiene issues detected."),
        (60, "C", "Elevated Risk", "Noticeable security exposures that increase susceptibility to targeted reconnaissance."),
        (80, "D", "High Risk", "Significant vulnerabilities and exposed attack surfaces requiring immediate remediation."),
        (100, "F", "Critical Risk", "Severe security defects and high-impact exposures that leave assets vulnerable to compromise."),
    ]

    SEV_WEIGHTS = {
        "critical": 1000,
        "high": 100,
        "medium": 20,
        "low": 5,
        "info": 1,
    }

    CONF_WEIGHTS = {
        "confirmed": 1.2,
        "likely": 1.0,
        "possible": 0.7,
    }

    @classmethod
    def generate(
        cls,
        scan: Any,
        findings: Optional[list[Any]] = None,
        results: Optional[list[Any]] = None,
    ) -> dict[str, Any]:
        """
        Generate executive summary dictionary.
        """
        domain = getattr(scan, "domain", None)
        score = getattr(scan, "risk_score", None)
        if domain is None and isinstance(scan, dict):
            domain = scan.get("domain", "target-organization.com")
            score = scan.get("risk_score", 0)
        domain = domain or "target-organization.com"
        score = score if score is not None else 0

        # Determine letter grade
        grade = "F"
        posture_label = "Critical Risk"
        posture_desc = ""
        for threshold, g, label, desc in cls.GRADE_TIERS:
            if score <= threshold:
                grade = g
                posture_label = label
                posture_desc = desc
                break

        # Extract findings
        findings_list = findings
        if findings_list is None:
            f = getattr(scan, "findings", None)
            if f is not None:
                findings_list = list(f)
            elif isinstance(scan, dict):
                findings_list = scan.get("findings", [])
            else:
                findings_list = []

        # Extract results
        results_map = {}
        target_results = results
        if target_results is None:
            r = getattr(scan, "results", None)
            if r is not None:
                target_results = list(r)
            elif isinstance(scan, dict):
                target_results = scan.get("results", [])

        if target_results:
            for item in target_results:
                m_name = getattr(item, "module_name", None)
                data = getattr(item, "data", None)
                if m_name is None and isinstance(item, dict):
                    m_name = item.get("module_name")
                    data = item.get("data")
                if m_name and isinstance(data, dict):
                    results_map[m_name] = data

        # Severity counts
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings_list:
            # Skip suppressed/accepted/false positive findings
            stat = getattr(f, "status", None)
            if stat is None and isinstance(f, dict):
                stat = f.get("status")
            if stat in ("accepted_risk", "false_positive", "fixed"):
                continue

            sev = getattr(f, "severity", None)
            if sev is None and isinstance(f, dict):
                sev = f.get("severity")
            if hasattr(sev, "value"):
                sev = sev.value
            sev = str(sev).lower() if sev else "info"
            if sev in counts:
                counts[sev] += 1

        # Key attack surface metrics
        subs_data = results_map.get("subdomains", {})
        sub_count = len(subs_data.get("subdomains", [])) or len(subs_data.get("discovered_subdomains", []))

        ports_data = results_map.get("ports", {})
        port_count = len(ports_data.get("open_ports", []))

        tech_data = results_map.get("web_tech", {})
        tech_count = len(tech_data.get("technologies", []))

        dns_data = results_map.get("dns", {})
        dmarc_verdict = dns_data.get("dmarc_verdict", "Unknown")

        ssl_data = results_map.get("ssl_tls", {})
        cert_days = ssl_data.get("days_remaining")

        # Top 5 prioritized fixes
        top_5_fixes = cls._derive_top_5_fixes(findings_list)

        # Plain-language non-technical executive narrative
        narrative = cls._compose_executive_narrative(
            domain=domain,
            grade=grade,
            score=score,
            posture_label=posture_label,
            sub_count=sub_count,
            port_count=port_count,
            crit_count=counts["critical"],
            high_count=counts["high"],
            dmarc_verdict=dmarc_verdict,
            cert_days=cert_days,
            top_fixes=top_5_fixes,
        )

        return {
            "domain": domain,
            "security_grade": grade,
            "risk_score": score,
            "risk_posture": posture_label,
            "posture_description": posture_desc,
            "executive_narrative": narrative,
            "severity_counts": counts,
            "attack_surface_kpis": {
                "subdomains_exposed": sub_count,
                "open_ports_detected": port_count,
                "technologies_identified": tech_count,
                "email_spoofing_status": dmarc_verdict,
                "ssl_certificate_days_remaining": cert_days,
            },
            "top_prioritized_fixes": top_5_fixes,
        }

    @classmethod
    def _derive_top_5_fixes(cls, findings: list[Any]) -> list[dict[str, Any]]:
        scored_findings = []
        for f in findings:
            stat = getattr(f, "status", None)
            if stat is None and isinstance(f, dict):
                stat = f.get("status")
            if stat in ("accepted_risk", "false_positive", "fixed"):
                continue

            sev = getattr(f, "severity", None)
            if sev is None and isinstance(f, dict):
                sev = f.get("severity")
            if hasattr(sev, "value"):
                sev = sev.value
            sev_str = str(sev).lower() if sev else "info"

            conf = getattr(f, "confidence", None)
            if conf is None and isinstance(f, dict):
                conf = f.get("confidence")
            if hasattr(conf, "value"):
                conf = conf.value
            conf_str = str(conf).lower() if conf else "likely"

            title = getattr(f, "title", None)
            if title is None and isinstance(f, dict):
                title = f.get("title", "")
            title = title or ""

            # Skip failed check logs
            if title.lower().startswith("check failed") or "lookup error" in title.lower():
                continue

            remediation = getattr(f, "remediation", None)
            if remediation is None and isinstance(f, dict):
                remediation = f.get("remediation", "")
            remediation = remediation or "Review technical configuration and apply security updates."

            weight = cls.SEV_WEIGHTS.get(sev_str, 1) * cls.CONF_WEIGHTS.get(conf_str, 1.0)
            business_impact = cls._infer_business_impact(title, sev_str)

            scored_findings.append({
                "title": title,
                "severity": sev_str,
                "confidence": conf_str,
                "business_impact": business_impact,
                "remediation_action": remediation,
                "_weight": weight,
            })

        # Sort descending by weight
        scored_findings.sort(key=lambda x: x["_weight"], reverse=True)

        # De-duplicate by title and take top 5
        unique_fixes = []
        seen = set()
        for fix in scored_findings:
            t = fix["title"].strip()
            if t and t not in seen:
                seen.add(t)
                unique_fixes.append({
                    "title": fix["title"],
                    "severity": fix["severity"],
                    "confidence": fix["confidence"],
                    "business_impact": fix["business_impact"],
                    "remediation_action": fix["remediation_action"],
                })
            if len(unique_fixes) >= 5:
                break

        return unique_fixes

    @classmethod
    def _infer_business_impact(cls, title: str, severity: str) -> str:
        tl = title.lower()
        if "dmarc" in tl or "spf" in tl or "spoof" in tl:
            return "Allows cybercriminals to forge executive emails to scam employees, suppliers, or clients."
        elif "cve" in tl or "vulnerab" in tl or "exploit" in tl:
            return "Provides known entry points that attackers can exploit to breach systems and access sensitive corporate data."
        elif "takeover" in tl or "dangling" in tl:
            return "Enables adversaries to hijack your subdomain to host phishing landing pages or harvest credentials."
        elif "hsts" in tl or "tls" in tl or "ssl" in tl or "cipher" in tl:
            return "Leaves corporate web traffic exposed to interception or eavesdropping by adversaries on public networks."
        elif "port" in tl or "open" in tl or "database" in tl:
            return "Exposes internal network interfaces directly to the public internet, increasing unauthorized access risks."
        elif "secret" in tl or "leak" in tl or "key" in tl:
            return "Exposes confidential credentials that grant direct access to cloud infrastructure or developer services."
        elif "lookalike" in tl or "typo" in tl:
            return "Signals that malicious actors may be preparing phishing campaigns imitating your organization's brand."
        elif severity == "critical":
            return "Presents an immediate risk of system compromise or unauthorized access to sensitive organization assets."
        elif severity == "high":
            return "Significantly impairs perimeter defense and provides high-probability attack vectors for adversaries."
        elif severity == "medium":
            return "Weakens defense-in-depth controls and increases overall exposure during automated vulnerability scans."
        return "Represents an unhardened configuration that deviates from industry security best practices."

    @classmethod
    def _compose_executive_narrative(
        cls,
        domain: str,
        grade: str,
        score: int,
        posture_label: str,
        sub_count: int,
        port_count: int,
        crit_count: int,
        high_count: int,
        dmarc_verdict: str,
        cert_days: Optional[int],
        top_fixes: list[dict],
    ) -> str:
        intro = (
            f"An automated perimeter assessment of {domain} resulted in an overall security grade of {grade} "
            f"with a normalized risk score of {score}/100, reflecting a {posture_label.lower()} posture."
        )

        exposure_parts = []
        if sub_count > 0:
            exposure_parts.append(f"{sub_count} exposed subdomains")
        if port_count > 0:
            exposure_parts.append(f"{port_count} publicly accessible network services")
        exposure_str = f"Reconnaissance telemetry cataloged {' and '.join(exposure_parts) if exposure_parts else 'minimal external attack surfaces'}."

        risk_parts = []
        if crit_count > 0 or high_count > 0:
            risk_parts.append(f"{crit_count + high_count} high-priority vulnerabilities requiring immediate leadership attention")
        if dmarc_verdict and "spoof" in dmarc_verdict.lower():
            risk_parts.append("an email domain configuration susceptible to executive impersonation")
        if cert_days is not None and cert_days <= 30:
            risk_parts.append(f"an SSL certificate nearing expiration ({cert_days} days remaining)")

        if risk_parts:
            risk_str = f"Key risk drivers include {', '.join(risk_parts)}."
        else:
            risk_str = "No critical remote compromise vectors or imminent security outages were detected."

        if top_fixes:
            action_str = f"Addressing the top {len(top_fixes)} prioritized remediation items will systematically harden organizational defenses and reduce exposure."
        else:
            action_str = "Maintaining continuous monitoring will ensure new exposures are promptly identified and mitigated."

        return f"{intro} {exposure_str} {risk_str} {action_str}"

