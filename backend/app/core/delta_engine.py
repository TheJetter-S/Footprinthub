# =============================================================================
# FootprintHub — Scan Delta Engine
# =============================================================================
# Analyzes changes between a target scan and its previous scan baseline:
# - New or removed subdomains
# - New open ports or closed ports
# - SSL/TLS certificate expiry warnings (30, 14, 7 days)
# - Newly introduced CVEs and resolved CVEs
# - DNS record modifications (A, AAAA, MX, NS, TXT, CNAME)
# - Newly registered lookalike domains
# - Threat reputation listing changes
# - Risk score posture shifts
# =============================================================================

from datetime import datetime, timezone
from typing import Any, Optional


class DeltaEngine:
    """
    Computes fine-grained differences between two scans of the same domain.
    """

    @classmethod
    def calculate_delta(
        cls,
        current_scan: Any,
        prior_scan: Optional[Any] = None,
        current_results: Optional[list[Any]] = None,
        prior_results: Optional[list[Any]] = None,
        current_findings: Optional[list[Any]] = None,
        prior_findings: Optional[list[Any]] = None,
    ) -> dict[str, Any]:
        """
        Compare current scan against prior scan baseline.
        If prior_scan is None, returns initial baseline report.
        """
        # Extract results dict keyed by module name
        curr_res_map = cls._index_results(current_scan, current_results)
        prior_res_map = cls._index_results(prior_scan, prior_results) if prior_scan else {}

        # Extract findings list
        curr_findings_list = cls._extract_findings(current_scan, current_findings)
        prior_findings_list = cls._extract_findings(prior_scan, prior_findings) if prior_scan else []

        # 1. Subdomain changes
        curr_subs = cls._extract_subdomains(curr_res_map)
        prior_subs = cls._extract_subdomains(prior_res_map)
        added_subs = sorted(list(curr_subs - prior_subs))
        removed_subs = sorted(list(prior_subs - curr_subs))

        # 2. Port changes
        curr_ports = cls._extract_open_ports(curr_res_map)
        prior_ports = cls._extract_open_ports(prior_res_map)
        opened_ports = [p for p in curr_ports if p.get("port") not in {x.get("port") for x in prior_ports}]
        closed_ports = [p for p in prior_ports if p.get("port") not in {x.get("port") for x in curr_ports}]

        # 3. Certificate expiry status
        cert_status = cls._check_certificate_expiry(curr_res_map)

        # 4. CVE changes
        curr_cves = cls._extract_cves(curr_res_map, curr_findings_list)
        prior_cves = cls._extract_cves(prior_res_map, prior_findings_list)
        curr_cve_ids = {c["id"]: c for c in curr_cves}
        prior_cve_ids = {c["id"]: c for c in prior_cves}
        new_cves = [c for c_id, c in curr_cve_ids.items() if c_id not in prior_cve_ids]
        resolved_cves = [c for c_id, c in prior_cve_ids.items() if c_id not in curr_cve_ids]

        # 5. DNS record changes
        curr_dns = cls._extract_dns_records(curr_res_map)
        prior_dns = cls._extract_dns_records(prior_res_map)
        dns_changes = cls._diff_dns_records(curr_dns, prior_dns)

        # 6. Lookalike domain changes
        curr_lookalikes = cls._extract_registered_lookalikes(curr_res_map)
        prior_lookalikes = cls._extract_registered_lookalikes(prior_res_map)
        new_lookalikes = sorted(list(curr_lookalikes - prior_lookalikes))

        # 7. Reputation status changes
        curr_rep = cls._extract_reputation_indicators(curr_res_map)
        prior_rep = cls._extract_reputation_indicators(prior_res_map)
        rep_changes = cls._diff_reputation(curr_rep, prior_rep)

        # 8. Findings changes
        curr_finding_titles = {getattr(f, "title", f.get("title") if isinstance(f, dict) else ""): f for f in curr_findings_list}
        prior_finding_titles = {getattr(f, "title", f.get("title") if isinstance(f, dict) else ""): f for f in prior_findings_list}
        new_findings = [
            cls._serialize_finding(f)
            for title, f in curr_finding_titles.items()
            if title and title not in prior_finding_titles
        ]
        resolved_findings = [
            cls._serialize_finding(f)
            for title, f in prior_finding_titles.items()
            if title and title not in curr_finding_titles
        ]

        # 9. Risk score posture
        curr_score = getattr(current_scan, "risk_score", None)
        if curr_score is None and isinstance(current_scan, dict):
            curr_score = current_scan.get("risk_score")
        curr_score = curr_score or 0

        prior_score = getattr(prior_scan, "risk_score", None) if prior_scan else None
        if prior_score is None and isinstance(prior_scan, dict):
            prior_score = prior_scan.get("risk_score")
        prior_score = prior_score if prior_score is not None else curr_score

        score_delta = curr_score - prior_score
        posture = "baseline"
        if prior_scan:
            if score_delta > 0:
                posture = "worsened"
            elif score_delta < 0:
                posture = "improved"
            else:
                posture = "unchanged"

        # Check if notable changes occurred
        has_changes = bool(
            added_subs
            or removed_subs
            or opened_ports
            or closed_ports
            or (cert_status.get("days_remaining") is not None and cert_status.get("days_remaining") <= 30)
            or new_cves
            or dns_changes.get("has_changes")
            or new_lookalikes
            or rep_changes.get("new_listings")
            or new_findings
        )

        summary_narrative = cls._build_summary_narrative(
            has_prior=bool(prior_scan),
            added_subs=added_subs,
            opened_ports=opened_ports,
            new_cves=new_cves,
            cert_status=cert_status,
            dns_changes=dns_changes,
            new_lookalikes=new_lookalikes,
            rep_changes=rep_changes,
            score_delta=score_delta,
            posture=posture,
        )

        return {
            "has_prior_baseline": bool(prior_scan),
            "has_changes": has_changes,
            "posture": posture,
            "risk_score_delta": score_delta,
            "current_risk_score": curr_score,
            "prior_risk_score": prior_score,
            "summary": summary_narrative,
            "subdomains": {
                "added": added_subs,
                "removed": removed_subs,
                "total_current": len(curr_subs),
                "total_prior": len(prior_subs),
            },
            "ports": {
                "opened": opened_ports,
                "closed": closed_ports,
                "total_current": len(curr_ports),
                "total_prior": len(prior_ports),
            },
            "certificate_expiry": cert_status,
            "vulnerabilities": {
                "new_cves": new_cves,
                "resolved_cves": resolved_cves,
                "total_current": len(curr_cves),
            },
            "dns_records": dns_changes,
            "lookalikes": {
                "new_registered": new_lookalikes,
                "total_detected": len(curr_lookalikes),
            },
            "reputation": rep_changes,
            "findings": {
                "new": new_findings,
                "resolved": resolved_findings,
                "total_current": len(curr_findings_list),
            },
        }

    @classmethod
    def _index_results(cls, scan: Any, results: Optional[list[Any]] = None) -> dict[str, dict]:
        res_map = {}
        target_results = results
        if target_results is None and scan:
            target_results = getattr(scan, "results", None)
            if target_results is None and isinstance(scan, dict):
                target_results = scan.get("results", [])

        if target_results:
            for r in target_results:
                mod_name = getattr(r, "module_name", None)
                data = getattr(r, "data", None)
                if mod_name is None and isinstance(r, dict):
                    mod_name = r.get("module_name")
                    data = r.get("data")
                if mod_name and isinstance(data, dict):
                    res_map[mod_name] = data
        return res_map

    @classmethod
    def _extract_findings(cls, scan: Any, findings: Optional[list[Any]] = None) -> list[Any]:
        if findings is not None:
            return findings
        if scan:
            f = getattr(scan, "findings", None)
            if f is not None:
                return list(f)
            if isinstance(scan, dict):
                return scan.get("findings", [])
        return []

    @classmethod
    def _extract_subdomains(cls, res_map: dict[str, dict]) -> set[str]:
        subs = set()
        sub_data = res_map.get("subdomains", {})
        for s in sub_data.get("subdomains", []):
            if isinstance(s, str):
                subs.add(s.lower().strip())
            elif isinstance(s, dict) and "subdomain" in s:
                subs.add(s["subdomain"].lower().strip())
        for s in sub_data.get("discovered_subdomains", []):
            if isinstance(s, str):
                subs.add(s.lower().strip())
        return subs

    @classmethod
    def _extract_open_ports(cls, res_map: dict[str, dict]) -> list[dict]:
        ports_data = res_map.get("ports", {})
        ports_list = ports_data.get("open_ports", [])
        extracted = []
        for p in ports_list:
            if isinstance(p, dict):
                extracted.append({
                    "port": p.get("port"),
                    "service": p.get("service") or p.get("service_name") or "unknown",
                    "cpe": p.get("cpe", []),
                    "cves": p.get("cves", []),
                })
            elif isinstance(p, (int, str)):
                try:
                    extracted.append({"port": int(p), "service": "unknown", "cpe": [], "cves": []})
                except ValueError:
                    pass
        return extracted

    @classmethod
    def _check_certificate_expiry(cls, res_map: dict[str, dict]) -> dict[str, Any]:
        ssl_data = res_map.get("ssl_tls", {})
        cert = ssl_data.get("certificate", {})
        days_rem = ssl_data.get("days_remaining")
        if days_rem is None and cert:
            days_rem = cert.get("days_until_expiration") or cert.get("days_remaining")

        not_after = ssl_data.get("not_after") or cert.get("not_after") or cert.get("valid_to")
        if days_rem is None and not_after:
            try:
                # Try parsing date
                dt = datetime.fromisoformat(str(not_after).replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                days_rem = (dt - now).days
            except Exception:
                pass

        status = "ok"
        alert_level = "info"
        if days_rem is not None:
            if days_rem <= 7:
                status = "critical_expiry"
                alert_level = "critical"
            elif days_rem <= 14:
                status = "warning_expiry"
                alert_level = "high"
            elif days_rem <= 30:
                status = "attention_needed"
                alert_level = "medium"

        return {
            "days_remaining": days_rem,
            "expires_at": not_after,
            "status": status,
            "alert_level": alert_level,
            "requires_action": days_rem is not None and days_rem <= 30,
        }

    @classmethod
    def _extract_cves(cls, res_map: dict[str, dict], findings: list[Any]) -> list[dict]:
        cves = []
        seen = set()

        # From ports module
        ports_data = res_map.get("ports", {})
        for cve_item in ports_data.get("cves", []):
            cid = cve_item.get("id") if isinstance(cve_item, dict) else str(cve_item)
            if cid and cid not in seen:
                seen.add(cid)
                cves.append({
                    "id": cid,
                    "epss": cve_item.get("epss") if isinstance(cve_item, dict) else None,
                    "cisa_kev": cve_item.get("cisa_kev") if isinstance(cve_item, dict) else False,
                })

        # From findings
        for f in findings:
            title = getattr(f, "title", f.get("title") if isinstance(f, dict) else "")
            if "CVE-" in title:
                import re
                matches = re.findall(r"CVE-\d{4}-\d{4,7}", title)
                for cid in matches:
                    if cid not in seen:
                        seen.add(cid)
                        cves.append({"id": cid, "epss": None, "cisa_kev": False})
        return cves

    @classmethod
    def _extract_dns_records(cls, res_map: dict[str, dict]) -> dict[str, list[str]]:
        dns_data = res_map.get("dns", {})
        records = dns_data.get("records", {})
        norm = {}
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
            vals = records.get(rtype, [])
            clean_vals = []
            for v in vals:
                if isinstance(v, str):
                    clean_vals.append(v.strip())
                elif isinstance(v, dict):
                    clean_vals.append(v.get("value") or v.get("target") or str(v))
            norm[rtype] = sorted(clean_vals)
        return norm

    @classmethod
    def _diff_dns_records(cls, curr: dict[str, list[str]], prior: dict[str, list[str]]) -> dict[str, Any]:
        added = {}
        removed = {}
        has_changes = False

        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
            c_set = set(curr.get(rtype, []))
            p_set = set(prior.get(rtype, [])) if prior else set()

            add_vals = sorted(list(c_set - p_set))
            rem_vals = sorted(list(p_set - c_set))

            if add_vals:
                added[rtype] = add_vals
                has_changes = True
            if rem_vals:
                removed[rtype] = rem_vals
                has_changes = True

        return {
            "has_changes": has_changes,
            "added_records": added,
            "removed_records": removed,
        }

    @classmethod
    def _extract_registered_lookalikes(cls, res_map: dict[str, dict]) -> set[str]:
        look_data = res_map.get("lookalike", {})
        registered = set()
        for item in look_data.get("registered_lookalikes", []):
            d = item.get("domain") if isinstance(item, dict) else str(item)
            if d:
                registered.add(d.lower().strip())
        return registered

    @classmethod
    def _extract_reputation_indicators(cls, res_map: dict[str, dict]) -> dict[str, Any]:
        rep_data = res_map.get("reputation", {})
        listings = []
        for bl in rep_data.get("blacklists", []):
            if isinstance(bl, dict) and bl.get("listed"):
                listings.append(bl.get("name") or bl.get("source"))
        return {
            "score": rep_data.get("reputation_score", 0),
            "listings": sorted(listings),
        }

    @classmethod
    def _diff_reputation(cls, curr: dict[str, Any], prior: dict[str, Any]) -> dict[str, Any]:
        c_listings = set(curr.get("listings", []))
        p_listings = set(prior.get("listings", [])) if prior else set()

        new_listings = sorted(list(c_listings - p_listings))
        resolved_listings = sorted(list(p_listings - c_listings))

        return {
            "new_listings": new_listings,
            "resolved_listings": resolved_listings,
            "has_changes": bool(new_listings or resolved_listings),
        }

    @classmethod
    def _serialize_finding(cls, f: Any) -> dict[str, Any]:
        if isinstance(f, dict):
            return {
                "title": f.get("title"),
                "severity": f.get("severity"),
                "module_name": f.get("module_name"),
                "confidence": f.get("confidence", "likely"),
            }
        return {
            "title": getattr(f, "title", ""),
            "severity": getattr(f, "severity", "info"),
            "module_name": getattr(f, "module_name", "unknown"),
            "confidence": getattr(f, "confidence", "likely"),
        }

    @classmethod
    def _build_summary_narrative(
        cls,
        has_prior: bool,
        added_subs: list[str],
        opened_ports: list[dict],
        new_cves: list[dict],
        cert_status: dict[str, Any],
        dns_changes: dict[str, Any],
        new_lookalikes: list[str],
        rep_changes: dict[str, Any],
        score_delta: int,
        posture: str,
    ) -> str:
        if not has_prior:
            return "Initial reconnaissance baseline established. No prior scan available for comparative differential analysis."

        changes = []
        if score_delta != 0:
            direction = "increased" if score_delta > 0 else "decreased"
            changes.append(f"Risk score {direction} by {abs(score_delta)} points (posture: {posture}).")
        if added_subs:
            changes.append(f"{len(added_subs)} new subdomain(s) detected ({', '.join(added_subs[:3])}{'...' if len(added_subs) > 3 else ''}).")
        if opened_ports:
            ports_str = ", ".join(str(p['port']) for p in opened_ports[:4])
            changes.append(f"{len(opened_ports)} newly opened network port(s) detected: {ports_str}.")
        if new_cves:
            cves_str = ", ".join(c['id'] for c in new_cves[:3])
            changes.append(f"{len(new_cves)} newly identified CVE vulnerability match(es): {cves_str}.")
        if cert_status.get("requires_action"):
            days = cert_status.get("days_remaining")
            changes.append(f"SSL/TLS Certificate expiration alert: expires in {days} day(s)!")
        if dns_changes.get("has_changes"):
            changes.append("DNS record changes identified across zone entries.")
        if new_lookalikes:
            changes.append(f"{len(new_lookalikes)} newly registered lookalike / typosquatted domain(s) observed.")
        if rep_changes.get("new_listings"):
            changes.append(f"New reputation threat listing(s): {', '.join(rep_changes['new_listings'])}.")

        if not changes:
            return "No perimeter changes or risk variations detected compared to previous baseline scan."

        return " ".join(changes)

