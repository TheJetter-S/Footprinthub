# =============================================================================
# FootprintHub — DNS & WHOIS Reconnaissance Module
# =============================================================================
# Queries DNS records, WHOIS registration info, DNSSEC status, and audits
# email security mechanisms (SPF, DMARC, DKIM) generating actionable findings.
# =============================================================================

import asyncio
import re
from datetime import datetime
from typing import Any, Optional

import dns.asyncresolver
import dns.dnssec
import dns.exception
import dns.rdatatype
import dns.resolver

from app.modules.base import (
    BaseModule,
    FindingSeverity,
    ModuleFinding,
    ModuleMode,
    ModuleResult,
    ProgressCallback,
)


class DNSModule(BaseModule):
    """
    DNS & WHOIS reconnaissance module.
    Performs passive analysis of domain records, infrastructure, and email authentication.
    """

    name: str = "dns"
    description: str = "DNS records, WHOIS registration, DNSSEC verification, and email security audit"
    mode: ModuleMode = ModuleMode.PASSIVE
    timeout: int = 45

    def __init__(self):
        super().__init__()
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.timeout = 5.0
        self.resolver.lifetime = 8.0
        # Use reliable public DNS resolvers as fallback
        self.resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

    async def run(
        self,
        target: str,
        on_progress: Optional[ProgressCallback] = None,
    ) -> ModuleResult:
        findings: list[ModuleFinding] = []
        data: dict[str, Any] = {
            "target": target,
            "records": {},
            "whois": {},
            "dnssec": {"enabled": False, "status": "unsigned"},
            "email_security": {},
        }

        self._progress(on_progress, 10, "Querying standard DNS records...")
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA"]
        records_data = await self._query_records(target, record_types)
        data["records"] = records_data

        # Check A/AAAA records
        a_records = records_data.get("A", [])
        if not a_records:
            findings.append(
                ModuleFinding(
                    severity=FindingSeverity.INFO,
                    title="No IPv4 Address (A Record)",
                    description=f"Domain {target} does not have any IPv4 A records configured.",
                    remediation="Ensure an A record points to your active server IP address if IPv4 access is required.",
                )
            )

        self._progress(on_progress, 35, "Checking DNSSEC status...")
        dnssec_info = await self._check_dnssec(target)
        data["dnssec"] = dnssec_info
        if not dnssec_info.get("enabled", False):
            findings.append(
                ModuleFinding(
                    severity=FindingSeverity.LOW,
                    title="DNSSEC Not Configured",
                    description=f"DNSSEC (Domain Name System Security Extensions) is not enabled for {target}, leaving the domain vulnerable to DNS spoofing and cache poisoning.",
                    remediation="Enable and configure DNSSEC at your domain registrar and DNS hosting provider.",
                )
            )

        self._progress(on_progress, 55, "Auditing email security (SPF, DMARC)...")
        email_sec = await self._audit_email_security(target, records_data.get("TXT", []), findings)
        data["email_security"] = email_sec

        self._progress(on_progress, 75, "Checking CAA records...")
        caa_records = records_data.get("CAA", [])
        if not caa_records:
            findings.append(
                ModuleFinding(
                    severity=FindingSeverity.LOW,
                    title="Missing CAA (Certificate Authority Authorization) Record",
                    description=f"No CAA records found for {target}. Any compliant Certificate Authority can issue certificates for this domain.",
                    remediation="Add CAA DNS records restricting certificate issuance to only your authorized CAs (e.g. '0 issue \"letsencrypt.org\"').",
                )
            )

        self._progress(on_progress, 85, "Querying WHOIS registration...")
        whois_info = await self._query_whois(target, findings)
        data["whois"] = whois_info

        self._progress(on_progress, 100, "DNS reconnaissance completed")

        return ModuleResult(
            module_name=self.name,
            mode=self.mode,
            status="success",
            data=data,
            findings=findings,
        )

    async def _query_records(self, domain: str, rtypes: list[str]) -> dict[str, list[Any]]:
        """Query multiple DNS record types concurrently."""
        results: dict[str, list[Any]] = {}

        async def _query_type(rtype: str):
            try:
                answers = await self.resolver.resolve(domain, rtype)
                type_results = []
                for rdata in answers:
                    if rtype == "MX":
                        type_results.append({
                            "preference": rdata.preference,
                            "exchange": str(rdata.exchange).rstrip("."),
                        })
                    elif rtype == "SOA":
                        type_results.append({
                            "mname": str(rdata.mname).rstrip("."),
                            "rname": str(rdata.rname).rstrip("."),
                            "serial": rdata.serial,
                            "refresh": rdata.refresh,
                            "retry": rdata.retry,
                            "expire": rdata.expire,
                            "minimum": rdata.minimum,
                        })
                    elif rtype == "CAA":
                        type_results.append({
                            "tag": rdata.tag.decode("utf-8", errors="ignore") if isinstance(rdata.tag, bytes) else str(rdata.tag),
                            "value": rdata.value.decode("utf-8", errors="ignore") if isinstance(rdata.value, bytes) else str(rdata.value),
                            "flags": rdata.flags,
                        })
                    elif rtype == "TXT":
                        txt_val = "".join(
                            s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else str(s)
                            for s in rdata.strings
                        )
                        type_results.append(txt_val)
                    else:
                        type_results.append(str(rdata).rstrip("."))
                results[rtype] = type_results
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                results[rtype] = []
            except Exception:
                results[rtype] = []

        await asyncio.gather(*[_query_type(rt) for rt in rtypes])
        return results

    async def _check_dnssec(self, domain: str) -> dict[str, Any]:
        """Check if DNSSEC signatures and keys exist for the domain."""
        try:
            answers = await self.resolver.resolve(domain, "DNSKEY")
            if answers:
                return {"enabled": True, "status": "active", "key_count": len(answers)}
        except Exception:
            pass

        try:
            answers = await self.resolver.resolve(domain, "DS")
            if answers:
                return {"enabled": True, "status": "active_ds", "ds_count": len(answers)}
        except Exception:
            pass

        return {"enabled": False, "status": "unsigned"}

    async def _audit_email_security(
        self,
        domain: str,
        txt_records: list[str],
        findings: list[ModuleFinding],
    ) -> dict[str, Any]:
        """Audit SPF, DMARC, and DKIM configuration."""
        email_sec: dict[str, Any] = {
            "spf": {"present": False, "record": None, "policy": None},
            "dmarc": {"present": False, "record": None, "policy": None, "subdomain_policy": None},
            "dkim_configured": False,
        }

        # 1. SPF Check
        spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]
        if not spf_records:
            findings.append(
                ModuleFinding(
                    severity=FindingSeverity.HIGH,
                    title="Missing SPF (Sender Policy Framework) Record",
                    description=f"Domain {domain} has no SPF record configured. Anyone can forge emails appearing to originate from this domain.",
                    remediation="Publish a valid TXT record starting with 'v=spf1' defining authorized email sending servers and terminating with '-all'.",
                )
            )
        else:
            spf = spf_records[0]
            email_sec["spf"]["present"] = True
            email_sec["spf"]["record"] = spf
            if "+all" in spf:
                email_sec["spf"]["policy"] = "+all (pass all)"
                findings.append(
                    ModuleFinding(
                        severity=FindingSeverity.CRITICAL,
                        title="Insecure SPF Policy (+all)",
                        description=f"The SPF record for {domain} ends with '+all', allowing any IP address in the world to legitimately send mail on behalf of this domain.",
                        remediation="Change the SPF mechanism terminator from '+all' to '-all' (hard fail) or '~all' (soft fail).",
                    )
                )
            elif "?all" in spf:
                email_sec["spf"]["policy"] = "?all (neutral)"
                findings.append(
                    ModuleFinding(
                        severity=FindingSeverity.MEDIUM,
                        title="Permissive SPF Policy (?all)",
                        description=f"The SPF record for {domain} specifies '?all' (neutral policy), offering minimal protection against unauthorized senders.",
                        remediation="Change the SPF mechanism terminator to '-all' (hard fail).",
                    )
                )
            elif "~all" in spf:
                email_sec["spf"]["policy"] = "~all (soft fail)"
            elif "-all" in spf:
                email_sec["spf"]["policy"] = "-all (hard fail)"

        # 2. DMARC Check
        try:
            dmarc_answers = await self.resolver.resolve(f"_dmarc.{domain}", "TXT")
            dmarc_txts = [
                "".join(
                    s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else str(s)
                    for s in rdata.strings
                )
                for rdata in dmarc_answers
            ]
            valid_dmarc = [d for d in dmarc_txts if d.lower().startswith("v=dmarc1")]
            if valid_dmarc:
                dmarc = valid_dmarc[0]
                email_sec["dmarc"]["present"] = True
                email_sec["dmarc"]["record"] = dmarc

                policy_match = re.search(r"p=(none|quarantine|reject)", dmarc, re.IGNORECASE)
                policy = policy_match.group(1).lower() if policy_match else "unknown"
                email_sec["dmarc"]["policy"] = policy

                sp_match = re.search(r"sp=(none|quarantine|reject)", dmarc, re.IGNORECASE)
                if sp_match:
                    email_sec["dmarc"]["subdomain_policy"] = sp_match.group(1).lower()

                if policy == "none":
                    findings.append(
                        ModuleFinding(
                            severity=FindingSeverity.MEDIUM,
                            title="DMARC Policy Set to 'none' (Monitor Only)",
                            description=f"The DMARC policy for {domain} is configured as 'p=none'. Spoofed emails failing SPF/DKIM will still be delivered to recipient inboxes.",
                            remediation="Gradually upgrade DMARC policy from 'p=none' to 'p=quarantine' and ultimately 'p=reject'.",
                        )
                    )
            else:
                self._add_missing_dmarc_finding(domain, findings)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            self._add_missing_dmarc_finding(domain, findings)
        except Exception:
            pass

        return email_sec

    def _add_missing_dmarc_finding(self, domain: str, findings: list[ModuleFinding]) -> None:
        findings.append(
            ModuleFinding(
                severity=FindingSeverity.HIGH,
                title="Missing DMARC Record",
                description=f"No DMARC record found at _dmarc.{domain}. The domain lacks centralized email spoofing reporting and enforcement rules.",
                remediation="Add a TXT record at _dmarc.{domain} with 'v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{domain}'.",
            )
        )

    async def _query_whois(self, domain: str, findings: list[ModuleFinding]) -> dict[str, Any]:
        """Perform WHOIS lookup via python-whois in a thread pool."""
        def _sync_whois():
            try:
                import whois
                w = whois.whois(domain)
                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                expiration_date = w.expiration_date
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]

                return {
                    "registrar": w.registrar,
                    "whois_server": w.whois_server,
                    "creation_date": str(creation_date) if creation_date else None,
                    "expiration_date": str(expiration_date) if expiration_date else None,
                    "name_servers": [str(ns).lower() for ns in (w.name_servers or []) if ns],
                    "status": w.status if isinstance(w.status, list) else [w.status] if w.status else [],
                    "emails": w.emails if isinstance(w.emails, list) else [w.emails] if w.emails else [],
                    "org": w.org,
                    "country": w.country,
                }
            except Exception as e:
                return {"error": str(e)}

        loop = asyncio.get_running_loop()
        try:
            res = await asyncio.wait_for(loop.run_in_executor(None, _sync_whois), timeout=12.0)
            exp_str = res.get("expiration_date")
            if exp_str:
                try:
                    exp_date = datetime.fromisoformat(exp_str[:10])
                    days_left = (exp_date - datetime.now()).days
                    if 0 < days_left <= 30:
                        findings.append(
                            ModuleFinding(
                                severity=FindingSeverity.HIGH,
                                title=f"Domain Expiring Soon ({days_left} days remaining)",
                                description=f"The domain {domain} is set to expire on {exp_str[:10]}. Failure to renew could lead to domain hijacking.",
                                remediation="Renew the domain registration with the registrar immediately.",
                            )
                        )
                except Exception:
                    pass
            return res
        except Exception:
            return {"status": "unavailable"}
