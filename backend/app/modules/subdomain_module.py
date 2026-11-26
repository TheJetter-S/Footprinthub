# =============================================================================
# FootprintHub — Subdomain Reconnaissance Module
# =============================================================================
# Enumerates subdomains via Certificate Transparency logs (crt.sh) & DNS,
# validates resolution, and checks for Subdomain Takeover vulnerabilities.
# =============================================================================

import asyncio
import re
import time
from typing import Any, Optional

import dns.asyncresolver
import dns.exception
import dns.resolver

from app.core.safe_request import safe_request
from app.modules.base import (
    BaseModule,
    FindingSeverity,
    ModuleFinding,
    ModuleMode,
    ModuleResult,
    ProgressCallback,
)

# High-value hosts selected from subdomain results for OSINT crawling
HIGH_VALUE_OSINT_PREFIXES = (
    "www", "about", "team", "careers", "blog",
    "press", "investors", "docs", "support", "app",
)
_SUBDOMAIN_RESULTS_CACHE: dict[str, tuple[float, list[dict[str, Any]]]] = {}
_SUBDOMAIN_CACHE_TTL = 600.0

# Known takeover target CNAME suffixes and their dangling response indicators
TAKEOVER_SIGNATURES: dict[str, dict[str, str]] = {
    "github.io": {
        "service": "GitHub Pages",
        "fingerprint": "There isn't a GitHub Pages site here",
        "severity": FindingSeverity.HIGH,
    },
    "s3.amazonaws.com": {
        "service": "AWS S3 Bucket",
        "fingerprint": "NoSuchBucket",
        "severity": FindingSeverity.HIGH,
    },
    "herokuapp.com": {
        "service": "Heroku",
        "fingerprint": "No such app",
        "severity": FindingSeverity.HIGH,
    },
    "azurewebsites.net": {
        "service": "Azure App Service",
        "fingerprint": "404 Web Site not found",
        "severity": FindingSeverity.HIGH,
    },
    "fastly.net": {
        "service": "Fastly CDN",
        "fingerprint": "Fastly error: unknown domain",
        "severity": FindingSeverity.HIGH,
    },
    "ghost.io": {
        "service": "Ghost",
        "fingerprint": "The thing you were looking for is no longer here",
        "severity": FindingSeverity.HIGH,
    },
    "myshopify.com": {
        "service": "Shopify",
        "fingerprint": "Sorry, this shop is currently unavailable",
        "severity": FindingSeverity.MEDIUM,
    },
    "bitbucket.io": {
        "service": "Bitbucket Cloud",
        "fingerprint": "Repository not found",
        "severity": FindingSeverity.HIGH,
    },
}

COMMON_SUBDOMAINS = [
    "www", "mail", "api", "dev", "staging", "admin", "vpn", "test",
    "portal", "app", "auth", "git", "status", "cdn", "support",
    "remote", "dashboard", "secure", "beta", "demo", "intranet", "db",
]


class SubdomainModule(BaseModule):
    """
    Subdomain enumeration and takeover analysis module.
    """

    name: str = "subdomains"
    description: str = "Certificate Transparency log search, active DNS verification, and takeover detection"
    mode: ModuleMode = ModuleMode.PASSIVE
    timeout: int = 60

    def __init__(self):
        super().__init__()
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.timeout = 3.0
        self.resolver.lifetime = 5.0
        self.resolver.nameservers = ["1.1.1.1", "8.8.8.8"]

    async def run(
        self,
        target: str,
        on_progress: Optional[ProgressCallback] = None,
    ) -> ModuleResult:
        findings: list[ModuleFinding] = []
        discovered_names: set[str] = set()

        self._progress(on_progress, 15, "Querying Certificate Transparency logs (crt.sh)...")
        ct_subdomains = await self._query_crt_sh(target)
        discovered_names.update(ct_subdomains)

        self._progress(on_progress, 35, f"Discovered {len(discovered_names)} CT entries. Probing common prefixes...")
        for prefix in COMMON_SUBDOMAINS:
            discovered_names.add(f"{prefix}.{target}")

        self._progress(on_progress, 50, f"Resolving {len(discovered_names)} candidate subdomains...")
        resolved_subdomains = await self._resolve_subdomains(target, list(discovered_names))
        _SUBDOMAIN_RESULTS_CACHE[target.lower().strip()] = (time.time(), list(resolved_subdomains))

        self._progress(on_progress, 75, "Checking for dangling CNAMEs / takeover vulnerabilities...")
        takeover_findings = await self._check_takeovers(resolved_subdomains)
        findings.extend(takeover_findings)

        self._progress(on_progress, 85, "Auditing sensitive subdomains exposed...")
        sensitive_findings = self._audit_sensitive_subdomains(target, resolved_subdomains)
        findings.extend(sensitive_findings)

        self._progress(on_progress, 100, f"Found {len(resolved_subdomains)} active subdomains")

        return ModuleResult(
            module_name=self.name,
            mode=self.mode,
            status="success",
            data={
                "target": target,
                "total_discovered": len(discovered_names),
                "total_active": len(resolved_subdomains),
                "subdomains": resolved_subdomains,
            },
            findings=findings,
        )

    async def _query_crt_sh(self, domain: str) -> set[str]:
        """Query crt.sh Certificate Transparency logs via SSRF-safe safe_request."""
        subdomains = set()
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            resp = await safe_request("GET", url, timeout=15.0)
            if resp.status_code == 200:
                entries = resp.json()
                for item in entries:
                    name_value = item.get("name_value", "")
                    for line in name_value.split("\n"):
                        line = line.strip().lower()
                        if line.startswith("*."):
                            line = line[2:]
                        if line.endswith(domain) and line != domain and "*" not in line:
                            subdomains.add(line)
        except Exception:
            pass  # crt.sh can occasionally time out or be rate-limited
        return subdomains

    @classmethod
    def select_high_value_hosts(cls, subdomains: list[Any], target_domain: str) -> list[str]:
        """Select high-value hosts (www, about, team, careers, blog, press, investors, docs, support, app) from subdomain results."""
        base = target_domain.lower().strip().replace("https://", "").replace("http://", "").split("/")[0]
        if base.startswith("www."):
            base = base[4:]
        priority_map: dict[str, int] = {p: idx for idx, p in enumerate(HIGH_VALUE_OSINT_PREFIXES)}
        selected: dict[str, int] = {}

        for item in subdomains:
            host = item.get("subdomain", "") if isinstance(item, dict) else str(item)
            host = host.lower().strip().rstrip(".")
            if not host or (host != base and not host.endswith(f".{base}")):
                continue
            prefix = host[: -(len(base) + 1)] if host != base else ""
            top_label = prefix.split(".")[0] if prefix else ""
            if host == base:
                selected[host] = -1
            elif top_label in priority_map:
                selected[host] = priority_map[top_label]

        return [h for h, _ in sorted(selected.items(), key=lambda kv: (kv[1], kv[0]))]

    @classmethod
    async def discover_high_value_hosts(cls, target_domain: str) -> list[str]:
        """
        Return high-value OSINT hosts for target_domain, reusing cached SubdomainModule
        results when available or performing a quick CT/DNS lookup of OSINT prefixes.
        """
        base = target_domain.lower().strip().replace("https://", "").replace("http://", "").split("/")[0]
        if base.startswith("www."):
            base = base[4:]

        cached = _SUBDOMAIN_RESULTS_CACHE.get(base)
        if cached and (time.time() - cached[0]) < _SUBDOMAIN_CACHE_TTL:
            hosts = cls.select_high_value_hosts(cached[1], base)
            return hosts[:8]

        mod = cls()
        candidates = [f"{p}.{base}" for p in HIGH_VALUE_OSINT_PREFIXES]
        try:
            ct_hosts = await asyncio.wait_for(mod._query_crt_sh(base), timeout=5.0)
            for h in ct_hosts:
                prefix = h[: -(len(base) + 1)] if h.endswith(f".{base}") else ""
                if prefix.split(".")[0] in HIGH_VALUE_OSINT_PREFIXES and h not in candidates:
                    candidates.append(h)
        except Exception:
            pass

        try:
            resolved = await asyncio.wait_for(mod._resolve_subdomains(base, candidates[:20]), timeout=6.0)
            _SUBDOMAIN_RESULTS_CACHE[base] = (time.time(), list(resolved))
            return cls.select_high_value_hosts(resolved, base)[:8]
        except Exception:
            return [f"www.{base}", base]

    async def _resolve_subdomains(
        self,
        target: str,
        candidates: list[str],
    ) -> list[dict[str, Any]]:
        """Resolve A, AAAA, and CNAME records for discovered candidate subdomains."""
        semaphore = asyncio.Semaphore(15)
        active_subdomains: list[dict[str, Any]] = []

        async def _resolve_one(subdomain: str):
            async with semaphore:
                ips = []
                cnames = []
                # Check A
                try:
                    a_ans = await self.resolver.resolve(subdomain, "A")
                    ips.extend([str(r) for r in a_ans])
                except Exception:
                    pass

                # Check AAAA
                try:
                    aaaa_ans = await self.resolver.resolve(subdomain, "AAAA")
                    ips.extend([str(r) for r in aaaa_ans])
                except Exception:
                    pass

                # Check CNAME
                try:
                    cname_ans = await self.resolver.resolve(subdomain, "CNAME")
                    cnames.extend([str(r.target).rstrip(".") for r in cname_ans])
                except Exception:
                    pass

                if ips or cnames:
                    active_subdomains.append({
                        "subdomain": subdomain,
                        "ips": list(set(ips)),
                        "cnames": cnames,
                        "is_root": subdomain == target,
                    })

        tasks = [_resolve_one(cand) for cand in candidates]
        await asyncio.gather(*tasks)

        # Sort with root/www first, then alphabetically
        active_subdomains.sort(key=lambda s: s["subdomain"])
        return active_subdomains

    async def _check_takeovers(
        self,
        subdomains: list[dict[str, Any]],
    ) -> list[ModuleFinding]:
        """Check if any subdomains have dangling CNAME pointers to claimable services."""
        findings: list[ModuleFinding] = []

        async def _probe_takeover(item: dict[str, Any]):
            subdomain = item["subdomain"]
            for cname in item.get("cnames", []):
                for suffix, sig in TAKEOVER_SIGNATURES.items():
                    if cname.endswith(suffix):
                        # CNAME points to a known cloud provider. Probe HTTP response via safe_request.
                        try:
                            resp = await safe_request("GET", f"http://{subdomain}", timeout=6.0)
                            if sig["fingerprint"].lower() in resp.text.lower():
                                    findings.append(
                                        ModuleFinding(
                                            severity=sig["severity"],
                                            title=f"Potential Subdomain Takeover ({sig['service']})",
                                            description=(
                                                f"Subdomain {subdomain} has a CNAME pointing to {cname} ({sig['service']}), "
                                                f"and returned an unclaimed signature '{sig['fingerprint']}'. "
                                                f"An attacker may claim this resource to hijack the domain."
                                            ),
                                            remediation=f"Remove the dangling CNAME record for {subdomain} in DNS or re-claim the resource on {sig['service']}.",
                                        )
                                    )
                        except Exception:
                            pass

        await asyncio.gather(*[_probe_takeover(item) for item in subdomains])
        return findings

    def _audit_sensitive_subdomains(
        self,
        target: str,
        subdomains: list[dict[str, Any]],
    ) -> list[ModuleFinding]:
        """Flag publicly accessible sensitive environments like dev, staging, vpn, or admin."""
        findings: list[ModuleFinding] = []
        sensitive_keywords = {
            "dev": "Development environment publicly accessible",
            "staging": "Staging environment publicly accessible",
            "test": "Test server publicly accessible",
            "admin": "Administrative portal publicly resolvable",
            "vpn": "Internal VPN portal discovered",
            "intranet": "Internal intranet portal discovered",
            "db": "Database host exposed via public DNS",
            "git": "Version control or internal repo subdomain exposed",
        }

        exposed_sensitive = []
        for item in subdomains:
            name = item["subdomain"].lower()
            prefix = name.replace(f".{target}", "")
            for kw, reason in sensitive_keywords.items():
                if kw in prefix.split("."):
                    exposed_sensitive.append((item["subdomain"], reason))

        for sub, reason in exposed_sensitive[:5]:  # Cap to top 5
            findings.append(
                ModuleFinding(
                    severity=FindingSeverity.MEDIUM if "dev" in sub or "staging" in sub or "admin" in sub else FindingSeverity.LOW,
                    title=f"Sensitive Subdomain Exposed: {sub}",
                    description=f"{reason} at {sub}. Pre-production environments often lack production-grade hardening or contain debug endpoints.",
                    remediation="Restrict access to private IP ranges, place behind an authenticated SSO/VPN, or decommission public DNS records.",
                )
            )

        return findings
