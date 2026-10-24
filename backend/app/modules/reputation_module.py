# =============================================================================
# FootprintHub — Domain Reputation & Blacklist Module
# =============================================================================
# Checks domain & IP against major DNSBL blacklists (Spamhaus, SURBL, Barracuda),
# VirusTotal, and Google Safe Browsing threat intelligence feeds.
# =============================================================================

import asyncio
from typing import Any, Optional
import dns.asyncresolver
import httpx

from app.config import settings
from app.modules.base import (
    BaseModule,
    FindingSeverity,
    ModuleFinding,
    ModuleMode,
    ModuleResult,
    ProgressCallback,
)

DNSBL_SERVERS = [
    {"name": "Spamhaus ZEN", "zone": "zen.spamhaus.org"},
    {"name": "SURBL", "zone": "multi.surbl.org"},
    {"name": "Spamcop", "zone": "bl.spamcop.net"},
    {"name": "Barracuda", "zone": "b.barracudacentral.org"},
]


class ReputationModule(BaseModule):
    """
    Domain & IP Reputation and Blacklist Verification Module.
    """

    name: str = "reputation"
    description: str = "DNSBL blacklist auditing (Spamhaus, SURBL), VirusTotal, and Google Safe Browsing lookups"
    mode: ModuleMode = ModuleMode.PASSIVE
    timeout: int = 40

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
        blacklist_results: list[dict[str, Any]] = []

        self._progress(on_progress, 15, "Resolving target IP for DNSBL blacklist queries...")
        ip = None
        try:
            answers = await self.resolver.resolve(target, "A")
            if answers:
                ip = str(answers[0])
        except Exception:
            pass

        # 1. DNSBL checks
        if ip and ":" not in ip:
            self._progress(on_progress, 30, f"Querying DNSBL servers for IP {ip}...")
            # Reverse IP: 1.2.3.4 -> 4.3.2.1
            octets = ip.split(".")
            reversed_ip = ".".join(reversed(octets))

            async def _check_dnsbl(entry: dict):
                query_name = f"{reversed_ip}.{entry['zone']}"
                try:
                    ans = await self.resolver.resolve(query_name, "A")
                    if ans:
                        code = str(ans[0])
                        blacklist_results.append({
                            "name": entry["name"],
                            "listed": True,
                            "response": code,
                        })
                        findings.append(
                            ModuleFinding(
                                severity=FindingSeverity.HIGH,
                                title=f"Blacklisted on {entry['name']}",
                                description=f"Host IP {ip} is actively listed on {entry['name']} blacklist ({code}). Mail and web traffic may be blocked.",
                                remediation=f"Investigate spam/malware activity on host and submit delisting request at {entry['name']}.",
                            )
                        )
                except Exception:
                    blacklist_results.append({
                        "name": entry["name"],
                        "listed": False,
                        "response": None,
                    })

            await asyncio.gather(*[_check_dnsbl(s) for s in DNSBL_SERVERS])
        else:
            for s in DNSBL_SERVERS:
                blacklist_results.append({"name": s["name"], "listed": False, "response": None})

        # 2. VirusTotal API
        vt_key = getattr(settings, "VIRUSTOTAL_API_KEY", None)
        vt_data = None
        if vt_key:
            self._progress(on_progress, 65, "Querying VirusTotal domain report...")
            try:
                headers = {"x-apikey": vt_key}
                async with httpx.AsyncClient(timeout=8.0) as client:
                    resp = await client.get(f"https://www.virustotal.com/api/v3/domains/{target}", headers=headers)
                    if resp.status_code == 200:
                        attrs = resp.json().get("data", {}).get("attributes", {})
                        stats = attrs.get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0)
                        suspicious = stats.get("suspicious", 0)
                        vt_data = stats

                        if malicious > 0:
                            findings.append(
                                ModuleFinding(
                                    severity=FindingSeverity.CRITICAL,
                                    title=f"Flagged as Malicious on VirusTotal ({malicious} vendor detections)",
                                    description=f"{target} is flagged as malicious by {malicious} antivirus and security vendors.",
                                    remediation="Review website for compromised files, unauthorized redirects, or phishing hosting.",
                                )
                            )
            except Exception:
                pass

        # 3. Google Safe Browsing
        gsb_key = getattr(settings, "GOOGLE_SAFE_BROWSING_API_KEY", None)
        gsb_status = "clean"
        if gsb_key:
            self._progress(on_progress, 85, "Querying Google Safe Browsing API...")
            try:
                payload = {
                    "client": {"clientId": "footprinthub", "clientVersion": "1.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": f"https://{target}/"}],
                    },
                }
                async with httpx.AsyncClient(timeout=8.0) as client:
                    resp = await client.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gsb_key}", json=payload)
                    if resp.status_code == 200:
                        matches = resp.json().get("matches", [])
                        if matches:
                            gsb_status = "unsafe"
                            threat_type = matches[0].get("threatType", "MALWARE")
                            findings.append(
                                ModuleFinding(
                                    severity=FindingSeverity.CRITICAL,
                                    title=f"Flagged by Google Safe Browsing: {threat_type}",
                                    description=f"Google Safe Browsing flags {target} as {threat_type}. Browsers will display red warning interstitials to visitors.",
                                    remediation="Identify and remove the malicious content, then request a malware review via Google Search Console.",
                                )
                            )
            except Exception:
                pass

        self._progress(on_progress, 100, "Reputation and blacklist analysis completed")

        return ModuleResult(
            module_name=self.name,
            mode=self.mode,
            status="success",
            data={
                "target": target,
                "ip": ip,
                "blacklists": blacklist_results,
                "virustotal": vt_data,
                "google_safe_browsing": gsb_status,
            },
            findings=findings,
        )
