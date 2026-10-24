# =============================================================================
# FootprintHub — IP & Network Reconnaissance Module
# =============================================================================
# Discovers target IPs, Geolocation, ASN, ISP, PTR reverse lookups,
# and detects Cloud/CDN/WAF providers (Cloudflare, Akamai, Fastly, AWS, etc.).
# =============================================================================

import asyncio
import socket
from typing import Any, Optional

import dns.asyncresolver
import dns.reversename
import httpx

from app.modules.base import (
    BaseModule,
    FindingSeverity,
    ModuleFinding,
    ModuleMode,
    ModuleResult,
    ProgressCallback,
)

# Known CDN / WAF provider signatures (by ASN, org keywords, or reverse DNS)
CDN_WAF_SIGNATURES = [
    {
        "provider": "Cloudflare",
        "type": "CDN / WAF / DDoS Protection",
        "asns": [13335, 209242],
        "keywords": ["cloudflare"],
        "cname_keywords": ["cloudflare.net"],
    },
    {
        "provider": "Amazon CloudFront",
        "type": "CDN",
        "asns": [16509],
        "keywords": ["cloudfront", "amazon"],
        "cname_keywords": ["cloudfront.net"],
    },
    {
        "provider": "Fastly",
        "type": "CDN / WAF",
        "asns": [54113],
        "keywords": ["fastly"],
        "cname_keywords": ["fastly.net"],
    },
    {
        "provider": "Akamai",
        "type": "CDN / WAF",
        "asns": [16625, 20940, 35994],
        "keywords": ["akamai", "prolexic"],
        "cname_keywords": ["akamai.net", "akamaiedge.net"],
    },
    {
        "provider": "Imperva / Incapsula",
        "type": "WAF / DDoS Protection",
        "asns": [19551],
        "keywords": ["incapsula", "imperva"],
        "cname_keywords": ["incapdns.net"],
    },
    {
        "provider": "Microsoft Azure Front Door",
        "type": "CDN / WAF",
        "asns": [8075],
        "keywords": ["microsoft", "azure"],
        "cname_keywords": ["azureedge.net", "trafficmanager.net"],
    },
    {
        "provider": "Google Cloud Armor / CDN",
        "type": "Cloud / WAF",
        "asns": [15169, 396982],
        "keywords": ["google"],
        "cname_keywords": ["ghs.googlehosted.com"],
    },
]


class IPNetworkModule(BaseModule):
    """
    IP & Network reconnaissance module.
    """

    name: str = "ip_network"
    description: str = "IP resolution, Geolocation, ASN, ISP, PTR records, and CDN/WAF detection"
    mode: ModuleMode = ModuleMode.PASSIVE
    timeout: int = 45

    def __init__(self):
        super().__init__()
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.timeout = 4.0
        self.resolver.lifetime = 6.0
        self.resolver.nameservers = ["1.1.1.1", "8.8.8.8"]

    async def run(
        self,
        target: str,
        on_progress: Optional[ProgressCallback] = None,
    ) -> ModuleResult:
        findings: list[ModuleFinding] = []
        ip_addresses: list[str] = []
        ipv6_addresses: list[str] = []

        self._progress(on_progress, 15, "Resolving target IPv4 and IPv6 addresses...")
        # Resolve A
        try:
            a_records = await self.resolver.resolve(target, "A")
            ip_addresses = [str(r) for r in a_records]
        except Exception:
            pass

        # Resolve AAAA
        try:
            aaaa_records = await self.resolver.resolve(target, "AAAA")
            ipv6_addresses = [str(r) for r in aaaa_records]
        except Exception:
            pass

        if not ip_addresses and not ipv6_addresses:
            findings.append(
                ModuleFinding(
                    severity=FindingSeverity.HIGH,
                    title="Domain Unresolvable to IP",
                    description=f"Neither A nor AAAA records could be resolved for {target}.",
                    remediation="Verify DNS hosting configurations and ensure valid A/AAAA records exist.",
                )
            )

        if ip_addresses and not ipv6_addresses:
            findings.append(
                ModuleFinding(
                    severity=FindingSeverity.INFO,
                    title="No IPv6 (AAAA) Support",
                    description=f"{target} only resolves to IPv4 addresses. IPv6 adoption improves connectivity and performance.",
                    remediation="Consider configuring IPv6 AAAA records alongside IPv4 for modern network compatibility.",
                )
            )

        all_ips = ip_addresses + ipv6_addresses

        self._progress(on_progress, 40, f"Looking up ASN and Geolocation for {len(all_ips)} IP(s)...")
        network_data: list[dict[str, Any]] = []
        detected_cdns: set[str] = set()

        for ip in all_ips:
            ip_info = await self._lookup_ip(ip)
            network_data.append(ip_info)

            # Check CDN/WAF match
            cdn_match = self._match_cdn_waf(ip_info)
            if cdn_match:
                detected_cdns.add(cdn_match)

        self._progress(on_progress, 80, "Checking reverse DNS (PTR) records...")
        for item in network_data:
            ptr = await self._lookup_ptr(item["ip"])
            item["ptr"] = ptr

        self._progress(on_progress, 90, "Evaluating network perimeter security...")
        if detected_cdns:
            cdn_list = ", ".join(detected_cdns)
            findings.append(
                ModuleFinding(
                    severity=FindingSeverity.INFO,
                    title=f"WAF / CDN Detected: {cdn_list}",
                    description=f"Target {target} is proxied behind {cdn_list}. Origin IP address is masked by proxy infrastructure.",
                    remediation="Ensure origin web server firewall rejects direct connections not originating from CDN edge IP blocks.",
                )
            )
        else:
            findings.append(
                ModuleFinding(
                    severity=FindingSeverity.LOW,
                    title="No WAF or Cloud CDN Protection Detected",
                    description=f"The domain resolves directly to hosting infrastructure without an intermediary CDN or Web Application Firewall.",
                    remediation="Consider deploying a reverse-proxy CDN or cloud WAF (e.g. Cloudflare, CloudFront, Fastly) to mitigate DDoS and web attacks.",
                )
            )

        self._progress(on_progress, 100, "IP & Network reconnaissance completed")

        return ModuleResult(
            module_name=self.name,
            mode=self.mode,
            status="success",
            data={
                "target": target,
                "ipv4_count": len(ip_addresses),
                "ipv6_count": len(ipv6_addresses),
                "detected_cdns": list(detected_cdns),
                "networks": network_data,
            },
            findings=findings,
        )

    async def _lookup_ip(self, ip: str) -> dict[str, Any]:
        """Lookup IP Geolocation, ASN, and organization details via public RDAP / IP API."""
        result: dict[str, Any] = {
            "ip": ip,
            "version": 6 if ":" in ip else 4,
            "country": "Unknown",
            "country_code": None,
            "city": "Unknown",
            "region": None,
            "org": "Unknown",
            "isp": "Unknown",
            "asn": None,
            "as_name": None,
            "latitude": None,
            "longitude": None,
        }

        # Query ip-api.com (free, non-commercial endpoints with fallback)
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,query"
            async with httpx.AsyncClient(timeout=6.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    d = resp.json()
                    if d.get("status") == "success":
                        as_field = d.get("as", "")
                        asn_num = None
                        if as_field.startswith("AS"):
                            parts = as_field.split(" ", 1)
                            try:
                                asn_num = int(parts[0][2:])
                            except ValueError:
                                pass
                        result.update({
                            "country": d.get("country"),
                            "country_code": d.get("countryCode"),
                            "city": d.get("city"),
                            "region": d.get("regionName"),
                            "org": d.get("org"),
                            "isp": d.get("isp"),
                            "asn": asn_num,
                            "as_name": as_field,
                            "latitude": d.get("lat"),
                            "longitude": d.get("lon"),
                        })
                        return result
        except Exception:
            pass

        return result

    async def _lookup_ptr(self, ip: str) -> Optional[str]:
        """Perform reverse DNS query for an IP."""
        try:
            rev_name = dns.reversename.from_address(ip)
            answers = await self.resolver.resolve(rev_name, "PTR")
            if answers:
                return str(answers[0]).rstrip(".")
        except Exception:
            pass
        return None

    def _match_cdn_waf(self, ip_info: dict[str, Any]) -> Optional[str]:
        """Check if an IP matches known CDN/WAF providers."""
        asn = ip_info.get("asn")
        isp_org = f"{ip_info.get('isp', '')} {ip_info.get('org', '')} {ip_info.get('as_name', '')}".lower()

        for sig in CDN_WAF_SIGNATURES:
            if asn and asn in sig["asns"]:
                return f"{sig['provider']} ({sig['type']})"
            for kw in sig["keywords"]:
                if kw in isp_org:
                    return f"{sig['provider']} ({sig['type']})"

        return None
