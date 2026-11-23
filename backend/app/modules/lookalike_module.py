# =============================================================================
# FootprintHub — Lookalike Domain & Brand Protection Module
# =============================================================================
# Generates brand permutations (typos, homoglyphs/IDN, TLD swaps, hyphenation,
# and bit-flips) and checks for active registration, Mail Exchange (MX) presence,
# and recent creation (< 30 days) for defensive brand protection.
# =============================================================================

import asyncio
from datetime import datetime, timezone
import re
from typing import Any, Optional
import httpx

try:
    import dns.asyncresolver
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

from app.modules.base import (
    BaseModule,
    FindingConfidence,
    FindingSeverity,
    ModuleFinding,
    ModuleMode,
    ModuleResult,
    ProgressCallback,
)
from app.modules.osint_helpers import RDAPService


# Keyboard adjacency map for QWERTY typos
QWERTY_NEIGHBORS = {
    "q": ["w", "a", "s"],
    "w": ["q", "e", "a", "s", "d"],
    "e": ["w", "r", "s", "d", "f"],
    "r": ["e", "t", "d", "f", "g"],
    "t": ["r", "y", "f", "g", "h"],
    "y": ["t", "u", "g", "h", "j"],
    "u": ["y", "i", "h", "j", "k"],
    "i": ["u", "o", "j", "k", "l"],
    "o": ["i", "p", "k", "l"],
    "p": ["o", "l"],
    "a": ["q", "w", "s", "z"],
    "s": ["a", "w", "e", "d", "x", "z"],
    "d": ["s", "e", "r", "f", "c", "x"],
    "f": ["d", "r", "t", "g", "v", "c"],
    "g": ["f", "t", "y", "h", "b", "v"],
    "h": ["g", "y", "u", "j", "n", "b"],
    "j": ["h", "u", "i", "k", "m", "n"],
    "k": ["j", "i", "o", "l", "m"],
    "l": ["k", "o", "p"],
    "z": ["a", "s", "x"],
    "x": ["z", "s", "d", "c"],
    "c": ["x", "d", "f", "v"],
    "v": ["c", "f", "g", "b"],
    "b": ["v", "g", "h", "n"],
    "n": ["b", "h", "j", "m"],
    "m": ["n", "j", "k"],
}

# Homoglyph substitution map (Latin to Cyrillic / visual lookalikes)
HOMOGLYPH_MAP = {
    "a": ["\u0430"],  # Cyrillic small letter a
    "c": ["\u0441"],  # Cyrillic small letter es
    "e": ["\u0435"],  # Cyrillic small letter ie
    "i": ["1", "l"],
    "l": ["1", "i"],
    "o": ["0", "\u043e"],  # 0 or Cyrillic small letter o
    "p": ["\u0440"],  # Cyrillic small letter er
    "s": ["5"],
    "x": ["\u0445"],  # Cyrillic small letter ha
    "y": ["\u0443"],  # Cyrillic small letter u
}

COMMON_TLDS = [
    "com", "net", "org", "co", "io", "in", "biz", "info",
    "online", "xyz", "security", "app", "tech", "site",
]


class LookalikeGenerator:
    """Generates defensive brand permutations across multiple squatted vectors."""

    @classmethod
    def generate(cls, domain: str, max_candidates: int = 40) -> list[dict[str, str]]:
        clean = domain.lower().strip()
        parts = clean.split(".")
        if len(parts) < 2:
            return []

        name = parts[0]
        original_tld = ".".join(parts[1:])
        buckets: dict[str, list[str]] = {
            "TLD Swap": [],
            "Hyphenation": [],
            "Homoglyph (IDN)": [],
            "Typo (Keyboard)": [],
            "Omission": [],
            "Transposition": [],
            "Repetition": [],
            "Bitsquatting": [],
        }

        def add_cand(cand_domain: str, p_type: str):
            if cand_domain != clean and cand_domain not in buckets[p_type]:
                buckets[p_type].append(cand_domain)

        # 1. TLD Swaps
        for tld in COMMON_TLDS:
            if tld != original_tld:
                add_cand(f"{name}.{tld}", "TLD Swap")

        # 2. Hyphenation
        if len(name) > 3:
            mid = len(name) // 2
            add_cand(f"{name[:mid]}-{name[mid:]}.{original_tld}", "Hyphenation")
            add_cand(f"{name}-security.{original_tld}", "Hyphenation")
            add_cand(f"{name}-login.{original_tld}", "Hyphenation")
            add_cand(f"secure-{name}.{original_tld}", "Hyphenation")

        # 3. Homoglyphs
        for i, char in enumerate(name):
            if char in HOMOGLYPH_MAP:
                for alt in HOMOGLYPH_MAP[char]:
                    homo_name = name[:i] + alt + name[i+1:]
                    try:
                        puny = homo_name.encode("idna").decode("ascii")
                        add_cand(f"{puny}.{original_tld}", "Homoglyph (IDN)")
                    except Exception:
                        pass

        # 4. Character Omission
        for i in range(len(name)):
            if len(name) > 3:
                omitted = name[:i] + name[i+1:]
                add_cand(f"{omitted}.{original_tld}", "Omission")

        # 5. Adjacent Character Transposition
        for i in range(len(name) - 1):
            transposed = name[:i] + name[i+1] + name[i] + name[i+2:]
            add_cand(f"{transposed}.{original_tld}", "Transposition")

        # 6. Adjacent Keyboard Typos
        for i, char in enumerate(name):
            if char in QWERTY_NEIGHBORS:
                for alt in QWERTY_NEIGHBORS[char][:2]:
                    typo = name[:i] + alt + name[i+1:]
                    add_cand(f"{typo}.{original_tld}", "Typo (Keyboard)")

        # 7. Double character repetition
        for i, char in enumerate(name):
            repeated = name[:i] + char + char + name[i+1:]
            add_cand(f"{repeated}.{original_tld}", "Repetition")

        # 8. Bit-flips (Bitsquatting)
        for i, char in enumerate(name[:6]):
            byte_val = ord(char)
            for bit in [1, 2, 4, 8, 16]:
                flipped = byte_val ^ bit
                if 97 <= flipped <= 122:  # a-z
                    flipped_name = name[:i] + chr(flipped) + name[i+1:]
                    add_cand(f"{flipped_name}.{original_tld}", "Bitsquatting")

        # Round-robin selection across buckets to ensure balanced representation
        final_list: list[dict[str, str]] = []
        seen_domains: set[str] = set()

        max_per_round = max(len(lst) for lst in buckets.values()) if any(buckets.values()) else 0
        for r in range(max_per_round):
            for b_type, b_domains in buckets.items():
                if r < len(b_domains):
                    d = b_domains[r]
                    if d not in seen_domains:
                        seen_domains.add(d)
                        final_list.append({"domain": d, "type": b_type})
                        if len(final_list) >= max_candidates:
                            return final_list

        return final_list[:max_candidates]


class LookalikeModule(BaseModule):
    """
    Lookalike Domain and Brand Protection Module.
    Generates permutations, identifies live lookalikes via DNS, checks MX capability,
    and detects recent registrations (< 30 days). Defensive use only.
    """

    name: str = "lookalike"
    description: str = "Brand protection, lookalike domain permutation, phishing readiness (MX) check, and recent registration audit"
    mode: ModuleMode = ModuleMode.PASSIVE
    timeout: int = 60

    async def run(
        self,
        target: str,
        on_progress: Optional[ProgressCallback] = None,
    ) -> ModuleResult:
        findings: list[ModuleFinding] = []
        base_domain = target.lower().strip()
        if base_domain.startswith("www."):
            base_domain = base_domain[4:]

        self._progress(on_progress, 10, f"Generating brand lookalike permutations for {base_domain}...")
        candidates = LookalikeGenerator.generate(base_domain, max_candidates=45)

        self._progress(on_progress, 25, f"Checking DNS resolution for {len(candidates)} candidate domains...")

        semaphore = asyncio.Semaphore(15)
        live_domains: list[dict[str, Any]] = []

        async def _check_candidate(cand: dict[str, str]):
            domain_name = cand["domain"]
            cand_type = cand["type"]

            async with semaphore:
                resolved_ips: list[str] = []
                mx_records: list[str] = []
                is_live = False

                if HAS_DNS:
                    resolver = dns.asyncresolver.Resolver()
                    resolver.timeout = 2.0
                    resolver.lifetime = 2.0

                    # 1. A / AAAA
                    try:
                        ans = await resolver.resolve(domain_name, "A")
                        for rdata in ans:
                            resolved_ips.append(str(rdata))
                            is_live = True
                    except Exception:
                        pass

                    if not is_live:
                        try:
                            ans = await resolver.resolve(domain_name, "AAAA")
                            for rdata in ans:
                                resolved_ips.append(str(rdata))
                                is_live = True
                        except Exception:
                            pass

                    # 2. MX check
                    try:
                        ans_mx = await resolver.resolve(domain_name, "MX")
                        for rdata in ans_mx:
                            mx_records.append(str(rdata.exchange).rstrip("."))
                    except Exception:
                        pass
                else:
                    # Fallback to getaddrinfo
                    try:
                        loop = asyncio.get_event_loop()
                        infos = await asyncio.wait_for(
                            loop.getaddrinfo(domain_name, None),
                            timeout=2.0
                        )
                        for item in infos:
                            ip = item[4][0]
                            if ip not in resolved_ips:
                                resolved_ips.append(ip)
                        if resolved_ips:
                            is_live = True
                    except Exception:
                        pass

                if is_live or mx_records:
                    entry = {
                        "domain": domain_name,
                        "type": cand_type,
                        "ips": resolved_ips,
                        "mx_records": mx_records,
                        "has_mx": bool(mx_records),
                        "registered": True,
                        "registered_date": None,
                        "is_recently_registered": False,
                        "age_days": None,
                    }
                    live_domains.append(entry)

        # Concurrently resolve candidates
        await asyncio.gather(*[_check_candidate(c) for c in candidates])

        self._progress(on_progress, 65, f"Auditing registration metadata for {len(live_domains)} registered lookalikes...")

        # For live lookalikes, fetch RDAP registration dates to identify recent registrations
        async with httpx.AsyncClient(timeout=4.0) as client:
            for item in live_domains[:10]:
                try:
                    rdap_res = await RDAPService.query_rdap(item["domain"], client=client)
                    if reg_date_str := rdap_res.get("registered_date"):
                        item["registered_date"] = reg_date_str
                        try:
                            # Parse ISO date
                            clean_date = reg_date_str.split("T")[0]
                            reg_dt = datetime.strptime(clean_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)
                            age_days = (now - reg_dt).days
                            item["age_days"] = age_days
                            if 0 <= age_days <= 30:
                                item["is_recently_registered"] = True
                        except Exception:
                            pass
                except Exception:
                    pass

        self._progress(on_progress, 85, "Synthesizing brand protection findings...")

        # Generate findings for live domains
        for live in live_domains:
            d_name = live["domain"]
            p_type = live["type"]
            has_mx = live["has_mx"]
            is_recent = live["is_recently_registered"]
            age_days = live.get("age_days")

            # High severity: MX record configured (phishing capable)
            if has_mx:
                mx_str = ", ".join(live["mx_records"][:3])
                findings.append(
                    ModuleFinding(
                        severity=FindingSeverity.HIGH,
                        confidence=FindingConfidence.CONFIRMED,
                        evidence=f"Domain {d_name} has active MX servers: {mx_str} (resolves to {', '.join(live['ips'][:2])})",
                        title=f"Phishing-Capable Lookalike Domain with Active Mail Exchange (MX): {d_name}",
                        description=(
                            f"The lookalike domain '{d_name}' ({p_type}) is registered and has active MX records "
                            f"({mx_str}), allowing it to send and receive emails. Attackers can leverage this domain "
                            f"for executive impersonation, vendor invoice fraud, or credential phishing."
                        ),
                        remediation=(
                            "Monitor domain activity, configure email gateway DMARC/anti-spoofing policies, "
                            "consider registering the defensive domain, or report brand infringement to the hosting registrar."
                        ),
                    )
                )

            # High severity: Recently registered lookalike domain
            if is_recent:
                findings.append(
                    ModuleFinding(
                        severity=FindingSeverity.HIGH,
                        confidence=FindingConfidence.CONFIRMED,
                        evidence=f"Domain {d_name} registered on {live.get('registered_date')} (~{age_days} days ago)",
                        title=f"Recently Registered Brand Lookalike Domain (< 30 days): {d_name}",
                        description=(
                            f"The lookalike domain '{d_name}' was registered approximately {age_days} days ago. "
                            "Recently registered lookalikes represent a high probability of impending phishing or brand attack infrastructure."
                        ),
                        remediation="Add this domain to external threat feeds, proxy blocklists, and submit takedown notices.",
                    )
                )

            # Medium/Low finding for any active resolving lookalike without MX
            if not has_mx and not is_recent:
                findings.append(
                    ModuleFinding(
                        severity=FindingSeverity.LOW,
                        confidence=FindingConfidence.LIKELY,
                        evidence=f"Resolves to IP(s): {', '.join(live['ips'][:3])}",
                        title=f"Active Lookalike Domain Detected: {d_name} ({p_type})",
                        description=(
                            f"The lookalike domain '{d_name}' ({p_type}) resolves to public IP addresses ({', '.join(live['ips'][:2])}). "
                            "While no MX records are currently advertised, this asset could be weaponized for visual brand impersonation."
                        ),
                        remediation="Audit the hosted content on this lookalike and evaluate defensive trademark enforcement.",
                    )
                )

        self._progress(on_progress, 100, f"Lookalike domain analysis completed: {len(live_domains)} registered lookalike(s) found.")

        return ModuleResult(
            module_name=self.name,
            mode=self.mode,
            status="success",
            data={
                "target": target,
                "domain": base_domain,
                "total_permutations_tested": len(candidates),
                "total_registered_lookalikes": len(live_domains),
                "phishing_capable_count": sum(1 for d in live_domains if d["has_mx"]),
                "recently_registered_count": sum(1 for d in live_domains if d["is_recently_registered"]),
                "live_lookalikes": live_domains,
                "disclaimer": "Defensive use only. Lookalike analysis identifies brand spoofing and phishing infrastructure targeting your organization.",
            },
            findings=findings,
        )
