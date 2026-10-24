# =============================================================================
# FootprintHub — Content & Information Disclosure Module
# =============================================================================
# Discovers robots.txt, sitemap.xml, security.txt (RFC 9116), extracts
# developer comments, and audits common sensitive paths (.git, .env, backups).
# =============================================================================

import re
from typing import Any, Optional
from bs4 import BeautifulSoup
import httpx

from app.modules.base import (
    BaseModule,
    FindingSeverity,
    ModuleFinding,
    ModuleMode,
    ModuleResult,
    ProgressCallback,
)

SENSITIVE_PATHS = [
    {
        "path": "/.git/HEAD",
        "signature": "ref: refs/",
        "title": "Git Repository Exposed (.git/HEAD)",
        "severity": FindingSeverity.CRITICAL,
        "description": "The .git repository is publicly accessible, allowing attackers to download the full source code and commit history.",
        "remediation": "Block web server access to all hidden directories starting with '.' (e.g. location ~ /\\.git { deny all; }).",
    },
    {
        "path": "/.env",
        "signature": "DB_PASSWORD",
        "alt_signatures": ["APP_KEY=", "DATABASE_URL=", "SECRET_KEY="],
        "title": "Environment Secrets File Exposed (.env)",
        "severity": FindingSeverity.CRITICAL,
        "description": "A .env configuration file is publicly exposed, leaking database credentials, API keys, and private secrets.",
        "remediation": "Move .env files outside of the web server document root and restrict web access immediately.",
    },
    {
        "path": "/actuator/env",
        "signature": "activeProfiles",
        "title": "Spring Boot Actuator Exposed (/actuator/env)",
        "severity": FindingSeverity.HIGH,
        "description": "Spring Boot actuator environment endpoint is publicly accessible without authentication.",
        "remediation": "Secure or disable Spring Boot Actuator endpoints in application.properties (management.endpoints.web.exposure.exclude=*).",
    },
    {
        "path": "/phpinfo.php",
        "signature": "PHP Version",
        "title": "PHP Info File Publicly Accessible (/phpinfo.php)",
        "severity": FindingSeverity.MEDIUM,
        "description": "A phpinfo diagnostic file is exposed, disclosing PHP configuration, extensions, environment variables, and module paths.",
        "remediation": "Delete phpinfo.php from production environments.",
    },
    {
        "path": "/.DS_Store",
        "signature": "\x00\x00\x00\x01Bud1",
        "title": "macOS .DS_Store Metadata File Exposed",
        "severity": FindingSeverity.LOW,
        "description": "A .DS_Store file is exposed, disclosing internal file and folder structures to attackers.",
        "remediation": "Remove .DS_Store files and block access via web server rules.",
    },
]


class ContentModule(BaseModule):
    """
    Content, Metadata, and Sensitive File Discovery Module.
    """

    name: str = "content"
    description: str = "robots.txt, sitemap.xml, security.txt, HTML comment scraping, and sensitive endpoint audit"
    mode: ModuleMode = ModuleMode.PASSIVE
    timeout: int = 50

    async def run(
        self,
        target: str,
        on_progress: Optional[ProgressCallback] = None,
    ) -> ModuleResult:
        findings: list[ModuleFinding] = []
        data: dict[str, Any] = {
            "target": target,
            "robots_txt": None,
            "disallowed_paths": [],
            "sitemap_found": False,
            "sitemap_url": None,
            "security_txt": None,
            "interesting_comments": [],
            "exposed_paths": [],
        }

        base_url = f"https://{target}"

        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, verify=False) as client:
            # 1. robots.txt
            self._progress(on_progress, 15, "Checking robots.txt...")
            try:
                resp = await client.get(f"{base_url}/robots.txt")
                if resp.status_code == 200 and "user-agent" in resp.text.lower():
                    data["robots_txt"] = resp.text[:5000]
                    disallowed = []
                    for line in resp.text.split("\n"):
                        if line.lower().startswith("disallow:"):
                            parts = line.split(":", 1)
                            if len(parts) > 1 and parts[1].strip():
                                disallowed.append(parts[1].strip())
                    data["disallowed_paths"] = disallowed[:50]

                    # Check for juicy paths in robots.txt
                    juicy_keywords = ["admin", "backup", "secret", "internal", "config", "api/v", "private"]
                    for path in disallowed:
                        if any(kw in path.lower() for kw in juicy_keywords):
                            findings.append(
                                ModuleFinding(
                                    severity=FindingSeverity.LOW,
                                    title=f"Sensitive Path Disclosed in robots.txt: {path}",
                                    description=f"robots.txt disallows '{path}', which advertises sensitive locations to attackers.",
                                    remediation="Enforce authentication and access controls at the application level rather than relying on robots.txt.",
                                )
                            )
                            break
            except Exception:
                pass

            # 2. sitemap.xml
            self._progress(on_progress, 35, "Checking sitemap.xml...")
            try:
                resp = await client.get(f"{base_url}/sitemap.xml")
                if resp.status_code == 200 and ("<urlset" in resp.text or "<sitemapindex" in resp.text):
                    data["sitemap_found"] = True
                    data["sitemap_url"] = f"{base_url}/sitemap.xml"
            except Exception:
                pass

            # 3. security.txt (RFC 9116)
            self._progress(on_progress, 50, "Checking security.txt (RFC 9116)...")
            sec_found = False
            for sec_path in ["/.well-known/security.txt", "/security.txt"]:
                try:
                    resp = await client.get(f"{base_url}{sec_path}")
                    if resp.status_code == 200 and "contact:" in resp.text.lower():
                        data["security_txt"] = resp.text[:2000]
                        sec_found = True
                        break
                except Exception:
                    pass

            if not sec_found:
                findings.append(
                    ModuleFinding(
                        severity=FindingSeverity.INFO,
                        title="Missing security.txt (RFC 9116)",
                        description=f"No security.txt found at {base_url}/.well-known/security.txt. Security researchers have no standard channel to report vulnerabilities.",
                        remediation="Create a /.well-known/security.txt file defining Contact, Policy, and Encryption keys as recommended by RFC 9116.",
                    )
                )

            # 4. Homepage HTML comments extraction
            self._progress(on_progress, 70, "Extracting developer comments from HTML...")
            try:
                resp = await client.get(base_url)
                if resp.status_code == 200:
                    soup = BeautifulSoup(resp.text[:100000], "html.parser")
                    comments = soup.find_all(string=lambda text: isinstance(text, type(soup.comment)) if hasattr(soup, "comment") else False)
                    # Regex fallback for HTML comments
                    raw_comments = re.findall(r"<!--(.*?)-->", resp.text[:100000], re.DOTALL)
                    interesting = []
                    keywords = ["todo", "fixme", "password", "user", "secret", "ip", "internal", "test", "debug"]
                    for c in raw_comments:
                        c_clean = c.strip()
                        if len(c_clean) > 5:
                            if any(kw in c_clean.lower() for kw in keywords):
                                interesting.append(c_clean[:120])

                    data["interesting_comments"] = interesting[:10]
                    if interesting:
                        findings.append(
                            ModuleFinding(
                                severity=FindingSeverity.LOW,
                                title=f"Developer Comments Disclosed in HTML ({len(interesting)} found)",
                                description="HTML source code contains comments with development notes, TODOs, or internal identifiers.",
                                remediation="Strip out developer comments during the frontend production build pipeline.",
                            )
                        )
            except Exception:
                pass

            # 5. Sensitive endpoints audit
            self._progress(on_progress, 85, "Auditing common sensitive paths...")
            for test_case in SENSITIVE_PATHS:
                try:
                    probe_url = f"{base_url}{test_case['path']}"
                    resp = await client.get(probe_url)
                    if resp.status_code == 200:
                        content = resp.text
                        sig_matched = test_case["signature"] in content
                        if not sig_matched and "alt_signatures" in test_case:
                            sig_matched = any(sig in content for sig in test_case["alt_signatures"])

                        if sig_matched:
                            data["exposed_paths"].append(test_case["path"])
                            findings.append(
                                ModuleFinding(
                                    severity=test_case["severity"],
                                    title=test_case["title"],
                                    description=test_case["description"],
                                    remediation=test_case["remediation"],
                                )
                            )
                except Exception:
                    continue

        self._progress(on_progress, 100, "Content reconnaissance completed")

        return ModuleResult(
            module_name=self.name,
            mode=self.mode,
            status="success",
            data=data,
            findings=findings,
        )
