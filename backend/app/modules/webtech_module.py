# =============================================================================
# FootprintHub — Web Technology & Security Headers Module
# =============================================================================
# Detects web servers, CMS, frontend frameworks, analytics, and conducts
# an audit of HTTP security headers (HSTS, CSP, X-Frame-Options) and cookie flags.
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

SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security (HSTS)",
        "severity": FindingSeverity.HIGH,
        "description": "Missing HSTS header allows protocol downgrade and man-in-the-middle attacks.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to response headers.",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy (CSP)",
        "severity": FindingSeverity.HIGH,
        "description": "Missing Content-Security-Policy leaves the application vulnerable to Cross-Site Scripting (XSS) and data injection.",
        "remediation": "Define a robust Content-Security-Policy specifying trusted sources for scripts, styles, and frames.",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": FindingSeverity.MEDIUM,
        "description": "Missing X-Frame-Options allows attackers to frame this page and execute Clickjacking attacks.",
        "remediation": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'.",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": FindingSeverity.LOW,
        "description": "Missing 'X-Content-Type-Options: nosniff' allows MIME-sniffing attacks.",
        "remediation": "Add 'X-Content-Type-Options: nosniff' header to all HTTP responses.",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": FindingSeverity.LOW,
        "description": "Missing Referrer-Policy may inadvertently leak sensitive query parameters or URL paths to external sites.",
        "remediation": "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "severity": FindingSeverity.INFO,
        "description": "Missing Permissions-Policy leaves browser features (camera, microphone, geolocation) unconstrained.",
        "remediation": "Specify a Permissions-Policy restricting access to sensitive browser APIs.",
    },
}

FRAMEWORK_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes", r"xmlrpc\.php"],
    "Drupal": [r"drupal\.js", r"/sites/default/files"],
    "Joomla": [r"/media/system/js", r"joomla"],
    "Next.js": [r"/_next/static", r"__NEXT_DATA__"],
    "Nuxt.js": [r"/_nuxt/", r"__NUXT__"],
    "React": [r"data-reactroot", r"react\.production\.min\.js"],
    "Vue.js": [r"vue\.min\.js", r"data-v-"],
    "Angular": [r"ng-version", r"angular\.min\.js"],
    "jQuery": [r"jquery[\.\-\d]*\.js", r"jquery"],
    "Bootstrap": [r"bootstrap[\.\-\d]*\.(css|js)"],
    "Tailwind CSS": [r"tailwind"],
    "Laravel": [r"laravel", r"XSRF-TOKEN"],
    "Django": [r"csrftoken", r"django"],
}


class WebTechModule(BaseModule):
    """
    Web Technology & HTTP Security Header Reconnaissance Module.
    """

    name: str = "web_tech"
    description: str = "Web server fingerprinting, CMS/framework detection, security headers and cookie audit"
    mode: ModuleMode = ModuleMode.PASSIVE
    timeout: int = 45

    async def run(
        self,
        target: str,
        on_progress: Optional[ProgressCallback] = None,
    ) -> ModuleResult:
        findings: list[ModuleFinding] = []
        data: dict[str, Any] = {
            "target": target,
            "status_code": None,
            "final_url": None,
            "server": None,
            "powered_by": None,
            "technologies": [],
            "security_headers": {},
            "cookies": [],
        }

        self._progress(on_progress, 15, "Fetching web headers and page content...")
        resp_text = ""
        resp_headers = {}
        cookies_list = []

        # Probe HTTPS first, then fallback to HTTP
        for scheme in ["https", "http"]:
            url = f"{scheme}://{target}"
            try:
                async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
                    resp = await client.get(url, headers={"User-Agent": "FootprintHub-Recon/1.0"})
                    data["status_code"] = resp.status_code
                    data["final_url"] = str(resp.url)
                    resp_text = resp.text
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                    cookies_list = list(resp.cookies.items())
                    break
            except Exception:
                continue

        if not resp_headers:
            findings.append(
                ModuleFinding(
                    severity=FindingSeverity.INFO,
                    title="Web Server Unreachable via HTTP/HTTPS",
                    description=f"Could not establish HTTP/HTTPS connection to {target}.",
                    remediation="Verify whether a web service is intended to run on standard ports 80/443.",
                )
            )
            return ModuleResult(
                module_name=self.name,
                mode=self.mode,
                status="success",
                data=data,
                findings=findings,
            )

        self._progress(on_progress, 40, "Auditing server tokens and information disclosure...")
        server = resp_headers.get("server")
        if server:
            data["server"] = server
            if re.search(r"[\d\.]+", server):
                findings.append(
                    ModuleFinding(
                        severity=FindingSeverity.LOW,
                        title=f"Server Version Disclosed: {server}",
                        description=f"The web server returned detailed version information '{server}', which aids attackers in fingerprinting known CVEs.",
                        remediation="Configure the web server to suppress granular version banners (e.g. ServerTokens Prod in Apache or server_tokens off in Nginx).",
                    )
                )

        powered_by = resp_headers.get("x-powered-by")
        if powered_by:
            data["powered_by"] = powered_by
            findings.append(
                ModuleFinding(
                    severity=FindingSeverity.LOW,
                    title=f"X-Powered-By Header Exposed: {powered_by}",
                    description=f"The application leaks the underlying backend technology through the X-Powered-By header: {powered_by}.",
                    remediation="Disable or remove the X-Powered-By header in application or framework settings.",
                )
            )

        self._progress(on_progress, 60, "Auditing HTTP security headers...")
        for header_key, meta in SECURITY_HEADERS.items():
            present = header_key in resp_headers
            data["security_headers"][header_key] = {
                "name": meta["name"],
                "present": present,
                "value": resp_headers.get(header_key),
            }
            if not present:
                findings.append(
                    ModuleFinding(
                        severity=meta["severity"],
                        title=f"Missing Security Header: {meta['name']}",
                        description=meta["description"],
                        remediation=meta["remediation"],
                    )
                )

        self._progress(on_progress, 75, "Inspecting cookies for security flags...")
        set_cookie_raw = resp_headers.get("set-cookie", "")
        if set_cookie_raw:
            for cookie_str in set_cookie_raw.split(","):
                c_lower = cookie_str.lower()
                c_name = cookie_str.split("=")[0].strip() if "=" in cookie_str else "cookie"
                c_secure = "secure" in c_lower
                c_httponly = "httponly" in c_lower
                c_samesite = "samesite" in c_lower

                data["cookies"].append({
                    "name": c_name,
                    "secure": c_secure,
                    "httponly": c_httponly,
                    "samesite": c_samesite,
                })

                if not c_secure:
                    findings.append(
                        ModuleFinding(
                            severity=FindingSeverity.MEDIUM,
                            title=f"Cookie '{c_name}' Missing 'Secure' Flag",
                            description="Cookies transmitted without the Secure flag can be intercepted in cleartext over unencrypted HTTP.",
                            remediation="Ensure the 'Secure' attribute is set on all session and sensitive cookies.",
                        )
                    )
                if not c_httponly:
                    findings.append(
                        ModuleFinding(
                            severity=FindingSeverity.MEDIUM,
                            title=f"Cookie '{c_name}' Missing 'HttpOnly' Flag",
                            description="Cookies lacking HttpOnly can be accessed by malicious client-side JavaScript during XSS attacks.",
                            remediation="Enable the 'HttpOnly' flag for authentication tokens and sensitive state cookies.",
                        )
                    )

        self._progress(on_progress, 90, "Fingerprinting CMS, frameworks and libraries...")
        detected_tech = set()

        # Check headers
        for tech, patterns in FRAMEWORK_SIGNATURES.items():
            for p in patterns:
                for h_val in resp_headers.values():
                    if re.search(p, str(h_val), re.IGNORECASE):
                        detected_tech.add(tech)

        # Check HTML content
        if resp_text:
            soup = BeautifulSoup(resp_text[:100000], "html.parser")
            # Check meta generator
            gen = soup.find("meta", attrs={"name": "generator"})
            if gen and gen.get("content"):
                data["generator"] = gen.get("content")
                detected_tech.add(gen.get("content"))

            # Check script tags & DOM
            for tech, patterns in FRAMEWORK_SIGNATURES.items():
                for p in patterns:
                    if re.search(p, resp_text[:100000], re.IGNORECASE):
                        detected_tech.add(tech)

        data["technologies"] = list(detected_tech)

        self._progress(on_progress, 100, f"Detected {len(detected_tech)} technology stack components")

        return ModuleResult(
            module_name=self.name,
            mode=self.mode,
            status="success",
            data=data,
            findings=findings,
        )
