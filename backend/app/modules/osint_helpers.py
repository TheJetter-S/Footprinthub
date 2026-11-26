# =============================================================================
# FootprintHub — OSINT Helper Classes & Intelligence Engines
# =============================================================================
# Social media extraction from target websites, corporate metadata & JSON-LD
# parsing, LinkedIn company & employee intelligence, team/founder discovery,
# GitHub public API reconnaissance, and corporate digital footprint aggregation.
# =============================================================================

import asyncio
import hashlib
import html
import json
import re
import urllib.parse
from typing import Any, Optional

from bs4 import BeautifulSoup
import httpx

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


class SocialMediaScraper:
    """Extracts social media profile links from target website HTML and JS bundles."""

    PLATFORMS: dict[str, list[str]] = {
        "LinkedIn": [
            r"https?://(?:[a-z0-9-]+\.)?linkedin\.com/company/[a-zA-Z0-9_.-]+",
            r"https?://(?:[a-z0-9-]+\.)?linkedin\.com/in/[a-zA-Z0-9_.-]+",
            r"https?://(?:[a-z0-9-]+\.)?linkedin\.com/school/[a-zA-Z0-9_.-]+",
        ],
        "GitHub": [
            r"https?://(?:www\.)?github\.com/[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)?",
        ],
        "Twitter / X": [
            r"https?://(?:www\.)?(?:twitter\.com|x\.com)/[a-zA-Z0-9_]+",
        ],
        "Facebook": [
            r"https?://(?:[a-z0-9-]+\.)?(?:facebook\.com|fb\.com)/people/[a-zA-Z0-9._-]+/[0-9]+",
            r"https?://(?:[a-z0-9-]+\.)?(?:facebook\.com|fb\.com)/pages/[a-zA-Z0-9._-]+/[0-9]+",
            r"https?://(?:[a-z0-9-]+\.)?(?:facebook\.com|fb\.com)/[a-zA-Z0-9._-]+",
        ],
        "Instagram": [
            r"https?://(?:www\.)?instagram\.com/[a-zA-Z0-9._-]+",
        ],
        "YouTube": [
            r"https?://(?:www\.)?youtube\.com/(?:c/|channel/|user/|@)[a-zA-Z0-9_.-]+",
            r"https?://(?:www\.)?youtube\.com/[a-zA-Z0-9_.-]+",
            r"https?://youtu\.be/[a-zA-Z0-9_-]+",
        ],
        "TikTok": [
            r"https?://(?:www\.)?tiktok\.com/@[a-zA-Z0-9._]+",
        ],
        "Pinterest": [
            r"https?://(?:[a-z0-9-]+\.)?pinterest\.(?:com|in|co\.uk|ca|de|fr|au)/[a-zA-Z0-9_.-]+",
        ],
        "Discord": [
            r"https?://(?:www\.)?discord\.(?:gg|com/invite)/[a-zA-Z0-9_-]+",
        ],
        "Telegram": [
            r"https?://(?:www\.)?t\.me/[a-zA-Z0-9_]+",
        ],
        "WhatsApp": [
            r"https?://(?:api\.)?whatsapp\.com/send\?phone=[0-9]+",
            r"https?://wa\.me/[0-9+]+",
        ],
        "Crunchbase": [
            r"https?://(?:www\.)?crunchbase\.com/organization/[a-zA-Z0-9_-]+",
        ],
        "Medium": [
            r"https?://(?:www\.)?medium\.com/@[a-zA-Z0-9._-]+",
        ],
        "Reddit": [
            r"https?://(?:www\.)?reddit\.com/r/[a-zA-Z0-9_-]+",
        ],
    }

    EXCLUDED_SLUGS: set[str] = {
        "share", "sharer", "sharer.php", "intent", "login", "signup", "help",
        "about", "privacy", "terms", "policy", "legal", "home", "explore",
        "settings", "search", "hashtag", "watch", "feed", "notifications",
        "messages", "jobs", "learning", "events", "groups", "marketplace",
        "gaming", "features", "download", "status", "blog", "press",
        "developers", "security", "trending", "topics", "company", "in",
        "school", "pub", "channel", "user", "c", "r", "follow", "profile",
        "people", "pages", "tr", "2008", "embed", "v", "plugins",
    }

    VENDOR_NOISE_PATHS: tuple[str, ...] = (
        "github.com/facebook/", "github.com/reactjs/", "github.com/remix-run/",
        "github.com/vercel/", "github.com/tailwindlabs/", "github.com/radix-ui/",
        "github.com/lucide-icons/", "github.com/axios/", "github.com/tc39/",
        "github.com/w3c/", "github.com/whatwg/", "github.com/vitejs/",
        "twitter.com/intent", "x.com/intent", "facebook.com/tr",
    )

    PLATFORM_ICONS: dict[str, str] = {
        "LinkedIn": "💼",
        "GitHub": "🐙",
        "Twitter / X": "🐦",
        "Facebook": "📘",
        "Instagram": "📸",
        "YouTube": "▶️",
        "TikTok": "🎵",
        "Pinterest": "📌",
        "Discord": "💬",
        "Telegram": "✈️",
        "WhatsApp": "💬",
        "Crunchbase": "📊",
        "Medium": "✍️",
        "Reddit": "🟠",
    }

    @classmethod
    def extract_social_links(cls, html_text: str) -> list[dict[str, Any]]:
        """Extract social media profile links from collected HTML/JS content, including JSON and unescaped payloads."""
        clean_text = html_text.replace(r"\/", "/")
        try:
            clean_text = html.unescape(clean_text)
        except Exception:
            pass

        all_urls: set[str] = set()
        # Standard hrefs
        all_urls.update(re.findall(r'href=["\']([^"\']+)["\']', clean_text))
        # Quoted URLs inside scripts / JSON / Vite JS objects (e.g. "url":"https://...", to:"https://...")
        all_urls.update(re.findall(r'["\'](https?://[^"\']+)["\']', clean_text))
        # Plain URLs in text
        all_urls.update(re.findall(r'https?://[^\s<>"\'\\()\[\]{},]+', clean_text))

        profiles: list[dict[str, Any]] = []
        seen: set[str] = set()

        for url in all_urls:
            # Keep WhatsApp query parameter ?phone=..., strip tracking params elsewhere
            if "whatsapp.com/send" in url.lower():
                url_clean = url.rstrip("/").split("#")[0]
            else:
                url_clean = url.rstrip("/").split("?")[0].split("#")[0]
            if len(url_clean) < 12:
                continue

            lower_u = url_clean.lower()
            if any(noise in lower_u for noise in cls.VENDOR_NOISE_PATHS):
                continue

            for platform, patterns in cls.PLATFORMS.items():
                matched = False
                for pattern in patterns:
                    m = re.match(pattern, url_clean, re.IGNORECASE)
                    if m:
                        matched_url = m.group(0).rstrip("/")
                        # Skip multi-segment GitHub paths unless it's just the org/user root
                        if platform == "GitHub":
                            gh_parts = re.sub(r"^https?://(?:www\.)?github\.com/", "", matched_url, flags=re.I).split("/")
                            if len(gh_parts) > 1:
                                # Keep org root for GitHub API org lookup, skip library repo subpaths
                                matched = True
                                break
                            handle = gh_parts[0]
                        elif platform == "Facebook" and ("/people/" in matched_url.lower() or "/pages/" in matched_url.lower()):
                            fb_parts = matched_url.split("/")
                            handle = fb_parts[-2] if len(fb_parts) >= 2 else fb_parts[-1]
                        else:
                            parts = matched_url.split("/")
                            handle = parts[-1] if parts else ""

                        if handle.startswith("@"):
                            handle = handle[1:]
                        if "phone=" in handle:
                            handle = handle.split("phone=")[-1]

                        if (
                            handle.lower() in cls.EXCLUDED_SLUGS
                            or not handle
                            or len(handle) < 2
                        ):
                            matched = True
                            break

                        dedup_key = f"{platform}:{handle.lower()}"
                        if dedup_key in seen:
                            matched = True
                            break
                        seen.add(dedup_key)

                        # Classify the profile type
                        profile_type = "profile"
                        if "/company/" in matched_url.lower():
                            profile_type = "company"
                        elif "/in/" in matched_url.lower():
                            profile_type = "personal"
                        elif "/organization/" in matched_url.lower():
                            profile_type = "organization"
                        elif "/r/" in matched_url.lower():
                            profile_type = "subreddit"
                        elif "/channel/" in matched_url.lower() or (platform == "YouTube" and "/@" in matched_url.lower()):
                            profile_type = "channel"

                        profiles.append(
                            {
                                "platform": platform,
                                "handle": handle,
                                "url": matched_url,
                                "type": profile_type,
                                "icon": cls.PLATFORM_ICONS.get(platform, "🔗"),
                                "found_on_website": True,
                            }
                        )
                        matched = True
                        break
                if matched:
                    break

        return profiles

    # ── GitHub Public API Intelligence ────────────────────────────────────

    @classmethod
    async def gather_github_intelligence(
        cls,
        github_handle: str,
        client: httpx.AsyncClient,
        github_token: Optional[str] = None,
    ) -> dict[str, Any]:
        """Query the GitHub public API for organization or user intelligence."""
        headers: dict[str, str] = {
            "User-Agent": "FootprintHub-OSINT",
            "Accept": "application/vnd.github.v3+json",
        }
        if github_token:
            headers["Authorization"] = f"Bearer {github_token}"

        intel: dict[str, Any] = {
            "handle": github_handle,
            "type": None,
            "profile": {},
            "members": [],
            "top_repos": [],
        }

        try:
            # Try as organization first
            resp = await client.get(
                f"https://api.github.com/orgs/{github_handle}",
                headers=headers,
                timeout=8.0,
            )
            if resp.status_code == 200:
                org = resp.json()
                intel["type"] = "organization"
                intel["profile"] = {
                    "name": org.get("name") or github_handle,
                    "description": org.get("description"),
                    "blog": org.get("blog"),
                    "location": org.get("location"),
                    "email": org.get("email"),
                    "public_repos": org.get("public_repos", 0),
                    "followers": org.get("followers", 0),
                    "avatar_url": org.get("avatar_url"),
                    "created_at": (org.get("created_at") or "")[:10],
                    "html_url": org.get("html_url"),
                    "twitter_username": org.get("twitter_username"),
                }

                # Get public members (up to 8 to respect rate limits)
                try:
                    members_resp = await client.get(
                        f"https://api.github.com/orgs/{github_handle}/public_members?per_page=15",
                        headers=headers,
                        timeout=8.0,
                    )
                    if members_resp.status_code == 200:
                        member_logins = members_resp.json()[:8]
                        member_tasks = [
                            client.get(
                                f"https://api.github.com/users/{m['login']}",
                                headers=headers,
                                timeout=5.0,
                            )
                            for m in member_logins
                        ]
                        member_results = await asyncio.gather(
                            *member_tasks, return_exceptions=True
                        )
                        for mr in member_results:
                            if (
                                isinstance(mr, httpx.Response)
                                and mr.status_code == 200
                            ):
                                m_data = mr.json()
                                intel["members"].append(
                                    {
                                        "login": m_data.get("login"),
                                        "name": m_data.get("name") or m_data.get("login"),
                                        "bio": m_data.get("bio"),
                                        "company": m_data.get("company"),
                                        "location": m_data.get("location"),
                                        "email": m_data.get("email"),
                                        "avatar_url": m_data.get("avatar_url"),
                                        "html_url": m_data.get("html_url"),
                                        "public_repos": m_data.get("public_repos", 0),
                                        "followers": m_data.get("followers", 0),
                                        "twitter": m_data.get("twitter_username"),
                                    }
                                )
                except Exception:
                    pass

                # Get top repositories
                try:
                    repos_resp = await client.get(
                        f"https://api.github.com/orgs/{github_handle}/repos?sort=stars&direction=desc&per_page=10",
                        headers=headers,
                        timeout=8.0,
                    )
                    if repos_resp.status_code == 200:
                        for r in repos_resp.json():
                            intel["top_repos"].append(
                                {
                                    "name": r.get("name"),
                                    "description": r.get("description"),
                                    "stars": r.get("stargazers_count", 0),
                                    "forks": r.get("forks_count", 0),
                                    "language": r.get("language"),
                                    "html_url": r.get("html_url"),
                                    "updated_at": (r.get("updated_at") or "")[:10],
                                }
                            )
                except Exception:
                    pass

            else:
                # Try as individual user
                resp = await client.get(
                    f"https://api.github.com/users/{github_handle}",
                    headers=headers,
                    timeout=8.0,
                )
                if resp.status_code == 200:
                    user = resp.json()
                    intel["type"] = "user"
                    intel["profile"] = {
                        "name": user.get("name") or github_handle,
                        "bio": user.get("bio"),
                        "company": user.get("company"),
                        "blog": user.get("blog"),
                        "location": user.get("location"),
                        "email": user.get("email"),
                        "public_repos": user.get("public_repos", 0),
                        "followers": user.get("followers", 0),
                        "avatar_url": user.get("avatar_url"),
                        "created_at": (user.get("created_at") or "")[:10],
                        "html_url": user.get("html_url"),
                        "twitter": user.get("twitter_username"),
                    }
        except Exception:
            pass

        return intel


class ContactMetadataExtractor:
    """Extracts telephone numbers and street addresses from crawled website content."""

    PHONE_REGEX = re.compile(
        r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b"
    )

    @classmethod
    def extract_phone_numbers(
        cls,
        html_text: str,
        plain_text: Optional[str] = None,
    ) -> list[dict[str, str]]:
        phones = []
        seen = set()
        for m in re.finditer(r'href=[\'"]tel:([^\'"]+)[\'"]', html_text, re.IGNORECASE):
            raw = m.group(1).strip()
            clean = re.sub(r"[^\d+]", "", raw)
            if clean and clean not in seen and len(clean) >= 7:
                seen.add(clean)
                phones.append({"number": raw, "type": "tel_link"})

        if plain_text is None:
            soup = BeautifulSoup(html_text, "html.parser")
            text = soup.get_text(separator=" ")
        else:
            text = plain_text
        for match in cls.PHONE_REGEX.finditer(text):
            num = match.group(0).strip()
            digits = re.sub(r"\D", "", num)
            if 7 <= len(digits) <= 15 and digits not in seen:
                seen.add(digits)
                phones.append({"number": num, "type": "text_mention"})
        return phones

    @classmethod
    def extract_physical_addresses(
        cls,
        html_text: str,
        soup: Optional[Any] = None,
    ) -> list[dict[str, Any] | str]:
        addresses = []
        if soup is None:
            soup = BeautifulSoup(html_text, "html.parser")
        for script in soup.find_all("script", type="application/ld+json"):
            try:
                data = json.loads(script.string or "")
                if isinstance(data, dict):
                    if data.get("@type") == "PostalAddress":
                        addresses.append(data)
                    elif "address" in data and isinstance(data["address"], dict):
                        addresses.append(data["address"])
            except Exception:
                pass

        for addr in soup.find_all("address"):
            txt = addr.get_text(strip=True)
            if txt and len(txt) > 10:
                addresses.append(txt)

        return addresses


class RDAPService:
    """Passively queries IANA/RIR RDAP bootstrap service for official domain registration metadata."""

    BOOTSTRAP_URL = "https://rdap.org/domain/"

    @classmethod
    async def query_rdap(
        cls, domain: str, client: Optional[httpx.AsyncClient] = None
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "domain": domain,
            "registrar": None,
            "registered_date": None,
            "expiration_date": None,
            "status": [],
            "nameservers": [],
        }
        url = f"{cls.BOOTSTRAP_URL}{domain}"
        close_client = False
        if client is None:
            client = httpx.AsyncClient(timeout=10.0, follow_redirects=True)
            close_client = True

        try:
            resp = await client.get(url, headers={"Accept": "application/rdap+json, application/json"})
            if resp.status_code == 200:
                data = resp.json()
                result["domain"] = data.get("ldhName") or domain
                result["status"] = data.get("status") or []

                for entity in data.get("entities", []):
                    if "registrar" in entity.get("roles", []):
                        vcard = entity.get("vcardArray")
                        if vcard and len(vcard) > 1:
                            for item in vcard[1]:
                                if len(item) > 3 and item[0] == "fn":
                                    result["registrar"] = item[3]
                                    break
                    if result["registrar"]:
                        break

                for event in data.get("events", []):
                    action = event.get("eventAction", "")
                    date_val = event.get("eventDate", "")
                    if action in ("registration", "registered") and not result["registered_date"]:
                        result["registered_date"] = date_val
                    elif action in ("expiration", "expires") and not result["expiration_date"]:
                        result["expiration_date"] = date_val

                for ns in data.get("nameservers", []):
                    ns_name = ns.get("ldhName")
                    if ns_name:
                        result["nameservers"].append(ns_name)
        except Exception:
            pass
        finally:
            if close_client:
                await client.aclose()

        return result


class SecretPatternScanner:
    """
    Detects exposed API tokens, access keys, and credentials in public code and configs.
    CRITICAL SECURITY MANDATE:
    NEVER stores or displays the raw secret value; all secret values are strictly masked!
    """

    PATTERNS = [
        {
            "name": "AWS Access Key ID",
            "regex": r"\b(AKIA[0-9A-Z]{16})\b",
            "mask": lambda m: m[:4] + "*" * 12 + m[-4:],
            "severity": "high",
        },
        {
            "name": "AWS Secret Access Key",
            "regex": r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
            "mask": lambda m: m[:3] + "*" * 34 + m[-3:],
            "severity": "critical",
        },
        {
            "name": "GitHub Personal Access Token",
            "regex": r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{30,})\b",
            "mask": lambda m: m[:4] + "*" * (len(m) - 8) + m[-4:],
            "severity": "high",
        },
        {
            "name": "Slack Token",
            "regex": r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b",
            "mask": lambda m: m[:4] + "*" * (len(m) - 8) + m[-4:],
            "severity": "high",
        },
        {
            "name": "Private Cryptographic Key",
            "regex": r"-----BEGIN (?:RSA|EC|DSA|OPENSSH)? PRIVATE KEY-----",
            "mask": lambda m: "[MASKED PRIVATE CRYPTOGRAPHIC KEY]",
            "severity": "critical",
        },
        {
            "name": "Generic Database Password / Secret",
            "regex": r"(?i)(?:db_password|database_url|api_secret|client_secret)\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]",
            "mask": lambda m: m[:2] + "*" * (len(m) - 4) + m[-2:],
            "severity": "high",
        },
    ]

    @classmethod
    def scan_content(cls, content: str, source_url: str = "") -> list[dict[str, Any]]:
        findings = []
        for p in cls.PATTERNS:
            for match in re.finditer(p["regex"], content):
                raw_match = match.group(1) if match.groups() else match.group(0)
                masked = p["mask"](raw_match)
                findings.append({
                    "secret_type": p["name"],
                    "masked_value": masked,
                    "source_url": source_url,
                    "severity": p["severity"],
                })
        return findings


class CodeLeakEngine:
    """
    Queries official public APIs and registries to identify public code repositories,
    container images, package registry publications, and Postman workspaces.
    """

    @classmethod
    async def search_leaks(
        cls,
        domain: str,
        company_name: str = "",
        client: Optional[httpx.AsyncClient] = None,
    ) -> dict[str, Any]:
        results: dict[str, Any] = {
            "github_repos": [],
            "gitlab_projects": [],
            "docker_hub_images": [],
            "npm_packages": [],
            "pypi_packages": [],
            "postman_workspaces": [],
            "detected_secrets": [],
        }
        term = company_name or domain.split(".")[0]
        close_client = False
        if client is None:
            client = httpx.AsyncClient(timeout=8.0, follow_redirects=True)
            close_client = True

        headers = {"User-Agent": "FootprintHub-CodeAudit"}

        try:
            # 1. GitHub public repositories search
            try:
                gh_resp = await client.get(
                    f"https://api.github.com/search/repositories?q={urllib.parse.quote(term)}&sort=stars&order=desc",
                    headers=headers,
                )
                if gh_resp.status_code == 200:
                    items = gh_resp.json().get("items", [])
                    for it in items[:10]:
                        desc = it.get("description") or ""
                        results["github_repos"].append({
                            "name": it.get("full_name"),
                            "url": it.get("html_url"),
                            "description": desc,
                            "stars": it.get("stargazers_count", 0),
                            "updated_at": it.get("updated_at"),
                        })
                        if desc:
                            secrets = SecretPatternScanner.scan_content(desc, it.get("html_url", ""))
                            results["detected_secrets"].extend(secrets)
            except Exception:
                pass

            # 2. GitLab public projects search
            try:
                gl_resp = await client.get(
                    f"https://gitlab.com/api/v4/projects?search={urllib.parse.quote(term)}&per_page=10",
                    headers=headers,
                )
                if gl_resp.status_code == 200:
                    for it in gl_resp.json()[:10]:
                        results["gitlab_projects"].append({
                            "name": it.get("name"),
                            "url": it.get("web_url"),
                            "description": it.get("description"),
                            "stars": it.get("star_count", 0),
                        })
            except Exception:
                pass

            # 3. Docker Hub public image search
            try:
                dh_resp = await client.get(
                    f"https://hub.docker.com/v2/search/repositories/?query={urllib.parse.quote(term)}&page_size=10",
                    headers=headers,
                )
                if dh_resp.status_code == 200:
                    for it in dh_resp.json().get("results", [])[:10]:
                        results["docker_hub_images"].append({
                            "name": it.get("repo_name"),
                            "description": it.get("short_description"),
                            "pull_count": it.get("pull_count", 0),
                        })
            except Exception:
                pass

            # 4. npm packages search
            try:
                npm_resp = await client.get(
                    f"https://registry.npmjs.org/-/v1/search?text={urllib.parse.quote(term)}&size=10",
                    headers=headers,
                )
                if npm_resp.status_code == 200:
                    for it in npm_resp.json().get("objects", [])[:10]:
                        pkg = it.get("package", {})
                        results["npm_packages"].append({
                            "name": pkg.get("name"),
                            "version": pkg.get("version"),
                            "description": pkg.get("description"),
                        })
            except Exception:
                pass

            # 5. PyPI package check
            try:
                pypi_resp = await client.get(
                    f"https://pypi.org/pypi/{urllib.parse.quote(term)}/json",
                    headers=headers,
                )
                if pypi_resp.status_code == 200:
                    info = pypi_resp.json().get("info", {})
                    results["pypi_packages"].append({
                        "name": info.get("name"),
                        "version": info.get("version"),
                        "summary": info.get("summary"),
                        "url": info.get("package_url"),
                    })
            except Exception:
                pass

            # 6. Postman public workspace footprint
            results["postman_workspaces"].append({
                "query": term,
                "url": f"https://www.postman.com/search?q={urllib.parse.quote(term)}&type=workspaces",
                "status": "query_ready",
            })

        finally:
            if close_client:
                await client.aclose()

        return results


class DomainOwnershipVerifier:
    """Verifies domain ownership prior to domain-wide credential breach searches."""

    @classmethod
    async def verify_ownership(
        cls,
        domain: str,
        client: Optional[httpx.AsyncClient] = None,
        token: Optional[str] = None,
    ) -> tuple[bool, str]:
        expected_token = token or "footprinthub-verification"
        close_client = False
        if client is None:
            client = httpx.AsyncClient(timeout=8.0, follow_redirects=True)
            close_client = True

        try:
            if HAS_DNS:
                try:
                    answers = dns.resolver.resolve(f"_footprinthub-challenge.{domain}", "TXT")
                    for rdata in answers:
                        txt_val = "".join([b.decode("utf-8", errors="ignore") for b in rdata.strings])
                        if expected_token in txt_val:
                            return True, f"Verified via DNS TXT record for {domain}"
                except Exception:
                    pass

            for scheme in ["https", "http"]:
                try:
                    url = f"{scheme}://{domain}/.well-known/footprinthub-verification.txt"
                    resp = await client.get(url)
                    if resp.status_code == 200 and expected_token in resp.text:
                        return True, f"Verified via HTTP file at {url}"
                except Exception:
                    pass

            return False, f"Unverified: No DNS challenge or /.well-known verification file detected for {domain}"

        finally:
            if close_client:
                await client.aclose()


class CompanyMetadataScraper:
    """
    Scrapes website HTML, meta tags, Schema.org JSON-LD, and team sections
    to extract corporate metadata, founders, executives, and employee data.
    """

    GENERIC_ANCHOR_TEXTS: set[str] = {
        "linkedin", "linkedin profile", "view on linkedin", "connect", "connect on linkedin",
        "follow", "view profile", "profile", "read more", "learn more", "click here", "link",
        "website", "here", "see more", "more", "contact", "about", "team", "meet the team",
        "our team", "social", "my linkedin",
    }

    @staticmethod
    def clean_slug_to_name(slug: str) -> str:
        """Convert a personal LinkedIn slug (e.g. 'john-doe-49a8b1') into a readable name."""
        clean = re.sub(r"-[a-f0-9]{5,}$", "", slug)
        parts = clean.split("-")
        return " ".join([p.title() for p in parts if p and not p.isdigit()])

    @staticmethod
    def _normalize_asset_url(src: Optional[str], domain: str) -> Optional[str]:
        """Convert relative or unescaped asset paths into properly encoded HTTPS URLs."""
        if not src:
            return None
        s = src.strip().replace(r"\/", "/")
        if not s or s.startswith("data:") or "${" in s or "placehold.co" in s:
            return None
        if s.startswith("//"):
            s = f"https:{s}"
        elif s.startswith("./"):
            s = f"https://{domain}/{s[2:]}"
        elif s.startswith("/"):
            s = f"https://{domain}{s}"
        elif not s.startswith("http"):
            s = f"https://{domain}/{s}"
        # Percent-encode spaces in asset paths cleanly
        try:
            parsed = urllib.parse.urlsplit(s)
            encoded_path = urllib.parse.quote(urllib.parse.unquote(parsed.path), safe="/@+-._~")
            return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, encoded_path, parsed.query, parsed.fragment))
        except Exception:
            return s.replace(" ", "%20")

    @classmethod
    def _extract_js_intelligence(
        cls, js_bundles: list[str], domain: str, company_name: str = ""
    ) -> dict[str, Any]:
        """
        Extracts structured team member objects, readable prose narratives,
        office/headquarters locations, contact numbers, and legal names from SPA JS bundles.
        """
        result: dict[str, Any] = {
            "team_objects": [],
            "prose_text": "",
            "addresses": [],
            "headquarters": "",
            "phones": [],
            "legal_name": "",
        }
        if not js_bundles:
            return result

        combined_js = "\n".join(js_bundles)
        prose_chunks: list[str] = []
        domain_root = domain.lower().replace("www.", "").split(".")[0]
        comp_low = (company_name or domain_root).lower().strip()

        # 1. Extract flat JS/JSON team objects containing `name` + role/title/linkedin/photo
        # Matches {...} blocks without nested braces up to 800 chars
        for obj_m in re.finditer(r"\{([^{}]{15,800})\}", combined_js):
            block = obj_m.group(1)
            # Reject customer testimonials / review cards
            if re.search(r'(?:^|[,;\s])"?(?:quote|testimonial|review|feedback|rating|stars|customer)"?\s*:', block, re.I):
                continue
            name_m = re.search(r'(?:^|[,;\s])"?name"?\s*:\s*["\']([^"\']{3,60})["\']', block)
            if not name_m:
                continue
            cand_name = name_m.group(1).strip()
            name_parts = cand_name.split()
            if len(name_parts) < 2 or len(name_parts) > 4:
                continue
            if not all(re.match(r"^[A-Z][a-zA-Z.'-]*$", p) for p in name_parts):
                continue

            role_m = re.search(
                r'(?:^|[,;\s])"?(?:role|title|designation|position|jobTitle|job_title)"?\s*:\s*["\']([^"\']{2,140})["\']',
                block,
            )
            raw_role = role_m.group(1).strip() if role_m else "Team Member"
            clean_role = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", raw_role)).strip()
            # Filter out external customer/partner roles such as "Founder & CEO, Digital by DV, Dubai"
            if "," in clean_role:
                trailing_org = clean_role.split(",", 1)[1].strip().lower()
                if trailing_org and domain_root not in trailing_org and comp_low not in trailing_org:
                    continue

            li_m = re.search(
                r'(?:^|[,;\s])"?(?:linkedin|linkedinUrl|linkedin_url|social|profileUrl)"?\s*:\s*["\'](https?://[^"\']*linkedin\.com/in/[^"\']+)["\']',
                block,
                re.I,
            )
            photo_m = re.search(
                r'(?:^|[,;\s])"?(?:photo|image|avatar|img|picture|photoUrl|avatarUrl|src)"?\s*:\s*["\']([^"\']+)["\']',
                block,
            )
            tag_m = re.search(
                r'(?:^|[,;\s])"?(?:tag|department|dept|team|category)"?\s*:\s*["\']([^"\']{2,50})["\']',
                block,
            )
            bio_m = re.search(
                r'(?:^|[,;\s])"?(?:bio|description|summary|about)"?\s*:\s*["\']([^"\']{15,500})["\']',
                block,
            )

            if role_m or li_m:
                result["team_objects"].append(
                    {
                        "name": cand_name,
                        "role": clean_role,
                        "linkedin": li_m.group(1).strip() if li_m else "",
                        "photo": cls._normalize_asset_url(photo_m.group(1), domain) if photo_m else None,
                        "tag": tag_m.group(1).strip() if tag_m else "",
                        "bio": re.sub(r"<[^>]+>", " ", bio_m.group(1)).strip() if bio_m else "",
                    }
                )

        # 2. Extract office / headquarters address objects from JS bundles
        for addr_obj_m in re.finditer(r"\{([^{}]{15,600})\}", combined_js):
            block = addr_obj_m.group(1)
            city_m = re.search(r'"?(?:city|location|office|title)"?\s*:\s*["\']([^"\']{2,80})["\']', block)
            addr_m = re.search(r'"?(?:address|street|locationAddress)"?\s*:\s*(?:["\']([^"\']{10,300})["\']|`([^`]{10,300})`)', block)
            if addr_m:
                addr_val = re.sub(r"\s+", " ", (addr_m.group(1) or addr_m.group(2) or "")).strip()
                city_val = city_m.group(1).strip() if city_m else ""
                if addr_val and addr_val not in result["addresses"]:
                    result["addresses"].append(addr_val)
                if city_val and any(hq in city_val.lower() for hq in ["headquarter", "head quarter", "hq", "main office"]):
                    hq_city = re.sub(r"\s*[-–—]\s*head\s*quarters?", "", city_val, flags=re.I).strip()
                    result["headquarters"] = f"{hq_city} ({addr_val[:90]})" if hq_city else addr_val[:120]
                elif not result["headquarters"] and city_val:
                    result["headquarters"] = city_val

        # 3. Extract tel: phone links from JS bundles
        for tel_m in re.finditer(r'["\']tel:([^"\']{7,25})["\']', combined_js, re.I):
            p_num = tel_m.group(1).strip()
            if p_num not in result["phones"]:
                result["phones"].append(p_num)

        # 4. Extract readable English prose string literals (to avoid regex matching minified code)
        for lit_m in re.finditer(r'(?:"([^"\\\n]{25,600})"|`([^`\\\n]{25,600})`)', combined_js):
            s = (lit_m.group(1) or lit_m.group(2) or "").strip()
            if not s or " " not in s:
                continue
            # Skip CSS rules, SVG paths, URLs, error/React internals
            if any(bad in s for bad in ["{", "}", "px ", "rgba(", "linear-gradient", "http://www.w3.org", "react.dev", "cubic-bezier", "box-shadow", "font-family"]):
                continue
            if re.match(r"^[MLCZHVQSTmlczhvqst0-9.,\s-]+$", s):
                continue
            if len(re.findall(r"[A-Za-z]{2,}", s)) >= 4:
                prose_chunks.append(s)

        result["prose_text"] = "\n".join(prose_chunks)

        # 5. Extract legal entity name matching target domain/company (e.g. "Zoho Communications Private Limited")
        for legal_m in re.finditer(
            r"\b([A-Z][A-Za-z0-9&.\s]{2,50}?\s+(?:Consulting\s+|Communications\s+)?(?:Pvt\.?\s*Ltd\.?|Private\s+Limited|Limited|Inc\.?|LLC|Corp\.?|Corporation))\b",
            result["prose_text"] + "\n" + combined_js[:80000],
        ):
            cand_legal = re.sub(r"\s+", " ", legal_m.group(1)).strip()
            if 2 <= len(cand_legal.split()) <= 7 and (domain_root in cand_legal.lower() or comp_low in cand_legal.lower()):
                if not any(bad in cand_legal.lower() for bad in ["copyright", "all rights", "apache", "mit "]):
                    result["legal_name"] = cand_legal
                    break

        return result

    @classmethod
    def extract_company_metadata(
        cls,
        html_text: str,
        domain: str,
        company_name: str,
        js_bundles: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """
        Parses all crawled website HTML and SPA JS bundles for company identity, description,
        founded year, headquarters, JSON-LD structured data, and team members.
        """
        html_clean = html_text.replace(r"\/", "/")
        try:
            html_clean = html.unescape(html_clean)
        except Exception:
            pass
        # Cap BeautifulSoup DOM size (homepage + priority about/team pages come first) to prevent >10s CPU stalls
        soup_html = html_clean[:2_500_000] if len(html_clean) > 2_500_000 else html_clean
        soup = BeautifulSoup(soup_html, "html.parser")

        js_list = list(js_bundles or [])
        ld_json_scripts: list[str] = []
        # Extract unescaped Next.js RSC / __NEXT_DATA__ payloads and JSON-LD scripts BEFORE decomposing <script>
        for sc in soup.find_all("script"):
            sc_type = str(sc.get("type") or "").lower()
            sc_txt = sc.string or sc.get_text() or ""
            if "ld+json" in sc_type and sc_txt:
                ld_json_scripts.append(sc_txt)
            if len(sc_txt) > 100 and any(marker in sc_txt for marker in ("__next_f", "__NEXT_DATA__", "__NUXT__", "__remixContext")):
                js_list.append(sc_txt.replace(r'\"', '"').replace(r"\/", "/"))

        # Extract physical addresses before decomposing <script type="application/ld+json">
        pre_addresses = ContactMetadataExtractor.extract_physical_addresses(soup_html, soup=soup)

        js_intel = cls._extract_js_intelligence(js_list, domain, company_name=company_name)
        js_prose = js_intel.get("prose_text", "")
        # Extract clean block-separated visible text and strip script/style/svg once (avoids re-parsing multi-MB HTML)
        for tag in soup(["script", "style", "noscript", "svg"]):
            tag.decompose()
        plain_html_text = re.sub(r"\n{3,}", "\n\n", soup.get_text("\n", strip=True))
        combined_readable = plain_html_text + ("\n" + js_prose if js_prose else "")

        meta: dict[str, Any] = {
            "name": company_name,
            "legal_name": js_intel.get("legal_name", ""),
            "description": "",
            "about_company": "",
            "industry": "Technology & Software",
            "founded_year": None,
            "founded_source": None,
            "headquarters": js_intel.get("headquarters", ""),
            "estimated_employees": "11-50 employees",
            "founders": [],
            "scraped_team": [],
            "json_ld_detected": False,
            "contact_emails": [],
            "phone_numbers": [],
            "addresses": list(js_intel.get("addresses", [])),
        }

        # Extract phone numbers from tel: links, JS tel: links, and on-page patterns (reusing plain_html_text)
        for p_num in js_intel.get("phones", []):
            if p_num and p_num not in meta["phone_numbers"]:
                meta["phone_numbers"].append(p_num)
        extracted_phones = ContactMetadataExtractor.extract_phone_numbers(html_clean, plain_text=plain_html_text)
        for p in extracted_phones:
            p_num = p["number"]
            if p_num and p_num not in meta["phone_numbers"]:
                meta["phone_numbers"].append(p_num)

        # Merge pre-extracted physical addresses
        for addr_item in pre_addresses:
            if addr_item not in meta["addresses"]:
                meta["addresses"].append(addr_item)
        if meta["addresses"] and not meta["headquarters"]:
            meta["headquarters"] = meta["addresses"][0]

        # 1. OpenGraph & Meta description
        og_site = soup.find("meta", property="og:site_name")
        if og_site and og_site.get("content"):
            meta["name"] = og_site["content"].strip()

        og_desc = (
            soup.find("meta", property="og:description")
            or soup.find("meta", attrs={"name": "description"})
            or soup.find("meta", attrs={"name": "twitter:description"})
        )
        if og_desc and og_desc.get("content"):
            meta["description"] = og_desc["content"].strip()

        # 1b. Extract About Company narrative from on-page sections or SPA JS prose
        heading_re = re.compile(
            rf"(?:about\s+(?:us|the\s+company|our\s+company|{re.escape(company_name.lower())})|our\s+story|who\s+we\s+are|what\s+we\s+do|our\s+mission)",
            re.I
        )
        for h in soup.find_all(["h1", "h2", "h3", "h4", "strong"]):
            txt = h.get_text(" ", strip=True)
            if heading_re.search(txt) and len(txt.split()) <= 6:
                curr = h.find_next_sibling(["p", "div"])
                if not curr:
                    parent = h.find_parent(["div", "section", "article"])
                    if parent:
                        curr = parent.find("p")
                if curr:
                    p_text = curr.get_text(" ", strip=True)
                    if len(p_text) > 40 and not any(b in p_text.lower() for b in ["cookie", "privacy policy", "terms of use", "all rights reserved"]):
                        meta["about_company"] = p_text
                        if not meta["description"] or len(meta["description"]) < 30:
                            meta["description"] = p_text
                        break
        if not meta["about_company"] and js_prose:
            for line in js_prose.splitlines():
                if any(kw in line.lower() for kw in ["was founded", "founded in", f"{company_name.lower()} is ", "proactive", "headquarter", "mission is"]) and 50 <= len(line) <= 450:
                    meta["about_company"] = line
                    if not meta["description"] or len(meta["description"]) < 30:
                        meta["description"] = line
                    break

        # 2. Schema.org JSON-LD parsing (with @graph support & Person parsing)
        for raw_json in ld_json_scripts:
            try:
                if not raw_json:
                    continue
                data = json.loads(raw_json)
                items: list[Any] = []
                if isinstance(data, list):
                    items.extend(data)
                elif isinstance(data, dict):
                    if "@graph" in data and isinstance(data["@graph"], list):
                        items.extend(data["@graph"])
                    items.append(data)

                for item in items:
                    if not isinstance(item, dict):
                        continue
                    schema_type = str(item.get("@type", ""))

                    # Organization / Corporation parsing
                    if any(
                        t in schema_type
                        for t in [
                            "Organization",
                            "Corporation",
                            "Company",
                            "LocalBusiness",
                            "EducationalOrganization",
                        ]
                    ):
                        meta["json_ld_detected"] = True
                        if item.get("name") and meta["name"] == company_name:
                            meta["name"] = str(item["name"]).strip()
                        if item.get("description") and not meta["description"]:
                            meta["description"] = str(item["description"]).strip()
                        if item.get("foundingDate"):
                            meta["founded_year"] = str(item["foundingDate"])[:4]
                        if item.get("numberOfEmployees"):
                            num_emp = item["numberOfEmployees"]
                            if isinstance(num_emp, dict):
                                meta["estimated_employees"] = str(num_emp.get("value", "50-200 employees"))
                            else:
                                meta["estimated_employees"] = f"{num_emp} employees"

                        # Parse address / headquarters
                        addr = item.get("address")
                        if isinstance(addr, dict):
                            parts = [
                                addr.get("addressLocality"),
                                addr.get("addressRegion"),
                                addr.get("addressCountry"),
                            ]
                            meta["headquarters"] = ", ".join([p for p in parts if p])
                        elif isinstance(addr, str):
                            meta["headquarters"] = addr

                        # Founders from Organization
                        f_raw = item.get("founder") or item.get("founders")
                        if f_raw:
                            f_list = f_raw if isinstance(f_raw, list) else [f_raw]
                            for f in f_list:
                                if isinstance(f, dict) and f.get("name"):
                                    f_name = str(f.get("name")).strip()
                                    f_url = f.get("url") or f.get("sameAs") or ""
                                    if isinstance(f_url, list):
                                        f_url = next((u for u in f_url if "linkedin.com/in" in str(u)), f_url[0] if f_url else "")
                                    meta["founders"].append(
                                        {
                                            "name": f_name,
                                            "title": f.get("jobTitle") or "Founder",
                                            "linkedin_url": str(f_url),
                                            "bio": f.get("description") or f"Company Founder of {company_name}",
                                            "source": "Schema.org Organization (JSON-LD)",
                                        }
                                    )
                                elif isinstance(f, str) and len(f.strip().split()) >= 2:
                                    meta["founders"].append(
                                        {
                                            "name": f.strip(),
                                            "title": "Founder",
                                            "linkedin_url": "",
                                            "bio": f"Company Founder of {company_name}",
                                            "source": "Schema.org Organization (JSON-LD)",
                                        }
                                    )

                        # Employees / Members from Organization
                        members_raw = item.get("member") or item.get("members") or item.get("employee") or item.get("employees")
                        if members_raw:
                            m_list = members_raw if isinstance(members_raw, list) else [members_raw]
                            for m_obj in m_list:
                                if isinstance(m_obj, dict) and m_obj.get("name"):
                                    m_name = str(m_obj.get("name")).strip()
                                    m_job = m_obj.get("jobTitle") or "Team Member"
                                    m_url = m_obj.get("url") or m_obj.get("sameAs") or ""
                                    if isinstance(m_url, list):
                                        m_url = next((u for u in m_url if "linkedin.com/in" in str(u)), m_url[0] if m_url else "")
                                    meta["scraped_team"].append(
                                        {
                                            "name": m_name,
                                            "title": m_job,
                                            "department": "Engineering & Tech" if any(w in m_job.lower() for w in ["engineer", "developer", "tech", "architect"]) else "Operations & Business",
                                            "linkedin_url": str(m_url),
                                            "source": "Schema.org Member (JSON-LD)",
                                        }
                                    )

                    # Top-level Person parsing in JSON-LD
                    elif "Person" in schema_type:
                        p_name = item.get("name")
                        if p_name and isinstance(p_name, str) and 1 < len(p_name.strip().split()) <= 4:
                            p_clean_name = p_name.strip()
                            p_title = item.get("jobTitle") or "Key Personnel"
                            p_url = item.get("url") or item.get("sameAs") or ""
                            if isinstance(p_url, list):
                                p_url = next((u for u in p_url if "linkedin.com/in" in str(u)), p_url[0] if p_url else "")
                            p_img = item.get("image")
                            if isinstance(p_img, dict):
                                p_img = p_img.get("url")

                            is_founder_role = bool(re.search(r"(founder|ceo|chief executive|owner|president)", p_title, re.I))
                            person_dict = {
                                "name": p_clean_name,
                                "title": p_title,
                                "department": "Executive Leadership" if is_founder_role else "Engineering & Tech",
                                "linkedin_url": str(p_url) if p_url else "",
                                "avatar_url": str(p_img) if p_img else None,
                                "bio": item.get("description") or f"Team member at {company_name}",
                                "source": "Schema.org Person (JSON-LD)",
                            }
                            meta["scraped_team"].append(person_dict)
                            if is_founder_role:
                                meta["founders"].append(person_dict)
            except Exception:
                pass

        # 3. Founded Year from text / JS prose / copyright heuristics
        if meta["founded_year"]:
            meta["founded_source"] = "schema_or_explicit"
        else:
            found_match = re.search(
                r"(?:founded\s+in|est\.|established\s+in|since)\s+(19\d\d|20\d\d)",
                combined_readable,
                re.IGNORECASE,
            ) or re.search(
                r"\bin\s+(19\d\d|20\d\d)[,\s]+(?:[A-Za-z0-9&.\s]{1,35}?)\s+(?:was\s+)?(?:founded|established|started|created)",
                combined_readable,
                re.IGNORECASE,
            )
            if found_match:
                meta["founded_year"] = found_match.group(1)
                meta["founded_source"] = "explicit"
            else:
                cpy_match = re.search(
                    r"©\s*(?:19\d\d\s*[-–]\s*)?(20\d\d)", combined_readable
                )
                if cpy_match:
                    meta["founded_year"] = cpy_match.group(1)
                    meta["founded_source"] = "copyright"

        # 4. Industry inference from keywords / description
        text_lower = (meta["description"] + " " + html_text[:5000] + " " + js_prose[:5000]).lower()
        if any(w in text_lower for w in ["security", "cyber", "penetration", "soc", "firewall", "threat"]):
            meta["industry"] = "Cybersecurity & Information Security"
        elif any(w in text_lower for w in ["cloud", "saas", "platform", "software", "api", "developer"]):
            meta["industry"] = "Cloud Software & SaaS"
        elif any(w in text_lower for w in ["finance", "payment", "banking", "fintech", "crypto"]):
            meta["industry"] = "Financial Technology (FinTech)"
        elif any(w in text_lower for w in ["health", "medical", "patient", "clinical", "biotech"]):
            meta["industry"] = "Healthcare & Biotechnology"
        elif any(w in text_lower for w in ["ecommerce", "shop", "retail", "store"]):
            meta["industry"] = "E-Commerce & Retail"

        # 5. Extract Founders / Leadership from text and narrative patterns
        def _norm_key(n: str) -> str:
            return re.sub(r"\s+", " ", n.lower().strip())

        def _slug_from_li(url: str) -> str:
            m_li = re.search(r"linkedin\.com/in/([a-zA-Z0-9_.-]+)", url or "", re.I)
            return m_li.group(1).rstrip("/").lower() if m_li else ""

        seen_names: set[str] = {_norm_key(f["name"]) for f in meta["founders"]}
        seen_names.update({_norm_key(t["name"]) for t in meta["scraped_team"]})
        seen_founder_keys: set[str] = {_norm_key(f["name"]) for f in meta["founders"]}
        seen_linkedin_slugs: set[str] = set()
        for existing_p in meta["founders"] + meta["scraped_team"]:
            s_li = _slug_from_li(existing_p.get("linkedin_url", ""))
            if s_li:
                seen_linkedin_slugs.add(s_li)

        def add_founder_entry(
            name: str,
            title: str,
            bio: str = "",
            photo: Optional[str] = None,
            li_url: str = "",
            source: str = "Website Text Mentions (About Section)",
        ) -> None:
            if not name:
                return
            if "'s" in name or "’s" in name:
                return
            clean_n = re.sub(r"^(?:Dr\.|Mr\.|Mrs\.|Ms\.|Prof\.)\s+", "", name.strip(), flags=re.I)
            clean_n = re.sub(r"[,;:\-].*$", "", clean_n).strip()
            parts = clean_n.split()
            if len(parts) < 2 or len(parts) > 4:
                return
            stop = {
                "the", "our", "its", "team", "company", "group", "engineers", "board", "directors",
                "founder", "founders", "ceo", "president", "management", "and", "best", "top",
                "enterprise", "solutions", "software", "platform", "cloud", "services", "technologies",
                "corporation", "review", "award", "products", "customers", "partners", "global", "leading",
                "meet", "about", "learn", "read", "view", "see", "discover", "join", "visit", "explore",
                "contact", "trusted", "why", "how", "build", "secure", "get", "start", "request", "postmans",
            }
            if any(p.lower().rstrip("'s’") in stop for p in parts):
                return
            norm_name = " ".join([p.capitalize() if p.islower() else p for p in parts])
            key = _norm_key(norm_name)
            clean_title = re.sub(r"\b(Ceo|Cto|Coo|Cfo|Ciso|Vp|Hr)\b", lambda m: m.group(1).upper(), (title or "Founder").strip())

            if li_url:
                s_li = _slug_from_li(li_url)
                if s_li:
                    seen_linkedin_slugs.add(s_li)

            if key in seen_founder_keys:
                for f in meta["founders"]:
                    if _norm_key(f.get("name", "")) == key:
                        if photo and not f.get("photo_url"):
                            f["photo_url"] = photo
                            f["avatar_url"] = photo
                        if bio and (not f.get("bio") or len(f.get("bio", "")) < len(bio)):
                            f["bio"] = bio
                            f["bio_summary"] = bio
                        if li_url and not f.get("linkedin_url"):
                            f["linkedin_url"] = li_url
                        if title and f.get("title") in ("Founder", "Key Personnel", "Team Member"):
                            f["title"] = clean_title
                return
            seen_founder_keys.add(key)
            seen_names.add(key)
            meta["scraped_team"] = [t for t in meta["scraped_team"] if _norm_key(t.get("name", "")) != key]

            biography: dict[str, str] = {
                "current_role": f"{clean_title}, {company_name}",
            }
            if "founder" in clean_title.lower():
                biography["company_founded"] = company_name
            if clean_title:
                biography["occupation"] = clean_title

            source_refs = [
                {
                    "name": f"{company_name} official website",
                    "url": f"https://{domain}",
                    "icon": "🌐",
                }
            ]
            if li_url:
                source_refs.append({
                    "name": "LinkedIn Profile",
                    "url": li_url,
                    "icon": "💼",
                })

            entry = {
                "name": norm_name,
                "title": clean_title,
                "department": "Executive Leadership",
                "linkedin_url": li_url,
                "linkedin_search_url": li_url or f"https://www.linkedin.com/search/results/people/?keywords={urllib.parse.quote(norm_name + ' ' + company_name)}",
                "avatar_url": photo,
                "photo_url": photo,
                "bio_summary": bio,
                "bio": bio or f"Identified as {clean_title} of {company_name}",
                "biography": biography,
                "source_references": source_refs,
                "source": source,
                "is_verified": True,
                "is_founder": True,
            }
            meta["founders"].append(entry)
            meta["scraped_team"].append(entry)

        # 5a. Text Narrative Patterns (supports initials like "Srinivasan M. S." or "Sanjay G")
        FIRST_WORD = r"[A-Z][a-z]{1,}"
        SUBSEQ_WORD = r"(?:[A-Z][a-z'-]+|[A-Z]\.(?!\w)|[A-Z](?![a-z]))"
        NAME = rf"{FIRST_WORD}(?:[^\S\r\n]+{SUBSEQ_WORD}){{1,3}}"

        # Pattern 1: Founded/established [in YEAR] by [Name] (and [Name])
        p1 = re.compile(
            rf"(?i:(?:founded|co-founded|started|created|launched|established)\s+(?:in\s+\d{{4}}\s+)?by\s+(?:(?:its|our|the)\s+)?(?:(?:founder|co-founder|ceo|president|managing\s+director|director|executive|dr\.|mr\.|mrs\.|ms\.)(?:[^\S\r\n]+(?:and|&)[^\S\r\n]+(?:founder|co-founder|ceo|president|managing\s+director|director|executive))?[\s,]+)*)({NAME})(?:[^\S\r\n]+(?:and|&)[^\S\r\n]+({NAME}))?"
        )
        for m in p1.finditer(combined_readable):
            if m.group(1):
                add_founder_entry(m.group(1), "Founder", combined_readable[max(0, m.start()-50):min(len(combined_readable), m.end()+100)])
            if m.group(2):
                add_founder_entry(m.group(2), "Co-Founder", combined_readable[max(0, m.start()-50):min(len(combined_readable), m.end()+100)])

        # Pattern 2: [Name], Founder & CEO / Founder and CEO of [Company]
        p2 = re.compile(
            rf"({NAME})[,\s—–-]+(?:(?i:is\s+(?:the|our)\s+)?((?i:(?:Co-)?Founder|CEO|Chief Executive Officer|President|Managing Director)(?:\s*(?:&|and|/)\s*(?i:CEO|CTO|COO|President|Director|Founder|Managing Director))?))"
        )
        for m in p2.finditer(combined_readable):
            t_raw = re.split(r"(?:\s+of\b|[.,;\n])", m.group(2).strip(), flags=re.I)[0]
            clean_t = " ".join(t_raw.split()[:4]).strip().title()
            add_founder_entry(m.group(1), clean_t, combined_readable[max(0, m.start()-50):min(len(combined_readable), m.end()+100)])

        # Pattern 3: Founder & CEO: [Name] / Founder: [Name]
        p3 = re.compile(
            rf"((?i:(?:Co-)?Founder(?:\s*(?:&|and|/)\s*(?:CEO|President|CTO|Managing Director|COO))?|CEO|President))\s*[:—–-]\s*({NAME})"
        )
        for m in p3.finditer(combined_readable):
            clean_t = m.group(1).strip()
            add_founder_entry(m.group(2), clean_t, combined_readable[max(0, m.start()-50):min(len(combined_readable), m.end()+100)])

        # Pattern 4: Under the leadership of [founder [and CEO]] [Name] / Led by [our founder,] [Name]
        p4 = re.compile(
            rf"(?i:(?:under the leadership of|led by|spearheaded by)\s+(?:(?:our|the)\s+)?(?:(?:founder|ceo|president|managing\s+director)(?:\s*(?:&|and)\s*(?:ceo|founder|president|cto|coo))?)?[\s,]+)({NAME})"
        )
        for m in p4.finditer(combined_readable):
            add_founder_entry(m.group(1), "Founder & CEO", combined_readable[max(0, m.start()-50):min(len(combined_readable), m.end()+100)])

        # Pattern 5: Meet our founder, [Name] / Meet the founder [Name]
        p5 = re.compile(
            rf"(?i:(?:meet\s+(?:our|the)\s+founder[s]?[\s,:]+|our founder[s]?[\s,:]+)\s*)({NAME})"
        )
        for m in p5.finditer(combined_readable):
            add_founder_entry(m.group(1), "Founder", combined_readable[max(0, m.start()-50):min(len(combined_readable), m.end()+100)])

        # Pattern 6: [Name] is the founder and CEO of [Company]
        p6 = re.compile(
            rf"({NAME})\s+(?i:is\s+the\s+((?:(?:co-)?founder|ceo|president)(?:\s*(?:&|and)\s*(?:ceo|founder|president|cto|coo))?))"
        )
        for m in p6.finditer(combined_readable):
            t_raw = re.split(r"(?:\s+of\b|[.,;\n])", m.group(2).strip(), flags=re.I)[0]
            clean_t = " ".join(t_raw.split()[:4]).strip().title()
            add_founder_entry(m.group(1), clean_t, combined_readable[max(0, m.start()-50):min(len(combined_readable), m.end()+100)])

        # Pattern 7: [Name] founded [Company] in [Year]
        p7 = re.compile(
            rf"({NAME})\s+(?i:(?:co-)?founded\s+(?:[A-Za-z0-9\s]+?)\s+in\s+\d{{4}})"
        )
        for m in p7.finditer(combined_readable):
            add_founder_entry(m.group(1), "Founder", combined_readable[max(0, m.start()-50):min(len(combined_readable), m.end()+100)])

        # 5b. Process structured SPA JS/JSON team objects
        for obj in js_intel.get("team_objects", []):
            j_name = obj["name"]
            j_role = obj["role"]
            j_li = obj["linkedin"]
            j_photo = obj["photo"]
            j_tag = obj.get("tag", "")
            j_bio = obj.get("bio", "")
            j_key = _norm_key(j_name)

            if j_li:
                s_li = _slug_from_li(j_li)
                if s_li:
                    seen_linkedin_slugs.add(s_li)

            is_exec = bool(
                re.search(
                    r"\b(founder|co-founder|ceo|coo|cto|cfo|chief|president|director|head|owner|partner|vp|officer|leadership)\b",
                    f"{j_role} {j_tag}",
                    re.I,
                )
            )
            if is_exec:
                add_founder_entry(j_name, j_role, bio=j_bio, photo=j_photo, li_url=j_li, source="Website JS Bundle (Team Registry)")
            else:
                if j_key not in seen_names:
                    seen_names.add(j_key)
                    dept = "Operations & Business"
                    role_low = f"{j_role} {j_tag}".lower()
                    if any(w in role_low for w in ["security", "soc", "cyber", "threat", "ciso", "audit", "vapt"]):
                        dept = "Cybersecurity & IT"
                    elif any(w in role_low for w in ["engineer", "developer", "architect", "tech", "product", "qa", "devops"]):
                        dept = "Engineering & Tech"
                    meta["scraped_team"].append({
                        "name": j_name,
                        "title": j_role,
                        "department": dept,
                        "linkedin_url": j_li,
                        "linkedin_search_url": j_li or f"https://www.linkedin.com/search/results/people/?keywords={urllib.parse.quote(j_name + ' ' + company_name)}",
                        "avatar_url": j_photo,
                        "photo_url": j_photo,
                        "bio": j_bio or f"{j_role} at {company_name}",
                        "source": "Website JS Bundle (Team Registry)",
                        "is_verified": True,
                        "is_founder": False,
                    })

        # Meta author tags
        author_meta = (
            soup.find("meta", attrs={"name": "author"})
            or soup.find("meta", property="article:author")
            or soup.find("meta", attrs={"name": "twitter:creator"})
        )
        if author_meta and author_meta.get("content"):
            auth_val = author_meta["content"].strip().lstrip("@")
            if 1 < len(auth_val.split()) <= 3 and not any(w in auth_val.lower() for w in ["admin", "root", "team", "wordpress", "author"]):
                auth_key = _norm_key(auth_val)
                if auth_key not in seen_names:
                    seen_names.add(auth_key)
                    meta["scraped_team"].append({
                        "name": auth_val,
                        "title": "Author / Creator",
                        "department": "Engineering & Tech",
                        "linkedin_url": "",
                        "source": "Website Meta Author Tag",
                    })

        # 6. Scrape Team Members & Founders from HTML & LinkedIn Personal links
        linkedin_in_links = soup.find_all(
            "a", href=re.compile(r"linkedin\.com/in/[a-zA-Z0-9_.-]+", re.IGNORECASE)
        )
        for a in linkedin_in_links:
            href = a.get("href", "")
            m = re.search(r"linkedin\.com/in/([a-zA-Z0-9_.-]+)", href, re.IGNORECASE)
            if not m:
                continue
            slug = m.group(1).rstrip("/")
            if slug.lower() in ("in", "company", "school", "pub", "feed") or slug.lower() in seen_linkedin_slugs:
                continue

            raw_text = a.get_text(strip=True)
            name = ""
            title = "Team Member"
            avatar_url = None
            parent = a.find_parent(["div", "section", "article", "li"])

            if parent:
                img = parent.find("img")
                if img and img.get("src"):
                    avatar_url = cls._normalize_asset_url(img["src"], domain)

                card_text = parent.get_text(" ", strip=True)
                role_match = re.search(
                    r"\b((?:Co-)?Founder(?:\s*(?:&|and|/)\s*(?:CEO|President|CTO|Managing Director|COO))?|Chief Executive Officer|CEO|Chief Technology Officer|CTO|Chief Operating Officer|COO|Chief Financial Officer|CFO|Chief Information Security Officer|CISO|President|Managing Director|Vice President|VP(?:\s+of\s+[\w\s]+)?|Director(?:\s+of\s+[\w\s]+)?|Lead\s+[\w\s]+|Senior\s+[\w\s]+|Software\s+[\w\s]+|Security\s+[\w\s]+|Product\s+Manager|Head\s+of\s+[\w\s]+)\b",
                    card_text,
                    re.IGNORECASE,
                )
                if role_match:
                    clean_role = role_match.group(0).strip()
                    clean_role = " ".join(clean_role.split()[:4]).title()
                    title = clean_role

                if not raw_text or raw_text.lower() in cls.GENERIC_ANCHOR_TEXTS or len(raw_text.split()) < 2:
                    for h in parent.find_all(["h2", "h3", "h4", "h5", "strong"]):
                        h_text = h.get_text(strip=True)
                        if 1 < len(h_text.split()) <= 4 and not re.search(r"(about|team|contact|follow|connect|join)", h_text, re.I):
                            name = h_text
                            break

            if not name:
                if raw_text and raw_text.lower() not in cls.GENERIC_ANCHOR_TEXTS and 1 < len(raw_text.split()) <= 4:
                    name = raw_text
                else:
                    name = cls.clean_slug_to_name(slug)

            name_key = _norm_key(name)
            if not name or name_key in seen_names or len(name_key) < 3:
                continue

            seen_linkedin_slugs.add(slug.lower())
            is_founder = bool(
                re.search(r"\b(founder|co-founder|ceo|coo|cto|cfo|chief|president|director|head|owner|partner|vp|officer)\b", title, re.IGNORECASE)
            )

            if is_founder:
                add_founder_entry(name, title, photo=avatar_url, li_url=href, source="Website LinkedIn Profile Link")
            else:
                seen_names.add(name_key)
                person_obj = {
                    "name": name,
                    "title": title,
                    "department": (
                        "Cybersecurity & IT"
                        if any(w in title.lower() for w in ["security", "ciso", "soc", "sysadmin", "cloud"])
                        else "Engineering & Tech"
                    ),
                    "linkedin_url": href,
                    "linkedin_search_url": f"https://www.linkedin.com/search/results/people/?keywords={urllib.parse.quote(name + ' ' + company_name)}",
                    "avatar_url": avatar_url,
                    "source": "Website LinkedIn Profile Link",
                }
                meta["scraped_team"].append(person_obj)

        # 7. Scrape HTML team cards (elements with class/id matching team/leaders/about)
        card_pattern = re.compile(
            r"(?:^|[\s_-])(team|leader|leadership|member|executive|founder|person|staff|profile|bio)(?:[\s_-]?(card|box|item|block|col|single|wrap|info|content|details|container|cell))?(?:$|[\s_-])",
            re.I
        )
        candidate_cards = soup.find_all(
            ["div", "section", "li", "article"],
            class_=card_pattern,
        )

        section_pattern = re.compile(r"(?:team|leadership|founders|executives|our-team|about-team|about-us)", re.I)
        for section in soup.find_all(["section", "div", "ul"], id=section_pattern):
            for child in section.find_all(["div", "li", "article"], recursive=True):
                if child not in candidate_cards:
                    if child.find(["h2", "h3", "h4", "h5", "strong"]) and (child.find("img") or child.find(["p", "span"])):
                        candidate_cards.append(child)

        # 7b. Generic Tailwind/Bootstrap/Webflow DOM card heuristic (when cards use utility classes instead of 'team-card')
        seen_card_elems: set[int] = {id(c) for c in candidate_cards}
        role_hint_re = re.compile(
            r"\b((?:Co-)?Founder|CEO|Chief Executive Officer|CTO|Chief Technology Officer|COO|Chief Operating Officer|CFO|Chief Financial Officer|CISO|Managing Director|President|VP|Vice President|Head of [A-Za-z &]{2,30}|Director of [A-Za-z &]{2,30}|(?:HR|Engineering|Security) Director)\b",
            re.I,
        )
        for role_el in soup.find_all(["p", "span", "div", "h4", "h5", "h6", "small"]):
            r_txt = role_el.get_text(" ", strip=True)
            if not r_txt or len(r_txt.split()) > 10 or len(r_txt) > 80:
                continue
            if not role_hint_re.search(r_txt):
                continue
            card_cand = role_el.find_parent(["div", "article", "li", "section"])
            if not card_cand or id(card_cand) in seen_card_elems:
                continue
            # Ignore oversized layout wrappers or testimonial blockquotes
            full_card_txt = card_cand.get_text(" ", strip=True)
            if len(full_card_txt.split()) > 160 or card_cand.find("blockquote"):
                continue
            card_cls_str = " ".join(card_cand.get("class") or []).lower()
            if any(bad in card_cls_str for bad in ["testimonial", "quote", "review", "case-study"]):
                continue
            heading_el = card_cand.find(["h2", "h3", "h4", "h5", "strong"])
            if heading_el and heading_el != role_el:
                h_txt = heading_el.get_text(" ", strip=True)
                if 2 <= len(h_txt.split()) <= 4 and all(re.match(r"^[A-Z][a-zA-Z.'-]*$", w) for w in h_txt.split()):
                    seen_card_elems.add(id(card_cand))
                    candidate_cards.append(card_cand)

        for card in candidate_cards[:60]:
            h = card.find(class_=re.compile(r"name", re.I)) or card.find(["h3", "h4", "h5", "h2", "strong"])
            if not h:
                continue
            c_name = h.get_text(strip=True)
            if not c_name or len(c_name.split()) < 2 or len(c_name.split()) > 4:
                continue
            if re.search(r"(about|team|leadership|join|contact|values|mission|solution|innovate|company|read|more)", c_name, re.I):
                continue

            c_key = _norm_key(c_name)

            title_elem = card.find(class_=re.compile(r"(role|title|designation|position|job)", re.I))
            c_title = ""
            if title_elem and title_elem != h:
                c_title = title_elem.get_text(" ", strip=True)

            if not c_title or len(c_title) > 60:
                for p in card.find_all(["p", "span", "small", "h4", "h5", "h6"]):
                    if p == h or p == title_elem:
                        continue
                    txt = p.get_text(" ", strip=True)
                    if any(k in txt.lower() for k in ["founder", "ceo", "cto", "coo", "cfo", "chief", "director", "president", "head of", "lead", "engineer", "manager"]):
                        if len(txt.split()) <= 6:
                            c_title = txt
                            break

            if c_title:
                c_title = re.sub(rf"^{re.escape(c_name)}[\s,:—–-]+", "", c_title, flags=re.I).strip()

            if not c_title:
                role_m = re.search(
                    r"\b((?:Co-)?Founder(?:\s*(?:&|and|/)\s*(?:CEO|President|CTO|Managing Director|COO))?|Chief Executive Officer|CEO|Chief Technology Officer|CTO|Chief Operating Officer|COO|Chief Financial Officer|CFO|Chief Information Security Officer|CISO|President|Managing Director|Director|VP|Vice President|Head\s+of\s+[A-Za-z\s]+|Lead\s+[A-Za-z\s]+|Senior\s+[A-Za-z\s]+)\b",
                    card.get_text(" ", strip=True),
                    re.I,
                )
                if role_m:
                    c_title = role_m.group(0).strip().title()

            if not c_title:
                c_title = "Team Member"

            bio = ""
            for p in card.find_all("p"):
                txt = p.get_text(" ", strip=True)
                if len(txt) > 30 and txt != c_title and txt != c_name:
                    bio = txt
                    break

            c_img = card.find("img")
            c_avatar = cls._normalize_asset_url(c_img["src"], domain) if (c_img and c_img.get("src")) else None

            c_li_link = ""
            for a_tag in card.find_all("a", href=True):
                if "linkedin.com/in/" in a_tag["href"]:
                    c_li_link = a_tag["href"]
                    s_li = _slug_from_li(c_li_link)
                    if s_li:
                        seen_linkedin_slugs.add(s_li)
                    break

            is_f = bool(re.search(r"\b(founder|co-founder|ceo|coo|cto|cfo|chief|president|director|head|owner|partner|vp|officer)\b", c_title, re.I))

            if is_f:
                is_already_founder = any(_norm_key(f.get("name", "")) == c_key for f in meta["founders"])
                if not is_already_founder:
                    meta["scraped_team"] = [t for t in meta["scraped_team"] if _norm_key(t.get("name", "")) != c_key]
                    add_founder_entry(c_name, c_title, bio=bio, photo=c_avatar, li_url=c_li_link, source="Website HTML Team Card")
                else:
                    for f in meta["founders"]:
                        if _norm_key(f.get("name", "")) == c_key:
                            if c_avatar and not f.get("photo_url"):
                                f["photo_url"] = c_avatar
                                f["avatar_url"] = c_avatar
                            if bio and (not f.get("bio") or len(f.get("bio", "")) < len(bio)):
                                f["bio"] = bio
                                f["bio_summary"] = bio
                            if c_li_link and not f.get("linkedin_url"):
                                f["linkedin_url"] = c_li_link
                            if c_title and f.get("title") in ("Founder", "Co-Founder", "Key Personnel", "Team Member") and len(c_title) > len(f.get("title", "")):
                                f["title"] = re.sub(r"\b(Ceo|Cto|Coo|Cfo|Ciso|Vp|Hr)\b", lambda m: m.group(1).upper(), c_title.strip())
            else:
                if c_key not in seen_names:
                    seen_names.add(c_key)
                    card_person = {
                        "name": c_name,
                        "title": c_title,
                        "department": "Engineering & Tech",
                        "linkedin_url": c_li_link,
                        "linkedin_search_url": c_li_link or f"https://www.linkedin.com/search/results/people/?keywords={urllib.parse.quote(c_name + ' ' + company_name)}",
                        "avatar_url": c_avatar,
                        "photo_url": c_avatar,
                        "bio_summary": bio,
                        "bio": bio or f"Team member at {company_name}",
                        "source": "Website HTML Team Card",
                        "is_verified": True,
                        "is_founder": False,
                    }
                    meta["scraped_team"].append(card_person)

        # 8. Direct regex search for any remaining LinkedIn personal profiles in HTML or JS bundles
        raw_li_corpus = html_clean + ("\n" + "\n".join(js_list) if js_list else "")
        raw_in_matches = re.findall(r'https?://(?:[a-z0-9-]+\.)?linkedin\.com/in/([a-zA-Z0-9_.-]+)', raw_li_corpus, re.I)
        for slug in raw_in_matches:
            slug = slug.rstrip("/")
            if slug.lower() in ("in", "company", "school", "pub", "feed") or slug.lower() in seen_linkedin_slugs:
                continue
            name = cls.clean_slug_to_name(slug)
            name_key = _norm_key(name)
            if not name or name_key in seen_names or len(name_key) < 3:
                continue
            seen_linkedin_slugs.add(slug.lower())
            seen_names.add(name_key)
            person_obj = {
                "name": name,
                "title": "Key Personnel / Associated Profile",
                "department": "Engineering & Tech",
                "linkedin_url": f"https://www.linkedin.com/in/{slug}",
                "linkedin_search_url": f"https://www.linkedin.com/search/results/people/?keywords={urllib.parse.quote(name + ' ' + company_name)}",
                "avatar_url": None,
                "source": "Website Direct Link",
            }
            meta["scraped_team"].append(person_obj)

        # Sort founders so primary Founders & CEOs always rank before VPs / Heads / Directors
        def _founder_rank(f_obj: dict[str, Any]) -> int:
            t_low = (f_obj.get("title") or "").lower()
            if "founder" in t_low and "ceo" in t_low:
                return 0
            if "founder" in t_low:
                return 1
            if any(w in t_low for w in ["ceo", "chief executive", "managing director", "owner", "president"]):
                return 2
            if any(w in t_low for w in ["cto", "coo", "cfo", "ciso", "chief"]):
                return 3
            return 4

        meta["founders"].sort(key=_founder_rank)

        return meta


class PublicKnowledgeHarvester:
    """
    Open Knowledge & Search Engine Harvester.
    Queries Wikipedia and Wikidata for verified company profiles,
    founders, C-suite executives, headquarters, founded year, employee headcount, and operating entities.
    """

    @classmethod
    async def harvest_public_knowledge(
        cls,
        company_name: str,
        domain: str,
        client: Optional[httpx.AsyncClient] = None,
        legal_name: str = "",
    ) -> dict[str, Any]:
        """Harvests authoritative company dossier from Wikipedia and Wikidata."""
        clean_domain = domain.lower().replace("www.", "").strip()
        domain_root = clean_domain.split(".")[0]
        raw_queries = [
            legal_name,
            f"{company_name} (company)",
            f"{company_name} (software)",
            company_name,
            f"{company_name} Corporation",
            f"{company_name} Inc.",
            f"{company_name} Foundation",
            domain_root,
        ]
        queries = [q.strip() for q in dict.fromkeys(raw_queries) if q and len(q.strip()) >= 3]
        headers = {
            "User-Agent": "FootprintHub-OSINT/1.0 (contact@footprinthub.com; https://footprinthub.com) Mozilla/5.0"
        }
        intel: dict[str, Any] = {
            "founders": [],
            "description": "",
            "industry": "",
            "headquarters": "",
            "founded_year": "",
            "estimated_employees": "",
            "parent_organization": "",
            "source_article": "",
            "source_url": "",
            "wikidata_id": "",
            "wikipedia_status": "not_listed",
            "searched_queries": queries[:6],
            "candidate_slugs": [],
        }

        should_close = False
        if not client:
            client = httpx.AsyncClient(timeout=6.0, follow_redirects=True, headers=headers)
            should_close = True

        try:
            candidate_titles: list[str] = []
            non_org_wd_words = ("film", "movie", "novel", "book", "song", "album", "band", "television", "episode", "village", "river", "municipality", "comic")

            # 1 & 2. Run Wikidata entity search and Wikipedia article search concurrently
            wd_queries = [q for q in [legal_name, company_name, domain_root] if q and len(q) >= 3][:2]

            async def _wd_search(wq: str) -> list[str]:
                matched_ids: list[str] = []
                try:
                    wd_url = f"https://www.wikidata.org/w/api.php?action=wbsearchentities&search={urllib.parse.quote(wq)}&language=en&limit=5&format=json"
                    wd_r = await client.get(wd_url, headers=headers, timeout=3.5)
                    if wd_r.status_code == 200:
                        for wd_item in wd_r.json().get("search", []):
                            wd_desc = (wd_item.get("description") or "").lower()
                            wd_id = wd_item.get("id", "")
                            if any(bad in wd_desc for bad in non_org_wd_words):
                                continue
                            if any(k in wd_desc for k in ["company", "corporation", "enterprise", "software", "platform", "organization", "firm", "cybersecurity", "financial", "provider", "business", "startup", "founded", "fintech", "technology"]):
                                if wd_id:
                                    matched_ids.append(wd_id)
                except Exception:
                    pass
                return matched_ids

            async def _wp_search(q_str: str) -> list[str]:
                try:
                    search_url = f"https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch={urllib.parse.quote(q_str)}&utf8=&format=json"
                    r = await client.get(search_url, headers=headers, timeout=3.8)
                    if r.status_code == 200:
                        return [res.get("title") for res in r.json().get("query", {}).get("search", [])[:4] if res.get("title")]
                except Exception:
                    pass
                return []

            wd_coros = [_wd_search(wq) for wq in wd_queries]
            wp_coros = [_wp_search(q) for q in queries[:5]]
            combined_search = await asyncio.gather(*wd_coros, *wp_coros, return_exceptions=True)

            wd_ids: list[str] = []
            for res in combined_search[: len(wd_coros)]:
                if isinstance(res, list):
                    for wid in res:
                        if wid not in wd_ids:
                            wd_ids.append(wid)
            if wd_ids:
                intel["wikidata_id"] = wd_ids[0]
                try:
                    ent_r = await client.get(
                        f"https://www.wikidata.org/w/api.php?action=wbgetentities&ids={'|'.join(wd_ids[:3])}&props=sitelinks&sitefilter=enwiki&format=json",
                        headers=headers,
                        timeout=3.0,
                    )
                    if ent_r.status_code == 200:
                        entities_map = ent_r.json().get("entities", {})
                        for wid in wd_ids[:3]:
                            en_title = entities_map.get(wid, {}).get("sitelinks", {}).get("enwiki", {}).get("title")
                            if en_title and en_title not in candidate_titles:
                                candidate_titles.append(en_title)
                except Exception:
                    pass

            for batch in combined_search[len(wd_coros):]:
                if isinstance(batch, list):
                    for t in batch:
                        if t not in candidate_titles:
                            candidate_titles.append(t)

            # 3. Inspect candidate Wikipedia articles concurrently
            matched_intel = await cls._inspect_wikipedia_candidates(
                candidate_titles=candidate_titles,
                company_name=company_name,
                clean_domain=clean_domain,
                domain_root=domain_root,
                client=client,
                headers=headers,
                base_intel=intel,
            )
            return matched_intel
        finally:
            if should_close:
                await client.aclose()

    @classmethod
    async def inspect_wikipedia_titles(
        cls,
        candidate_titles: list[str],
        company_name: str,
        domain: str,
        client: Optional[httpx.AsyncClient] = None,
    ) -> dict[str, Any]:
        """Inspects pre-discovered Wikipedia titles (e.g. from web search) for authoritative company matches."""
        clean_domain = domain.lower().replace("www.", "").strip()
        domain_root = clean_domain.split(".")[0]
        headers = {
            "User-Agent": "FootprintHub-OSINT/1.0 (contact@footprinthub.com; https://footprinthub.com) Mozilla/5.0"
        }
        base_intel: dict[str, Any] = {
            "founders": [],
            "description": "",
            "industry": "",
            "headquarters": "",
            "founded_year": "",
            "estimated_employees": "",
            "parent_organization": "",
            "source_article": "",
            "source_url": "",
            "wikidata_id": "",
            "wikipedia_status": "not_listed",
            "searched_queries": [],
            "candidate_slugs": [],
        }
        if not candidate_titles:
            return base_intel
        should_close = False
        if not client:
            client = httpx.AsyncClient(timeout=5.0, follow_redirects=True, headers=headers)
            should_close = True
        try:
            return await cls._inspect_wikipedia_candidates(
                candidate_titles=candidate_titles,
                company_name=company_name,
                clean_domain=clean_domain,
                domain_root=domain_root,
                client=client,
                headers=headers,
                base_intel=base_intel,
            )
        finally:
            if should_close:
                await client.aclose()

    @classmethod
    async def _inspect_wikipedia_candidates(
        cls,
        candidate_titles: list[str],
        company_name: str,
        clean_domain: str,
        domain_root: str,
        client: httpx.AsyncClient,
        headers: dict[str, str],
        base_intel: dict[str, Any],
    ) -> dict[str, Any]:
        """Concurrently fetches and validates candidate Wikipedia infoboxes for company/software relevance."""
        intel = dict(base_intel)
        filtered_titles = [
            t for t in candidate_titles
            if t and not any(bad in t.lower() for bad in ["(film)", "(novel)", "(song)", "(album)", "(disambiguation)", "(band)", "(tv series)"])
        ][:6]
        if not filtered_titles:
            return intel

        async def _fetch_parse(t: str) -> tuple[str, str]:
            try:
                parse_url = f"https://en.wikipedia.org/w/api.php?action=parse&page={urllib.parse.quote(t)}&prop=text&section=0&format=json"
                p_resp = await client.get(parse_url, headers=headers, timeout=3.5)
                if p_resp.status_code == 200:
                    return (t, p_resp.json().get("parse", {}).get("text", {}).get("*", "") or "")
            except Exception:
                pass
            return (t, "")

        parsed_articles = await asyncio.gather(*[_fetch_parse(t) for t in filtered_titles])
        non_org_infobox_labels = {
            "directed by", "starring", "cinematography", "screenplay", "box office",
            "running time", "produced by", "distributed by", "narrated by",
            "music by", "edited by", "release date", "studio", "album",
            "population", "elevation", "mayor", "coordinates", "born", "died",
        }

        for title, html_text in parsed_articles:
            if not html_text:
                continue
            try:
                soup = BeautifulSoup(html_text, "html.parser")
                infobox = soup.find("table", class_=re.compile(r"infobox", re.I))
                if not infobox:
                    continue

                # Verify relevance: check explicit official website row or article title against company/domain
                # (Do not match arbitrary <sup class="reference"> citation links inside unrelated infoboxes)
                comp_words = [w for w in company_name.lower().split() if len(w) >= 3]
                title_low = title.lower()
                title_matched = (
                    (len(domain_root) >= 3 and domain_root in title_low)
                    or (bool(comp_words) and all(w in title_low for w in comp_words))
                )

                parsed_industry = ""
                parsed_hq = ""
                parsed_emp = ""
                parsed_founded = ""
                parsed_parent = ""
                parsed_founders: list[dict[str, Any]] = []
                parsed_slugs: list[str] = []
                website_mismatch = False
                official_website_matched = False
                non_org_article = False
                seen_labels: set[str] = set()

                for tr in infobox.find_all("tr"):
                    th = tr.find(["th", "td"], class_=re.compile(r"label", re.I)) or tr.find("th")
                    td = tr.find("td", class_=re.compile(r"data", re.I)) or tr.find("td")
                    if not th or not td or th == td:
                        continue
                    lbl = th.get_text(" ", strip=True).lower().replace("\xa0", " ")
                    seen_labels.add(lbl)
                    if any(nol in lbl for nol in non_org_infobox_labels):
                        non_org_article = True
                        break
                    val = re.sub(r"\[\s*\d+\s*\]", "", td.get_text(" ", strip=True)).strip()

                    if "website" in lbl or lbl == "url":
                        site_low = (val + " " + " ".join(a.get("href", "") for a in td.find_all("a", href=True))).lower()
                        if site_low and (clean_domain in site_low or (len(domain_root) >= 3 and domain_root in site_low)):
                            official_website_matched = True
                        elif site_low:
                            website_mismatch = True
                            break
                    elif "industry" in lbl and not parsed_industry:
                        parsed_industry = val
                    elif "headquarters" in lbl and not parsed_hq:
                        parsed_hq = val
                    elif "founded" in lbl and not parsed_founded:
                        ym = re.search(r"(19\d\d|20\d\d)", val)
                        if ym:
                            parsed_founded = ym.group(1)
                    elif ("employee" in lbl or "size" in lbl) and not parsed_emp:
                        parsed_emp = val
                    elif "owner" in lbl or "parent" in lbl:
                        parsed_parent = val
                        parent_clean = re.sub(r"[^a-zA-Z0-9_-]", "-", val.lower().strip()).strip("-")
                        if parent_clean and len(parent_clean) > 3:
                            parsed_slugs.append(parent_clean)
                    elif any(k in lbl for k in ["founder", "key people", "leader", "ceo", "author", "developer"]):
                        if "developer" in lbl and not any(k in lbl for k in ["founder", "author"]):
                            continue
                        extracted_here: list[str] = []
                        for a_tag in td.find_all("a"):
                            name = " ".join(re.sub(r"\[\s*\d+\s*\]", "", a_tag.get_text(" ", strip=True)).split()).strip()
                            if 1 < len(name.split()) <= 4:
                                extracted_here.append(name)
                        if not extracted_here:
                            for raw_part in re.split(r"[,;\n•|]+", val):
                                clean_p = " ".join(re.sub(r"\([^)]*\)", "", raw_part).split()).strip()
                                if 1 < len(clean_p.split()) <= 4 and all(re.match(r"^[A-Z][a-zA-Z.'-]*$", w) for w in clean_p.split()):
                                    extracted_here.append(clean_p)
                        # Drop compound anchor strings that concatenate >=2 individually extracted names
                        if len(extracted_here) >= 2:
                            low_list = [n.lower() for n in extracted_here]
                            extracted_here = [
                                n for n in extracted_here
                                if sum(1 for other in low_list if other != n.lower() and other in n.lower()) < 2
                            ]
                        for name in extracted_here:
                            if name not in [f["name"] for f in parsed_founders]:
                                if not any(stop in name.lower() for stop in ["university", "college", "software", "limited", "inc", "company", "corporation", "foundation", "institute"]):
                                    parsed_founders.append({
                                        "name": name,
                                        "title": "Founder / Key Executive",
                                        "department": "Executive Leadership",
                                        "linkedin_url": "",
                                        "source": f"Wikipedia / Open Knowledge ({title})",
                                        "is_founder": True,
                                        "is_verified": True,
                                    })

                # Also remove compound duplicates across different infobox rows (e.g. "Ritesh Arora Nakul Aggarwal")
                if len(parsed_founders) >= 2:
                    all_f_low = [f["name"].lower() for f in parsed_founders]
                    parsed_founders = [
                        f for f in parsed_founders
                        if sum(1 for other in all_f_low if other != f["name"].lower() and other in f["name"].lower()) < 2
                    ]

                if website_mismatch or non_org_article or not (official_website_matched or title_matched):
                    continue

                has_org_signal = bool(
                    parsed_founders or parsed_industry or parsed_hq or parsed_founded or official_website_matched
                    or any(any(k in lb for k in ["website", "type", "services", "products", "revenue", "employees", "parent"]) for lb in seen_labels)
                )
                if has_org_signal:
                    intel["industry"] = parsed_industry
                    intel["headquarters"] = parsed_hq
                    intel["estimated_employees"] = parsed_emp
                    intel["founded_year"] = parsed_founded
                    intel["parent_organization"] = parsed_parent
                    intel["founders"] = parsed_founders
                    intel["candidate_slugs"] = parsed_slugs
                    intel["source_article"] = title
                    intel["source_url"] = f"https://en.wikipedia.org/wiki/{urllib.parse.quote(title.replace(' ', '_'))}"
                    intel["wikipedia_status"] = "found"
                    slug_from_title = re.sub(r"[^a-zA-Z0-9_-]", "-", title.lower().strip()).strip("-")
                    if slug_from_title and slug_from_title not in intel["candidate_slugs"]:
                        intel["candidate_slugs"].append(slug_from_title)

                    try:
                        s_resp = await client.get(
                            f"https://en.wikipedia.org/api/rest_v1/page/summary/{urllib.parse.quote(title)}",
                            headers=headers,
                            timeout=3.0,
                        )
                        if s_resp.status_code == 200:
                            intel["description"] = s_resp.json().get("extract", "")
                    except Exception:
                        pass

                    if not intel["founders"] and intel["description"]:
                        lead_m = re.search(
                            r"(?:founded|co-founded)\s+(?:in\s+\d{4}\s+)?by\s+([A-Z][a-zA-Z.'-]+(?:\s+[A-Z][a-zA-Z.'-]+){1,3})",
                            intel["description"],
                        )
                        if lead_m:
                            f_n = lead_m.group(1).strip()
                            intel["founders"].append({
                                "name": f_n,
                                "title": "Founder",
                                "department": "Executive Leadership",
                                "linkedin_url": "",
                                "source": f"Wikipedia / Open Knowledge ({title})",
                                "is_founder": True,
                                "is_verified": True,
                            })

                    if intel["founders"]:
                        try:
                            p_tasks = [
                                cls.enrich_person_profile(f["name"], company_name, domain=clean_domain, client=client)
                                for f in intel["founders"][:3]
                            ]
                            p_results = await asyncio.wait_for(
                                asyncio.gather(*p_tasks, return_exceptions=True),
                                timeout=3.0,
                            )
                            for idx, p_res in enumerate(p_results):
                                if isinstance(p_res, dict) and p_res:
                                    target_f = intel["founders"][idx]
                                    for key in ["photo_url", "avatar_url", "bio_summary", "bio", "wikipedia_url", "biography", "source_references"]:
                                        if p_res.get(key):
                                            target_f[key] = p_res[key]
                                    if p_res.get("current_role") and target_f.get("title") in ("Founder", "Founder / Key Executive", "Key Executive", None):
                                        target_f["title"] = p_res["current_role"]
                        except Exception:
                            pass

                    return intel
            except Exception:
                pass

        return intel

    @classmethod
    async def dig_online_intelligence(
        cls,
        company_name: str,
        domain: str,
        client: Optional[httpx.AsyncClient] = None,
    ) -> dict[str, Any]:
        """
        Actively digs live online search results (Yahoo Web Search organic index) to discover
        founders, CEOs, LinkedIn profiles, Wikipedia pages, and official social channels—even
        for companies that use heavy SPAs, bot protection, or are not listed on Wikipedia.
        """
        clean_domain = domain.lower().replace("www.", "").strip()
        domain_root = clean_domain.split(".")[0]
        comp_low = (company_name or domain_root).lower().strip()

        out: dict[str, Any] = {
            "founders": [],
            "social_profiles": [],
            "wikipedia_titles": [],
            "linkedin_company_url": "",
            "search_snippets": [],
        }

        queries = [
            f"{company_name} founder CEO",
            f'"{clean_domain}" OR "{company_name}" site:linkedin.com/company OR site:en.wikipedia.org',
        ]
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
        }
        should_close = False
        if not client:
            client = httpx.AsyncClient(timeout=8.0, follow_redirects=True)
            should_close = True

        def _unwrap_yahoo_url(href: str) -> str:
            m_ru = re.search(r"/RU=([^/]+)/", href or "")
            if m_ru:
                try:
                    return urllib.parse.unquote(m_ru.group(1))
                except Exception:
                    pass
            return href or ""

        def _norm_role(raw_r: str) -> str:
            cleaned = re.sub(r"\bco-\s+", "Co-", raw_r, flags=re.I)
            cleaned = re.sub(r"\s+", " ", cleaned).strip(" ,.-|")
            return re.sub(r"\b(Ceo|Cto|Coo|Cfo|Ciso|Vp)\b", lambda m: m.group(1).upper(), cleaned.title())

        def _strip_yahoo_title(raw_t: str) -> str:
            # Yahoo anchor text often prepends breadcrumb: "LinkedIn https://www.linkedin.com › in › slug Name - Title"
            cleaned = re.sub(r"^(?:[A-Za-z0-9._-]+\s+)?https?://[^\s]+(?:\s+›\s+[^\s]+)*\s+", "", raw_t or "").strip()
            cleaned = re.sub(r"\s*[|•]\s*(?:LinkedIn|Crunchbase|Forbes.*|RocketReach).*$", "", cleaned, flags=re.I)
            cleaned = re.sub(r"\([^)]*\)", "", cleaned).strip()
            return cleaned

        seen_founder_names: set[str] = set()
        seen_soc_keys: set[str] = set()

        async def _query_yahoo(q_str: str) -> str:
            try:
                resp = await client.get(
                    f"https://search.yahoo.com/search?p={urllib.parse.quote(q_str)}",
                    headers=headers,
                    timeout=5.5,
                )
                if resp.status_code == 200 and resp.text:
                    return resp.text
            except Exception:
                pass
            return ""

        async def _query_google_news(q_str: str) -> str:
            try:
                resp = await client.get(
                    f"https://news.google.com/rss/search?q={urllib.parse.quote(q_str)}&hl=en-US&gl=US&ceid=US:en",
                    headers=headers,
                    timeout=5.5,
                )
                if resp.status_code == 200 and resp.text:
                    return resp.text
            except Exception:
                pass
            return ""

        try:
            yahoo_pages, gnews_xml = await asyncio.gather(
                asyncio.gather(*[_query_yahoo(q) for q in queries]),
                _query_google_news(f'"{company_name}" founder OR CEO'),
            )
            for html_body in yahoo_pages:
                if not html_body:
                    continue
                soup = BeautifulSoup(html_body, "html.parser")
                for algo in soup.select("div.algo")[:8]:
                    a_tag = algo.select_one("h3 a, a")
                    if not a_tag:
                        continue
                    dest_url = _unwrap_yahoo_url(a_tag.get("href", ""))
                    raw_title = re.sub(r"\s+", " ", a_tag.get_text(" ", strip=True)).strip()
                    snip_el = algo.select_one("div.compText, p")
                    snippet = re.sub(r"\s+", " ", snip_el.get_text(" ", strip=True)).strip() if snip_el else ""

                    combined_low = f"{raw_title} {snippet} {dest_url}".lower()
                    # Verify strong relevance to the target company/domain
                    is_relevant = (
                        clean_domain in combined_low
                        or (len(comp_low) >= 4 and comp_low in combined_low)
                        or (len(domain_root) >= 4 and domain_root in combined_low)
                    )
                    if not is_relevant:
                        continue

                    if snippet and len(out["search_snippets"]) < 6:
                        out["search_snippets"].append({"title": raw_title, "url": dest_url, "snippet": snippet[:280]})

                    # 1. Discover official LinkedIn company URL or social channels
                    for soc in SocialMediaScraper.extract_social_links(dest_url):
                        if soc.get("type") == "personal":
                            continue
                        handle_low = soc.get("handle", "").lower()
                        if (len(domain_root) >= 3 and domain_root in handle_low) or (len(comp_low) >= 4 and comp_low.replace(" ", "") in handle_low.replace("-", "")):
                            dk = f"{soc['platform']}:{handle_low}"
                            if dk not in seen_soc_keys:
                                seen_soc_keys.add(dk)
                                soc["found_on_website"] = False
                                soc["source"] = "Online OSINT Search"
                                out["social_profiles"].append(soc)
                                if soc["platform"] == "LinkedIn" and soc.get("type") == "company" and not out["linkedin_company_url"]:
                                    out["linkedin_company_url"] = soc["url"]

                    # 2. Discover Wikipedia pages for company or founder
                    if "en.wikipedia.org/wiki/" in dest_url.lower():
                        wiki_t = urllib.parse.unquote(dest_url.split("/wiki/")[-1].split("#")[0].split("?")[0]).replace("_", " ")
                        if wiki_t and wiki_t not in out["wikipedia_titles"]:
                            out["wikipedia_titles"].append(wiki_t)

                    # 3. Extract founder/CEO from LinkedIn /in/ or verified executive profile search results
                    is_exec_profile_site = any(
                        host_tok in dest_url.lower()
                        for host_tok in ("linkedin.com/in/", "crunchbase.com/person/", "forbes.com/", "rocketreach.co/", "tracxn.com/")
                    )
                    if is_exec_profile_site:
                        clean_t = _strip_yahoo_title(raw_title)
                        parts = [p.strip() for p in re.split(r"\s+(?:[-–—|]|,)\s+", clean_t) if p.strip()]
                        cand_name = parts[0] if parts else ""
                        cand_role_text = " ".join(parts[1:]) if len(parts) > 1 else ""

                        # Validate person name (2-4 words, capitalized)
                        n_words = cand_name.split()
                        if 2 <= len(n_words) <= 4 and all(re.match(r"^[A-Z][a-zA-Z.'-]*$", w) for w in n_words):
                            # Confirm executive role appears in title or snippet alongside company
                            role_m = re.search(
                                r"\b((?:Co-?\s*)?Founder(?:\s*(?:&|and|,)\s*(?:CEO|CTO|COO|President|Managing Director))?|Chief Executive Officer|CEO(?:\s*(?:&|and|,)\s*(?:Co-?\s*)?Founder)?|Managing Director|President)\b",
                                f"{cand_role_text} {snippet}",
                                re.I,
                            )
                            if role_m:
                                # Ensure they aren't explicitly listed as founder of a *different* company
                                text_after_role = f"{cand_role_text}".lower()
                                tied_to_target = (
                                    comp_low in f"{raw_title} {snippet}".lower()
                                    or domain_root in f"{raw_title} {snippet}".lower()
                                )
                                li_profile_url = dest_url if "linkedin.com/in/" in dest_url.lower() else ""
                                if tied_to_target and (not text_after_role or comp_low in text_after_role or domain_root in text_after_role or "at " not in text_after_role):
                                    nk = cand_name.lower()
                                    if nk not in seen_founder_names:
                                        seen_founder_names.add(nk)
                                        role_clean = _norm_role(role_m.group(0))
                                        out["founders"].append({
                                            "name": cand_name,
                                            "title": role_clean,
                                            "department": "Executive Leadership",
                                            "linkedin_url": li_profile_url,
                                            "linkedin_search_url": li_profile_url or f"https://www.linkedin.com/search/results/people/?keywords={urllib.parse.quote(cand_name + ' ' + company_name)}",
                                            "bio": snippet or f"{role_clean} at {company_name}",
                                            "source": "Online OSINT Search (LinkedIn / Web Index)" if li_profile_url else "Online OSINT Search (Web Index)",
                                            "source_references": [
                                                {"name": f"{company_name} official website", "url": f"https://{clean_domain}", "icon": "🌐"},
                                                {"name": "LinkedIn Profile" if li_profile_url else raw_title[:50], "url": dest_url, "icon": "💼" if li_profile_url else "🔍"},
                                            ],
                                            "is_verified": True,
                                            "is_founder": True,
                                        })

                    # 4. Extract founder/CEO from Wikipedia or Crunchbase snippet text
                    for fm in re.finditer(
                        r"(?:founded|co-founded)\s+(?:in\s+\d{4}\s+)?by\s+([A-Z][a-z]{1,}(?:\s+[A-Z][a-zA-Z.'-]*){1,3})(?:\s+(?:and|&)\s+([A-Z][a-z]{1,}(?:\s+[A-Z][a-zA-Z.'-]*){1,3}))?",
                        f"{raw_title} {snippet}",
                    ):
                        for grp_idx, grp_role in [(1, "Founder"), (2, "Co-Founder")]:
                            fn = fm.group(grp_idx)
                            if fn and not any(bad in fn.lower() for bad in ["the ", "our ", "its ", "company", "group"]):
                                nk = fn.lower().strip()
                                if nk not in seen_founder_names:
                                    seen_founder_names.add(nk)
                                    out["founders"].append({
                                        "name": fn.strip(),
                                        "title": grp_role,
                                        "department": "Executive Leadership",
                                        "linkedin_url": "",
                                        "linkedin_search_url": f"https://www.linkedin.com/search/results/people/?keywords={urllib.parse.quote(fn.strip() + ' ' + company_name)}",
                                        "bio": snippet or f"{grp_role} of {company_name}",
                                        "source": "Online OSINT Search (Web Index)",
                                        "source_references": [
                                            {"name": raw_title[:60], "url": dest_url, "icon": "🌐"},
                                        ],
                                        "is_verified": True,
                                        "is_founder": True,
                                    })

            # 5. Parse Google News RSS items for press/news founder mentions (works reliably even if web search limits)
            if gnews_xml and "<item>" in gnews_xml:
                import xml.etree.ElementTree as ET
                root_el = ET.fromstring(gnews_xml)
                for item_el in root_el.findall(".//item")[:10]:
                    t_el = item_el.find("title")
                    l_el = item_el.find("link")
                    d_el = item_el.find("description")
                    item_title = (t_el.text or "").strip() if t_el is not None else ""
                    raw_desc = (d_el.text or "").strip() if d_el is not None else ""
                    item_desc = re.sub(r"<[^>]+>", " ", html.unescape(raw_desc)).strip() if raw_desc else ""
                    item_url = (l_el.text or "").strip() if l_el is not None else ""
                    item_txt = f"{item_title} {item_desc}"
                    item_low = item_txt.lower()
                    if not (
                        clean_domain in item_low
                        or (len(comp_low) >= 4 and comp_low in item_low)
                        or (len(domain_root) >= 4 and domain_root in item_low)
                    ):
                        continue
                    if item_title and len(out["search_snippets"]) < 6:
                        out["search_snippets"].append({"title": item_title, "url": item_url, "snippet": item_desc[:280]})

                    for gm in re.finditer(
                        rf"(?:{re.escape(company_name)}|{re.escape(domain_root)})(?:'s|’s)?\s+(?:(Co-?\s*Founder(?:\s*(?:&|and)\s*CEO)?|Founder(?:\s*(?:&|and)\s*CEO)?|CEO))\s+([A-Z][a-z]+(?:\s+[A-Z][a-zA-Z.'-]{{1,15}}){{1,2}})",
                        item_txt,
                    ):
                        g_role, g_name = _norm_role(gm.group(1)), gm.group(2).strip()
                        nk = g_name.lower()
                        if nk not in seen_founder_names and not any(b in nk for b in ("the ", "and ", "says", "said", "announces", "launches")):
                            seen_founder_names.add(nk)
                            out["founders"].append({
                                "name": g_name,
                                "title": g_role,
                                "department": "Executive Leadership",
                                "linkedin_url": "",
                                "linkedin_search_url": f"https://www.linkedin.com/search/results/people/?keywords={urllib.parse.quote(g_name + ' ' + company_name)}",
                                "bio": item_desc[:260] or item_title,
                                "source": "Online News & Press Search",
                                "source_references": [{"name": item_title[:60], "url": item_url, "icon": "📰"}],
                                "is_verified": True,
                                "is_founder": True,
                            })
                    for gm2 in re.finditer(
                        r"([A-Z][a-z]+(?:\s+[A-Z][a-zA-Z.'-]{1,15}){1,2}),\s+(Co-?\s*Founder(?:\s*(?:&|and)\s*CEO)?|Founder(?:\s*(?:&|and)\s*CEO)?|Chief Executive Officer|CEO)\s+(?:of|at)\s+([A-Za-z0-9 .&-]{2,35})",
                        item_txt,
                    ):
                        g_name, g_role, g_comp = gm2.group(1).strip(), _norm_role(gm2.group(2)), gm2.group(3).lower()
                        if comp_low in g_comp or domain_root in g_comp:
                            nk = g_name.lower()
                            if nk not in seen_founder_names:
                                seen_founder_names.add(nk)
                                out["founders"].append({
                                    "name": g_name,
                                    "title": g_role,
                                    "department": "Executive Leadership",
                                    "linkedin_url": "",
                                    "linkedin_search_url": f"https://www.linkedin.com/search/results/people/?keywords={urllib.parse.quote(g_name + ' ' + company_name)}",
                                    "bio": item_desc[:260] or item_title,
                                    "source": "Online News & Press Search",
                                    "source_references": [{"name": item_title[:60], "url": item_url, "icon": "📰"}],
                                    "is_verified": True,
                                    "is_founder": True,
                                })
        except Exception:
            pass
        finally:
            if should_close:
                await client.aclose()

        return out

    @classmethod
    async def search_person_image(
        cls, name: str, company_name: str = "", client: Optional[httpx.AsyncClient] = None
    ) -> Optional[str]:
        """Search public image search indexes for person photo when not on Wikipedia."""
        q = f"{name} {company_name}".strip()
        url = f"https://www.bing.com/images/search?q={urllib.parse.quote(q)}&form=HDRSC2&first=1"
        b_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 FootprintHub/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        should_close = False
        if not client:
            client = httpx.AsyncClient(timeout=6.0, follow_redirects=True)
            should_close = True
        try:
            resp = await client.get(url, headers=b_headers, timeout=6.0)
            if resp.status_code == 200:
                murls = re.findall(r'murl&quot;:&quot;(https?://[^&]+)&quot;', resp.text)
                if not murls:
                    murls = re.findall(r'"murl":"(https?://[^"]+)"', resp.text)
                for m in murls:
                    clean_m = m.replace("\\/", "/")
                    if not any(bad in clean_m.lower() for bad in [".svg", "logo", "icon", "banner", "1x1", "placeholder"]):
                        return clean_m
                if murls:
                    return murls[0].replace("\\/", "/")
        except Exception:
            pass
        finally:
            if should_close:
                await client.aclose()
        return None

    @classmethod
    async def enrich_person_profile(
        cls,
        name: str,
        company_name: str,
        domain: str = "",
        client: Optional[httpx.AsyncClient] = None,
    ) -> dict[str, Any]:
        """
        Enriches an individual founder or executive with verified Wikipedia biographical details,
        authoritative person photo, career milestones, and verified source references.
        Only attaches Wikipedia profiles that demonstrably match the person AND company context.
        """
        headers = {
            "User-Agent": "FootprintHub-OSINT/1.0 (https://footprinthub.com; security@footprinthub.com) Mozilla/5.0"
        }
        profile: dict[str, Any] = {
            "photo_url": None,
            "avatar_url": None,
            "bio_summary": "",
            "bio": "",
            "wikipedia_url": "",
            "biography": {},
            "source_references": [],
            "current_role": "",
        }

        should_close = False
        if not client:
            client = httpx.AsyncClient(timeout=8.0, follow_redirects=True, headers=headers)
            should_close = True

        try:
            if domain:
                profile["source_references"].append({
                    "name": f"{company_name} official website",
                    "url": f"https://{domain}",
                    "icon": "🌐",
                })

            # 1. Search Wikipedia strictly using person name + company context to avoid false namesake matches
            matched_title = ""
            comp_tokens = [w for w in company_name.lower().split() if len(w) >= 3]
            domain_root = domain.lower().replace("www.", "").split(".")[0] if domain else ""

            for search_q in [f'"{name}" "{company_name}"', name]:
                search_url = f"https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch={urllib.parse.quote(search_q)}&utf8=&format=json"
                r = await client.get(search_url, headers=headers, timeout=6.0)
                if r.status_code != 200:
                    continue
                results = r.json().get("query", {}).get("search", [])
                for res in results[:3]:
                    t = res.get("title", "")
                    snippet_low = re.sub(r"<[^>]+>", "", res.get("snippet", "")).lower()
                    name_tokens = [w for w in name.lower().split() if len(w) >= 3]
                    name_matches = name.lower() in t.lower() or (len(name_tokens) >= 1 and all(w in t.lower() for w in name_tokens))
                    company_matches = (
                        (company_name and company_name.lower() in snippet_low)
                        or any(ct in snippet_low for ct in comp_tokens)
                        or (domain_root and len(domain_root) >= 3 and domain_root in snippet_low)
                    )
                    if name_matches and company_matches:
                        matched_title = t
                        break
                if matched_title:
                    break

            if matched_title:
                # 2. Query summary and double-check company relation before accepting
                s_url = f"https://en.wikipedia.org/api/rest_v1/page/summary/{urllib.parse.quote(matched_title)}"
                s_resp = await client.get(s_url, headers=headers, timeout=6.0)
                s_extract = ""
                if s_resp.status_code == 200:
                    s_data = s_resp.json()
                    s_extract = s_data.get("extract", "")
                    s_low = s_extract.lower()
                    if any(ct in s_low for ct in comp_tokens) or (domain_root and domain_root in s_low):
                        profile["wikipedia_url"] = f"https://en.wikipedia.org/wiki/{urllib.parse.quote(matched_title.replace(' ', '_'))}"
                        profile["bio_summary"] = s_extract
                        profile["bio"] = s_extract
                        thumb = s_data.get("thumbnail", {}).get("source") or s_data.get("originalimage", {}).get("source")
                        if thumb:
                            profile["photo_url"] = thumb
                            profile["avatar_url"] = thumb
                    else:
                        matched_title = ""

            if matched_title:
                # 3. Parse infobox for biography table & institutional source references
                p_url = f"https://en.wikipedia.org/w/api.php?action=parse&page={urllib.parse.quote(matched_title)}&prop=text&section=0&format=json"
                p_resp = await client.get(p_url, headers=headers, timeout=6.0)
                if p_resp.status_code == 200:
                    html_text = p_resp.json().get("parse", {}).get("text", {}).get("*", "")
                    if html_text:
                        soup = BeautifulSoup(html_text, "html.parser")
                        box = soup.find("table", class_=re.compile(r"infobox", re.I))
                        if box:
                            for tr in box.find_all("tr"):
                                th = tr.find(["th", "td"], class_=re.compile(r"label", re.I)) or tr.find("th")
                                td = tr.find("td", class_=re.compile(r"data", re.I)) or tr.find("td")
                                if not th or not td or th == td:
                                    continue
                                lbl = th.get_text(" ", strip=True).lower().replace("\xa0", " ")
                                val = re.sub(r"\[\s*\d+\s*\]", "", td.get_text(" ", strip=True)).strip()
                                val = re.sub(r"\s+", " ", val)

                                for a_tag in td.find_all("a", href=True):
                                    a_name = a_tag.get_text(strip=True)
                                    if len(a_name) > 3 and not any(stop in a_name.lower() for stop in ["btech", "ms", "phd", "mba", "bsc", "msc", "age", "edit"]):
                                        if not any(ref["name"].lower() == a_name.lower() for ref in profile["source_references"]):
                                            is_inst = any(u in a_name.lower() for u in ["university", "iit", "college", "school", "institute", "academy"])
                                            profile["source_references"].append({
                                                "name": a_name,
                                                "url": f"https://en.wikipedia.org{a_tag['href']}" if a_tag["href"].startswith("/") else a_tag["href"],
                                                "icon": "🏛️" if is_inst else "💼",
                                            })

                                if "born" in lbl:
                                    profile["biography"]["born"] = val
                                elif any(k in lbl for k in ["education", "alma mater"]):
                                    profile["biography"]["education"] = val
                                elif any(k in lbl for k in ["early career", "early life"]):
                                    profile["biography"]["early_career"] = val
                                elif any(k in lbl for k in ["occupation", "profession"]):
                                    profile["biography"]["occupation"] = val
                                elif any(k in lbl for k in ["title", "current role", "role"]):
                                    profile["biography"]["current_role"] = val
                                    profile["current_role"] = val
                                elif any(k in lbl for k in ["honours", "awards", "recognition"]):
                                    profile["biography"]["recognition"] = val
                                elif any(k in lbl for k in ["nationality", "citizenship"]):
                                    profile["biography"]["nationality"] = val
                                elif any(k in lbl for k in ["known for", "known_for"]):
                                    profile["biography"]["known_for"] = val
                                elif "net worth" in lbl:
                                    profile["biography"]["net_worth"] = val
                                elif any(k in lbl for k in ["spouse", "partner"]):
                                    profile["biography"]["spouse"] = val
                                elif "children" in lbl:
                                    profile["biography"]["children"] = val

                        lead_text = soup.get_text()
                        if "company_founded" not in profile["biography"]:
                            found_m = re.search(r"co-founded\s+([A-Za-z0-9\s]+?)\s+in\s+(\d{4})", lead_text, re.I)
                            if found_m:
                                profile["biography"]["company_founded"] = f"{found_m.group(1).strip()}, {found_m.group(2)} (later {company_name})"
                        if "early_career" not in profile["biography"]:
                            early_m = re.search(r"(?:engineer|worked|started (?:his|her) career)\s+at\s+([A-Za-z0-9\s]+?)(?:\.|\,)", lead_text, re.I)
                            if early_m:
                                profile["biography"]["early_career"] = f"{early_m.group(0).strip()}".strip("., ")

            # 4. If photo is still None, search public image index (e.g. Bing Images)
            if not profile["photo_url"]:
                img_candidate = await cls.search_person_image(name, company_name, client=client)
                if img_candidate:
                    profile["photo_url"] = img_candidate
                    profile["avatar_url"] = img_candidate

            profile["source_references"] = profile["source_references"][:4]

        except Exception:
            pass
        finally:
            if should_close:
                await client.aclose()

        return profile


class LinkedInOSINTEngine:
    """
    LinkedIn Open Source Intelligence Engine.
    Compiles official LinkedIn company profiles, verified founder & executive cards,
    complete departmental employee directories, and live targeted Google Dorks.
    """

    @classmethod
    def parse_linkedin_company_html(
        cls, html_text: str, domain: str, company_name: str
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """
        Parses public LinkedIn company page HTML and JSON-LD structured data.
        Extracts verified corporate metadata (followers, logo, description, employee count),
        as well as all associated personnel, current employees, and follower/mention profiles.
        """
        soup = BeautifulSoup(html_text, "html.parser")
        clean_domain = domain.lower().strip()

        meta_info: dict[str, Any] = {
            "title": company_name,
            "followers": None,
            "description": "",
            "logo_url": None,
            "industry": "",
            "headquarters": "",
            "estimated_employees": "",
        }

        # 1. OpenGraph & Meta properties
        og_title = soup.find("meta", property="og:title")
        if og_title and og_title.get("content"):
            meta_info["title"] = og_title["content"].split("|")[0].strip()

        og_desc = (
            soup.find("meta", property="og:description")
            or soup.find("meta", attrs={"name": "description"})
        )
        if og_desc and og_desc.get("content"):
            meta_info["description"] = og_desc["content"].strip()
            fol_m = re.search(r"([0-9,]+)\s+followers", meta_info["description"], re.I)
            if fol_m:
                meta_info["followers"] = fol_m.group(1)

        og_img = soup.find("meta", property="og:image")
        if og_img and og_img.get("content"):
            meta_info["logo_url"] = og_img["content"].strip()

        if not meta_info["followers"]:
            fol_m = re.search(r"([0-9,]+)\s+followers", html_text, re.I)
            if fol_m:
                meta_info["followers"] = fol_m.group(1)

        # Parse JSON-LD for Organization
        for script in soup.find_all("script", type="application/ld+json"):
            try:
                raw_json = script.string or script.get_text()
                if not raw_json:
                    continue
                d = json.loads(raw_json)
                items = d.get("@graph", [d]) if isinstance(d, dict) else (d if isinstance(d, list) else [])
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    if item.get("@type") == "Organization":
                        if item.get("name") and not meta_info["title"]:
                            meta_info["title"] = str(item["name"]).strip()
                        if item.get("description") and not meta_info["description"]:
                            meta_info["description"] = str(item["description"]).strip()
                        if item.get("numberOfEmployees"):
                            ne = item["numberOfEmployees"]
                            meta_info["estimated_employees"] = str(ne.get("value", ne) if isinstance(ne, dict) else ne)
                        if item.get("address"):
                            addr = item["address"]
                            if isinstance(addr, dict):
                                parts = [addr.get("addressLocality"), addr.get("addressCountry")]
                                meta_info["headquarters"] = ", ".join([p for p in parts if p])
            except Exception:
                pass

        # 2. Extract employee directory & personal profiles (/in/ links)
        employees: list[dict[str, Any]] = []
        seen_slugs: set[str] = set()

        for a in soup.find_all("a", href=re.compile(r"linkedin\.com/in/([a-zA-Z0-9_-]+)", re.I)):
            href = a.get("href", "")
            m = re.search(r"linkedin\.com/in/([a-zA-Z0-9_-]+)", href, re.I)
            if not m:
                continue
            slug = m.group(1).rstrip("/")
            if slug.lower() in ("in", "company", "school", "pub", "feed", "posts", "pulse"):
                continue

            slug_key = slug.lower()
            if slug_key in seen_slugs:
                continue
            seen_slugs.add(slug_key)

            clean_url = f"https://www.linkedin.com/in/{slug}"

            raw_text = a.get_text(" ", strip=True)
            if (
                raw_text
                and 1 < len(raw_text.split()) <= 4
                and not any(w in raw_text.lower() for w in ["view", "more", "profile", "connect", "follow", "see", "join"])
            ):
                name = raw_text
            else:
                name = CompanyMetadataScraper.clean_slug_to_name(slug)

            parent = a.find_parent(["div", "li", "article", "section", "p"])
            parent_text = parent.get_text(" ", strip=True) if parent else ""

            # Avatar image
            img = a.find("img") or (parent.find("img") if parent else None)
            avatar = None
            if img:
                avatar = img.get("src") or img.get("data-delayed-url")
                if avatar and avatar.startswith("data:"):
                    avatar = None

            is_direct_employee = "org-employees" in href or "employee" in href.lower()

            title = "Company Employee" if is_direct_employee else "Staff / Team Member"
            role_m = re.search(
                r"\b((?:Co-)?Founder(?:\s*(?:&|and)\s*[\w\s]+)?|CEO|CTO|COO|CFO|CISO|President|Managing Director|Director|VP|Lead\s+[\w\s]+|Senior\s+[\w\s]+|Software\s+[\w\s]+|Engineer|Analyst|Consultant|Developer|Designer|Educator|Instructor|Manager|Specialist)\b",
                parent_text,
                re.I,
            )
            if role_m:
                title = role_m.group(0).strip().title()
            elif not is_direct_employee:
                title = "Associated Professional / Follower"

            # Department & Executive classification
            # If not direct employee, they are a follower or mention, never executive leadership
            if not is_direct_employee or any(f in title.lower() for f in ["follower", "associated", "mention", "fan"]):
                dept = "Operations & Business"
                is_exec = False
            elif any(w in title.lower() for w in ["founder", "ceo", "chief executive", "president", "coo", "cto", "cfo", "director", "managing"]):
                dept = "Executive Leadership"
                is_exec = True
            elif any(w in title.lower() for w in ["security", "ciso", "soc", "analyst", "forensics", "infosec", "network"]):
                dept = "Cybersecurity & IT"
                is_exec = False
            elif any(w in title.lower() for w in ["engineer", "developer", "architect", "tech", "software", "ai", "cloud"]):
                dept = "Engineering & Tech"
                is_exec = False
            else:
                dept = "Operations & Business"
                is_exec = False

            first_n = name.split()[0].lower() if name.split() else "user"
            last_n = name.split()[-1].lower() if len(name.split()) > 1 else "name"
            inferred_email = f"{first_n}.{last_n}@{clean_domain}"

            employees.append(
                {
                    "name": name,
                    "title": title,
                    "department": dept,
                    "linkedin_url": clean_url,
                    "linkedin_search_url": f"https://www.linkedin.com/search/results/people/?keywords={urllib.parse.quote(name + ' ' + company_name)}",
                    "avatar_url": avatar,
                    "inferred_email": inferred_email,
                    "bio": f"Associated with {company_name} on LinkedIn ({'Current Organization Employee' if is_direct_employee else 'LinkedIn Follower & Mention'})",
                    "source": "LinkedIn Company Page (" + ("Employee Directory" if is_direct_employee else "Mentions & Followers") + ")",
                    "is_verified": True,
                    "is_founder": is_exec,
                    "risk_level": "High Risk: Primary Target for Spear-Phishing & BEC" if is_exec else "Elevated: Public Identity Exposes Organization Footprint",
                }
            )

        return meta_info, employees

    @classmethod
    async def fetch_and_build_linkedin_intelligence(
        cls,
        domain: str,
        company_name: str,
        website_social_profiles: list[dict[str, Any]],
        company_meta: dict[str, Any],
        github_intel: dict[str, Any],
        enriched_email_profiles: list[dict[str, Any]],
        client: Optional[httpx.AsyncClient] = None,
    ) -> dict[str, Any]:
        """
        Asynchronously fetches and synthesizes complete LinkedIn company intelligence.
        Identifies official LinkedIn company profile, queries company page for followers
        and employee accounts, and builds unified directory.
        """
        clean_domain = domain.lower().strip()
        slug_fallback = re.sub(r"[^a-zA-Z0-9_-]", "-", company_name.lower().strip())
        domain_slug = clean_domain.replace("www.", "").split(".")[0]

        # 1. Discover or resolve candidate LinkedIn company URLs
        company_url = f"https://www.linkedin.com/company/{slug_fallback}"
        company_slug = slug_fallback
        linkedin_profiles = [p for p in website_social_profiles if p.get("platform") == "LinkedIn"]
        company_pages = [p for p in linkedin_profiles if p.get("type") == "company"]

        urls_to_try: list[str] = []
        if company_pages:
            company_url = company_pages[0]["url"]
            company_slug = company_pages[0]["handle"]
            urls_to_try.append(company_url)
        else:
            for cand in [slug_fallback, domain_slug, f"{domain_slug}-technologies", f"{domain_slug}-solutions", f"{domain_slug}it"]:
                cand_clean = re.sub(r"[^a-zA-Z0-9_-]", "-", cand.lower().strip()).strip("-")
                if cand_clean and cand_clean not in [u.split("/")[-1] for u in urls_to_try]:
                    urls_to_try.append(f"https://www.linkedin.com/company/{cand_clean}")

        # Add candidate slugs from Open Knowledge / Wikipedia harvester
        for c_slug in company_meta.get("candidate_slugs", []):
            c_url = f"https://www.linkedin.com/company/{c_slug}"
            if c_url not in urls_to_try:
                urls_to_try.append(c_url)

        crawled_employees: list[dict[str, Any]] = []
        company_details: dict[str, Any] = {}

        # 2. Safely query the public LinkedIn company page
        if client and urls_to_try:
            for target_url in urls_to_try[:3]:
                try:
                    resp = await client.get(target_url, timeout=7.0)
                    if resp.status_code == 200 and resp.text and len(resp.text) > 2000:
                        company_url = str(resp.url).rstrip("/")
                        company_slug = company_url.split("/")[-1].split("?")[0]
                        c_meta, c_emps = cls.parse_linkedin_company_html(
                            resp.text, clean_domain, company_name
                        )
                        company_details = c_meta
                        crawled_employees.extend(c_emps)

                        # If not already present in website_social_profiles, add this discovered LinkedIn channel
                        if not any(p.get("platform") == "LinkedIn" and p.get("type") == "company" for p in website_social_profiles):
                            website_social_profiles.append({
                                "platform": "LinkedIn",
                                "handle": company_slug,
                                "url": company_url,
                                "type": "company",
                                "icon": "💼",
                                "found_on_website": False,
                                "source": "LinkedIn Public Directory",
                            })
                        break
                except Exception:
                    pass

        # 3. Build unified LinkedIn intelligence
        return cls.build_linkedin_intelligence(
            domain=domain,
            company_name=company_name,
            website_social_profiles=website_social_profiles,
            company_meta=company_meta,
            github_intel=github_intel,
            enriched_email_profiles=enriched_email_profiles,
            crawled_linkedin_employees=crawled_employees,
            company_details=company_details,
        )

    @classmethod
    def build_linkedin_intelligence(
        cls,
        domain: str,
        company_name: str,
        website_social_profiles: list[dict[str, Any]],
        company_meta: dict[str, Any],
        github_intel: dict[str, Any],
        enriched_email_profiles: list[dict[str, Any]],
        crawled_linkedin_employees: Optional[list[dict[str, Any]]] = None,
        company_details: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        Synthesizes complete LinkedIn company overview, founder data,
        employee directory, and targeted search queries.
        """
        clean_domain = domain.lower().strip()
        slug_fallback = re.sub(r"[^a-zA-Z0-9_-]", "-", company_name.lower().strip())

        # 1. Discover official LinkedIn Company URL
        company_url = f"https://www.linkedin.com/company/{slug_fallback}"
        company_slug = slug_fallback
        linkedin_profiles = [p for p in website_social_profiles if p.get("platform") == "LinkedIn"]
        company_pages = [p for p in linkedin_profiles if p.get("type") == "company"]

        if company_pages:
            company_url = company_pages[0]["url"]
            company_slug = company_pages[0]["handle"]

        # 2. Curate Real Founders & Executives (Strictly verified people only, NO fake placeholders!)
        founders: list[dict[str, Any]] = []
        seen_founders: set[str] = set()

        def _clean_email_part(part: str, fallback: str) -> str:
            cleaned = re.sub(r"[^a-z0-9]", "", part.lower())
            return cleaned or fallback

        for f in company_meta.get("founders", []):
            f_name = f.get("name", "").strip()
            if f_name and f_name.lower() not in seen_founders:
                seen_founders.add(f_name.lower())
                f_parts = f_name.split()
                first_name = _clean_email_part(f_parts[0], "user") if f_parts else "user"
                last_name = _clean_email_part(f_parts[-1], "name") if len(f_parts) > 1 else "name"
                inferred_email = f"{first_name}.{last_name}@{clean_domain}"
                
                founders.append(
                    {
                        "name": f_name,
                        "title": f.get("title") or "Founder & Executive",
                        "department": "Executive Leadership",
                        "linkedin_url": f.get("linkedin_url") or "",
                        "linkedin_search_url": f.get("linkedin_url") or f"https://www.linkedin.com/search/results/people/?keywords={urllib.parse.quote(f_name + ' ' + company_name)}",
                        "avatar_url": f.get("avatar_url") or f.get("photo_url"),
                        "photo_url": f.get("photo_url") or f.get("avatar_url"),
                        "bio": f.get("bio") or f.get("bio_summary") or f"Leadership at {company_name}",
                        "bio_summary": f.get("bio_summary") or f.get("bio") or "",
                        "biography": f.get("biography") or {},
                        "source_references": f.get("source_references") or [],
                        "wikipedia_url": f.get("wikipedia_url") or "",
                        "source": f.get("source") or "Website Team Page",
                        "is_verified": True,
                        "inferred_email": inferred_email,
                        "risk_level": "High Risk: Primary Target for Spear-Phishing & BEC Impersonation",
                    }
                )

        # 3. Assemble Complete Employee Directory (Real scraped individuals only)
        employee_directory: list[dict[str, Any]] = []
        seen_employees: set[str] = set()
        seen_emp_li_slugs: set[str] = set()

        def add_employee(emp: dict[str, Any]):
            name = emp.get("name", "").strip()
            li_url = (emp.get("linkedin_url") or "").strip()
            li_m = re.search(r"linkedin\.com/in/([a-zA-Z0-9_.-]+)", li_url, re.I)
            li_slug = li_m.group(1).rstrip("/").lower() if li_m else ""
            key = (name.lower() or emp.get("email", "").lower() or li_url.lower())
            if not key or key in seen_employees or (li_slug and li_slug in seen_emp_li_slugs):
                return
            seen_employees.add(key)
            if li_slug:
                seen_emp_li_slugs.add(li_slug)
            employee_directory.append(emp)

        # Add verified founders first
        for f in founders:
            add_employee(f)

        # Add scraped team members from website HTML/JS before fallback LinkedIn slugs
        for t in company_meta.get("scraped_team", []):
            t_name = t.get("name", "").strip()
            t_parts = t_name.split()
            first_name = _clean_email_part(t_parts[0], "user") if t_parts else "user"
            last_name = _clean_email_part(t_parts[-1], "name") if len(t_parts) > 1 else "name"
            t["inferred_email"] = f"{first_name}.{last_name}@{clean_domain}"
            t["is_verified"] = True
            t["risk_level"] = "Elevated: Public Identity Exposes Corporate Structure"
            add_employee(t)

        # Add crawled LinkedIn employees and followers from company page
        if crawled_linkedin_employees:
            for c_emp in crawled_linkedin_employees:
                add_employee(c_emp)
                # Only promote to founders if STRICTLY verified direct executive (never followers or general staff)
                if c_emp.get("is_founder") and not any(w in c_emp.get("title", "").lower() for w in ["follower", "associated", "staff", "member"]):
                    c_name = c_emp.get("name", "").strip()
                    if c_name and c_name.lower() not in seen_founders:
                        seen_founders.add(c_name.lower())
                        founders.append(c_emp)

        # Add personal LinkedIn profiles discovered on the target website (only if not already matched above)
        for p in website_social_profiles:
            if p.get("platform") == "LinkedIn" and p.get("type") == "personal":
                slug = p.get("handle") or ""
                p_url = p.get("url") or f"https://www.linkedin.com/in/{slug}"
                p_name = CompanyMetadataScraper.clean_slug_to_name(slug) if slug else "Team Member"
                p_parts = p_name.split()
                first_name = _clean_email_part(p_parts[0], "user") if p_parts else "user"
                last_name = _clean_email_part(p_parts[-1], "name") if len(p_parts) > 1 else "name"
                inferred_email = f"{first_name}.{last_name}@{clean_domain}"
                add_employee({
                    "name": p_name,
                    "title": "Staff / Team Member",
                    "department": "Engineering & Tech",
                    "linkedin_url": p_url,
                    "linkedin_search_url": f"https://www.linkedin.com/search/results/people/?keywords={urllib.parse.quote(p_name + ' ' + company_name)}",
                    "avatar_url": None,
                    "inferred_email": inferred_email,
                    "bio": f"Identified via website LinkedIn personal profile link: {p_url}",
                    "source": "Website LinkedIn Profile Link",
                    "is_verified": True,
                    "risk_level": "Elevated: Public Identity Exposes Corporate Structure",
                })

        # Add GitHub public organization members
        for m in github_intel.get("members", []):
            m_name = m.get("name") or m.get("login")
            add_employee(
                {
                    "name": m_name,
                    "title": f"Developer / Contributor (@{m.get('login')})",
                    "department": "Engineering & Tech",
                    "linkedin_url": "",
                    "linkedin_search_url": f"https://www.linkedin.com/search/results/people/?keywords={urllib.parse.quote(m_name + ' ' + company_name)}",
                    "avatar_url": m.get("avatar_url"),
                    "email": m.get("email"),
                    "bio": m.get("bio") or f"Public GitHub member of @{github_intel.get('handle', '')}",
                    "source": "GitHub Organization Member",
                }
            )

        # Add Behind the Email enriched identities
        for prof in enriched_email_profiles:
            p_data = prof.get("profile_enrichment", {})
            full_name = p_data.get("full_name") or p_data.get("username")
            inferred_role = p_data.get("inferred_role") or "Corporate Account"
            dept = p_data.get("department") or "Operations & Business"

            dept_normalized = "Operations & Business"
            if any(w in dept.lower() for w in ["security", "infrastructure"]):
                dept_normalized = "Cybersecurity & IT"
            elif any(w in dept.lower() for w in ["engineering", "architecture", "technology"]):
                dept_normalized = "Engineering & Tech"
            elif any(w in dept.lower() for w in ["executive", "management", "founder"]):
                dept_normalized = "Executive Leadership"

            add_employee(
                {
                    "name": full_name,
                    "title": inferred_role,
                    "department": dept_normalized,
                    "linkedin_url": "",
                    "linkedin_search_url": p_data.get("linkedin_search_url")
                    or f"https://www.linkedin.com/search/results/people/?keywords={urllib.parse.quote(full_name + ' ' + company_name)}",
                    "avatar_url": prof.get("avatar_url"),
                    "email": prof.get("email"),
                    "bio": f"Role: {inferred_role} ({dept})",
                    "source": "Discovered Corporate Identity",
                }
            )

        # 4. Role-based targeted Google Dorks for LinkedIn Reconnaissance
        dorks = [
            {
                "role_category": "All Company Personnel",
                "description": f"Enumerate all registered LinkedIn employee profiles working at {company_name}",
                "dork": f'site:linkedin.com/in/ "{company_name}"',
                "url": f'https://www.google.com/search?q=site:linkedin.com/in/+"{urllib.parse.quote(company_name)}"',
            },
            {
                "role_category": "Executive Leadership & Board",
                "description": f"C-Suite executives (CEO, CTO, CFO, Founder, Managing Director, VP) at {company_name}",
                "dork": f'site:linkedin.com/in/ "{company_name}" (CEO OR CTO OR CFO OR "Chief" OR Director OR Founder OR VP)',
                "url": f'https://www.google.com/search?q=site:linkedin.com/in/+"{urllib.parse.quote(company_name)}"+(CEO+OR+CTO+OR+CFO+OR+"Chief"+OR+Director+OR+Founder+OR+VP)',
            },
            {
                "role_category": "Cybersecurity & IT Infrastructure",
                "description": f"Security engineers, CISO, SOC analysts, and DevOps staff at {company_name}",
                "dork": f'site:linkedin.com/in/ "{company_name}" ("Security" OR "IT" OR "DevOps" OR "Sysadmin" OR "CISO" OR "Cloud" OR "Cyber")',
                "url": f'https://www.google.com/search?q=site:linkedin.com/in/+"{urllib.parse.quote(company_name)}"+("Security"+OR+"IT"+OR+"DevOps"+OR+"Sysadmin"+OR+"CISO"+OR+"Cloud"+OR+"Cyber")',
            },
            {
                "role_category": "Software Engineering & Tech Stack",
                "description": f"Software engineers, architects, and developers disclosing stack details",
                "dork": f'site:linkedin.com/in/ "{company_name}" ("Software Engineer" OR "Developer" OR "Architect" OR "Backend" OR "Frontend")',
                "url": f'https://www.google.com/search?q=site:linkedin.com/in/+"{urllib.parse.quote(company_name)}"+("Software+Engineer"+OR+"Developer"+OR+"Architect"+OR+"Backend"+OR+"Frontend")',
            },
            {
                "role_category": "Job Postings & Tech Stack Insights",
                "description": f"Active job hiring postings by {company_name} revealing tech stack and expansion areas",
                "dork": f'site:linkedin.com/jobs "{company_name}"',
                "url": f'https://www.google.com/search?q=site:linkedin.com/jobs+"{urllib.parse.quote(company_name)}"',
            },
        ]

        result_payload: dict[str, Any] = {
            "company_name": company_name,
            "company_url": company_url,
            "company_slug": company_slug,
            "company_search_url": f"https://www.linkedin.com/search/results/companies/?keywords={urllib.parse.quote(company_name)}",
            "people_search_url": f"https://www.linkedin.com/search/results/people/?keywords={urllib.parse.quote(company_name)}",
            "detected_email_pattern": f"{{first}}.{{last}}@{clean_domain}",
            "founders": founders,
            "employees": employee_directory,
            "employee_count": len(employee_directory),
            "dorks": dorks,
        }

        if company_details:
            result_payload["company_details"] = company_details
            if company_details.get("followers"):
                result_payload["followers"] = company_details["followers"]
            if company_details.get("logo_url"):
                result_payload["logo_url"] = company_details["logo_url"]

        return result_payload


class CompanyDigitalFootprintEngine:
    """
    Compiles public corporate registers, registry lookups (OpenCorporates,
    Crunchbase, SEC EDGAR, Google Knowledge Graph), and categorizes all social
    media channels into corporate, developer, and community presence.
    """

    @classmethod
    def build_digital_footprint(
        cls,
        domain: str,
        company_name: str,
        website_social_profiles: list[dict[str, Any]],
        company_meta: dict[str, Any],
    ) -> dict[str, Any]:
        """Build public registry links and categorized digital footprint."""
        encoded_company = urllib.parse.quote(company_name)

        # Public Registries & Corporate Footprint Links
        registries = [
            {
                "name": "OpenCorporates",
                "description": "Worldwide corporate entity registry & incorporation filing",
                "url": f"https://opencorporates.com/companies?q={encoded_company}",
                "icon": "🏛️",
            },
            {
                "name": "Crunchbase",
                "description": "Company profile, funding rounds, founders & acquisitions",
                "url": f"https://www.crunchbase.com/textsearch?q={encoded_company}",
                "icon": "📊",
            },
            {
                "name": "SEC EDGAR",
                "description": "Public financial filings, quarterly reports & ownership",
                "url": f"https://www.sec.gov/edgar/searchedgar/companysearch?companyName={encoded_company}",
                "icon": "📑",
            },
            {
                "name": "Google Knowledge Graph",
                "description": "Public company overview & verified knowledge graph entry",
                "url": f"https://www.google.com/search?q={encoded_company}+company+profile",
                "icon": "🌐",
            },
            {
                "name": "WHOIS Domain Registry",
                "description": f"Domain registration, nameservers & ownership records for {domain}",
                "url": f"https://whois.domaintools.com/{domain}",
                "icon": "🔎",
            },
        ]

        # Categorize social profiles
        official_channels: list[dict[str, Any]] = []
        developer_channels: list[dict[str, Any]] = []
        community_channels: list[dict[str, Any]] = []

        for p in website_social_profiles:
            plat = p.get("platform", "")
            if plat in ("LinkedIn", "Twitter / X", "Facebook", "YouTube", "Crunchbase"):
                official_channels.append(p)
            elif plat in ("GitHub", "Reddit", "Medium", "Discord"):
                developer_channels.append(p)
            else:
                community_channels.append(p)

        return {
            "company_name": company_name,
            "domain": domain,
            "description": company_meta.get("description", ""),
            "industry": company_meta.get("industry", "Technology & Software"),
            "founded_year": company_meta.get("founded_year"),
            "headquarters": company_meta.get("headquarters"),
            "estimated_employees": company_meta.get("estimated_employees", "11-50 employees"),
            "registries": registries,
            "official_channels": official_channels,
            "developer_channels": developer_channels,
            "community_channels": community_channels,
            "all_social_profiles": website_social_profiles,
        }


class WebsiteIntelligenceEngine:
    """
    Comprehensive Internet-Wide OSINT Intelligence Engine.
    Gathers publicly available information about a website from across the internet:
    - Wayback Machine / Internet Archive historical snapshots
    - Internet-wide infrastructure intelligence (Shodan, Censys, BuiltWith)
    - Company review & reputation intelligence (Glassdoor, Trustpilot, BBB)
    - News, press, and media mentions
    - Domain age and registration intelligence
    - Technology stack disclosure from job postings
    - Aggregated company intelligence summary
    """

    @classmethod
    async def gather_wayback_intelligence(
        cls, domain: str, client: httpx.AsyncClient
    ) -> dict[str, Any]:
        """Query the Wayback Machine CDX API for historical snapshots of the target domain."""
        wayback: dict[str, Any] = {
            "available": False,
            "total_snapshots": 0,
            "oldest_snapshot": None,
            "newest_snapshot": None,
            "notable_years": [],
            "archive_url": f"https://web.archive.org/web/*/{domain}",
            "first_seen_url": "",
        }

        try:
            # Check availability
            resp = await client.get(
                f"https://archive.org/wayback/available?url={domain}",
                timeout=6.0,
            )
            if resp.status_code == 200:
                wb_data = resp.json()
                closest = wb_data.get("archived_snapshots", {}).get("closest", {})
                if closest.get("available"):
                    wayback["available"] = True
                    wayback["newest_snapshot"] = {
                        "timestamp": closest.get("timestamp", ""),
                        "url": closest.get("url", ""),
                        "status": closest.get("status", ""),
                    }
                    wayback["first_seen_url"] = closest.get("url", "")

            # Get CDX summary for snapshot count and date range
            cdx_resp = await client.get(
                f"https://web.archive.org/cdx/search/cdx?url={domain}&output=json&limit=5&fl=timestamp,statuscode&collapse=timestamp:4",
                timeout=8.0,
            )
            if cdx_resp.status_code == 200:
                cdx_data = cdx_resp.json()
                if len(cdx_data) > 1:  # First row is headers
                    rows = cdx_data[1:]
                    wayback["available"] = True
                    years = sorted(set(r[0][:4] for r in rows if len(r[0]) >= 4))
                    wayback["notable_years"] = years
                    if rows:
                        wayback["oldest_snapshot"] = {
                            "year": rows[0][0][:4],
                            "timestamp": rows[0][0],
                            "url": f"https://web.archive.org/web/{rows[0][0]}/{domain}",
                        }
                    wayback["total_snapshots"] = len(rows)
        except Exception:
            pass

        return wayback

    @classmethod
    def build_internet_intelligence(
        cls,
        domain: str,
        company_name: str,
        company_meta: dict[str, Any],
        website_social_profiles: list[dict[str, Any]],
        wayback_data: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Build comprehensive internet-wide intelligence about the target website.
        Aggregates data from multiple OSINT sources and provides actionable lookup links.
        """
        encoded_domain = urllib.parse.quote(domain)
        encoded_company = urllib.parse.quote(company_name)

        # ── Infrastructure & Technical Intelligence Lookups ──────────────
        infrastructure_intel = [
            {
                "name": "Shodan",
                "category": "Infrastructure",
                "description": f"Internet-wide scan results: open ports, services, SSL certs, vulnerabilities for {domain}",
                "url": f"https://www.shodan.io/search?query=hostname:{domain}",
                "icon": "🔭",
            },
            {
                "name": "Censys",
                "category": "Infrastructure",
                "description": f"Certificate transparency logs, host enumeration, and TLS configuration for {domain}",
                "url": f"https://search.censys.io/search?resource=hosts&q={encoded_domain}",
                "icon": "🔬",
            },
            {
                "name": "BuiltWith",
                "category": "Technology",
                "description": f"Complete technology stack profile: CMS, CDN, analytics, frameworks used by {domain}",
                "url": f"https://builtwith.com/{domain}",
                "icon": "🏗️",
            },
            {
                "name": "SecurityTrails",
                "category": "DNS History",
                "description": f"Historical DNS records, IP address changes, and domain ownership history for {domain}",
                "url": f"https://securitytrails.com/domain/{domain}",
                "icon": "🛤️",
            },
            {
                "name": "DNSDumpster",
                "category": "DNS Mapping",
                "description": f"Domain DNS mapping, attack surface visualization, and host discovery",
                "url": f"https://dnsdumpster.com/",
                "icon": "🗺️",
            },
            {
                "name": "Netcraft",
                "category": "Site Report",
                "description": f"Website hosting history, technology, SSL certificate chain, and risk assessment",
                "url": f"https://sitereport.netcraft.com/?url={domain}",
                "icon": "🌍",
            },
            {
                "name": "crt.sh",
                "category": "Certificates",
                "description": f"Certificate Transparency log search — all SSL/TLS certificates issued for {domain}",
                "url": f"https://crt.sh/?q=%25.{domain}",
                "icon": "📜",
            },
            {
                "name": "ViewDNS.info",
                "category": "DNS Tools",
                "description": f"Reverse IP lookup, WHOIS, DNS propagation, and IP history for {domain}",
                "url": f"https://viewdns.info/reverseip/?host={domain}&t=1",
                "icon": "🔎",
            },
        ]

        # ── Company Review & Reputation Intelligence ────────────────────
        reputation_intel = [
            {
                "name": "Glassdoor",
                "category": "Employee Reviews",
                "description": f"Employee reviews, salaries, interview experiences, and company culture for {company_name}",
                "url": f"https://www.glassdoor.com/Search/results.htm?keyword={encoded_company}",
                "icon": "⭐",
            },
            {
                "name": "Trustpilot",
                "category": "Customer Reviews",
                "description": f"Customer trust score, reviews, and complaint history for {company_name}",
                "url": f"https://www.trustpilot.com/search?query={encoded_company}",
                "icon": "🏆",
            },
            {
                "name": "Better Business Bureau",
                "category": "Business Rating",
                "description": f"BBB accreditation status, customer complaints, and business rating",
                "url": f"https://www.bbb.org/search?find_text={encoded_company}",
                "icon": "📋",
            },
            {
                "name": "Indeed",
                "category": "Employer Profile",
                "description": f"Company reviews, job postings, and salary data from employees and applicants",
                "url": f"https://www.indeed.com/cmp/{company_name.lower().replace(' ', '-')}/reviews",
                "icon": "💼",
            },
            {
                "name": "G2",
                "category": "Software Reviews",
                "description": f"Product reviews, pricing, and competitive alternatives for {company_name}'s software",
                "url": f"https://www.g2.com/search?query={encoded_company}",
                "icon": "📊",
            },
        ]

        # ── News, Press & Media Mentions ────────────────────────────────
        news_intel = [
            {
                "name": "Google News",
                "category": "News",
                "description": f"Latest news articles, press releases, and media mentions for {company_name}",
                "url": f"https://news.google.com/search?q={encoded_company}",
                "icon": "📰",
            },
            {
                "name": "TechCrunch",
                "category": "Tech News",
                "description": f"Startup funding, product launches, and technology news coverage",
                "url": f"https://techcrunch.com/search/{encoded_company}",
                "icon": "🚀",
            },
            {
                "name": "PitchBook",
                "category": "Funding & VC",
                "description": f"Venture capital funding rounds, investors, and valuation data",
                "url": f"https://pitchbook.com/profiles/company/{company_name.lower().replace(' ', '-')}",
                "icon": "💰",
            },
            {
                "name": "AngelList",
                "category": "Startup Profile",
                "description": f"Startup profile, team members, job listings, and investor details",
                "url": f"https://wellfound.com/company/{company_name.lower().replace(' ', '-')}",
                "icon": "👼",
            },
            {
                "name": "Product Hunt",
                "category": "Product Launch",
                "description": f"Product launches, user reviews, and maker profiles for {company_name}",
                "url": f"https://www.producthunt.com/search?q={encoded_company}",
                "icon": "🎯",
            },
        ]

        # ── Legal & Compliance Lookups ──────────────────────────────────
        legal_intel = [
            {
                "name": "ICANN WHOIS",
                "category": "Domain Registration",
                "description": f"Official ICANN WHOIS domain registration and ownership records",
                "url": f"https://lookup.icann.org/lookup?name={domain}",
                "icon": "🏛️",
            },
            {
                "name": "Google Transparency Report",
                "category": "Safe Browsing",
                "description": f"Google Safe Browsing threat status and site safety analysis",
                "url": f"https://transparencyreport.google.com/safe-browsing/search?url={domain}",
                "icon": "🛡️",
            },
            {
                "name": "URLScan.io",
                "category": "URL Analysis",
                "description": f"Live website scan with screenshots, DOM analysis, and resource inspection",
                "url": f"https://urlscan.io/search/#domain:{domain}",
                "icon": "🔍",
            },
            {
                "name": "VirusTotal",
                "category": "Malware & Threats",
                "description": f"Multi-engine antivirus scan, domain reputation, and threat intelligence",
                "url": f"https://www.virustotal.com/gui/domain/{domain}",
                "icon": "🦠",
            },
        ]

        # ── LinkedIn Deep Intelligence Queries ──────────────────────────
        linkedin_deep_queries = [
            {
                "name": "Company Employees (Current)",
                "description": f"All current employees at {company_name} on LinkedIn",
                "dork": f'site:linkedin.com/in "{company_name}" "Present"',
                "url": f'https://www.google.com/search?q=site:linkedin.com/in+"{encoded_company}"+"Present"',
                "icon": "👥",
            },
            {
                "name": "Former Employees",
                "description": f"People who previously worked at {company_name} — may reveal internal culture & stack",
                "dork": f'site:linkedin.com/in "{company_name}" -"Present"',
                "url": f'https://www.google.com/search?q=site:linkedin.com/in+"{encoded_company}"+-"Present"',
                "icon": "🚶",
            },
            {
                "name": "Hiring Managers & Recruiters",
                "description": f"HR & recruiting contacts at {company_name} — reveals org structure",
                "dork": f'site:linkedin.com/in "{company_name}" ("Recruiter" OR "Talent Acquisition" OR "HR")',
                "url": f'https://www.google.com/search?q=site:linkedin.com/in+"{encoded_company}"+("Recruiter"+OR+"Talent+Acquisition"+OR+"HR")',
                "icon": "🎯",
            },
            {
                "name": "Engineering & DevOps Team",
                "description": f"Technical staff revealing technology stack and internal architecture",
                "dork": f'site:linkedin.com/in "{company_name}" ("Engineer" OR "DevOps" OR "Developer" OR "Architect")',
                "url": f'https://www.google.com/search?q=site:linkedin.com/in+"{encoded_company}"+("Engineer"+OR+"DevOps"+OR+"Developer"+OR+"Architect")',
                "icon": "⚙️",
            },
            {
                "name": "Security & Compliance Team",
                "description": f"Security personnel revealing defense posture and compliance frameworks",
                "dork": f'site:linkedin.com/in "{company_name}" ("Security" OR "CISO" OR "Compliance" OR "SOC" OR "Pentest")',
                "url": f'https://www.google.com/search?q=site:linkedin.com/in+"{encoded_company}"+("Security"+OR+"CISO"+OR+"Compliance"+OR+"SOC"+OR+"Pentest")',
                "icon": "🔐",
            },
            {
                "name": "Company Job Postings",
                "description": f"Active job postings revealing expansion areas, tech stack requirements, and team gaps",
                "dork": f'site:linkedin.com/jobs "{company_name}"',
                "url": f'https://www.google.com/search?q=site:linkedin.com/jobs+"{encoded_company}"',
                "icon": "📋",
            },
        ]

        # ── Social Media Deep Intelligence ──────────────────────────────
        social_deep_queries = [
            {
                "name": "Twitter/X Mentions",
                "description": f"Public tweets and discussions mentioning {company_name} or {domain}",
                "url": f"https://x.com/search?q={encoded_company}+OR+{encoded_domain}&f=live",
                "icon": "🐦",
            },
            {
                "name": "Reddit Mentions",
                "description": f"Reddit discussions, complaints, and insider info about {company_name}",
                "url": f"https://www.reddit.com/search/?q={encoded_company}&type=link&sort=new",
                "icon": "🟠",
            },
            {
                "name": "YouTube Content",
                "description": f"Video content, tutorials, and reviews related to {company_name}",
                "url": f"https://www.youtube.com/results?search_query={encoded_company}",
                "icon": "▶️",
            },
            {
                "name": "Hacker News",
                "description": f"Tech community discussions and submissions about {company_name} or {domain}",
                "url": f"https://hn.algolia.com/?q={encoded_company}",
                "icon": "🔶",
            },
            {
                "name": "Stack Overflow",
                "description": f"Technical questions and community contributions associated with {company_name}",
                "url": f"https://stackoverflow.com/search?q={encoded_company}",
                "icon": "📚",
            },
        ]

        # ── Categorize found website social profiles ────────────────────
        social_summary = {
            "total_found": len(website_social_profiles),
            "platforms": sorted(set(p.get("platform", "") for p in website_social_profiles)),
            "linkedin_profiles": [p for p in website_social_profiles if p.get("platform") == "LinkedIn"],
            "linkedin_company_pages": [
                p for p in website_social_profiles
                if p.get("platform") == "LinkedIn" and p.get("type") == "company"
            ],
            "linkedin_personal_profiles": [
                p for p in website_social_profiles
                if p.get("platform") == "LinkedIn" and p.get("type") == "personal"
            ],
            "other_social": [
                p for p in website_social_profiles
                if p.get("platform") != "LinkedIn"
            ],
        }

        # ── Compute Wayback Machine age estimate ────────────────────────
        domain_age_estimate = None
        if wayback_data.get("oldest_snapshot") and wayback_data["oldest_snapshot"].get("year"):
            try:
                oldest_year = int(wayback_data["oldest_snapshot"]["year"])
                from datetime import datetime
                current_year = datetime.now().year
                domain_age_estimate = f"{current_year - oldest_year}+ years (first archived in {oldest_year})"
            except (ValueError, TypeError):
                pass

        return {
            "domain": domain,
            "company_name": company_name,
            "domain_age_estimate": domain_age_estimate,
            "wayback_machine": wayback_data,
            "infrastructure_intel": infrastructure_intel,
            "reputation_intel": reputation_intel,
            "news_intel": news_intel,
            "legal_intel": legal_intel,
            "linkedin_deep_queries": linkedin_deep_queries,
            "social_deep_queries": social_deep_queries,
            "social_summary": social_summary,
        }
