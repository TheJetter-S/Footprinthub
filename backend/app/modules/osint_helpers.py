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
import logging
import re
import time
import urllib.parse
import urllib.robotparser
from typing import Any, Optional

from bs4 import BeautifulSoup
import httpx

from app.config import settings
from app.core.safe_request import safe_request, USER_AGENT as SAFE_USER_AGENT

logger = logging.getLogger("footprinthub.osint")

# In-memory TTL cache for Wikipedia / Wikidata / search / robots.txt
_OSINT_RESPONSE_CACHE: dict[str, tuple[float, httpx.Response]] = {}
_ROBOTS_CACHE: dict[str, tuple[float, Optional[urllib.robotparser.RobotFileParser]]] = {}


def validate_image_url(url: Optional[str], base_domain: str = "") -> Optional[str]:
    """Validate and normalize public image URLs (rejects data URIs and unsafe schemes)."""
    if not url or not isinstance(url, str):
        return None
    u = url.strip()
    if not u or u.startswith("data:") or u.startswith("javascript:"):
        return None
    if u.startswith("//"):
        u = f"https:{u}"
    elif u.startswith("/") and base_domain:
        clean_host = base_domain.replace("https://", "").replace("http://", "").split("/")[0]
        u = f"https://{clean_host}{u}"
    if not u.startswith(("http://", "https://")):
        return None
    if " " in u:
        u = u.replace(" ", "%20")
    return u


async def safe_osint_request(
    method: str,
    url: str,
    *,
    client: Optional[Any] = None,
    headers: Optional[dict[str, str]] = None,
    params: Optional[dict[str, Any]] = None,
    timeout: float = 8.0,
    retries: int = 1,
    max_size: Optional[int] = None,
    cache_ttl: float = 0.0,
) -> Optional[httpx.Response]:
    """
    Execute an outbound OSINT HTTP request through SSRF-guarded `safe_request`,
    with optional in-memory TTL caching and retries. Honors injected mock `client` in tests.
    """
    cache_key = f"{method.upper()}:{url}:{json.dumps(params or {}, sort_keys=True)}"
    if cache_ttl > 0 and method.upper() == "GET" and client is None:
        cached = _OSINT_RESPONSE_CACHE.get(cache_key)
        if cached and (time.time() - cached[0]) < cache_ttl:
            return cached[1]

    req_headers = {"User-Agent": SAFE_USER_AGENT}
    if headers:
        req_headers.update(headers)

    for attempt in range(max(1, retries + 1)):
        try:
            if client is not None and type(client) is not httpx.AsyncClient:
                # Injected mock test client
                if method.upper() == "HEAD" and hasattr(client, "head"):
                    resp = await client.head(url, headers=req_headers, timeout=timeout)
                else:
                    try:
                        resp = await client.get(url, headers=req_headers, params=params, timeout=timeout)
                    except TypeError:
                        resp = await client.get(url, headers=req_headers, timeout=timeout)
            else:
                resp = await safe_request(
                    method,
                    url,
                    headers=req_headers,
                    params=params,
                    timeout=timeout,
                    max_size=max_size or getattr(settings, "MAX_RESPONSE_SIZE_BYTES", 10_485_760),
                    follow_redirects=True,
                )
            if cache_ttl > 0 and method.upper() == "GET" and client is None and getattr(resp, "status_code", 0) == 200:
                _OSINT_RESPONSE_CACHE[cache_key] = (time.time(), resp)
            return resp
        except Exception as exc:
            if attempt >= retries:
                logger.debug("safe_osint_request failed (%s %s): %s", method, url, exc)
                return None
            await asyncio.sleep(0.25)
    return None


class RobotsTxtGuard:
    """Checks and caches robots.txt rules per crawled host via safe_osint_request."""

    @classmethod
    async def is_allowed(cls, host_base_url: str, path: str, client: Optional[Any] = None) -> bool:
        clean_base = host_base_url.rstrip("/")
        cached = _ROBOTS_CACHE.get(clean_base)
        now = time.time()
        parser: Optional[urllib.robotparser.RobotFileParser] = None
        if cached and (now - cached[0]) < 1800.0:
            parser = cached[1]
        else:
            robots_url = f"{clean_base}/robots.txt"
            resp = await safe_osint_request("GET", robots_url, client=client, timeout=3.5, retries=0, max_size=512_000)
            if resp is not None and getattr(resp, "status_code", 0) == 200 and getattr(resp, "text", ""):
                rp = urllib.robotparser.RobotFileParser()
                rp.parse(resp.text.splitlines())
                parser = rp
            _ROBOTS_CACHE[clean_base] = (now, parser)

        if parser is None:
            return True
        try:
            target_path = path if path.startswith("/") else f"/{path}"
            return parser.can_fetch(SAFE_USER_AGENT, target_path) and parser.can_fetch("*", target_path)
        except Exception:
            return True

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
            # Try as organization first via safe_osint_request
            resp = await safe_osint_request(
                "GET",
                f"https://api.github.com/orgs/{github_handle}",
                client=client,
                headers=headers,
                timeout=8.0,
                cache_ttl=900.0,
            )
            if resp is not None and resp.status_code == 200:
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
                members_resp = await safe_osint_request(
                    "GET",
                    f"https://api.github.com/orgs/{github_handle}/public_members?per_page=15",
                    client=client,
                    headers=headers,
                    timeout=8.0,
                    cache_ttl=900.0,
                )
                if members_resp is not None and members_resp.status_code == 200:
                    member_logins = members_resp.json()[:8]
                    member_tasks = [
                        safe_osint_request(
                            "GET",
                            f"https://api.github.com/users/{m['login']}",
                            client=client,
                            headers=headers,
                            timeout=5.0,
                            cache_ttl=900.0,
                        )
                        for m in member_logins
                    ]
                    member_results = await asyncio.gather(*member_tasks, return_exceptions=True)
                    for mr in member_results:
                        if mr is not None and not isinstance(mr, Exception) and getattr(mr, "status_code", 0) == 200:
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

                # Get top repositories
                repos_resp = await safe_osint_request(
                    "GET",
                    f"https://api.github.com/orgs/{github_handle}/repos?sort=stars&direction=desc&per_page=10",
                    client=client,
                    headers=headers,
                    timeout=8.0,
                    cache_ttl=900.0,
                )
                if repos_resp is not None and repos_resp.status_code == 200:
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

            else:
                # Try as individual user
                resp = await safe_osint_request(
                    "GET",
                    f"https://api.github.com/users/{github_handle}",
                    client=client,
                    headers=headers,
                    timeout=8.0,
                    cache_ttl=900.0,
                )
                if resp is not None and resp.status_code == 200:
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
        try:
            resp = await safe_osint_request("GET", url, client=client, headers={"Accept": "application/rdap+json, application/json"}, timeout=8.0, cache_ttl=1800.0)
            if resp is not None and resp.status_code == 200:
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
            "logo": None,
            "same_as_links": [],
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

        # 1. OpenGraph, Logo & Meta description
        og_site = soup.find("meta", property="og:site_name")
        if og_site and og_site.get("content"):
            meta["name"] = og_site["content"].strip()

        og_img = soup.find("meta", property="og:image") or soup.find("meta", attrs={"name": "twitter:image"})
        if og_img and og_img.get("content"):
            meta["logo"] = validate_image_url(og_img["content"], domain)
        if not meta["logo"]:
            icon_link = soup.find("link", rel=lambda r: r and "icon" in " ".join(r).lower() if isinstance(r, list) else (r and "icon" in r.lower()))
            if icon_link and icon_link.get("href"):
                meta["logo"] = validate_image_url(icon_link["href"], domain)

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

                        if item.get("logo"):
                            raw_logo = item["logo"].get("url") if isinstance(item["logo"], dict) else str(item["logo"])
                            val_logo = validate_image_url(raw_logo, domain)
                            if val_logo:
                                meta["logo"] = val_logo
                        if item.get("sameAs"):
                            sa_list = item["sameAs"] if isinstance(item["sameAs"], list) else [item["sameAs"]]
                            for sa_u in sa_list:
                                if isinstance(sa_u, str) and sa_u.startswith(("http://", "https://")) and sa_u not in meta["same_as_links"]:
                                    meta["same_as_links"].append(sa_u)

                        # Founders from Organization
                        f_raw = item.get("founder") or item.get("founders")
                        if f_raw:
                            f_list = f_raw if isinstance(f_raw, list) else [f_raw]
                            for f in f_list:
                                if isinstance(f, dict) and f.get("name"):
                                    f_name = str(f.get("name")).strip()
                                    raw_urls = []
                                    for field_k in ("url", "sameAs"):
                                        fv = f.get(field_k)
                                        if isinstance(fv, list):
                                            raw_urls.extend([str(u) for u in fv if u])
                                        elif fv:
                                            raw_urls.append(str(fv))
                                    f_url = next((u for u in raw_urls if "linkedin.com/in" in u.lower()), "")
                                    f_wiki = next((u for u in raw_urls if "wikipedia.org/wiki/" in u.lower()), "")
                                    f_tw = next((u for u in raw_urls if "twitter.com/" in u.lower() or "x.com/" in u.lower()), "")
                                    f_gh = next((u for u in raw_urls if "github.com/" in u.lower()), "")
                                    f_img = f.get("image")
                                    if isinstance(f_img, dict):
                                        f_img = f_img.get("url")
                                    meta["founders"].append(
                                        {
                                            "name": f_name,
                                            "title": f.get("jobTitle") or "Founder",
                                            "linkedin_url": str(f_url),
                                            "wikipedia_url": str(f_wiki),
                                            "twitter_url": f_tw,
                                            "github_url": f_gh,
                                            "photo_url": validate_image_url(str(f_img), domain) if f_img else None,
                                            "avatar_url": validate_image_url(str(f_img), domain) if f_img else None,
                                            "bio": f.get("description") or f"Company Founder of {company_name}",
                                            "source": "Schema.org Organization (JSON-LD)",
                                            "sources": ["Schema.org Organization (JSON-LD)"],
                                            "confidence": "HIGH",
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
                                            "sources": ["Schema.org Organization (JSON-LD)"],
                                            "confidence": "HIGH",
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
            twitter_url: str = "",
            github_url: str = "",
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
                "product", "architect", "architecture", "chief", "officer", "director", "manager",
                "engineer", "senior", "lead", "head", "operations", "sales", "marketing", "co",
            }
            if any(p.lower().rstrip("'s’") in stop for p in parts):
                return
            norm_name = " ".join([p.capitalize() if p.islower() else p for p in parts])
            key = _norm_key(norm_name)
            clean_title = re.sub(r"\b(Ceo|Cto|Coo|Cfo|Ciso|Vp|Hr)\b", lambda m: m.group(1).upper(), (title or "Founder").strip())
            valid_photo = validate_image_url(photo, domain)
            clean_bio = re.sub(r"\s+", " ", bio).strip() if bio else ""

            if li_url:
                s_li = _slug_from_li(li_url)
                if s_li:
                    seen_linkedin_slugs.add(s_li)

            if key in seen_founder_keys:
                for f in meta["founders"]:
                    if _norm_key(f.get("name", "")) == key:
                        if valid_photo and not f.get("photo_url"):
                            f["photo_url"] = valid_photo
                            f["avatar_url"] = valid_photo
                        if clean_bio and (not f.get("bio") or len(f.get("bio", "")) < len(clean_bio)):
                            f["bio"] = clean_bio
                            f["bio_summary"] = clean_bio
                        if clean_bio and not f.get("source_sentence"):
                            f["source_sentence"] = clean_bio
                        if li_url and not f.get("linkedin_url"):
                            f["linkedin_url"] = li_url
                        if twitter_url and not f.get("twitter_url"):
                            f["twitter_url"] = twitter_url
                        if github_url and not f.get("github_url"):
                            f["github_url"] = github_url
                        if source and source not in f.get("sources", []):
                            f.setdefault("sources", [f.get("source")] if f.get("source") else []).append(source)
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
            if twitter_url:
                source_refs.append({
                    "name": "Twitter / X Profile",
                    "url": twitter_url,
                    "icon": "𝕏",
                })
            if github_url:
                source_refs.append({
                    "name": "GitHub Profile",
                    "url": github_url,
                    "icon": "🐙",
                })

            confidence = "HIGH" if ("JSON-LD" in source or "Team" in source or "LinkedIn" in source) else "MEDIUM"
            entry = {
                "name": norm_name,
                "title": clean_title,
                "department": "Executive Leadership",
                "linkedin_url": li_url,
                "twitter_url": twitter_url,
                "github_url": github_url,
                "linkedin_search_url": li_url or f"https://www.linkedin.com/search/results/people/?keywords={urllib.parse.quote(norm_name + ' ' + company_name)}",
                "avatar_url": valid_photo,
                "photo_url": valid_photo,
                "bio_summary": clean_bio,
                "bio": clean_bio or f"Identified as {clean_title} of {company_name}",
                "source_sentence": clean_bio,
                "biography": biography,
                "source_references": source_refs,
                "source": source,
                "sources": [source],
                "confidence": confidence,
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
            "revenue": "",
            "products": "",
            "logo": None,
            "source_article": "",
            "source_url": "",
            "wikidata_id": "",
            "wikidata_url": "",
            "linkedin_id": "",
            "wikipedia_status": "not_listed",
            "searched_queries": queries[:6],
            "candidate_slugs": [],
        }

        try:
            candidate_titles: list[str] = []
            non_org_wd_words = ("film", "movie", "novel", "book", "song", "album", "band", "television", "episode", "village", "river", "municipality", "comic")

            # 1 & 2. Run Wikidata entity search and Wikipedia article search concurrently
            wd_queries = [q for q in [legal_name, company_name, domain_root] if q and len(q) >= 3][:2]

            async def _wd_search(wq: str) -> list[str]:
                matched_ids: list[str] = []
                wd_url = f"https://www.wikidata.org/w/api.php?action=wbsearchentities&search={urllib.parse.quote(wq)}&language=en&limit=5&format=json"
                wd_r = await safe_osint_request("GET", wd_url, client=client, headers=headers, timeout=3.5, cache_ttl=1800.0)
                if wd_r is not None and wd_r.status_code == 200:
                    for wd_item in wd_r.json().get("search", []):
                        wd_desc = (wd_item.get("description") or "").lower()
                        wd_id = wd_item.get("id", "")
                        if any(bad in wd_desc for bad in non_org_wd_words):
                            continue
                        if any(k in wd_desc for k in ["company", "corporation", "enterprise", "software", "platform", "organization", "firm", "cybersecurity", "financial", "provider", "business", "startup", "founded", "fintech", "technology"]):
                            if wd_id:
                                matched_ids.append(wd_id)
                return matched_ids

            async def _wp_search(q_str: str) -> list[str]:
                search_url = f"https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch={urllib.parse.quote(q_str)}&utf8=&format=json"
                r = await safe_osint_request("GET", search_url, client=client, headers=headers, timeout=3.8, cache_ttl=1800.0)
                if r is not None and r.status_code == 200:
                    return [res.get("title") for res in r.json().get("query", {}).get("search", [])[:4] if res.get("title")]
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
                intel["wikidata_url"] = f"https://www.wikidata.org/wiki/{wd_ids[0]}"
                ent_r = await safe_osint_request(
                    "GET",
                    f"https://www.wikidata.org/w/api.php?action=wbgetentities&ids={'|'.join(wd_ids[:3])}&props=sitelinks&sitefilter=enwiki&format=json",
                    client=client,
                    headers=headers,
                    timeout=3.0,
                    cache_ttl=1800.0,
                )
                if ent_r is not None and ent_r.status_code == 200:
                    entities_map = ent_r.json().get("entities", {})
                    for wid in wd_ids[:3]:
                        en_title = entities_map.get(wid, {}).get("sitelinks", {}).get("enwiki", {}).get("title")
                        if en_title and en_title not in candidate_titles:
                            candidate_titles.append(en_title)

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
            # 4. Structured Wikidata fallback (P112 founder, P169 CEO, P127 owned by, P856 website, P571 inception, P159 HQ, P1128 employees, P18 image, P6634 LinkedIn ID)
            if wd_ids and (
                matched_intel.get("wikipedia_status") != "found"
                or not matched_intel.get("founders")
                or not matched_intel.get("headquarters")
                or not matched_intel.get("founded_year")
                or not matched_intel.get("estimated_employees")
                or not matched_intel.get("linkedin_id")
            ):
                wd_data = await cls.query_wikidata_fallback(
                    company_name=company_name,
                    domain=clean_domain,
                    wikidata_id=wd_ids[0],
                    client=client,
                )
                if wd_data:
                    for fk in ("headquarters", "founded_year", "estimated_employees", "parent_organization", "logo", "linkedin_id", "wikidata_id", "wikidata_url"):
                        if wd_data.get(fk) and not matched_intel.get(fk):
                            matched_intel[fk] = wd_data[fk]
                    if wd_data.get("linkedin_id") and wd_data["linkedin_id"] not in matched_intel.get("candidate_slugs", []):
                        matched_intel.setdefault("candidate_slugs", []).append(wd_data["linkedin_id"])
                    existing_f = {f.get("name", "").lower() for f in matched_intel.get("founders", [])}
                    for wf in wd_data.get("founders", []):
                        if wf.get("name", "").lower() not in existing_f:
                            existing_f.add(wf["name"].lower())
                            matched_intel.setdefault("founders", []).append(wf)
            return matched_intel
        finally:
            pass

    @classmethod
    async def query_wikidata_fallback(
        cls,
        company_name: str,
        domain: str,
        wikidata_id: str = "",
        client: Optional[Any] = None,
    ) -> dict[str, Any]:
        """Structured Wikidata fallback extracting P112, P169, P127, P856, P571, P159, P1128, P18, P6634."""
        clean_domain = domain.lower().replace("www.", "").strip()
        domain_root = clean_domain.split(".")[0]
        headers = {
            "User-Agent": SAFE_USER_AGENT
        }
        out: dict[str, Any] = {
            "wikidata_id": wikidata_id,
            "wikidata_url": f"https://www.wikidata.org/wiki/{wikidata_id}" if wikidata_id else "",
            "founders": [],
            "parent_organization": "",
            "founded_year": "",
            "headquarters": "",
            "estimated_employees": "",
            "logo": None,
            "linkedin_id": "",
            "official_website": "",
        }
        if not wikidata_id:
            wd_url = f"https://www.wikidata.org/w/api.php?action=wbsearchentities&search={urllib.parse.quote(company_name or domain_root)}&language=en&limit=3&format=json"
            sr = await safe_osint_request("GET", wd_url, client=client, headers=headers, timeout=3.5, cache_ttl=1800.0)
            if sr is not None and sr.status_code == 200:
                for it in sr.json().get("search", []):
                    desc = (it.get("description") or "").lower()
                    if any(k in desc for k in ("company", "corporation", "software", "organization", "enterprise", "platform", "business")):
                        wikidata_id = it.get("id", "")
                        break
        if not wikidata_id:
            return {}
        out["wikidata_id"] = wikidata_id
        out["wikidata_url"] = f"https://www.wikidata.org/wiki/{wikidata_id}"

        ent_url = f"https://www.wikidata.org/w/api.php?action=wbgetentities&ids={wikidata_id}&props=labels|claims|sitelinks&languages=en&format=json"
        er = await safe_osint_request("GET", ent_url, client=client, headers=headers, timeout=4.0, cache_ttl=1800.0)
        if er is None or er.status_code != 200:
            return {}
        entity = er.json().get("entities", {}).get(wikidata_id, {})
        claims = entity.get("claims", {})
        if not claims:
            return {}

        def _claim_vals(prop: str) -> list[Any]:
            vals: list[Any] = []
            for st in claims.get(prop, []):
                dv = st.get("mainsnak", {}).get("datavalue", {})
                if "value" in dv:
                    vals.append(dv["value"])
            return vals

        # P856 official website verification
        websites = [str(v).lower() for v in _claim_vals("P856") if isinstance(v, str)]
        if websites:
            out["official_website"] = websites[0]
            if not any(clean_domain in w or (len(domain_root) >= 3 and domain_root in w) for w in websites):
                lbl_en = (entity.get("labels", {}).get("en", {}).get("value") or "").lower()
                if company_name.lower() not in lbl_en and domain_root not in lbl_en:
                    return {}

        # P571 inception
        for tv in _claim_vals("P571"):
            if isinstance(tv, dict) and tv.get("time"):
                ym = re.search(r"(\d{4})", tv["time"])
                if ym:
                    out["founded_year"] = ym.group(1)
                    break

        # P1128 employees
        for ev in _claim_vals("P1128"):
            if isinstance(ev, dict) and ev.get("amount"):
                num_str = str(ev["amount"]).lstrip("+")
                out["estimated_employees"] = f"{num_str} employees"
                break

        # P6634 LinkedIn ID
        for li in _claim_vals("P6634"):
            if isinstance(li, str) and li.strip():
                out["linkedin_id"] = li.strip().rstrip("/").split("/")[-1]
                break

        # P18 image
        for img_name in _claim_vals("P18"):
            if isinstance(img_name, str) and img_name.strip():
                fn = urllib.parse.quote(img_name.strip().replace(" ", "_"))
                out["logo"] = f"https://commons.wikimedia.org/wiki/Special:FilePath/{fn}?width=300"
                break

        # Collect Q-IDs for P112 (founder), P169 (CEO), P127 (owned by), P159 (HQ)
        qids: list[str] = []
        prop_qids: dict[str, list[str]] = {}
        for p_code in ("P112", "P169", "P127", "P159"):
            prop_qids[p_code] = []
            for v in _claim_vals(p_code):
                if isinstance(v, dict) and v.get("id"):
                    qid = v["id"]
                    prop_qids[p_code].append(qid)
                    if qid not in qids:
                        qids.append(qid)

        label_map: dict[str, str] = {}
        if qids:
            lr = await safe_osint_request(
                "GET",
                f"https://www.wikidata.org/w/api.php?action=wbgetentities&ids={'|'.join(qids[:15])}&props=labels&languages=en&format=json",
                client=client,
                headers=headers,
                timeout=3.5,
                cache_ttl=1800.0,
            )
            if lr is not None and lr.status_code == 200:
                for qid, qent in lr.json().get("entities", {}).items():
                    lbl = qent.get("labels", {}).get("en", {}).get("value")
                    if lbl:
                        label_map[qid] = lbl

        if prop_qids["P159"]:
            out["headquarters"] = ", ".join(label_map[q] for q in prop_qids["P159"] if q in label_map)
        if prop_qids["P127"]:
            out["parent_organization"] = ", ".join(label_map[q] for q in prop_qids["P127"] if q in label_map)

        seen_names: set[str] = set()
        for qid in prop_qids["P112"]:
            p_name = label_map.get(qid)
            if p_name and p_name.lower() not in seen_names:
                seen_names.add(p_name.lower())
                out["founders"].append({
                    "name": p_name,
                    "title": "Founder",
                    "department": "Executive Leadership",
                    "linkedin_url": "",
                    "source": f"Wikidata ({wikidata_id})",
                    "sources": [f"Wikidata ({wikidata_id})"],
                    "confidence": "HIGH",
                    "is_founder": True,
                    "is_verified": True,
                })
        for qid in prop_qids["P169"]:
            p_name = label_map.get(qid)
            if p_name and p_name.lower() not in seen_names:
                seen_names.add(p_name.lower())
                out["founders"].append({
                    "name": p_name,
                    "title": "CEO",
                    "department": "Executive Leadership",
                    "linkedin_url": "",
                    "source": f"Wikidata ({wikidata_id})",
                    "sources": [f"Wikidata ({wikidata_id})"],
                    "confidence": "HIGH",
                    "is_founder": True,
                    "is_verified": True,
                })

        return out

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
            "User-Agent": SAFE_USER_AGENT
        }
        base_intel: dict[str, Any] = {
            "founders": [],
            "description": "",
            "industry": "",
            "headquarters": "",
            "founded_year": "",
            "estimated_employees": "",
            "parent_organization": "",
            "revenue": "",
            "products": "",
            "logo": None,
            "source_article": "",
            "source_url": "",
            "wikidata_id": "",
            "wikidata_url": "",
            "linkedin_id": "",
            "wikipedia_status": "not_listed",
            "searched_queries": [],
            "candidate_slugs": [],
        }
        if not candidate_titles:
            return base_intel
        return await cls._inspect_wikipedia_candidates(
            candidate_titles=candidate_titles,
            company_name=company_name,
            clean_domain=clean_domain,
            domain_root=domain_root,
            client=client,
            headers=headers,
            base_intel=base_intel,
        )

    @classmethod
    async def _fetch_commons_attribution(
        cls, image_url: str, client: Optional[Any] = None
    ) -> dict[str, str]:
        """Fetch Wikimedia Commons license & author attribution via imageinfo API when applicable."""
        if not image_url or "wikimedia.org" not in image_url.lower():
            return {}
        try:
            fname = urllib.parse.unquote(image_url.split("/")[-1].split("?")[0])
            # Thumbnail URLs often prefix e.g. 220px-Filename.jpg
            fname = re.sub(r"^\d+px-", "", fname)
            api_url = (
                "https://commons.wikimedia.org/w/api.php?action=query"
                f"&titles=File:{urllib.parse.quote(fname)}&prop=imageinfo&iiprop=extmetadata&format=json"
            )
            r = await safe_osint_request("GET", api_url, client=client, timeout=3.0, cache_ttl=3600.0)
            if r is not None and r.status_code == 200:
                pages = r.json().get("query", {}).get("pages", {})
                for p in pages.values():
                    meta = (p.get("imageinfo") or [{}])[0].get("extmetadata", {})
                    lic = meta.get("LicenseShortName", {}).get("value", "")
                    artist = re.sub(r"<[^>]+>", "", meta.get("Artist", {}).get("value", "")).strip()
                    if lic or artist:
                        return {"license": lic, "attribution": artist[:120]}
        except Exception:
            pass
        return {}

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
            parse_url = f"https://en.wikipedia.org/w/api.php?action=parse&page={urllib.parse.quote(t)}&prop=text&section=0&format=json"
            p_resp = await safe_osint_request("GET", parse_url, client=client, headers=headers, timeout=3.5, cache_ttl=1800.0)
            if p_resp is not None and p_resp.status_code == 200:
                return (t, p_resp.json().get("parse", {}).get("text", {}).get("*", "") or "")
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
                parsed_revenue = ""
                parsed_products = ""
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
                    elif "revenue" in lbl and not parsed_revenue:
                        parsed_revenue = val
                    elif ("product" in lbl or "services" in lbl) and not parsed_products:
                        parsed_products = val
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
                                        "title": "CEO" if ("ceo" in lbl and "founder" not in lbl) else "Founder / Key Executive",
                                        "department": "Executive Leadership",
                                        "linkedin_url": "",
                                        "source": f"Wikipedia / Open Knowledge ({title})",
                                        "sources": [f"Wikipedia ({title})"],
                                        "confidence": "HIGH",
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
                    intel["revenue"] = parsed_revenue
                    intel["products"] = parsed_products
                    intel["founders"] = parsed_founders
                    intel["candidate_slugs"] = parsed_slugs
                    intel["source_article"] = title
                    intel["source_url"] = f"https://en.wikipedia.org/wiki/{urllib.parse.quote(title.replace(' ', '_'))}"
                    intel["wikipedia_status"] = "found"
                    slug_from_title = re.sub(r"[^a-zA-Z0-9_-]", "-", title.lower().strip()).strip("-")
                    if slug_from_title and slug_from_title not in intel["candidate_slugs"]:
                        intel["candidate_slugs"].append(slug_from_title)

                    s_resp = await safe_osint_request(
                        "GET",
                        f"https://en.wikipedia.org/api/rest_v1/page/summary/{urllib.parse.quote(title)}",
                        client=client,
                        headers=headers,
                        timeout=3.0,
                        cache_ttl=1800.0,
                    )
                    if s_resp is not None and s_resp.status_code == 200:
                        s_json = s_resp.json()
                        intel["description"] = s_json.get("extract", "")
                        w_logo = s_json.get("thumbnail", {}).get("source") or s_json.get("originalimage", {}).get("source")
                        if w_logo and not intel.get("logo"):
                            intel["logo"] = w_logo
                        if s_json.get("wikibase_item"):
                            intel["wikidata_id"] = s_json["wikibase_item"]
                            intel["wikidata_url"] = f"https://www.wikidata.org/wiki/{s_json['wikibase_item']}"

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

        active_provider = SearchProvider.get_provider()
        out: dict[str, Any] = {
            "founders": [],
            "employees": [],
            "social_profiles": [],
            "wikipedia_titles": [],
            "linkedin_company_url": "",
            "search_snippets": [],
            "search_provider": active_provider.name,
            "provider_configured": active_provider.is_configured,
        }

        queries = [
            f"{company_name} founder CEO",
            f'site:linkedin.com/in "{company_name}" "Founder OR CEO OR Engineer"',
            f'site:linkedin.com/company "{company_name}"',
            f'"{clean_domain}" OR "{company_name}" site:en.wikipedia.org',
        ]
        headers = {
            "User-Agent": SAFE_USER_AGENT,
            "Accept-Language": "en-US,en;q=0.9",
        }

        def _norm_role(raw_r: str) -> str:
            cleaned = re.sub(r"\bco-\s+", "Co-", raw_r, flags=re.I)
            cleaned = re.sub(r"\s+", " ", cleaned).strip(" ,.-|")
            return re.sub(r"\b(Ceo|Cto|Coo|Cfo|Ciso|Vp)\b", lambda m: m.group(1).upper(), cleaned.title())

        def _strip_title_prefix(raw_t: str) -> str:
            cleaned = re.sub(r"^(?:[A-Za-z0-9._-]+\s+)?https?://[^\s]+(?:\s+›\s+[^\s]+)*\s+", "", raw_t or "").strip()
            cleaned = re.sub(r"\s*[|•]\s*(?:LinkedIn|Crunchbase|Forbes.*|RocketReach).*$", "", cleaned, flags=re.I)
            cleaned = re.sub(r"\([^)]*\)", "", cleaned).strip()
            return cleaned

        seen_founder_names: set[str] = set()
        seen_emp_names: set[str] = set()
        seen_soc_keys: set[str] = set()

        try:
            search_hits, gnews_resp = await asyncio.gather(
                active_provider.search_many(queries[:3] if active_provider.is_configured else queries[:2], client=client),
                safe_osint_request(
                    "GET",
                    f"https://news.google.com/rss/search?q={urllib.parse.quote(f'\"{company_name}\" founder OR CEO')}&hl=en-US&gl=US&ceid=US:en",
                    client=client,
                    headers=headers,
                    timeout=5.5,
                    cache_ttl=900.0,
                ),
            )
            gnews_xml = gnews_resp.text if gnews_resp is not None and getattr(gnews_resp, "status_code", 0) == 200 else ""
            logger.info("SearchProvider(%s) returned %d hits for %s", active_provider.name, len(search_hits), clean_domain)

            for hit in search_hits:
                dest_url = hit.get("url", "")
                raw_title = hit.get("title", "")
                snippet = hit.get("snippet", "")
                combined_low = f"{raw_title} {snippet} {dest_url}".lower()

                is_relevant = (
                    clean_domain in combined_low
                    or (len(comp_low) >= 4 and comp_low in combined_low)
                    or (len(domain_root) >= 4 and domain_root in combined_low)
                )
                if not is_relevant:
                    logger.debug("Rejected search hit (no company/domain affiliation): %s", dest_url)
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
                            soc["source"] = f"Online OSINT Search ({active_provider.name})"
                            out["social_profiles"].append(soc)
                            if soc["platform"] == "LinkedIn" and soc.get("type") == "company" and not out["linkedin_company_url"]:
                                out["linkedin_company_url"] = soc["url"]

                # 2. Discover Wikipedia pages for company or founder
                if "en.wikipedia.org/wiki/" in dest_url.lower():
                    wiki_t = urllib.parse.unquote(dest_url.split("/wiki/")[-1].split("#")[0].split("?")[0]).replace("_", " ")
                    if wiki_t and wiki_t not in out["wikipedia_titles"]:
                        out["wikipedia_titles"].append(wiki_t)

                # 3. Extract founder/CEO or employee from LinkedIn /in/ & verified profile results
                is_exec_profile_site = any(
                    host_tok in dest_url.lower()
                    for host_tok in ("linkedin.com/in/", "crunchbase.com/person/", "forbes.com/", "rocketreach.co/", "tracxn.com/")
                )
                if is_exec_profile_site:
                    clean_t = _strip_title_prefix(raw_title)
                    parts = [p.strip() for p in re.split(r"\s+(?:[-–—|]|,)\s+", clean_t) if p.strip()]
                    cand_name = parts[0] if parts else ""
                    cand_role_text = " ".join(parts[1:]) if len(parts) > 1 else ""

                    n_words = cand_name.split()
                    if 2 <= len(n_words) <= 4 and all(re.match(r"^[A-Z][a-zA-Z.'-]*$", w) for w in n_words):
                        tied_to_target = (
                            comp_low in f"{raw_title} {snippet}".lower()
                            or domain_root in f"{raw_title} {snippet}".lower()
                        )
                        text_after_role = f"{cand_role_text}".lower()
                        affiliation_ok = tied_to_target and (
                            not text_after_role or comp_low in text_after_role or domain_root in text_after_role or "at " not in text_after_role
                        )
                        if not affiliation_ok:
                            logger.debug("Rejected LinkedIn/profile candidate %s (missing affiliation)", cand_name)
                            continue

                        role_m = re.search(
                            r"\b((?:Co-?\s*)?Founder(?:\s*(?:&|and|,)\s*(?:CEO|CTO|COO|President|Managing Director))?|Chief Executive Officer|CEO(?:\s*(?:&|and|,)\s*(?:Co-?\s*)?Founder)?|CTO|COO|CFO|CISO|Managing Director|President|VP\s+[A-Za-z &]{2,25}|(?:Senior\s+|Lead\s+|Principal\s+)?(?:Software|Security|DevOps|Cloud|Product)?\s*(?:Engineer|Developer|Architect|Manager|Director|Analyst))\b",
                            f"{cand_role_text} {snippet}",
                            re.I,
                        )
                        li_profile_url = dest_url if "linkedin.com/in/" in dest_url.lower() else ""
                        is_leader_role = bool(
                            role_m and re.search(r"(founder|ceo|chief executive|cto|coo|cfo|managing director|president)", role_m.group(0), re.I)
                        )
                        role_clean = _norm_role(role_m.group(0)) if role_m else (_norm_role(cand_role_text) if cand_role_text and len(cand_role_text) <= 45 else "Staff / Professional")
                        conf = "HIGH" if (li_profile_url and (comp_low in text_after_role or domain_root in text_after_role)) else "MEDIUM"
                        src_label = f"Online Search ({active_provider.name})"
                        person_obj = {
                            "name": cand_name,
                            "title": role_clean,
                            "department": "Executive Leadership" if is_leader_role else (
                                "Cybersecurity & IT" if any(w in role_clean.lower() for w in ("security", "ciso", "soc", "analyst")) else (
                                    "Engineering & Tech" if any(w in role_clean.lower() for w in ("engineer", "developer", "architect", "devops", "cto", "tech")) else "Operations & Business"
                                )
                            ),
                            "linkedin_url": li_profile_url,
                            "linkedin_search_url": li_profile_url or f"https://www.linkedin.com/search/results/people/?keywords={urllib.parse.quote(cand_name + ' ' + company_name)}",
                            "bio": snippet or f"{role_clean} at {company_name}",
                            "source_sentence": snippet or raw_title,
                            "source": src_label,
                            "sources": [src_label],
                            "confidence": conf,
                            "source_references": [
                                {"name": f"{company_name} official website", "url": f"https://{clean_domain}", "icon": "🌐"},
                                {"name": "LinkedIn Profile" if li_profile_url else raw_title[:50], "url": dest_url, "icon": "💼" if li_profile_url else "🔍"},
                            ],
                            "is_verified": True,
                            "is_founder": is_leader_role,
                        }
                        nk = cand_name.lower()
                        if is_leader_role:
                            if nk not in seen_founder_names:
                                seen_founder_names.add(nk)
                                out["founders"].append(person_obj)
                        elif li_profile_url:
                            if nk not in seen_emp_names and nk not in seen_founder_names:
                                seen_emp_names.add(nk)
                                out["employees"].append(person_obj)

                # 4. Extract founder/CEO from snippet narrative
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
                                    "source_sentence": fm.group(0),
                                    "source": f"Online Search ({active_provider.name})",
                                    "sources": [f"Online Search ({active_provider.name})"],
                                    "confidence": "MEDIUM",
                                    "source_references": [
                                        {"name": raw_title[:60], "url": dest_url, "icon": "🌐"},
                                    ],
                                    "is_verified": True,
                                    "is_founder": True,
                                })

            # 5. Parse Google News RSS items for press/news founder mentions
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
                                "source_sentence": gm.group(0),
                                "source": "Google News RSS",
                                "sources": ["Google News RSS"],
                                "confidence": "MEDIUM",
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
                                    "source_sentence": gm2.group(0),
                                    "source": "Google News RSS",
                                    "sources": ["Google News RSS"],
                                    "confidence": "MEDIUM",
                                    "source_references": [{"name": item_title[:60], "url": item_url, "icon": "📰"}],
                                    "is_verified": True,
                                    "is_founder": True,
                                })
        except Exception as exc:
            logger.debug("dig_online_intelligence error for %s: %s", clean_domain, exc)

        return out

    @classmethod
    async def search_person_image(
        cls, name: str, company_name: str = "", client: Optional[httpx.AsyncClient] = None
    ) -> Optional[str]:
        """Search public image search indexes for person photo when not on Wikipedia."""
        q = f"{name} {company_name}".strip()
        url = f"https://www.bing.com/images/search?q={urllib.parse.quote(q)}&form=HDRSC2&first=1"
        b_headers = {
            "User-Agent": SAFE_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        try:
            resp = await safe_osint_request("GET", url, client=client, headers=b_headers, timeout=6.0, cache_ttl=1800.0)
            if resp is not None and resp.status_code == 200:
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
        authoritative person photo (with Wikimedia Commons attribution), career milestones, and references.
        Only attaches Wikipedia profiles that demonstrably match the person AND company context.
        """
        headers = {
            "User-Agent": SAFE_USER_AGENT
        }
        profile: dict[str, Any] = {
            "photo_url": None,
            "avatar_url": None,
            "photo_attribution": {},
            "bio_summary": "",
            "bio": "",
            "wikipedia_url": "",
            "biography": {},
            "source_references": [],
            "current_role": "",
        }

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
                r = await safe_osint_request("GET", search_url, client=client, headers=headers, timeout=6.0, cache_ttl=1800.0)
                if r is None or r.status_code != 200:
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
                s_resp = await safe_osint_request("GET", s_url, client=client, headers=headers, timeout=6.0, cache_ttl=1800.0)
                s_extract = ""
                if s_resp is not None and s_resp.status_code == 200:
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
                            attr = await cls._fetch_commons_attribution(thumb, client=client)
                            if attr:
                                profile["photo_attribution"] = attr
                    else:
                        matched_title = ""

            if matched_title:
                # 3. Parse infobox for biography table & institutional source references
                p_url = f"https://en.wikipedia.org/w/api.php?action=parse&page={urllib.parse.quote(matched_title)}&prop=text&section=0&format=json"
                p_resp = await safe_osint_request("GET", p_url, client=client, headers=headers, timeout=6.0, cache_ttl=1800.0)
                if p_resp is not None and p_resp.status_code == 200:
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

        return profile


class SearchProvider:
    """Pluggable SearchProvider interface for OSINT web & LinkedIn search discovery."""

    name: str = "base"
    is_configured: bool = False

    async def search(self, query: str, client: Optional[Any] = None) -> list[dict[str, str]]:
        return []

    async def search_many(self, queries: list[str], client: Optional[Any] = None) -> list[dict[str, str]]:
        batches = await asyncio.gather(*[self.search(q, client=client) for q in queries], return_exceptions=True)
        out: list[dict[str, str]] = []
        seen_urls: set[str] = set()
        for batch in batches:
            if isinstance(batch, list):
                for hit in batch:
                    u = (hit.get("url") or "").strip()
                    if u and u not in seen_urls:
                        seen_urls.add(u)
                        out.append(hit)
        return out

    @classmethod
    def get_provider(cls) -> "SearchProvider":
        pref = (getattr(settings, "SEARCH_PROVIDER", "auto") or "auto").strip().lower()
        brave_key = getattr(settings, "BRAVE_API_KEY", None)
        serp_key = getattr(settings, "SERPAPI_KEY", None)
        bing_key = getattr(settings, "BING_SEARCH_API_KEY", None)

        if pref == "brave" or (pref == "auto" and brave_key):
            if brave_key:
                return BraveSearchProvider(brave_key)
        if pref == "serpapi" or (pref == "auto" and serp_key):
            if serp_key:
                return SerpAPISearchProvider(serp_key)
        if pref == "bing" or (pref == "auto" and bing_key):
            if bing_key:
                return BingSearchProvider(bing_key)
        return PublicFallbackSearchProvider()


class BraveSearchProvider(SearchProvider):
    """Brave Web Search API provider."""

    name = "Brave Search API"
    is_configured = True

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    async def search(self, query: str, client: Optional[Any] = None) -> list[dict[str, str]]:
        resp = await safe_osint_request(
            "GET",
            "https://api.search.brave.com/res/v1/web/search",
            client=client,
            headers={"X-Subscription-Token": self.api_key, "Accept": "application/json"},
            params={"q": query, "count": 10},
            timeout=6.0,
            cache_ttl=900.0,
        )
        if resp is None or resp.status_code != 200:
            return []
        hits: list[dict[str, str]] = []
        for item in resp.json().get("web", {}).get("results", []):
            hits.append({
                "title": item.get("title", ""),
                "url": item.get("url", ""),
                "snippet": item.get("description", ""),
            })
        return hits


class SerpAPISearchProvider(SearchProvider):
    """SerpAPI Google organic search provider."""

    name = "SerpAPI"
    is_configured = True

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    async def search(self, query: str, client: Optional[Any] = None) -> list[dict[str, str]]:
        resp = await safe_osint_request(
            "GET",
            "https://serpapi.com/search.json",
            client=client,
            params={"q": query, "api_key": self.api_key, "num": 10},
            timeout=6.0,
            cache_ttl=900.0,
        )
        if resp is None or resp.status_code != 200:
            return []
        hits: list[dict[str, str]] = []
        for item in resp.json().get("organic_results", []):
            hits.append({
                "title": item.get("title", ""),
                "url": item.get("link", ""),
                "snippet": item.get("snippet", ""),
            })
        return hits


class BingSearchProvider(SearchProvider):
    """Microsoft Bing Web Search v7 API provider."""

    name = "Bing Search API"
    is_configured = True

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    async def search(self, query: str, client: Optional[Any] = None) -> list[dict[str, str]]:
        resp = await safe_osint_request(
            "GET",
            "https://api.bing.microsoft.com/v7.0/search",
            client=client,
            headers={"Ocp-Apim-Subscription-Key": self.api_key},
            params={"q": query, "count": 10},
            timeout=6.0,
            cache_ttl=900.0,
        )
        if resp is None or resp.status_code != 200:
            return []
        hits: list[dict[str, str]] = []
        for item in resp.json().get("webPages", {}).get("value", []):
            hits.append({
                "title": item.get("name", ""),
                "url": item.get("url", ""),
                "snippet": item.get("snippet", ""),
            })
        return hits


class PublicFallbackSearchProvider(SearchProvider):
    """Unauthenticated Yahoo public search fallback (Google News RSS runs alongside)."""

    name = "Public Web Fallback (Yahoo / News)"
    is_configured = False

    @staticmethod
    def _unwrap_yahoo_url(href: str) -> str:
        m_ru = re.search(r"/RU=([^/]+)/", href or "")
        if m_ru:
            try:
                return urllib.parse.unquote(m_ru.group(1))
            except Exception:
                pass
        return href or ""

    async def search(self, query: str, client: Optional[Any] = None) -> list[dict[str, str]]:
        resp = await safe_osint_request(
            "GET",
            f"https://search.yahoo.com/search?p={urllib.parse.quote(query)}",
            client=client,
            headers={"Accept-Language": "en-US,en;q=0.9"},
            timeout=5.5,
            cache_ttl=900.0,
        )
        if resp is None or getattr(resp, "status_code", 0) != 200 or not getattr(resp, "text", ""):
            return []
        soup = BeautifulSoup(resp.text, "html.parser")
        hits: list[dict[str, str]] = []
        for algo in soup.select("div.algo")[:8]:
            a_tag = algo.select_one("h3 a, a")
            if not a_tag:
                continue
            dest_url = self._unwrap_yahoo_url(a_tag.get("href", ""))
            raw_title = re.sub(r"\s+", " ", a_tag.get_text(" ", strip=True)).strip()
            snip_el = algo.select_one("div.compText, p")
            snippet = re.sub(r"\s+", " ", snip_el.get_text(" ", strip=True)).strip() if snip_el else ""
            if dest_url:
                hits.append({"title": raw_title, "url": dest_url, "snippet": snippet})
        return hits


class OptionalPeopleDataProvider:
    """Optional licensed people-data API hook (skipped silently unless PEOPLE_DATA_API_KEY + URL set)."""

    @classmethod
    async def lookup_company_people(
        cls,
        domain: str,
        company_name: str,
        client: Optional[Any] = None,
    ) -> list[dict[str, Any]]:
        api_key = getattr(settings, "PEOPLE_DATA_API_KEY", None)
        api_url = getattr(settings, "PEOPLE_DATA_API_URL", None)
        if not api_key or not api_url:
            return []
        resp = await safe_osint_request(
            "GET",
            api_url,
            client=client,
            headers={"X-Api-Key": api_key, "Accept": "application/json"},
            params={"domain": domain, "company": company_name, "limit": 20},
            timeout=6.0,
            cache_ttl=1800.0,
        )
        if resp is None or resp.status_code != 200:
            return []
        results: list[dict[str, Any]] = []
        try:
            payload = resp.json()
            raw_rows = payload.get("data") or payload.get("employees") or payload.get("results") or []
            for row in raw_rows:
                name = (row.get("full_name") or row.get("name") or "").strip()
                if not name or len(name.split()) < 2:
                    continue
                results.append({
                    "name": name,
                    "title": row.get("job_title") or row.get("title") or "Team Member",
                    "department": row.get("department") or "Operations & Business",
                    "linkedin_url": row.get("linkedin_url") or "",
                    "email": row.get("work_email") or row.get("email") or "",
                    "location": row.get("location") or "",
                    "avatar_url": validate_image_url(row.get("photo_url") or row.get("avatar_url"), domain),
                    "source": "Licensed People Data API",
                    "sources": ["Licensed People Data API"],
                    "confidence": "HIGH",
                    "is_verified": True,
                })
        except Exception:
            pass
        return results


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

        if not meta_info["estimated_employees"]:
            emp_m = re.search(
                r"(?:View all\s+)?([0-9,]+(?:\s*[-–]\s*[0-9,]+|\+)?)\s+employees\b",
                f"{meta_info.get('description', '')} {soup.get_text(' ', strip=True)[:8000]}",
                re.I,
            )
            if emp_m:
                meta_info["estimated_employees"] = f"{emp_m.group(1).strip()} employees"

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
    async def fetch_public_profile_og(
        cls,
        linkedin_url: str,
        company_name: str,
        domain: str,
        client: Optional[Any] = None,
    ) -> Optional[dict[str, Any]]:
        """
        Passively fetch public og:title / og:description / og:image from a LinkedIn /in/ URL
        only when served publicly without login/authwall. Never bypasses protections.
        """
        if not linkedin_url or "linkedin.com/in/" not in linkedin_url.lower():
            return None
        resp = await safe_osint_request(
            "GET",
            linkedin_url,
            client=client,
            headers={"Accept-Language": "en-US,en;q=0.9"},
            timeout=4.5,
            retries=0,
            cache_ttl=1800.0,
        )
        if resp is None or getattr(resp, "status_code", 0) != 200:
            return None
        body = getattr(resp, "text", "") or ""
        # Abort immediately if LinkedIn serves login/authwall page
        if not body or any(w in body.lower() for w in ("authwall", "session_key", "sign in to linkedin")):
            return None
        soup = BeautifulSoup(body, "html.parser")
        og_t = soup.find("meta", property="og:title")
        og_d = soup.find("meta", property="og:description") or soup.find("meta", attrs={"name": "description"})
        og_i = soup.find("meta", property="og:image")
        title_txt = (og_t.get("content") or "").strip() if og_t else ""
        desc_txt = (og_d.get("content") or "").strip() if og_d else ""
        img_url = validate_image_url((og_i.get("content") or "").strip() if og_i else None)
        if not title_txt:
            return None
        comp_low = (company_name or "").lower()
        dom_root = domain.lower().replace("www.", "").split(".")[0]
        combined_low = f"{title_txt} {desc_txt}".lower()
        if not ((len(comp_low) >= 3 and comp_low in combined_low) or (len(dom_root) >= 3 and dom_root in combined_low)):
            return None
        parts = [p.strip() for p in re.split(r"\s+[-–—|]\s+", re.sub(r"\s*\|\s*LinkedIn.*$", "", title_txt, flags=re.I)) if p.strip()]
        parsed_name = parts[0] if parts else ""
        headline = parts[1] if len(parts) > 1 else desc_txt[:120]
        loc_m = re.search(r"(?:Location|Based in|Greater\s+[A-Z][a-z]+|[A-Z][a-z]+,\s+[A-Z][a-zA-Z ]{2,20})", desc_txt)
        return {
            "name": parsed_name,
            "title": headline[:80] if headline else "",
            "bio": desc_txt[:260],
            "location": loc_m.group(0) if loc_m else "",
            "linkedin_og_image": img_url,
            "linkedin_url": linkedin_url,
        }

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
        online_employees: Optional[list[dict[str, Any]]] = None,
        wiki_intel: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        Asynchronously fetches and synthesizes complete LinkedIn company intelligence.
        Queries public LinkedIn pages, enriches public /in/ og:* meta (when served without login),
        calls optional people-data API (when key configured), and merges a deduplicated directory.
        """
        clean_domain = domain.lower().strip()
        slug_fallback = re.sub(r"[^a-zA-Z0-9_-]", "-", company_name.lower().strip())
        domain_slug = clean_domain.replace("www.", "").split(".")[0]

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

        for c_slug in company_meta.get("candidate_slugs", []):
            c_url = f"https://www.linkedin.com/company/{c_slug}"
            if c_url not in urls_to_try:
                urls_to_try.append(c_url)

        crawled_employees: list[dict[str, Any]] = []
        company_details: dict[str, Any] = {}

        # Query public LinkedIn company page via SSRF-safe request
        for target_url in urls_to_try[:3]:
            resp = await safe_osint_request("GET", target_url, client=client, timeout=6.0, retries=0, cache_ttl=1800.0)
            if resp is not None and getattr(resp, "status_code", 0) == 200 and getattr(resp, "text", "") and len(resp.text) > 2000:
                if "authwall" in resp.text.lower() or "session_key" in resp.text.lower():
                    continue
                company_url = str(getattr(resp, "url", target_url) or target_url).rstrip("/")
                company_slug = company_url.split("/")[-1].split("?")[0]
                c_meta, c_emps = cls.parse_linkedin_company_html(resp.text, clean_domain, company_name)
                company_details = c_meta
                crawled_employees.extend(c_emps)
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

        # Concurrently check optional people-data API & public /in/ og:* tags (up to 3 discovered profiles)
        people_api_emps: list[dict[str, Any]] = []
        personal_li_urls = []
        for src_p in list(company_meta.get("founders", [])) + list(company_meta.get("scraped_team", [])) + list(online_employees or []):
            lu = (src_p.get("linkedin_url") or "").strip()
            if "linkedin.com/in/" in lu.lower() and lu not in personal_li_urls:
                personal_li_urls.append(lu)

        og_results = await asyncio.gather(
            OptionalPeopleDataProvider.lookup_company_people(clean_domain, company_name, client=client),
            *[cls.fetch_public_profile_og(u, company_name, clean_domain, client=client) for u in personal_li_urls[:3]],
            return_exceptions=True,
        )
        if isinstance(og_results[0], list):
            people_api_emps = og_results[0]
        for og_item in og_results[1:]:
            if isinstance(og_item, dict) and og_item:
                crawled_employees.append({
                    "name": og_item["name"],
                    "title": og_item.get("title") or "Team Member",
                    "department": "Executive Leadership" if re.search(r"(founder|ceo|cto|coo|cfo|president|director)", og_item.get("title", ""), re.I) else "Operations & Business",
                    "linkedin_url": og_item["linkedin_url"],
                    "linkedin_og_image": og_item.get("linkedin_og_image"),
                    "location": og_item.get("location", ""),
                    "bio": og_item.get("bio", ""),
                    "source": "LinkedIn Public Profile (og:meta)",
                    "sources": ["LinkedIn Public Profile (og:meta)"],
                    "confidence": "HIGH",
                    "is_verified": True,
                })

        return cls.build_linkedin_intelligence(
            domain=domain,
            company_name=company_name,
            website_social_profiles=website_social_profiles,
            company_meta=company_meta,
            github_intel=github_intel,
            enriched_email_profiles=enriched_email_profiles,
            crawled_linkedin_employees=crawled_employees,
            company_details=company_details,
            online_employees=online_employees,
            people_api_employees=people_api_emps,
            wiki_intel=wiki_intel,
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
        online_employees: Optional[list[dict[str, Any]]] = None,
        people_api_employees: Optional[list[dict[str, Any]]] = None,
        wiki_intel: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        Synthesizes deduplicated founders & employee directory across all OSINT sources:
        merges fields by normalized name + LinkedIn slug + email, keeps sources[] list,
        picks highest-priority photo (Wikipedia > official site > LinkedIn og:image > Gravatar),
        and reports reported_employee_count separately from len(directory).
        """
        clean_domain = domain.lower().strip()
        slug_fallback = re.sub(r"[^a-zA-Z0-9_-]", "-", company_name.lower().strip())

        company_url = f"https://www.linkedin.com/company/{slug_fallback}"
        company_slug = slug_fallback
        linkedin_profiles = [p for p in website_social_profiles if p.get("platform") == "LinkedIn"]
        company_pages = [p for p in linkedin_profiles if p.get("type") == "company"]
        if company_pages:
            company_url = company_pages[0]["url"]
            company_slug = company_pages[0]["handle"]

        def _clean_email_part(part: str, fallback: str) -> str:
            cleaned = re.sub(r"[^a-z0-9]", "", part.lower())
            return cleaned or fallback

        def _norm_person_name(n: str) -> str:
            return re.sub(r"[^a-z0-9 ]", "", re.sub(r"\s+", " ", (n or "").lower())).strip()

        def _extract_li_slug(url: str) -> str:
            m_li = re.search(r"linkedin\.com/in/([a-zA-Z0-9_.-]+)", url or "", re.I)
            return m_li.group(1).rstrip("/").lower() if m_li else ""

        def _photo_rank(url: str, src_hint: str = "") -> int:
            u = (url or "").lower()
            s = (src_hint or "").lower()
            if not u:
                return 99
            if "wikimedia" in u or "wikipedia" in s:
                return 1
            if clean_domain.split(".")[0] in u or "website" in s or "json-ld" in s:
                return 2
            if "licdn" in u or "linkedin" in s or "og:image" in s:
                return 3
            if "gravatar" in u:
                return 4
            return 3

        def _merge_records(existing: dict[str, Any], incoming: dict[str, Any]) -> None:
            # Merge sources[]
            ex_sources = existing.setdefault("sources", [existing.get("source")] if existing.get("source") else [])
            for src_val in (incoming.get("sources") or ([incoming.get("source")] if incoming.get("source") else [])):
                if src_val and src_val not in ex_sources:
                    ex_sources.append(src_val)
            existing["source"] = ex_sources[0] if ex_sources else existing.get("source", "")

            # Merge source_references
            ex_refs = existing.setdefault("source_references", [])
            seen_ref_urls = {r.get("url") for r in ex_refs if isinstance(r, dict)}
            for ref in incoming.get("source_references") or []:
                if isinstance(ref, dict) and ref.get("url") not in seen_ref_urls:
                    seen_ref_urls.add(ref.get("url"))
                    ex_refs.append(ref)

            # Pick best photo: Wikipedia > official site > LinkedIn og:image > Gravatar
            inc_photo = incoming.get("photo_url") or incoming.get("avatar_url") or incoming.get("linkedin_og_image")
            ex_photo = existing.get("photo_url") or existing.get("avatar_url")
            inc_src_str = " ".join(incoming.get("sources") or [incoming.get("source") or ""])
            ex_src_str = " ".join(ex_sources)
            if inc_photo and (_photo_rank(inc_photo, inc_src_str) < _photo_rank(ex_photo or "", ex_src_str)):
                existing["photo_url"] = inc_photo
                existing["avatar_url"] = inc_photo

            # Merge URLs & metadata fields if empty or generic
            for k in ("linkedin_url", "wikipedia_url", "twitter_url", "github_url", "email", "location", "source_sentence"):
                if incoming.get(k) and not existing.get(k):
                    existing[k] = incoming[k]
            if incoming.get("bio") and len(str(incoming["bio"])) > len(str(existing.get("bio") or "")):
                existing["bio"] = incoming["bio"]
            if incoming.get("bio_summary") and len(str(incoming["bio_summary"])) > len(str(existing.get("bio_summary") or "")):
                existing["bio_summary"] = incoming["bio_summary"]
            if incoming.get("biography"):
                merged_b = dict(incoming["biography"])
                merged_b.update(existing.get("biography") or {})
                existing["biography"] = merged_b
            if incoming.get("title") and existing.get("title") in ("", "Founder", "Staff / Team Member", "Team Member", "Associated Professional / Follower"):
                if not any(w in incoming["title"].lower() for w in ("follower", "associated")):
                    existing["title"] = incoming["title"]
            # Confidence upgrade on multi-source corroboration
            conf_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
            cur_conf = existing.get("confidence") or "MEDIUM"
            inc_conf = incoming.get("confidence") or "MEDIUM"
            if len(ex_sources) >= 2:
                existing["confidence"] = "HIGH"
            elif conf_rank.get(inc_conf, 0) > conf_rank.get(cur_conf, 0):
                existing["confidence"] = inc_conf

        founders: list[dict[str, Any]] = []
        seen_founders: dict[str, dict[str, Any]] = {}

        for f in company_meta.get("founders", []):
            f_name = (f.get("name") or "").strip()
            if not f_name:
                continue
            nk = _norm_person_name(f_name)
            f_parts = f_name.split()
            first_name = _clean_email_part(f_parts[0], "user") if f_parts else "user"
            last_name = _clean_email_part(f_parts[-1], "name") if len(f_parts) > 1 else "name"
            inferred_email = f"{first_name}.{last_name}@{clean_domain}"
            rec = {
                "name": f_name,
                "title": f.get("title") or "Founder & Executive",
                "role": f.get("title") or "Founder & Executive",
                "department": "Executive Leadership",
                "linkedin_url": f.get("linkedin_url") or "",
                "twitter_url": f.get("twitter_url") or "",
                "github_url": f.get("github_url") or "",
                "linkedin_search_url": f.get("linkedin_url") or f"https://www.linkedin.com/search/results/people/?keywords={urllib.parse.quote(f_name + ' ' + company_name)}",
                "avatar_url": f.get("avatar_url") or f.get("photo_url"),
                "photo_url": f.get("photo_url") or f.get("avatar_url"),
                "bio": f.get("bio") or f.get("bio_summary") or f"Leadership at {company_name}",
                "bio_summary": f.get("bio_summary") or f.get("bio") or "",
                "source_sentence": f.get("source_sentence") or "",
                "biography": f.get("biography") or {},
                "source_references": list(f.get("source_references") or []),
                "wikipedia_url": f.get("wikipedia_url") or "",
                "location": f.get("location") or "",
                "email": f.get("email") or "",
                "source": f.get("source") or "Website Team Page",
                "sources": list(f.get("sources") or ([f.get("source")] if f.get("source") else ["Website Team Page"])),
                "confidence": f.get("confidence") or ("HIGH" if f.get("wikipedia_url") or f.get("linkedin_url") else "MEDIUM"),
                "is_verified": True,
                "inferred_email": inferred_email,
                "risk_level": "High Risk: Primary Target for Spear-Phishing & BEC Impersonation",
            }
            if nk in seen_founders:
                _merge_records(seen_founders[nk], rec)
            else:
                seen_founders[nk] = rec
                founders.append(rec)

        employee_directory: list[dict[str, Any]] = []
        by_name: dict[str, dict[str, Any]] = {}
        by_slug: dict[str, dict[str, Any]] = {}
        by_email: dict[str, dict[str, Any]] = {}

        def add_employee(emp: dict[str, Any]) -> None:
            name = (emp.get("name") or "").strip()
            li_url = (emp.get("linkedin_url") or "").strip()
            li_slug = _extract_li_slug(li_url)
            em = (emp.get("email") or "").strip().lower()
            nk = _norm_person_name(name)
            if not (nk or li_slug or em):
                return

            existing = (
                (by_slug.get(li_slug) if li_slug else None)
                or (by_email.get(em) if em else None)
                or (by_name.get(nk) if nk else None)
            )
            if existing:
                _merge_records(existing, emp)
                if li_slug:
                    by_slug[li_slug] = existing
                if em:
                    by_email[em] = existing
                if nk:
                    by_name[nk] = existing
                return

            if not emp.get("sources"):
                emp["sources"] = [emp["source"]] if emp.get("source") else ["Public Footprint"]
            if not emp.get("confidence"):
                emp["confidence"] = "HIGH" if (li_url or emp.get("wikipedia_url")) else "MEDIUM"
            photo = emp.get("photo_url") or emp.get("avatar_url") or emp.get("linkedin_og_image")
            if photo:
                emp["photo_url"] = photo
                emp["avatar_url"] = photo

            employee_directory.append(emp)
            if nk:
                by_name[nk] = emp
            if li_slug:
                by_slug[li_slug] = emp
            if em:
                by_email[em] = emp

        for f in founders:
            add_employee(dict(f))

        for t in company_meta.get("scraped_team", []):
            t_name = (t.get("name") or "").strip()
            t_parts = t_name.split()
            first_name = _clean_email_part(t_parts[0], "user") if t_parts else "user"
            last_name = _clean_email_part(t_parts[-1], "name") if len(t_parts) > 1 else "name"
            t["inferred_email"] = f"{first_name}.{last_name}@{clean_domain}"
            t["is_verified"] = True
            t.setdefault("confidence", "HIGH")
            t.setdefault("sources", [t.get("source") or "Website Team Page"])
            t["risk_level"] = "Elevated: Public Identity Exposes Corporate Structure"
            add_employee(t)

        for c_emp in (crawled_linkedin_employees or []) + (online_employees or []) + (people_api_emps if 'people_api_emps' in locals() else []) + (people_api_employees or []):
            add_employee(c_emp)
            if c_emp.get("is_founder") and not any(w in c_emp.get("title", "").lower() for w in ["follower", "associated", "staff", "member"]):
                c_name = (c_emp.get("name") or "").strip()
                nk = _norm_person_name(c_name)
                if nk and nk not in seen_founders:
                    seen_founders[nk] = c_emp
                    founders.append(c_emp)

        for p in website_social_profiles:
            if p.get("platform") == "LinkedIn" and p.get("type") == "personal":
                slug = p.get("handle") or ""
                p_url = p.get("url") or f"https://www.linkedin.com/in/{slug}"
                p_name = CompanyMetadataScraper.clean_slug_to_name(slug) if slug else "Team Member"
                p_parts = p_name.split()
                first_name = _clean_email_part(p_parts[0], "user") if p_parts else "user"
                last_name = _clean_email_part(p_parts[-1], "name") if len(p_parts) > 1 else "name"
                add_employee({
                    "name": p_name,
                    "title": "Staff / Team Member",
                    "department": "Engineering & Tech",
                    "linkedin_url": p_url,
                    "linkedin_search_url": f"https://www.linkedin.com/search/results/people/?keywords={urllib.parse.quote(p_name + ' ' + company_name)}",
                    "avatar_url": None,
                    "inferred_email": f"{first_name}.{last_name}@{clean_domain}",
                    "bio": f"Identified via website LinkedIn personal profile link: {p_url}",
                    "source": "Website LinkedIn Profile Link",
                    "sources": ["Website LinkedIn Profile Link"],
                    "confidence": "MEDIUM",
                    "is_verified": True,
                    "risk_level": "Elevated: Public Identity Exposes Corporate Structure",
                })

        for m in github_intel.get("members", []):
            m_name = m.get("name") or m.get("login")
            add_employee({
                "name": m_name,
                "title": f"Developer / Contributor (@{m.get('login')})",
                "department": "Engineering & Tech",
                "linkedin_url": "",
                "github_url": f"https://github.com/{m.get('login')}" if m.get("login") else "",
                "linkedin_search_url": f"https://www.linkedin.com/search/results/people/?keywords={urllib.parse.quote(m_name + ' ' + company_name)}",
                "avatar_url": m.get("avatar_url"),
                "photo_url": m.get("avatar_url"),
                "email": m.get("email"),
                "location": m.get("location") or "",
                "bio": m.get("bio") or f"Public GitHub member of @{github_intel.get('handle', '')}",
                "source": "GitHub Organization Member",
                "sources": ["GitHub Organization Member"],
                "confidence": "HIGH",
            })

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

            add_employee({
                "name": full_name,
                "title": inferred_role,
                "department": dept_normalized,
                "linkedin_url": "",
                "linkedin_search_url": p_data.get("linkedin_search_url") or f"https://www.linkedin.com/search/results/people/?keywords={urllib.parse.quote(full_name + ' ' + company_name)}",
                "avatar_url": prof.get("avatar_url"),
                "photo_url": prof.get("avatar_url"),
                "email": prof.get("email"),
                "bio": f"Role: {inferred_role} ({dept})",
                "source": "Gravatar / Email Identity" if prof.get("avatar_url") else "Discovered Corporate Identity",
                "sources": ["Gravatar / Email Identity"] if prof.get("avatar_url") else ["Discovered Corporate Identity"],
                "confidence": "MEDIUM" if prof.get("avatar_url") else "LOW",
            })

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

        reported_emp_count = (
            (company_details or {}).get("estimated_employees")
            or (wiki_intel or {}).get("estimated_employees")
            or company_meta.get("estimated_employees")
            or ""
        )

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
            "directory_count": len(employee_directory),
            "reported_employee_count": reported_emp_count,
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
            # Check availability & CDX summary concurrently via safe_osint_request
            resp, cdx_resp = await asyncio.gather(
                safe_osint_request("GET", f"https://archive.org/wayback/available?url={domain}", client=client, timeout=6.0, cache_ttl=1800.0),
                safe_osint_request("GET", f"https://web.archive.org/cdx/search/cdx?url={domain}&output=json&limit=5&fl=timestamp,statuscode&collapse=timestamp:4", client=client, timeout=7.5, cache_ttl=1800.0),
            )
            if resp is not None and resp.status_code == 200:
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

            if cdx_resp is not None and cdx_resp.status_code == 200:
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
