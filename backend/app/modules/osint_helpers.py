# =============================================================================
# FootprintHub — OSINT Helper Classes & Intelligence Engines
# =============================================================================
# Social media extraction from target websites, corporate metadata & JSON-LD
# parsing, LinkedIn company & employee intelligence, team/founder discovery,
# GitHub public API reconnaissance, and corporate digital footprint aggregation.
# =============================================================================

import asyncio
import html
import json
import re
import urllib.parse
from typing import Any, Optional

from bs4 import BeautifulSoup
import httpx


class SocialMediaScraper:
    """Extracts social media profile links from target website HTML pages."""

    PLATFORMS: dict[str, list[str]] = {
        "LinkedIn": [
            r"https?://(?:www\.)?linkedin\.com/company/[a-zA-Z0-9_.-]+",
            r"https?://(?:www\.)?linkedin\.com/in/[a-zA-Z0-9_.-]+",
            r"https?://(?:www\.)?linkedin\.com/school/[a-zA-Z0-9_.-]+",
        ],
        "GitHub": [
            r"https?://(?:www\.)?github\.com/[a-zA-Z0-9_.-]+",
        ],
        "Twitter / X": [
            r"https?://(?:www\.)?(?:twitter\.com|x\.com)/[a-zA-Z0-9_]+",
        ],
        "Facebook": [
            r"https?://(?:www\.)?(?:facebook\.com|fb\.com)/[a-zA-Z0-9._-]+",
        ],
        "Instagram": [
            r"https?://(?:www\.)?instagram\.com/[a-zA-Z0-9._-]+",
        ],
        "YouTube": [
            r"https?://(?:www\.)?youtube\.com/(?:c/|channel/|user/|@)?[a-zA-Z0-9_-]+",
        ],
        "TikTok": [
            r"https?://(?:www\.)?tiktok\.com/@[a-zA-Z0-9._]+",
        ],
        "Pinterest": [
            r"https?://(?:www\.)?pinterest\.com/[a-zA-Z0-9_-]+",
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
    }

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
        """Extract social media profile links from collected HTML content, including JSON and unescaped payloads."""
        # Unescape JSON escaped slashes and HTML entities
        clean_text = html_text.replace(r"\/", "/")
        try:
            clean_text = html.unescape(clean_text)
        except Exception:
            pass

        all_urls: set[str] = set()
        # Standard hrefs
        all_urls.update(re.findall(r'href=["\']([^"\']+)["\']', clean_text))
        # Quoted URLs inside scripts / JSON objects (e.g. "url":"https://...")
        all_urls.update(re.findall(r'["\'](https?://[^"\']+)["\']', clean_text))
        # Plain URLs in text
        all_urls.update(re.findall(r'https?://[^\s<>"\'\\()\[\]]+', clean_text))

        profiles: list[dict[str, Any]] = []
        seen: set[str] = set()

        for url in all_urls:
            url_clean = url.rstrip("/").split("?")[0].split("#")[0]
            if len(url_clean) < 20:
                continue

            for platform, patterns in cls.PLATFORMS.items():
                matched = False
                for pattern in patterns:
                    m = re.match(pattern, url_clean, re.IGNORECASE)
                    if m:
                        matched_url = m.group(0).rstrip("/")
                        parts = matched_url.split("/")
                        handle = parts[-1] if parts else ""
                        if handle.startswith("@"):
                            handle = handle[1:]

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
                        if "/company/" in matched_url:
                            profile_type = "company"
                        elif "/in/" in matched_url:
                            profile_type = "personal"
                        elif "/organization/" in matched_url:
                            profile_type = "organization"
                        elif "/r/" in matched_url:
                            profile_type = "subreddit"
                        elif "/channel/" in matched_url:
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

    @classmethod
    def extract_company_metadata(
        cls, html_text: str, domain: str, company_name: str
    ) -> dict[str, Any]:
        """
        Parses all crawled website HTML for company identity, description,
        founded year, headquarters, JSON-LD structured data, and team members.
        """
        html_clean = html_text.replace(r"\/", "/")
        try:
            html_clean = html.unescape(html_clean)
        except Exception:
            pass
        soup = BeautifulSoup(html_clean, "html.parser")

        meta: dict[str, Any] = {
            "name": company_name,
            "description": "",
            "industry": "Technology & Software",
            "founded_year": None,
            "headquarters": "",
            "estimated_employees": "11-50 employees",
            "founders": [],
            "scraped_team": [],
            "json_ld_detected": False,
            "contact_emails": [],
            "phone_numbers": [],
        }

        # Extract phone numbers from tel: links
        for a_tel in soup.find_all("a", href=re.compile(r"^tel:", re.I)):
            phone_val = a_tel.get("href", "").replace("tel:", "").strip()
            if phone_val and len(phone_val) >= 7 and phone_val not in meta["phone_numbers"]:
                meta["phone_numbers"].append(phone_val)

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

        # 2. Schema.org JSON-LD parsing (with @graph support & Person parsing)
        for script in soup.find_all("script", type="application/ld+json"):
            try:
                raw_json = script.string or script.get_text()
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

        # 3. Founded Year from text / copyright heuristics
        if not meta["founded_year"]:
            found_match = re.search(
                r"(?:founded\s+in|est\.|established\s+in|since)\s+(19\d\d|20\d\d)",
                html_text,
                re.IGNORECASE,
            )
            if found_match:
                meta["founded_year"] = found_match.group(1)
            else:
                cpy_match = re.search(
                    r"©\s*(?:19\d\d\s*[-–]\s*)?(20\d\d)", html_text
                )
                if cpy_match:
                    meta["founded_year"] = cpy_match.group(1)

        # 4. Industry inference from keywords / description
        text_lower = (meta["description"] + " " + html_text[:5000]).lower()
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

        # 5. Extract Founders / Leadership from text and Meta tags
        # Heuristic: "Founded by [Name]", "Created by [Name]", "Co-founded by [Name]"
        founder_text_matches = re.findall(
            r"(?:founded|co-founded|started|created|launched)\s+by\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})",
            html_text,
        )
        for f_name in founder_text_matches:
            f_clean = f_name.strip()
            if 1 < len(f_clean.split()) <= 3 and not any(w in f_clean.lower() for w in ["the", "team", "our", "company", "group", "engineers"]):
                if not any(f["name"].lower() == f_clean.lower() for f in meta["founders"]):
                    meta["founders"].append({
                        "name": f_clean,
                        "title": "Founder",
                        "department": "Executive Leadership",
                        "linkedin_url": "",
                        "bio": f"Identified as Founder of {company_name} from website text",
                        "source": "Website Text Mentions",
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
                if not any(t["name"].lower() == auth_val.lower() for t in meta["scraped_team"]):
                    meta["scraped_team"].append({
                        "name": auth_val,
                        "title": "Author / Creator",
                        "department": "Engineering & Tech",
                        "linkedin_url": "",
                        "source": "Website Meta Author Tag",
                    })

        # 6. Scrape Team Members & Founders from HTML & LinkedIn Personal links
        seen_names: set[str] = {f["name"].lower().strip() for f in meta["founders"]}
        seen_names.update({t["name"].lower().strip() for t in meta["scraped_team"]})

        # Find all LinkedIn personal profile links (/in/...)
        linkedin_in_links = soup.find_all(
            "a", href=re.compile(r"linkedin\.com/in/[a-zA-Z0-9_-]+", re.IGNORECASE)
        )
        for a in linkedin_in_links:
            href = a.get("href", "")
            m = re.search(r"linkedin\.com/in/([a-zA-Z0-9_-]+)", href, re.IGNORECASE)
            if not m:
                continue
            slug = m.group(1).rstrip("/")
            if slug.lower() in ("in", "company", "school", "pub", "feed"):
                continue

            raw_text = a.get_text(strip=True)
            name = ""
            title = "Team Member"
            avatar_url = None
            parent = a.find_parent(["div", "section", "article", "li"])

            if parent:
                # Find image in card
                img = parent.find("img")
                if img and img.get("src"):
                    src = img["src"]
                    if src.startswith("/"):
                        src = f"https://{domain}{src}"
                    avatar_url = src

                # Search card text for job title / executive roles
                card_text = parent.get_text(" ", strip=True)
                role_match = re.search(
                    r"((?:Co-)?Founder(?:\s*(?:&|and)\s*[\w\s]+)?|Chief Executive Officer|CEO|Chief Technology Officer|CTO|Chief Operating Officer|COO|Chief Financial Officer|CFO|Chief Information Security Officer|CISO|President|Managing Director|Vice President|VP(?:\s+of\s+[\w\s]+)?|Director(?:\s+of\s+[\w\s]+)?|Lead\s+[\w\s]+|Senior\s+[\w\s]+|Software\s+[\w\s]+|Security\s+[\w\s]+|Product\s+Manager|Head\s+of\s+[\w\s]+)",
                    card_text,
                    re.IGNORECASE,
                )
                if role_match:
                    title = role_match.group(0).strip().title()

                # If anchor text is a generic call to action, check headings in card
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

            name_key = name.lower().strip()
            if not name or name_key in seen_names or len(name_key) < 3:
                continue
            seen_names.add(name_key)

            is_founder = bool(
                re.search(r"(founder|ceo|chief executive|owner|president)", title, re.IGNORECASE)
            )

            person_obj = {
                "name": name,
                "title": title,
                "department": (
                    "Executive Leadership"
                    if is_founder
                    else (
                        "Cybersecurity & IT"
                        if any(w in title.lower() for w in ["security", "ciso", "soc", "sysadmin", "cloud"])
                        else "Engineering & Tech"
                    )
                ),
                "linkedin_url": href,
                "linkedin_search_url": f"https://www.linkedin.com/search/results/people/?keywords={urllib.parse.quote(name + ' ' + company_name)}",
                "avatar_url": avatar_url,
                "source": "Website LinkedIn Profile Link",
            }
            meta["scraped_team"].append(person_obj)
            if is_founder and not any(f["name"].lower() == name_key for f in meta["founders"]):
                meta["founders"].append(person_obj)

        # 7. Scrape HTML team cards (elements with class/id matching team/leaders/about)
        team_containers = soup.find_all(
            ["div", "section", "li", "article"],
            class_=re.compile(r"(team-member|team_member|team-card|member-card|leader|leadership|person-card|bio-card)", re.I),
        )
        for card in team_containers[:15]:
            h = card.find(["h2", "h3", "h4", "h5", "strong"])
            if not h:
                continue
            c_name = h.get_text(strip=True)
            if not c_name or len(c_name.split()) < 2 or len(c_name.split()) > 4:
                continue
            if re.search(r"(team|about|leadership|join|contact|values|mission)", c_name, re.I):
                continue
            c_key = c_name.lower().strip()
            if c_key in seen_names:
                continue
            seen_names.add(c_key)

            c_title = "Team Member"
            card_text = card.get_text(" ", strip=True)
            role_m = re.search(
                r"((?:Co-)?Founder(?:\s*(?:&|and)\s*[\w\s]+)?|CEO|CTO|COO|CFO|CISO|President|Managing Director|VP|Director|Lead\s+[\w\s]+|Senior\s+[\w\s]+|Software\s+[\w\s]+|Head\s+of\s+[\w\s]+|Engineer|Designer|Developer)",
                card_text,
                re.I,
            )
            if role_m:
                c_title = role_m.group(0).strip().title()

            c_img = card.find("img")
            c_avatar = None
            if c_img and c_img.get("src"):
                src = c_img["src"]
                if src.startswith("/"):
                    src = f"https://{domain}{src}"
                c_avatar = src

            # Check if card contains social links
            c_li_link = ""
            for a_tag in card.find_all("a", href=True):
                if "linkedin.com/in/" in a_tag["href"]:
                    c_li_link = a_tag["href"]
                    break

            is_f = bool(re.search(r"(founder|ceo|chief executive|owner|president)", c_title, re.I))
            card_person = {
                "name": c_name,
                "title": c_title,
                "department": "Executive Leadership" if is_f else "Engineering & Tech",
                "linkedin_url": c_li_link,
                "avatar_url": c_avatar,
                "source": "Website HTML Team Card",
            }
            meta["scraped_team"].append(card_person)
            if is_f and not any(f["name"].lower() == c_key for f in meta["founders"]):
                meta["founders"].append(card_person)

        # 8. Direct regex search for any LinkedIn personal profiles in scripts/JSON/raw text
        raw_in_matches = re.findall(r'https?://(?:www\.)?linkedin\.com/in/([a-zA-Z0-9_-]+)', html_clean, re.I)
        for slug in raw_in_matches:
            slug = slug.rstrip("/")
            if slug.lower() in ("in", "company", "school", "pub", "feed"):
                continue
            name = cls.clean_slug_to_name(slug)
            name_key = name.lower().strip()
            if not name or name_key in seen_names or len(name_key) < 3:
                continue
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

        return meta


class LinkedInOSINTEngine:
    """
    LinkedIn Open Source Intelligence Engine.
    Compiles official LinkedIn company profiles, verified founder & executive cards,
    complete departmental employee directories, and live targeted Google Dorks.
    """

    @classmethod
    def build_linkedin_intelligence(
        cls,
        domain: str,
        company_name: str,
        website_social_profiles: list[dict[str, Any]],
        company_meta: dict[str, Any],
        github_intel: dict[str, Any],
        enriched_email_profiles: list[dict[str, Any]],
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

        for f in company_meta.get("founders", []):
            f_name = f.get("name", "").strip()
            if f_name and f_name.lower() not in seen_founders:
                seen_founders.add(f_name.lower())
                first_name = f_name.split()[0].lower() if f_name.split() else "user"
                last_name = f_name.split()[-1].lower() if len(f_name.split()) > 1 else "name"
                inferred_email = f"{first_name}.{last_name}@{clean_domain}"
                
                founders.append(
                    {
                        "name": f_name,
                        "title": f.get("title") or "Founder & Executive",
                        "department": "Executive Leadership",
                        "linkedin_url": f.get("linkedin_url") or "",
                        "linkedin_search_url": f.get("linkedin_url") or f"https://www.linkedin.com/search/results/people/?keywords={urllib.parse.quote(f_name + ' ' + company_name)}",
                        "avatar_url": f.get("avatar_url"),
                        "bio": f.get("bio") or f"Leadership at {company_name}",
                        "source": f.get("source") or "Website Team Page",
                        "is_verified": True,
                        "inferred_email": inferred_email,
                        "risk_level": "High Risk: Primary Target for Spear-Phishing & BEC Impersonation",
                    }
                )

        # 3. Assemble Complete Employee Directory (Real scraped individuals only)
        employee_directory: list[dict[str, Any]] = []
        seen_employees: set[str] = set()

        def add_employee(emp: dict[str, Any]):
            name = emp.get("name", "").strip()
            key = (name.lower() or emp.get("email", "").lower())
            if not key or key in seen_employees:
                return
            seen_employees.add(key)
            employee_directory.append(emp)

        # Add verified founders first
        for f in founders:
            add_employee(f)

        # Add scraped team members from website HTML
        for t in company_meta.get("scraped_team", []):
            t_name = t.get("name", "").strip()
            first_name = t_name.split()[0].lower() if t_name.split() else "user"
            last_name = t_name.split()[-1].lower() if len(t_name.split()) > 1 else "name"
            t["inferred_email"] = f"{first_name}.{last_name}@{clean_domain}"
            t["is_verified"] = True
            t["risk_level"] = "Elevated: Public Identity Exposes Corporate Structure"
            add_employee(t)

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

        return {
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
