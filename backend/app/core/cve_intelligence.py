# =============================================================================
# FootprintHub — CVE Threat Intelligence & Prioritization Service
# =============================================================================
# Manages CISA Known Exploited Vulnerabilities (KEV) catalog and FIRST Exploit
# Prediction Scoring System (EPSS) data feeds with daily in-memory and disk caching.
# Prioritizes discovered CVEs by active exploitation likelihood and critical risk.
# =============================================================================

import asyncio
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
CACHE_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "cache"
KEV_CACHE_FILE = CACHE_DIR / "cisa_kev.json"
EPSS_CACHE_FILE = CACHE_DIR / "epss_cache.json"

# In-memory caches
_cisa_kev_cache: dict[str, dict[str, Any]] = {}
_cisa_kev_timestamp: Optional[datetime] = None
_epss_cache: dict[str, dict[str, float]] = {}


class CVEIntelligenceService:
    """Service to load, cache, and score CVEs against CISA KEV and EPSS feeds."""

    @classmethod
    def _ensure_cache_dir(cls) -> None:
        try:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.warning(f"Failed to create cache directory {CACHE_DIR}: {e}")

    @classmethod
    async def load_cisa_kev(cls, force_refresh: bool = False) -> dict[str, dict[str, Any]]:
        """
        Load CISA Known Exploited Vulnerabilities catalog.
        Caches in-memory and on disk for 24 hours.
        """
        global _cisa_kev_cache, _cisa_kev_timestamp
        now = datetime.now(timezone.utc)

        # 1. Check in-memory freshness (24h TTL)
        if not force_refresh and _cisa_kev_cache and _cisa_kev_timestamp:
            age_hours = (now - _cisa_kev_timestamp).total_seconds() / 3600.0
            if age_hours < 24.0:
                return _cisa_kev_cache

        # 2. Check disk cache
        cls._ensure_cache_dir()
        if not force_refresh and KEV_CACHE_FILE.exists():
            try:
                stat = KEV_CACHE_FILE.stat()
                file_age_hours = (datetime.now().timestamp() - stat.st_mtime) / 3600.0
                if file_age_hours < 24.0:
                    with open(KEV_CACHE_FILE, "r", encoding="utf-8") as f:
                        disk_data = json.load(f)
                        if disk_data and len(disk_data) > 0:
                            _cisa_kev_cache = disk_data
                            _cisa_kev_timestamp = now
                            return _cisa_kev_cache
            except Exception as e:
                logger.warning(f"Error reading CISA KEV disk cache: {e}")

        # 3. Fetch from CISA feed
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(CISA_KEV_URL)
                if resp.status_code == 200:
                    data = resp.json()
                    vulns = data.get("vulnerabilities", [])
                    kev_map = {}
                    for v in vulns:
                        cve_id = v.get("cveID", "").upper().strip()
                        if cve_id:
                            kev_map[cve_id] = {
                                "cve_id": cve_id,
                                "vendor_project": v.get("vendorProject", ""),
                                "product": v.get("product", ""),
                                "vulnerability_name": v.get("vulnerabilityName", ""),
                                "date_added": v.get("dateAdded", ""),
                                "short_description": v.get("shortDescription", ""),
                                "required_action": v.get("requiredAction", ""),
                            }
                    if kev_map:
                        _cisa_kev_cache = kev_map
                        _cisa_kev_timestamp = now

                        # Save to disk
                        try:
                            with open(KEV_CACHE_FILE, "w", encoding="utf-8") as f:
                                json.dump(kev_map, f)
                        except Exception as e:
                            logger.warning(f"Failed to write CISA KEV to disk cache: {e}")

                        return _cisa_kev_cache
        except Exception as e:
            logger.warning(f"Failed to fetch CISA KEV feed: {e}")

        # 4. Stale disk cache fallback on network error
        if KEV_CACHE_FILE.exists():
            try:
                with open(KEV_CACHE_FILE, "r", encoding="utf-8") as f:
                    _cisa_kev_cache = json.load(f)
                    _cisa_kev_timestamp = now
                    return _cisa_kev_cache
            except Exception:
                pass

        return _cisa_kev_cache

    @classmethod
    async def get_epss_scores(cls, cve_ids: list[str]) -> dict[str, dict[str, float]]:
        """
        Query FIRST Exploit Prediction Scoring System (EPSS) for a list of CVE IDs.
        Returns mapping: CVE -> {"epss": float, "percentile": float}.
        """
        global _epss_cache
        normalized_ids = [c.upper().strip() for c in cve_ids if c and c.strip()]
        if not normalized_ids:
            return {}

        cls._ensure_cache_dir()

        # Load disk cache if memory is empty
        if not _epss_cache and EPSS_CACHE_FILE.exists():
            try:
                with open(EPSS_CACHE_FILE, "r", encoding="utf-8") as f:
                    _epss_cache = json.load(f)
            except Exception:
                pass

        missing_cves = [c for c in normalized_ids if c not in _epss_cache]
        if missing_cves:
            # Query FIRST API in batches of 30
            batch_size = 30
            for i in range(0, len(missing_cves), batch_size):
                batch = missing_cves[i:i + batch_size]
                query_str = ",".join(batch)
                try:
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        resp = await client.get(f"{EPSS_API_URL}?cve={query_str}")
                        if resp.status_code == 200:
                            data = resp.json()
                            for item in data.get("data", []):
                                c_id = item.get("cve", "").upper().strip()
                                try:
                                    epss_val = float(item.get("epss", 0.0))
                                    percentile_val = float(item.get("percentile", 0.0))
                                except (ValueError, TypeError):
                                    epss_val = 0.0
                                    percentile_val = 0.0
                                _epss_cache[c_id] = {
                                    "epss": epss_val,
                                    "percentile": percentile_val,
                                }
                except Exception as e:
                    logger.warning(f"Error querying EPSS API for batch {batch}: {e}")

            # Populate default zeros for any CVE that wasn't found in FIRST API
            for c in missing_cves:
                if c not in _epss_cache:
                    _epss_cache[c] = {"epss": 0.0, "percentile": 0.0}

            # Persist updated EPSS cache to disk
            try:
                with open(EPSS_CACHE_FILE, "w", encoding="utf-8") as f:
                    json.dump(_epss_cache, f)
            except Exception as e:
                logger.warning(f"Failed to persist EPSS cache: {e}")

        return {c: _epss_cache.get(c, {"epss": 0.0, "percentile": 0.0}) for c in normalized_ids}

    @classmethod
    async def prioritize_cves(cls, cve_ids: list[str]) -> list[dict[str, Any]]:
        """
        Enrich and rank CVEs by exploitation likelihood and CISA KEV inclusion.
        Returns a sorted list of enriched CVE records.
        """
        if not cve_ids:
            return []

        # Deduplicate & normalize
        unique_cves = sorted(list({c.upper().strip() for c in cve_ids if c and c.strip()}))
        kev_map, epss_map = await asyncio.gather(
            cls.load_cisa_kev(),
            cls.get_epss_scores(unique_cves),
        )

        ranked: list[dict[str, Any]] = []
        for cve in unique_cves:
            is_kev = cve in kev_map
            kev_info = kev_map.get(cve)
            epss_data = epss_map.get(cve, {"epss": 0.0, "percentile": 0.0})
            epss_score = epss_data.get("epss", 0.0)
            epss_pct = epss_data.get("percentile", 0.0)

            # Determine risk tier
            if is_kev or epss_score >= 0.50:
                risk_level = "Critical"
            elif epss_score >= 0.10 or epss_pct >= 0.90:
                risk_level = "High"
            elif epss_score >= 0.02 or epss_pct >= 0.50:
                risk_level = "Medium"
            else:
                risk_level = "Low"

            record = {
                "cve_id": cve,
                "known_exploited": is_kev,
                "epss_score": round(epss_score, 4),
                "epss_percentile": round(epss_pct, 4),
                "risk_level": risk_level,
                "vendor_project": kev_info.get("vendor_project") if kev_info else None,
                "product": kev_info.get("product") if kev_info else None,
                "vulnerability_name": kev_info.get("vulnerability_name") if kev_info else None,
                "required_action": kev_info.get("required_action") if kev_info else None,
                "date_added": kev_info.get("date_added") if kev_info else None,
            }
            ranked.append(record)

        # Sort: 1st known exploited (descending), 2nd EPSS score (descending)
        ranked.sort(
            key=lambda r: (1 if r["known_exploited"] else 0, r["epss_score"], r["epss_percentile"]),
            reverse=True,
        )
        return ranked

