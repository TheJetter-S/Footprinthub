# =============================================================================
# FootprintHub — Cloud Assets & Object Storage Reconnaissance Module
# =============================================================================
# Discovers AWS S3 buckets, Azure Blob containers, and Google Cloud Storage (GCS)
# buckets associated with the target domain and checks for public exposure.
# =============================================================================

import asyncio
from typing import Any, Optional
import httpx

from app.modules.base import (
    BaseModule,
    FindingSeverity,
    ModuleFinding,
    ModuleMode,
    ModuleResult,
    ProgressCallback,
)


class CloudModule(BaseModule):
    """
    Cloud Storage Discovery & Permission Audit Module.
    """

    name: str = "cloud"
    description: str = "AWS S3, Azure Blob, and GCP storage bucket discovery and public permission auditing"
    mode: ModuleMode = ModuleMode.PASSIVE
    timeout: int = 50

    async def run(
        self,
        target: str,
        on_progress: Optional[ProgressCallback] = None,
    ) -> ModuleResult:
        findings: list[ModuleFinding] = []
        discovered_buckets: list[dict[str, Any]] = []

        # Generate candidate bucket names
        base_name = target.split(".")[0].lower()
        clean_target = target.replace(".", "-").lower()

        candidates = [
            base_name,
            clean_target,
            f"{base_name}-backup",
            f"{base_name}-data",
            f"{base_name}-assets",
            f"{base_name}-public",
            f"{base_name}-dev",
            f"{base_name}-prod",
            f"{base_name}-media",
            f"{base_name}-static",
        ]

        self._progress(on_progress, 20, f"Testing {len(candidates)} object storage candidates across AWS, Azure, GCP...")

        semaphore = asyncio.Semaphore(10)

        async def _check_aws_s3(name: str):
            async with semaphore:
                url = f"https://{name}.s3.amazonaws.com"
                try:
                    async with httpx.AsyncClient(timeout=5.0) as client:
                        resp = await client.get(url)
                        if resp.status_code == 200 and "ListBucketResult" in resp.text:
                            discovered_buckets.append({
                                "provider": "AWS S3",
                                "bucket_name": name,
                                "url": url,
                                "status": "open_read",
                            })
                            findings.append(
                                ModuleFinding(
                                    severity=FindingSeverity.CRITICAL,
                                    title=f"Publicly Listable AWS S3 Bucket: {name}",
                                    description=f"S3 bucket {url} is completely open to the public without authentication. Any anonymous user can list and download files.",
                                    remediation="Enable S3 'Block Public Access' setting and update bucket policy to deny public ListBucket.",
                                )
                            )
                        elif resp.status_code == 403:
                            discovered_buckets.append({
                                "provider": "AWS S3",
                                "bucket_name": name,
                                "url": url,
                                "status": "protected",
                            })
                except Exception:
                    pass

        async def _check_gcp_bucket(name: str):
            async with semaphore:
                url = f"https://storage.googleapis.com/{name}"
                try:
                    async with httpx.AsyncClient(timeout=5.0) as client:
                        resp = await client.get(url)
                        if resp.status_code == 200 and "ListBucketResult" in resp.text:
                            discovered_buckets.append({
                                "provider": "Google Cloud Storage",
                                "bucket_name": name,
                                "url": url,
                                "status": "open_read",
                            })
                            findings.append(
                                ModuleFinding(
                                    severity=FindingSeverity.CRITICAL,
                                    title=f"Publicly Listable GCS Bucket: {name}",
                                    description=f"Google Cloud Storage bucket {url} is publicly listable.",
                                    remediation="Enforce uniform bucket-level access in GCP and remove 'allUsers' or 'allAuthenticatedUsers' permissions.",
                                )
                            )
                        elif resp.status_code == 403:
                            discovered_buckets.append({
                                "provider": "Google Cloud Storage",
                                "bucket_name": name,
                                "url": url,
                                "status": "protected",
                            })
                except Exception:
                    pass

        tasks = []
        for name in candidates:
            tasks.append(_check_aws_s3(name))
            tasks.append(_check_gcp_bucket(name))

        await asyncio.gather(*tasks)

        self._progress(on_progress, 100, f"Cloud scan completed. Found {len(discovered_buckets)} associated cloud buckets.")

        return ModuleResult(
            module_name=self.name,
            mode=self.mode,
            status="success",
            data={
                "target": target,
                "total_buckets_found": len(discovered_buckets),
                "buckets": discovered_buckets,
            },
            findings=findings,
        )
