"""
GrayhatWarfare OSINT Client — Exposed S3/Azure/GCS buckets.
"""

import logging
from typing import Any, Dict

import aiohttp

from backend.core.osint.base_client import OSINTClient

logger = logging.getLogger(__name__)


class GrayhatWarfareClient(OSINTClient):
    SERVICE_NAME = "grayhat_warfare"
    RATE_LIMIT_PER_SECOND = 1.0
    BASE_URL = "https://buckets.grayhatwarfare.com/api/v2"

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
        }

    async def enrich_target(self, domain: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Search for exposed cloud storage buckets related to the domain."""
        cache_key = f"grayhat:{domain}"
        cached = self._cache_get(cache_key)
        if cached:
            return cached

        result: Dict[str, Any] = {"source": "grayhat_warfare", "exposed_buckets": []}

        # Search buckets by keyword (domain name and variations)
        search_terms = [domain, domain.replace(".", "-"), domain.split(".")[0]]

        for term in search_terms:
            data = await self._fetch_json(
                f"{self.BASE_URL}/buckets",
                session,
                headers=self._headers(),
                params={"keyword": term, "limit": 20},
            )
            if not data:
                continue

            for bucket in data.get("buckets", []):
                bucket_entry = {
                    "bucket_name": bucket.get("bucket", ""),
                    "provider": bucket.get("type", "unknown"),
                    "file_count": bucket.get("fileCount", 0),
                    "url": bucket.get("url", ""),
                }
                # Deduplicate by bucket name
                if not any(
                    b["bucket_name"] == bucket_entry["bucket_name"]
                    for b in result["exposed_buckets"]
                ):
                    result["exposed_buckets"].append(bucket_entry)

        # Also search files
        file_data = await self._fetch_json(
            f"{self.BASE_URL}/files",
            session,
            headers=self._headers(),
            params={"keyword": domain, "limit": 20},
        )
        if file_data:
            result["exposed_files"] = [
                {
                    "filename": f.get("filename", ""),
                    "url": f.get("url", ""),
                    "bucket": f.get("bucket", ""),
                    "size": f.get("size", 0),
                }
                for f in file_data.get("files", [])[:20]
            ]

        result["total_buckets"] = len(result["exposed_buckets"])

        self._cache_set(cache_key, result)
        logger.info(
            f"GrayhatWarfare search for {domain}: "
            f"{result['total_buckets']} exposed buckets"
        )
        return result
