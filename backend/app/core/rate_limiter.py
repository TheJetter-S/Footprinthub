# =============================================================================
# FootprintHub — Rate Limiter
# =============================================================================
# Simple Redis-backed sliding-window rate limiter.
# Applied per-user (authenticated) or per-IP (unauthenticated).
# =============================================================================

from datetime import datetime, timezone
from typing import Optional

from fastapi import HTTPException, Request, status
import redis.asyncio as aioredis

from app.config import settings


class RateLimiter:
    """Redis-backed sliding window rate limiter."""

    def __init__(self):
        self._redis: Optional[aioredis.Redis] = None

    async def init(self) -> None:
        """Initialize Redis connection (call once at startup)."""
        try:
            self._redis = aioredis.from_url(
                settings.REDIS_URL, decode_responses=True
            )
            # Quick connectivity check with 1s timeout
            await self._redis.ping()
        except Exception:
            self._redis = None

    async def close(self) -> None:
        """Close Redis connection."""
        if self._redis:
            try:
                await self._redis.close()
            except Exception:
                pass

    def _get_key(self, identifier: str) -> str:
        """Build the Redis key for a rate-limit bucket."""
        return f"ratelimit:{identifier}"

    async def check(self, identifier: str) -> None:
        """
        Check if the identifier (user ID or IP) is within rate limits.
        Raises HTTP 429 if the limit is exceeded.
        """
        if not self._redis:
            return  # Rate limiting disabled if Redis unavailable

        try:
            key = self._get_key(identifier)
            now = datetime.now(timezone.utc).timestamp()
            window_start = now - 60  # 1-minute sliding window

            pipe = self._redis.pipeline()
            pipe.zremrangebyscore(key, "-inf", window_start)
            pipe.zcard(key)
            pipe.zadd(key, {str(now): now})
            pipe.expire(key, 120)
            results = await pipe.execute()

            current_count = results[1]
            if current_count >= settings.RATE_LIMIT_PER_MINUTE:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded. Max {settings.RATE_LIMIT_PER_MINUTE} requests per minute.",
                )
        except HTTPException:
            raise
        except Exception:
            return  # Allow request if Redis is unreachable


# Singleton instance
rate_limiter = RateLimiter()
