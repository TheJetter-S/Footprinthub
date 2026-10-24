# =============================================================================
# FootprintHub Backend — Application Configuration
# =============================================================================
# Loads all settings from environment variables / .env file using Pydantic.
# The .env file is searched from this file's location upward so that running
# from backend/ or the project root both work.
# =============================================================================

from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import field_validator
from typing import Optional

# Resolve project root: walk up from this file until we find .env
_here = Path(__file__).resolve().parent
_env_file = ".env"  # fallback
for _parent in [_here, _here.parent, _here.parent.parent]:
    _candidate = _parent / ".env"
    if _candidate.exists():
        _env_file = str(_candidate)
        break


class Settings(BaseSettings):
    """Central configuration loaded from environment variables."""

    # ── Database ─────────────────────────────────────────────────────────────
    # Default to SQLite so the app works with zero external services
    DATABASE_URL: str = "sqlite+aiosqlite:///./footprinthub.db"

    # ── Redis ────────────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"

    # ── JWT ──────────────────────────────────────────────────────────────────
    JWT_SECRET_KEY: str = "change-this-to-a-random-64-char-hex-string"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ── API Keys (optional — modules degrade gracefully) ────────────────────
    SHODAN_API_KEY: Optional[str] = None
    CENSYS_API_ID: Optional[str] = None
    CENSYS_API_SECRET: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    SECURITYTRAILS_API_KEY: Optional[str] = None
    HUNTER_IO_API_KEY: Optional[str] = None
    HIBP_API_KEY: Optional[str] = None
    GOOGLE_SAFE_BROWSING_API_KEY: Optional[str] = None
    GITHUB_TOKEN: Optional[str] = None

    # ── Rate Limiting ───────────────────────────────────────────────────────
    RATE_LIMIT_PER_MINUTE: int = 10

    # ── Scan Defaults ───────────────────────────────────────────────────────
    DEFAULT_MODULE_TIMEOUT: int = 60
    MAX_RESPONSE_SIZE_BYTES: int = 10_485_760  # 10 MB
    CACHE_TTL_SECONDS: int = 86400  # 24 hours

    # ── Application ─────────────────────────────────────────────────────────
    BACKEND_CORS_ORIGINS: str = "http://localhost:3000,http://localhost:5173"
    APP_ENV: str = "development"

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: str) -> str:
        """Keep as string; we'll split in main.py when adding CORS middleware."""
        return v

    @property
    def cors_origins_list(self) -> list[str]:
        """Return CORS origins as a list."""
        return [origin.strip() for origin in self.BACKEND_CORS_ORIGINS.split(",")]

    class Config:
        env_file = _env_file
        env_file_encoding = "utf-8"
        case_sensitive = True
        extra = "ignore"  # ignore Docker-only vars like POSTGRES_USER


# Singleton instance — import this everywhere
settings = Settings()
