# =============================================================================
# FootprintHub — Public REST API Key Management Routes
# =============================================================================

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.models.api_key import ApiKey
from app.models.user import User

router = APIRouter(prefix="/api-keys", tags=["API Keys Management"])


class ApiKeyCreate(BaseModel):
    name: str = Field(..., max_length=100, description="Label for the API key (e.g. CI/CD or CLI)")
    scopes: Optional[str] = Field("read,scan", description="Comma-separated permission scopes")


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_api_key(
    payload: ApiKeyCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Generate a new public API key for programmatic automation and CLI usage.
    Returns the plain-text key once; only the SHA-256 hash is persisted.
    """
    random_hex = secrets.token_hex(20)
    raw_key = f"fph_live_{random_hex}"
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    key_prefix = raw_key[:14]

    api_key_obj = ApiKey(
        user_id=current_user.id,
        name=payload.name.strip(),
        key_hash=key_hash,
        key_prefix=key_prefix,
        scopes=payload.scopes or "read,scan",
        is_active=True,
    )
    db.add(api_key_obj)
    await db.commit()
    await db.refresh(api_key_obj)

    return {
        "id": api_key_obj.id,
        "name": api_key_obj.name,
        "raw_api_key": raw_key,  # Returned only once
        "prefix": api_key_obj.key_prefix,
        "scopes": api_key_obj.scopes,
        "created_at": api_key_obj.created_at,
        "message": "Store this API key safely; it cannot be viewed again.",
    }


@router.get("")
async def list_api_keys(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all API keys belonging to the authenticated user."""
    res = await db.execute(
        select(ApiKey)
        .where(ApiKey.user_id == current_user.id)
        .order_by(desc(ApiKey.created_at))
    )
    keys = res.scalars().all()
    return [
        {
            "id": k.id,
            "name": k.name,
            "prefix": k.key_prefix,
            "scopes": k.scopes,
            "is_active": k.is_active,
            "last_used_at": k.last_used_at,
            "created_at": k.created_at,
        }
        for k in keys
    ]


@router.delete("/{key_id}")
async def revoke_api_key(
    key_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Revoke and deactivate an API key."""
    res = await db.execute(
        select(ApiKey).where(ApiKey.id == key_id, ApiKey.user_id == current_user.id)
    )
    key_obj = res.scalar_one_or_none()
    if not key_obj:
        raise HTTPException(status_code=404, detail="API key not found")

    await db.delete(key_obj)
    await db.commit()
    return {"status": "revoked", "id": key_id}

