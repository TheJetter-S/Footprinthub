# =============================================================================
# FootprintHub — White-Label Configuration Routes
# =============================================================================

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.models.user import User
from app.models.white_label import WhiteLabelConfig

router = APIRouter(prefix="/settings/white-label", tags=["White-Label Branding"])


class WhiteLabelUpdate(BaseModel):
    company_name: Optional[str] = Field("FootprintHub Security", max_length=255)
    logo_url: Optional[str] = Field(None, max_length=1024)
    accent_color: Optional[str] = Field("#2563eb", max_length=20)
    footer_text: Optional[str] = Field(
        "Confidential Reconnaissance & Security Assessment Report", max_length=500
    )


@router.get("")
async def get_white_label(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get current white-label branding configuration."""
    res = await db.execute(
        select(WhiteLabelConfig).where(WhiteLabelConfig.user_id == current_user.id)
    )
    wl = res.scalar_one_or_none()
    if not wl:
        return {
            "company_name": "FootprintHub Security",
            "logo_url": None,
            "accent_color": "#2563eb",
            "footer_text": "Confidential Reconnaissance & Security Assessment Report",
        }

    return {
        "company_name": wl.company_name,
        "logo_url": wl.logo_url,
        "accent_color": wl.accent_color,
        "footer_text": wl.footer_text,
    }


@router.put("")
async def update_white_label(
    payload: WhiteLabelUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create or update white-label branding configuration."""
    res = await db.execute(
        select(WhiteLabelConfig).where(WhiteLabelConfig.user_id == current_user.id)
    )
    wl = res.scalar_one_or_none()
    if not wl:
        wl = WhiteLabelConfig(user_id=current_user.id)
        db.add(wl)

    if payload.company_name is not None:
        wl.company_name = payload.company_name.strip() or "FootprintHub Security"
    if payload.logo_url is not None:
        wl.logo_url = payload.logo_url.strip() or None
    if payload.accent_color is not None:
        wl.accent_color = payload.accent_color.strip() or "#2563eb"
    if payload.footer_text is not None:
        wl.footer_text = payload.footer_text.strip() or "Confidential Security Assessment Report"

    await db.commit()
    await db.refresh(wl)

    return {
        "company_name": wl.company_name,
        "logo_url": wl.logo_url,
        "accent_color": wl.accent_color,
        "footer_text": wl.footer_text,
    }

