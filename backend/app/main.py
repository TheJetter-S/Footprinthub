# =============================================================================
# FootprintHub — FastAPI Application Entry Point
# =============================================================================

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.core.rate_limiter import rate_limiter


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    # ── Startup ──────────────────────────────────────────────────────────
    await rate_limiter.init()
    try:
        from app.models.base import engine, Base
        import app.models  # noqa: F401 — registers all models with metadata
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        print("✅ Database tables created/verified")
    except Exception as e:
        print(f"⚠️ Database notice: {e}")

    # ── Seed admin account if it doesn't exist ────────────────────────────
    try:
        from app.models.base import async_session_factory
        from app.models.user import User
        from app.core.security import hash_password
        from sqlalchemy import select

        async with async_session_factory() as session:
            result = await session.execute(
                select(User).where(User.email == "admin@footprinthub.com")
            )
            if not result.scalar_one_or_none():
                admin = User(
                    email="admin@footprinthub.com",
                    hashed_password=hash_password("Admin@1234"),
                    full_name="FootprintHub Admin",
                    is_active=True,
                )
                session.add(admin)
                await session.commit()
                print("✅ Admin user seeded: admin@footprinthub.com / Admin@1234")
            else:
                print("✅ Admin user already exists")
    except Exception as e:
        print(f"⚠️ Admin seed notice: {e}")

    print("✅ FootprintHub backend ready")
    yield
    # ── Shutdown ─────────────────────────────────────────────────────────
    await rate_limiter.close()
    print("🛑 FootprintHub backend stopped")


# ── Create FastAPI App ───────────────────────────────────────────────────────
app = FastAPI(
    title="FootprintHub",
    description="All-in-one web-based footprinting & reconnaissance platform for authorized security assessments.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS Middleware ──────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Health Check ─────────────────────────────────────────────────────────────
@app.get("/health", tags=["System"])
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "footprinthub-backend"}


# ── Register Routers ────────────────────────────────────────────────────────
from app.api.auth import router as auth_router
from app.api.scans import router as scans_router
from app.api.export import router as export_router
from app.api.history import router as history_router
from app.api.ws import router as ws_router

app.include_router(auth_router, prefix="/api/v1")
app.include_router(scans_router, prefix="/api/v1")
app.include_router(export_router, prefix="/api/v1")
app.include_router(history_router, prefix="/api/v1")
app.include_router(ws_router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
