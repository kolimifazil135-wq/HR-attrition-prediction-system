# Application entry point.
# Creates all DB tables on startup (if they don't exist) and registers all routers.
#
# Router layout:
#   admin  → /auth/admin/*   [Admin]   — admin login
#   auth   → /auth/*         [Auth]    — password login, forgot/reset password, session
#                            [OAuth]   — Google & Microsoft OAuth
#   users  → /users/*        [Admin]   — user CRUD (admin only)
#
# Authentication is handled via HTTP-Only cookies. Once logged in, the browser
# automatically attaches the session tokens to all subsequent requests.

import logging
import time

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from slowapi.extension import _rate_limit_exceeded_handler

from app.routers.auth import limiter
from app.database import Base, engine
from app.routers import admin, auth, users

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("hr_attrition")

# ── Database tables ───────────────────────────────────────────────────────────
Base.metadata.create_all(bind=engine)
logger.info("Database tables verified / created")

# ── Application ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="HR Attrition API",
    version="2.0.0",
    description=(
        "Backend API for the HR Attrition Prediction System.\n\n"
        "**Authentication:** Call any login endpoint — the token is captured in an "
        "HTTP-Only cookie and sent automatically on all subsequent requests."
    ),
    redoc_url=None,  # ReDoc not used
)

# ── Rate Limiting ─────────────────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS ──────────────────────────────────────────────────────────────────────
# Allows the frontend (and Swagger UI on localhost) to call the API.
# Restrict `allow_origins` to your production domain before deploying.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Global exception handler ──────────────────────────────────────────────────
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception on %s %s — %s", request.method, request.url.path, exc, exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "status": "error",
            "message": "An unexpected internal error occurred. Please try again later.",
        },
    )


# ── Request timing middleware ─────────────────────────────────────────────────
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    duration_ms = (time.perf_counter() - start) * 1000
    logger.info(
        "%s %s → %d (%.1f ms)",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )
    return response


# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(admin.router)
app.include_router(auth.router)
app.include_router(users.router)


# ── Root endpoint ─────────────────────────────────────────────────────────────
@app.get(
    "/",
    tags=["System"],
    summary="API Root",
    response_description="Server status and navigation links",
)
def root():
    """
    Returns a welcome message confirming the API is live, along with
    navigation links to the docs, health check, and version endpoints.
    """
    return {
        "status": "running",
        "message": "HR Attrition API is running successfully ✓",
        "version": app.version,
        "docs": "/docs",
        "health": "/health",
        "version_info": "/version",
    }


# ── Version endpoint ──────────────────────────────────────────────────────────
@app.get(
    "/version",
    tags=["System"],
    summary="API Version",
    response_description="Current API version and stack info",
)
def version():
    """
    Returns the current API version, technology stack details, and build metadata.
    """
    return {
        "api": app.title,
        "version": app.version,
        "stack": {
            "framework": "FastAPI",
            "database": "MySQL",
            "orm": "SQLAlchemy 2.x",
            "migrations": "Alembic",
            "auth": "JWT via HTTP-Only Cookies",
        },
        "environment": "development",
    }


# ── Health check ──────────────────────────────────────────────────────────────
@app.get(
    "/health",
    tags=["System"],
    summary="Health Check",
    response_description="Application health status",
)
def health():
    """
    Simple liveness probe. Returns 200 OK when the server is up.
    Use this endpoint for load-balancer / Docker health checks.
    """
    return {"status": "ok", "message": "Service is healthy"}

