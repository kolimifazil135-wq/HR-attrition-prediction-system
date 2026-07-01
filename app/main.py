# Application entry point.
# Creates all DB tables on startup (if they don't exist) and registers all routers.
#
# Router layout:
#   admin  → /auth/admin/*   [Admin]   — admin login
#   auth   → /auth/*         [Auth]    — password login, forgot/reset password, session
#                            [OAuth]   — Google & Microsoft OAuth
#   users  → /users/*        [Admin]   — user CRUD (admin only)
#
# Swagger UI (/docs):
#   The Authorize button is hidden. swagger_token.js (served from /static) captures
#   the access_token from any login response and auto-injects it on all subsequent
#   requests. Token is stored in sessionStorage (browser memory — cleared on tab close).

import logging
import time

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

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
    ),
    docs_url=None,   # Custom /docs route injects swagger_token.js
    redoc_url=None,  # ReDoc not used
)

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

# ── Static assets ─────────────────────────────────────────────────────────────
app.mount("/static", StaticFiles(directory="app/static"), name="static")


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


# ── OpenAPI schema — strip Authorize button ───────────────────────────────────
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    schema = get_openapi(
        title=app.title,
        version=app.version,
        openapi_version=app.openapi_version,
        description=app.description,
        routes=app.routes,
    )

    # Remove global security schemes (hides the Authorize button)
    if "components" in schema and "securitySchemes" in schema["components"]:
        del schema["components"]["securitySchemes"]

    # Remove per-endpoint security requirements (hides padlock icons)
    for path in schema.get("paths", {}).values():
        for method in path.values():
            if "security" in method:
                del method["security"]

    app.openapi_schema = schema
    return app.openapi_schema


app.openapi = custom_openapi


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
            "auth": "JWT (RS256 / HS256)",
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


# ── Swagger UI ────────────────────────────────────────────────────────────────
@app.get("/docs", include_in_schema=False)
async def swagger_ui():
    html = get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=app.title + " - Swagger UI",
        oauth2_redirect_url=app.swagger_ui_oauth2_redirect_url,
    )
    html_content = html.body.decode("utf-8").replace(
        "</body>",
        '<script src="/static/swagger_token.js"></script></body>',
    )
    return HTMLResponse(html_content)
