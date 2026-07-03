# Unified authentication router.
# This file merges the former user_auth.py and oauth_auth.py into a single
# cohesive module covering all non-admin authentication flows.
#
# ── Tag: [Auth] — password-based flows ───────────────────────────────────────
#   POST /auth/user/login                  — email + password login
#   POST /auth/forgot-password             — sends OTP for password reset
#   POST /auth/forgot-password/verify-otp  — validates OTP, returns reset token
#   POST /auth/reset-password              — sets new password using reset token
#   POST /auth/refresh-token               — exchanges refresh token for new access token
#   POST /auth/logout                      — invalidates the session (clears refresh token)
#   GET  /auth/me                          — returns current user's profile
#
# ── Tag: [OAuth] — social login flows ────────────────────────────────────────
#   GET  /auth/google/login                — browser test page (hidden from schema)
#   POST /auth/google                      — Google ID token verification
#   GET  /auth/microsoft/login             — redirect to Microsoft consent screen
#   GET  /auth/microsoft/callback          — Microsoft OAuth callback
#
# Commented-out sections (kept for reference, not connected to the system):
#   Passwordless OTP sign-in : POST /auth/otp/send, POST /auth/otp/verify
#   Old sign-up wizard       : POST /auth/signup/step1, step2, step3
#   Old setup-password flow  : GET /auth/setup-password, POST /auth/setup-password/*
#   Old MFA endpoints        : POST /auth/mfa/send-otp, POST /auth/mfa/verify-otp

from datetime import datetime, timedelta, timezone
import logging

import requests as http_requests
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import settings
from app.core.oauth import get_microsoft_user_info, verify_google_token
from app.database import get_db
from app.dependencies import get_current_user
from app.models import User, UserRole
from app.schemas import (
    ForgotPasswordOTPVerifyRequest,
    ForgotPasswordOTPVerifyResponse,
    ForgotPasswordRequest,
    GoogleOAuthRequest,
    LoginRequest,
    MessageResponse,
    ResetPasswordRequest,
    TokenPairResponse,
    TokenResponse,
    UserResponse,
)
from app.security import (
    create_access_token,
    create_refresh_token,
    create_session_token,
    verify_session_token,
    decode_microsoft_token,
    decode_token,
    generate_otp,
    generate_password_reset_token,
    hash_password,
    send_forgot_password_otp_email,
    validate_password_strength,
    verify_password,
)

router = APIRouter(prefix="/auth")
logger = logging.getLogger("hr_attrition.auth")

# Global rate limiter instance. Tracks clients by their IP address.
limiter = Limiter(key_func=get_remote_address)


def render_block(filepath: str, block_name: str, **kwargs) -> str:
    import string
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    marker = f"<!-- === {block_name} === -->"
    if marker not in content:
        return f"Error: Block {block_name} not found"
    block_content = content.split(marker)[1].split("<!-- ===")[0].strip()
    return string.Template(block_content).safe_substitute(**kwargs)


# ═══════════════════════════════════════════════════════════════════════════════
# ── [Auth] PASSWORD-BASED FLOWS ───────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════


# ── Sign-In: Password Login ────────────────────────────────────────────────────

# POST /auth/user/login
# Non-admin login — verifies email + password and issues tokens directly.
# On first login (signup_completed=False), auto-sets signup_completed=True
# so the user isn't redirected to the old wizard.
# Admin accounts must use POST /auth/admin/login.
@router.post(
    "/user/login",
    response_model=TokenPairResponse,
    tags=["Auth"],
)
@limiter.limit("5/minute")
def user_login(request: Request, payload: LoginRequest, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()

    if not user or not user.hashed_password or not verify_password(payload.password, user.hashed_password):
        logger.warning(f"Failed login attempt for user email: {payload.email} - Invalid credentials")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not user.is_active:
        logger.warning(f"Attempted login on deactivated user account: {payload.email}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated — contact your administrator",
        )


    # Admins must use the dedicated admin endpoint
    if user.role == UserRole.admin:
        logger.warning(f"Failed login attempt for admin email on user endpoint: {payload.email}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin accounts must log in via POST /auth/admin/login",
        )

    # First-time login — automatically complete signup so the user isn't blocked
    if not user.signup_completed:
        user.signup_completed = True

    access_token = create_access_token({"sub": str(user.id), "role": user.role})
    refresh_token = create_refresh_token({"sub": str(user.id), "role": user.role})
    user.refresh_token = refresh_token
    db.commit()

    # Set HTTP-Only cookies
    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True, samesite="lax")
    response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=True, samesite="lax")

    logger.info(f"Successful user login for user ID: {user.id} ({payload.email})")
    return TokenPairResponse(access_token=access_token, refresh_token=refresh_token)


# ── Forgot Password ────────────────────────────────────────────────────────────

# POST /auth/forgot-password
# User submits their email. A 6-digit OTP is generated and emailed.
# The OTP is stored in otp_code / otp_expires_at (shared with OTP login fields).
# After this, the user calls POST /auth/forgot-password/verify-otp to get a reset token.
@router.post(
    "/forgot-password",
    response_model=MessageResponse,
    tags=["Auth"],
)
@limiter.limit("5/minute")
def forgot_password(request: Request, response: Response, payload: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()

    # Return a generic success message to prevent user enumeration
    if not user or not user.is_active:
        return MessageResponse(message="If this email is registered, an OTP has been sent")

    otp = generate_otp()
    user.otp_code = otp
    user.otp_expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    db.commit()

    otp_token = create_session_token(user.email, timedelta(minutes=5), "otp")
    response.set_cookie(
        key="otp_session",
        value=otp_token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=300,
    )

    send_forgot_password_otp_email(user.email, user.name, otp)
    return MessageResponse(message="If this email is registered, an OTP has been sent")


# POST /auth/forgot-password/verify-otp
# User submits the 6-digit OTP they received via the forgot-password email.
# On success:
#   1. OTP is cleared from the DB
#   2. A short-lived UUID reset token is generated and stored (valid 15 minutes)
#   3. The reset token is returned to the frontend
# The frontend uses this token to call POST /auth/reset-password.
@router.post(
    "/forgot-password/verify-otp",
    response_model=ForgotPasswordOTPVerifyResponse,
    tags=["Auth"],
)
@limiter.limit("5/minute")
def forgot_password_verify_otp(
    request: Request, response: Response, payload: ForgotPasswordOTPVerifyRequest, db: Session = Depends(get_db)
):
    otp_token = request.cookies.get("otp_session")
    if not otp_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing OTP session")

    try:
        email = verify_session_token(otp_token, "otp")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    user = db.query(User).filter(User.email == email).first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid OTP or email",
        )

    if not user.otp_code or user.otp_code != payload.otp:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid OTP",
        )

    expiry = user.otp_expires_at
    if expiry is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid OTP",
        )

    # Normalize timezone for comparison
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) > expiry:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OTP has expired — request a new one via POST /auth/forgot-password",
        )

    # OTP is valid — clear it and issue a short-lived password reset token cookie
    user.otp_code = None
    user.otp_expires_at = None
    db.commit()

    response.delete_cookie("otp_session")

    reset_token = create_session_token(user.email, timedelta(minutes=15), "reset")
    response.set_cookie(
        key="reset_session",
        value=reset_token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=900,
    )

    return ForgotPasswordOTPVerifyResponse(
        message="OTP verified — use the reset_session to set your new password",
    )


# ── Reset Password ─────────────────────────────────────────────────────────────

# POST /auth/reset-password
# User submits the reset token (returned by /forgot-password/verify-otp) plus new password.
# On success: new password is hashed and saved, reset token is cleared.
@router.post(
    "/reset-password",
    response_model=MessageResponse,
    tags=["Auth"],
)
@limiter.limit("5/minute")
def reset_password(request: Request, response: Response, payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    reset_token = request.cookies.get("reset_session")
    if not reset_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing reset session")

    try:
        email = verify_session_token(reset_token, "reset")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    user = db.query(User).filter(User.email == email).first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session or user",
        )

    if payload.new_password != payload.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match",
        )

    try:
        validate_password_strength(payload.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    user.hashed_password = hash_password(payload.new_password)
    user.password_reset_token = None
    user.password_reset_expires_at = None
    db.commit()

    response.delete_cookie("reset_session")

    return MessageResponse(message="Password reset successfully — you can now log in")


# ── Token Refresh ──────────────────────────────────────────────────────────────

# POST /auth/refresh-token
# Exchanges a valid refresh token for a new access token.
# The refresh token must match the one stored in the DB (revoked on logout).
@router.post(
    "/refresh-token",
    response_model=TokenPairResponse,
    tags=["Auth"],
)
def refresh_token(request: Request, response: Response, db: Session = Depends(get_db)):
    # Read the refresh_token from the HTTP-Only cookie
    refresh_cookie = request.cookies.get("refresh_token")
    if not refresh_cookie:
        logger.warning("Refresh token attempt failed: no refresh token found in cookies")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found in cookies",
        )

    token_data = decode_token(refresh_cookie)

    if not token_data or token_data.get("type") != "refresh":
        logger.warning("Refresh token attempt failed: invalid refresh token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    user_id = token_data.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    user = db.get(User, int(user_id))
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    if user.refresh_token != refresh_cookie:
        logger.warning(f"Refresh token attempt failed: token revoked for user ID {user_id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked — please log in again",
        )

    new_access_token = create_access_token({"sub": str(user.id), "role": user.role})
    new_refresh_token = create_refresh_token({"sub": str(user.id), "role": user.role})
    user.refresh_token = new_refresh_token
    db.commit()
    
    # Set the new access token and refresh token cookies
    response.set_cookie(key="access_token", value=new_access_token, httponly=True, secure=True, samesite="lax")
    response.set_cookie(key="refresh_token", value=new_refresh_token, httponly=True, secure=True, samesite="lax")

    logger.info(f"Successful refresh token rotation for user ID: {user.id}")
    return TokenPairResponse(access_token=new_access_token, refresh_token=new_refresh_token)


# ── Session — Logout / Me ──────────────────────────────────────────────────────

# POST /auth/logout
# Clears the stored refresh token — future refresh attempts with the old token will fail.
@router.post(
    "/logout",
    response_model=MessageResponse,
    tags=["Auth"],
)
def logout(
    response: Response,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    current_user.refresh_token = None
    db.commit()

    # Clear the session cookies
    response.delete_cookie(key="access_token", httponly=True, secure=True, samesite="lax")
    response.delete_cookie(key="refresh_token", httponly=True, secure=True, samesite="lax")

    logger.info(f"Successful logout for user ID: {current_user.id}")
    return MessageResponse(message="Logged out successfully")


# GET /auth/me
# Returns the profile of whoever is currently logged in.
@router.get(
    "/me",
    response_model=UserResponse,
    tags=["Auth"],
)
def me(current_user: User = Depends(get_current_user)):
    return current_user


# ═══════════════════════════════════════════════════════════════════════════════
# ── [OAuth] SOCIAL LOGIN FLOWS ────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════


# ── Google ────────────────────────────────────────────────────────────────────

# GET /auth/google/login
# Serves a self-contained HTML test page with a real Google Sign-In button.
# On sign-in, the page calls POST /auth/google automatically and displays the tokens.
# This endpoint is intentionally hidden from Swagger (it's a browser page).
# Linked from the welcome email as the "Sign in with Google" button.
@router.get("/google/login", include_in_schema=False)
def google_login_page():
    if not settings.GOOGLE_CLIENT_ID:
        html = render_block("app/templates/auth_screens.html", "NOT_CONFIGURED")
        return HTMLResponse(content=html, status_code=503)
        
    html = render_block("app/templates/auth_screens.html", "GOOGLE_LOGIN", google_client_id=settings.GOOGLE_CLIENT_ID)
    return HTMLResponse(content=html)


# POST /auth/google
# Accepts a Google ID token (from frontend SDK or the test page above).
# Looks up by google_id, falls back to email match for account linking.
# First-time Google sign-in creates the account automatically (no setup step needed).
@router.post(
    "/google",
    summary="Sign in with Google",
    tags=["OAuth"],
)
def google_auth(payload: GoogleOAuthRequest, response: Response, db: Session = Depends(get_db)):
    if not settings.GOOGLE_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google OAuth is not configured on this server — see oauth_setup_guide.md",
        )

    try:
        info = verify_google_token(payload.token)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid Google token: {exc}",
        )

    # Look up by google_id first, then fall back to email match
    user = db.query(User).filter(User.google_id == info["google_id"]).first()

    if not user and info["email"]:
        user = db.query(User).filter(User.email == info["email"]).first()
        if user:
            # Link the existing email account to Google
            user.google_id = info["google_id"]
            user.auth_provider = "google"
            user.signup_completed = True
            db.commit()

    if not user:
        # First-time Google sign-in — create the account automatically
        user = User(
            name=info["name"] or info["email"].split("@")[0],
            email=info["email"],
            auth_provider="google",
            google_id=info["google_id"],
            signup_completed=True,
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated — contact your administrator",
        )

    access_token = create_access_token({"sub": str(user.id), "role": user.role})
    refresh_token = create_refresh_token({"sub": str(user.id), "role": user.role})
    user.refresh_token = refresh_token
    db.commit()

    # Set HTTP-Only cookies
    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True, samesite="lax")
    response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=True, samesite="lax")

    return MessageResponse(message="Authentication successful")


# ── Microsoft ─────────────────────────────────────────────────────────────────

# GET /auth/microsoft/login
# Redirects the browser to Microsoft's OAuth consent screen.
# Called directly from a browser or linked from the welcome email.
@router.get(
    "/microsoft/login",
    summary="Sign in with Microsoft (Step 1 — redirect)",
    tags=["OAuth"],
)
def microsoft_login():
    if not settings.MICROSOFT_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Microsoft OAuth is not configured on this server — see oauth_setup_guide.md",
        )

    url = (
        f"{settings.MICROSOFT_AUTH_URL}?"
        f"client_id={settings.MICROSOFT_CLIENT_ID}&"
        f"response_type=code&"
        f"redirect_uri={settings.MICROSOFT_REDIRECT_URI}&"
        f"response_mode=query&"
        f"scope=openid profile email offline_access User.Read"
    )
    return RedirectResponse(url)


# GET /auth/microsoft/callback
# Microsoft redirects here after the user authenticates.
# Exchanges the authorization code for tokens, fetches the user profile,
# and returns an app token pair.
@router.get(
    "/microsoft/callback",
    summary="Microsoft OAuth Callback (Step 2 — auto-called by Microsoft)",
    tags=["OAuth"],
)
def microsoft_callback(code: str, response: Response, db: Session = Depends(get_db)):
    # Exchange the authorization code for Microsoft tokens
    token_response = http_requests.post(
        settings.MICROSOFT_TOKEN_URL,
        data={
            "client_id": settings.MICROSOFT_CLIENT_ID,
            "client_secret": settings.MICROSOFT_CLIENT_SECRET,
            "code": code,
            "redirect_uri": settings.MICROSOFT_REDIRECT_URI,
            "grant_type": "authorization_code",
        },
        timeout=15,
    )
    token_data = token_response.json()

    if "error" in token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Microsoft token exchange failed: {token_data.get('error_description', token_data['error'])}",
        )

    # Use the id_token claims for identity (faster than an extra Graph call)
    id_token_raw = token_data.get("id_token")
    if id_token_raw:
        claims = decode_microsoft_token(id_token_raw)
        email = claims.get("email") or claims.get("preferred_username", "")
        name = claims.get("name", "")
        microsoft_id = claims.get("oid", "")
    else:
        # Fallback: call Microsoft Graph with the access token
        try:
            info = get_microsoft_user_info(token_data["access_token"])
            email = info["email"]
            name = info["name"]
            microsoft_id = info["microsoft_id"]
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Failed to fetch Microsoft profile: {exc}",
            )

    if not microsoft_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not retrieve Microsoft user identity",
        )

    # Look up by microsoft_id first, then fall back to email match
    user = db.query(User).filter(User.microsoft_id == microsoft_id).first()

    if not user and email:
        user = db.query(User).filter(User.email == email).first()
        if user:
            # Link the existing email account to Microsoft
            user.microsoft_id = microsoft_id
            user.auth_provider = "microsoft"
            user.signup_completed = True
            db.commit()

    if not user:
        # First-time Microsoft sign-in — create the account automatically
        user = User(
            name=name or (email.split("@")[0] if email else "MS User"),
            email=email or None,
            auth_provider="microsoft",
            microsoft_id=microsoft_id,
            signup_completed=True,
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated — contact your administrator",
        )

    access_token = create_access_token({"sub": str(user.id), "role": user.role})
    refresh_token = create_refresh_token({"sub": str(user.id), "role": user.role})
    user.refresh_token = refresh_token
    db.commit()

    html = render_block("app/templates/auth_screens.html", "MICROSOFT_SUCCESS")
    html_response = HTMLResponse(content=html)
    
    # Set HTTP-Only cookies
    html_response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True, samesite="lax")
    html_response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=True, samesite="lax")

    return html_response


# ═══════════════════════════════════════════════════════════════════════════════
# ── LEGACY / REFERENCE — OLD FLOW (commented out, not connected to the system) ─
# ═══════════════════════════════════════════════════════════════════════════════
#
# The sections below are original auth endpoints from the old flow.
# They are intentionally commented out so they do NOT appear in Swagger UI
# or affect the running application.
# They are kept for reference only. Do NOT uncomment without reviewing
# their imports and schema dependencies.
# ─────────────────────────────────────────────────────────────────────────────


# ── OLD: Passwordless OTP Sign-In ─────────────────────────────────────────────

# @router.post(
#     "/otp/send",
#     response_model=MessageResponse,
#     summary="Send Login OTP (Passwordless Login — Step 1 of 2)",
#     tags=["Auth"],
# )
# def otp_login_send(payload: OTPLoginSendRequest, db: Session = Depends(get_db)):
#     user = db.query(User).filter(User.email == payload.email).first()
#     if not user or not user.is_active:
#         return MessageResponse(message="If this email is registered, an OTP has been sent")
#     if user.role == UserRole.admin:
#         raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
#                             detail="Admin accounts must log in via POST /auth/admin/login")
#     otp = generate_otp()
#     user.otp_code = otp
#     user.otp_expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
#     if not user.signup_completed:
#         user.signup_completed = True
#     db.commit()
#     send_otp_email(user.email, user.name, otp)
#     return MessageResponse(message="If this email is registered, an OTP has been sent")


# @router.post(
#     "/otp/verify",
#     response_model=TokenPairResponse,
#     summary="Verify Login OTP (Passwordless Login — Step 2 of 2)",
#     tags=["Auth"],
# )
# def otp_login_verify(payload: OTPLoginVerifyRequest, db: Session = Depends(get_db)):
#     user = db.query(User).filter(User.email == payload.email).first()
#     if not user or not user.is_active:
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP or email")
#     if not user.otp_code or user.otp_code != payload.otp:
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP")
#     expiry = user.otp_expires_at
#     if expiry is None:
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP")
#     if expiry.tzinfo is None:
#         expiry = expiry.replace(tzinfo=timezone.utc)
#     if datetime.now(timezone.utc) > expiry:
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
#                             detail="OTP has expired — request a new one via POST /auth/otp/send")
#     user.otp_code = None
#     user.otp_expires_at = None
#     access_token = create_access_token({"sub": str(user.id), "role": user.role})
#     refresh_token = create_refresh_token({"sub": str(user.id), "role": user.role})
#     user.refresh_token = refresh_token
#     db.commit()
#     return TokenPairResponse(access_token=access_token, refresh_token=refresh_token)


# ── OLD: MFA Send / Verify ────────────────────────────────────────────────────

# @router.post("/mfa/send-otp", response_model=MessageResponse, summary="[OLD FLOW] Resend OTP", tags=["Auth"])
# def send_otp(...): ...

# @router.post("/mfa/verify-otp", response_model=TokenPairResponse, summary="[OLD FLOW] Verify OTP", tags=["Auth"])
# def verify_otp(...): ...


# ── OLD: Sign-Up Wizard (3 steps) ─────────────────────────────────────────────

# @router.post("/signup/step1", response_model=MessageResponse, summary="[OLD FLOW] Sign-Up Step 1", tags=["Auth"])
# def signup_step1(...): ...

# @router.post("/signup/step2", response_model=MessageResponse, summary="[OLD FLOW] Sign-Up Step 2", tags=["Auth"])
# def signup_step2(...): ...

# @router.post("/signup/step3", response_model=MessageResponse, summary="[OLD FLOW] Sign-Up Step 3", tags=["Auth"])
# def signup_step3(...): ...


# ── OLD: Setup-Password Flow ──────────────────────────────────────────────────

# @router.get("/setup-password", include_in_schema=False)
# def setup_password_page(...): ...

# @router.post("/setup-password/verify-token", response_model=MessageResponse, tags=["Auth"])
# def verify_setup_token(...): ...

# @router.post("/setup-password", response_model=MessageResponse, tags=["Auth"])
# def setup_password(...): ...
