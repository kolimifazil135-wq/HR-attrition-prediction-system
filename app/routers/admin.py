# Admin authentication router.
# Handles admin-only login — no MFA, token pair returned immediately.
# All admin user-management endpoints live in routers/users.py.
# Both this file and users.py use the [Admin] tag so they appear
# together as one clean group in Swagger UI.

import logging
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.routers.auth import limiter
from app.database import get_db
from app.models import User, UserRole
from app.schemas import LoginRequest, TokenPairResponse
from app.security import create_access_token, create_refresh_token, verify_password

router = APIRouter(prefix="/auth/admin", tags=["Admin"])
logger = logging.getLogger("hr_attrition.auth")


# POST /auth/admin/login
# Admin-only — verifies email + password and returns a token pair directly.
# No OTP step. Non-admin accounts are rejected with a clear redirect hint.
@router.post(
    "/login",
    response_model=TokenPairResponse,
)
@limiter.limit("5/minute")
def admin_login(request: Request, payload: LoginRequest, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()

    if not user or not user.hashed_password or not verify_password(payload.password, user.hashed_password):
        logger.warning(f"Failed login attempt for admin email: {payload.email} - Invalid credentials")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not user.is_active:
        logger.warning(f"Attempted login on deactivated admin account: {payload.email}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated — contact your administrator",
        )

    if user.role != UserRole.admin:
        logger.warning(f"Failed login attempt for non-admin email on admin endpoint: {payload.email}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This endpoint is for admin accounts only. Non-admin users must log in via POST /auth/user/login",
        )

    # OAuth-linked admins should use their provider, not email/password
    if user.auth_provider != "email":
        logger.warning(f"Failed login attempt - OAuth user {payload.email} attempted password login")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"This account uses {user.auth_provider.title()} login. Please sign in with {user.auth_provider.title()}.",
        )

    access_token = create_access_token({"sub": str(user.id), "role": user.role})
    refresh_token = create_refresh_token({"sub": str(user.id), "role": user.role})
    user.refresh_token = refresh_token
    db.commit()

    # Set HTTP-Only cookies
    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=True, samesite="lax")
    response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=True, samesite="lax")

    logger.info(f"Successful admin login for user ID: {user.id} ({payload.email})")
    return TokenPairResponse(access_token=access_token, refresh_token=refresh_token)
