# Admin authentication router.
# Handles admin-only login — no MFA, token pair returned immediately.
# All admin user-management endpoints live in routers/users.py.
# Both this file and users.py use the [Admin] tag so they appear
# together as one clean group in Swagger UI.

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, UserRole
from app.schemas import LoginRequest, TokenPairResponse
from app.security import create_access_token, create_refresh_token, verify_password

router = APIRouter(prefix="/auth/admin", tags=["Admin"])


# POST /auth/admin/login
# Admin-only — verifies email + password and returns a token pair directly.
# No OTP step. Non-admin accounts are rejected with a clear redirect hint.
@router.post(
    "/login",
    response_model=TokenPairResponse,
)
def admin_login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()

    if not user or not user.hashed_password or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated — contact your administrator",
        )

    if user.role != UserRole.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This endpoint is for admin accounts only. Non-admin users must log in via POST /auth/user/login",
        )

    # OAuth-linked admins should use their provider, not email/password
    if user.auth_provider != "email":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"This account uses {user.auth_provider.title()} login. Please sign in with {user.auth_provider.title()}.",
        )

    access_token = create_access_token({"sub": str(user.id), "role": user.role})
    refresh_token = create_refresh_token({"sub": str(user.id), "role": user.role})
    user.refresh_token = refresh_token
    db.commit()
    return TokenPairResponse(access_token=access_token, refresh_token=refresh_token)
