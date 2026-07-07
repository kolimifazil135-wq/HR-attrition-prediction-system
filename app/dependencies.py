# FastAPI dependency functions used to protect routes.
# Inject these via Depends() in route handlers to enforce authentication and authorization.
#
# Role hierarchy (least → most privileged):
#   employee  — standard user, default for all new accounts and OAuth sign-ups
#   hr        — HR department personnel; elevated read/write access to HR features
#   admin     — full system access; manages users, roles, and platform settings
#
# Guard functions:
#   get_current_user  — any authenticated active user (no role check)
#   require_employee  — any of the three roles (effectively same as get_current_user + role guard)
#   require_hr        — hr or admin only
#   require_admin     — admin only

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, UserRole
from app.security import decode_token


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    # Extracts the access_token from the HTTP-Only cookies.
    # Decodes the JWT and returns the corresponding active User from the DB.
    # Raises 401 if the token is invalid, expired, or the user doesn't exist.
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    payload = decode_token(token)
    user_id: int = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = db.get(User, int(user_id))
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
    return user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    # Enforces that the caller has the admin role.
    # Raises 403 if the authenticated user is not an admin.
    if current_user.role != UserRole.admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return current_user


def require_hr(current_user: User = Depends(get_current_user)) -> User:
    # Enforces that the caller is either an admin or an HR user.
    # Use this on any endpoint that HR personnel should access but employees should not.
    # Raises 403 if the authenticated user is an employee.
    if current_user.role not in (UserRole.admin, UserRole.hr):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="HR access required — this endpoint is restricted to HR and Admin roles",
        )
    return current_user


def require_employee(current_user: User = Depends(get_current_user)) -> User:
    # Permits any authenticated active user regardless of role (admin, hr, or employee).
    # Use this on endpoints that all logged-in users should reach (e.g. profile, dashboards).
    # The role check is implicit — get_current_user already validates the session.
    if current_user.role not in (UserRole.admin, UserRole.hr, UserRole.employee):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )
    return current_user
