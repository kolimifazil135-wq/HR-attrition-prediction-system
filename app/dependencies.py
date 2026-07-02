# FastAPI dependency functions used to protect routes.
# Inject these via Depends() in route handlers to enforce authentication and authorization.

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
    # Extends get_current_user — additionally enforces that the caller has the admin role.
    # Raises 403 if the authenticated user is not an admin.
    if current_user.role != UserRole.admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return current_user
