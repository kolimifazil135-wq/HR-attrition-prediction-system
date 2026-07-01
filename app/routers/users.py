# Users router — CRUD operations on user accounts.
# All endpoints require a valid admin JWT (enforced via require_admin dependency).

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_admin
from app.models import User
from app.schemas import UserCreate, UserResponse, UserRoleUpdate, UserUpdate
from app.security import generate_default_password, hash_password, send_welcome_email

router = APIRouter(prefix="/users", tags=["Admin"])


# POST /users
# Admin creates a new user account.
# A secure default password is generated, hashed, and stored.
# The user's email and default password are sent to them via a welcome email.
# The user must sign in with these credentials and then complete the sign-up wizard.
@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    default_password = generate_default_password()

    user = User(
        name=payload.name,
        email=payload.email,
        hashed_password=hash_password(default_password),
        role=payload.role,
        signup_completed=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    send_welcome_email(user.email, user.name, default_password)
    return user


# GET /users
# returns all users including deactivated ones — admin needs to see the full list
@router.get("", response_model=List[UserResponse])
def list_users(
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    return db.query(User).all()


# GET /users/{user_id}
# fetch a single user by their ID
@router.get("/{user_id}", response_model=UserResponse)
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


# PUT /users/{user_id}
# partial update — only fields that are sent in the body get changed
@router.put("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    payload: UserUpdate,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if payload.email and payload.email != user.email:
        if db.query(User).filter(User.email == payload.email).first():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already in use")
        user.email = payload.email

    if payload.name:
        user.name = payload.name
    if payload.password:
        user.hashed_password = hash_password(payload.password)

    db.commit()
    db.refresh(user)
    return user


# PUT /users/{user_id}/role
# change a user's role — does not touch any other field
@router.put("/{user_id}/role", response_model=UserResponse)
def update_user_role(
    user_id: int,
    payload: UserRoleUpdate,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.role = payload.role
    db.commit()
    db.refresh(user)
    return user


# PUT /users/{user_id}/deactivate
# soft delete — sets is_active to False instead of removing the record
# admin cannot deactivate their own account
@router.put("/{user_id}/deactivate", response_model=UserResponse)
def deactivate_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot deactivate your own account")

    user.is_active = False
    db.commit()
    db.refresh(user)
    return user


# DELETE /users/{user_id}
# permanently removes the user record — admin cannot delete their own account
@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete your own account")

    db.delete(user)
    db.commit()
