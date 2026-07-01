# ORM models that map directly to MySQL tables.
# SQLAlchemy uses these to create/query tables via Base.metadata.create_all().

import enum
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Enum, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


# Roles available in the system.
# Five HR-domain-specific roles reflecting real organisational structure.
# Only the admin role has full system access; all others are feature-scoped.
class UserRole(str, enum.Enum):
    admin               = "admin"               # Full system access — platform administrator
    hr_manager          = "hr_manager"          # HR department lead
    hr_business_partner = "hr_business_partner" # Strategic HR liaison per business unit
    hr_analyst          = "hr_analyst"          # Data / reporting access
    department_manager  = "department_manager"  # Line manager (view own dept data only)


class User(Base):
    __tablename__ = "users"

    # basic identity fields
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[Optional[str]] = mapped_column(String(255), unique=True, index=True, nullable=True)
    hashed_password: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # nullable for OAuth users
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.hr_analyst, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # True once the user completes all three sign-up steps; always True for OAuth users
    signup_completed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # OAuth provider: "email" | "google" | "microsoft"
    auth_provider: Mapped[str] = mapped_column(String(50), default="email", nullable=False)

    # OAuth provider-specific IDs — used to look up existing accounts on OAuth sign-in
    google_id: Mapped[Optional[str]] = mapped_column(String(255), unique=True, nullable=True, index=True)
    microsoft_id: Mapped[Optional[str]] = mapped_column(String(255), unique=True, nullable=True, index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # sign-up step 1 — personal details filled in during the first-time wizard
    first_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    last_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    phone_number: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)

    # sign-up step 2 — company details
    company_name: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    company_size: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    industry_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # sign-up step 3 — role and use-case preferences
    user_role_title: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    primary_use_case: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # account setup — one-time token sent via welcome email, expires in 15 minutes
    setup_token: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    setup_token_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # MFA — 6-digit OTP generated at login, expires in 5 minutes
    otp_code: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    otp_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # password reset — token sent via forgot-password email, expires in 30 minutes
    password_reset_token: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    password_reset_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # session management — cleared on logout to invalidate the refresh token
    refresh_token: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
