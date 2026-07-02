# Pydantic schemas for request validation and response serialization.
# These are separate from ORM models — they define what comes IN and goes OUT of the API,
# not what's stored in the database.

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr

from app.models import UserRole


# ── Auth ──────────────────────────────────────────────────

class LoginRequest(BaseModel):
    # Body expected for POST /auth/admin/login and POST /auth/user/login
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    # Returned after a successful admin login (access token only)
    access_token: str
    token_type: str = "bearer"


class TokenPairResponse(BaseModel):
    # Returned after MFA verification or OAuth login (both tokens)
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class MessageResponse(BaseModel):
    message: str


# Returned by POST /auth/user/login.
# requires_signup=True → sign-up wizard not yet completed; access_token and refresh_token will be None.
# requires_signup=False → sign-up is done; access_token and refresh_token are populated and ready to use.
class UserLoginResponse(BaseModel):
    requires_signup: bool
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: str = "bearer"


# ── Password Setup (legacy flow — endpoints still available) ──

class SetupPasswordVerifyRequest(BaseModel):
    # Body for POST /auth/setup-password/verify-token
    token: str


class SetupPasswordRequest(BaseModel):
    # Body for POST /auth/setup-password
    token: str
    password: str


# ── MFA ───────────────────────────────────────────────────

class MFASendOTPRequest(BaseModel):
    # Body for POST /auth/mfa/send-otp
    email: EmailStr


class MFAVerifyOTPRequest(BaseModel):
    # Body for POST /auth/mfa/verify-otp
    email: EmailStr
    otp: str


# ── Token Refresh ─────────────────────────────────────────

# (Token is now read from HTTP-Only cookies, no request body needed)


# ── Sign-Up Wizard (3 steps) ──────────────────────────────

class SignupStep1Request(BaseModel):
    # Body for POST /auth/signup/step1 — personal details and password
    email: EmailStr
    first_name: str
    last_name: str
    phone_number: Optional[str] = None
    password: str
    confirm_password: str


class SignupStep2Request(BaseModel):
    # Body for POST /auth/signup/step2 — company details
    email: EmailStr
    company_name: str
    company_size: str
    industry_type: str


class SignupStep3Request(BaseModel):
    # Body for POST /auth/signup/step3 — role, use-case, and terms acceptance
    email: EmailStr
    user_role_title: str
    primary_use_case: str
    terms_accepted: bool


# ── Forgot / Reset Password ───────────────────────────────

class ForgotPasswordRequest(BaseModel):
    # Body for POST /auth/forgot-password
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    # Body for POST /auth/reset-password
    new_password: str
    confirm_password: str


# ── New Flow: OTP Login (Passwordless) ────────────────────
# Used by the new POST /auth/otp/send and POST /auth/otp/verify endpoints.

class OTPLoginSendRequest(BaseModel):
    # Body for POST /auth/otp/send — triggers OTP email for passwordless login
    email: EmailStr


class OTPLoginVerifyRequest(BaseModel):
    # Body for POST /auth/otp/verify — submits the OTP to complete passwordless login
    email: EmailStr
    otp: str


# ── New Flow: Forgot Password via OTP ─────────────────────
# Used by the new POST /auth/forgot-password/verify-otp endpoint.

class ForgotPasswordOTPVerifyRequest(BaseModel):
    # Body for POST /auth/forgot-password/verify-otp
    # User submits the 6-digit OTP they received via the forgot-password email
    otp: str


class ForgotPasswordOTPVerifyResponse(BaseModel):
    # Returned on successful OTP verification for forgot password.
    message: str


# ── OAuth ─────────────────────────────────────────────────

class GoogleOAuthRequest(BaseModel):
    # Body for POST /auth/google
    # `token` is the Google ID token returned by the frontend Google Sign-In SDK
    token: str


# Microsoft OAuth uses a redirect flow (GET /auth/microsoft/login → callback)
# so no request body schema is needed for it.


# ── User ──────────────────────────────────────────────────

class UserCreate(BaseModel):
    # Body for POST /users — admin provides name, email, role; default password is generated and emailed
    name: str
    email: EmailStr
    role: UserRole = UserRole.hr_analyst


class UserUpdate(BaseModel):
    # Body for PUT /users/{id} — all fields optional, only provided fields are updated
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    password: Optional[str] = None


class UserRoleUpdate(BaseModel):
    # Body for PUT /users/{id}/role
    role: UserRole


class UserResponse(BaseModel):
    # Shape returned in all user-related responses (password never included)
    id: int
    name: str
    email: Optional[str] = None
    role: UserRole
    is_active: bool
    signup_completed: bool
    auth_provider: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}  # Allows building from SQLAlchemy model instances
