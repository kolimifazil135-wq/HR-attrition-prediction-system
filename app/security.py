# Handles password hashing, JWT operations, OTP generation, and outbound email.
# Used by auth router, users router, and dependencies.

import re
import secrets
import smtplib
import string
import uuid
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from threading import Thread

import bcrypt as _bcrypt
from jose import JWTError, jwt

from app.config import settings


# ── Password hashing ──────────────────────────────────────
# Uses the bcrypt library directly — passlib 1.7.4 is incompatible with bcrypt >= 4.2

def hash_password(password: str) -> str:
    # Converts a plain-text password to a bcrypt hash for safe storage
    return _bcrypt.hashpw(password.encode("utf-8"), _bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    # Checks a plain-text password against the stored hash (used during login)
    return _bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def validate_password_strength(password: str) -> None:
    # Enforces password rules: min 8 chars, uppercase, lowercase, digit, special character.
    # Raises ValueError with a descriptive message if any rule is not met.
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter")
    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter")
    if not re.search(r"\d", password):
        raise ValueError("Password must contain at least one number")
    if not re.search(r"[^A-Za-z0-9]", password):
        raise ValueError("Password must contain at least one special character")


# ── JWT tokens ────────────────────────────────────────────

def create_access_token(data: dict) -> str:
    # Encodes user data (sub = user ID, role) into a signed JWT with an expiry
    payload = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload["exp"] = expire
    payload["type"] = "access"
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(data: dict) -> str:
    # Longer-lived token used to get a new access token without re-logging in
    payload = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    payload["exp"] = expire
    payload["type"] = "refresh"
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_session_token(email: str, expires_delta: timedelta, token_type: str) -> str:
    # Encodes an email into a short-lived session JWT (used for OTP and Reset cookies)
    expire = datetime.now(timezone.utc) + expires_delta
    payload = {"sub": email, "exp": expire, "type": token_type}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def verify_session_token(token: str, expected_type: str) -> str:
    # Decodes a session JWT, validates its type, and returns the email (sub)
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != expected_type:
            raise JWTError("Invalid token type")
        email: str = payload.get("sub")
        if email is None:
            raise JWTError("Token missing subject")
        return email
    except JWTError as e:
        raise ValueError(f"Token invalid or expired: {e}")


def decode_token(token: str) -> dict:
    # Decodes and verifies a JWT; returns empty dict if token is invalid or expired
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        return {}


def decode_microsoft_token(id_token: str) -> dict:
    # Extracts claims from a Microsoft id_token WITHOUT verifying the signature.
    # Signature verification is skipped because the token was just received from
    # Microsoft's own token endpoint over HTTPS — the transport itself is the trust anchor.
    return jwt.get_unverified_claims(id_token)


# ── OTP and setup token ───────────────────────────────────

def generate_otp() -> str:
    # 6-digit numeric OTP for MFA — cryptographically random
    return str(secrets.randbelow(900000) + 100000)


def generate_setup_token() -> str:
    # UUID used as the one-time account setup token sent in the welcome email
    return str(uuid.uuid4())


def generate_default_password() -> str:
    # Generates a 12-character default password that satisfies all strength rules.
    # Guarantees at least one uppercase, one lowercase, one digit, and one special character.
    special_chars = "!@#$%^&*"
    alphabet = string.ascii_letters + string.digits + special_chars

    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(12))
        if (
            any(c.isupper() for c in pwd)
            and any(c.islower() for c in pwd)
            and any(c.isdigit() for c in pwd)
            and any(c in special_chars for c in pwd)
        ):
            return pwd


def generate_password_reset_token() -> str:
    # UUID used as the one-time password reset token sent via the forgot-password email
    return str(uuid.uuid4())


# ── Email helpers ─────────────────────────────────────────

def _send_email(to: str, subject: str, html_body: str) -> None:
    # Internal — builds and sends the email over SMTP with STARTTLS
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_USER
    msg["To"] = to
    msg.attach(MIMEText(html_body, "html"))

    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
        server.ehlo()
        server.starttls()
        server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        server.sendmail(settings.SMTP_USER, to, msg.as_string())


import logging

logger = logging.getLogger("hr_attrition.security")

def _fire_and_forget(fn, *args) -> None:
    # Runs email sending in a background thread so the HTTP response isn't blocked
    def wrapper(*args):
        try:
            fn(*args)
        except Exception as e:
            logger.error(f"Background task {fn.__name__} failed: {e}", exc_info=True)

    Thread(target=wrapper, args=args, daemon=True).start()


def send_welcome_email(to_email: str, name: str, default_password: str) -> None:
    # Welcome email sent to new users created by the admin.
    # Contains the user's email address and their system-generated default password.
    # The user must log in with these credentials and then complete the sign-up wizard.
    subject = "Welcome to HR Portal — Your Account Credentials"
    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; color: #2d3748;">

        <h2 style="color: #2d3748;">Welcome, {name}!</h2>
        <p style="color: #4a5568;">
            Your HR Portal account has been created by your administrator.<br>
            Use the credentials below to sign in for the first time.
        </p>

        <div style="background: #f7fafc; border: 1px solid #e2e8f0; border-radius: 8px;
                    padding: 20px; margin: 24px 0;">
            <p style="margin: 0 0 10px; font-size: 14px; color: #2d3748;">
                <strong>Email:</strong>&nbsp; {to_email}
            </p>
            <p style="margin: 0; font-size: 14px; color: #2d3748;">
                <strong>Default Password:</strong>&nbsp;
                <code style="background: #eef2ff; padding: 3px 10px; border-radius: 4px;
                             color: #4f46e5; font-size: 14px; letter-spacing: 0.05em;">
                    {default_password}
                </code>
            </p>
        </div>

        <p style="color: #718096; font-size: 13px; line-height: 1.6;">
            After signing in, you will be guided through a quick account setup to choose
            your own password and complete your profile. This default password will no
            longer work once you set a new one.
        </p>

        <p style="font-size: 12px; color: #a0aec0; border-top: 1px solid #e2e8f0; padding-top: 16px;">
            If you did not expect this email, please contact your HR administrator.
        </p>
        <p style="color: #a0aec0; font-size: 12px; margin-top: 8px;">HR Attrition Portal</p>
    </div>
    """
    _fire_and_forget(_send_email, to_email, subject, html_body)


def send_password_reset_email(to_email: str, name: str, token: str) -> None:
    # Forgot-password email — contains a link the user clicks to reset their password.
    # The link points to the frontend reset-password page with the token as a query param.
    reset_url = f"{settings.FRONTEND_BASE_URL}/reset-password?token={token}"
    subject = "HR Portal — Password Reset Request"
    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; color: #2d3748;">

        <h2 style="color: #2d3748;">Password Reset</h2>
        <p style="color: #4a5568;">Hi {name},</p>
        <p style="color: #4a5568;">
            We received a request to reset your HR Portal password.<br>
            Click the button below to set a new password.
        </p>

        <p style="text-align: center; margin: 32px 0;">
            <a href="{reset_url}"
               style="background: #4f46e5; color: #fff; padding: 12px 30px;
                      border-radius: 6px; text-decoration: none; font-weight: bold;
                      font-size: 14px; display: inline-block;">
                Reset My Password
            </a>
        </p>

        <p style="font-size: 12px; color: #a0aec0; text-align: center;">
            This link expires in <strong>30 minutes</strong>.
        </p>

        <p style="font-size: 13px; color: #718096; line-height: 1.6;">
            If you did not request a password reset, you can safely ignore this email.
            Your password will not be changed.
        </p>

        <p style="font-size: 12px; color: #a0aec0; border-top: 1px solid #e2e8f0; padding-top: 16px;">
            For security, never share this link with anyone.
        </p>
        <p style="color: #a0aec0; font-size: 12px; margin-top: 8px;">HR Attrition Portal</p>
    </div>
    """
    _fire_and_forget(_send_email, to_email, subject, html_body)


def send_account_setup_email(to_email: str, name: str, token: str) -> None:
    # Welcome email sent to new users.
    # Offers three ways to get started:
    #   1. Classic setup-token link (set your own password, then log in with MFA)
    #   2. Sign in directly with Microsoft (browser redirect, no MFA)
    #   3. Sign in directly with Google (no MFA — uses the backend test page)
    setup_url      = f"{settings.API_BASE_URL}/auth/setup-password?token={token}"
    microsoft_url  = f"{settings.API_BASE_URL}/auth/microsoft/login"
    google_url     = f"{settings.API_BASE_URL}/auth/google/login"

    subject = "Welcome to HR Portal — Access Your Account"
    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; color: #2d3748;">

        <h2 style="color: #2d3748;">Welcome, {name}!</h2>
        <p style="color: #4a5568;">
            Your HR Portal account has been created by your administrator.<br>
            Choose how you'd like to get started:
        </p>

        <!-- ── Option 1: Classic setup link ── -->
        <div style="background: #f7fafc; border: 1px solid #e2e8f0; border-radius: 8px;
                    padding: 20px; margin: 24px 0;">
            <p style="margin: 0 0 6px; font-weight: bold; color: #2d3748;">
                Option 1 — Set Your Own Password
            </p>
            <p style="margin: 0 0 16px; font-size: 13px; color: #718096;">
                Click the button below to choose your password, then log in with
                your email + password + OTP verification.
            </p>
            <p style="text-align: center;">
                <a href="{setup_url}"
                   style="background: #4f46e5; color: #fff; padding: 11px 28px;
                          border-radius: 6px; text-decoration: none; font-weight: bold;
                          font-size: 14px; display: inline-block;">
                    Set Up My Account
                </a>
            </p>
            <p style="font-size: 12px; color: #a0aec0; text-align: center; margin: 12px 0 0;">
                This link expires in <strong>15 minutes</strong>.
            </p>
        </div>

        <!-- ── Divider ── -->
        <p style="text-align: center; color: #a0aec0; font-size: 13px; margin: 0;">
            ── or sign in directly with ──
        </p>

        <!-- ── Option 2: Microsoft ── -->
        <div style="margin: 20px 0; text-align: center;">
            <a href="{microsoft_url}"
               style="display: inline-block; background: #0078d4; color: #fff;
                      padding: 11px 28px; border-radius: 6px; text-decoration: none;
                      font-weight: bold; font-size: 14px; margin-bottom: 12px;">
                Sign in with Microsoft
            </a>
            <p style="font-size: 12px; color: #718096; margin: 4px 0 0;">
                Uses your Microsoft / Outlook account — no OTP required.
            </p>
        </div>

        <!-- ── Option 3: Google ── -->
        <div style="margin: 8px 0 24px; text-align: center;">
            <a href="{google_url}"
               style="display: inline-block; background: #ea4335; color: #fff;
                      padding: 11px 28px; border-radius: 6px; text-decoration: none;
                      font-weight: bold; font-size: 14px; margin-bottom: 12px;">
                Sign in with Google
            </a>
            <p style="font-size: 12px; color: #718096; margin: 4px 0 0;">
                Uses your Google account — no OTP required.
            </p>
        </div>

        <p style="font-size: 12px; color: #a0aec0; border-top: 1px solid #e2e8f0; padding-top: 16px;">
            If you sign in with Google or Microsoft using <strong>{to_email}</strong>,
            your HR Portal account will be linked automatically.
        </p>
        <p style="color: #a0aec0; font-size: 12px; margin-top: 8px;">HR Attrition Portal</p>
    </div>
    """
    _fire_and_forget(_send_email, to_email, subject, html_body)


def send_otp_email(to_email: str, name: str, otp: str) -> None:
    # OTP email sent during login for users going through MFA
    subject = "Your HR Portal Login OTP"
    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto;">
        <h2 style="color: #2d3748;">Two-Factor Authentication</h2>
        <p>Hi {name}, use the code below to complete your login.</p>
        <div style="text-align: center; margin: 32px 0;">
            <span style="font-size: 36px; font-weight: bold; letter-spacing: 8px;
                         color: #4f46e5; background: #eef2ff; padding: 16px 32px;
                         border-radius: 8px; display: inline-block;">
                {otp}
            </span>
        </div>
        <p style="color: #718096; font-size: 13px;">
            This code expires in <strong>5 minutes</strong>. Never share it with anyone.
        </p>
        <hr style="border: none; border-top: 1px solid #e2e8f0; margin-top: 32px;">
        <p style="color: #a0aec0; font-size: 12px;">HR Attrition Portal</p>
    </div>
    """
    _fire_and_forget(_send_email, to_email, subject, html_body)


def send_forgot_password_otp_email(to_email: str, name: str, otp: str) -> None:
    # Forgot-password OTP email — distinct from the login OTP so the user clearly
    # understands this code is for resetting their password, not for signing in.
    # OTP is valid for 5 minutes (same as login OTP).
    subject = "HR Portal — Password Reset OTP"
    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; color: #2d3748;">

        <h2 style="color: #2d3748;">Password Reset Request</h2>
        <p style="color: #4a5568;">Hi {name},</p>
        <p style="color: #4a5568;">
            We received a request to reset your HR Portal password.<br>
            Use the verification code below to continue. Do <strong>not</strong> share this code
            with anyone.
        </p>

        <div style="text-align: center; margin: 32px 0;">
            <span style="font-size: 36px; font-weight: bold; letter-spacing: 8px;
                         color: #4f46e5; background: #eef2ff; padding: 16px 32px;
                         border-radius: 8px; display: inline-block;">
                {otp}
            </span>
        </div>

        <p style="font-size: 12px; color: #a0aec0; text-align: center;">
            This code expires in <strong>5 minutes</strong>.
        </p>

        <p style="font-size: 13px; color: #718096; line-height: 1.6;">
            If you did not request a password reset, you can safely ignore this email.
            Your password will not be changed.
        </p>

        <hr style="border: none; border-top: 1px solid #e2e8f0; margin-top: 32px;">
        <p style="color: #a0aec0; font-size: 12px;">HR Attrition Portal</p>
    </div>
    """
    _fire_and_forget(_send_email, to_email, subject, html_body)

