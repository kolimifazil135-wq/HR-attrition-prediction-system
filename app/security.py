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

def render_block(filepath: str, block_name: str, **kwargs) -> str:
    import string
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    marker = f"<!-- === {block_name} === -->"
    if marker not in content:
        return f"Error: Block {block_name} not found"
    block_content = content.split(marker)[1].split("<!-- ===")[0].strip()
    return string.Template(block_content).safe_substitute(**kwargs)


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
    
    google_url = f"{settings.API_BASE_URL}/auth/google/login"
    microsoft_url = f"{settings.API_BASE_URL}/auth/microsoft/login"
    
    html_body = render_block(
        "app/templates/emails.html",
        "WELCOME",
        name=name,
        email=to_email,
        default_password=default_password,
        google_url=google_url,
        microsoft_url=microsoft_url,
    )
    _fire_and_forget(_send_email, to_email, subject, html_body)


def send_password_reset_email(to_email: str, name: str, token: str) -> None:
    # Forgot-password email — contains a link the user clicks to reset their password.
    # The link points to the frontend reset-password page with the token as a query param.
    reset_url = f"{settings.FRONTEND_BASE_URL}/reset-password?token={token}"
    subject = "HR Portal — Password Reset Request"
    html_body = render_block("app/templates/emails.html", "PASSWORD_RESET", name=name, reset_url=reset_url)
    _fire_and_forget(_send_email, to_email, subject, html_body)





def send_otp_email(to_email: str, name: str, otp: str) -> None:
    # OTP email sent during login for users going through MFA
    subject = "Your HR Portal Login OTP"
    html_body = render_block("app/templates/emails.html", "OTP_LOGIN", name=name, otp=otp)
    _fire_and_forget(_send_email, to_email, subject, html_body)


def send_forgot_password_otp_email(to_email: str, name: str, otp: str) -> None:
    # Forgot-password OTP email — distinct from the login OTP so the user clearly
    # understands this code is for resetting their password, not for signing in.
    # OTP is valid for 5 minutes (same as login OTP).
    subject = "HR Portal — Password Reset OTP"
    html_body = render_block("app/templates/emails.html", "FORGOT_PASSWORD_OTP", name=name, otp=otp)
    _fire_and_forget(_send_email, to_email, subject, html_body)

