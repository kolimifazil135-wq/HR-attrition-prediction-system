# Loads environment variables from .env and exposes them as typed settings.
# Import `settings` anywhere in the app to access config values.

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str
    SMTP_PASSWORD: str

    API_BASE_URL: str = "http://localhost:8000"
    FRONTEND_BASE_URL: str = "http://localhost:3000"

    # ── Google OAuth ──────────────────────────────────────
    # Get from https://console.cloud.google.com → Credentials → OAuth 2.0 Client IDs
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""

    # ── Microsoft OAuth ───────────────────────────────────
    # Get from https://portal.azure.com → App registrations
    MICROSOFT_CLIENT_ID: str = ""
    MICROSOFT_CLIENT_SECRET: str = ""
    MICROSOFT_TENANT_ID: str = "common"     # Use "common" to allow any MS account, or your tenant GUID
    MICROSOFT_REDIRECT_URI: str = "http://localhost:8000/auth/microsoft/callback"

    @property
    def MICROSOFT_AUTH_URL(self) -> str:
        return f"https://login.microsoftonline.com/{self.MICROSOFT_TENANT_ID}/oauth2/v2.0/authorize"

    @property
    def MICROSOFT_TOKEN_URL(self) -> str:
        return f"https://login.microsoftonline.com/{self.MICROSOFT_TENANT_ID}/oauth2/v2.0/token"

    class Config:
        env_file = ".env"


settings = Settings()
