# OAuth token verification helpers.
# Each function contacts the respective provider to validate the token and
# returns a normalised dict so the auth router doesn't need to know provider details.

import requests as http_requests
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token

from app.config import settings


def verify_google_token(token: str) -> dict:
    """
    Verifies a Google ID token received from the frontend (Google Sign-In SDK).
    Returns normalised user info on success; raises ValueError on failure.

    Return shape: {"email": str, "name": str, "google_id": str}
    """
    data = id_token.verify_oauth2_token(
        token,
        google_requests.Request(),
        settings.GOOGLE_CLIENT_ID,
    )
    return {
        "email": data["email"],
        "name": data.get("name", ""),
        "google_id": data["sub"],           # "sub" is Google's stable user identifier
    }


def get_microsoft_user_info(access_token: str) -> dict:
    """
    Calls the Microsoft Graph /me endpoint with the access token to fetch user profile.
    Returns normalised user info on success; raises ValueError on failure.

    Return shape: {"email": str, "name": str, "microsoft_id": str}
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    response = http_requests.get(
        "https://graph.microsoft.com/v1.0/me",
        headers=headers,
        timeout=10,
    )
    if not response.ok:
        raise ValueError(f"Microsoft Graph error: {response.text}")

    data = response.json()
    email = data.get("mail") or data.get("userPrincipalName", "")
    return {
        "email": email,
        "name": data.get("displayName", ""),
        "microsoft_id": data["id"],         # stable OID from Microsoft
    }
