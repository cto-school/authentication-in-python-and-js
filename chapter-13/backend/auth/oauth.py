# ================================================================================
# OAuth Service (Google)
# ================================================================================
# Handles Google OAuth 2.0 authentication.
# ================================================================================

import secrets
import requests
from urllib.parse import urlencode
from flask import current_app, session
from typing import Optional, Dict, Any

# Google OAuth URLs
GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth'
GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'
GOOGLE_USERINFO_URL = 'https://www.googleapis.com/oauth2/v2/userinfo'


def get_google_auth_url() -> Optional[str]:
    """
    Generate Google OAuth authorization URL.

    Returns None if Google OAuth is not configured.
    """
    client_id = current_app.config.get('GOOGLE_CLIENT_ID')
    if not client_id:
        return None

    base_url = current_app.config.get('BASE_URL', 'http://localhost:5013')
    redirect_uri = f"{base_url}/auth/google/callback"

    # Generate and store state for CSRF protection
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state

    params = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': 'openid email profile',
        'state': state,
        'access_type': 'offline',
        'prompt': 'consent'
    }

    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"


def verify_oauth_state(state: str) -> bool:
    """Verify OAuth state parameter to prevent CSRF."""
    stored_state = session.pop('oauth_state', None)
    return stored_state and stored_state == state


def exchange_code_for_tokens(code: str) -> Optional[Dict[str, Any]]:
    """Exchange authorization code for access token."""
    client_id = current_app.config.get('GOOGLE_CLIENT_ID')
    client_secret = current_app.config.get('GOOGLE_CLIENT_SECRET')
    base_url = current_app.config.get('BASE_URL', 'http://localhost:5013')
    redirect_uri = f"{base_url}/auth/google/callback"

    try:
        response = requests.post(GOOGLE_TOKEN_URL, data={
            'client_id': client_id,
            'client_secret': client_secret,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri
        }, timeout=10)

        if response.status_code == 200:
            return response.json()

        current_app.logger.error(f"Token exchange error: {response.status_code}")
        return None

    except Exception as e:
        current_app.logger.error(f"Token exchange exception: {e}")
        return None


def get_google_user_info(access_token: str) -> Optional[Dict[str, Any]]:
    """Fetch user profile from Google."""
    try:
        response = requests.get(
            GOOGLE_USERINFO_URL,
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=10
        )

        if response.status_code == 200:
            return response.json()

        current_app.logger.error(f"User info error: {response.status_code}")
        return None

    except Exception as e:
        current_app.logger.error(f"User info exception: {e}")
        return None


def is_google_configured() -> bool:
    """Check if Google OAuth is configured."""
    return bool(
        current_app.config.get('GOOGLE_CLIENT_ID') and
        current_app.config.get('GOOGLE_CLIENT_SECRET')
    )
