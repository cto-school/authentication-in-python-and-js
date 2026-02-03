# ================================================================================
# CHAPTER 12: Google OAuth 2.0 (Sign in with Google)
# ================================================================================
#
# This chapter implements "Sign in with Google" - the most common social login.
#
# WHAT YOU'LL LEARN:
#   1. OAuth 2.0 Authorization Code Flow
#   2. Setting up Google Cloud Console credentials
#   3. Redirecting users to Google's consent screen
#   4. Handling the OAuth callback
#   5. Exchanging authorization code for tokens
#   6. Fetching user info from Google
#   7. Creating/linking local accounts for OAuth users
#
# OAUTH 2.0 FLOW:
#   1. User clicks "Sign in with Google"
#   2. Your app redirects to Google's authorization URL
#   3. User logs into Google and approves access
#   4. Google redirects back to your callback URL with a CODE
#   5. Your backend exchanges the CODE for an ACCESS TOKEN
#   6. Your backend uses the token to fetch user info from Google
#   7. Create local account (if new) or log in (if exists)
#   8. Return your own JWT token to the frontend
#
# GOOGLE CLOUD SETUP (Do this before running):
#   1. Go to https://console.cloud.google.com/
#   2. Create a new project (or select existing)
#   3. Enable "Google+ API" or "Google People API"
#   4. Go to APIs & Services > Credentials
#   5. Create OAuth 2.0 Client ID (Web application)
#   6. Add authorized redirect URI: http://localhost:5012/auth/google/callback
#   7. Copy Client ID and Client Secret to .env
#
# ================================================================================

from flask import Flask, jsonify, request, redirect, g, send_file, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import secrets
import requests
from urllib.parse import urlencode
from datetime import datetime, timedelta
from functools import wraps
import os
import warnings

from dotenv import load_dotenv
load_dotenv()

warnings.filterwarnings('ignore', message='.*Query.get.*')

app = Flask(__name__)

# ================================================================================
# CORS (Cross-Origin Resource Sharing)
# ================================================================================
# CORS allows the frontend to make API requests from a different origin.
#
# supports_credentials=True is REQUIRED for OAuth because:
#   1. We use Flask sessions to store the OAuth 'state' parameter
#   2. Sessions use cookies, which require credentials support
#   3. Without this, the state verification will fail
#
# Note: When using supports_credentials=True, you cannot use wildcard (*) origins.
# In production, specify exact allowed origins.
# ================================================================================
CORS(app, supports_credentials=True)

# Session for OAuth state management
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_ch12.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ================================================================================
# CONFIGURATION
# ================================================================================

SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
BASE_URL = os.environ.get('BASE_URL', 'http://localhost:5012')

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')
GOOGLE_REDIRECT_URI = f"{BASE_URL}/auth/google/callback"

# Google OAuth URLs
GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth'
GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'
GOOGLE_USERINFO_URL = 'https://www.googleapis.com/oauth2/v2/userinfo'

db = SQLAlchemy(app)


# ================================================================================
# MODELS
# ================================================================================

class User(db.Model):
    """
    User model with OAuth support.

    OAuth users may have:
    - No password (if they only use Google login)
    - google_id to link their Google account
    - profile_picture from Google
    """
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=True)  # Nullable for OAuth-only users
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # OAuth fields
    google_id = db.Column(db.String(100), unique=True, nullable=True)
    auth_provider = db.Column(db.String(20), default='local')  # 'local', 'google', 'both'

    # Profile fields (populated from Google)
    name = db.Column(db.String(100), nullable=True)
    profile_picture = db.Column(db.String(500), nullable=True)

    # Email verification (auto-verified for Google users)
    is_verified = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'profile_picture': self.profile_picture,
            'auth_provider': self.auth_provider,
            'is_verified': self.is_verified,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }


# ================================================================================
# HELPER FUNCTIONS
# ================================================================================

def hash_password(password):
    return generate_password_hash(password)


def verify_password(plain, hashed):
    return check_password_hash(hashed, plain)


def create_token(user):
    return jwt.encode({
        'user_id': user.id,
        'email': user.email,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, SECRET_KEY, algorithm='HS256')


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'success': False, 'message': 'Token missing'}), 401
        try:
            parts = auth_header.split(' ')
            if len(parts) != 2 or parts[0] != 'Bearer':
                return jsonify({'success': False, 'message': 'Invalid token format'}), 401
            decoded = jwt.decode(parts[1], SECRET_KEY, algorithms=['HS256'])
            g.current_user = {'user_id': decoded['user_id'], 'email': decoded['email']}
        except jwt.ExpiredSignatureError:
            return jsonify({'success': False, 'message': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'success': False, 'message': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated


# ================================================================================
# ROUTES
# ================================================================================

@app.route('/')
def index():
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    return send_file(html_path)


@app.route('/config-status')
def config_status():
    """Check if Google OAuth is properly configured."""
    google_configured = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)
    return jsonify({
        'google_configured': google_configured,
        'google_client_id': GOOGLE_CLIENT_ID[:20] + '...' if GOOGLE_CLIENT_ID else None,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'message': 'Google OAuth configured!' if google_configured else 'Google OAuth not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.'
    })


# ================================================================================
# TRADITIONAL REGISTRATION & LOGIN
# ================================================================================

@app.route('/register', methods=['POST'])
def register():
    """Traditional email/password registration."""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    name = data.get('name', '')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password required'}), 400

    if len(password) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters'}), 400

    existing = User.query.filter_by(email=email).first()
    if existing:
        # Check if it's an OAuth-only account
        if existing.auth_provider == 'google' and not existing.password:
            # Allow adding password to Google account
            existing.password = hash_password(password)
            existing.auth_provider = 'both'
            if name:
                existing.name = name
            db.session.commit()
            return jsonify({
                'success': True,
                'message': 'Password added to your Google account. You can now login with either method.',
                'user': existing.to_dict()
            })
        return jsonify({'success': False, 'message': 'Email already registered'}), 400

    user = User(
        email=email,
        password=hash_password(password),
        name=name or email.split('@')[0],
        auth_provider='local',
        is_verified=False
    )
    db.session.add(user)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Registration successful',
        'user': user.to_dict(),
        'token': create_token(user)
    }), 201


@app.route('/login', methods=['POST'])
def login():
    """Traditional email/password login."""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Credentials required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

    # Check if user has a password (might be OAuth-only)
    if not user.password:
        return jsonify({
            'success': False,
            'message': 'This account uses Google Sign-In. Please use "Sign in with Google" or set a password.',
            'error': 'OAUTH_ONLY_ACCOUNT'
        }), 401

    if not verify_password(password, user.password):
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

    return jsonify({
        'success': True,
        'message': 'Login successful',
        'token': create_token(user),
        'user': user.to_dict()
    })


# ================================================================================
# GOOGLE OAUTH ROUTES
# ================================================================================

@app.route('/auth/google')
def google_login():
    """
    Step 1: Redirect user to Google's OAuth consent screen.

    We generate a random 'state' parameter to prevent CSRF attacks.
    Google will include this state in the callback, and we verify it.
    """
    if not GOOGLE_CLIENT_ID:
        return jsonify({
            'success': False,
            'message': 'Google OAuth not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.'
        }), 500

    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state

    # Build Google authorization URL
    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid email profile',
        'state': state,
        'access_type': 'offline',  # Get refresh token
        'prompt': 'consent'  # Always show consent screen (for demo)
    }

    auth_url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"

    # For API calls, return the URL; for browser, redirect
    if request.args.get('redirect') == 'false':
        return jsonify({'auth_url': auth_url})

    return redirect(auth_url)


@app.route('/auth/google/callback')
def google_callback():
    """
    Step 2: Handle Google's callback with authorization code.

    This is where Google redirects after user approves access.
    We exchange the code for tokens, then fetch user info.
    """
    # Check for errors from Google
    error = request.args.get('error')
    if error:
        return f'''
        <html><body style="font-family: Arial; text-align: center; padding: 50px;">
            <h1 style="color: #dc3545;">Authorization Failed</h1>
            <p>Error: {error}</p>
            <a href="/">Go back</a>
        </body></html>
        ''', 400

    # Get authorization code
    code = request.args.get('code')
    state = request.args.get('state')

    if not code:
        return jsonify({'success': False, 'message': 'No authorization code received'}), 400

    # Verify state to prevent CSRF
    stored_state = session.pop('oauth_state', None)
    if not stored_state or stored_state != state:
        return jsonify({'success': False, 'message': 'Invalid state parameter (CSRF protection)'}), 400

    # Exchange code for tokens
    token_data = exchange_code_for_tokens(code)
    if not token_data:
        return jsonify({'success': False, 'message': 'Failed to exchange authorization code'}), 500

    # Get user info from Google
    user_info = get_google_user_info(token_data['access_token'])
    if not user_info:
        return jsonify({'success': False, 'message': 'Failed to get user info from Google'}), 500

    # Create or update user in our database
    user = handle_google_user(user_info)

    # Create our own JWT token
    token = create_token(user)

    # Return HTML that passes token to frontend
    return f'''
    <html>
    <head><title>Login Successful</title></head>
    <body style="font-family: Arial; text-align: center; padding: 50px;">
        <h1 style="color: #28a745;">Login Successful!</h1>
        <p>Welcome, {user.name or user.email}!</p>
        <p>Redirecting...</p>
        <script>
            // Store token in localStorage
            localStorage.setItem('token', '{token}');
            localStorage.setItem('user', JSON.stringify({user.to_dict()}));

            // Redirect to main page
            setTimeout(() => {{
                window.location.href = '/';
            }}, 1500);
        </script>
    </body>
    </html>
    '''


def exchange_code_for_tokens(code):
    """
    Exchange authorization code for access token.

    This is a server-to-server request (code never exposed to browser).
    """
    try:
        response = requests.post(GOOGLE_TOKEN_URL, data={
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': GOOGLE_REDIRECT_URI
        }, timeout=10)

        if response.status_code == 200:
            return response.json()
        else:
            print(f"Token exchange error: {response.status_code} - {response.text}")
            return None

    except Exception as e:
        print(f"Token exchange exception: {e}")
        return None


def get_google_user_info(access_token):
    """
    Fetch user profile from Google using access token.
    """
    try:
        response = requests.get(
            GOOGLE_USERINFO_URL,
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=10
        )

        if response.status_code == 200:
            return response.json()
        else:
            print(f"User info error: {response.status_code} - {response.text}")
            return None

    except Exception as e:
        print(f"User info exception: {e}")
        return None


def handle_google_user(google_user):
    """
    Create or update local user from Google profile.

    Cases:
    1. New user (no matching email or google_id) → Create account
    2. Existing user by google_id → Login
    3. Existing user by email (local account) → Link Google account

    Google user info contains:
    - id: Google's unique user ID
    - email: User's email
    - name: Display name
    - picture: Profile picture URL
    - verified_email: Whether email is verified by Google
    """
    google_id = google_user.get('id')
    email = google_user.get('email', '').lower()
    name = google_user.get('name')
    picture = google_user.get('picture')

    # First, try to find by Google ID (returning user)
    user = User.query.filter_by(google_id=google_id).first()

    if user:
        # Update profile info from Google
        user.name = name or user.name
        user.profile_picture = picture or user.profile_picture
        db.session.commit()
        return user

    # Try to find by email (might be existing local account)
    user = User.query.filter_by(email=email).first()

    if user:
        # Link Google account to existing local account
        user.google_id = google_id
        user.name = name or user.name
        user.profile_picture = picture or user.profile_picture
        user.is_verified = True  # Google verified the email
        user.auth_provider = 'both' if user.password else 'google'
        db.session.commit()
        return user

    # Create new user
    user = User(
        email=email,
        google_id=google_id,
        name=name,
        profile_picture=picture,
        auth_provider='google',
        is_verified=True  # Google verified the email
    )
    db.session.add(user)
    db.session.commit()

    return user


# ================================================================================
# API ENDPOINT FOR GOOGLE LOGIN (SPA-friendly)
# ================================================================================

@app.route('/auth/google/url')
def get_google_auth_url():
    """
    Get Google authorization URL without redirecting.
    Useful for single-page applications (SPAs).
    """
    if not GOOGLE_CLIENT_ID:
        return jsonify({
            'success': False,
            'message': 'Google OAuth not configured'
        }), 500

    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state

    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid email profile',
        'state': state,
        'access_type': 'offline',
        'prompt': 'consent'
    }

    auth_url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"

    return jsonify({
        'success': True,
        'auth_url': auth_url
    })


# ================================================================================
# PROTECTED ROUTES
# ================================================================================

@app.route('/profile', methods=['GET'])
@token_required
def get_profile():
    user = User.query.get(g.current_user['user_id'])
    return jsonify({'success': True, 'profile': user.to_dict()})


@app.route('/profile', methods=['PUT'])
@token_required
def update_profile():
    """Update user profile."""
    data = request.get_json()
    user = User.query.get(g.current_user['user_id'])

    if 'name' in data:
        user.name = data['name']

    db.session.commit()

    return jsonify({'success': True, 'profile': user.to_dict()})


# ================================================================================
# KEY TAKEAWAYS
# ================================================================================
#
# 1. OAUTH 2.0 FLOW: Authorization Code flow is most secure for web apps.
#    - User approves on Google's site (not your site)
#    - You only receive a code, not the token
#    - Code is exchanged server-to-server (secret never exposed)
#
# 2. STATE PARAMETER: Always use random state for CSRF protection.
#    Store in session, verify on callback.
#
# 3. ACCOUNT LINKING: Handle three cases:
#    - New user → Create account
#    - Returning Google user → Login
#    - Existing email user → Link accounts
#
# 4. SCOPES: Request only what you need.
#    - 'openid' → Required for OIDC
#    - 'email' → User's email address
#    - 'profile' → Name, picture
#
# 5. SECURITY:
#    - Never expose client_secret to frontend
#    - Validate state parameter
#    - Use HTTPS in production
#
# ================================================================================
#
# TRY THIS:
#   1. Set up Google Cloud Console and get credentials
#   2. Click "Sign in with Google" and complete the flow
#   3. Check the database - see how Google user was created
#   4. Try linking: Register with email, then sign in with same email via Google
#
# EXERCISES:
#   1. Add "Sign in with GitHub" (similar OAuth flow)
#   2. Add ability to unlink Google account
#   3. Store Google refresh token and implement token refresh
#   4. Add profile picture display in frontend
#
# ================================================================================

with app.app_context():
    db.create_all()


if __name__ == '__main__':
    print("=" * 60)
    print("CHAPTER 12: Google OAuth 2.0")
    print("=" * 60)
    print(f"Server: http://localhost:5012")
    print("")
    print("Google OAuth:", "CONFIGURED" if GOOGLE_CLIENT_ID else "NOT CONFIGURED")
    if GOOGLE_CLIENT_ID:
        print(f"  Client ID: {GOOGLE_CLIENT_ID[:20]}...")
        print(f"  Redirect URI: {GOOGLE_REDIRECT_URI}")
    print("")
    print("Endpoints:")
    print("  GET  /auth/google          - Start Google OAuth flow")
    print("  GET  /auth/google/callback - OAuth callback (Google redirects here)")
    print("  GET  /auth/google/url      - Get auth URL (for SPAs)")
    print("  POST /register             - Traditional registration")
    print("  POST /login                - Traditional login")
    print("  GET  /profile              - Get user profile (protected)")
    print("=" * 60)
    app.run(debug=True, port=5012)
