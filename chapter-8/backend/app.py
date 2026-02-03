# ================================================================================
# CHAPTER 8: Refresh Tokens
# ================================================================================
#
# This chapter covers the industry-standard two-token pattern:
#
#   ACCESS TOKEN  - Short-lived (15 min), used for API calls
#   REFRESH TOKEN - Long-lived (7 days), used ONLY to get new access tokens
#
# WHY TWO TOKENS?
#   - Short access token = less damage if stolen
#   - Long refresh token = good UX (no constant re-login)
#   - Refresh token can be revoked (logout)
#
# ================================================================================

from flask import Flask, jsonify, request, g, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import uuid  # For generating unique token IDs (jti)
from datetime import datetime, timedelta
from functools import wraps
import os
import warnings
warnings.filterwarnings('ignore', message='.*Query.get.*')

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_ch8.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
SECRET_KEY = 'your-secret-key-keep-it-safe-123'

# Token lifetimes
ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
REFRESH_TOKEN_EXPIRES = timedelta(days=7)

db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def to_dict(self):
        return {'id': self.id, 'email': self.email}


class TokenBlacklist(db.Model):
    """Stores revoked refresh tokens by their jti (token ID)."""
    __tablename__ = 'token_blacklist'
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), unique=True, nullable=False)
    revoked_at = db.Column(db.DateTime, default=datetime.utcnow)


def hash_password(password):
    return generate_password_hash(password)


def verify_password(plain, hashed):
    return check_password_hash(hashed, plain)


def create_access_token(user):
    """Short-lived token for API calls."""
    return jwt.encode({
        'user_id': user.id,
        'email': user.email,
        'type': 'access',
        'exp': datetime.utcnow() + ACCESS_TOKEN_EXPIRES
    }, SECRET_KEY, algorithm='HS256')


def create_refresh_token(user):
    """Long-lived token for getting new access tokens."""
    return jwt.encode({
        'user_id': user.id,
        'type': 'refresh',
        'jti': str(uuid.uuid4()),  # Unique ID for blacklisting
        'exp': datetime.utcnow() + REFRESH_TOKEN_EXPIRES
    }, SECRET_KEY, algorithm='HS256')


def is_token_blacklisted(jti):
    return TokenBlacklist.query.filter_by(jti=jti).first() is not None


def access_token_required(f):
    """Decorator requiring valid ACCESS token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'success': False, 'message': 'Token missing'}), 401
        try:
            parts = auth_header.split(' ')
            if len(parts) != 2 or parts[0] != 'Bearer':
                return jsonify({'success': False, 'message': 'Invalid format'}), 401

            decoded = jwt.decode(parts[1], SECRET_KEY, algorithms=['HS256'])

            if decoded.get('type') != 'access':
                return jsonify({'success': False, 'message': 'Use access token'}), 401

            g.current_user = {'user_id': decoded['user_id'], 'email': decoded['email']}

        except jwt.ExpiredSignatureError:
            return jsonify({'success': False, 'message': 'Token expired', 'error': 'TOKEN_EXPIRED'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'success': False, 'message': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated


@app.route('/')
def index():
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    return send_file(html_path)


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': 'Email exists'}), 400

    user = User(email=email, password=hash_password(password))
    db.session.add(user)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Registered', 'user': user.to_dict()}), 201


@app.route('/login', methods=['POST'])
def login():
    """Returns BOTH access and refresh tokens."""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Credentials required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not verify_password(password, user.password):
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

    return jsonify({
        'success': True,
        'message': 'Login successful',
        'access_token': create_access_token(user),
        'refresh_token': create_refresh_token(user),
        'expires_in': int(ACCESS_TOKEN_EXPIRES.total_seconds()),
        'user': user.to_dict()
    })


@app.route('/refresh', methods=['POST'])
def refresh():
    """Get new access token using refresh token."""
    data = request.get_json()
    refresh_token = data.get('refresh_token')

    if not refresh_token:
        return jsonify({'success': False, 'message': 'Refresh token required'}), 400

    try:
        decoded = jwt.decode(refresh_token, SECRET_KEY, algorithms=['HS256'])

        if decoded.get('type') != 'refresh':
            return jsonify({'success': False, 'message': 'Use refresh token'}), 401

        jti = decoded.get('jti')
        if is_token_blacklisted(jti):
            return jsonify({'success': False, 'message': 'Token revoked'}), 401

        user = User.query.get(decoded['user_id'])
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404

        return jsonify({
            'success': True,
            'message': 'Token refreshed',
            'access_token': create_access_token(user),
            'expires_in': int(ACCESS_TOKEN_EXPIRES.total_seconds())
        })

    except jwt.ExpiredSignatureError:
        return jsonify({'success': False, 'message': 'Refresh token expired. Login again.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'success': False, 'message': 'Invalid refresh token'}), 401


@app.route('/logout', methods=['POST'])
def logout():
    """Revoke refresh token by adding jti to blacklist."""
    data = request.get_json()
    refresh_token = data.get('refresh_token')

    if not refresh_token:
        return jsonify({'success': False, 'message': 'Refresh token required'}), 400

    try:
        decoded = jwt.decode(refresh_token, SECRET_KEY, algorithms=['HS256'])
        jti = decoded.get('jti')

        if is_token_blacklisted(jti):
            return jsonify({'success': True, 'message': 'Already logged out'})

        db.session.add(TokenBlacklist(jti=jti))
        db.session.commit()

        return jsonify({'success': True, 'message': 'Logged out'})

    except jwt.ExpiredSignatureError:
        return jsonify({'success': True, 'message': 'Token already expired'})
    except jwt.InvalidTokenError:
        return jsonify({'success': False, 'message': 'Invalid token'}), 400


@app.route('/profile', methods=['GET'])
@access_token_required
def get_profile():
    user = User.query.get(g.current_user['user_id'])
    return jsonify({'success': True, 'profile': user.to_dict()})


with app.app_context():
    db.create_all()


# ================================================================================
# KEY TAKEAWAYS - Chapter 8
# ================================================================================
#
# 1. TWO-TOKEN PATTERN (Industry Standard):
#    ACCESS TOKEN  - Short-lived (15 min), used for every API call
#    REFRESH TOKEN - Long-lived (7 days), used ONLY to get new access tokens
#
# 2. WHY TWO TOKENS?
#    - Short access token = less damage if stolen (expires quickly)
#    - Long refresh token = good UX (user doesn't re-login constantly)
#    - Refresh token can be revoked = proper logout!
#
# 3. TOKEN BLACKLISTING with JTI:
#    - jti = JWT ID (unique identifier for each token)
#    - On logout, we add the jti to a blacklist table
#    - Before accepting a refresh token, check if jti is blacklisted
#    - This allows TRUE logout (not just deleting from frontend)
#
# 4. TYPE FIELD IN TOKENS:
#    Access token has: type: 'access'
#    Refresh token has: type: 'refresh'
#    Server checks type to prevent using wrong token on wrong endpoint.
#
# 5. FRONTEND: Two tokens stored separately!
#    localStorage.setItem('access_token', data.access_token);
#    localStorage.setItem('refresh_token', data.refresh_token);
#
#    TRY THIS - Check both tokens in localStorage:
#    - Login in the browser
#    - Open Developer Tools (F12) → "Application" tab
#    - Click "Local Storage" → "http://localhost:5008"
#    - You'll see TWO entries:
#      • access_token: eyJ... (short-lived)
#      • refresh_token: eyJ... (long-lived)
#
# 6. FRONTEND: Auto-refresh pattern (production apps do this):
#    async function apiCall(url) {
#        let res = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` }});
#        if (res.status === 401) {          // Access token expired!
#            await refreshAccessToken();     // Get new one using refresh token
#            res = await fetch(url, ...);   // Retry the original request
#        }
#        return res;
#    }
#
# 7. TRY THIS - Test the full flow:
#    - Login and get both tokens (check localStorage)
#    - Click "GET /profile" → works
#    - Click "Logout" → refresh token is blacklisted on server
#    - Check localStorage → both tokens are removed
#    - Try "Refresh Access Token" → "Token revoked" (server rejected it!)
#    - This is TRUE logout - even if attacker saved the token, it won't work!
#
# NEXT CHAPTER: Role-based access control (admin vs regular users).
#
# ================================================================================


# ================================================================================
# EXERCISES - Test Your Understanding!
# ================================================================================
#
# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 1: Token Expiry Info Endpoint (Easy)
# ────────────────────────────────────────────────────────────────────────────────
# Create an endpoint GET /token-expiry that:
# - Requires access token
# - Returns how much time is left before the access token expires
#
# Test: curl http://localhost:5008/token-expiry \
#       -H "Authorization: Bearer eyJ..."
#
# Expected: {
#   "expires_at": "2024-01-15 10:45:00",
#   "seconds_remaining": 543,
#   "is_expired": false
# }
#
# HINT: The exp is already in g.current_user from the token decode
#       Actually, you need to decode the token again to get exp, or modify
#       access_token_required to also store exp in g.current_user
# ────────────────────────────────────────────────────────────────────────────────

# YOUR CODE HERE:
# @app.route('/token-expiry', methods=['GET'])
# @access_token_required
# def token_expiry():
#     pass


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 2: Logout All Sessions (Medium)
# ────────────────────────────────────────────────────────────────────────────────
# Create an endpoint POST /logout-all that:
# - Requires access token to identify the user
# - Blacklists ALL refresh tokens for this user (not just one)
# - Returns count of tokens revoked
#
# This is useful for "logout from all devices" feature.
#
# To implement this, you need to track which refresh tokens belong to which user.
# HINT: Add user_id field to TokenBlacklist, or create a separate UserTokens table
#
# Test: Login from multiple "devices" (just call /login multiple times)
#       Call /logout-all
#       Try to refresh any of the old tokens → all should fail
#
# Expected: {"success": true, "message": "Logged out from all devices", "sessions_revoked": 3}
# ────────────────────────────────────────────────────────────────────────────────

# YOUR CODE HERE (you'll need to modify the models too):
# @app.route('/logout-all', methods=['POST'])
# @access_token_required
# def logout_all():
#     pass


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 3: Active Sessions List (Hard)
# ────────────────────────────────────────────────────────────────────────────────
# Track and list active sessions for a user:
# - Create an ActiveSession model (user_id, jti, created_at, last_used, device_info)
# - On login, create a session record
# - On refresh, update last_used
# - On logout, delete the session
# - Create GET /sessions endpoint to list all active sessions
#
# Test: Login multiple times, call GET /sessions
#
# Expected: {
#   "sessions": [
#     {"jti": "abc...", "created_at": "...", "last_used": "...", "device": "..."},
#     {"jti": "def...", "created_at": "...", "last_used": "...", "device": "..."}
#   ]
# }
#
# HINT: You can get device info from request.user_agent.string
# ────────────────────────────────────────────────────────────────────────────────


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 4: Refresh Token Rotation (Hard)
# ────────────────────────────────────────────────────────────────────────────────
# Implement refresh token rotation for extra security:
# - When /refresh is called, issue a NEW refresh token too (not just new access)
# - Blacklist the old refresh token
# - This way, if a refresh token is stolen, it can only be used once
#
# Modify the /refresh endpoint to return both new access AND new refresh tokens.
#
# Test: Call /refresh, get new tokens, try to use OLD refresh token → should fail
#
# Expected /refresh response: {
#   "success": true,
#   "access_token": "new_access...",
#   "refresh_token": "new_refresh...",  // ← This is new!
#   "note": "Old refresh token has been revoked"
# }
# ────────────────────────────────────────────────────────────────────────────────


# ================================================================================


if __name__ == '__main__':
    print("=" * 60)
    print("CHAPTER 8: Refresh Tokens")
    print("=" * 60)
    print(f"Access Token:  {ACCESS_TOKEN_EXPIRES}")
    print(f"Refresh Token: {REFRESH_TOKEN_EXPIRES}")
    print("Server: http://localhost:5008")
    print("=" * 60)
    app.run(debug=True, port=5008)
