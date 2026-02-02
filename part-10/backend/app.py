# ================================================================================
# PART 10: REFRESH TOKENS - Better Token Management
# ================================================================================
#
# This part solves a problem with simple JWT auth:
#   - Short-lived tokens (15 min) = secure but annoying (constant re-login)
#   - Long-lived tokens (24h+) = convenient but risky (if stolen, attacker has long access)
#
# SOLUTION: Two types of tokens
#   1. ACCESS TOKEN  - Short-lived (15 min), used for API calls
#   2. REFRESH TOKEN - Long-lived (7 days), used ONLY to get new access tokens
#
# HOW IT WORKS:
#   1. User logs in → Gets both access_token AND refresh_token
#   2. User makes API calls with access_token (valid 15 min)
#   3. Access token expires → Frontend calls /refresh with refresh_token
#   4. Server returns new access_token (no re-login needed!)
#   5. Refresh token expires → User must login again
#
# WHY IS THIS MORE SECURE?
#   - If access_token is stolen, attacker has only 15 minutes
#   - Refresh token is sent less frequently (only to /refresh endpoint)
#   - Refresh token can be revoked (logout) via blacklist
#
# NEW CONCEPTS IN THIS PART:
#   - uuid module for generating unique token IDs (jti)
#   - Token blacklist for logout
#   - Different token types (access vs refresh)
#
# ================================================================================

from flask import Flask, jsonify, request, g, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
# Password hashing using werkzeug.security (comes built-in with Flask)
from werkzeug.security import generate_password_hash, check_password_hash
import jwt  # From 'pyjwt' package (pip install pyjwt), NOT 'jwt'
# ================================================================================
# uuid module - Universally Unique Identifiers
# ================================================================================
# uuid.uuid4() generates a random UUID like: "550e8400-e29b-41d4-a716-446655440000"
#
# We use this for 'jti' (JWT ID) claim - a unique identifier for each token.
# Why?
#   - We can blacklist specific tokens by their jti (for logout)
#   - We don't store the entire token in the blacklist (just 36-char jti)
#   - Each token is uniquely identifiable
#
# UUID4 is random, so it's practically impossible to guess or collide.
# ================================================================================
import uuid
from datetime import datetime, timedelta
from functools import wraps
import os

app = Flask(__name__)
CORS(app)


@app.route('/')  # Serve the frontend HTML
def index():
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    return send_file(html_path)


@app.route('/index.html')  # Also serve index.html for direct links
def index_html():
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    return send_file(html_path)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_new.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
SECRET_KEY = 'your-secret-key-keep-it-safe'

# ================================================================================
# TOKEN EXPIRATION TIMES
# ================================================================================
# These values represent a common production pattern:
#
# ACCESS_TOKEN: 15 minutes
#   - Short enough to limit damage if stolen
#   - Long enough that users don't notice refreshes happening
#
# REFRESH_TOKEN: 7 days
#   - Long enough for "remember me" functionality
#   - User stays logged in for a week without re-entering password
#   - Can be made shorter (1 day) or longer (30 days) based on security needs
#
# For testing, you might want to use shorter times:
#   ACCESS_TOKEN_EXPIRES = timedelta(seconds=30)
#   REFRESH_TOKEN_EXPIRES = timedelta(minutes=5)
# ================================================================================
ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
REFRESH_TOKEN_EXPIRES = timedelta(days=7)

db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {'id': self.id, 'email': self.email}


# ================================================================================
# TOKEN BLACKLIST MODEL
# ================================================================================
# This table stores revoked (logged out) refresh tokens.
#
# Why a blacklist?
#   JWTs are stateless - the server doesn't remember issued tokens.
#   To "logout", we need to remember which tokens are NO LONGER valid.
#
# Why store only 'jti' (token ID)?
#   - jti is just 36 characters (UUID)
#   - Full token could be 200+ characters
#   - Saves database space
#   - jti is unique, so it's perfect for lookup
#
# Database structure:
#   +----+--------------------------------------+---------------------+
#   | id | jti                                  | revoked_at          |
#   +----+--------------------------------------+---------------------+
#   | 1  | 550e8400-e29b-41d4-a716-446655440000 | 2024-01-15 10:30:00 |
#   | 2  | 6ba7b810-9dad-11d1-80b4-00c04fd430c8 | 2024-01-15 11:45:00 |
#   +----+--------------------------------------+---------------------+
#
# When checking if token is valid:
#   1. Decode the token to get jti
#   2. Check if jti exists in blacklist
#   3. If yes → token is revoked, deny access
# ================================================================================


class TokenBlacklist(db.Model):
    __tablename__ = 'token_blacklist'
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), unique=True, nullable=False)  # UUID is 36 chars
    revoked_at = db.Column(db.DateTime, default=datetime.utcnow)


# Hash password - converts plain text to secure hash
def hash_password(password):
    return generate_password_hash(password)


# Verify password - compares plain password with stored hash
def check_password(password, hashed_password):
    return check_password_hash(hashed_password, password)


# ================================================================================
# TOKEN CREATION FUNCTIONS
# ================================================================================
# We now have TWO different token types with different purposes and lifetimes.
#
# ACCESS TOKEN payload:
#   {
#       "user_id": 1,
#       "email": "user@example.com",
#       "type": "access",          ← Identifies token type
#       "exp": 1705312800          ← Expires in 15 minutes
#   }
#
# REFRESH TOKEN payload:
#   {
#       "user_id": 1,
#       "type": "refresh",         ← Identifies token type
#       "jti": "550e8400-...",     ← Unique ID for blacklisting
#       "exp": 1705917600          ← Expires in 7 days
#   }
#
# Notice: Refresh token doesn't include email (not needed for refresh operation)
# ================================================================================


def create_access_token(user):
    """
    Create a SHORT-LIVED access token for API calls.

    - Used for: Authorization header in API requests
    - Lifetime: 15 minutes
    - Contains: user_id, email (for display), type identifier
    """
    payload = {
        'user_id': user.id,
        'email': user.email,
        'type': 'access',  # Identifies this as an access token
        'exp': datetime.utcnow() + ACCESS_TOKEN_EXPIRES
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


def create_refresh_token(user):
    """
    Create a LONG-LIVED refresh token for getting new access tokens.

    - Used for: Only the /refresh endpoint
    - Lifetime: 7 days
    - Contains: user_id, jti (for blacklisting), type identifier
    - jti (JWT ID): Unique identifier using UUID4
    """
    payload = {
        'user_id': user.id,
        'type': 'refresh',  # Identifies this as a refresh token
        'jti': str(uuid.uuid4()),  # Unique ID for this specific token
        'exp': datetime.utcnow() + REFRESH_TOKEN_EXPIRES
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


def is_token_blacklisted(jti):
    """Check if a refresh token has been revoked (user logged out)."""
    return TokenBlacklist.query.filter_by(jti=jti).first() is not None


# ================================================================================
# ACCESS TOKEN DECORATOR
# ================================================================================
# This decorator now specifically checks for ACCESS tokens (type='access').
# If someone tries to use a refresh token for API calls, it will be rejected.
#
# Important: On TOKEN_EXPIRED error, frontend should:
#   1. Call /refresh with stored refresh_token
#   2. Get new access_token
#   3. Retry the original request
# ================================================================================


def access_token_required(f):
    """Decorator to require valid ACCESS token (not refresh token)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')

        if not auth_header:
            return jsonify({'message': 'Access token is missing!'}), 401

        try:
            parts = auth_header.split(' ')
            if len(parts) != 2 or parts[0] != 'Bearer':
                return jsonify({'message': 'Invalid token format!'}), 401

            token = parts[1]
            decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

            # IMPORTANT: Verify this is an ACCESS token, not a refresh token
            # Prevents someone from using refresh token for API calls
            if decoded.get('type') != 'access':
                return jsonify({'message': 'Invalid token type! Use access token.'}), 401

            g.current_user = {'user_id': decoded['user_id'], 'email': decoded['email']}

        except jwt.ExpiredSignatureError:
            # Return special error code so frontend knows to refresh
            return jsonify({
                'message': 'Access token has expired!',
                'error': 'TOKEN_EXPIRED'  # Frontend can check this code
            }), 401

        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401

        return f(*args, **kwargs)
    return decorated


@app.route('/register', methods=['POST'])  # Register endpoint
def register():
    data = request.get_json()  # Get JSON data
    email, password = data.get('email'), data.get('password')  # Get credentials

    if not email or not password:  # Validate input
        return jsonify({'message': 'Email and password are required!'}), 400

    if User.query.filter_by(email=email).first():  # Check email exists
        return jsonify({'message': 'Email already exists!'}), 400

    new_user = User(email=email, password=hash_password(password))  # Create user
    db.session.add(new_user)  # Add to session
    db.session.commit()  # Save to database

    return jsonify({'message': 'User registered successfully!', 'user': new_user.to_dict()}), 201


# ================================================================================
# LOGIN - Returns BOTH Access and Refresh Tokens
# ================================================================================
# On successful login, user receives:
#   - access_token: For API calls (short-lived)
#   - refresh_token: For getting new access tokens (long-lived)
#   - expires_in: Seconds until access token expires (frontend can set timer)
#
# Frontend should:
#   1. Store access_token in memory (NOT localStorage for security)
#   2. Store refresh_token in httpOnly cookie (if possible) or localStorage
#   3. Use access_token for all API calls
#   4. When access_token expires, use refresh_token to get a new one
# ================================================================================


@app.route('/login', methods=['POST'])
def login():
    """Login and receive both access and refresh tokens."""
    data = request.get_json()
    email, password = data.get('email'), data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required!'}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not check_password(password, user.password):
        return jsonify({'message': 'Invalid email or password!'}), 401

    # Create both tokens
    access_token = create_access_token(user)
    refresh_token = create_refresh_token(user)

    return jsonify({
        'message': 'Login successful!',
        'access_token': access_token,    # Use this for API calls
        'refresh_token': refresh_token,  # Store securely, use to refresh
        'expires_in': int(ACCESS_TOKEN_EXPIRES.total_seconds()),  # e.g., 900 (15 min)
        'user': user.to_dict()
    })


# ================================================================================
# REFRESH ENDPOINT - Get New Access Token
# ================================================================================
# This is the "magic" of refresh tokens:
#   - User doesn't need to re-enter password
#   - Just sends refresh_token, gets new access_token
#
# Security checks:
#   1. Is the token a refresh token (type='refresh')?
#   2. Is the token blacklisted (user logged out)?
#   3. Does the user still exist?
#
# Flow:
#   Frontend detects TOKEN_EXPIRED error
#     → Calls POST /refresh with refresh_token
#     → Gets new access_token
#     → Retries original request with new token
# ================================================================================


@app.route('/refresh', methods=['POST'])
def refresh():
    """Get a new access token using a valid refresh token."""
    data = request.get_json()
    refresh_token = data.get('refresh_token')

    if not refresh_token:
        return jsonify({'message': 'Refresh token is required!'}), 400

    try:
        decoded = jwt.decode(refresh_token, SECRET_KEY, algorithms=['HS256'])

        # Verify this is a refresh token, not an access token
        if decoded.get('type') != 'refresh':
            return jsonify({'message': 'Invalid token type! Use refresh token.'}), 401

        # Check if token has been revoked (user logged out)
        jti = decoded.get('jti')
        if is_token_blacklisted(jti):
            return jsonify({'message': 'Token has been revoked. Please login again.'}), 401

        # Verify user still exists (might have been deleted)
        user = User.query.get(decoded['user_id'])
        if not user:
            return jsonify({'message': 'User not found!'}), 404

        # All checks passed - issue new access token
        new_access_token = create_access_token(user)

        return jsonify({
            'message': 'Token refreshed!',
            'access_token': new_access_token,
            'expires_in': int(ACCESS_TOKEN_EXPIRES.total_seconds())
        })

    except jwt.ExpiredSignatureError:
        # Refresh token itself has expired - user must login again
        return jsonify({'message': 'Refresh token has expired. Please login again.'}), 401

    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid refresh token!'}), 401


# ================================================================================
# LOGOUT - Revoke Refresh Token
# ================================================================================
# "Logging out" with JWTs means blacklisting the refresh token.
#
# Why blacklist refresh token and not access token?
#   - Access token expires in 15 min anyway
#   - We can't really invalidate access tokens (stateless)
#   - Blacklisting refresh token prevents getting NEW access tokens
#
# After logout:
#   - Current access token still works until it expires (max 15 min)
#   - Refresh token is immediately invalid
#   - User cannot get new access tokens
#   - For immediate invalidation of access tokens, you'd need a different approach
#     (like storing all access tokens in Redis and checking on each request)
# ================================================================================


@app.route('/logout', methods=['POST'])
def logout():
    """Logout by blacklisting the refresh token."""
    data = request.get_json()
    refresh_token = data.get('refresh_token')

    if not refresh_token:
        return jsonify({'message': 'Refresh token is required!'}), 400

    try:
        decoded = jwt.decode(refresh_token, SECRET_KEY, algorithms=['HS256'])
        jti = decoded.get('jti')

        # Check if already logged out
        if is_token_blacklisted(jti):
            return jsonify({'message': 'Already logged out!'})

        # Add to blacklist
        blacklist_entry = TokenBlacklist(jti=jti)
        db.session.add(blacklist_entry)
        db.session.commit()

        return jsonify({'message': 'Logged out successfully!'})

    except jwt.ExpiredSignatureError:
        # Token already expired - no need to blacklist
        return jsonify({'message': 'Token already expired!'})

    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token!'}), 400


@app.route('/profile', methods=['GET'])  # Protected route - requires access token
@access_token_required
def get_profile():
    user = User.query.get(g.current_user['user_id'])  # Get user

    if not user:  # User not found
        return jsonify({'message': 'User not found!'}), 404

    return jsonify({'message': 'Profile retrieved!', 'profile': user.to_dict()})


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    print("=" * 50)
    print("Refresh Token Server Running on http://localhost:5010")
    print(f"Access Token Expires: {ACCESS_TOKEN_EXPIRES}")
    print(f"Refresh Token Expires: {REFRESH_TOKEN_EXPIRES}")
    print("=" * 50)
    app.run(debug=True, port=5010)


# ===========================================
# EXERCISES - Try These!
# ===========================================
"""
EXERCISE 1: Test Token Expiration
---------------------------------
Change access token to expire in 30 seconds:
    ACCESS_TOKEN_EXPIRES = timedelta(seconds=30)

Test:
1. Login and get tokens
2. Immediately call /profile (works)
3. Wait 30+ seconds
4. Call /profile again (should fail with TOKEN_EXPIRED)
5. Call /refresh with refresh_token (should get new access token)
6. Call /profile again (works!)

Question: Why use short-lived access tokens + long-lived refresh tokens?


EXERCISE 2: Test Logout/Blacklist
---------------------------------
Test:
1. Login and save the refresh_token
2. Call /refresh (works - get new access token)
3. Call /logout with refresh_token
4. Try /refresh with SAME refresh_token (should fail!)

Question: Why do we blacklist the jti (token ID) instead of the whole token?


EXERCISE 3: Add "Logout All Devices"
------------------------------------
Store refresh tokens in database to allow revoking all:

1. Create new model:
    class RefreshToken(db.Model):
        __tablename__ = 'refresh_tokens'
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, nullable=False)
        jti = db.Column(db.String(36), unique=True, nullable=False)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)

2. When creating refresh token, save to database
3. Add endpoint to revoke all:
    @app.route('/logout-all', methods=['POST'])
    @access_token_required
    def logout_all():
        user_id = g.current_user['user_id']
        tokens = RefreshToken.query.filter_by(user_id=user_id).all()
        for token in tokens:
            if not is_token_blacklisted(token.jti):
                db.session.add(TokenBlacklist(jti=token.jti))
        db.session.commit()
        return jsonify({'message': 'Logged out from all devices!'})

Question: When would a user want to logout from all devices?


EXERCISE 4: Token Rotation
--------------------------
Issue a new refresh token each time /refresh is called:

In the refresh() route, after creating new access token:
    # Blacklist old refresh token
    db.session.add(TokenBlacklist(jti=jti))

    # Create new refresh token
    new_refresh_token = create_refresh_token(user)

    return jsonify({
        'access_token': new_access_token,
        'refresh_token': new_refresh_token,  # New refresh token
        'expires_in': int(ACCESS_TOKEN_EXPIRES.total_seconds())
    })

Question: Why is token rotation more secure? What's the downside?


EXERCISE 5: Clean Up Expired Blacklist Entries
----------------------------------------------
Blacklist table grows forever. Add cleanup:

@app.route('/admin/cleanup-blacklist', methods=['POST'])
def cleanup_blacklist():
    # Delete blacklist entries older than refresh token lifetime
    cutoff = datetime.utcnow() - REFRESH_TOKEN_EXPIRES
    old_entries = TokenBlacklist.query.filter(TokenBlacklist.revoked_at < cutoff).all()
    count = len(old_entries)
    for entry in old_entries:
        db.session.delete(entry)
    db.session.commit()
    return jsonify({'message': f'Cleaned up {count} old blacklist entries'})

Question: Why is it safe to delete old blacklist entries?
(Hint: What happens if the original token is already expired?)


SELF-STUDY QUESTIONS
--------------------
1. What is the purpose of having two types of tokens (access vs refresh)?

2. Why store jti (token ID) in blacklist instead of the whole token?

3. What is "token rotation" and why is it more secure?

4. Where should the frontend store refresh tokens? (Hint: httpOnly cookies vs localStorage)

5. What happens if someone steals your refresh token? How can you protect against this?
"""
