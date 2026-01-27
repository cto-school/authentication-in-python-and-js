from flask import Flask, jsonify, request, g, send_file  # Flask framework
from flask_cors import CORS  # Cross-origin requests
from flask_sqlalchemy import SQLAlchemy  # Database ORM
import bcrypt  # Password hashing
import jwt  # JWT tokens
import uuid  # For generating unique token IDs (jti)
from datetime import datetime, timedelta  # Date/time
from functools import wraps  # Decorator helper
import os  # For file paths

app = Flask(__name__)  # Create Flask app
CORS(app)  # Enable CORS


@app.route('/')  # Serve the frontend HTML
def index():
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    return send_file(html_path)


@app.route('/index.html')  # Also serve index.html for direct links
def index_html():
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    return send_file(html_path)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable tracking
SECRET_KEY = 'your-secret-key-keep-it-safe'  # JWT secret

ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)  # Access token: short-lived (15 min)
REFRESH_TOKEN_EXPIRES = timedelta(days=7)  # Refresh token: long-lived (7 days)

db = SQLAlchemy(app)  # Database instance


class User(db.Model):  # User model
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)  # Primary key
    email = db.Column(db.String(120), unique=True, nullable=False)  # Unique email
    password = db.Column(db.String(255), nullable=False)  # Hashed password
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Created time

    def to_dict(self):  # Convert to dictionary
        return {'id': self.id, 'email': self.email}


class TokenBlacklist(db.Model):  # Stores revoked refresh tokens
    __tablename__ = 'token_blacklist'
    id = db.Column(db.Integer, primary_key=True)  # Primary key
    jti = db.Column(db.String(36), unique=True, nullable=False)  # Token's unique ID (not the whole token)
    revoked_at = db.Column(db.DateTime, default=datetime.utcnow)  # When token was revoked


def hash_password(password):  # Hash password
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def check_password(password, hashed_password):  # Verify password
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


def create_access_token(user):  # Create SHORT-LIVED access token (for API calls)
    payload = {'user_id': user.id, 'email': user.email, 'type': 'access', 'exp': datetime.utcnow() + ACCESS_TOKEN_EXPIRES}  # type='access' marks this as access token
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


def create_refresh_token(user):  # Create LONG-LIVED refresh token (only for getting new access tokens)
    payload = {'user_id': user.id, 'type': 'refresh', 'jti': str(uuid.uuid4()), 'exp': datetime.utcnow() + REFRESH_TOKEN_EXPIRES}  # jti = unique ID for blacklisting
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


def is_token_blacklisted(jti):  # Check if refresh token has been revoked (logged out)
    return TokenBlacklist.query.filter_by(jti=jti).first() is not None


def access_token_required(f):  # Decorator to require valid ACCESS token
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')  # Get auth header

        if not auth_header:  # No header
            return jsonify({'message': 'Access token is missing!'}), 401

        try:
            parts = auth_header.split(' ')  # Split "Bearer <token>"
            if len(parts) != 2 or parts[0] != 'Bearer':  # Invalid format
                return jsonify({'message': 'Invalid token format!'}), 401

            token = parts[1]  # Get token
            decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])  # Decode token

            if decoded.get('type') != 'access':  # Must be access token, not refresh token
                return jsonify({'message': 'Invalid token type! Use access token.'}), 401

            g.current_user = {'user_id': decoded['user_id'], 'email': decoded['email']}  # Store user info

        except jwt.ExpiredSignatureError:  # Token expired
            return jsonify({'message': 'Access token has expired!', 'error': 'TOKEN_EXPIRED'}), 401  # Frontend should use refresh token
        except jwt.InvalidTokenError:  # Invalid token
            return jsonify({'message': 'Invalid token!'}), 401

        return f(*args, **kwargs)  # Call protected function
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


@app.route('/login', methods=['POST'])  # Login - returns BOTH tokens
def login():
    data = request.get_json()  # Get JSON data
    email, password = data.get('email'), data.get('password')  # Get credentials

    if not email or not password:  # Validate input
        return jsonify({'message': 'Email and password are required!'}), 400

    user = User.query.filter_by(email=email).first()  # Find user

    if not user or not check_password(password, user.password):  # Invalid credentials
        return jsonify({'message': 'Invalid email or password!'}), 401

    access_token = create_access_token(user)  # Create short-lived access token
    refresh_token = create_refresh_token(user)  # Create long-lived refresh token

    return jsonify({
        'message': 'Login successful!',
        'access_token': access_token,  # Use for API calls
        'refresh_token': refresh_token,  # Store securely, use to get new access token
        'expires_in': int(ACCESS_TOKEN_EXPIRES.total_seconds()),  # Seconds until access token expires
        'user': user.to_dict()
    })


@app.route('/refresh', methods=['POST'])  # Get new access token using refresh token
def refresh():
    data = request.get_json()  # Get JSON data
    refresh_token = data.get('refresh_token')  # Get refresh token

    if not refresh_token:  # No refresh token
        return jsonify({'message': 'Refresh token is required!'}), 400

    try:
        decoded = jwt.decode(refresh_token, SECRET_KEY, algorithms=['HS256'])  # Decode refresh token

        if decoded.get('type') != 'refresh':  # Must be refresh token
            return jsonify({'message': 'Invalid token type! Use refresh token.'}), 401

        jti = decoded.get('jti')  # Get token's unique ID
        if is_token_blacklisted(jti):  # Check if logged out
            return jsonify({'message': 'Token has been revoked. Please login again.'}), 401

        user = User.query.get(decoded['user_id'])  # Get user
        if not user:  # User not found
            return jsonify({'message': 'User not found!'}), 404

        new_access_token = create_access_token(user)  # Create new access token

        return jsonify({
            'message': 'Token refreshed!',
            'access_token': new_access_token,
            'expires_in': int(ACCESS_TOKEN_EXPIRES.total_seconds())
        })

    except jwt.ExpiredSignatureError:  # Refresh token expired - must login again
        return jsonify({'message': 'Refresh token has expired. Please login again.'}), 401
    except jwt.InvalidTokenError:  # Invalid token
        return jsonify({'message': 'Invalid refresh token!'}), 401


@app.route('/logout', methods=['POST'])  # Logout - revoke refresh token
def logout():
    data = request.get_json()  # Get JSON data
    refresh_token = data.get('refresh_token')  # Get refresh token

    if not refresh_token:  # No refresh token
        return jsonify({'message': 'Refresh token is required!'}), 400

    try:
        decoded = jwt.decode(refresh_token, SECRET_KEY, algorithms=['HS256'])  # Decode token
        jti = decoded.get('jti')  # Get token's unique ID

        if is_token_blacklisted(jti):  # Already logged out
            return jsonify({'message': 'Already logged out!'})

        blacklist_entry = TokenBlacklist(jti=jti)  # Add to blacklist
        db.session.add(blacklist_entry)  # Add to session
        db.session.commit()  # Save to database

        return jsonify({'message': 'Logged out successfully!'})

    except jwt.ExpiredSignatureError:  # Token already expired
        return jsonify({'message': 'Token already expired!'})
    except jwt.InvalidTokenError:  # Invalid token
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
