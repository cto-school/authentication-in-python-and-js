# ================================================================================
# CHAPTER 3: User Login & JWT Tokens
# ================================================================================
#
# This chapter covers:
#   1. Verifying user credentials (email + password)
#   2. Creating JWT tokens upon successful login
#   3. Returning tokens to the frontend
#
# BUILDS ON: Chapter 2 (User model, password hashing)
#
# KEY CONCEPT: Login = Verify credentials → Return JWT token
#
# ================================================================================

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
# ================================================================================
# pyjwt - JWT Library
# ================================================================================
# jwt.encode() - Create a token from payload + secret
# jwt.decode() - Verify and extract data from a token
# ================================================================================
import jwt
from datetime import datetime, timedelta
import os
import warnings
warnings.filterwarnings('ignore', message='.*Query.get.*')

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_ch3.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ================================================================================
# SECRET KEY
# ================================================================================
# Used to SIGN JWT tokens. Anyone with this key can create valid tokens!
# In production: Use environment variable, never commit to code.
# ================================================================================
SECRET_KEY = 'your-secret-key-keep-it-safe-123'

db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }


def hash_password(password):
    """Hash a password for storage."""
    return generate_password_hash(password)


def verify_password(plain_password, hashed_password):
    """
    Verify a password against its hash.

    How it works:
        1. Extract the salt from the stored hash
        2. Hash the plain_password with the same salt
        3. Compare the two hashes
        4. Return True if they match, False otherwise

    Note: Arguments are (hash, password) - hash comes first!
    """
    return check_password_hash(hashed_password, plain_password)


# ================================================================================
# JWT TOKEN CREATION
# ================================================================================
# A JWT token contains:
#   - Payload: Your data (user_id, email, etc.)
#   - Expiration: When the token becomes invalid
#   - Signature: Proves the token wasn't tampered with
# ================================================================================


def create_token(user):
    """
    Create a JWT token for a user.

    Payload contains:
        user_id - To identify which user this token belongs to
        email   - For convenience (frontend can display without API call)
        exp     - Expiration timestamp (token invalid after this time)

    Returns:
        A JWT token string like "eyJhbGciOiJIUzI1NiIs..."
    """
    payload = {
        'user_id': user.id,
        'email': user.email,
        'exp': datetime.utcnow() + timedelta(hours=24)  # Token valid for 24 hours
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


# ================================================================================
# ROUTES
# ================================================================================


@app.route('/')
def index():
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    return send_file(html_path)


@app.route('/register', methods=['POST'])
def register():
    """Register a new user (same as Chapter 2)."""
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required!'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already exists!'}), 400

    new_user = User(email=email, password=hash_password(password))
    db.session.add(new_user)
    db.session.commit()

    return jsonify({
        'message': 'User registered successfully!',
        'user': new_user.to_dict()
    }), 201


@app.route('/login', methods=['POST'])
def login():
    """
    Authenticate user and return JWT token.

    Expected JSON body:
        {
            "email": "user@example.com",
            "password": "secret123"
        }

    Process:
        1. Get email and password from request
        2. Find user by email
        3. Verify password matches hash
        4. If valid: Create and return JWT token
        5. If invalid: Return error

    Returns:
        200: Login successful with token
        400: Missing email or password
        401: Invalid credentials
    """
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    # Validate input
    if not email or not password:
        return jsonify({'message': 'Email and password are required!'}), 400

    # Find user by email
    user = User.query.filter_by(email=email).first()

    # ================================================================================
    # SECURITY: Use same error message for "user not found" and "wrong password"
    # ================================================================================
    # Why? If we say "User not found", attackers know the email doesn't exist.
    # By using the same message, we don't reveal which part was wrong.
    # ================================================================================

    if not user:
        return jsonify({'message': 'Invalid email or password!'}), 401

    if not verify_password(password, user.password):
        return jsonify({'message': 'Invalid email or password!'}), 401

    # ================================================================================
    # LOGIN SUCCESS - Create JWT Token
    # ================================================================================
    # The token contains user info and will be sent with future requests
    # to prove the user is authenticated.
    # ================================================================================

    token = create_token(user)

    return jsonify({
        'message': 'Login successful!',
        'token': token,
        'user': user.to_dict()
    })


with app.app_context():
    db.create_all()


# ================================================================================
# KEY TAKEAWAYS - Chapter 3
# ================================================================================
#
# 1. LOGIN FLOW:
#    User sends email + password → Server verifies → Server returns JWT token
#    The token is proof that the user logged in successfully.
#
# 2. SECURITY: Same error message for "user not found" and "wrong password"
#    WHY? If we say "User not found", attackers learn which emails exist.
#    Always use: "Invalid email or password" for both cases.
#
# 3. PASSWORD VERIFICATION:
#    check_password_hash(stored_hash, user_input)
#    - Takes the stored hash and the password user entered
#    - Returns True if they match, False otherwise
#    - We NEVER compare plain passwords!
#
# 4. TOKEN PAYLOAD contains:
#    - user_id: To identify the user in future requests
#    - email: For convenience (frontend can display without extra API call)
#    - exp: Expiration time (24 hours in this example)
#
# 5. FRONTEND: Token is saved in localStorage!
#    After login, the frontend does: localStorage.setItem('token', data.token)
#
#    TRY THIS - Verify token storage:
#    - Login in the browser
#    - Open Developer Tools (F12)
#    - Go to "Application" tab (Chrome) or "Storage" tab (Firefox)
#    - Click "Local Storage" → "http://localhost:5003"
#    - You'll see: key="token", value="eyJhbGciOiJIUzI1NiIs..."
#    - This is YOUR token stored in the browser!
#
# 6. TRY THIS - Decode the token:
#    - Copy the token value from localStorage
#    - Go to https://jwt.io and paste it
#    - See your user_id and email in the payload!
#    - Notice: The payload is NOT encrypted, just encoded (base64)
#
# NEXT CHAPTER: We'll send this token with requests to access protected routes.
#
# ================================================================================


# ================================================================================
# EXERCISES - Test Your Understanding!
# ================================================================================
#
# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 1: Add last_login Field (Easy)
# ────────────────────────────────────────────────────────────────────────────────
# Modify the system to track when users last logged in:
# - Add 'last_login' field to User model (DateTime, nullable=True)
# - Update /login to set last_login = datetime.utcnow() on successful login
# - Include last_login in to_dict()
#
# Test: Login, then check the response - should include last_login timestamp
#
# NOTE: Delete users.db file and restart server after changing the model!
# ────────────────────────────────────────────────────────────────────────────────


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 2: Remember Me Feature (Medium)
# ────────────────────────────────────────────────────────────────────────────────
# Modify /login to support a "remember me" option:
# - Accept optional 'remember_me' boolean in request body
# - If true: token expires in 30 days
# - If false (default): token expires in 24 hours
# - Return the expiration time in the response
#
# Test: curl -X POST http://localhost:5003/login \
#       -H "Content-Type: application/json" \
#       -d '{"email": "test@test.com", "password": "123", "remember_me": true}'
#
# Expected: {..., "token": "...", "expires_in": "30 days"}
#
# HINT: Modify create_token() to accept an optional parameter, or create
#       create_token_with_expiry(user, days=1) function
# ────────────────────────────────────────────────────────────────────────────────


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 3: Login Count Tracker (Medium)
# ────────────────────────────────────────────────────────────────────────────────
# Track how many times each user has logged in:
# - Add 'login_count' field to User model (Integer, default=0)
# - Increment login_count on each successful login
# - Include login_count in the login response
#
# Test: Login multiple times, verify login_count increases each time
#
# HINT: user.login_count += 1 before db.session.commit()
# ────────────────────────────────────────────────────────────────────────────────


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 4: Token Info Endpoint (Medium)
# ────────────────────────────────────────────────────────────────────────────────
# Create an endpoint GET /token-info that:
# - Reads the token from Authorization header (like protected routes will)
# - Returns the decoded payload WITHOUT requiring full authentication
# - Returns error if token is missing, expired, or invalid
#
# Test: Login to get a token, then:
#       curl http://localhost:5003/token-info \
#       -H "Authorization: Bearer eyJ..."
#
# Expected: {"user_id": 1, "email": "...", "exp": ..., "expires_at": "..."}
#
# HINT: This is practice for the @token_required decorator in Chapter 4!
# ────────────────────────────────────────────────────────────────────────────────

# YOUR CODE HERE:
# @app.route('/token-info', methods=['GET'])
# def token_info():
#     pass


# ================================================================================


if __name__ == '__main__':
    print("=" * 60)
    print("CHAPTER 3: User Login & JWT Tokens")
    print("=" * 60)
    print("Server running at: http://localhost:5003")
    print("")
    print("Endpoints:")
    print("  POST /register - Register new user")
    print("  POST /login    - Login and get JWT token")
    print("=" * 60)
    app.run(debug=True, port=5003)
