# ================================================================================
# PART 5: FORGOT PASSWORD - Token Generation & Verification
# ================================================================================
#
# This part covers the FIRST HALF of password reset:
#   1. User requests password reset (enters email)
#   2. Server generates a secure random token
#   3. Server stores token in database with expiration
#   4. Server returns reset link (in production: sends via email)
#   5. User clicks link, server verifies token is valid
#
# Part 6 will cover the SECOND HALF:
#   6. User enters new password
#   7. Server validates token again
#   8. Server updates password
#   9. Server marks token as used
#
# NEW CONCEPTS IN THIS PART:
#   - secrets module for cryptographically secure random tokens
#   - New database table (PasswordResetToken) with ForeignKey relationship
#   - Token expiration and one-time use
#   - URL query parameters (request.args vs request.get_json)
#
# ================================================================================

from flask import Flask, jsonify, request, g, send_file
from flask_cors import CORS  # Cross-origin requests
from flask_sqlalchemy import SQLAlchemy  # Database ORM
# Password hashing using werkzeug.security (comes built-in with Flask)
from werkzeug.security import generate_password_hash, check_password_hash
import jwt  # From 'pyjwt' package (pip install pyjwt), NOT 'jwt'
# ================================================================================
# secrets module - Cryptographically Secure Random Generator
# ================================================================================
# Why use 'secrets' instead of 'random'?
#   - 'random' module is for games, simulations - NOT secure for passwords/tokens
#   - 'secrets' module is designed for security-sensitive applications
#   - Uses the operating system's secure random number generator
#   - Unpredictable - attackers cannot guess the next value
#
# Example of the danger of using 'random':
#   import random
#   random.seed(123)  # If attacker knows the seed, they can predict all values!
#
# With 'secrets', there's no seed - it's truly random and secure.
# ================================================================================
import secrets
from datetime import datetime, timedelta  # Date/time handling
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


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Database file
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable tracking
SECRET_KEY = 'your-secret-key-keep-it-safe'  # JWT secret
BASE_URL = 'http://localhost:5005'  # Base URL for reset links

db = SQLAlchemy(app)  # Database instance


class User(db.Model):  # User model
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)  # Primary key
    email = db.Column(db.String(120), unique=True, nullable=False)  # Unique email
    password = db.Column(db.String(255), nullable=False)  # Hashed password
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Created time


# ================================================================================
# PASSWORD RESET TOKEN MODEL - New Database Table
# ================================================================================
# This is a NEW table (separate from users) to store password reset requests.
#
# Why a separate table?
#   1. One user can have multiple reset tokens (requested multiple times)
#   2. We need to track: when created, when expires, if used
#   3. Keeps user table clean - reset tokens are temporary data
#
# Database Relationship:
#   users table                    password_reset_tokens table
#   +---------+                    +------------------+
#   | id      |<-------------------| user_id (FK)     |
#   | email   |      One-to-Many   | token            |
#   | password|      (1 user can   | expires_at       |
#   +---------+       have many    | used             |
#                     tokens)      +------------------+
# ================================================================================
class PasswordResetToken(db.Model):
    __tablename__ = 'password_reset_tokens'

    id = db.Column(db.Integer, primary_key=True)

    # ForeignKey - Links this token to a specific user
    # 'users.id' refers to the 'id' column in the 'users' table
    # This creates a database-level constraint: user_id MUST exist in users table
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # The actual reset token - a random string like "a7f8b9c0d1e2f3..."
    # unique=True ensures no duplicate tokens can exist
    token = db.Column(db.String(100), unique=True, nullable=False)

    # Expiration time - tokens should not last forever (security risk)
    # Typically 1 hour for password reset tokens
    expires_at = db.Column(db.DateTime, nullable=False)

    # One-time use flag - once used, token cannot be used again
    # This prevents replay attacks (someone reusing an old link)
    used = db.Column(db.Boolean, default=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # ================================================================================
    # SQLAlchemy Relationship - Makes accessing related data easy
    # ================================================================================
    # This creates a convenient way to access the User from a token:
    #   token_record.user.email  → Gets the user's email
    #
    # 'backref' creates a reverse relationship on User:
    #   user.reset_tokens  → Gets all reset tokens for this user
    #
    # This is NOT a database column - it's a Python-level convenience
    # The actual link is through user_id (the ForeignKey)
    # ================================================================================
    user = db.relationship('User', backref='reset_tokens')


# Hash password - converts plain text to secure hash
def hash_password(password):
    return generate_password_hash(password)


# Verify password - compares plain password with stored hash
def check_password(password, hashed_password):
    return check_password_hash(hashed_password, password)


def create_token(user):  # Create JWT token
    payload = {'user_id': user.id, 'email': user.email, 'exp': datetime.utcnow() + timedelta(hours=24)}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


# ================================================================================
# GENERATE RESET TOKEN - Creating a Secure Random String
# ================================================================================
# secrets.token_hex(32) generates:
#   - 32 random bytes (256 bits of randomness)
#   - Converted to hexadecimal = 64 characters
#   - Example: "a7f8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8"
#
# Why 32 bytes?
#   - 256 bits = extremely hard to guess (2^256 possibilities)
#   - Even if attacker tries 1 billion guesses per second,
#     it would take longer than the age of the universe to guess
#
# Alternative: secrets.token_urlsafe(32) - URL-safe base64 (shorter, still secure)
# ================================================================================
def generate_reset_token():
    return secrets.token_hex(32)


@app.route('/register', methods=['POST'])  # Register endpoint
def register():
    data = request.get_json()
    email, password = data.get('email'), data.get('password')
    if not email or not password:
        return jsonify({'message': 'Email and password are required!'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already exists!'}), 400
    new_user = User(email=email, password=hash_password(password))
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered!', 'user': {'id': new_user.id, 'email': new_user.email}}), 201


@app.route('/login', methods=['POST'])  # Login endpoint
def login():
    data = request.get_json()
    email, password = data.get('email'), data.get('password')
    if not email or not password:
        return jsonify({'message': 'Email and password are required!'}), 400
    user = User.query.filter_by(email=email).first()
    if not user or not check_password(password, user.password):
        return jsonify({'message': 'Invalid email or password!'}), 401
    return jsonify({'message': 'Login successful!', 'token': create_token(user), 'user': {'id': user.id, 'email': user.email}})


# ================================================================================
# FORGOT PASSWORD ENDPOINT - Step 1 of Password Reset Flow
# ================================================================================
# This is where users REQUEST a password reset (they don't reset here, just request)
#
# Flow:
#   1. User clicks "Forgot Password" on frontend
#   2. User enters their email
#   3. Frontend calls POST /forgot-password with { "email": "user@example.com" }
#   4. Backend generates a unique reset token
#   5. Backend stores token in database (with expiration)
#   6. Backend returns reset link (in production: sends via email instead)
#   7. User clicks link to go to reset page (Part 6)
#
# Security Note:
#   In production, you should NOT reveal whether email exists or not.
#   Always say "If this email exists, we've sent a reset link."
#   This prevents attackers from discovering which emails are registered.
# ================================================================================
@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'message': 'Email is required!'}), 400

    user = User.query.filter_by(email=email).first()

    # NOTE: In production, don't reveal if email exists!
    # For learning/testing, we tell the user if email wasn't found
    if not user:
        return jsonify({'message': 'Email not found!'}), 404

    # Generate a cryptographically secure random token
    reset_token = generate_reset_token()

    # Create a database record to track this reset request
    token_record = PasswordResetToken(
        user_id=user.id,              # Which user requested the reset
        token=reset_token,            # The random token
        expires_at=datetime.utcnow() + timedelta(hours=1),  # Valid for 1 hour
        used=False                    # Not used yet (will be True after password is reset)
    )

    db.session.add(token_record)
    db.session.commit()

    # Build the reset link that user will click
    # Format: http://localhost:5005/reset-password?token=abc123...
    # The token is passed as a URL query parameter
    reset_link = f"{BASE_URL}/reset-password?token={reset_token}"

    # In production: Send this link via email (see Part 7 for Mailgun integration)
    # For testing: We return the link directly so you can click it
    return jsonify({
        'message': 'Password reset link generated!',
        'reset_link': reset_link,
        'token': reset_token,
        'expires_in': '1 hour',
        'note': 'In production, this link would be sent via email'
    })


# ================================================================================
# VERIFY RESET TOKEN - Check if a token is valid before showing reset form
# ================================================================================
# This endpoint is called by the frontend to check if a token is valid
# BEFORE showing the "enter new password" form.
#
# Why verify first?
#   - Better UX: Don't show password form if token is invalid/expired
#   - Security: Validate token before allowing any password change
#
# Three things can make a token invalid:
#   1. Token doesn't exist in database (wrong/fake token)
#   2. Token has been used before (one-time use)
#   3. Token has expired (past expires_at time)
# ================================================================================
@app.route('/verify-reset-token', methods=['POST'])
def verify_reset_token():
    data = request.get_json()
    token = data.get('token')

    if not token:
        return jsonify({'message': 'Token is required!'}), 400

    # Look up the token in database
    token_record = PasswordResetToken.query.filter_by(token=token).first()

    # Check 1: Does token exist?
    if not token_record:
        return jsonify({'valid': False, 'message': 'Invalid token!'}), 400

    # Check 2: Has token been used already?
    # (After password is reset, we mark token as used=True)
    if token_record.used:
        return jsonify({'valid': False, 'message': 'Token has already been used!'}), 400

    # Check 3: Has token expired?
    # Compare expires_at with current time
    if token_record.expires_at < datetime.utcnow():
        return jsonify({'valid': False, 'message': 'Token has expired!'}), 400

    # All checks passed - token is valid!
    # Return the user's email so frontend can display it
    # token_record.user.email works because of the 'relationship' we defined
    return jsonify({
        'valid': True,
        'message': 'Token is valid!',
        'email': token_record.user.email  # Accessing related User via relationship
    })


# ================================================================================
# RESET PASSWORD PAGE - Serve HTML when user clicks reset link
# ================================================================================
# This is a GET request (user clicking a link), not POST (form submission)
#
# URL Query Parameters:
#   When user clicks: http://localhost:5005/reset-password?token=abc123
#   The "?token=abc123" part is a query parameter
#
#   request.args.get('token')  → Gets 'abc123' from the URL
#   request.get_json()         → Gets data from POST body (NOT for GET requests)
#
# Difference between GET and POST data:
#   GET:  Data in URL → request.args.get('param')
#   POST: Data in body → request.get_json() or request.form.get('param')
#
# Note: Part 5 only VERIFIES the token and shows status.
#       Part 6 adds the actual password reset functionality.
# ================================================================================
@app.route('/reset-password', methods=['GET'])
def reset_password_page():
    # request.args contains URL query parameters
    # For URL: /reset-password?token=abc123&foo=bar
    #   request.args.get('token') → 'abc123'
    #   request.args.get('foo') → 'bar'
    token = request.args.get('token')

    if not token:
        return '''
        <html><body style="font-family: Arial; padding: 40px; text-align: center;">
            <h2 style="color: red;">Error: No Token Provided</h2>
            <p>Please use the link from your email.</p>
        </body></html>
        '''

    # Verify the token
    token_record = PasswordResetToken.query.filter_by(token=token).first()

    if not token_record:
        status = "Invalid token!"
        color = "red"
        valid = False
    elif token_record.used:
        status = "Token has already been used!"
        color = "orange"
        valid = False
    elif token_record.expires_at < datetime.utcnow():
        status = "Token has expired!"
        color = "orange"
        valid = False
    else:
        status = f"Token is valid! Email: {token_record.user.email}"
        color = "green"
        valid = True

    return f'''
    <html>
    <head>
        <title>Part 5: Token Verification</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <div class="container py-5">
            <div class="card mx-auto" style="max-width: 500px;">
                <div class="card-header bg-primary text-white">
                    <h4>Part 5: Token Verification Result</h4>
                </div>
                <div class="card-body text-center">
                    <h3 style="color: {color};">{status}</h3>
                    <hr>
                    <p><strong>Token:</strong><br><small>{token[:20]}...</small></p>
                    <div class="alert alert-info mt-3">
                        <strong>Note:</strong> Part 5 only covers token generation and verification.<br>
                        Part 6 covers the actual password reset functionality.
                    </div>
                    <a href="/" class="btn btn-primary">Back to Home</a>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    print("=" * 50)
    print("Forgot Password Server Running on http://localhost:5005")
    print("=" * 50)
    app.run(debug=True, port=5005)


# ===========================================
# EXERCISES - Try These!
# ===========================================
"""
EXERCISE 1: Change Token Expiration Time
----------------------------------------
Current code (line 83):
    expires_at=datetime.utcnow() + timedelta(hours=1)

Try changing to:
    expires_at=datetime.utcnow() + timedelta(seconds=30)

Test:
1. Request forgot-password
2. Wait 30 seconds
3. Call verify-reset-token

Question: What message do you get? Why is expiration important for security?


EXERCISE 2: See the Token in Database
-------------------------------------
Add this route to view all tokens:

@app.route('/debug/tokens', methods=['GET'])
def debug_tokens():
    tokens = PasswordResetToken.query.all()
    return jsonify({
        'tokens': [{
            'id': t.id,
            'user_email': t.user.email,
            'token': t.token[:20] + '...',  # Show first 20 chars
            'expires_at': t.expires_at.strftime('%Y-%m-%d %H:%M:%S'),
            'used': t.used
        } for t in tokens]
    })

Test: Create multiple reset requests and view them
Question: Why do we store tokens in database instead of just in memory?


EXERCISE 3: Prevent Multiple Active Tokens
------------------------------------------
Currently, a user can request multiple reset tokens.
Add code to invalidate old tokens when creating new one:

In forgot_password(), before creating new token:
    # Mark all old tokens for this user as used
    old_tokens = PasswordResetToken.query.filter_by(user_id=user.id, used=False).all()
    for old_token in old_tokens:
        old_token.used = True

Question: Why might you want only one active reset token per user?


EXERCISE 4: Add Rate Limiting (Simple Version)
----------------------------------------------
Prevent spam by limiting reset requests:

# At the top of forgot_password():
    # Check if user requested reset in last 5 minutes
    recent_token = PasswordResetToken.query.filter(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.created_at > datetime.utcnow() - timedelta(minutes=5)
    ).first()

    if recent_token:
        return jsonify({'message': 'Please wait 5 minutes before requesting again'}), 429

Question: Why is rate limiting important? What does status code 429 mean?


SELF-STUDY QUESTIONS
--------------------
1. Why use secrets.token_hex() instead of random string generators?

2. What's the difference between token expiration and "used" flag?

3. In production, should we tell users if email exists? Why/why not?

4. Why store reset tokens in database instead of sending them in email only?

5. What happens if someone intercepts the reset link?
"""
