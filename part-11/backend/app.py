# ================================================================================
# PART 11: EMAIL VERIFICATION
# ================================================================================
#
# This part adds email verification - ensuring users own the email they registered with.
#
# WHY VERIFY EMAILS?
#   1. Prevent fake accounts (someone using random emails)
#   2. Prevent impersonation (someone using YOUR email)
#   3. Enable account recovery (password reset requires valid email)
#   4. Reduce spam registrations
#   5. Legal compliance (GDPR, etc.)
#
# HOW IT WORKS:
#   1. User registers → Account created with is_verified=False
#   2. Server generates verification token
#   3. Server sends verification link (in production: via email)
#   4. User clicks link → Token is verified
#   5. Account marked as verified (is_verified=True)
#   6. User can now access verified-only features
#
# NEW CONCEPTS IN THIS PART:
#   - is_verified field in User model
#   - verification_token and verification_expires fields
#   - @verified_required decorator (stacks with @token_required)
#   - Resend verification functionality
#   - Different access levels (logged in vs verified)
#
# ================================================================================

from flask import Flask, jsonify, request, g, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
# Password hashing using werkzeug.security (comes built-in with Flask)
from werkzeug.security import generate_password_hash, check_password_hash
import jwt  # From 'pyjwt' package (pip install pyjwt), NOT 'jwt'
# secrets module - Same as Part 5, for cryptographically secure random tokens
import secrets
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


@app.route('/verify.html')  # Serve the verify HTML page
def verify_page():
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'verify.html')
    return send_file(html_path)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_new_new.db'  # Database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable tracking
SECRET_KEY = 'your-secret-key-keep-it-safe'  # JWT secret
FRONTEND_URL = 'http://localhost:5011'  # Frontend URL for verification link

db = SQLAlchemy(app)  # Database instance


# ================================================================================
# USER MODEL WITH VERIFICATION FIELDS
# ================================================================================
# New fields added for email verification:
#
#   is_verified          - Boolean: Has user verified their email?
#   verification_token   - The random token sent in verification link
#   verification_expires - When the verification token expires
#
# User lifecycle:
#   1. Register → is_verified=False, token generated
#   2. Click verification link → is_verified=True, token cleared
#
# Database structure:
#   +----+---------+----------+-------------+--------------------+---------------------+
#   | id | email   | password | is_verified | verification_token | verification_expires|
#   +----+---------+----------+-------------+--------------------+---------------------+
#   | 1  | a@b.com | hash...  | False       | abc123...          | 2024-01-16 12:00:00 |
#   | 2  | c@d.com | hash...  | True        | NULL               | NULL                |
#   +----+---------+----------+-------------+--------------------+---------------------+
# ================================================================================


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # ================================================================================
    # VERIFICATION FIELDS
    # ================================================================================
    # is_verified: Starts False, becomes True after email verification
    # verification_token: Random token in verification link, cleared after use
    # verification_expires: Token expiration time (e.g., 24 hours after registration)
    # ================================================================================
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), unique=True, nullable=True)
    verification_expires = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        """Convert to dictionary, including verification status."""
        return {
            'id': self.id,
            'email': self.email,
            'is_verified': self.is_verified,  # Frontend can show verification badge
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }


# Hash password - converts plain text to secure hash
def hash_password(password):
    return generate_password_hash(password)


# Verify password - compares plain password with stored hash
def check_password(password, hashed_password):
    return check_password_hash(hashed_password, password)


# ================================================================================
# JWT TOKEN WITH VERIFICATION STATUS
# ================================================================================
# The is_verified status is included in the JWT token.
#
# IMPORTANT: If user verifies email, old tokens still have is_verified=False!
# User must re-login to get a new token with is_verified=True.
#
# Token payload:
#   {
#       "user_id": 1,
#       "email": "user@example.com",
#       "is_verified": true,       ← NEW!
#       "exp": 1234567890
#   }
# ================================================================================


def create_token(user):
    """Create JWT token with verification status included."""
    payload = {
        'user_id': user.id,
        'email': user.email,
        'is_verified': user.is_verified,  # Include verification status
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


def generate_verification_token():
    """
    Generate a cryptographically secure URL-safe token.

    secrets.token_urlsafe(32):
        - 32 bytes of randomness
        - Encoded as URL-safe base64 (43 characters)
        - Can be safely used in URLs without encoding
        - Example: "dGhpcyBpcyBhIHRlc3Qgc3RyaW5n..."
    """
    return secrets.token_urlsafe(32)


def token_required(f):
    """Decorator to require valid JWT token (logged in)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')

        if not auth_header:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            parts = auth_header.split(' ')
            if len(parts) != 2 or parts[0] != 'Bearer':
                return jsonify({'message': 'Invalid token format!'}), 401

            token = parts[1]
            decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

            # Store user info INCLUDING is_verified for @verified_required
            g.current_user = {
                'user_id': decoded['user_id'],
                'email': decoded['email'],
                'is_verified': decoded.get('is_verified', False)
            }

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401

        return f(*args, **kwargs)
    return decorated


# ================================================================================
# VERIFIED REQUIRED DECORATOR
# ================================================================================
# This decorator adds a verification check ON TOP OF authentication.
#
# Two-level access control:
#   Level 1: @token_required      - User is logged in
#   Level 2: @verified_required   - User is logged in AND email is verified
#
# Use cases:
#   - Profile viewing: @token_required only (unverified can view)
#   - Posting content: @token_required + @verified_required (must be verified)
#   - Payment: @token_required + @verified_required (must be verified)
#
# Decorator stacking:
#   @app.route('/protected')
#   @token_required         ← Runs first: Is user logged in?
#   @verified_required      ← Runs second: Is email verified?
#   def protected_route():
# ================================================================================


def verified_required(f):
    """
    Decorator to require verified email.
    MUST be used AFTER @token_required (stacked below it).
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.current_user.get('is_verified'):
            return jsonify({
                'message': 'Email not verified! Please verify your email first.',
                'error': 'EMAIL_NOT_VERIFIED'  # Frontend can show verification prompt
            }), 403  # 403 Forbidden: Logged in but not permitted

        return f(*args, **kwargs)
    return decorated


# ================================================================================
# REGISTRATION WITH VERIFICATION
# ================================================================================
# Registration now creates an UNVERIFIED account.
# User must verify email before accessing certain features.
#
# Flow:
#   1. User submits email + password
#   2. Server creates user with is_verified=False
#   3. Server generates verification token
#   4. Server returns verification link (in production: sends via email)
#   5. User clicks link to verify
# ================================================================================


@app.route('/register', methods=['POST'])
def register():
    """Register a new user - starts as unverified."""
    data = request.get_json()
    email, password = data.get('email'), data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required!'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already exists!'}), 400

    # Generate verification token
    verification_token = generate_verification_token()

    # Create user with verification fields
    new_user = User(
        email=email,
        password=hash_password(password),
        is_verified=False,  # Starts unverified!
        verification_token=verification_token,
        verification_expires=datetime.utcnow() + timedelta(hours=24)
    )

    db.session.add(new_user)
    db.session.commit()

    # Build verification link
    # In production, this link would be sent via email (see Part 7)
    verification_link = f"{FRONTEND_URL}/verify.html?token={verification_token}"

    return jsonify({
        'message': 'Registration successful! Please verify your email.',
        'user': new_user.to_dict(),
        'verification_link': verification_link,  # For testing only!
        'note': 'In production, this link would be sent via email'
    }), 201


# ================================================================================
# EMAIL VERIFICATION ENDPOINT
# ================================================================================
# This endpoint is called when user clicks the verification link.
#
# Validation checks:
#   1. Token is provided
#   2. Token exists in database (matches a user)
#   3. User isn't already verified
#   4. Token hasn't expired
#
# After verification:
#   - is_verified = True
#   - verification_token = NULL (cleared, one-time use)
#   - verification_expires = NULL (no longer needed)
# ================================================================================


@app.route('/verify-email', methods=['GET'])
def verify_email():
    """Verify email using the token from the verification link."""
    # Token comes from URL: /verify-email?token=abc123
    token = request.args.get('token')

    if not token:
        return jsonify({'message': 'Verification token is required!'}), 400

    # Find user by verification token
    user = User.query.filter_by(verification_token=token).first()

    if not user:
        return jsonify({'message': 'Invalid verification token!'}), 400

    if user.is_verified:
        return jsonify({'message': 'Email already verified!', 'user': user.to_dict()})

    # Check if token has expired
    if user.verification_expires < datetime.utcnow():
        return jsonify({'message': 'Verification token has expired! Please request a new one.'}), 400

    # ================================================================================
    # VERIFICATION SUCCESS
    # ================================================================================
    # Mark as verified and clear token (one-time use security)
    # Clearing token prevents replay attacks (using same link twice)
    # ================================================================================
    user.is_verified = True
    user.verification_token = None  # Clear - token is now used
    user.verification_expires = None  # Clear - no longer needed
    db.session.commit()

    return jsonify({'message': 'Email verified successfully! You can now login.', 'user': user.to_dict()})


# ================================================================================
# RESEND VERIFICATION
# ================================================================================
# Users might need to resend verification if:
#   - Original email went to spam
#   - Token expired before they clicked
#   - They deleted the email by accident
#
# Security considerations:
#   1. Don't reveal if email exists (prevents email enumeration)
#   2. Generate NEW token (invalidates old one)
#   3. Consider rate limiting (prevent spam)
# ================================================================================


@app.route('/resend-verification', methods=['POST'])
def resend_verification():
    """Resend verification email with a new token."""
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'message': 'Email is required!'}), 400

    user = User.query.filter_by(email=email).first()

    # ================================================================================
    # SECURITY: Don't Reveal Email Existence
    # ================================================================================
    # If email doesn't exist, return the SAME message as success.
    # This prevents attackers from discovering which emails are registered.
    # ================================================================================
    if not user:
        return jsonify({'message': 'If this email exists, a verification link has been sent.'})

    if user.is_verified:
        return jsonify({'message': 'Email is already verified!'})

    # Generate NEW token (invalidates old one automatically)
    verification_token = generate_verification_token()
    user.verification_token = verification_token
    user.verification_expires = datetime.utcnow() + timedelta(hours=24)
    db.session.commit()

    verification_link = f"{FRONTEND_URL}/verify.html?token={verification_token}"

    return jsonify({
        'message': 'Verification link generated!',
        'verification_link': verification_link,
        'note': 'In production, this would be sent via email'
    })


# ================================================================================
# LOGIN - Works for Both Verified and Unverified Users
# ================================================================================
# Design choice: Allow unverified users to login.
#
# Alternative approach: Block login until verified
#   PROS: Forces verification, simpler access control
#   CONS: Users can't access their account at all until verified
#
# Our approach: Allow login, restrict features
#   PROS: Users can still see their account, resend verification
#   CONS: Need @verified_required on sensitive routes
# ================================================================================


@app.route('/login', methods=['POST'])
def login():
    """Login - works for verified AND unverified users."""
    data = request.get_json()
    email, password = data.get('email'), data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required!'}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not check_password(password, user.password):
        return jsonify({'message': 'Invalid email or password!'}), 401

    # Create token with is_verified status
    token = create_token(user)

    response = {
        'message': 'Login successful!',
        'token': token,
        'user': user.to_dict()
    }

    # Warn unverified users
    if not user.is_verified:
        response['warning'] = 'Email not verified. Some features may be restricted.'

    return jsonify(response)


# ================================================================================
# PROTECTED ROUTES - Different Levels of Access
# ================================================================================
# Two examples showing different access levels:
#
#   /profile            - Requires login AND verification
#   /profile-unverified - Requires login only
#
# Use @verified_required for:
#   - Posting content
#   - Making purchases
#   - Sending messages
#   - Any feature requiring confirmed identity
#
# Skip @verified_required for:
#   - Viewing own basic profile
#   - Accessing settings
#   - Resending verification
# ================================================================================


@app.route('/profile', methods=['GET'])
@token_required      # First: Is user logged in?
@verified_required   # Second: Is email verified?
def get_profile():
    """Get full profile - VERIFIED USERS ONLY."""
    user = User.query.get(g.current_user['user_id'])

    if not user:
        return jsonify({'message': 'User not found!'}), 404

    return jsonify({'message': 'Profile retrieved!', 'profile': user.to_dict()})


@app.route('/profile-unverified', methods=['GET'])
@token_required  # Only requires login, NOT verification
def get_profile_unverified():
    """
    Get basic profile - ANY logged-in user (verified OR unverified).

    This demonstrates allowing unverified users limited access.
    They can see their profile but might not be able to do other actions.
    """
    user = User.query.get(g.current_user['user_id'])

    return jsonify({
        'message': 'Basic profile retrieved!',
        'profile': user.to_dict(),
        'note': 'This route works for unverified users too'
    })


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    print("=" * 50)
    print("Email Verification Server Running on http://localhost:5011")
    print("=" * 50)
    app.run(debug=True, port=5011)


# ===========================================
# EXERCISES - Try These!
# ===========================================
"""
EXERCISE 1: Test Verified vs Unverified Access
----------------------------------------------
Test:
1. Register a new user (don't verify yet)
2. Login and get token
3. Try GET /profile (should fail with EMAIL_NOT_VERIFIED)
4. Try GET /profile-unverified (should work!)
5. Verify email using the verification link
6. Login again (to get updated token)
7. Try GET /profile (should work now!)

Question: Why do we need to login again after verification?
(Hint: is_verified is stored in the JWT token)


EXERCISE 2: Change Token Expiration
-----------------------------------
Current: verification_expires=datetime.utcnow() + timedelta(hours=24)

Try changing to:
    verification_expires=datetime.utcnow() + timedelta(minutes=5)

Test:
1. Register a user
2. Wait 5+ minutes
3. Try to verify email

Question: What error message do you get? Why set expiration on verification tokens?


EXERCISE 3: Rate Limit Resend Verification
------------------------------------------
Prevent spam by limiting resend requests:

In resend_verification(), before generating new token:
    # Check if recently sent (within 2 minutes)
    if user.verification_expires and user.verification_expires > datetime.utcnow() + timedelta(hours=23, minutes=58):
        return jsonify({'message': 'Please wait 2 minutes before requesting again.'}), 429

Question: Why is rate limiting important? What does status code 429 mean?


EXERCISE 4: Auto-Delete Unverified Users
----------------------------------------
Delete users who never verified after 7 days:

@app.route('/admin/cleanup-unverified', methods=['POST'])
def cleanup_unverified():
    cutoff = datetime.utcnow() - timedelta(days=7)
    unverified = User.query.filter(
        User.is_verified == False,
        User.created_at < cutoff
    ).all()
    count = len(unverified)
    for user in unverified:
        db.session.delete(user)
    db.session.commit()
    return jsonify({'message': f'Deleted {count} unverified users'})

Question: Why might you want to delete old unverified accounts?


EXERCISE 5: Add Verification Status to Login Response
-----------------------------------------------------
Show different message based on verification status:

In login(), modify the response:
    if not user.is_verified:
        response['warning'] = 'Email not verified!'
        response['verification_required'] = True
        response['can_resend'] = True
    else:
        response['verified_at'] = 'Email verified'  # You could add a verified_at column

Question: How would the frontend use this information?


EXERCISE 6: Block Login for Unverified Users
--------------------------------------------
Some apps require verification before login:

In login(), after finding user:
    if not user.is_verified:
        return jsonify({
            'message': 'Please verify your email before logging in!',
            'error': 'EMAIL_NOT_VERIFIED'
        }), 403

Question: What are pros and cons of blocking vs allowing unverified login?


SELF-STUDY QUESTIONS
--------------------
1. Why verify email? What problems does it solve?

2. Why use secrets.token_urlsafe() instead of a simple random string?

3. What's the difference between @token_required and @verified_required decorators?

4. Should users be able to change their email? What verification is needed?

5. What happens if someone registers with YOUR email? How does verification prevent abuse?
"""
