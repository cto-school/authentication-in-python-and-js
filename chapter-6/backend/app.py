# ================================================================================
# CHAPTER 6: Email Verification
# ================================================================================
#
# This chapter covers:
#   1. Adding is_verified field to User model
#   2. Generating secure verification tokens
#   3. Verification flow (register → verify → access features)
#   4. @verified_required decorator
#   5. Resend verification functionality
#
# WHY VERIFY EMAILS?
#   - Prevent fake accounts
#   - Prevent impersonation
#   - Enable password recovery
#   - Reduce spam
#
# ================================================================================

from flask import Flask, jsonify, request, g, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import secrets  # For generating secure tokens
from datetime import datetime, timedelta
from functools import wraps
import os
import warnings
warnings.filterwarnings('ignore', message='.*Query.get.*')

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_ch6.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
SECRET_KEY = 'your-secret-key-keep-it-safe-123'
BASE_URL = 'http://localhost:5006'

db = SQLAlchemy(app)


# ================================================================================
# USER MODEL WITH VERIFICATION
# ================================================================================


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Verification fields
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), unique=True, nullable=True)
    verification_expires = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'is_verified': self.is_verified,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }


# ================================================================================
# HELPER FUNCTIONS
# ================================================================================


def hash_password(password):
    return generate_password_hash(password)


def verify_password(plain_password, hashed_password):
    return check_password_hash(hashed_password, plain_password)


def create_token(user):
    """JWT now includes is_verified status."""
    return jwt.encode({
        'user_id': user.id,
        'email': user.email,
        'is_verified': user.is_verified,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, SECRET_KEY, algorithm='HS256')


def generate_verification_token():
    """Generate a secure random token for email verification."""
    return secrets.token_urlsafe(32)


# ================================================================================
# DECORATORS
# ================================================================================


def token_required(f):
    """Require valid JWT token (logged in)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')

        if not auth_header:
            return jsonify({'success': False, 'message': 'Token is missing'}), 401

        try:
            parts = auth_header.split(' ')
            if len(parts) != 2 or parts[0] != 'Bearer':
                return jsonify({'success': False, 'message': 'Invalid token format'}), 401

            decoded = jwt.decode(parts[1], SECRET_KEY, algorithms=['HS256'])
            g.current_user = {
                'user_id': decoded['user_id'],
                'email': decoded['email'],
                'is_verified': decoded.get('is_verified', False)
            }

        except jwt.ExpiredSignatureError:
            return jsonify({'success': False, 'message': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'success': False, 'message': 'Invalid token'}), 401

        return f(*args, **kwargs)
    return decorated


def verified_required(f):
    """Require verified email. Use AFTER @token_required."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.current_user.get('is_verified'):
            return jsonify({
                'success': False,
                'message': 'Email not verified',
                'error': 'EMAIL_NOT_VERIFIED'
            }), 403
        return f(*args, **kwargs)
    return decorated


# ================================================================================
# ROUTES
# ================================================================================


@app.route('/')
def index():
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    return send_file(html_path)


@app.route('/register', methods=['POST'])
def register():
    """Register creates unverified user with verification token."""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': 'Email already exists'}), 400

    # Generate verification token
    verification_token = generate_verification_token()

    new_user = User(
        email=email,
        password=hash_password(password),
        is_verified=False,
        verification_token=verification_token,
        verification_expires=datetime.utcnow() + timedelta(hours=24)
    )

    db.session.add(new_user)
    db.session.commit()

    # In production, send this link via email!
    verification_link = f"{BASE_URL}/verify-email?token={verification_token}"

    return jsonify({
        'success': True,
        'message': 'Registration successful! Please verify your email.',
        'user': new_user.to_dict(),
        'verification_link': verification_link,  # Only for testing!
        'note': 'In production, this link would be sent via email'
    }), 201


@app.route('/verify-email', methods=['GET'])
def verify_email():
    """Verify email using token from link."""
    token = request.args.get('token')

    if not token:
        return jsonify({'success': False, 'message': 'Token required'}), 400

    user = User.query.filter_by(verification_token=token).first()

    if not user:
        return jsonify({'success': False, 'message': 'Invalid token'}), 400

    if user.is_verified:
        return jsonify({'success': True, 'message': 'Already verified'})

    if user.verification_expires < datetime.utcnow():
        return jsonify({'success': False, 'message': 'Token expired'}), 400

    # Verify the user
    user.is_verified = True
    user.verification_token = None
    user.verification_expires = None
    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Email verified! You can now login.',
        'user': user.to_dict()
    })


@app.route('/resend-verification', methods=['POST'])
def resend_verification():
    """Resend verification email."""
    data = request.get_json()
    email = data.get('email', '').strip().lower()

    if not email:
        return jsonify({'success': False, 'message': 'Email required'}), 400

    user = User.query.filter_by(email=email).first()

    # Don't reveal if email exists
    if not user:
        return jsonify({'success': True, 'message': 'If email exists, verification link sent'})

    if user.is_verified:
        return jsonify({'success': True, 'message': 'Email already verified'})

    # Generate new token
    user.verification_token = generate_verification_token()
    user.verification_expires = datetime.utcnow() + timedelta(hours=24)
    db.session.commit()

    verification_link = f"{BASE_URL}/verify-email?token={user.verification_token}"

    return jsonify({
        'success': True,
        'message': 'Verification link sent',
        'verification_link': verification_link  # Only for testing
    })


@app.route('/login', methods=['POST'])
def login():
    """Login works for both verified and unverified users."""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not verify_password(password, user.password):
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

    response = {
        'success': True,
        'message': 'Login successful',
        'token': create_token(user),
        'user': user.to_dict()
    }

    if not user.is_verified:
        response['warning'] = 'Email not verified. Some features restricted.'

    return jsonify(response)


@app.route('/profile', methods=['GET'])
@token_required
@verified_required  # Requires verified email!
def get_profile():
    """Protected route - requires verification."""
    user = User.query.get(g.current_user['user_id'])
    return jsonify({'success': True, 'profile': user.to_dict()})


@app.route('/profile-basic', methods=['GET'])
@token_required  # Only requires login, not verification
def get_profile_basic():
    """Route accessible by unverified users too."""
    user = User.query.get(g.current_user['user_id'])
    return jsonify({
        'success': True,
        'profile': user.to_dict(),
        'note': 'This works for unverified users'
    })


with app.app_context():
    db.create_all()


# ================================================================================
# KEY TAKEAWAYS - Chapter 6
# ================================================================================
#
# 1. EMAIL VERIFICATION FLOW:
#    Register → Receive verification link → Click link → Email verified!
#    User can login before verifying, but some features are restricted.
#
# 2. WHY VERIFY EMAILS?
#    - Prevents fake accounts (using others' emails)
#    - Enables password recovery (we know the email is real)
#    - Reduces spam registrations
#    - Required for many features (notifications, receipts, etc.)
#
# 3. STACKING DECORATORS:
#    @token_required      ← Runs FIRST (checks if logged in)
#    @verified_required   ← Runs SECOND (checks if email verified)
#    def my_route():
#
#    Order matters! @verified_required assumes g.current_user exists.
#
# 4. SECURITY: secrets.token_urlsafe(32)
#    - Generates cryptographically secure random tokens
#    - 32 bytes = 256 bits of randomness
#    - URL-safe means no characters that need encoding
#
# 5. TOKEN EXPIRATION:
#    - Verification tokens expire (24 hours in this example)
#    - After verification, we clear the token (set to None)
#    - This prevents token reuse
#
# 6. FRONTEND: Verification link handling
#    In production, the link is sent via email. For testing, we show it directly.
#    The link format: http://localhost:5006/verify-email?token=abc123...
#
#    TRY THIS - Follow the complete verification flow:
#    - Register a new user → Note the verification_link in the response
#    - Login with that user → Notice "warning": "Email not verified"
#    - Click "Test /profile (verified)" → 403 "Email not verified"
#    - Click the verification link (or paste it in browser)
#    - Login AGAIN → No warning this time, is_verified: true in response
#    - Click "Test /profile (verified)" → Now it works!
#
#    WHY LOGIN AGAIN? The JWT token contains is_verified status. After you
#    verify your email, you need a NEW token that has is_verified: true.
#
# NEXT CHAPTER: Password management (change password & forgot password flows).
#
# ================================================================================


# ================================================================================
# EXERCISES - Test Your Understanding!
# ================================================================================
#
# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 1: Verification Status Endpoint (Easy)
# ────────────────────────────────────────────────────────────────────────────────
# Create an endpoint GET /verification-status that:
# - Requires authentication (@token_required)
# - Returns the user's verification status and when they registered
#
# Test: curl http://localhost:5006/verification-status \
#       -H "Authorization: Bearer eyJ..."
#
# Expected: {
#   "email": "test@test.com",
#   "is_verified": false,
#   "registered_at": "2024-01-15 10:30:00",
#   "message": "Please verify your email"  (or "Email verified" if true)
# }
# ────────────────────────────────────────────────────────────────────────────────

# YOUR CODE HERE:
# @app.route('/verification-status', methods=['GET'])
# @token_required
# def verification_status():
#     pass


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 2: Rate Limit Resend Verification (Medium)
# ────────────────────────────────────────────────────────────────────────────────
# Modify /resend-verification to prevent spam:
# - Add 'last_verification_sent' field to User model (DateTime, nullable)
# - Only allow resending if last sent > 1 minute ago
# - Return error with remaining wait time if too soon
#
# Test: Call /resend-verification twice quickly
#
# Expected (too soon): {
#   "success": false,
#   "message": "Please wait 45 seconds before requesting again"
# }
#
# HINT: Check (datetime.utcnow() - user.last_verification_sent).seconds < 60
# NOTE: Delete users.db after modifying the model!
# ────────────────────────────────────────────────────────────────────────────────


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 3: Verified-Only Feature Route (Medium)
# ────────────────────────────────────────────────────────────────────────────────
# Create an endpoint POST /premium-feature that:
# - Requires both authentication AND email verification
# - Simulates a premium feature (just return success message)
# - Returns helpful error if not verified (with resend link hint)
#
# Test as unverified user: Should get 403 with helpful message
# Test as verified user: Should get 200 with success
#
# Expected (unverified): {
#   "success": false,
#   "message": "This feature requires email verification",
#   "action": "Please check your email or request a new verification link"
# }
# ────────────────────────────────────────────────────────────────────────────────

# YOUR CODE HERE:
# @app.route('/premium-feature', methods=['POST'])
# @token_required
# @verified_required
# def premium_feature():
#     pass


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 4: Admin Verify User Endpoint (Hard)
# ────────────────────────────────────────────────────────────────────────────────
# Create an endpoint POST /admin/verify-user that:
# - Accepts JSON body with 'email' field
# - Manually verifies a user (admin override, bypassing email)
# - For now, no actual admin check - just implement the logic
#
# In a real app, this would be admin-only. For learning, anyone can call it.
#
# Test: curl -X POST http://localhost:5006/admin/verify-user \
#       -H "Content-Type: application/json" \
#       -d '{"email": "unverified@test.com"}'
#
# Expected: {"success": true, "message": "User manually verified", "user": {...}}
#
# HINT: Find user by email, set is_verified=True, clear verification_token
# ────────────────────────────────────────────────────────────────────────────────

# YOUR CODE HERE:
# @app.route('/admin/verify-user', methods=['POST'])
# def admin_verify_user():
#     pass


# ================================================================================


if __name__ == '__main__':
    print("=" * 60)
    print("CHAPTER 6: Email Verification")
    print("=" * 60)
    print("Server running at: http://localhost:5006")
    print("")
    print("Flow: Register → Get link → Verify → Login → Access")
    print("=" * 60)
    app.run(debug=True, port=5006)
