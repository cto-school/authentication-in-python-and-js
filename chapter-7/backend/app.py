# ================================================================================
# CHAPTER 7: Password Management
# ================================================================================
#
# This chapter covers TWO password flows:
#
# SECTION A: Change Password (user is logged in)
#   - Requires current password verification
#   - User knows their current password
#
# SECTION B: Forgot Password / Reset (user is NOT logged in)
#   - User forgot their password
#   - Uses email reset token
#
# ================================================================================

from flask import Flask, jsonify, request, g, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import secrets
from datetime import datetime, timedelta
from functools import wraps
import os
import warnings
warnings.filterwarnings('ignore', message='.*Query.get.*')

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_ch7.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
SECRET_KEY = 'your-secret-key-keep-it-safe-123'
BASE_URL = 'http://localhost:5007'

db = SQLAlchemy(app)


# ================================================================================
# MODELS
# ================================================================================


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    password_changed_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'password_changed_at': self.password_changed_at.strftime('%Y-%m-%d %H:%M:%S') if self.password_changed_at else None
        }


class PasswordResetToken(db.Model):
    """Stores password reset tokens for forgot password flow."""
    __tablename__ = 'password_reset_tokens'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='reset_tokens')


# ================================================================================
# HELPERS
# ================================================================================


def hash_password(password):
    return generate_password_hash(password)


def verify_password(plain_password, hashed_password):
    return check_password_hash(hashed_password, plain_password)


def create_token(user):
    return jwt.encode({
        'user_id': user.id,
        'email': user.email,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, SECRET_KEY, algorithm='HS256')


def generate_reset_token():
    return secrets.token_urlsafe(32)


def token_required(f):
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


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password required'}), 400

    if len(password) < 6:
        return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': 'Email already exists'}), 400

    new_user = User(email=email, password=hash_password(password))
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Registered!', 'user': new_user.to_dict()}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not verify_password(password, user.password):
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

    return jsonify({
        'success': True,
        'message': 'Login successful',
        'token': create_token(user),
        'user': user.to_dict()
    })


# ================================================================================
# SECTION A: CHANGE PASSWORD (User is logged in)
# ================================================================================
# Flow:
#   1. User is logged in (has token)
#   2. User provides current password + new password
#   3. Verify current password is correct
#   4. Validate new password
#   5. Update password
# ================================================================================


@app.route('/change-password', methods=['POST'])
@token_required
def change_password():
    """Change password for logged-in user. Requires current password."""
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')

    if not current_password:
        return jsonify({'success': False, 'message': 'Current password required'}), 400

    if not new_password:
        return jsonify({'success': False, 'message': 'New password required'}), 400

    user = User.query.get(g.current_user['user_id'])

    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    # Verify current password
    if not verify_password(current_password, user.password):
        return jsonify({'success': False, 'message': 'Current password is incorrect'}), 401

    # Validate new password
    if len(new_password) < 6:
        return jsonify({'success': False, 'message': 'New password must be at least 6 characters'}), 400

    # Check new password is different
    if verify_password(new_password, user.password):
        return jsonify({'success': False, 'message': 'New password must be different'}), 400

    # Update password
    user.password = hash_password(new_password)
    user.password_changed_at = datetime.utcnow()
    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Password changed successfully',
        'password_changed_at': user.password_changed_at.strftime('%Y-%m-%d %H:%M:%S')
    })


# ================================================================================
# SECTION B: FORGOT PASSWORD / RESET (User is NOT logged in)
# ================================================================================
# Flow:
#   1. User clicks "Forgot Password"
#   2. User enters email
#   3. Server generates reset token, sends email (or shows link for testing)
#   4. User clicks link with token
#   5. User enters new password
#   6. Server verifies token and updates password
# ================================================================================


@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    """Request password reset. Generates reset token."""
    data = request.get_json()
    email = data.get('email', '').strip().lower()

    if not email:
        return jsonify({'success': False, 'message': 'Email required'}), 400

    user = User.query.filter_by(email=email).first()

    # Don't reveal if email exists (security)
    if not user:
        return jsonify({'success': True, 'message': 'If email exists, reset link sent'})

    # Generate reset token
    reset_token = generate_reset_token()

    token_record = PasswordResetToken(
        user_id=user.id,
        token=reset_token,
        expires_at=datetime.utcnow() + timedelta(hours=1)
    )
    db.session.add(token_record)
    db.session.commit()

    reset_link = f"{BASE_URL}/reset-password?token={reset_token}"

    return jsonify({
        'success': True,
        'message': 'Reset link generated',
        'reset_link': reset_link,  # Only for testing!
        'note': 'In production, this would be sent via email',
        'expires_in': '1 hour'
    })


@app.route('/reset-password', methods=['POST'])
def reset_password():
    """Reset password using token from email link."""
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')

    if not token:
        return jsonify({'success': False, 'message': 'Reset token required'}), 400

    if not new_password:
        return jsonify({'success': False, 'message': 'New password required'}), 400

    if len(new_password) < 6:
        return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400

    # Find token
    token_record = PasswordResetToken.query.filter_by(token=token).first()

    if not token_record:
        return jsonify({'success': False, 'message': 'Invalid reset token'}), 400

    if token_record.used:
        return jsonify({'success': False, 'message': 'Token already used'}), 400

    if token_record.expires_at < datetime.utcnow():
        return jsonify({'success': False, 'message': 'Token expired'}), 400

    # Update password
    user = User.query.get(token_record.user_id)
    user.password = hash_password(new_password)
    user.password_changed_at = datetime.utcnow()

    # Mark token as used
    token_record.used = True

    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Password reset successful! You can now login.',
        'email': user.email
    })


@app.route('/verify-reset-token', methods=['POST'])
def verify_reset_token():
    """Verify if reset token is valid (before showing reset form)."""
    data = request.get_json()
    token = data.get('token')

    if not token:
        return jsonify({'valid': False, 'message': 'Token required'}), 400

    token_record = PasswordResetToken.query.filter_by(token=token).first()

    if not token_record:
        return jsonify({'valid': False, 'message': 'Invalid token'})

    if token_record.used:
        return jsonify({'valid': False, 'message': 'Token already used'})

    if token_record.expires_at < datetime.utcnow():
        return jsonify({'valid': False, 'message': 'Token expired'})

    return jsonify({
        'valid': True,
        'message': 'Token is valid',
        'email': token_record.user.email
    })


with app.app_context():
    db.create_all()


# ================================================================================
# KEY TAKEAWAYS - Chapter 7
# ================================================================================
#
# 1. TWO DIFFERENT PASSWORD FLOWS:
#
#    CHANGE PASSWORD (user is logged in):
#    - User knows current password
#    - Must verify current password before allowing change
#    - Requires authentication token
#
#    FORGOT PASSWORD (user is NOT logged in):
#    - User doesn't know their password
#    - Uses email to receive reset link
#    - No authentication required (they can't login!)
#
# 2. RESET TOKENS ARE ONE-TIME USE:
#    - Mark token as 'used' after password reset
#    - Prevents replay attacks (using same link twice)
#    - Also have expiration time (1 hour is common)
#
# 3. SECURITY: Don't reveal if email exists!
#    /forgot-password returns same message whether email exists or not.
#    "If email exists, reset link sent" - attacker learns nothing.
#
# 4. SEPARATE MODEL FOR RESET TOKENS:
#    PasswordResetToken has: user_id, token, expires_at, used
#    This allows:
#    - Multiple reset requests (only latest works)
#    - Audit trail of reset attempts
#    - Easy cleanup of expired tokens
#
# 5. FRONTEND: Complete password reset flow
#
#    TRY THIS - Change Password (logged in):
#    - Register and login (check localStorage has token)
#    - In "Change Password" section, enter current + new password
#    - Success! Now logout and login with NEW password
#
#    TRY THIS - Forgot Password (not logged in):
#    - Click "Clear Token" to simulate being logged out
#    - Enter your email in "Forgot Password" section
#    - Copy the reset_link from the response
#    - The link contains a token: ?token=abc123...
#    - In "Reset Password" section, paste token + new password
#    - Success! Now login with the NEW password
#
#    TRY THIS - See token security in action:
#    - Use the same reset link again → "Token already used"
#    - This prevents attackers from reusing intercepted links!
#
# MILESTONE: You now have production-ready authentication!
# NEXT CHAPTER: Refresh tokens for better security and UX.
#
# ================================================================================


# ================================================================================
# EXERCISES - Test Your Understanding!
# ================================================================================
#
# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 1: Password Strength Checker (Easy)
# ────────────────────────────────────────────────────────────────────────────────
# Create an endpoint POST /check-password-strength that:
# - Accepts JSON body with 'password' field
# - Returns a strength score (weak/medium/strong) based on:
#   - weak: < 8 chars or no numbers
#   - medium: 8+ chars with numbers
#   - strong: 8+ chars with numbers AND uppercase AND special char
#
# Test: curl -X POST http://localhost:5007/check-password-strength \
#       -H "Content-Type: application/json" \
#       -d '{"password": "abc123"}'
#
# Expected: {"strength": "weak", "suggestions": ["Use at least 8 characters"]}
# ────────────────────────────────────────────────────────────────────────────────

# YOUR CODE HERE:
# @app.route('/check-password-strength', methods=['POST'])
# def check_password_strength():
#     pass


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 2: Confirm Password Validation (Easy)
# ────────────────────────────────────────────────────────────────────────────────
# Modify /change-password and /reset-password to:
# - Require 'confirm_password' field that must match 'new_password'
# - Return clear error if they don't match
#
# Test: curl -X POST http://localhost:5007/reset-password \
#       -H "Content-Type: application/json" \
#       -d '{"token": "...", "new_password": "abc", "confirm_password": "xyz"}'
#
# Expected: {"success": false, "message": "Passwords do not match"}
# ────────────────────────────────────────────────────────────────────────────────


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 3: Password History (Hard)
# ────────────────────────────────────────────────────────────────────────────────
# Prevent users from reusing their last 3 passwords:
# - Create a PasswordHistory model (user_id, password_hash, created_at)
# - On password change, check new password against history
# - Store new password in history after successful change
# - Only keep last 3 entries per user
#
# Test: Change password to "Password1", then try changing back to "Password1"
#
# Expected: {"success": false, "message": "Cannot reuse recent passwords"}
#
# HINT: Create new model, check with check_password_hash against each history entry
# ────────────────────────────────────────────────────────────────────────────────

# YOUR CODE HERE:
# class PasswordHistory(db.Model):
#     __tablename__ = 'password_history'
#     id = db.Column(db.Integer, primary_key=True)
#     user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
#     password_hash = db.Column(db.String(255), nullable=False)
#     created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 4: Invalidate All Reset Tokens (Medium)
# ────────────────────────────────────────────────────────────────────────────────
# When a user successfully resets their password:
# - Mark ALL their unused reset tokens as used (not just the one they used)
# - This prevents old tokens from being used after password is changed
#
# Modify the /reset-password endpoint to implement this.
#
# Test: Request reset twice (get 2 tokens), use first token, try second token
#
# Expected with second token: {"success": false, "message": "Token already used"}
#
# HINT: PasswordResetToken.query.filter_by(user_id=user.id, used=False).update({'used': True})
# ────────────────────────────────────────────────────────────────────────────────


# ================================================================================


if __name__ == '__main__':
    print("=" * 60)
    print("CHAPTER 7: Password Management")
    print("=" * 60)
    print("Server running at: http://localhost:5007")
    print("")
    print("Section A: Change Password (logged in)")
    print("  POST /change-password")
    print("")
    print("Section B: Forgot Password (not logged in)")
    print("  POST /forgot-password")
    print("  POST /reset-password")
    print("=" * 60)
    app.run(debug=True, port=5007)
