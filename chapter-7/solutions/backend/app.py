# ================================================================================
# CHAPTER 7: SOLUTIONS - Password Management
# ================================================================================

from flask import Flask, jsonify, request, g, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import secrets
import re
from datetime import datetime, timedelta
from functools import wraps
import os
import warnings
warnings.filterwarnings('ignore', message='.*Query.get.*')

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_ch7_solutions.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
SECRET_KEY = 'your-secret-key-keep-it-safe-123'
BASE_URL = 'http://localhost:5007'

db = SQLAlchemy(app)


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
    __tablename__ = 'password_reset_tokens'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='reset_tokens')


# ================================================================================
# EXERCISE 3 SOLUTION: Password History
# ================================================================================

class PasswordHistory(db.Model):
    __tablename__ = 'password_history'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


def check_password_history(user_id, new_password, history_count=3):
    """Check if password was used in last N passwords."""
    history = PasswordHistory.query.filter_by(user_id=user_id)\
        .order_by(PasswordHistory.created_at.desc())\
        .limit(history_count).all()

    for entry in history:
        if check_password_hash(entry.password_hash, new_password):
            return False  # Password was used recently
    return True  # Password is new


def add_to_password_history(user_id, password_hash):
    """Add password to history and keep only last 3."""
    entry = PasswordHistory(user_id=user_id, password_hash=password_hash)
    db.session.add(entry)

    # Clean up old entries (keep only last 3)
    old_entries = PasswordHistory.query.filter_by(user_id=user_id)\
        .order_by(PasswordHistory.created_at.desc())\
        .offset(3).all()
    for old in old_entries:
        db.session.delete(old)


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
# EXERCISE 1 SOLUTION: Password Strength Checker
# ================================================================================

@app.route('/check-password-strength', methods=['POST'])
def check_password_strength():
    data = request.get_json()
    password = data.get('password', '')

    if not password:
        return jsonify({'strength': 'none', 'suggestions': ['Password is required']}), 400

    suggestions = []
    score = 0

    # Length check
    if len(password) >= 8:
        score += 1
    else:
        suggestions.append('Use at least 8 characters')

    # Number check
    if re.search(r'[0-9]', password):
        score += 1
    else:
        suggestions.append('Add at least one number')

    # Uppercase check
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        suggestions.append('Add at least one uppercase letter')

    # Lowercase check
    if re.search(r'[a-z]', password):
        score += 1
    else:
        suggestions.append('Add at least one lowercase letter')

    # Special character check
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    else:
        suggestions.append('Add a special character (!@#$%^&*)')

    # Determine strength
    if score <= 2:
        strength = 'weak'
    elif score <= 4:
        strength = 'medium'
    else:
        strength = 'strong'

    return jsonify({
        'strength': strength,
        'score': f'{score}/5',
        'suggestions': suggestions if suggestions else ['Password is strong!']
    })


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

    hashed = hash_password(password)
    new_user = User(email=email, password=hashed)
    db.session.add(new_user)
    db.session.flush()  # Get user ID

    # Add to password history
    add_to_password_history(new_user.id, hashed)
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
# EXERCISE 2 & 3 SOLUTION: Change Password with Confirmation & History
# ================================================================================

@app.route('/change-password', methods=['POST'])
@token_required
def change_password():
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')  # EXERCISE 2

    if not current_password:
        return jsonify({'success': False, 'message': 'Current password required'}), 400

    if not new_password:
        return jsonify({'success': False, 'message': 'New password required'}), 400

    # EXERCISE 2: Confirm password validation
    if not confirm_password:
        return jsonify({'success': False, 'message': 'Please confirm your new password'}), 400

    if new_password != confirm_password:
        return jsonify({'success': False, 'message': 'Passwords do not match'}), 400

    user = User.query.get(g.current_user['user_id'])

    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    if not verify_password(current_password, user.password):
        return jsonify({'success': False, 'message': 'Current password is incorrect'}), 401

    if len(new_password) < 6:
        return jsonify({'success': False, 'message': 'New password must be at least 6 characters'}), 400

    if verify_password(new_password, user.password):
        return jsonify({'success': False, 'message': 'New password must be different'}), 400

    # EXERCISE 3: Check password history
    if not check_password_history(user.id, new_password):
        return jsonify({'success': False, 'message': 'Cannot reuse recent passwords'}), 400

    # Update password
    new_hash = hash_password(new_password)
    user.password = new_hash
    user.password_changed_at = datetime.utcnow()

    # Add to history
    add_to_password_history(user.id, new_hash)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Password changed successfully',
        'password_changed_at': user.password_changed_at.strftime('%Y-%m-%d %H:%M:%S')
    })


@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email', '').strip().lower()

    if not email:
        return jsonify({'success': False, 'message': 'Email required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'success': True, 'message': 'If email exists, reset link sent'})

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
        'reset_link': reset_link,
        'expires_in': '1 hour'
    })


# ================================================================================
# EXERCISE 2 & 4 SOLUTION: Reset Password with Confirmation & Invalidate All Tokens
# ================================================================================

@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')  # EXERCISE 2

    if not token:
        return jsonify({'success': False, 'message': 'Reset token required'}), 400

    if not new_password:
        return jsonify({'success': False, 'message': 'New password required'}), 400

    # EXERCISE 2: Confirm password validation
    if confirm_password and new_password != confirm_password:
        return jsonify({'success': False, 'message': 'Passwords do not match'}), 400

    if len(new_password) < 6:
        return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400

    token_record = PasswordResetToken.query.filter_by(token=token).first()

    if not token_record:
        return jsonify({'success': False, 'message': 'Invalid reset token'}), 400

    if token_record.used:
        return jsonify({'success': False, 'message': 'Token already used'}), 400

    if token_record.expires_at < datetime.utcnow():
        return jsonify({'success': False, 'message': 'Token expired'}), 400

    user = User.query.get(token_record.user_id)

    # Check password history
    if not check_password_history(user.id, new_password):
        return jsonify({'success': False, 'message': 'Cannot reuse recent passwords'}), 400

    # Update password
    new_hash = hash_password(new_password)
    user.password = new_hash
    user.password_changed_at = datetime.utcnow()

    # Mark current token as used
    token_record.used = True

    # EXERCISE 4: Invalidate ALL unused reset tokens for this user
    PasswordResetToken.query.filter_by(user_id=user.id, used=False).update({'used': True})

    # Add to password history
    add_to_password_history(user.id, new_hash)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Password reset successful! You can now login.',
        'email': user.email
    })


@app.route('/verify-reset-token', methods=['POST'])
def verify_reset_token():
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


if __name__ == '__main__':
    print("=" * 60)
    print("CHAPTER 7: SOLUTIONS")
    print("=" * 60)
    print("Server running at: http://localhost:5007")
    print("")
    print("Exercise Solutions:")
    print("  POST /check-password-strength - Exercise 1")
    print("  Confirm password in change/reset - Exercise 2")
    print("  Password history (no reuse) - Exercise 3")
    print("  Invalidate all tokens on reset - Exercise 4")
    print("=" * 60)
    app.run(debug=True, port=5007)
