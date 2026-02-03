# ================================================================================
# CHAPTER 6: SOLUTIONS - Email Verification
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

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_ch6_solutions.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
SECRET_KEY = 'your-secret-key-keep-it-safe-123'
BASE_URL = 'http://localhost:5006'

db = SQLAlchemy(app)


# ================================================================================
# User Model with Exercise 2 Solution (rate limit tracking)
# ================================================================================

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), unique=True, nullable=True)
    verification_expires = db.Column(db.DateTime, nullable=True)
    last_verification_sent = db.Column(db.DateTime, nullable=True)  # EXERCISE 2

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'is_verified': self.is_verified,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }


def hash_password(password):
    return generate_password_hash(password)


def verify_password(plain_password, hashed_password):
    return check_password_hash(hashed_password, plain_password)


def create_token(user):
    return jwt.encode({
        'user_id': user.id,
        'email': user.email,
        'is_verified': user.is_verified,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, SECRET_KEY, algorithm='HS256')


def generate_verification_token():
    return secrets.token_urlsafe(32)


def token_required(f):
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
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.current_user.get('is_verified'):
            return jsonify({
                'success': False,
                'message': 'Email not verified',
                'error': 'EMAIL_NOT_VERIFIED',
                'action': 'Please check your email or request a new verification link'
            }), 403
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
        return jsonify({'success': False, 'message': 'Email already exists'}), 400

    verification_token = generate_verification_token()
    now = datetime.utcnow()

    new_user = User(
        email=email,
        password=hash_password(password),
        is_verified=False,
        verification_token=verification_token,
        verification_expires=now + timedelta(hours=24),
        last_verification_sent=now  # Track when verification was sent
    )

    db.session.add(new_user)
    db.session.commit()

    verification_link = f"{BASE_URL}/verify-email?token={verification_token}"

    return jsonify({
        'success': True,
        'message': 'Registration successful! Please verify your email.',
        'user': new_user.to_dict(),
        'verification_link': verification_link
    }), 201


@app.route('/verify-email', methods=['GET'])
def verify_email():
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

    user.is_verified = True
    user.verification_token = None
    user.verification_expires = None
    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Email verified! You can now login.',
        'user': user.to_dict()
    })


# ================================================================================
# EXERCISE 2 SOLUTION: Rate Limited Resend Verification
# ================================================================================

@app.route('/resend-verification', methods=['POST'])
def resend_verification():
    data = request.get_json()
    email = data.get('email', '').strip().lower()

    if not email:
        return jsonify({'success': False, 'message': 'Email required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'success': True, 'message': 'If email exists, verification link sent'})

    if user.is_verified:
        return jsonify({'success': True, 'message': 'Email already verified'})

    # EXERCISE 2: Check rate limit
    if user.last_verification_sent:
        time_since_last = (datetime.utcnow() - user.last_verification_sent).seconds
        if time_since_last < 60:  # 1 minute cooldown
            wait_time = 60 - time_since_last
            return jsonify({
                'success': False,
                'message': f'Please wait {wait_time} seconds before requesting again',
                'retry_after': wait_time
            }), 429

    # Generate new token
    user.verification_token = generate_verification_token()
    user.verification_expires = datetime.utcnow() + timedelta(hours=24)
    user.last_verification_sent = datetime.utcnow()
    db.session.commit()

    verification_link = f"{BASE_URL}/verify-email?token={user.verification_token}"

    return jsonify({
        'success': True,
        'message': 'Verification link sent',
        'verification_link': verification_link
    })


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

    response = {
        'success': True,
        'message': 'Login successful',
        'token': create_token(user),
        'user': user.to_dict()
    }

    if not user.is_verified:
        response['warning'] = 'Email not verified. Some features restricted.'

    return jsonify(response)


# ================================================================================
# EXERCISE 1 SOLUTION: Verification Status Endpoint
# ================================================================================

@app.route('/verification-status', methods=['GET'])
@token_required
def verification_status():
    user = User.query.get(g.current_user['user_id'])

    status_message = 'Email verified' if user.is_verified else 'Please verify your email'

    return jsonify({
        'success': True,
        'email': user.email,
        'is_verified': user.is_verified,
        'registered_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'message': status_message
    })


# ================================================================================
# EXERCISE 3 SOLUTION: Verified-Only Feature Route
# ================================================================================

@app.route('/premium-feature', methods=['POST'])
@token_required
@verified_required
def premium_feature():
    return jsonify({
        'success': True,
        'message': 'Premium feature accessed!',
        'user': g.current_user['email'],
        'data': {'feature': 'premium', 'content': 'This is premium content'}
    })


# ================================================================================
# EXERCISE 4 SOLUTION: Admin Verify User
# ================================================================================

@app.route('/admin/verify-user', methods=['POST'])
def admin_verify_user():
    data = request.get_json()
    email = data.get('email', '').strip().lower()

    if not email:
        return jsonify({'success': False, 'message': 'Email required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    if user.is_verified:
        return jsonify({'success': True, 'message': 'User already verified', 'user': user.to_dict()})

    user.is_verified = True
    user.verification_token = None
    user.verification_expires = None
    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'User manually verified',
        'user': user.to_dict()
    })


@app.route('/profile', methods=['GET'])
@token_required
@verified_required
def get_profile():
    user = User.query.get(g.current_user['user_id'])
    return jsonify({'success': True, 'profile': user.to_dict()})


@app.route('/profile-basic', methods=['GET'])
@token_required
def get_profile_basic():
    user = User.query.get(g.current_user['user_id'])
    return jsonify({
        'success': True,
        'profile': user.to_dict(),
        'note': 'This works for unverified users'
    })


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    print("=" * 60)
    print("CHAPTER 6: SOLUTIONS")
    print("=" * 60)
    print("Server running at: http://localhost:5006")
    print("")
    print("Exercise Solutions:")
    print("  GET /verification-status  - Exercise 1")
    print("  POST /resend-verification - Exercise 2 (rate limited)")
    print("  POST /premium-feature     - Exercise 3")
    print("  POST /admin/verify-user   - Exercise 4")
    print("=" * 60)
    app.run(debug=True, port=5006)
