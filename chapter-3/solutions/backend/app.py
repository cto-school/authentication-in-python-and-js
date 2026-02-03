# ================================================================================
# CHAPTER 3: SOLUTIONS - User Login & JWT Tokens
# ================================================================================
# This file contains solutions to all exercises from Chapter 3.
# ================================================================================

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
import os
import warnings
warnings.filterwarnings('ignore', message='.*Query.get.*')

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_ch3_solutions.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
SECRET_KEY = 'your-secret-key-keep-it-safe-123'

db = SQLAlchemy(app)


# ================================================================================
# EXERCISE 1 & 3 SOLUTION: Add last_login and login_count Fields
# ================================================================================

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)  # EXERCISE 1
    login_count = db.Column(db.Integer, default=0)       # EXERCISE 3

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'last_login': self.last_login.strftime('%Y-%m-%d %H:%M:%S') if self.last_login else None,
            'login_count': self.login_count
        }


def hash_password(password):
    return generate_password_hash(password)


def verify_password(plain_password, hashed_password):
    return check_password_hash(hashed_password, plain_password)


# ================================================================================
# EXERCISE 2 SOLUTION: Remember Me Feature
# ================================================================================
# Create tokens with different expiration times based on remember_me flag
# ================================================================================

def create_token(user, remember_me=False):
    """
    Create JWT token with configurable expiration.

    Args:
        user: User object
        remember_me: If True, token expires in 30 days; otherwise 24 hours
    """
    if remember_me:
        expiration = timedelta(days=30)
        expires_in_text = '30 days'
    else:
        expiration = timedelta(hours=24)
        expires_in_text = '24 hours'

    payload = {
        'user_id': user.id,
        'email': user.email,
        'exp': datetime.utcnow() + expiration,
        'iat': datetime.utcnow(),  # Issued at
        'remember_me': remember_me
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

    return token, expires_in_text


@app.route('/')
def index():
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    return send_file(html_path)


@app.route('/register', methods=['POST'])
def register():
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


# ================================================================================
# Modified Login with Exercises 1, 2, 3 Solutions
# ================================================================================

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    remember_me = data.get('remember_me', False)  # EXERCISE 2

    if not email or not password:
        return jsonify({'message': 'Email and password are required!'}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'message': 'Invalid email or password!'}), 401

    if not verify_password(password, user.password):
        return jsonify({'message': 'Invalid email or password!'}), 401

    # EXERCISE 1: Update last_login
    user.last_login = datetime.utcnow()

    # EXERCISE 3: Increment login_count
    user.login_count += 1

    db.session.commit()

    # EXERCISE 2: Create token with remember_me option
    token, expires_in = create_token(user, remember_me)

    return jsonify({
        'message': 'Login successful!',
        'token': token,
        'expires_in': expires_in,
        'remember_me': remember_me,
        'user': user.to_dict()
    })


# ================================================================================
# EXERCISE 4 SOLUTION: Token Info Endpoint
# ================================================================================
# This endpoint reads and decodes a token from the Authorization header.
# Good practice for understanding how @token_required will work in Chapter 4!
# ================================================================================

@app.route('/token-info', methods=['GET'])
def token_info():
    # Get Authorization header
    auth_header = request.headers.get('Authorization')

    if not auth_header:
        return jsonify({
            'valid': False,
            'error': 'Authorization header is missing',
            'hint': 'Send header: Authorization: Bearer <your_token>'
        }), 401

    # Parse "Bearer <token>" format
    parts = auth_header.split(' ')

    if len(parts) != 2 or parts[0] != 'Bearer':
        return jsonify({
            'valid': False,
            'error': 'Invalid Authorization header format',
            'expected': 'Bearer <token>',
            'received': auth_header
        }), 401

    token = parts[1]

    try:
        # Decode the token
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

        # Calculate time until expiration
        exp_timestamp = decoded['exp']
        exp_datetime = datetime.fromtimestamp(exp_timestamp)
        now = datetime.utcnow()
        time_remaining = exp_datetime - now

        return jsonify({
            'valid': True,
            'payload': {
                'user_id': decoded['user_id'],
                'email': decoded['email'],
                'issued_at': datetime.fromtimestamp(decoded.get('iat', 0)).strftime('%Y-%m-%d %H:%M:%S'),
                'expires_at': exp_datetime.strftime('%Y-%m-%d %H:%M:%S'),
                'remember_me': decoded.get('remember_me', False)
            },
            'time_remaining': {
                'seconds': int(time_remaining.total_seconds()),
                'human_readable': str(time_remaining).split('.')[0]  # Remove microseconds
            }
        })

    except jwt.ExpiredSignatureError:
        return jsonify({
            'valid': False,
            'error': 'Token has expired',
            'hint': 'Login again to get a new token'
        }), 401

    except jwt.InvalidTokenError as e:
        return jsonify({
            'valid': False,
            'error': 'Invalid token',
            'details': str(e)
        }), 401


# ================================================================================
# Bonus: Get all users (for testing)
# ================================================================================

@app.route('/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify({
        'users': [u.to_dict() for u in users]
    })


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    print("=" * 60)
    print("CHAPTER 3: SOLUTIONS")
    print("=" * 60)
    print("Server running at: http://localhost:5003")
    print("")
    print("Exercise Solutions:")
    print("  User model now has: last_login (Ex 1), login_count (Ex 3)")
    print("  POST /login    - Now supports remember_me (Ex 2)")
    print("  GET /token-info - Exercise 4")
    print("=" * 60)
    app.run(debug=True, port=5003)
