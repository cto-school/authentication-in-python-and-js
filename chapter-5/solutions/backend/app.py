# ================================================================================
# CHAPTER 5: SOLUTIONS - Error Handling & Validation
# ================================================================================

from flask import Flask, jsonify, request, g, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import re
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
import time
import os
import warnings
warnings.filterwarnings('ignore', message='.*Query.get.*')

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_ch5_solutions.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
SECRET_KEY = 'your-secret-key-keep-it-safe-123'

db = SQLAlchemy(app)


# ================================================================================
# EXERCISE 3 SOLUTION: Rate Limiter
# ================================================================================

rate_limit_store = defaultdict(list)  # IP -> [timestamps]
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 5  # requests per window


def check_rate_limit():
    """
    Check if the current IP has exceeded the rate limit.
    Returns error response if rate limited, None otherwise.
    """
    ip = request.remote_addr
    now = time.time()

    # Clean old entries
    rate_limit_store[ip] = [t for t in rate_limit_store[ip] if now - t < RATE_LIMIT_WINDOW]

    # Check if limit exceeded
    if len(rate_limit_store[ip]) >= RATE_LIMIT_MAX:
        oldest = min(rate_limit_store[ip])
        wait_time = int(RATE_LIMIT_WINDOW - (now - oldest))
        return jsonify({
            'success': False,
            'error': {
                'code': 'RATE_LIMIT_ERROR',
                'message': f'Too many requests. Try again in {wait_time} seconds.',
                'retry_after': wait_time
            }
        }), 429

    # Add current request
    rate_limit_store[ip].append(now)
    return None


# ================================================================================
# EXERCISE 4 SOLUTION: Global Request Logger
# ================================================================================

@app.before_request
def log_request():
    """Log every request to the console."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    method = request.method
    path = request.path
    ip = request.remote_addr

    # Skip static files
    if not path.startswith('/static'):
        print(f"[{timestamp}] {method} {path} from {ip}")


# ================================================================================
# Response Helpers
# ================================================================================

def error_response(code, message, field=None, status_code=400):
    response = {
        'success': False,
        'error': {'code': code, 'message': message}
    }
    if field:
        response['error']['field'] = field
    return jsonify(response), status_code


def success_response(data, message="Success"):
    return jsonify({'success': True, 'message': message, 'data': data})


# ================================================================================
# EXERCISE 1 SOLUTION: Enhanced Password Validation
# ================================================================================

def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_password(password):
    """
    Validate password strength.
    Returns (is_valid, list of error messages)
    """
    errors = []

    if len(password) < 8:
        errors.append('Password must be at least 8 characters')

    if not any(c.isdigit() for c in password):
        errors.append('Password must contain at least one number')

    if not any(c.isupper() for c in password):
        errors.append('Password must contain at least one uppercase letter')

    if not any(c.islower() for c in password):
        errors.append('Password must contain at least one lowercase letter')

    return len(errors) == 0, errors


def validate_registration(email, password):
    """Validate both email and password."""
    if not email:
        return False, error_response('VALIDATION_ERROR', 'Email is required', 'email')

    if not is_valid_email(email):
        return False, error_response('VALIDATION_ERROR', 'Invalid email format', 'email')

    if len(email) > 120:
        return False, error_response('VALIDATION_ERROR', 'Email too long (max 120)', 'email')

    if not password:
        return False, error_response('VALIDATION_ERROR', 'Password is required', 'password')

    # Exercise 1: Enhanced password validation
    is_valid, password_errors = validate_password(password)
    if not is_valid:
        return False, error_response('VALIDATION_ERROR', password_errors[0], 'password')

    return True, None


# ================================================================================
# Models
# ================================================================================

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
    return generate_password_hash(password)


def verify_password(plain_password, hashed_password):
    return check_password_hash(hashed_password, plain_password)


def create_token(user):
    return jwt.encode({
        'user_id': user.id,
        'email': user.email,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, SECRET_KEY, algorithm='HS256')


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return error_response('AUTH_ERROR', 'Token is missing', status_code=401)
        try:
            parts = auth_header.split(' ')
            if len(parts) != 2 or parts[0] != 'Bearer':
                return error_response('AUTH_ERROR', 'Invalid token format', status_code=401)
            decoded = jwt.decode(parts[1], SECRET_KEY, algorithms=['HS256'])
            g.current_user = {'user_id': decoded['user_id'], 'email': decoded['email']}
        except jwt.ExpiredSignatureError:
            return error_response('TOKEN_EXPIRED', 'Token has expired', status_code=401)
        except jwt.InvalidTokenError:
            return error_response('TOKEN_INVALID', 'Invalid token', status_code=401)
        return f(*args, **kwargs)
    return decorated


# Global error handlers
@app.errorhandler(404)
def not_found(error):
    return error_response('NOT_FOUND', 'Resource not found', status_code=404)


@app.errorhandler(500)
def server_error(error):
    return error_response('SERVER_ERROR', 'Something went wrong', status_code=500)


# ================================================================================
# Routes
# ================================================================================

@app.route('/')
def index():
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    return send_file(html_path)


@app.route('/register', methods=['POST'])
def register():
    # Check rate limit first
    rate_limit_error = check_rate_limit()
    if rate_limit_error:
        return rate_limit_error

    try:
        data = request.get_json()
        if not data:
            return error_response('VALIDATION_ERROR', 'Request body required')

        email = data.get('email', '').strip().lower()
        password = data.get('password', '')

        is_valid, err = validate_registration(email, password)
        if not is_valid:
            return err

        if User.query.filter_by(email=email).first():
            return error_response('ALREADY_EXISTS', 'Email already registered', 'email', 409)

        new_user = User(email=email, password=hash_password(password))
        db.session.add(new_user)
        db.session.commit()

        return success_response(new_user.to_dict(), 'Registration successful!'), 201

    except Exception as e:
        app.logger.error(f'Registration error: {e}')
        db.session.rollback()
        return error_response('SERVER_ERROR', 'Registration failed')


@app.route('/login', methods=['POST'])
def login():
    rate_limit_error = check_rate_limit()
    if rate_limit_error:
        return rate_limit_error

    try:
        data = request.get_json()
        if not data:
            return error_response('VALIDATION_ERROR', 'Request body required')

        email = data.get('email', '').strip().lower()
        password = data.get('password', '')

        if not email:
            return error_response('VALIDATION_ERROR', 'Email is required', 'email')
        if not password:
            return error_response('VALIDATION_ERROR', 'Password is required', 'password')

        user = User.query.filter_by(email=email).first()
        if not user or not verify_password(password, user.password):
            return error_response('AUTH_ERROR', 'Invalid email or password', status_code=401)

        return success_response({
            'token': create_token(user),
            'user': user.to_dict()
        }, 'Login successful!')

    except Exception as e:
        app.logger.error(f'Login error: {e}')
        return error_response('SERVER_ERROR', 'Login failed')


# ================================================================================
# EXERCISE 2 SOLUTION: Validation Endpoint
# ================================================================================

@app.route('/validate', methods=['POST'])
def validate_input():
    """
    Validate email and password without creating a user.
    Returns ALL validation errors at once.
    """
    data = request.get_json()
    if not data:
        return jsonify({
            'valid': False,
            'errors': [{'field': 'body', 'message': 'Request body required'}]
        }), 400

    email = data.get('email', '').strip()
    password = data.get('password', '')

    errors = []

    # Validate email
    if not email:
        errors.append({'field': 'email', 'message': 'Email is required'})
    elif not is_valid_email(email):
        errors.append({'field': 'email', 'message': 'Invalid email format'})
    elif len(email) > 120:
        errors.append({'field': 'email', 'message': 'Email too long (max 120 characters)'})

    # Validate password with all rules
    if not password:
        errors.append({'field': 'password', 'message': 'Password is required'})
    else:
        _, password_errors = validate_password(password)
        for err in password_errors:
            errors.append({'field': 'password', 'message': err})

    return jsonify({
        'valid': len(errors) == 0,
        'errors': errors
    })


# Test endpoint for different error types
@app.route('/test-error/<error_type>')
def test_error(error_type):
    if error_type == 'validation':
        return error_response('VALIDATION_ERROR', 'Test validation error', 'test_field')
    elif error_type == 'auth':
        return error_response('AUTH_ERROR', 'Test auth error', status_code=401)
    elif error_type == 'notfound':
        return error_response('NOT_FOUND', 'Test not found', status_code=404)
    elif error_type == 'server':
        return error_response('SERVER_ERROR', 'Test server error', status_code=500)
    elif error_type == 'ratelimit':
        # Force add requests to trigger rate limit
        ip = request.remote_addr
        for _ in range(RATE_LIMIT_MAX):
            rate_limit_store[ip].append(time.time())
        return check_rate_limit() or success_response({'message': 'Rate limit not triggered'})
    return success_response({'type': error_type}, 'Unknown error type')


@app.route('/profile', methods=['GET'])
@token_required
def get_profile():
    user = User.query.get(g.current_user['user_id'])
    if not user:
        return error_response('NOT_FOUND', 'User not found', status_code=404)
    return success_response(user.to_dict(), 'Profile retrieved')


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    print("=" * 60)
    print("CHAPTER 5: SOLUTIONS")
    print("=" * 60)
    print("Server running at: http://localhost:5005")
    print("")
    print("Exercise Solutions:")
    print("  Enhanced password validation (Ex 1)")
    print("  POST /validate     - Exercise 2")
    print("  Rate limiting      - Exercise 3")
    print("  Request logging    - Exercise 4 (check console)")
    print("=" * 60)
    app.run(debug=True, port=5005)
