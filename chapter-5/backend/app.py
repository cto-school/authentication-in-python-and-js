# ================================================================================
# CHAPTER 5: Error Handling & Validation
# ================================================================================
#
# This chapter covers:
#   1. Standardized error/success response format
#   2. Input validation with helpful messages
#   3. HTTP status codes and when to use them
#   4. Global error handlers
#   5. Try-except with database rollback
#
# WHY NOW? Before adding more features, we need solid error handling.
# Otherwise, users get confusing errors and debugging is hard.
#
# KEY PRINCIPLE: Never expose internal errors to users!
#
# ================================================================================

from flask import Flask, jsonify, request, g, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import re  # For email validation regex
from datetime import datetime, timedelta
from functools import wraps
import os
import warnings
warnings.filterwarnings('ignore', message='.*Query.get.*')

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_ch5.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
SECRET_KEY = 'your-secret-key-keep-it-safe-123'

db = SQLAlchemy(app)


# ================================================================================
# STANDARDIZED RESPONSE HELPERS
# ================================================================================
# Consistent format for ALL responses:
#
# Error:
#   {"success": false, "error": {"code": "...", "message": "...", "field": "..."}}
#
# Success:
#   {"success": true, "message": "...", "data": {...}}
# ================================================================================


def error_response(code, message, field=None, status_code=400):
    """
    Create standardized error response.

    Args:
        code: Error code (VALIDATION_ERROR, AUTH_ERROR, etc.)
        message: Human-readable message
        field: Optional field name that caused the error
        status_code: HTTP status code
    """
    response = {
        'success': False,
        'error': {
            'code': code,
            'message': message
        }
    }
    if field:
        response['error']['field'] = field
    return jsonify(response), status_code


def success_response(data, message="Success"):
    """Create standardized success response."""
    return jsonify({
        'success': True,
        'message': message,
        'data': data
    })


# ================================================================================
# INPUT VALIDATION
# ================================================================================
# Validate on BOTH frontend AND backend!
# Frontend: Quick feedback
# Backend: Security (never trust client data)
# ================================================================================


def is_valid_email(email):
    """Validate email format using regex."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_registration(email, password):
    """
    Validate registration input.
    Returns (is_valid, error_response or None)
    """
    if not email:
        return False, error_response('VALIDATION_ERROR', 'Email is required', 'email')

    if not is_valid_email(email):
        return False, error_response('VALIDATION_ERROR', 'Invalid email format', 'email')

    if len(email) > 120:
        return False, error_response('VALIDATION_ERROR', 'Email too long (max 120)', 'email')

    if not password:
        return False, error_response('VALIDATION_ERROR', 'Password is required', 'password')

    if len(password) < 6:
        return False, error_response('VALIDATION_ERROR', 'Password must be at least 6 characters', 'password')

    return True, None


# ================================================================================
# USER MODEL
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
    payload = {
        'user_id': user.id,
        'email': user.email,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


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

            token = parts[1]
            decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            g.current_user = {'user_id': decoded['user_id'], 'email': decoded['email']}

        except jwt.ExpiredSignatureError:
            return error_response('TOKEN_EXPIRED', 'Token has expired', status_code=401)
        except jwt.InvalidTokenError:
            return error_response('TOKEN_INVALID', 'Invalid token', status_code=401)

        return f(*args, **kwargs)
    return decorated


# ================================================================================
# GLOBAL ERROR HANDLERS
# ================================================================================
# Catch errors that slip through to ensure consistent error format.
# ================================================================================


@app.errorhandler(404)
def not_found(error):
    return error_response('NOT_FOUND', 'Resource not found', status_code=404)


@app.errorhandler(500)
def server_error(error):
    app.logger.error(f'Server error: {error}')  # Log for debugging
    return error_response('SERVER_ERROR', 'Something went wrong', status_code=500)


@app.errorhandler(Exception)
def handle_exception(error):
    app.logger.error(f'Unhandled exception: {error}')
    return error_response('SERVER_ERROR', 'An unexpected error occurred', status_code=500)


# ================================================================================
# ROUTES
# ================================================================================


@app.route('/')
def index():
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    return send_file(html_path)


@app.route('/register', methods=['POST'])
def register():
    """Register with proper validation and error handling."""
    try:
        data = request.get_json()

        if not data:
            return error_response('VALIDATION_ERROR', 'Request body required')

        email = data.get('email', '').strip().lower()  # Normalize email
        password = data.get('password', '')

        # Validate input
        is_valid, err = validate_registration(email, password)
        if not is_valid:
            return err

        # Check duplicate
        if User.query.filter_by(email=email).first():
            return error_response('ALREADY_EXISTS', 'Email already registered', 'email', 409)

        # Create user
        new_user = User(email=email, password=hash_password(password))
        db.session.add(new_user)
        db.session.commit()

        return success_response(new_user.to_dict(), 'Registration successful!'), 201

    except Exception as e:
        app.logger.error(f'Registration error: {e}')
        db.session.rollback()  # Rollback partial changes!
        return error_response('SERVER_ERROR', 'Registration failed')


@app.route('/login', methods=['POST'])
def login():
    """Login with proper error handling."""
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

        token = create_token(user)
        return success_response({
            'token': token,
            'user': user.to_dict()
        }, 'Login successful!')

    except Exception as e:
        app.logger.error(f'Login error: {e}')
        return error_response('SERVER_ERROR', 'Login failed')


@app.route('/profile', methods=['GET'])
@token_required
def get_profile():
    try:
        user = User.query.get(g.current_user['user_id'])
        if not user:
            return error_response('NOT_FOUND', 'User not found', status_code=404)
        return success_response(user.to_dict(), 'Profile retrieved')
    except Exception as e:
        app.logger.error(f'Profile error: {e}')
        return error_response('SERVER_ERROR', 'Could not get profile')


# Test endpoint to see different error types
@app.route('/test-error/<error_type>')
def test_error(error_type):
    """Test endpoint to demonstrate different error types."""
    if error_type == 'validation':
        return error_response('VALIDATION_ERROR', 'Test validation error', 'test_field')
    elif error_type == 'auth':
        return error_response('AUTH_ERROR', 'Test auth error', status_code=401)
    elif error_type == 'notfound':
        return error_response('NOT_FOUND', 'Test not found', status_code=404)
    elif error_type == 'server':
        return error_response('SERVER_ERROR', 'Test server error', status_code=500)
    elif error_type == 'exception':
        raise Exception('Test exception')
    return success_response({'type': error_type}, 'Unknown error type')


with app.app_context():
    db.create_all()


# ================================================================================
# KEY TAKEAWAYS - Chapter 5
# ================================================================================
#
# 1. CONSISTENT ERROR FORMAT helps frontend developers:
#    {"success": false, "error": {"code": "VALIDATION_ERROR", "message": "...", "field": "email"}}
#    Frontend can check error.code and error.field to show specific UI feedback.
#
# 2. NEVER EXPOSE INTERNAL ERRORS to users!
#    BAD:  "Database connection failed: mysql://root:password@localhost:3306"
#    GOOD: "Something went wrong. Please try again."
#    Log the real error for debugging, but show a generic message to users.
#
# 3. HTTP STATUS CODES matter:
#    - 400 Bad Request: Client sent invalid data (validation error)
#    - 401 Unauthorized: Not logged in / bad token
#    - 403 Forbidden: Logged in but no permission
#    - 404 Not Found: Resource doesn't exist
#    - 409 Conflict: Resource already exists (duplicate email)
#    - 500 Server Error: Something broke on our end
#
# 4. VALIDATE ON BOTH SIDES:
#    - Frontend: Quick feedback for users
#    - Backend: Security (never trust client data!)
#
# 5. DATABASE ROLLBACK on errors:
#    If something fails mid-operation, db.session.rollback() prevents
#    partial/corrupted data from being saved.
#
# 6. FRONTEND: Handling errors consistently
#    The frontend checks response.success to determine how to display:
#    - if (data.success) → show success message
#    - else → show data.error.message, highlight data.error.field
#
#    TRY THIS - See error handling in action:
#    - Open Developer Tools (F12) → "Network" tab
#    - Try registering with invalid email format
#    - Click the request → look at "Response" tab
#    - See the structured error: {"success": false, "error": {...}}
#    - Notice the HTTP status code (400) in the request list
#
# 7. TRY THIS - Test different error types:
#    - Visit /test-error/validation → 400 with VALIDATION_ERROR
#    - Visit /test-error/auth → 401 with AUTH_ERROR
#    - Visit /test-error/notfound → 404 with NOT_FOUND
#    - Visit /test-error/server → 500 with SERVER_ERROR
#
# NEXT CHAPTER: We'll add email verification to ensure users own their email.
#
# ================================================================================


# ================================================================================
# EXERCISES - Test Your Understanding!
# ================================================================================
#
# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 1: Add Password Validation (Easy)
# ────────────────────────────────────────────────────────────────────────────────
# Enhance validate_registration() to also check:
# - Password must be at least 8 characters (currently 6)
# - Password must contain at least one number
#
# Test: Try registering with password "abcdefgh" → should fail (no number)
# Test: Try registering with password "abc123" → should fail (too short)
# Test: Try registering with password "abcdefg1" → should succeed
#
# HINT: Use any(c.isdigit() for c in password) to check for numbers
# ────────────────────────────────────────────────────────────────────────────────


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 2: Create a Validation Endpoint (Medium)
# ────────────────────────────────────────────────────────────────────────────────
# Create an endpoint POST /validate that:
# - Accepts JSON body with 'email' and 'password' fields
# - Returns validation results WITHOUT creating a user
# - Returns all validation errors at once (not just the first one)
#
# Test: curl -X POST http://localhost:5005/validate \
#       -H "Content-Type: application/json" \
#       -d '{"email": "invalid", "password": "123"}'
#
# Expected: {
#   "valid": false,
#   "errors": [
#     {"field": "email", "message": "Invalid email format"},
#     {"field": "password", "message": "Password must be at least 6 characters"}
#   ]
# }
#
# If all valid: {"valid": true, "errors": []}
# ────────────────────────────────────────────────────────────────────────────────

# YOUR CODE HERE:
# @app.route('/validate', methods=['POST'])
# def validate_input():
#     pass


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 3: Add Custom Error Code (Medium)
# ────────────────────────────────────────────────────────────────────────────────
# Add a new error type: RATE_LIMIT_ERROR
# - Create a simple in-memory rate limiter (dictionary)
# - Track requests per IP address
# - Return RATE_LIMIT_ERROR if more than 5 requests per minute from same IP
#
# Test: Hit any endpoint more than 5 times quickly
#
# Expected after limit: {
#   "success": false,
#   "error": {
#     "code": "RATE_LIMIT_ERROR",
#     "message": "Too many requests. Try again later."
#   }
# }, 429
#
# HINT: request.remote_addr gives the IP address
#       Use time.time() to track timestamps
# ────────────────────────────────────────────────────────────────────────────────

# YOUR CODE HERE (add this before routes):
# from collections import defaultdict
# import time
# request_counts = defaultdict(list)  # IP -> [timestamps]
#
# def check_rate_limit():
#     """Returns error response if rate limited, None otherwise."""
#     pass


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 4: Global Request Logger (Medium)
# ────────────────────────────────────────────────────────────────────────────────
# Add a @app.before_request handler that:
# - Logs every request: timestamp, method, path, IP address
# - Prints to console (in production, you'd write to a file)
#
# Test: Make any request, check the server console for log output
#
# Expected log: "[2024-01-15 10:30:00] GET /register from 127.0.0.1"
#
# HINT: Use @app.before_request decorator
#       Access: request.method, request.path, request.remote_addr
# ────────────────────────────────────────────────────────────────────────────────

# YOUR CODE HERE:
# @app.before_request
# def log_request():
#     pass


# ================================================================================


if __name__ == '__main__':
    print("=" * 60)
    print("CHAPTER 5: Error Handling & Validation")
    print("=" * 60)
    print("Server running at: http://localhost:5005")
    print("")
    print("Test error handling: GET /test-error/<type>")
    print("  Types: validation, auth, notfound, server, exception")
    print("=" * 60)
    app.run(debug=True, port=5005)
