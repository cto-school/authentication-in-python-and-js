# ================================================================================
# PART 8: ERROR HANDLING - Professional Error Responses
# ================================================================================
#
# This part covers how to handle errors properly in a production application:
#
#   1. Standardized error response format (consistent structure for ALL errors)
#   2. Input validation with helpful error messages
#   3. Try-except blocks with database rollback
#   4. Global error handlers for uncaught exceptions
#   5. HTTP status codes and when to use each one
#
# WHY ERROR HANDLING MATTERS:
#   - Without it: Users see confusing stack traces, security info leaks
#   - With it: Clear messages, secure logging, good user experience
#
# KEY PRINCIPLE: Never expose internal errors to users!
#   BAD:  {"error": "SQL Error: column 'password' not found"}  ← Security risk!
#   GOOD: {"error": {"code": "SERVER_ERROR", "message": "Something went wrong"}}
#
# ================================================================================

from flask import Flask, jsonify, request, g, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
# Password hashing using werkzeug.security (comes built-in with Flask)
from werkzeug.security import generate_password_hash, check_password_hash
import jwt  # From 'pyjwt' package (pip install pyjwt), NOT 'jwt'
# ================================================================================
# re module - Regular Expressions for Pattern Matching
# ================================================================================
# Used here for email validation. Regular expressions (regex) let you define
# patterns to match text. For example:
#   r'^[a-z]+$'  → matches lowercase letters only
#   r'^\d{3}$'   → matches exactly 3 digits
#
# Email regex is complex because emails have many valid formats:
#   user@domain.com, user.name@sub.domain.co.uk, user+tag@domain.com
# ================================================================================
import re
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


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable tracking
SECRET_KEY = 'your-secret-key-keep-it-safe'  # JWT secret

db = SQLAlchemy(app)  # Database instance


# ================================================================================
# STANDARDIZED RESPONSE HELPERS
# ================================================================================
# These functions ensure ALL responses have a consistent format.
# Frontend developers love this because they always know what to expect!
#
# Error Response Format:
#   {
#       "success": false,
#       "error": {
#           "code": "VALIDATION_ERROR",    ← For programmatic handling
#           "message": "Email is required", ← For displaying to user
#           "field": "email"                ← (Optional) Which form field has error
#       }
#   }
#
# Success Response Format:
#   {
#       "success": true,
#       "message": "Login successful!",
#       "data": { ... }
#   }
#
# Why use error CODES?
#   - Frontend can switch on code: if (error.code === 'TOKEN_EXPIRED') { refresh() }
#   - Messages can be translated to different languages
#   - Codes are stable, messages might change
# ================================================================================


def error_response(code, message, field=None, status_code=400):
    """
    Create a standardized error response.

    Args:
        code: Error code (e.g., 'VALIDATION_ERROR', 'AUTH_ERROR')
        message: Human-readable error message
        field: (Optional) Form field that caused the error
        status_code: HTTP status code (default 400)

    Returns:
        JSON response with error details and HTTP status code
    """
    response = {'success': False, 'error': {'code': code, 'message': message}}
    if field:
        response['error']['field'] = field
    return jsonify(response), status_code


def success_response(data, message="Success"):
    """Create a standardized success response."""
    return jsonify({'success': True, 'message': message, 'data': data})


# ================================================================================
# INPUT VALIDATION FUNCTIONS
# ================================================================================
# Validation should happen on BOTH frontend AND backend:
#   - Frontend: Quick feedback, better UX
#   - Backend: Security (never trust client data!)
#
# An attacker can bypass frontend validation easily (browser dev tools, curl, etc.)
# Backend validation is your last line of defense.
# ================================================================================


def is_valid_email(email):
    """
    Validate email format using regular expression.

    The pattern breakdown:
        ^                   - Start of string
        [a-zA-Z0-9._%+-]+   - Username: letters, numbers, dots, underscores, etc.
        @                   - Literal @ symbol
        [a-zA-Z0-9.-]+      - Domain: letters, numbers, dots, hyphens
        \.                  - Literal dot before TLD
        [a-zA-Z]{2,}        - TLD: at least 2 letters (com, org, co.uk)
        $                   - End of string

    Note: This is a simplified regex. Real email validation is incredibly complex!
    For production, consider using a library like 'email-validator'.
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_registration(data):
    """
    Validate registration input. Returns (is_valid, error_response).

    Validation checks:
        1. Email is provided
        2. Email format is valid
        3. Email length is within limit (database column constraint)
        4. Password is provided
        5. Password meets minimum length requirement

    Returns:
        (True, None) if validation passes
        (False, error_response) if validation fails
    """
    email = data.get('email', '').strip()  # strip() removes leading/trailing whitespace
    password = data.get('password', '')

    # Check email - order matters! Check existence before format
    if not email:
        return False, error_response('VALIDATION_ERROR', 'Email is required', 'email')

    if not is_valid_email(email):
        return False, error_response('VALIDATION_ERROR', 'Invalid email format', 'email')

    if len(email) > 120:  # Must match database column: db.String(120)
        return False, error_response('VALIDATION_ERROR', 'Email is too long (max 120 characters)', 'email')

    # Check password
    if not password:
        return False, error_response('VALIDATION_ERROR', 'Password is required', 'password')

    if len(password) < 6:
        return False, error_response('VALIDATION_ERROR', 'Password must be at least 6 characters', 'password')

    return True, None  # All checks passed!


class User(db.Model):  # User model
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# Hash password - converts plain text to secure hash
def hash_password(password):
    return generate_password_hash(password)


# Verify password - compares plain password with stored hash
def check_password(password, hashed_password):
    return check_password_hash(hashed_password, password)


def create_jwt_token(user):  # Create JWT
    payload = {'user_id': user.id, 'email': user.email, 'exp': datetime.utcnow() + timedelta(hours=24)}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


# ================================================================================
# TOKEN DECORATOR - With Proper Error Handling
# ================================================================================
# This decorator now uses our standardized error_response() function.
# Notice how each error has a specific CODE that frontend can use.
# ================================================================================


def token_required(f):
    """Decorator that protects routes by requiring a valid JWT token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')

        if not auth_header:
            # AUTH_ERROR: Generic authentication problem
            return error_response('AUTH_ERROR', 'Token is missing. Please login first.', status_code=401)

        try:
            parts = auth_header.split(' ')
            if len(parts) != 2 or parts[0] != 'Bearer':
                return error_response('AUTH_ERROR', 'Invalid token format. Use: Bearer <token>', status_code=401)

            token = parts[1]
            decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            g.current_user = {'user_id': decoded['user_id'], 'email': decoded['email']}

        except jwt.ExpiredSignatureError:
            # TOKEN_EXPIRED: Specific code so frontend knows to try refresh token
            return error_response('TOKEN_EXPIRED', 'Your session has expired. Please login again.', status_code=401)

        except jwt.InvalidTokenError:
            # TOKEN_INVALID: Token is malformed or signature doesn't match
            return error_response('TOKEN_INVALID', 'Invalid token. Please login again.', status_code=401)

        return f(*args, **kwargs)
    return decorated


# ================================================================================
# GLOBAL ERROR HANDLERS
# ================================================================================
# These catch errors that occur ANYWHERE in the app.
# Flask's @app.errorhandler decorator registers handlers for specific errors.
#
# Why use global handlers?
#   - Ensures consistent error format even for unexpected errors
#   - Prevents sensitive info from leaking to users
#   - Centralizes error logging
#
# Order of specificity:
#   1. @app.errorhandler(404) - Catches 404 Not Found specifically
#   2. @app.errorhandler(500) - Catches 500 Internal Server Error
#   3. @app.errorhandler(Exception) - Catches EVERYTHING else (catch-all)
# ================================================================================


@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 Not Found - when URL doesn't match any route."""
    return error_response('NOT_FOUND', 'The requested resource was not found', status_code=404)


@app.errorhandler(500)
def internal_error(error):
    """
    Handle 500 Internal Server Error.

    IMPORTANT: Log the actual error for debugging, but show generic message to user.
    Never expose internal details like stack traces or database errors!
    """
    app.logger.error(f'Server Error: {error}')  # This goes to server logs
    return error_response('SERVER_ERROR', 'Something went wrong. Please try again later.', status_code=500)


@app.errorhandler(Exception)
def handle_exception(error):
    """
    Catch-all handler for any uncaught exception.

    This is your safety net - if an error slips through all other handlers,
    this one will catch it. Without this, users might see a raw Python traceback!
    """
    app.logger.error(f'Unhandled Exception: {error}')  # Log for debugging
    return error_response('SERVER_ERROR', 'An unexpected error occurred.', status_code=500)


# ================================================================================
# ROUTES WITH PROPER ERROR HANDLING
# ================================================================================
# Notice the pattern:
#   1. Wrap everything in try-except
#   2. Validate input first (fail fast)
#   3. Do business logic
#   4. On exception: log, rollback, return generic error
#
# HTTP STATUS CODES - When to use which:
#   200 OK           - Success (default for GET)
#   201 Created      - Success, new resource created (POST register)
#   400 Bad Request  - Client error, invalid input (validation failed)
#   401 Unauthorized - Not logged in, or bad credentials
#   403 Forbidden    - Logged in, but no permission
#   404 Not Found    - Resource doesn't exist
#   409 Conflict     - Resource already exists (duplicate email)
#   500 Server Error - Our fault, something went wrong internally
# ================================================================================


@app.route('/register', methods=['POST'])
def register():
    """
    Register a new user with comprehensive error handling.

    This route demonstrates:
        1. Input validation with helpful error messages
        2. Email normalization (lowercase, trimmed)
        3. Duplicate check with 409 Conflict
        4. Database rollback on failure
        5. Logging errors for debugging
    """
    try:
        data = request.get_json()

        # Check if request body exists (could be None if not JSON)
        if not data:
            return error_response('VALIDATION_ERROR', 'Request body is required')

        # Run all validation checks
        is_valid, error = validate_registration(data)
        if not is_valid:
            return error  # error already contains the response

        # ================================================================================
        # Email Normalization
        # ================================================================================
        # Why normalize?
        #   - "John@Email.com" and "john@email.com" should be the same user
        #   - .strip() removes accidental spaces: " john@email.com " → "john@email.com"
        #   - .lower() makes case-insensitive: "John@Email.com" → "john@email.com"
        # ================================================================================
        email = data.get('email').strip().lower()
        password = data.get('password')

        # Check for duplicate email - return 409 Conflict (not 400)
        if User.query.filter_by(email=email).first():
            return error_response('ALREADY_EXISTS', 'An account with this email already exists', 'email', status_code=409)

        # Create and save user
        new_user = User(email=email, password=hash_password(password))
        db.session.add(new_user)
        db.session.commit()

        return success_response({'id': new_user.id, 'email': new_user.email}, 'Registration successful!'), 201

    except Exception as e:
        # ================================================================================
        # Exception Handling Best Practices
        # ================================================================================
        # 1. LOG the actual error (for debugging)
        # 2. ROLLBACK the database session (partial operations are dangerous!)
        # 3. RETURN generic message (don't expose internal details)
        #
        # Why rollback?
        #   Imagine: INSERT user succeeded, but something failed after.
        #   Without rollback, you might have a partial/corrupt record in the database.
        # ================================================================================
        app.logger.error(f'Registration error: {e}')
        db.session.rollback()
        return error_response('SERVER_ERROR', 'Registration failed. Please try again.')


@app.route('/login', methods=['POST'])  # Login with error handling
def login():
    try:
        data = request.get_json()
        if not data:
            return error_response('VALIDATION_ERROR', 'Request body is required')

        email = data.get('email', '').strip().lower()  # Get and normalize email
        password = data.get('password', '')  # Get password

        if not email:  # Email missing
            return error_response('VALIDATION_ERROR', 'Email is required', 'email')
        if not password:  # Password missing
            return error_response('VALIDATION_ERROR', 'Password is required', 'password')

        user = User.query.filter_by(email=email).first()  # Find user

        if not user or not check_password(password, user.password):  # Invalid credentials
            return error_response('AUTH_ERROR', 'Invalid email or password', status_code=401)

        token = create_jwt_token(user)  # Create token
        return success_response({'token': token, 'user': {'id': user.id, 'email': user.email}}, 'Login successful!')

    except Exception as e:
        app.logger.error(f'Login error: {e}')
        return error_response('SERVER_ERROR', 'Login failed. Please try again.')


@app.route('/profile', methods=['GET'])  # Protected route
@token_required
def get_profile():
    try:
        user = User.query.get(g.current_user['user_id'])  # Get user
        if not user:  # User not found
            return error_response('NOT_FOUND', 'User not found', status_code=404)
        return success_response({'id': user.id, 'email': user.email, 'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S')}, 'Profile retrieved successfully')
    except Exception as e:
        app.logger.error(f'Profile error: {e}')
        return error_response('SERVER_ERROR', 'Failed to get profile.')


@app.route('/test-error/<error_type>', methods=['GET'])  # Test different errors
def test_error(error_type):
    if error_type == 'validation':
        return error_response('VALIDATION_ERROR', 'Test validation error', 'test_field')
    elif error_type == 'auth':
        return error_response('AUTH_ERROR', 'Test auth error', status_code=401)
    elif error_type == 'not-found':
        return error_response('NOT_FOUND', 'Test not found error', status_code=404)
    elif error_type == 'server':
        return error_response('SERVER_ERROR', 'Test server error', status_code=500)
    elif error_type == 'exception':
        raise Exception('Test exception')  # Triggers global handler
    return success_response({'error_type': error_type}, 'Unknown error type')


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    print("=" * 50)
    print("Error Handling Server Running on http://localhost:5008")
    print("=" * 50)
    app.run(debug=True, port=5008)


# ===========================================
# EXERCISES - Try These!
# ===========================================
"""
EXERCISE 1: Test All Error Types
--------------------------------
Call these endpoints and observe the responses:

1. GET /test-error/validation
2. GET /test-error/auth
3. GET /test-error/not-found
4. GET /test-error/server
5. GET /test-error/exception

Question: What's the difference in status codes? Why different codes for each?


EXERCISE 2: Add Custom Error Code
---------------------------------
Add a new error type for rate limiting:

@app.route('/test-error/rate-limit', methods=['GET'])
def test_rate_limit():
    return error_response(
        'RATE_LIMIT_EXCEEDED',
        'Too many requests. Please wait before trying again.',
        status_code=429
    )

Question: What does status code 429 mean? When would you use it?


EXERCISE 3: Add Password Strength Validation
--------------------------------------------
Modify validate_registration() to check password strength:

    # After checking length
    if not re.search(r'[0-9]', password):  # Must have number
        return False, error_response('VALIDATION_ERROR', 'Password must contain at least one number', 'password')

    if not re.search(r'[A-Z]', password):  # Must have uppercase
        return False, error_response('VALIDATION_ERROR', 'Password must contain at least one uppercase letter', 'password')

Test: Register with weak passwords
Question: What other password requirements could you add?


EXERCISE 4: Log All Errors to File
----------------------------------
Add file logging:

import logging
logging.basicConfig(
    filename='error.log',
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

Test: Trigger an error and check error.log file
Question: Why is error logging important in production?


EXERCISE 5: Create Error Statistics Route
-----------------------------------------
Track errors and create a route to view them:

error_stats = {'VALIDATION_ERROR': 0, 'AUTH_ERROR': 0, 'NOT_FOUND': 0, 'SERVER_ERROR': 0}

# In error_response(), add:
error_stats[code] = error_stats.get(code, 0) + 1

@app.route('/error-stats', methods=['GET'])
def get_error_stats():
    return success_response(error_stats, 'Error statistics')

Question: How could you use error statistics to improve your app?


SELF-STUDY QUESTIONS
--------------------
1. What's the difference between status codes 400, 401, 403, 404, 500?

2. Why use standardized error response format (code, message, field)?

3. Why should internal errors be logged but not shown to users?

4. What is the purpose of db.session.rollback()?

5. Why normalize email to lowercase before storing?
"""
