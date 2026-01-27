from flask import Flask, jsonify, request, g, send_file  # Flask framework
from flask_cors import CORS  # Cross-origin
from flask_sqlalchemy import SQLAlchemy  # Database
import bcrypt  # Password hashing
import jwt  # JWT tokens
import re  # For email validation regex
from datetime import datetime, timedelta  # Date/time
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


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable tracking
SECRET_KEY = 'your-secret-key-keep-it-safe'  # JWT secret

db = SQLAlchemy(app)  # Database instance


def error_response(code, message, field=None, status_code=400):  # Standardized error response
    response = {'success': False, 'error': {'code': code, 'message': message}}  # Build error object
    if field:  # Add field if provided (for form validation)
        response['error']['field'] = field
    return jsonify(response), status_code  # Return JSON with status code


def success_response(data, message="Success"):  # Standardized success response
    return jsonify({'success': True, 'message': message, 'data': data})  # Return JSON


def is_valid_email(email):  # Email format validation
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'  # Email regex pattern
    return re.match(pattern, email) is not None  # Return True if matches


def validate_registration(data):  # Validate registration input
    email = data.get('email', '').strip()  # Get email, strip whitespace
    password = data.get('password', '')  # Get password

    if not email:  # Email missing
        return False, error_response('VALIDATION_ERROR', 'Email is required', 'email')

    if not is_valid_email(email):  # Invalid email format
        return False, error_response('VALIDATION_ERROR', 'Invalid email format', 'email')

    if len(email) > 120:  # Email too long
        return False, error_response('VALIDATION_ERROR', 'Email is too long (max 120 characters)', 'email')

    if not password:  # Password missing
        return False, error_response('VALIDATION_ERROR', 'Password is required', 'password')

    if len(password) < 6:  # Password too short
        return False, error_response('VALIDATION_ERROR', 'Password must be at least 6 characters', 'password')

    return True, None  # Validation passed


class User(db.Model):  # User model
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


def hash_password(password):  # Hash password
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def check_password(password, hashed_password):  # Verify password
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


def create_jwt_token(user):  # Create JWT
    payload = {'user_id': user.id, 'email': user.email, 'exp': datetime.utcnow() + timedelta(hours=24)}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


def token_required(f):  # Token decorator with error handling
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')  # Get auth header

        if not auth_header:  # No header
            return error_response('AUTH_ERROR', 'Token is missing. Please login first.', status_code=401)

        try:
            parts = auth_header.split(' ')  # Split header
            if len(parts) != 2 or parts[0] != 'Bearer':  # Invalid format
                return error_response('AUTH_ERROR', 'Invalid token format. Use: Bearer <token>', status_code=401)
            token = parts[1]  # Get token
            decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])  # Decode token
            g.current_user = {'user_id': decoded['user_id'], 'email': decoded['email']}  # Store user info

        except jwt.ExpiredSignatureError:  # Token expired
            return error_response('TOKEN_EXPIRED', 'Your session has expired. Please login again.', status_code=401)

        except jwt.InvalidTokenError:  # Invalid token
            return error_response('TOKEN_INVALID', 'Invalid token. Please login again.', status_code=401)

        return f(*args, **kwargs)  # Call protected function
    return decorated


@app.errorhandler(404)  # Handle 404 errors
def not_found_error(error):
    return error_response('NOT_FOUND', 'The requested resource was not found', status_code=404)


@app.errorhandler(500)  # Handle 500 errors
def internal_error(error):
    app.logger.error(f'Server Error: {error}')  # Log actual error
    return error_response('SERVER_ERROR', 'Something went wrong. Please try again later.', status_code=500)


@app.errorhandler(Exception)  # Catch-all error handler
def handle_exception(error):
    app.logger.error(f'Unhandled Exception: {error}')  # Log error
    return error_response('SERVER_ERROR', 'An unexpected error occurred.', status_code=500)


@app.route('/register', methods=['POST'])  # Register with validation
def register():
    try:
        data = request.get_json()  # Get JSON data
        if not data:  # No data
            return error_response('VALIDATION_ERROR', 'Request body is required')

        is_valid, error = validate_registration(data)  # Validate input
        if not is_valid:  # Validation failed
            return error

        email = data.get('email').strip().lower()  # Normalize email
        password = data.get('password')  # Get password

        if User.query.filter_by(email=email).first():  # Email exists
            return error_response('ALREADY_EXISTS', 'An account with this email already exists', 'email', status_code=409)

        new_user = User(email=email, password=hash_password(password))  # Create user
        db.session.add(new_user)
        db.session.commit()

        return success_response({'id': new_user.id, 'email': new_user.email}, 'Registration successful!'), 201

    except Exception as e:
        app.logger.error(f'Registration error: {e}')  # Log error
        db.session.rollback()  # Rollback on error
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
