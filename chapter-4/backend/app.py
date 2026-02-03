# ================================================================================
# CHAPTER 4: Protected Routes
# ================================================================================
#
# This chapter covers:
#   1. Python decorators pattern
#   2. Creating @token_required decorator
#   3. Flask's g object for request-scoped data
#   4. Protecting routes with authentication
#
# BUILDS ON: Chapter 3 (JWT token creation)
#
# KEY CONCEPT: Decorators add behavior to functions without modifying them
#
# ================================================================================

from flask import Flask, jsonify, request, g, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
# ================================================================================
# functools.wraps - Decorator Helper
# ================================================================================
# When you create a decorator, the wrapped function loses its name and docstring.
# @wraps preserves the original function's metadata.
# ================================================================================
from functools import wraps
import os
import warnings
warnings.filterwarnings('ignore', message='.*Query.get.*')

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_ch4.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
SECRET_KEY = 'your-secret-key-keep-it-safe-123'

db = SQLAlchemy(app)


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


# ================================================================================
# DECORATOR PATTERN - What is a Decorator?
# ================================================================================
#
# A decorator is a function that wraps another function to add extra behavior.
# Think of it like a "wrapper" that runs BEFORE and/or AFTER your function.
#
# WITHOUT decorator (repetitive code):
#     @app.route('/profile')
#     def get_profile():
#         token = check_token()      # Must repeat this EVERYWHERE
#         if not token:
#             return error
#         # actual code...
#
# WITH decorator (clean code):
#     @app.route('/profile')
#     @token_required              # Just add this line!
#     def get_profile():
#         # actual code...
#
# HOW IT WORKS:
#     @token_required
#     def get_profile():
#         ...
#
#     Is equivalent to:
#     get_profile = token_required(get_profile)
#
# ================================================================================


def token_required(f):
    """
    Decorator that protects routes by requiring a valid JWT token.

    Usage:
        @app.route('/protected')
        @token_required
        def protected_route():
            user_id = g.current_user['user_id']
            ...

    How it works:
        1. Checks for Authorization header
        2. Validates "Bearer <token>" format
        3. Decodes and verifies the JWT
        4. Stores user info in Flask's g object
        5. Calls the actual route function
    """
    @wraps(f)  # Preserves original function's name and docstring
    def decorated(*args, **kwargs):
        # ----------------------------------------
        # STEP 1: Get Authorization header
        # ----------------------------------------
        # Frontend sends: headers: { 'Authorization': 'Bearer eyJ...' }
        auth_header = request.headers.get('Authorization')

        if not auth_header:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            # ----------------------------------------
            # STEP 2: Parse "Bearer <token>" format
            # ----------------------------------------
            parts = auth_header.split(' ')

            if len(parts) != 2 or parts[0] != 'Bearer':
                return jsonify({'message': 'Invalid token format! Use: Bearer <token>'}), 401

            token = parts[1]

            # ----------------------------------------
            # STEP 3: Decode and verify the JWT
            # ----------------------------------------
            # jwt.decode() does THREE things:
            #   1. Decodes the base64 payload
            #   2. Verifies the signature
            #   3. Checks expiration time
            decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

            # ----------------------------------------
            # STEP 4: Store user info in Flask's g object
            # ----------------------------------------
            # g (global) is request-scoped:
            #   - Lives for ONE request only
            #   - Perfect for passing data from decorator to route
            #   - Automatically cleared after request ends
            g.current_user = {
                'user_id': decoded['user_id'],
                'email': decoded['email']
            }

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401

        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401

        # ----------------------------------------
        # STEP 5: Call the actual route function
        # ----------------------------------------
        return f(*args, **kwargs)

    return decorated


# ================================================================================
# ROUTES
# ================================================================================


@app.route('/')
def index():
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    return send_file(html_path)


# PUBLIC ROUTES - No token required
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email, password = data.get('email'), data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required!'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already exists!'}), 400

    new_user = User(email=email, password=hash_password(password))
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered!', 'user': new_user.to_dict()}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email, password = data.get('email'), data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required!'}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not verify_password(password, user.password):
        return jsonify({'message': 'Invalid email or password!'}), 401

    return jsonify({
        'message': 'Login successful!',
        'token': create_token(user),
        'user': user.to_dict()
    })


# ================================================================================
# PROTECTED ROUTES - Token required
# ================================================================================
# These routes have @token_required decorator.
# If token is missing/invalid/expired, user gets 401 error.
# If token is valid, route function runs with g.current_user available.
# ================================================================================


@app.route('/profile', methods=['GET'])
@token_required  # ← This decorator protects the route
def get_profile():
    """
    Get current user's profile.
    Protected route - requires valid JWT token.
    """
    # g.current_user was set by @token_required decorator
    user = User.query.get(g.current_user['user_id'])

    if not user:
        return jsonify({'message': 'User not found!'}), 404

    return jsonify({
        'message': 'Profile retrieved!',
        'profile': user.to_dict()
    })


@app.route('/dashboard', methods=['GET'])
@token_required
def get_dashboard():
    """
    Example dashboard route - also protected.
    Demonstrates using g.current_user for personalization.
    """
    return jsonify({
        'message': 'Dashboard data',
        'welcome': f"Hello, {g.current_user['email']}!",
        'data': {
            'stats': {'posts': 10, 'likes': 50}
        }
    })


with app.app_context():
    db.create_all()


# ================================================================================
# KEY TAKEAWAYS - Chapter 4
# ================================================================================
#
# 1. DECORATORS wrap functions to add behavior:
#    @token_required
#    def my_route():  →  my_route = token_required(my_route)
#
# 2. THE @token_required PATTERN is reusable!
#    Write it once, use it on ANY route that needs authentication.
#    This is the DRY principle (Don't Repeat Yourself).
#
# 3. FLASK'S g OBJECT:
#    - g is request-scoped (lives for one request only)
#    - Perfect for passing data from decorator to route function
#    - g.current_user is set in decorator, used in route
#
# 4. AUTHORIZATION HEADER FORMAT:
#    Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
#    - "Bearer" is the token type (industry standard)
#    - Space separates "Bearer" from the actual token
#
# 5. FRONTEND: Sending the token with requests
#    fetch('/profile', {
#        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
#    });
#
#    TRY THIS - See the Authorization header:
#    - Open Developer Tools (F12) → "Network" tab
#    - Click "Test Profile" button in the frontend
#    - Click on the "profile" request in the Network list
#    - Look at "Request Headers" section
#    - You'll see: Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
#    - This is how the token travels from frontend to backend!
#
# 6. TRY THIS - Test without token:
#    - Clear localStorage (Application tab → Local Storage → Clear)
#    - Click "Test Profile" → 401 "Token is missing!"
#    - Login again, then try → Success!
#
# 7. jwt.decode() does THREE things automatically:
#    - Decodes the base64 payload
#    - Verifies the signature (token wasn't tampered)
#    - Checks expiration time
#
# MILESTONE: You now have a working authentication system!
# NEXT CHAPTER: We'll add proper error handling for production use.
#
# ================================================================================


# ================================================================================
# EXERCISES - Test Your Understanding!
# ================================================================================
#
# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 1: Create Another Protected Route (Easy)
# ────────────────────────────────────────────────────────────────────────────────
# Create a protected endpoint GET /settings that:
# - Requires authentication (use @token_required)
# - Returns user's settings (for now, just return placeholder data)
#
# Test without token: curl http://localhost:5004/settings → 401
# Test with token: curl http://localhost:5004/settings \
#                  -H "Authorization: Bearer eyJ..." → 200
#
# Expected: {"settings": {"theme": "dark", "notifications": true}, "user": "..."}
# ────────────────────────────────────────────────────────────────────────────────

# YOUR CODE HERE:
# @app.route('/settings', methods=['GET'])
# @token_required
# def get_settings():
#     pass


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 2: Update Profile Endpoint (Medium)
# ────────────────────────────────────────────────────────────────────────────────
# Create a protected endpoint PUT /profile that:
# - Requires authentication
# - Accepts JSON body with optional 'email' field
# - Updates the user's email (validate it's not already taken!)
# - Returns the updated profile
#
# Test: curl -X PUT http://localhost:5004/profile \
#       -H "Authorization: Bearer eyJ..." \
#       -H "Content-Type: application/json" \
#       -d '{"email": "newemail@test.com"}'
#
# Expected success: {"message": "Profile updated", "profile": {...}}
# Expected error (email taken): {"message": "Email already in use"}, 400
#
# HINT: Use g.current_user['user_id'] to get the current user
# ────────────────────────────────────────────────────────────────────────────────

# YOUR CODE HERE:
# @app.route('/profile', methods=['PUT'])
# @token_required
# def update_profile():
#     pass


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 3: Create a Logging Decorator (Hard)
# ────────────────────────────────────────────────────────────────────────────────
# Create a new decorator @log_access that:
# - Prints a log message when the route is accessed
# - Includes: timestamp, endpoint name, user email (if authenticated)
# - Works with both protected and public routes
#
# Usage example:
#   @app.route('/some-route')
#   @token_required
#   @log_access
#   def some_route():
#       pass
#
# Expected log output: "[2024-01-15 10:30:00] /some-route accessed by user@test.com"
#
# HINT: Use request.path for endpoint, g.current_user.get('email', 'anonymous')
#       Use datetime.now().strftime('%Y-%m-%d %H:%M:%S') for timestamp
# ────────────────────────────────────────────────────────────────────────────────

# YOUR CODE HERE:
# def log_access(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         # Log the access
#         # ...
#         return f(*args, **kwargs)
#     return decorated


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 4: Optional Authentication Decorator (Hard)
# ────────────────────────────────────────────────────────────────────────────────
# Create a decorator @token_optional that:
# - If token is present and valid: sets g.current_user with user info
# - If token is missing or invalid: sets g.current_user = None (doesn't error!)
# - Useful for routes that work differently for logged-in vs anonymous users
#
# Test: Create a route that returns different data based on login status
#
# Example route using it:
#   @app.route('/welcome')
#   @token_optional
#   def welcome():
#       if g.current_user:
#           return {"message": f"Welcome back, {g.current_user['email']}!"}
#       return {"message": "Welcome, guest!"}
# ────────────────────────────────────────────────────────────────────────────────

# YOUR CODE HERE:
# def token_optional(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         # Try to extract and decode token, but don't error if missing/invalid
#         # ...
#         return f(*args, **kwargs)
#     return decorated


# ================================================================================


if __name__ == '__main__':
    print("=" * 60)
    print("CHAPTER 4: Protected Routes")
    print("=" * 60)
    print("Server running at: http://localhost:5004")
    print("")
    print("Public Endpoints:")
    print("  POST /register - Register new user")
    print("  POST /login    - Login and get token")
    print("")
    print("Protected Endpoints (require token):")
    print("  GET /profile   - Get user profile")
    print("  GET /dashboard - Get dashboard data")
    print("=" * 60)
    app.run(debug=True, port=5004)
