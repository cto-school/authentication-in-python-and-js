from flask import Flask, jsonify, request, g, send_file  # g is Flask's global object for request-scoped data
from flask_cors import CORS  # Cross-origin support
from flask_sqlalchemy import SQLAlchemy  # Database ORM
# Password hashing using werkzeug.security (comes built-in with Flask)
from werkzeug.security import generate_password_hash, check_password_hash
import jwt  # From 'pyjwt' package (pip install pyjwt), NOT 'jwt'
from datetime import datetime, timedelta  # Date/time utilities
# functools.wraps - Used when creating decorators to preserve the original function's metadata
# Without @wraps, the decorated function would lose its __name__ and __doc__ attributes
from functools import wraps
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


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Database file
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable tracking
SECRET_KEY = 'your-secret-key-keep-it-safe'  # JWT secret

db = SQLAlchemy(app)  # Database instance


class User(db.Model):  # User model
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)  # Primary key
    email = db.Column(db.String(120), unique=True, nullable=False)  # Unique email
    password = db.Column(db.String(255), nullable=False)  # Hashed password
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Created timestamp


# Hash password - converts plain text to secure hash
def hash_password(password):
    return generate_password_hash(password)


# Verify password - compares plain password with stored hash
# Returns True if password matches, False otherwise
def check_password(password, hashed_password):
    return check_password_hash(hashed_password, password)


def create_token(user):  # Create JWT token
    payload = {'user_id': user.id, 'email': user.email, 'exp': datetime.utcnow() + timedelta(hours=24)}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


# ================================================================================
# DECORATOR PATTERN - What is a Decorator?
# ================================================================================
#
# A decorator is a function that wraps another function to add extra behavior.
# Think of it like a "wrapper" or "middleware" that runs BEFORE and/or AFTER your function.
#
# WITHOUT decorator (repetitive code):
#     @app.route('/profile')
#     def get_profile():
#         token = check_token()      # Must repeat this in EVERY protected route
#         if not token:
#             return error
#         # actual code...
#
#     @app.route('/dashboard')
#     def get_dashboard():
#         token = check_token()      # Repeating same code again!
#         if not token:
#             return error
#         # actual code...
#
# WITH decorator (clean code):
#     @app.route('/profile')
#     @token_required              # Just add this line - token check happens automatically!
#     def get_profile():
#         # actual code...
#
#     @app.route('/dashboard')
#     @token_required              # Same here - no repetition!
#     def get_dashboard():
#         # actual code...
#
# ================================================================================
# HOW DECORATORS WORK - Step by Step
# ================================================================================
#
# When you write:
#     @token_required
#     def get_profile():
#         ...
#
# Python transforms it to:
#     get_profile = token_required(get_profile)
#
# So when someone calls get_profile(), they're actually calling the "decorated" version,
# which runs the token check FIRST, and only calls the real get_profile() if token is valid.
#
# EXECUTION FLOW:
#     1. User calls GET /profile
#     2. Flask routes to get_profile()
#     3. But get_profile is wrapped, so decorated() runs first
#     4. decorated() checks the token
#     5. If token invalid → return error (get_profile never runs)
#     6. If token valid → call f(*args, **kwargs) which is the real get_profile()
#
# ================================================================================

def token_required(f):
    """
    Decorator that protects routes by requiring a valid JWT token.

    Usage:
        @app.route('/protected')
        @token_required
        def protected_route():
            # This code only runs if token is valid
            user_id = g.current_user['user_id']
            ...

    The decorator:
    1. Checks if Authorization header exists
    2. Validates the "Bearer <token>" format
    3. Decodes and verifies the JWT token
    4. Stores user info in Flask's g object for the route to use
    5. Only then calls the actual route function
    """

    @wraps(f)  # Preserves original function's __name__ and __doc__
    def decorated(*args, **kwargs):
        # ----------------------------------------
        # STEP 1: Get the Authorization header
        # ----------------------------------------
        # Frontend sends: headers: { 'Authorization': 'Bearer eyJhbG...' }
        auth_header = request.headers.get('Authorization')

        if not auth_header:
            # No Authorization header = user didn't send a token
            return jsonify({'message': 'Token is missing!'}), 401  # 401 = Unauthorized

        try:
            # ----------------------------------------
            # STEP 2: Parse the "Bearer <token>" format
            # ----------------------------------------
            # Expected format: "Bearer eyJhbGciOiJIUzI1NiIs..."
            # Split by space: ["Bearer", "eyJhbGciOiJIUzI1NiIs..."]
            parts = auth_header.split(' ')

            if len(parts) != 2 or parts[0] != 'Bearer':
                # Invalid format - maybe they sent just the token without "Bearer"
                return jsonify({'message': 'Invalid token format! Use: Bearer <token>'}), 401

            token = parts[1]  # The actual JWT token

            # ----------------------------------------
            # STEP 3: Decode and verify the JWT token
            # ----------------------------------------
            # jwt.decode() does THREE things:
            # 1. Decodes the base64 payload
            # 2. Verifies the signature using SECRET_KEY
            # 3. Checks if token has expired (exp claim)
            # If ANY of these fail, it raises an exception
            decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

            # ----------------------------------------
            # STEP 4: Store user info in Flask's g object
            # ----------------------------------------
            # Flask's g (global) object:
            # - Lives for ONE request only (request-scoped)
            # - Automatically cleared after request ends
            # - Perfect for passing data from decorator to route function
            # - Better than global variables (which persist across requests)
            g.current_user = {
                'user_id': decoded['user_id'],
                'email': decoded['email']
            }

        except jwt.ExpiredSignatureError:
            # Token's 'exp' claim is in the past - token has expired
            return jsonify({'message': 'Token has expired!'}), 401

        except jwt.InvalidTokenError:
            # Signature verification failed, or token is malformed
            # This catches: invalid signature, invalid format, missing claims, etc.
            return jsonify({'message': 'Token is invalid!'}), 401

        # ----------------------------------------
        # STEP 5: Token is valid! Call the actual route function
        # ----------------------------------------
        # f is the original function (e.g., get_profile)
        # *args, **kwargs passes through any arguments
        return f(*args, **kwargs)

    # Return the wrapper function (this replaces the original function)
    return decorated


# ================================================================================
# PUBLIC ROUTES - No token required
# ================================================================================
# These routes do NOT have @token_required decorator.
# Anyone can access them without logging in.
# This makes sense because:
#   - /register: User doesn't have an account yet, so can't have a token
#   - /login: User needs to login to GET a token, so can't require one
# ================================================================================
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

    return jsonify({'message': 'User registered successfully!', 'user': {'id': new_user.id, 'email': new_user.email}}), 201


@app.route('/login', methods=['POST'])  # Public - returns a token upon successful login
def login():
    data = request.get_json()
    email, password = data.get('email'), data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required!'}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not check_password(password, user.password):
        return jsonify({'message': 'Invalid email or password!'}), 401

    return jsonify({'message': 'Login successful!', 'token': create_token(user), 'user': {'id': user.id, 'email': user.email}})


# ================================================================================
# PROTECTED ROUTE EXAMPLE
# ================================================================================
# This route requires authentication - only logged-in users can access it.
#
# How it works:
#   1. User sends: GET /profile with header "Authorization: Bearer <token>"
#   2. @token_required decorator runs FIRST (before get_profile)
#   3. If token invalid → decorator returns 401, get_profile() NEVER runs
#   4. If token valid → decorator stores user info in g.current_user, then calls get_profile()
#   5. get_profile() can safely access g.current_user (guaranteed to exist)
# ================================================================================
@app.route('/profile', methods=['GET'])
@token_required  # ← This decorator protects the route
def get_profile():
    # At this point, we KNOW the token is valid (decorator already checked)
    # User info is available in g.current_user (set by the decorator)
    user = User.query.get(g.current_user['user_id'])

    if not user:
        # Edge case: Token is valid but user was deleted from database
        # Token contains user_id, but that user no longer exists
        return jsonify({'message': 'User not found!'}), 404

    return jsonify({
        'message': 'Profile retrieved successfully!',
        'profile': {
            'id': user.id,
            'email': user.email,
            'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
    })


# Another protected route - demonstrates using g.current_user
@app.route('/dashboard', methods=['GET'])
@token_required
def get_dashboard():
    # g.current_user was set by @token_required decorator
    # We can use it directly without any additional checks
    return jsonify({
        'message': 'Dashboard data retrieved!',
        'data': {
            'welcome': f"Hello, {g.current_user['email']}!",
            'stats': {'total_posts': 10, 'total_likes': 50, 'total_comments': 25}
        }
    })


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    print("=" * 50)
    print("Protected Routes Server Running on http://localhost:5004")
    print("=" * 50)
    app.run(debug=True, port=5004)


# ===========================================
# EXERCISES - Try These!
# ===========================================
"""
EXERCISE 1: Test Protected Route Without Token
----------------------------------------------
Using browser or Postman:

1. Try: GET http://localhost:5004/profile (no Authorization header)
   What response do you get?

2. Try: GET http://localhost:5004/profile
   Header: Authorization: InvalidToken
   What response do you get?

3. Try: GET http://localhost:5004/profile
   Header: Authorization: Bearer invalid.token.here
   What response do you get?

Question: Why are there different error messages for each case?


EXERCISE 2: Create Your Own Protected Route
-------------------------------------------
Add a new protected route:

@app.route('/settings', methods=['GET'])
@token_required
def get_settings():
    return jsonify({
        'user_id': g.current_user['user_id'],
        'email': g.current_user['email'],
        'settings': {
            'theme': 'dark',
            'notifications': True,
            'language': 'en'
        }
    })

Test: Can you access it without token? With valid token?


EXERCISE 3: Add Token Info to Response
--------------------------------------
Create a route that shows token information:

@app.route('/token-info', methods=['GET'])
@token_required
def token_info():
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(' ')[1]
    decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

    return jsonify({
        'user_id': decoded['user_id'],
        'email': decoded['email'],
        'expires_at': datetime.fromtimestamp(decoded['exp']).strftime('%Y-%m-%d %H:%M:%S'),
        'issued_at': 'Not available (add iat claim to token)'
    })

Bonus: Add 'iat' (issued at) claim in create_token() and display it here.


EXERCISE 4: Understand the Decorator
------------------------------------
Add print statements inside token_required:

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        print(f"Decorator running for function: {f.__name__}")  # Add this
        print(f"Authorization header: {request.headers.get('Authorization')}")  # Add this
        # ... rest of code
        print(f"Token valid! Calling {f.__name__}")  # Add before return f()
        return f(*args, **kwargs)
    return decorated

Test: Call /profile and watch the console output
Question: In what order do things execute?


SELF-STUDY QUESTIONS
--------------------
1. What is a decorator in Python? How does @token_required work?

2. What is Flask's 'g' object? Why use it instead of a regular variable?

3. What's the difference between a public route and a protected route?

4. If token is valid but user is deleted from database, what happens?

5. Why do we use "Bearer" prefix in Authorization header?
   (Hint: Research "Bearer token authentication")
"""
