# ================================================================================
# CHAPTER 4: SOLUTIONS - Protected Routes
# ================================================================================
# This file contains solutions to all exercises from Chapter 4.
# ================================================================================

from flask import Flask, jsonify, request, g, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps
import os
import warnings
warnings.filterwarnings('ignore', message='.*Query.get.*')

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_ch4_solutions.db'
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
# ORIGINAL DECORATOR: @token_required
# ================================================================================

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')

        if not auth_header:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            parts = auth_header.split(' ')
            if len(parts) != 2 or parts[0] != 'Bearer':
                return jsonify({'message': 'Invalid token format!'}), 401

            token = parts[1]
            decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

            g.current_user = {
                'user_id': decoded['user_id'],
                'email': decoded['email']
            }

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401

        return f(*args, **kwargs)
    return decorated


# ================================================================================
# EXERCISE 3 SOLUTION: Logging Decorator
# ================================================================================
# This decorator logs access to any route it decorates.
# Key learning: Decorators can be stacked and used for cross-cutting concerns!
# ================================================================================

def log_access(f):
    """
    Decorator that logs route access.
    Prints timestamp, endpoint, and user email (if authenticated).
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        endpoint = request.path
        method = request.method

        # Try to get user email from g.current_user (set by @token_required)
        # Will be None for public routes or if called before @token_required
        user_email = getattr(g, 'current_user', {}).get('email', 'anonymous')

        # Log to console (in production, you'd write to a file or logging service)
        log_message = f"[{timestamp}] {method} {endpoint} accessed by {user_email}"
        print(log_message)

        # Store log in g for the response (optional - shows the log was recorded)
        g.access_log = log_message

        return f(*args, **kwargs)
    return decorated


# ================================================================================
# EXERCISE 4 SOLUTION: Optional Authentication Decorator
# ================================================================================
# This decorator doesn't fail if token is missing - just sets g.current_user = None.
# Perfect for routes that work differently for logged-in vs anonymous users.
# ================================================================================

def token_optional(f):
    """
    Decorator that extracts user info if token is present, but doesn't require it.
    g.current_user will be set to user info or None.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')

        # Default to None (anonymous user)
        g.current_user = None

        if auth_header:
            try:
                parts = auth_header.split(' ')
                if len(parts) == 2 and parts[0] == 'Bearer':
                    token = parts[1]
                    decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
                    g.current_user = {
                        'user_id': decoded['user_id'],
                        'email': decoded['email']
                    }
            except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                # Token is invalid, but we don't fail - just treat as anonymous
                g.current_user = None

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


@app.route('/profile', methods=['GET'])
@token_required
def get_profile():
    user = User.query.get(g.current_user['user_id'])
    return jsonify({'message': 'Profile retrieved!', 'profile': user.to_dict()})


@app.route('/dashboard', methods=['GET'])
@token_required
@log_access  # EXERCISE 3: Using the logging decorator
def get_dashboard():
    return jsonify({
        'message': 'Dashboard data',
        'welcome': f"Hello, {g.current_user['email']}!",
        'logged': getattr(g, 'access_log', None)  # Show that logging worked
    })


# ================================================================================
# EXERCISE 1 SOLUTION: Create Another Protected Route
# ================================================================================

@app.route('/settings', methods=['GET'])
@token_required
@log_access
def get_settings():
    """Protected settings endpoint."""
    return jsonify({
        'success': True,
        'settings': {
            'theme': 'dark',
            'notifications': True,
            'language': 'en',
            'timezone': 'UTC'
        },
        'user': g.current_user['email'],
        'access_logged': getattr(g, 'access_log', None)
    })


# ================================================================================
# EXERCISE 2 SOLUTION: Update Profile Endpoint
# ================================================================================

@app.route('/profile', methods=['PUT'])
@token_required
@log_access
def update_profile():
    """Update user profile - allows changing email."""
    data = request.get_json()

    if not data:
        return jsonify({'message': 'Request body required'}), 400

    user = User.query.get(g.current_user['user_id'])
    if not user:
        return jsonify({'message': 'User not found'}), 404

    new_email = data.get('email')

    if new_email:
        # Normalize email
        new_email = new_email.strip().lower()

        # Check if email is different
        if new_email == user.email:
            return jsonify({'message': 'Email is the same as current'}), 400

        # Check if email is already taken by another user
        existing = User.query.filter_by(email=new_email).first()
        if existing and existing.id != user.id:
            return jsonify({'message': 'Email already in use'}), 400

        # Update email
        user.email = new_email
        db.session.commit()

        # Note: After changing email, user should get a new token
        # because the old token has the old email in the payload
        new_token = create_token(user)

        return jsonify({
            'message': 'Profile updated',
            'profile': user.to_dict(),
            'new_token': new_token,
            'note': 'Please use the new token - old one has outdated email'
        })

    return jsonify({'message': 'Nothing to update'}), 400


# ================================================================================
# EXERCISE 4 SOLUTION: Welcome Route (Uses @token_optional)
# ================================================================================

@app.route('/welcome', methods=['GET'])
@token_optional  # Doesn't require token, but uses it if present
@log_access
def welcome():
    """
    Welcome route that works for both logged-in and anonymous users.
    Returns different messages based on authentication status.
    """
    if g.current_user:
        # User is logged in
        user = User.query.get(g.current_user['user_id'])
        return jsonify({
            'authenticated': True,
            'message': f"Welcome back, {g.current_user['email']}!",
            'user': user.to_dict() if user else None,
            'features': ['profile', 'settings', 'dashboard']
        })
    else:
        # Anonymous user
        return jsonify({
            'authenticated': False,
            'message': 'Welcome, guest!',
            'hint': 'Login to access more features',
            'features': ['register', 'login']
        })


# ================================================================================
# Bonus: Route that shows decorator stacking order
# ================================================================================

@app.route('/debug-decorators', methods=['GET'])
@token_required  # 1st: Check authentication
@log_access      # 2nd: Log the access (user is now known)
def debug_decorators():
    """Shows the order in which decorators execute."""
    return jsonify({
        'message': 'Decorators executed in order: token_required → log_access → function',
        'user': g.current_user['email'],
        'access_log': getattr(g, 'access_log', None)
    })


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    print("=" * 60)
    print("CHAPTER 4: SOLUTIONS")
    print("=" * 60)
    print("Server running at: http://localhost:5004")
    print("")
    print("Exercise Solutions:")
    print("  GET /settings          - Exercise 1 (protected)")
    print("  PUT /profile           - Exercise 2 (update email)")
    print("  GET /dashboard         - Uses @log_access (Ex 3)")
    print("  GET /welcome           - Uses @token_optional (Ex 4)")
    print("  GET /debug-decorators  - Shows decorator order")
    print("=" * 60)
    app.run(debug=True, port=5004)
