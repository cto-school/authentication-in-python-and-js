from flask import Flask, jsonify, request, g, send_file  # g is Flask's global object for request-scoped data
from flask_cors import CORS  # Cross-origin support
from flask_sqlalchemy import SQLAlchemy  # Database ORM
import bcrypt  # Password hashing
import jwt  # JWT tokens
from datetime import datetime, timedelta  # Date/time utilities
from functools import wraps  # For creating decorators
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


def hash_password(password):  # Hash password
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def check_password(password, hashed_password):  # Verify password
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


def create_token(user):  # Create JWT token
    payload = {'user_id': user.id, 'email': user.email, 'exp': datetime.utcnow() + timedelta(hours=24)}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


def token_required(f):  # Decorator function to protect routes
    @wraps(f)  # Preserves original function's name and docstring
    def decorated(*args, **kwargs):  # Wrapper function that runs before protected route
        auth_header = request.headers.get('Authorization')  # Get Authorization header from request

        if not auth_header:  # No header = no token
            return jsonify({'message': 'Token is missing!'}), 401  # 401 = Unauthorized

        try:
            parts = auth_header.split(' ')  # Split "Bearer <token>" into parts
            if len(parts) != 2 or parts[0] != 'Bearer':  # Must be exactly "Bearer <token>"
                return jsonify({'message': 'Invalid token format! Use: Bearer <token>'}), 401

            token = parts[1]  # Extract token (second part)
            decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])  # Decode and verify token

            g.current_user = {'user_id': decoded['user_id'], 'email': decoded['email']}  # Store user info in g

        except jwt.ExpiredSignatureError:  # Token has expired
            return jsonify({'message': 'Token has expired!'}), 401

        except jwt.InvalidTokenError:  # Token is invalid
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(*args, **kwargs)  # Token valid - call the actual route function

    return decorated  # Return the wrapper function


@app.route('/register', methods=['POST'])  # Public route - no token needed
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


@app.route('/login', methods=['POST'])  # Public route - no token needed
def login():
    data = request.get_json()
    email, password = data.get('email'), data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required!'}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not check_password(password, user.password):
        return jsonify({'message': 'Invalid email or password!'}), 401

    return jsonify({'message': 'Login successful!', 'token': create_token(user), 'user': {'id': user.id, 'email': user.email}})


@app.route('/profile', methods=['GET'])  # Protected route
@token_required  # This decorator runs BEFORE get_profile(), checks token
def get_profile():
    user = User.query.get(g.current_user['user_id'])  # Get user using ID from token

    if not user:  # User deleted but token still valid
        return jsonify({'message': 'User not found!'}), 404

    return jsonify({
        'message': 'Profile retrieved successfully!',
        'profile': {'id': user.id, 'email': user.email, 'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S')}
    })


@app.route('/dashboard', methods=['GET'])  # Another protected route
@token_required  # Must have valid token
def get_dashboard():
    return jsonify({
        'message': 'Dashboard data retrieved!',
        'data': {
            'welcome': f"Hello, {g.current_user['email']}!",  # Use email from token
            'stats': {'total_posts': 10, 'total_likes': 50, 'total_comments': 25}  # Dummy data
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

1. Try: GET http://localhost:5000/profile (no Authorization header)
   What response do you get?

2. Try: GET http://localhost:5000/profile
   Header: Authorization: InvalidToken
   What response do you get?

3. Try: GET http://localhost:5000/profile
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
