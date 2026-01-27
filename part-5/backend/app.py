from flask import Flask, jsonify, request, g, send_file  # Flask framework and utilities
from flask_cors import CORS  # Cross-origin requests
from flask_sqlalchemy import SQLAlchemy  # Database ORM
import bcrypt  # Password hashing
import jwt  # JWT tokens
import secrets  # For generating random tokens
from datetime import datetime, timedelta  # Date/time handling
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


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Database file
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable tracking
SECRET_KEY = 'your-secret-key-keep-it-safe'  # JWT secret
BASE_URL = 'http://localhost:5005'  # Base URL for reset links

db = SQLAlchemy(app)  # Database instance


class User(db.Model):  # User model
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)  # Primary key
    email = db.Column(db.String(120), unique=True, nullable=False)  # Unique email
    password = db.Column(db.String(255), nullable=False)  # Hashed password
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Created time


class PasswordResetToken(db.Model):  # Model to store reset tokens
    __tablename__ = 'password_reset_tokens'
    id = db.Column(db.Integer, primary_key=True)  # Primary key
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Links to user
    token = db.Column(db.String(100), unique=True, nullable=False)  # Random token string
    expires_at = db.Column(db.DateTime, nullable=False)  # When token expires
    used = db.Column(db.Boolean, default=False)  # Has token been used?
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # When created
    user = db.relationship('User', backref='reset_tokens')  # Relationship to User


def hash_password(password):  # Hash a password
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def check_password(password, hashed_password):  # Verify password
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


def create_token(user):  # Create JWT token
    payload = {'user_id': user.id, 'email': user.email, 'exp': datetime.utcnow() + timedelta(hours=24)}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


def generate_reset_token():  # Generate random 64-character token
    return secrets.token_hex(32)  # 32 bytes = 64 hex characters


@app.route('/register', methods=['POST'])  # Register endpoint
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
    return jsonify({'message': 'User registered!', 'user': {'id': new_user.id, 'email': new_user.email}}), 201


@app.route('/login', methods=['POST'])  # Login endpoint
def login():
    data = request.get_json()
    email, password = data.get('email'), data.get('password')
    if not email or not password:
        return jsonify({'message': 'Email and password are required!'}), 400
    user = User.query.filter_by(email=email).first()
    if not user or not check_password(password, user.password):
        return jsonify({'message': 'Invalid email or password!'}), 401
    return jsonify({'message': 'Login successful!', 'token': create_token(user), 'user': {'id': user.id, 'email': user.email}})


@app.route('/forgot-password', methods=['POST'])  # Request password reset
def forgot_password():
    data = request.get_json()  # Get request data
    email = data.get('email')  # Get email from request

    if not email:  # Validate email provided
        return jsonify({'message': 'Email is required!'}), 400

    user = User.query.filter_by(email=email).first()  # Find user by email

    if not user:  # For testing: tell if email not found (in production, don't reveal this)
        return jsonify({'message': 'Email not found!'}), 404

    reset_token = generate_reset_token()  # Generate random token

    token_record = PasswordResetToken(  # Create token record
        user_id=user.id,  # Link to user
        token=reset_token,  # Store token
        expires_at=datetime.utcnow() + timedelta(hours=1),  # Expires in 1 hour
        used=False  # Not used yet
    )

    db.session.add(token_record)  # Add to session
    db.session.commit()  # Save to database

    reset_link = f"{BASE_URL}/reset-password?token={reset_token}"  # Build reset link

    return jsonify({  # Return reset link (in production, send via email)
        'message': 'Password reset link generated!',
        'reset_link': reset_link,
        'token': reset_token,  # Return token for easy testing
        'expires_in': '1 hour',
        'note': 'In production, this link would be sent via email'
    })


@app.route('/verify-reset-token', methods=['POST'])  # Check if token is valid
def verify_reset_token():
    data = request.get_json()  # Get request data
    token = data.get('token')  # Get token

    if not token:  # Validate token provided
        return jsonify({'message': 'Token is required!'}), 400

    token_record = PasswordResetToken.query.filter_by(token=token).first()  # Find token in database

    if not token_record:  # Token doesn't exist
        return jsonify({'valid': False, 'message': 'Invalid token!'}), 400

    if token_record.used:  # Token already used
        return jsonify({'valid': False, 'message': 'Token has already been used!'}), 400

    if token_record.expires_at < datetime.utcnow():  # Token expired
        return jsonify({'valid': False, 'message': 'Token has expired!'}), 400

    return jsonify({'valid': True, 'message': 'Token is valid!', 'email': token_record.user.email})


@app.route('/reset-password', methods=['GET'])  # Serve reset password page when link is clicked
def reset_password_page():
    token = request.args.get('token')  # Get token from URL: /reset-password?token=xxx

    if not token:
        return '''
        <html><body style="font-family: Arial; padding: 40px; text-align: center;">
            <h2 style="color: red;">Error: No Token Provided</h2>
            <p>Please use the link from your email.</p>
        </body></html>
        '''

    # Verify the token
    token_record = PasswordResetToken.query.filter_by(token=token).first()

    if not token_record:
        status = "Invalid token!"
        color = "red"
        valid = False
    elif token_record.used:
        status = "Token has already been used!"
        color = "orange"
        valid = False
    elif token_record.expires_at < datetime.utcnow():
        status = "Token has expired!"
        color = "orange"
        valid = False
    else:
        status = f"Token is valid! Email: {token_record.user.email}"
        color = "green"
        valid = True

    return f'''
    <html>
    <head>
        <title>Part 5: Token Verification</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <div class="container py-5">
            <div class="card mx-auto" style="max-width: 500px;">
                <div class="card-header bg-primary text-white">
                    <h4>Part 5: Token Verification Result</h4>
                </div>
                <div class="card-body text-center">
                    <h3 style="color: {color};">{status}</h3>
                    <hr>
                    <p><strong>Token:</strong><br><small>{token[:20]}...</small></p>
                    <div class="alert alert-info mt-3">
                        <strong>Note:</strong> Part 5 only covers token generation and verification.<br>
                        Part 6 covers the actual password reset functionality.
                    </div>
                    <a href="/" class="btn btn-primary">Back to Home</a>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    print("=" * 50)
    print("Forgot Password Server Running on http://localhost:5005")
    print("=" * 50)
    app.run(debug=True, port=5005)


# ===========================================
# EXERCISES - Try These!
# ===========================================
"""
EXERCISE 1: Change Token Expiration Time
----------------------------------------
Current code (line 83):
    expires_at=datetime.utcnow() + timedelta(hours=1)

Try changing to:
    expires_at=datetime.utcnow() + timedelta(seconds=30)

Test:
1. Request forgot-password
2. Wait 30 seconds
3. Call verify-reset-token

Question: What message do you get? Why is expiration important for security?


EXERCISE 2: See the Token in Database
-------------------------------------
Add this route to view all tokens:

@app.route('/debug/tokens', methods=['GET'])
def debug_tokens():
    tokens = PasswordResetToken.query.all()
    return jsonify({
        'tokens': [{
            'id': t.id,
            'user_email': t.user.email,
            'token': t.token[:20] + '...',  # Show first 20 chars
            'expires_at': t.expires_at.strftime('%Y-%m-%d %H:%M:%S'),
            'used': t.used
        } for t in tokens]
    })

Test: Create multiple reset requests and view them
Question: Why do we store tokens in database instead of just in memory?


EXERCISE 3: Prevent Multiple Active Tokens
------------------------------------------
Currently, a user can request multiple reset tokens.
Add code to invalidate old tokens when creating new one:

In forgot_password(), before creating new token:
    # Mark all old tokens for this user as used
    old_tokens = PasswordResetToken.query.filter_by(user_id=user.id, used=False).all()
    for old_token in old_tokens:
        old_token.used = True

Question: Why might you want only one active reset token per user?


EXERCISE 4: Add Rate Limiting (Simple Version)
----------------------------------------------
Prevent spam by limiting reset requests:

# At the top of forgot_password():
    # Check if user requested reset in last 5 minutes
    recent_token = PasswordResetToken.query.filter(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.created_at > datetime.utcnow() - timedelta(minutes=5)
    ).first()

    if recent_token:
        return jsonify({'message': 'Please wait 5 minutes before requesting again'}), 429

Question: Why is rate limiting important? What does status code 429 mean?


SELF-STUDY QUESTIONS
--------------------
1. Why use secrets.token_hex() instead of random string generators?

2. What's the difference between token expiration and "used" flag?

3. In production, should we tell users if email exists? Why/why not?

4. Why store reset tokens in database instead of sending them in email only?

5. What happens if someone intercepts the reset link?
"""
