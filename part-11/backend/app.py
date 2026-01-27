from flask import Flask, jsonify, request, g, send_file  # Flask framework
from flask_cors import CORS  # Cross-origin requests
from flask_sqlalchemy import SQLAlchemy  # Database ORM
import bcrypt  # Password hashing
import jwt  # JWT tokens
import secrets  # For generating random tokens
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


@app.route('/verify.html')  # Serve the verify HTML page
def verify_page():
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'verify.html')
    return send_file(html_path)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable tracking
SECRET_KEY = 'your-secret-key-keep-it-safe'  # JWT secret
FRONTEND_URL = 'http://localhost:5011'  # Frontend URL for verification link

db = SQLAlchemy(app)  # Database instance


class User(db.Model):  # User model with verification fields
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)  # Primary key
    email = db.Column(db.String(120), unique=True, nullable=False)  # Unique email
    password = db.Column(db.String(255), nullable=False)  # Hashed password
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Created time
    is_verified = db.Column(db.Boolean, default=False)  # NEW: Is email verified?
    verification_token = db.Column(db.String(100), unique=True, nullable=True)  # NEW: Verification token
    verification_expires = db.Column(db.DateTime, nullable=True)  # NEW: When token expires

    def to_dict(self):  # Convert to dictionary
        return {'id': self.id, 'email': self.email, 'is_verified': self.is_verified, 'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')}


def hash_password(password):  # Hash password
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def check_password(password, hashed_password):  # Verify password
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


def create_token(user):  # Create JWT with is_verified included
    payload = {'user_id': user.id, 'email': user.email, 'is_verified': user.is_verified, 'exp': datetime.utcnow() + timedelta(hours=24)}  # is_verified in payload
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


def generate_verification_token():  # Generate random URL-safe token
    return secrets.token_urlsafe(32)  # 32 bytes = 43 characters


def token_required(f):  # Decorator to require valid JWT
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')  # Get auth header

        if not auth_header:  # No header
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            parts = auth_header.split(' ')  # Split "Bearer <token>"
            if len(parts) != 2 or parts[0] != 'Bearer':  # Invalid format
                return jsonify({'message': 'Invalid token format!'}), 401

            token = parts[1]  # Get token
            decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])  # Decode token

            g.current_user = {'user_id': decoded['user_id'], 'email': decoded['email'], 'is_verified': decoded.get('is_verified', False)}  # Store user info

        except jwt.ExpiredSignatureError:  # Token expired
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:  # Invalid token
            return jsonify({'message': 'Invalid token!'}), 401

        return f(*args, **kwargs)  # Call protected function
    return decorated


def verified_required(f):  # Decorator to require verified email - MUST use AFTER @token_required
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.current_user.get('is_verified'):  # Check if verified
            return jsonify({'message': 'Email not verified! Please verify your email first.', 'error': 'EMAIL_NOT_VERIFIED'}), 403

        return f(*args, **kwargs)  # Call protected function
    return decorated


@app.route('/register', methods=['POST'])  # Register - creates unverified user
def register():
    data = request.get_json()  # Get JSON data
    email, password = data.get('email'), data.get('password')  # Get credentials

    if not email or not password:  # Validate input
        return jsonify({'message': 'Email and password are required!'}), 400

    if User.query.filter_by(email=email).first():  # Check email exists
        return jsonify({'message': 'Email already exists!'}), 400

    verification_token = generate_verification_token()  # Generate verification token

    new_user = User(
        email=email,
        password=hash_password(password),
        is_verified=False,  # Start as unverified
        verification_token=verification_token,  # Store token
        verification_expires=datetime.utcnow() + timedelta(hours=24)  # Token expires in 24 hours
    )

    db.session.add(new_user)  # Add to session
    db.session.commit()  # Save to database

    verification_link = f"{FRONTEND_URL}/verify.html?token={verification_token}"  # Build verification link

    return jsonify({
        'message': 'Registration successful! Please verify your email.',
        'user': new_user.to_dict(),
        'verification_link': verification_link,  # For local testing (in production, send via email)
        'note': 'In production, this link would be sent via email'
    }), 201


@app.route('/verify-email', methods=['GET'])  # Verify email using token
def verify_email():
    token = request.args.get('token')  # Get token from URL: /verify-email?token=xxx

    if not token:  # No token
        return jsonify({'message': 'Verification token is required!'}), 400

    user = User.query.filter_by(verification_token=token).first()  # Find user by token

    if not user:  # Token not found
        return jsonify({'message': 'Invalid verification token!'}), 400

    if user.is_verified:  # Already verified
        return jsonify({'message': 'Email already verified!', 'user': user.to_dict()})

    if user.verification_expires < datetime.utcnow():  # Token expired
        return jsonify({'message': 'Verification token has expired! Please request a new one.'}), 400

    user.is_verified = True  # Mark as verified
    user.verification_token = None  # Clear token (one-time use)
    user.verification_expires = None  # Clear expiration
    db.session.commit()  # Save changes

    return jsonify({'message': 'Email verified successfully! You can now login.', 'user': user.to_dict()})


@app.route('/resend-verification', methods=['POST'])  # Resend verification email
def resend_verification():
    data = request.get_json()  # Get JSON data
    email = data.get('email')  # Get email

    if not email:  # No email
        return jsonify({'message': 'Email is required!'}), 400

    user = User.query.filter_by(email=email).first()  # Find user

    if not user:  # Don't reveal if email exists (security)
        return jsonify({'message': 'If this email exists, a verification link has been sent.'})

    if user.is_verified:  # Already verified
        return jsonify({'message': 'Email is already verified!'})

    verification_token = generate_verification_token()  # Generate new token
    user.verification_token = verification_token  # Update token
    user.verification_expires = datetime.utcnow() + timedelta(hours=24)  # Reset expiration
    db.session.commit()  # Save changes

    verification_link = f"{FRONTEND_URL}/verify.html?token={verification_token}"  # Build link

    return jsonify({
        'message': 'Verification link generated!',
        'verification_link': verification_link,
        'note': 'In production, this would be sent via email'
    })


@app.route('/login', methods=['POST'])  # Login - works for both verified and unverified
def login():
    data = request.get_json()  # Get JSON data
    email, password = data.get('email'), data.get('password')  # Get credentials

    if not email or not password:  # Validate input
        return jsonify({'message': 'Email and password are required!'}), 400

    user = User.query.filter_by(email=email).first()  # Find user

    if not user or not check_password(password, user.password):  # Invalid credentials
        return jsonify({'message': 'Invalid email or password!'}), 401

    token = create_token(user)  # Create JWT

    response = {'message': 'Login successful!', 'token': token, 'user': user.to_dict()}

    if not user.is_verified:  # Warn if not verified
        response['warning'] = 'Email not verified. Some features may be restricted.'

    return jsonify(response)


@app.route('/profile', methods=['GET'])  # Protected route - ONLY verified users
@token_required
@verified_required  # Requires verified email
def get_profile():
    user = User.query.get(g.current_user['user_id'])  # Get user

    if not user:  # User not found
        return jsonify({'message': 'User not found!'}), 404

    return jsonify({'message': 'Profile retrieved!', 'profile': user.to_dict()})


@app.route('/profile-unverified', methods=['GET'])  # Route for ANY logged-in user (verified or not)
@token_required  # Only requires login, not verification
def get_profile_unverified():
    user = User.query.get(g.current_user['user_id'])  # Get user

    return jsonify({
        'message': 'Basic profile retrieved!',
        'profile': user.to_dict(),
        'note': 'This route works for unverified users too'
    })


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    print("=" * 50)
    print("Email Verification Server Running on http://localhost:5011")
    print("=" * 50)
    app.run(debug=True, port=5011)


# ===========================================
# EXERCISES - Try These!
# ===========================================
"""
EXERCISE 1: Test Verified vs Unverified Access
----------------------------------------------
Test:
1. Register a new user (don't verify yet)
2. Login and get token
3. Try GET /profile (should fail with EMAIL_NOT_VERIFIED)
4. Try GET /profile-unverified (should work!)
5. Verify email using the verification link
6. Login again (to get updated token)
7. Try GET /profile (should work now!)

Question: Why do we need to login again after verification?
(Hint: is_verified is stored in the JWT token)


EXERCISE 2: Change Token Expiration
-----------------------------------
Current: verification_expires=datetime.utcnow() + timedelta(hours=24)

Try changing to:
    verification_expires=datetime.utcnow() + timedelta(minutes=5)

Test:
1. Register a user
2. Wait 5+ minutes
3. Try to verify email

Question: What error message do you get? Why set expiration on verification tokens?


EXERCISE 3: Rate Limit Resend Verification
------------------------------------------
Prevent spam by limiting resend requests:

In resend_verification(), before generating new token:
    # Check if recently sent (within 2 minutes)
    if user.verification_expires and user.verification_expires > datetime.utcnow() + timedelta(hours=23, minutes=58):
        return jsonify({'message': 'Please wait 2 minutes before requesting again.'}), 429

Question: Why is rate limiting important? What does status code 429 mean?


EXERCISE 4: Auto-Delete Unverified Users
----------------------------------------
Delete users who never verified after 7 days:

@app.route('/admin/cleanup-unverified', methods=['POST'])
def cleanup_unverified():
    cutoff = datetime.utcnow() - timedelta(days=7)
    unverified = User.query.filter(
        User.is_verified == False,
        User.created_at < cutoff
    ).all()
    count = len(unverified)
    for user in unverified:
        db.session.delete(user)
    db.session.commit()
    return jsonify({'message': f'Deleted {count} unverified users'})

Question: Why might you want to delete old unverified accounts?


EXERCISE 5: Add Verification Status to Login Response
-----------------------------------------------------
Show different message based on verification status:

In login(), modify the response:
    if not user.is_verified:
        response['warning'] = 'Email not verified!'
        response['verification_required'] = True
        response['can_resend'] = True
    else:
        response['verified_at'] = 'Email verified'  # You could add a verified_at column

Question: How would the frontend use this information?


EXERCISE 6: Block Login for Unverified Users
--------------------------------------------
Some apps require verification before login:

In login(), after finding user:
    if not user.is_verified:
        return jsonify({
            'message': 'Please verify your email before logging in!',
            'error': 'EMAIL_NOT_VERIFIED'
        }), 403

Question: What are pros and cons of blocking vs allowing unverified login?


SELF-STUDY QUESTIONS
--------------------
1. Why verify email? What problems does it solve?

2. Why use secrets.token_urlsafe() instead of a simple random string?

3. What's the difference between @token_required and @verified_required decorators?

4. Should users be able to change their email? What verification is needed?

5. What happens if someone registers with YOUR email? How does verification prevent abuse?
"""
