from flask import Flask, jsonify, request, g, send_file  # Flask framework
from flask_cors import CORS  # Cross-origin requests
from flask_sqlalchemy import SQLAlchemy  # Database ORM
import bcrypt  # Password hashing
import jwt  # JWT tokens
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


class User(db.Model):  # User model with password change tracking
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)  # Primary key
    email = db.Column(db.String(120), unique=True, nullable=False)  # Unique email
    password = db.Column(db.String(255), nullable=False)  # Hashed password
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Created time
    password_changed_at = db.Column(db.DateTime, nullable=True)  # NEW: Track when password was last changed

    def to_dict(self):  # Convert to dictionary
        return {
            'id': self.id,
            'email': self.email,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'password_changed_at': self.password_changed_at.strftime('%Y-%m-%d %H:%M:%S') if self.password_changed_at else None
        }


def hash_password(password):  # Hash password
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def check_password(password, hashed_password):  # Verify password
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


def create_token(user):  # Create JWT token
    payload = {'user_id': user.id, 'email': user.email, 'exp': datetime.utcnow() + timedelta(hours=24)}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


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

            g.current_user = {'user_id': decoded['user_id'], 'email': decoded['email']}  # Store user info

        except jwt.ExpiredSignatureError:  # Token expired
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:  # Invalid token
            return jsonify({'message': 'Invalid token!'}), 401

        return f(*args, **kwargs)  # Call protected function
    return decorated


@app.route('/register', methods=['POST'])  # Register endpoint
def register():
    data = request.get_json()  # Get JSON data
    email, password = data.get('email'), data.get('password')  # Get credentials

    if not email or not password:  # Validate input
        return jsonify({'message': 'Email and password are required!'}), 400

    if len(password) < 6:  # Validate password length
        return jsonify({'message': 'Password must be at least 6 characters!'}), 400

    if User.query.filter_by(email=email).first():  # Check email exists
        return jsonify({'message': 'Email already exists!'}), 400

    new_user = User(email=email, password=hash_password(password))  # Create user
    db.session.add(new_user)  # Add to session
    db.session.commit()  # Save to database

    return jsonify({'message': 'User registered successfully!', 'user': new_user.to_dict()}), 201


@app.route('/login', methods=['POST'])  # Login endpoint
def login():
    data = request.get_json()  # Get JSON data
    email, password = data.get('email'), data.get('password')  # Get credentials

    if not email or not password:  # Validate input
        return jsonify({'message': 'Email and password are required!'}), 400

    user = User.query.filter_by(email=email).first()  # Find user

    if not user or not check_password(password, user.password):  # Invalid credentials
        return jsonify({'message': 'Invalid email or password!'}), 401

    return jsonify({'message': 'Login successful!', 'token': create_token(user), 'user': user.to_dict()})


@app.route('/profile', methods=['GET'])  # Get profile endpoint
@token_required
def get_profile():
    user = User.query.get(g.current_user['user_id'])  # Get user

    if not user:  # User not found
        return jsonify({'message': 'User not found!'}), 404

    return jsonify({'message': 'Profile retrieved!', 'profile': user.to_dict()})


@app.route('/change-password', methods=['POST'])  # Change password endpoint (MAIN FEATURE OF THIS PART!)
@token_required  # Must be logged in
def change_password():
    data = request.get_json()  # Get JSON data
    current_password = data.get('current_password')  # Get current password
    new_password = data.get('new_password')  # Get new password

    if not current_password:  # Step 1: Validate current password provided
        return jsonify({'message': 'Current password is required!'}), 400

    if not new_password:  # Step 2: Validate new password provided
        return jsonify({'message': 'New password is required!'}), 400

    user = User.query.get(g.current_user['user_id'])  # Step 3: Get current user

    if not user:  # User not found
        return jsonify({'message': 'User not found!'}), 404

    if not check_password(current_password, user.password):  # Step 4: Verify current password is correct
        return jsonify({'message': 'Current password is incorrect!'}), 401

    if len(new_password) < 6:  # Step 5: Validate new password length
        return jsonify({'message': 'New password must be at least 6 characters!'}), 400

    if check_password(new_password, user.password):  # Step 6: Check new password is different from current
        return jsonify({'message': 'New password must be different from current password!'}), 400

    user.password = hash_password(new_password)  # Step 7: Hash and save new password
    user.password_changed_at = datetime.utcnow()  # Step 8: Record when password was changed
    db.session.commit()  # Save changes

    return jsonify({  # Step 9: Return success
        'message': 'Password changed successfully!',
        'password_changed_at': user.password_changed_at.strftime('%Y-%m-%d %H:%M:%S')
    })


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    print("=" * 50)
    print("Change Password Server Running on http://localhost:5012")
    print("=" * 50)
    app.run(debug=True, port=5012)


# ===========================================
# EXERCISES - Try These!
# ===========================================
"""
EXERCISE 1: Test Password Change Flow
-------------------------------------
Test:
1. Register: email=test@test.com, password=password123
2. Login and save token
3. Change password: current_password=password123, new_password=newpass456
4. Try login with OLD password (should fail!)
5. Try login with NEW password (should work!)

Question: Why must we require the current password to change password?


EXERCISE 2: Test Same Password Rejection
----------------------------------------
Test:
1. Login
2. Try change password with same password:
   current_password=password123, new_password=password123

Question: What message do you get? Why prevent this?


EXERCISE 3: Add Password Confirmation
-------------------------------------
Many forms require typing new password twice:

In change_password(), add:
    confirm_password = data.get('confirm_password')

    if not confirm_password:
        return jsonify({'message': 'Password confirmation is required!'}), 400

    if new_password != confirm_password:
        return jsonify({'message': 'Passwords do not match!'}), 400

Question: Should password confirmation be on frontend, backend, or both? Why?


EXERCISE 4: Password Strength Validation
----------------------------------------
Add stronger password requirements:

import re

def validate_password_strength(password):
    if len(password) < 8:
        return False, 'Password must be at least 8 characters'
    if not re.search(r'[A-Z]', password):
        return False, 'Password must contain at least one uppercase letter'
    if not re.search(r'[a-z]', password):
        return False, 'Password must contain at least one lowercase letter'
    if not re.search(r'[0-9]', password):
        return False, 'Password must contain at least one number'
    return True, None

In change_password(), use it:
    is_strong, error = validate_password_strength(new_password)
    if not is_strong:
        return jsonify({'message': error}), 400

Test: Try weak passwords like "abc", "abcdefgh", "ABCDEFGH", "abcDEFgh"
Question: What other password rules could you add? (symbols? no common words?)


EXERCISE 5: Invalidate All Tokens After Password Change
-------------------------------------------------------
For extra security, logout user after password change:

1. Add password_changed_at to JWT:
    def create_token(user):
        payload = {
            'user_id': user.id,
            'password_version': user.password_changed_at.timestamp() if user.password_changed_at else 0,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }

2. In token_required, check password_version:
    user = User.query.get(decoded['user_id'])
    token_version = decoded.get('password_version', 0)
    current_version = user.password_changed_at.timestamp() if user.password_changed_at else 0
    if token_version != current_version:
        return jsonify({'message': 'Password was changed. Please login again.'}), 401

Question: Why invalidate old tokens when password changes?


EXERCISE 6: Password History
----------------------------
Prevent reusing recent passwords:

1. Create a model:
    class PasswordHistory(db.Model):
        __tablename__ = 'password_history'
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, nullable=False)
        password_hash = db.Column(db.String(255), nullable=False)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)

2. Before changing password, check history:
    recent_passwords = PasswordHistory.query.filter_by(user_id=user.id).order_by(PasswordHistory.created_at.desc()).limit(5).all()
    for old_pw in recent_passwords:
        if check_password(new_password, old_pw.password_hash):
            return jsonify({'message': 'Cannot reuse recent passwords!'}), 400

3. After changing, save to history:
    history = PasswordHistory(user_id=user.id, password_hash=user.password)
    db.session.add(history)

Question: Why prevent password reuse? How many old passwords should you track?


SELF-STUDY QUESTIONS
--------------------
1. Why require current password when changing password? Why not just let logged-in users change it?

2. What's the difference between "change password" and "forgot password/reset password"?

3. Should the user be logged out after changing password? Pros and cons?

4. Why track password_changed_at? What can you use it for?

5. How would you implement "force password change after 90 days"?
"""
