from flask import Flask, jsonify, request, send_file  # Flask framework
from flask_cors import CORS  # Cross-origin requests
from flask_sqlalchemy import SQLAlchemy  # Database ORM
import bcrypt  # Password hashing
import jwt  # JWT tokens
import secrets  # Random tokens
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
BASE_URL = 'http://localhost:5006'  # Base URL

db = SQLAlchemy(app)  # Database instance


class User(db.Model):  # User model
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class PasswordResetToken(db.Model):  # Reset token model
    __tablename__ = 'password_reset_tokens'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='reset_tokens')


def hash_password(password):  # Hash password
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def check_password(password, hashed_password):  # Verify password
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


def create_token(user):  # Create JWT
    payload = {'user_id': user.id, 'email': user.email, 'exp': datetime.utcnow() + timedelta(hours=24)}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


def generate_reset_token():  # Generate random token
    return secrets.token_hex(32)


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
    return jsonify({'message': 'User registered!', 'user': {'id': new_user.id, 'email': new_user.email}}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email, password = data.get('email'), data.get('password')
    if not email or not password:
        return jsonify({'message': 'Email and password are required!'}), 400
    user = User.query.filter_by(email=email).first()
    if not user or not check_password(password, user.password):
        return jsonify({'message': 'Invalid email or password!'}), 401
    return jsonify({'message': 'Login successful!', 'token': create_token(user), 'user': {'id': user.id, 'email': user.email}})


@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({'message': 'Email is required!'}), 400
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'Email not found!'}), 404
    reset_token = generate_reset_token()
    token_record = PasswordResetToken(user_id=user.id, token=reset_token, expires_at=datetime.utcnow() + timedelta(hours=1), used=False)
    db.session.add(token_record)
    db.session.commit()
    reset_link = f"{BASE_URL}/reset-password?token={reset_token}"
    return jsonify({'message': 'Password reset link generated!', 'reset_link': reset_link, 'token': reset_token, 'expires_in': '1 hour'})


@app.route('/verify-reset-token', methods=['POST'])
def verify_reset_token():
    data = request.get_json()
    token = data.get('token')
    if not token:
        return jsonify({'message': 'Token is required!'}), 400
    token_record = PasswordResetToken.query.filter_by(token=token).first()
    if not token_record:
        return jsonify({'valid': False, 'message': 'Invalid token!'}), 400
    if token_record.used:
        return jsonify({'valid': False, 'message': 'Token has already been used!'}), 400
    if token_record.expires_at < datetime.utcnow():
        return jsonify({'valid': False, 'message': 'Token has expired!'}), 400
    return jsonify({'valid': True, 'message': 'Token is valid!', 'email': token_record.user.email})


@app.route('/reset-password', methods=['GET'])  # Serve reset password page
def reset_password_page():
    token = request.args.get('token')

    if not token:
        return '''<html><body style="font-family:Arial;padding:40px;text-align:center;">
            <h2 style="color:red;">Error: No Token</h2></body></html>'''

    # Verify token first
    token_record = PasswordResetToken.query.filter_by(token=token).first()

    if not token_record:
        error = "Invalid token!"
    elif token_record.used:
        error = "Token has already been used!"
    elif token_record.expires_at < datetime.utcnow():
        error = "Token has expired!"
    else:
        error = None

    if error:
        return f'''<html><body style="font-family:Arial;padding:40px;text-align:center;">
            <h2 style="color:red;">{error}</h2>
            <a href="/">Back to Home</a></body></html>'''

    return f'''
    <html>
    <head>
        <title>Reset Password</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <div class="container py-5">
            <div class="card mx-auto" style="max-width:400px;">
                <div class="card-header bg-success text-white"><h4>Reset Password</h4></div>
                <div class="card-body">
                    <p>Email: <strong>{token_record.user.email}</strong></p>
                    <div class="mb-3">
                        <label class="form-label">New Password:</label>
                        <input type="password" id="newPassword" class="form-control" minlength="6">
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Confirm Password:</label>
                        <input type="password" id="confirmPassword" class="form-control">
                    </div>
                    <button onclick="resetPassword()" class="btn btn-success w-100">Reset Password</button>
                    <div id="result" class="mt-3"></div>
                </div>
            </div>
        </div>
        <script>
            async function resetPassword() {{
                const newPass = document.getElementById('newPassword').value;
                const confirmPass = document.getElementById('confirmPassword').value;

                if (newPass.length < 6) {{
                    document.getElementById('result').innerHTML = '<div class="alert alert-danger">Password must be at least 6 characters!</div>';
                    return;
                }}
                if (newPass !== confirmPass) {{
                    document.getElementById('result').innerHTML = '<div class="alert alert-danger">Passwords do not match!</div>';
                    return;
                }}

                const res = await fetch('/reset-password', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{token: '{token}', new_password: newPass}})
                }});
                const data = await res.json();

                if (res.ok) {{
                    document.getElementById('result').innerHTML = '<div class="alert alert-success">' + data.message + '</div>';
                    setTimeout(() => window.location.href = '/', 2000);
                }} else {{
                    document.getElementById('result').innerHTML = '<div class="alert alert-danger">' + data.message + '</div>';
                }}
            }}
        </script>
    </body>
    </html>
    '''


@app.route('/reset-password', methods=['POST'])  # Reset password endpoint
def reset_password():
    data = request.get_json()  # Get request data
    token = data.get('token')  # Get reset token
    new_password = data.get('new_password')  # Get new password

    if not token:  # Validate token provided
        return jsonify({'message': 'Token is required!'}), 400

    if not new_password:  # Validate password provided
        return jsonify({'message': 'New password is required!'}), 400

    if len(new_password) < 6:  # Validate password length
        return jsonify({'message': 'Password must be at least 6 characters!'}), 400

    token_record = PasswordResetToken.query.filter_by(token=token).first()  # Find token in database

    if not token_record:  # Token not found
        return jsonify({'message': 'Invalid token!'}), 400

    if token_record.used:  # Token already used (one-time use)
        return jsonify({'message': 'Token has already been used!'}), 400

    if token_record.expires_at < datetime.utcnow():  # Token expired
        return jsonify({'message': 'Token has expired!'}), 400

    user = token_record.user  # Get user from token relationship

    user.password = hash_password(new_password)  # Hash and set new password

    token_record.used = True  # Mark token as used (cannot be used again)

    db.session.commit()  # Save changes to database

    return jsonify({'message': 'Password reset successful! You can now login.', 'email': user.email})


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    print("=" * 50)
    print("Reset Password Server Running on http://localhost:5006")
    print("=" * 50)
    app.run(debug=True, port=5006)


# ===========================================
# EXERCISES - Try These!
# ===========================================
"""
EXERCISE 1: Test One-Time Use Token
-----------------------------------
Test:
1. Request forgot-password to get a token
2. Use the token to reset password (success)
3. Try using the SAME token again

Question: What message do you get? Why is one-time use important?


EXERCISE 2: Prevent Same Password
---------------------------------
Currently, users can "reset" to the same password.
Add this check before updating password:

    # Check if new password is same as old
    if check_password(new_password, user.password):
        return jsonify({'message': 'New password cannot be same as old password!'}), 400

Question: Why might you want to prevent this?


EXERCISE 3: Add Password Confirmation
-------------------------------------
Many forms ask user to type password twice.
Modify the API to accept 'confirm_password':

    confirm_password = data.get('confirm_password')

    if new_password != confirm_password:
        return jsonify({'message': 'Passwords do not match!'}), 400

Test: Send mismatched passwords
Question: Should this check be on frontend, backend, or both? Why?


EXERCISE 4: Log Password Resets
-------------------------------
Add logging to track password resets:

At the top, add: import logging
Configure logging: logging.basicConfig(level=logging.INFO)

Before return success:
    logging.info(f"Password reset for user {user.email} at {datetime.utcnow()}")

Question: Why is logging important for security audits?


EXERCISE 5: Delete Token After Use (Alternative to "used" flag)
---------------------------------------------------------------
Instead of marking token as "used", you could delete it:

Replace:
    token_record.used = True

With:
    db.session.delete(token_record)

Question: What are pros/cons of delete vs "used" flag?
(Hint: Think about audit trails)


SELF-STUDY QUESTIONS
--------------------
1. What's the complete flow from "forgot password" to "new password working"?

2. Why do we hash the new password before storing?

3. What would happen if we didn't check token expiration?

4. Why is password minimum length important?

5. After resetting password, should the user be logged in automatically?
   What are pros/cons?
"""
