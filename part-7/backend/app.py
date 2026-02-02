from flask import Flask, jsonify, request, send_file  # Flask framework
from flask_cors import CORS  # Cross-origin requests
from flask_sqlalchemy import SQLAlchemy  # Database ORM
# Password hashing using werkzeug.security (comes built-in with Flask)
from werkzeug.security import generate_password_hash, check_password_hash
import jwt  # From 'pyjwt' package (pip install pyjwt), NOT 'jwt'
import secrets  # Random tokens
import requests  # For calling Mailgun API
import os  # For environment variables
from datetime import datetime, timedelta  # Date/time
from dotenv import load_dotenv  # Load .env file

load_dotenv()  # Load environment variables from .env file

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

SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-keep-it-safe')  # Get from env or use default
FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:5007')  # Frontend URL for reset link
MAILGUN_API_KEY = os.getenv('MAILGUN_API_KEY')  # Mailgun API key from env
MAILGUN_DOMAIN = os.getenv('MAILGUN_DOMAIN')  # Mailgun domain from env
MAILGUN_SENDER = os.getenv('MAILGUN_SENDER', 'Password Reset <noreply@example.com>')  # Sender email

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


# Hash password - converts plain text to secure hash
def hash_password(password):
    return generate_password_hash(password)


# Verify password - compares plain password with stored hash
def check_password(password, hashed_password):
    return check_password_hash(hashed_password, password)


def create_token(user):  # Create JWT
    payload = {'user_id': user.id, 'email': user.email, 'exp': datetime.utcnow() + timedelta(hours=24)}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


def generate_reset_token():  # Generate random token
    return secrets.token_hex(32)


def send_reset_email(to_email, reset_link):  # Send email via Mailgun
    if not MAILGUN_API_KEY or not MAILGUN_DOMAIN:  # Check if Mailgun is configured
        print("Mailgun not configured - skipping email send")  # Log warning
        return False  # Return false to indicate email not sent

    subject = "Password Reset Request"  # Email subject

    text_content = f"""
Hello,

You requested to reset your password. Click the link below:
{reset_link}

This link expires in 1 hour.

If you didn't request this, ignore this email.
    """  # Plain text version

    html_content = f"""
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px;">
        <h2>Password Reset Request</h2>
        <p>You requested to reset your password.</p>
        <p><a href="{reset_link}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a></p>
        <p><small>Link: {reset_link}</small></p>
        <p><small>Expires in 1 hour.</small></p>
    </body>
    </html>
    """  # HTML version (looks nicer)

    try:
        url = f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages"  # Mailgun API endpoint
        response = requests.post(url, auth=("api", MAILGUN_API_KEY), data={"from": MAILGUN_SENDER, "to": to_email, "subject": subject, "text": text_content, "html": html_content})  # Send POST request
        if response.status_code == 200:  # Success
            print(f"Email sent to {to_email}")  # Log success
            return True
        else:  # Failed
            print(f"Email failed: {response.status_code} - {response.text}")  # Log error
            return False
    except Exception as e:  # Error
        print(f"Email error: {str(e)}")  # Log exception
        return False


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


@app.route('/forgot-password', methods=['POST'])  # Forgot password with email
def forgot_password():
    data = request.get_json()  # Get request data
    email = data.get('email')  # Get email

    if not email:  # Validate email
        return jsonify({'message': 'Email is required!'}), 400

    user = User.query.filter_by(email=email).first()  # Find user
    response_message = "If this email exists, a password reset link has been sent."  # Security message

    if not user:  # User not found - return same message (don't reveal if email exists)
        return jsonify({'message': response_message})

    reset_token = generate_reset_token()  # Generate token
    token_record = PasswordResetToken(user_id=user.id, token=reset_token, expires_at=datetime.utcnow() + timedelta(hours=1), used=False)
    db.session.add(token_record)
    db.session.commit()

    reset_link = f"{FRONTEND_URL}/reset-password?token={reset_token}"  # Build reset link
    email_sent = send_reset_email(email, reset_link)  # Try to send email

    if not email_sent:  # Mailgun not configured - return link for local testing
        return jsonify({'message': 'Password reset link generated (email not configured)', 'reset_link': reset_link, 'token': reset_token, 'note': 'Configure Mailgun to send real emails'})

    return jsonify({'message': response_message, 'email_sent': True})  # Email sent


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
            <h2 style="color:red;">{error}</h2><a href="/">Back</a></body></html>'''

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
                        <input type="password" id="newPassword" class="form-control">
                    </div>
                    <button onclick="resetPassword()" class="btn btn-success w-100">Reset Password</button>
                    <div id="result" class="mt-3"></div>
                </div>
            </div>
        </div>
        <script>
            async function resetPassword() {{
                const newPass = document.getElementById('newPassword').value;
                if (newPass.length < 6) {{
                    document.getElementById('result').innerHTML = '<div class="alert alert-danger">Min 6 characters!</div>';
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


@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token, new_password = data.get('token'), data.get('new_password')
    if not token:
        return jsonify({'message': 'Token is required!'}), 400
    if not new_password or len(new_password) < 6:
        return jsonify({'message': 'Password must be at least 6 characters!'}), 400
    token_record = PasswordResetToken.query.filter_by(token=token).first()
    if not token_record or token_record.used or token_record.expires_at < datetime.utcnow():
        return jsonify({'message': 'Invalid or expired token!'}), 400
    user = token_record.user
    user.password = hash_password(new_password)
    token_record.used = True
    db.session.commit()
    return jsonify({'message': 'Password reset successful!', 'email': user.email})


@app.route('/config-status', methods=['GET'])  # Check Mailgun configuration
def config_status():
    return jsonify({'mailgun_configured': bool(MAILGUN_API_KEY and MAILGUN_DOMAIN), 'mailgun_domain': MAILGUN_DOMAIN[:10] + '...' if MAILGUN_DOMAIN else None, 'frontend_url': FRONTEND_URL})


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    print("=" * 50)
    print("Mailgun Email Server Running on http://localhost:5007")
    print("=" * 50)
    print(f"Mailgun: {'CONFIGURED' if MAILGUN_API_KEY else 'NOT CONFIGURED'}")
    app.run(debug=True, port=5007)


# ===========================================
# EXERCISES - Try These!
# ===========================================
"""
EXERCISE 1: Set Up Mailgun (Real Email)
---------------------------------------
1. Go to mailgun.com and create free account
2. Get API key from Dashboard > API Keys
3. Get sandbox domain from Sending > Domains
4. Add your email as "Authorized Recipient"
5. Create .env file with:
   MAILGUN_API_KEY=your-key
   MAILGUN_DOMAIN=sandbox123.mailgun.org
6. Restart server and test

Question: Why do sandbox domains need authorized recipients?


EXERCISE 2: Customize Email Template
------------------------------------
Modify the html_content in send_reset_email():

- Change button color: background-color: #28a745 (green)
- Add your app name
- Add a footer with support email

Test: Send a reset email and view the HTML
Question: Why have both text and HTML versions?


EXERCISE 3: Add Email Logging
-----------------------------
Log all email attempts:

import logging
logging.basicConfig(filename='email.log', level=logging.INFO)

In send_reset_email(), add:
    logging.info(f"Email attempt to {to_email} at {datetime.utcnow()}")
    # After success:
    logging.info(f"Email sent successfully to {to_email}")
    # After failure:
    logging.error(f"Email failed to {to_email}: {response.text}")

Question: Why is email logging important?


EXERCISE 4: Test Without Mailgun
--------------------------------
Comment out the Mailgun credentials in .env:
# MAILGUN_API_KEY=...
# MAILGUN_DOMAIN=...

Test forgot-password endpoint.
Question: What response do you get? How does the code handle missing config?


EXERCISE 5: Add Email Verification Check
----------------------------------------
Before sending reset email, you might want to verify the email format:

import re
def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

Use in forgot_password():
    if not is_valid_email(email):
        return jsonify({'message': 'Invalid email format!'}), 400

Question: Should email validation be on frontend, backend, or both?


SELF-STUDY QUESTIONS
--------------------
1. Why use environment variables for API keys instead of hardcoding?

2. What is a "sandbox" domain in Mailgun?

3. Why don't we reveal whether an email exists in the response?

4. What happens if Mailgun API is down? How would you handle it?

5. What's the difference between API key authentication and OAuth?
"""
