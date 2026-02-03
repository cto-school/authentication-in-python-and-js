# ================================================================================
# CHAPTER 11: Email Integration with Mailgun
# ================================================================================
#
# This chapter transforms simulated email flows into REAL email delivery.
#
# WHAT YOU'LL LEARN:
#   1. Setting up Mailgun for email delivery
#   2. Using environment variables for secrets (python-dotenv)
#   3. Creating professional HTML email templates
#   4. Sending verification and password reset emails
#   5. Handling email delivery failures gracefully
#
# MAILGUN SETUP (Do this before running):
#   1. Go to https://www.mailgun.com/ and create a free account
#   2. Get your API key from Settings > API Keys
#   3. Get your sandbox domain from Sending > Domains
#   4. Add authorized recipients (sandbox mode only allows verified emails)
#   5. Copy .env.example to .env and fill in your values
#
# ================================================================================

from flask import Flask, jsonify, request, g, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import secrets
from datetime import datetime, timedelta
from functools import wraps
import os
import warnings

# ================================================================================
# python-dotenv - Environment Variables
# ================================================================================
# Loads variables from .env file into os.environ
# This keeps secrets OUT of your code!
#
# .env file example:
#   MAILGUN_API_KEY=key-xxxxxxxxxxxxxxxx
#   MAILGUN_DOMAIN=sandboxXXXXX.mailgun.org
#   SECRET_KEY=your-super-secret-key
#
# IMPORTANT: Add .env to .gitignore - never commit secrets!
# ================================================================================
from dotenv import load_dotenv
load_dotenv()  # Load .env file

# Import our email service module
from email_service import (
    send_verification_email,
    send_password_reset_email,
    send_email_dev_mode,
    MAILGUN_API_KEY
)

warnings.filterwarnings('ignore', message='.*Query.get.*')

app = Flask(__name__)

# ================================================================================
# CORS (Cross-Origin Resource Sharing)
# ================================================================================
# CORS allows the frontend (running on a different origin/port) to make API requests.
# Without CORS, browsers block cross-origin requests for security reasons.
#
# Example: Frontend at file:///path/index.html calling http://localhost:5011
# This is a cross-origin request because the protocols/ports differ.
# ================================================================================
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_ch11.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Load SECRET_KEY from environment (with fallback for development)
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
BASE_URL = os.environ.get('BASE_URL', 'http://localhost:5011')

db = SQLAlchemy(app)


# ================================================================================
# MODELS
# ================================================================================

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Email verification fields
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), nullable=True)
    verification_expires = db.Column(db.DateTime, nullable=True)
    verification_sent_at = db.Column(db.DateTime, nullable=True)  # For rate limiting

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'is_verified': self.is_verified,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }


class PasswordResetToken(db.Model):
    __tablename__ = 'password_reset_tokens'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ================================================================================
# HELPER FUNCTIONS
# ================================================================================

def hash_password(password):
    return generate_password_hash(password)


def verify_password(plain, hashed):
    return check_password_hash(hashed, plain)


def create_token(user):
    return jwt.encode({
        'user_id': user.id,
        'email': user.email,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, SECRET_KEY, algorithm='HS256')


def generate_verification_token():
    """Generate a secure random token for email verification."""
    return secrets.token_urlsafe(32)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'success': False, 'message': 'Token missing'}), 401
        try:
            parts = auth_header.split(' ')
            if len(parts) != 2 or parts[0] != 'Bearer':
                return jsonify({'success': False, 'message': 'Invalid token format'}), 401
            decoded = jwt.decode(parts[1], SECRET_KEY, algorithms=['HS256'])
            g.current_user = {'user_id': decoded['user_id'], 'email': decoded['email']}
        except jwt.ExpiredSignatureError:
            return jsonify({'success': False, 'message': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'success': False, 'message': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated


# ================================================================================
# ROUTES
# ================================================================================

@app.route('/')
def index():
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    return send_file(html_path)


@app.route('/config-status')
def config_status():
    """Check if Mailgun is properly configured."""
    mailgun_configured = bool(MAILGUN_API_KEY and os.environ.get('MAILGUN_DOMAIN'))
    return jsonify({
        'mailgun_configured': mailgun_configured,
        'base_url': BASE_URL,
        'message': 'Mailgun is configured!' if mailgun_configured else 'Mailgun not configured. Emails will be simulated.'
    })


# ================================================================================
# REGISTRATION WITH REAL EMAIL VERIFICATION
# ================================================================================

@app.route('/register', methods=['POST'])
def register():
    """
    Register a new user and send verification email.

    Expected JSON:
        {"email": "user@example.com", "password": "securepass123"}

    Flow:
        1. Validate input
        2. Check if email already exists
        3. Create user (unverified)
        4. Generate verification token
        5. Send verification email via Mailgun
        6. Return success with email status
    """
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    # Validation
    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password required'}), 400

    if len(password) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters'}), 400

    # Check if user exists
    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': 'Email already registered'}), 400

    # Create user
    verification_token = generate_verification_token()
    user = User(
        email=email,
        password=hash_password(password),
        is_verified=False,
        verification_token=verification_token,
        verification_expires=datetime.utcnow() + timedelta(hours=24),
        verification_sent_at=datetime.utcnow()
    )

    db.session.add(user)
    db.session.commit()

    # Build verification link
    verification_link = f"{BASE_URL}/verify-email?token={verification_token}"

    # Send verification email
    email_result = send_verification_email(
        to_email=email,
        username=email.split('@')[0],  # Use part before @ as username
        verification_link=verification_link
    )

    # Handle email result
    if email_result.get('simulated'):
        # Mailgun not configured - development mode
        return jsonify({
            'success': True,
            'message': 'Registration successful! (Email simulated - Mailgun not configured)',
            'user': user.to_dict(),
            'email_status': 'simulated',
            'verification_link': verification_link,  # Show link in dev mode
            'note': 'Configure Mailgun to send real emails'
        }), 201

    elif email_result['success']:
        return jsonify({
            'success': True,
            'message': 'Registration successful! Please check your email to verify your account.',
            'user': user.to_dict(),
            'email_status': 'sent'
        }), 201

    else:
        # Email failed but user was created
        return jsonify({
            'success': True,
            'message': 'Registration successful, but verification email failed to send. Use resend option.',
            'user': user.to_dict(),
            'email_status': 'failed',
            'email_error': email_result.get('error')
        }), 201


# ================================================================================
# EMAIL VERIFICATION
# ================================================================================

@app.route('/verify-email', methods=['GET'])
def verify_email():
    """
    Verify user's email with token from link.

    Query params:
        token: The verification token from email link

    Returns HTML page showing verification status.
    """
    token = request.args.get('token')

    if not token:
        return '''
        <html><body style="font-family: Arial; text-align: center; padding: 50px;">
            <h1 style="color: #dc3545;">Invalid Link</h1>
            <p>No verification token provided.</p>
        </body></html>
        ''', 400

    user = User.query.filter_by(verification_token=token).first()

    if not user:
        return '''
        <html><body style="font-family: Arial; text-align: center; padding: 50px;">
            <h1 style="color: #dc3545;">Invalid Token</h1>
            <p>This verification link is invalid or has already been used.</p>
        </body></html>
        ''', 400

    if user.is_verified:
        return '''
        <html><body style="font-family: Arial; text-align: center; padding: 50px;">
            <h1 style="color: #17a2b8;">Already Verified</h1>
            <p>Your email has already been verified. You can close this page.</p>
        </body></html>
        '''

    if user.verification_expires < datetime.utcnow():
        return '''
        <html><body style="font-family: Arial; text-align: center; padding: 50px;">
            <h1 style="color: #ffc107;">Link Expired</h1>
            <p>This verification link has expired. Please request a new one.</p>
        </body></html>
        ''', 400

    # Verify the user
    user.is_verified = True
    user.verification_token = None
    user.verification_expires = None
    db.session.commit()

    return '''
    <html><body style="font-family: Arial; text-align: center; padding: 50px;">
        <h1 style="color: #28a745;">Email Verified!</h1>
        <p>Your email has been successfully verified. You can now log in.</p>
        <a href="/" style="color: #007bff;">Go to Login</a>
    </body></html>
    '''


@app.route('/verify-email-api', methods=['POST'])
def verify_email_api():
    """API endpoint for email verification (returns JSON)."""
    data = request.get_json()
    token = data.get('token')

    if not token:
        return jsonify({'success': False, 'message': 'Token required'}), 400

    user = User.query.filter_by(verification_token=token).first()

    if not user:
        return jsonify({'success': False, 'message': 'Invalid token'}), 400

    if user.is_verified:
        return jsonify({'success': True, 'message': 'Already verified', 'user': user.to_dict()})

    if user.verification_expires < datetime.utcnow():
        return jsonify({'success': False, 'message': 'Token expired'}), 400

    user.is_verified = True
    user.verification_token = None
    user.verification_expires = None
    db.session.commit()

    return jsonify({'success': True, 'message': 'Email verified!', 'user': user.to_dict()})


# ================================================================================
# RESEND VERIFICATION EMAIL
# ================================================================================

@app.route('/resend-verification', methods=['POST'])
def resend_verification():
    """
    Resend verification email with rate limiting.

    Expected JSON:
        {"email": "user@example.com"}

    Rate limit: 1 email per 60 seconds per user
    """
    data = request.get_json()
    email = data.get('email', '').strip().lower()

    if not email:
        return jsonify({'success': False, 'message': 'Email required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        # Don't reveal if email exists or not (security)
        return jsonify({'success': True, 'message': 'If this email is registered, a verification link will be sent.'})

    if user.is_verified:
        return jsonify({'success': False, 'message': 'Email already verified'}), 400

    # Rate limiting: Check if email was sent recently
    if user.verification_sent_at:
        time_since_last = datetime.utcnow() - user.verification_sent_at
        if time_since_last < timedelta(seconds=60):
            remaining = 60 - time_since_last.seconds
            return jsonify({
                'success': False,
                'message': f'Please wait {remaining} seconds before requesting another email'
            }), 429

    # Generate new token
    verification_token = generate_verification_token()
    user.verification_token = verification_token
    user.verification_expires = datetime.utcnow() + timedelta(hours=24)
    user.verification_sent_at = datetime.utcnow()
    db.session.commit()

    # Build verification link
    verification_link = f"{BASE_URL}/verify-email?token={verification_token}"

    # Send email
    email_result = send_verification_email(
        to_email=email,
        username=email.split('@')[0],
        verification_link=verification_link
    )

    if email_result.get('simulated'):
        return jsonify({
            'success': True,
            'message': 'Verification email sent (simulated)',
            'verification_link': verification_link,
            'email_status': 'simulated'
        })

    elif email_result['success']:
        return jsonify({
            'success': True,
            'message': 'Verification email sent! Check your inbox.',
            'email_status': 'sent'
        })

    else:
        return jsonify({
            'success': False,
            'message': 'Failed to send email. Please try again.',
            'error': email_result.get('error')
        }), 500


# ================================================================================
# LOGIN
# ================================================================================

@app.route('/login', methods=['POST'])
def login():
    """Login and optionally check verification status."""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Credentials required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not verify_password(password, user.password):
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

    # Optional: Require email verification for login
    # Uncomment to enforce:
    # if not user.is_verified:
    #     return jsonify({
    #         'success': False,
    #         'message': 'Please verify your email first',
    #         'error': 'EMAIL_NOT_VERIFIED'
    #     }), 403

    return jsonify({
        'success': True,
        'message': 'Login successful',
        'token': create_token(user),
        'user': user.to_dict(),
        'warning': None if user.is_verified else 'Email not yet verified'
    })


# ================================================================================
# FORGOT PASSWORD WITH REAL EMAIL
# ================================================================================

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    """
    Request password reset - sends email with reset link.

    Expected JSON:
        {"email": "user@example.com"}
    """
    data = request.get_json()
    email = data.get('email', '').strip().lower()

    if not email:
        return jsonify({'success': False, 'message': 'Email required'}), 400

    user = User.query.filter_by(email=email).first()

    # Always return success (don't reveal if email exists)
    if not user:
        return jsonify({
            'success': True,
            'message': 'If this email is registered, a password reset link will be sent.'
        })

    # Invalidate any existing reset tokens for this user
    PasswordResetToken.query.filter_by(user_id=user.id, used=False).update({'used': True})

    # Create new reset token
    reset_token = secrets.token_urlsafe(32)
    token_record = PasswordResetToken(
        user_id=user.id,
        token=reset_token,
        expires_at=datetime.utcnow() + timedelta(hours=1)
    )
    db.session.add(token_record)
    db.session.commit()

    # Build reset link
    reset_link = f"{BASE_URL}/reset-password?token={reset_token}"

    # Send email
    email_result = send_password_reset_email(
        to_email=email,
        username=email.split('@')[0],
        reset_link=reset_link
    )

    if email_result.get('simulated'):
        return jsonify({
            'success': True,
            'message': 'Password reset email sent (simulated)',
            'reset_link': reset_link,
            'email_status': 'simulated'
        })

    elif email_result['success']:
        return jsonify({
            'success': True,
            'message': 'Password reset email sent! Check your inbox.',
            'email_status': 'sent'
        })

    else:
        return jsonify({
            'success': True,
            'message': 'If this email is registered, a password reset link will be sent.'
        })


# ================================================================================
# RESET PASSWORD (with token from email)
# ================================================================================

@app.route('/reset-password', methods=['GET'])
def reset_password_page():
    """Show password reset form (HTML page)."""
    token = request.args.get('token', '')

    return f'''
    <html>
    <head>
        <title>Reset Password</title>
        <style>
            body {{ font-family: Arial; max-width: 400px; margin: 50px auto; padding: 20px; }}
            input {{ width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; }}
            button {{ width: 100%; padding: 12px; background: #2196F3; color: white; border: none; cursor: pointer; }}
            button:hover {{ background: #1976D2; }}
            .error {{ color: #dc3545; }}
            .success {{ color: #28a745; }}
        </style>
    </head>
    <body>
        <h2>Reset Your Password</h2>
        <form id="resetForm">
            <input type="hidden" id="token" value="{token}">
            <input type="password" id="password" placeholder="New Password (min 8 characters)" required minlength="8">
            <input type="password" id="confirmPassword" placeholder="Confirm Password" required>
            <button type="submit">Reset Password</button>
        </form>
        <p id="message"></p>

        <script>
            document.getElementById('resetForm').addEventListener('submit', async (e) => {{
                e.preventDefault();
                const password = document.getElementById('password').value;
                const confirmPassword = document.getElementById('confirmPassword').value;
                const token = document.getElementById('token').value;
                const messageEl = document.getElementById('message');

                if (password !== confirmPassword) {{
                    messageEl.className = 'error';
                    messageEl.textContent = 'Passwords do not match!';
                    return;
                }}

                const res = await fetch('/reset-password-confirm', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{ token, new_password: password }})
                }});

                const data = await res.json();
                messageEl.className = data.success ? 'success' : 'error';
                messageEl.textContent = data.message;

                if (data.success) {{
                    setTimeout(() => window.location.href = '/', 2000);
                }}
            }});
        </script>
    </body>
    </html>
    '''


@app.route('/reset-password-confirm', methods=['POST'])
def reset_password_confirm():
    """Process password reset with token."""
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')

    if not token or not new_password:
        return jsonify({'success': False, 'message': 'Token and new password required'}), 400

    if len(new_password) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters'}), 400

    # Find valid token
    token_record = PasswordResetToken.query.filter_by(token=token, used=False).first()

    if not token_record:
        return jsonify({'success': False, 'message': 'Invalid or expired reset link'}), 400

    if token_record.expires_at < datetime.utcnow():
        return jsonify({'success': False, 'message': 'Reset link has expired'}), 400

    # Update password
    user = User.query.get(token_record.user_id)
    user.password = hash_password(new_password)

    # Mark token as used
    token_record.used = True

    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Password reset successful! You can now log in with your new password.'
    })


# ================================================================================
# PROTECTED ROUTE EXAMPLE
# ================================================================================

@app.route('/profile', methods=['GET'])
@token_required
def get_profile():
    user = User.query.get(g.current_user['user_id'])
    return jsonify({'success': True, 'profile': user.to_dict()})


# ================================================================================
# KEY TAKEAWAYS
# ================================================================================
#
# 1. ENVIRONMENT VARIABLES: Use python-dotenv to load secrets from .env file.
#    Never hardcode API keys, database passwords, or secret keys in code!
#
# 2. MAILGUN SETUP: Free tier provides 5,000 emails/month. Sandbox mode requires
#    adding authorized recipients first. Production domain removes this limit.
#
# 3. EMAIL TEMPLATES: HTML emails should be table-based for compatibility.
#    Include plain text fallback for email clients that don't support HTML.
#
# 4. GRACEFUL FAILURES: If email fails, don't fail the registration. Let user
#    resend verification later. Log errors for debugging.
#
# 5. RATE LIMITING: Prevent abuse by limiting email resends (1 per minute here).
#
# 6. SECURITY: Don't reveal if an email exists in forgot-password responses.
#    Use cryptographically secure tokens (secrets.token_urlsafe).
#
# ================================================================================
#
# TRY THIS:
#   1. Set up Mailgun and send a real verification email
#   2. Check your inbox (or spam folder) for the email
#   3. Click the verification link and see it work
#   4. Try the forgot password flow with real emails
#
# EXERCISES:
#   1. Add a "Welcome" email sent after successful verification
#   2. Implement email change with verification (verify new email)
#   3. Add an admin endpoint to see email delivery statistics
#   4. Create a "Login Alert" email when login from new IP
#
# ================================================================================

with app.app_context():
    db.create_all()


if __name__ == '__main__':
    print("=" * 60)
    print("CHAPTER 11: Email Integration with Mailgun")
    print("=" * 60)
    print(f"Server: http://localhost:5011")
    print("")
    print("Mailgun Status:", "CONFIGURED" if MAILGUN_API_KEY else "NOT CONFIGURED (emails will be simulated)")
    print("")
    print("Endpoints:")
    print("  POST /register         - Register with email verification")
    print("  GET  /verify-email     - Verify email (from link)")
    print("  POST /resend-verification - Resend verification email")
    print("  POST /login            - Login")
    print("  POST /forgot-password  - Request password reset")
    print("  GET  /reset-password   - Reset password form")
    print("  GET  /config-status    - Check Mailgun configuration")
    print("=" * 60)
    app.run(debug=True, port=5011)
