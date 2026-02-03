# ================================================================================
# Authentication Routes
# ================================================================================
# All authentication-related endpoints.
# ================================================================================

import secrets
import uuid
import jwt
from datetime import datetime, timedelta
from flask import request, jsonify, redirect, g, current_app
from werkzeug.security import generate_password_hash, check_password_hash

from . import auth_bp
from .decorators import token_required, refresh_token_required, admin_required
from .email_service import send_verification_email, send_password_reset_email, send_welcome_email
from .oauth import (
    get_google_auth_url, verify_oauth_state,
    exchange_code_for_tokens, get_google_user_info, is_google_configured
)
from models import db, User, PasswordResetToken, RefreshToken, AuditLog


# ================================================================================
# HELPER FUNCTIONS
# ================================================================================

def create_access_token(user):
    """Create short-lived access token."""
    secret_key = current_app.config.get('JWT_SECRET_KEY') or current_app.config.get('SECRET_KEY')
    expires = current_app.config.get('JWT_ACCESS_TOKEN_EXPIRES', timedelta(minutes=15))

    payload = {
        'user_id': user.id,
        'email': user.email,
        'role': user.role,
        'type': 'access',
        'exp': datetime.utcnow() + expires
    }
    return jwt.encode(payload, secret_key, algorithm='HS256')


def create_refresh_token(user):
    """Create long-lived refresh token and store in database."""
    secret_key = current_app.config.get('JWT_SECRET_KEY') or current_app.config.get('SECRET_KEY')
    expires = current_app.config.get('JWT_REFRESH_TOKEN_EXPIRES', timedelta(days=7))
    jti = str(uuid.uuid4())

    payload = {
        'user_id': user.id,
        'type': 'refresh',
        'jti': jti,
        'exp': datetime.utcnow() + expires
    }

    # Store refresh token in database
    token_record = RefreshToken(
        user_id=user.id,
        token_jti=jti,
        expires_at=datetime.utcnow() + expires,
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string[:255] if request.user_agent else None
    )
    db.session.add(token_record)
    db.session.commit()

    return jwt.encode(payload, secret_key, algorithm='HS256')


def get_client_ip():
    """Get client IP address."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr


def log_action(action, user_id=None, details=None, success=True):
    """Log an audit event."""
    AuditLog.log(
        action=action,
        user_id=user_id,
        ip_address=get_client_ip(),
        user_agent=request.user_agent.string[:255] if request.user_agent else None,
        details=details,
        success=success
    )


# ================================================================================
# REGISTRATION
# ================================================================================

@auth_bp.route('/register', methods=['POST'])
def register():
    """Register a new user with email/password."""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    name = data.get('name', '').strip()

    # Validation
    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password required'}), 400

    min_password_length = current_app.config.get('PASSWORD_MIN_LENGTH', 8)
    if len(password) < min_password_length:
        return jsonify({'success': False, 'message': f'Password must be at least {min_password_length} characters'}), 400

    # Check existing user
    existing = User.query.filter_by(email=email).first()
    if existing:
        if existing.auth_provider == 'google' and not existing.password:
            # Allow setting password for OAuth-only account
            existing.password = generate_password_hash(password)
            existing.auth_provider = 'both'
            if name:
                existing.name = name
            db.session.commit()
            log_action('PASSWORD_SET', existing.id, 'Password added to Google account')
            return jsonify({
                'success': True,
                'message': 'Password set for your Google account',
                'user': existing.to_dict()
            })
        return jsonify({'success': False, 'message': 'Email already registered'}), 400

    # Create user
    verification_token = secrets.token_urlsafe(32)
    user = User(
        email=email,
        password=generate_password_hash(password),
        name=name or email.split('@')[0],
        auth_provider='local',
        is_verified=False,
        verification_token=verification_token,
        verification_expires=datetime.utcnow() + timedelta(hours=24),
        verification_sent_at=datetime.utcnow()
    )
    db.session.add(user)
    db.session.commit()

    # Send verification email
    base_url = current_app.config.get('BASE_URL', 'http://localhost:5013')
    verification_link = f"{base_url}/verify-email.html?token={verification_token}"

    email_result = send_verification_email(user.email, user.name, verification_link)

    log_action('REGISTER', user.id, f'New user registered: {email}')

    response = {
        'success': True,
        'message': 'Registration successful! Please check your email to verify your account.',
        'user': user.to_dict()
    }

    if email_result.get('simulated'):
        response['verification_link'] = verification_link
        response['note'] = 'Email simulated - configure Mailgun for real emails'

    return jsonify(response), 201


# ================================================================================
# LOGIN
# ================================================================================

@auth_bp.route('/login', methods=['POST'])
def login():
    """Login with email/password."""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Credentials required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        log_action('LOGIN_FAILED', None, f'Unknown email: {email}', success=False)
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

    # Check if account is locked
    if user.is_locked():
        remaining = user.get_lockout_remaining()
        log_action('LOGIN_BLOCKED', user.id, 'Account locked', success=False)
        return jsonify({
            'success': False,
            'message': f'Account locked. Try again in {remaining} seconds.',
            'error': 'ACCOUNT_LOCKED',
            'retry_after': remaining
        }), 403

    # Check if user has password (might be OAuth-only)
    if not user.password:
        return jsonify({
            'success': False,
            'message': 'This account uses Google Sign-In. Please use Google or set a password.',
            'error': 'OAUTH_ONLY_ACCOUNT'
        }), 401

    # Verify password
    if not check_password_hash(user.password, password):
        user.failed_login_attempts += 1

        max_attempts = current_app.config.get('MAX_LOGIN_ATTEMPTS', 5)
        if user.failed_login_attempts >= max_attempts:
            lockout_minutes = current_app.config.get('LOCKOUT_DURATION_MINUTES', 15)
            user.locked_until = datetime.utcnow() + timedelta(minutes=lockout_minutes)
            user.failed_login_attempts = 0
            db.session.commit()
            log_action('ACCOUNT_LOCKED', user.id, f'Locked for {lockout_minutes} minutes', success=False)
            return jsonify({
                'success': False,
                'message': f'Account locked for {lockout_minutes} minutes due to too many failed attempts.',
                'error': 'ACCOUNT_LOCKED'
            }), 403

        db.session.commit()
        log_action('LOGIN_FAILED', user.id, 'Invalid password', success=False)
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

    # Check if account is active
    if not user.is_active:
        return jsonify({
            'success': False,
            'message': 'Account is disabled',
            'error': 'ACCOUNT_DISABLED'
        }), 403

    # Success - reset failed attempts
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login = datetime.utcnow()
    user.last_login_ip = get_client_ip()
    db.session.commit()

    log_action('LOGIN_SUCCESS', user.id, f'Login from {get_client_ip()}')

    return jsonify({
        'success': True,
        'message': 'Login successful',
        'access_token': create_access_token(user),
        'refresh_token': create_refresh_token(user),
        'user': user.to_dict()
    })


# ================================================================================
# TOKEN REFRESH
# ================================================================================

@auth_bp.route('/refresh', methods=['POST'])
@refresh_token_required
def refresh_token():
    """Get new access token using refresh token."""
    jti = g.refresh_token_data.get('jti')
    user_id = g.refresh_token_data.get('user_id')

    # Check if refresh token is revoked
    token_record = RefreshToken.query.filter_by(token_jti=jti).first()
    if not token_record or token_record.revoked:
        return jsonify({'success': False, 'message': 'Token revoked'}), 401

    user = User.query.get(user_id)
    if not user or not user.is_active:
        return jsonify({'success': False, 'message': 'User not found or disabled'}), 401

    return jsonify({
        'success': True,
        'access_token': create_access_token(user)
    })


# ================================================================================
# LOGOUT
# ================================================================================

@auth_bp.route('/logout', methods=['POST'])
@refresh_token_required
def logout():
    """Logout - revoke refresh token."""
    jti = g.refresh_token_data.get('jti')

    token_record = RefreshToken.query.filter_by(token_jti=jti).first()
    if token_record:
        token_record.revoked = True
        token_record.revoked_at = datetime.utcnow()
        db.session.commit()

    log_action('LOGOUT', g.refresh_token_data.get('user_id'))

    return jsonify({'success': True, 'message': 'Logged out successfully'})


@auth_bp.route('/logout-all', methods=['POST'])
@token_required
def logout_all():
    """Logout from all devices - revoke all refresh tokens."""
    user_id = g.current_user['user_id']

    RefreshToken.query.filter_by(user_id=user_id, revoked=False).update({
        'revoked': True,
        'revoked_at': datetime.utcnow()
    })
    db.session.commit()

    log_action('LOGOUT_ALL', user_id, 'All sessions revoked')

    return jsonify({'success': True, 'message': 'Logged out from all devices'})


# ================================================================================
# EMAIL VERIFICATION
# ================================================================================

@auth_bp.route('/verify-email', methods=['POST'])
def verify_email():
    """Verify email with token."""
    data = request.get_json()
    token = data.get('token')

    if not token:
        return jsonify({'success': False, 'message': 'Token required'}), 400

    user = User.query.filter_by(verification_token=token).first()

    if not user:
        return jsonify({'success': False, 'message': 'Invalid token'}), 400

    if user.is_verified:
        return jsonify({'success': True, 'message': 'Already verified'})

    if user.verification_expires < datetime.utcnow():
        return jsonify({'success': False, 'message': 'Token expired'}), 400

    user.is_verified = True
    user.verification_token = None
    user.verification_expires = None
    db.session.commit()

    log_action('EMAIL_VERIFIED', user.id)
    send_welcome_email(user.email, user.name)

    return jsonify({'success': True, 'message': 'Email verified!', 'user': user.to_dict()})


@auth_bp.route('/resend-verification', methods=['POST'])
def resend_verification():
    """Resend verification email."""
    data = request.get_json()
    email = data.get('email', '').strip().lower()

    if not email:
        return jsonify({'success': False, 'message': 'Email required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'success': True, 'message': 'If registered, verification email will be sent.'})

    if user.is_verified:
        return jsonify({'success': False, 'message': 'Already verified'}), 400

    # Rate limiting
    if user.verification_sent_at:
        time_since = datetime.utcnow() - user.verification_sent_at
        if time_since < timedelta(seconds=60):
            return jsonify({
                'success': False,
                'message': f'Please wait {60 - time_since.seconds} seconds'
            }), 429

    # Generate new token
    user.verification_token = secrets.token_urlsafe(32)
    user.verification_expires = datetime.utcnow() + timedelta(hours=24)
    user.verification_sent_at = datetime.utcnow()
    db.session.commit()

    base_url = current_app.config.get('BASE_URL', 'http://localhost:5013')
    verification_link = f"{base_url}/verify-email.html?token={user.verification_token}"

    email_result = send_verification_email(user.email, user.name, verification_link)

    response = {'success': True, 'message': 'Verification email sent'}
    if email_result.get('simulated'):
        response['verification_link'] = verification_link

    return jsonify(response)


# ================================================================================
# PASSWORD RESET
# ================================================================================

@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    """Request password reset."""
    data = request.get_json()
    email = data.get('email', '').strip().lower()

    if not email:
        return jsonify({'success': False, 'message': 'Email required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'success': True, 'message': 'If registered, reset email will be sent.'})

    # Invalidate existing tokens
    PasswordResetToken.query.filter_by(user_id=user.id, used=False).update({'used': True})

    # Create new token
    reset_token = secrets.token_urlsafe(32)
    token_record = PasswordResetToken(
        user_id=user.id,
        token=reset_token,
        expires_at=datetime.utcnow() + timedelta(hours=1),
        ip_address=get_client_ip()
    )
    db.session.add(token_record)
    db.session.commit()

    base_url = current_app.config.get('BASE_URL', 'http://localhost:5013')
    reset_link = f"{base_url}/reset-password.html?token={reset_token}"

    email_result = send_password_reset_email(user.email, user.name, reset_link)

    log_action('PASSWORD_RESET_REQUESTED', user.id)

    response = {'success': True, 'message': 'If registered, reset email will be sent.'}
    if email_result.get('simulated'):
        response['reset_link'] = reset_link

    return jsonify(response)


@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    """Reset password with token."""
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')

    if not token or not new_password:
        return jsonify({'success': False, 'message': 'Token and new password required'}), 400

    min_length = current_app.config.get('PASSWORD_MIN_LENGTH', 8)
    if len(new_password) < min_length:
        return jsonify({'success': False, 'message': f'Password must be at least {min_length} characters'}), 400

    token_record = PasswordResetToken.query.filter_by(token=token, used=False).first()

    if not token_record:
        return jsonify({'success': False, 'message': 'Invalid or expired token'}), 400

    if token_record.expires_at < datetime.utcnow():
        return jsonify({'success': False, 'message': 'Token expired'}), 400

    user = User.query.get(token_record.user_id)
    user.password = generate_password_hash(new_password)
    user.password_changed_at = datetime.utcnow()

    token_record.used = True
    token_record.used_at = datetime.utcnow()

    # Revoke all refresh tokens (security measure)
    RefreshToken.query.filter_by(user_id=user.id, revoked=False).update({
        'revoked': True,
        'revoked_at': datetime.utcnow()
    })

    db.session.commit()

    log_action('PASSWORD_RESET', user.id)

    return jsonify({'success': True, 'message': 'Password reset successful'})


# ================================================================================
# GOOGLE OAUTH
# ================================================================================

@auth_bp.route('/auth/google')
def google_login():
    """Start Google OAuth flow."""
    auth_url = get_google_auth_url()
    if not auth_url:
        return jsonify({'success': False, 'message': 'Google OAuth not configured'}), 500

    if request.args.get('redirect') == 'false':
        return jsonify({'success': True, 'auth_url': auth_url})

    return redirect(auth_url)


@auth_bp.route('/auth/google/callback')
def google_callback():
    """Handle Google OAuth callback."""
    error = request.args.get('error')
    if error:
        return redirect(f"/?error={error}")

    code = request.args.get('code')
    state = request.args.get('state')

    if not code:
        return redirect('/?error=no_code')

    if not verify_oauth_state(state):
        return redirect('/?error=invalid_state')

    # Exchange code for tokens
    token_data = exchange_code_for_tokens(code)
    if not token_data:
        return redirect('/?error=token_exchange_failed')

    # Get user info
    user_info = get_google_user_info(token_data['access_token'])
    if not user_info:
        return redirect('/?error=user_info_failed')

    # Find or create user
    user = handle_google_user(user_info)

    # Create tokens
    access_token = create_access_token(user)
    refresh_token = create_refresh_token(user)

    log_action('OAUTH_LOGIN', user.id, 'Google OAuth login')

    # Redirect with tokens (in production, use a more secure method)
    return f'''
    <html>
    <head><title>Login Successful</title></head>
    <body>
        <script>
            localStorage.setItem('access_token', '{access_token}');
            localStorage.setItem('refresh_token', '{refresh_token}');
            localStorage.setItem('user', JSON.stringify({user.to_dict()}));
            window.location.href = '/dashboard.html';
        </script>
    </body>
    </html>
    '''


def handle_google_user(google_user):
    """Create or update user from Google profile."""
    google_id = google_user.get('id')
    email = google_user.get('email', '').lower()
    name = google_user.get('name')
    picture = google_user.get('picture')

    # Find by Google ID
    user = User.query.filter_by(google_id=google_id).first()
    if user:
        user.name = name or user.name
        user.profile_picture = picture or user.profile_picture
        db.session.commit()
        return user

    # Find by email
    user = User.query.filter_by(email=email).first()
    if user:
        user.google_id = google_id
        user.name = name or user.name
        user.profile_picture = picture or user.profile_picture
        user.is_verified = True
        user.auth_provider = 'both' if user.password else 'google'
        db.session.commit()
        return user

    # Create new user
    user = User(
        email=email,
        google_id=google_id,
        name=name,
        profile_picture=picture,
        auth_provider='google',
        is_verified=True
    )
    db.session.add(user)
    db.session.commit()

    return user


# ================================================================================
# PROFILE
# ================================================================================

@auth_bp.route('/profile', methods=['GET'])
@token_required
def get_profile():
    """Get current user's profile."""
    user = User.query.get(g.current_user['user_id'])
    return jsonify({'success': True, 'user': user.to_dict()})


@auth_bp.route('/profile', methods=['PUT'])
@token_required
def update_profile():
    """Update current user's profile."""
    data = request.get_json()
    user = User.query.get(g.current_user['user_id'])

    if 'name' in data:
        user.name = data['name'].strip()

    db.session.commit()

    return jsonify({'success': True, 'user': user.to_dict()})


@auth_bp.route('/change-password', methods=['POST'])
@token_required
def change_password():
    """Change password (requires current password)."""
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')

    if not current_password or not new_password:
        return jsonify({'success': False, 'message': 'Current and new password required'}), 400

    user = User.query.get(g.current_user['user_id'])

    if not user.password:
        return jsonify({'success': False, 'message': 'No password set. Use forgot password.'}), 400

    if not check_password_hash(user.password, current_password):
        return jsonify({'success': False, 'message': 'Current password incorrect'}), 401

    min_length = current_app.config.get('PASSWORD_MIN_LENGTH', 8)
    if len(new_password) < min_length:
        return jsonify({'success': False, 'message': f'Password must be at least {min_length} characters'}), 400

    user.password = generate_password_hash(new_password)
    user.password_changed_at = datetime.utcnow()
    db.session.commit()

    log_action('PASSWORD_CHANGED', user.id)

    return jsonify({'success': True, 'message': 'Password changed successfully'})


# ================================================================================
# CONFIG STATUS
# ================================================================================

@auth_bp.route('/config-status')
def config_status():
    """Check service configuration status."""
    return jsonify({
        'google_oauth': is_google_configured(),
        'mailgun': bool(current_app.config.get('MAILGUN_API_KEY')),
        'base_url': current_app.config.get('BASE_URL')
    })
