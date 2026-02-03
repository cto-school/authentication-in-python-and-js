# ================================================================================
# Authentication Decorators
# ================================================================================
# Reusable decorators for protecting routes and checking permissions.
# ================================================================================

from functools import wraps
from flask import request, jsonify, g, current_app
import jwt

from models import User


def get_token_from_header():
    """Extract JWT token from Authorization header."""
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return None

    parts = auth_header.split(' ')
    if len(parts) != 2 or parts[0] != 'Bearer':
        return None

    return parts[1]


def decode_token(token):
    """Decode and validate JWT token."""
    try:
        secret_key = current_app.config.get('JWT_SECRET_KEY') or current_app.config.get('SECRET_KEY')
        decoded = jwt.decode(token, secret_key, algorithms=['HS256'])
        return decoded, None
    except jwt.ExpiredSignatureError:
        return None, 'Token expired'
    except jwt.InvalidTokenError:
        return None, 'Invalid token'


def token_required(f):
    """
    Decorator that requires a valid JWT token.

    Usage:
        @app.route('/protected')
        @token_required
        def protected_route():
            user_id = g.current_user['user_id']
            ...
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_from_header()
        if not token:
            return jsonify({'success': False, 'message': 'Token required'}), 401

        decoded, error = decode_token(token)
        if error:
            return jsonify({'success': False, 'message': error}), 401

        # Check token type (should be 'access')
        if decoded.get('type') != 'access':
            return jsonify({'success': False, 'message': 'Invalid token type'}), 401

        g.current_user = {
            'user_id': decoded['user_id'],
            'email': decoded['email'],
            'role': decoded.get('role', 'user')
        }

        return f(*args, **kwargs)
    return decorated


def verified_required(f):
    """
    Decorator that requires email verification.
    Must be used after @token_required.

    Usage:
        @app.route('/verified-only')
        @token_required
        @verified_required
        def verified_route():
            ...
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        user = User.query.get(g.current_user['user_id'])
        if not user or not user.is_verified:
            return jsonify({
                'success': False,
                'message': 'Email verification required',
                'error': 'EMAIL_NOT_VERIFIED'
            }), 403
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """
    Decorator that requires admin role.
    Must be used after @token_required.

    Usage:
        @app.route('/admin-only')
        @token_required
        @admin_required
        def admin_route():
            ...
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if g.current_user.get('role') != 'admin':
            return jsonify({
                'success': False,
                'message': 'Admin access required',
                'error': 'FORBIDDEN'
            }), 403
        return f(*args, **kwargs)
    return decorated


def active_required(f):
    """
    Decorator that requires an active (non-disabled) account.
    Must be used after @token_required.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        user = User.query.get(g.current_user['user_id'])
        if not user or not user.is_active:
            return jsonify({
                'success': False,
                'message': 'Account is disabled',
                'error': 'ACCOUNT_DISABLED'
            }), 403
        return f(*args, **kwargs)
    return decorated


def refresh_token_required(f):
    """
    Decorator for refresh token endpoints.
    Validates that the token is a refresh token.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_from_header()
        if not token:
            return jsonify({'success': False, 'message': 'Token required'}), 401

        decoded, error = decode_token(token)
        if error:
            return jsonify({'success': False, 'message': error}), 401

        if decoded.get('type') != 'refresh':
            return jsonify({'success': False, 'message': 'Refresh token required'}), 401

        g.refresh_token_data = decoded
        return f(*args, **kwargs)
    return decorated
