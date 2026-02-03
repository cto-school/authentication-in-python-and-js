# ================================================================================
# CHAPTER 13: Production-Ready Authentication Boilerplate
# ================================================================================
#
# This is a COMPLETE, PRODUCTION-READY authentication system that you can use
# as a starting point for real projects.
#
# FEATURES INCLUDED:
#   - Email/Password Registration & Login
#   - Google OAuth (Sign in with Google)
#   - Email Verification (Mailgun)
#   - Password Reset via Email
#   - JWT Access & Refresh Tokens
#   - Account Lockout (brute force protection)
#   - Rate Limiting (flask-limiter)
#   - Role-Based Access Control
#   - Audit Logging
#   - Modular Code Structure
#
# PROJECT STRUCTURE:
#   backend/
#   ├── app.py              # This file - Flask app setup
#   ├── config.py           # Configuration management
#   ├── models.py           # Database models
#   └── auth/
#       ├── __init__.py     # Blueprint setup
#       ├── routes.py       # All auth endpoints
#       ├── decorators.py   # @token_required, etc.
#       ├── email_service.py # Email sending
#       └── oauth.py        # Google OAuth
#
# GETTING STARTED:
#   1. Copy .env.example to .env and fill in your values
#   2. pip install -r requirements.txt
#   3. python app.py
#   4. Open http://localhost:5013
#
# ================================================================================

import os
import warnings
from flask import Flask, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import get_config
from models import db

warnings.filterwarnings('ignore', message='.*Query.get.*')


def create_app(config_class=None):
    """Application factory pattern."""

    app = Flask(__name__)

    # Load configuration
    if config_class is None:
        config_class = get_config()
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)

    # ================================================================================
    # CORS (Cross-Origin Resource Sharing)
    # ================================================================================
    # CORS allows the frontend to make API requests from a different origin.
    #
    # supports_credentials=True is required because:
    #   1. We use sessions for OAuth state management
    #   2. Sessions use cookies which require credentials support
    #
    # In production, you should specify exact allowed origins instead of allowing all:
    #   CORS(app, origins=['https://yourdomain.com'], supports_credentials=True)
    # ================================================================================
    CORS(app, supports_credentials=True)

    # Flask-Limiter for rate limiting
    # Uses memory by default, configure REDIS_URL for production
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=["100 per hour"],
        storage_uri=app.config.get('RATELIMIT_STORAGE_URL', 'memory://'),
        strategy="fixed-window"
    )

    # Apply rate limits to auth endpoints
    @limiter.limit("5 per minute")
    def limit_auth():
        pass

    # Register blueprints
    from auth import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/api')

    # Apply rate limiting to specific routes
    limiter.limit("5 per minute")(auth_bp)

    # ================================================================================
    # STATIC FILE ROUTES (Serve Frontend)
    # ================================================================================

    @app.route('/')
    def index():
        return send_file(os.path.join(app.root_path, '..', 'frontend', 'index.html'))

    @app.route('/<path:filename>.html')
    def serve_html(filename):
        try:
            return send_file(os.path.join(app.root_path, '..', 'frontend', f'{filename}.html'))
        except:
            return send_file(os.path.join(app.root_path, '..', 'frontend', 'index.html'))

    @app.route('/css/<path:filename>')
    def serve_css(filename):
        return send_file(os.path.join(app.root_path, '..', 'frontend', 'css', filename))

    # ================================================================================
    # ERROR HANDLERS
    # ================================================================================

    @app.errorhandler(429)
    def ratelimit_handler(e):
        return {
            'success': False,
            'message': 'Too many requests. Please slow down.',
            'error': 'RATE_LIMITED'
        }, 429

    @app.errorhandler(500)
    def internal_error(e):
        db.session.rollback()
        return {
            'success': False,
            'message': 'Internal server error',
            'error': 'SERVER_ERROR'
        }, 500

    # Create database tables
    with app.app_context():
        db.create_all()

    return app


# ================================================================================
# MAIN
# ================================================================================

if __name__ == '__main__':
    app = create_app()

    print("=" * 70)
    print("CHAPTER 13: Production-Ready Authentication Boilerplate")
    print("=" * 70)
    print(f"Server: http://localhost:5013")
    print("")
    print("Configuration Status:")
    with app.app_context():
        from auth.oauth import is_google_configured
        print(f"  Google OAuth: {'CONFIGURED' if is_google_configured() else 'NOT CONFIGURED'}")
        print(f"  Mailgun: {'CONFIGURED' if app.config.get('MAILGUN_API_KEY') else 'NOT CONFIGURED (emails simulated)'}")
        print(f"  Rate Limiting: flask-limiter (memory storage)")
    print("")
    print("API Endpoints (prefix: /api):")
    print("  POST /api/register          - Register with email/password")
    print("  POST /api/login             - Login")
    print("  POST /api/refresh           - Refresh access token")
    print("  POST /api/logout            - Logout (revoke token)")
    print("  POST /api/logout-all        - Logout all devices")
    print("  POST /api/verify-email      - Verify email")
    print("  POST /api/resend-verification - Resend verification")
    print("  POST /api/forgot-password   - Request password reset")
    print("  POST /api/reset-password    - Reset password")
    print("  POST /api/change-password   - Change password")
    print("  GET  /api/auth/google       - Start Google OAuth")
    print("  GET  /api/profile           - Get profile (protected)")
    print("  PUT  /api/profile           - Update profile (protected)")
    print("")
    print("Frontend Pages:")
    print("  /                    - Landing page")
    print("  /login.html          - Login page")
    print("  /register.html       - Registration page")
    print("  /forgot-password.html - Forgot password")
    print("  /reset-password.html - Reset password")
    print("  /verify-email.html   - Email verification")
    print("  /dashboard.html      - Dashboard (protected)")
    print("=" * 70)

    app.run(debug=True, port=5013)
