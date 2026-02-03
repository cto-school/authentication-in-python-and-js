# ================================================================================
# CHAPTER 10: Security Best Practices
# ================================================================================
#
# This chapter demonstrates security features you should implement:
#
#   1. Rate limiting (prevent brute force)
#   2. Password strength validation
#   3. Account lockout after failed attempts
#   4. Secure headers
#   5. Input sanitization
#   6. Audit logging
#
# ================================================================================

from flask import Flask, jsonify, request, g, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import re
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
import time
import os
import warnings
warnings.filterwarnings('ignore', message='.*Query.get.*')

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_ch10.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
SECRET_KEY = 'your-secret-key-keep-it-safe-123'

db = SQLAlchemy(app)


# ================================================================================
# RATE LIMITING (Simple in-memory implementation)
# ================================================================================
# In production, use Redis for distributed rate limiting
# ================================================================================

rate_limit_store = defaultdict(list)  # IP -> [timestamps]
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 10  # max requests per window


def is_rate_limited(ip):
    """Check if IP has exceeded rate limit."""
    now = time.time()
    # Clean old entries
    rate_limit_store[ip] = [t for t in rate_limit_store[ip] if now - t < RATE_LIMIT_WINDOW]
    # Check limit
    if len(rate_limit_store[ip]) >= RATE_LIMIT_MAX_REQUESTS:
        return True
    # Add current request
    rate_limit_store[ip].append(now)
    return False


def rate_limit(f):
    """Decorator to apply rate limiting."""
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.remote_addr
        if is_rate_limited(ip):
            return jsonify({
                'success': False,
                'message': 'Too many requests. Please wait.',
                'error': 'RATE_LIMITED'
            }), 429
        return f(*args, **kwargs)
    return decorated


# ================================================================================
# PASSWORD STRENGTH VALIDATION
# ================================================================================


def validate_password_strength(password):
    """
    Validate password meets security requirements.
    Returns (is_valid, error_message)
    """
    if len(password) < 8:
        return False, 'Password must be at least 8 characters'

    if not re.search(r'[A-Z]', password):
        return False, 'Password must contain uppercase letter'

    if not re.search(r'[a-z]', password):
        return False, 'Password must contain lowercase letter'

    if not re.search(r'[0-9]', password):
        return False, 'Password must contain a number'

    return True, None


# ================================================================================
# MODELS
# ================================================================================


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Security fields
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'last_login': self.last_login.strftime('%Y-%m-%d %H:%M:%S') if self.last_login else None,
            'is_locked': self.is_locked()
        }

    def is_locked(self):
        """Check if account is currently locked."""
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False


class AuditLog(db.Model):
    """Track security-relevant actions."""
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, nullable=True)
    action = db.Column(db.String(50), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    details = db.Column(db.String(255), nullable=True)
    success = db.Column(db.Boolean, default=True)


def log_action(action, user_id=None, details=None, success=True):
    """Log security action."""
    log = AuditLog(
        user_id=user_id,
        action=action,
        ip_address=request.remote_addr,
        details=details,
        success=success
    )
    db.session.add(log)
    db.session.commit()


# ================================================================================
# HELPERS
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


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'success': False, 'message': 'Token missing'}), 401
        try:
            parts = auth_header.split(' ')
            if len(parts) != 2 or parts[0] != 'Bearer':
                return jsonify({'success': False, 'message': 'Invalid format'}), 401
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


@app.route('/register', methods=['POST'])
@rate_limit  # Rate limiting!
def register():
    """Register with password strength validation."""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Credentials required'}), 400

    # Password strength check
    is_valid, error = validate_password_strength(password)
    if not is_valid:
        return jsonify({'success': False, 'message': error}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': 'Email exists'}), 400

    user = User(email=email, password=hash_password(password))
    db.session.add(user)
    db.session.commit()

    log_action('REGISTER', user.id, f'New user: {email}')

    return jsonify({'success': True, 'message': 'Registered', 'user': user.to_dict()}), 201


@app.route('/login', methods=['POST'])
@rate_limit  # Rate limiting!
def login():
    """Login with account lockout protection."""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Credentials required'}), 400

    user = User.query.filter_by(email=email).first()

    # Check if account is locked
    if user and user.is_locked():
        log_action('LOGIN_BLOCKED', user.id, 'Account locked', success=False)
        remaining = (user.locked_until - datetime.utcnow()).seconds
        return jsonify({
            'success': False,
            'message': f'Account locked. Try again in {remaining} seconds.',
            'error': 'ACCOUNT_LOCKED'
        }), 403

    # Verify credentials
    if not user or not verify_password(password, user.password):
        if user:
            # Increment failed attempts
            user.failed_login_attempts += 1

            # Lock account after 5 failed attempts
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                db.session.commit()
                log_action('ACCOUNT_LOCKED', user.id, '5 failed attempts', success=False)
                return jsonify({
                    'success': False,
                    'message': 'Account locked for 15 minutes due to failed attempts',
                    'error': 'ACCOUNT_LOCKED'
                }), 403

            db.session.commit()

        log_action('LOGIN_FAILED', user.id if user else None, f'Failed: {email}', success=False)
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

    # Success - reset failed attempts
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login = datetime.utcnow()
    db.session.commit()

    log_action('LOGIN_SUCCESS', user.id, f'Login: {email}')

    return jsonify({
        'success': True,
        'message': 'Login successful',
        'token': create_token(user),
        'user': user.to_dict()
    })


@app.route('/profile', methods=['GET'])
@token_required
def get_profile():
    user = User.query.get(g.current_user['user_id'])
    return jsonify({'success': True, 'profile': user.to_dict()})


@app.route('/audit-logs', methods=['GET'])
@token_required
def get_audit_logs():
    """View recent audit logs (should be admin only in production)."""
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    return jsonify({
        'success': True,
        'logs': [{
            'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'action': log.action,
            'user_id': log.user_id,
            'ip': log.ip_address,
            'details': log.details,
            'success': log.success
        } for log in logs]
    })


@app.route('/test-rate-limit', methods=['GET'])
@rate_limit
def test_rate_limit():
    """Endpoint to test rate limiting."""
    return jsonify({
        'success': True,
        'message': 'Request allowed',
        'limit': f'{RATE_LIMIT_MAX_REQUESTS} requests per {RATE_LIMIT_WINDOW} seconds'
    })


with app.app_context():
    db.create_all()


# ================================================================================
# KEY TAKEAWAYS - Chapter 10 (FINAL CHAPTER)
# ================================================================================
#
# 1. RATE LIMITING prevents brute force attacks:
#    - Track requests per IP address
#    - Block after threshold (10 requests/minute)
#    - In production: Use Redis for distributed rate limiting
#
# 2. ACCOUNT LOCKOUT stops password guessing:
#    - Track failed login attempts per user
#    - Lock account after 5 failures
#    - Auto-unlock after timeout (15 minutes)
#    - Reset counter on successful login
#
# 3. PASSWORD STRENGTH rules:
#    - Minimum length (8 characters)
#    - Require uppercase, lowercase, number
#    - Consider: special characters, no common passwords
#
# 4. AUDIT LOGGING tracks security events:
#    - LOGIN_SUCCESS, LOGIN_FAILED, ACCOUNT_LOCKED, etc.
#    - Include: timestamp, user_id, IP address, action, success/failure
#    - Critical for debugging and security investigations
#
# 5. FRONTEND: See security features in action!
#
#    TRY THIS - Rate Limiting:
#    - Click "Send Request" button rapidly (10+ times)
#    - Watch the counter: "Allowed (Request #1)", "#2", ...
#    - After #10: "BLOCKED! (Request #11)" with red text
#    - Open Network tab: see HTTP 429 (Too Many Requests) status
#    - Wait 60 seconds, counter resets
#
#    TRY THIS - Account Lockout:
#    - Register a user, then try logging in with wrong password
#    - Watch the failed attempts count: "4 attempts remaining"
#    - After 5 failures: "Account locked for 15 minutes"
#    - Check Network tab: HTTP 403 with error: "ACCOUNT_LOCKED"
#
#    TRY THIS - Audit Logs:
#    - Register a user and login successfully
#    - Click "Refresh" on the Audit Logs section
#    - You'll see all your actions: REGISTER, LOGIN_SUCCESS, etc.
#    - Try a failed login → see LOGIN_FAILED in the logs
#    - This is how admins investigate security incidents!
#
# 6. ADDITIONAL SECURITY (not implemented, but important):
#    - HTTPS in production (encrypt all traffic)
#    - CSRF protection for forms (Flask-WTF)
#    - Secure headers (Flask-Talisman)
#    - Input sanitization (prevent XSS)
#    - Prepared statements (prevent SQL injection - SQLAlchemy does this!)
#
# ================================================================================
# CONGRATULATIONS! You've completed the Authentication Mastery course!
#
# You now understand:
#   ✓ JWT tokens and how they work
#   ✓ Password hashing and verification
#   ✓ Protected routes with decorators
#   ✓ Error handling best practices
#   ✓ Email verification flow
#   ✓ Password management (change & reset)
#   ✓ Refresh token pattern
#   ✓ Role-based access control
#   ✓ Security best practices
#
# You have ENTERPRISE-GRADE authentication knowledge!
# ================================================================================


# ================================================================================
# EXERCISES - Test Your Understanding!
# ================================================================================
#
# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 1: Add Special Character Requirement (Easy)
# ────────────────────────────────────────────────────────────────────────────────
# Enhance validate_password_strength() to also require:
# - At least one special character (!@#$%^&*(),.?":{}|<>)
#
# Test: Try password "Password1" → should fail
# Test: Try password "Password1!" → should succeed
#
# HINT: Use regex: re.search(r'[!@#$%^&*(),.?":{}|<>]', password)
# ────────────────────────────────────────────────────────────────────────────────


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 2: Progressive Lockout (Medium)
# ────────────────────────────────────────────────────────────────────────────────
# Implement progressive lockout that increases with repeated lockouts:
# - First lockout: 15 minutes (current)
# - Second lockout: 30 minutes
# - Third lockout: 1 hour
# - Fourth+ lockout: 24 hours
#
# Add 'lockout_count' field to User model to track this.
# Reset lockout_count on successful login.
#
# Test: Get locked out, wait, try again, get locked out longer
#
# HINT: lockout_duration = [15, 30, 60, 1440][min(user.lockout_count, 3)]
# NOTE: Delete users.db after modifying the model!
# ────────────────────────────────────────────────────────────────────────────────


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 3: Filter Audit Logs (Medium)
# ────────────────────────────────────────────────────────────────────────────────
# Enhance GET /audit-logs to support filtering:
# - ?action=LOGIN_FAILED - filter by action type
# - ?user_id=1 - filter by user
# - ?success=false - filter by success/failure
# - ?from=2024-01-01&to=2024-01-31 - filter by date range
#
# Test: curl "http://localhost:5010/audit-logs?action=LOGIN_FAILED&success=false" \
#       -H "Authorization: Bearer eyJ..."
#
# Expected: Only failed login attempts in the response
#
# HINT: Use request.args.get('action') to get query parameters
#       Build query dynamically: query = AuditLog.query
#       if action: query = query.filter_by(action=action)
# ────────────────────────────────────────────────────────────────────────────────

# YOUR CODE HERE (modify the existing get_audit_logs function):
# Starter code:
# @app.route('/audit-logs-filtered', methods=['GET'])
# @token_required
# def get_audit_logs_filtered():
#     query = AuditLog.query
#
#     action = request.args.get('action')
#     if action:
#         query = query.filter_by(action=action)
#
#     # Add more filters...
#
#     logs = query.order_by(AuditLog.timestamp.desc()).limit(50).all()
#     # ... rest of the code


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 4: Suspicious Activity Detection (Hard)
# ────────────────────────────────────────────────────────────────────────────────
# Create a system that detects suspicious login patterns:
# - Multiple failed logins from different IPs for same user
# - Successful login from new IP after failed attempts
# - Login from unusual location (different IP pattern)
#
# Create GET /security-alerts endpoint that returns suspicious activities.
#
# Test: Login with wrong password from multiple IPs (or simulate with different user agents)
#
# Expected: {
#   "alerts": [
#     {
#       "type": "MULTIPLE_IP_FAILURES",
#       "user_email": "test@test.com",
#       "ips": ["192.168.1.1", "192.168.1.2"],
#       "timestamp": "2024-01-15 10:30:00"
#     }
#   ]
# }
#
# HINT: Query AuditLog for patterns:
#       - LOGIN_FAILED from multiple IPs within 1 hour for same user
#       - LOGIN_SUCCESS from IP not seen before for this user
# ────────────────────────────────────────────────────────────────────────────────


# ────────────────────────────────────────────────────────────────────────────────
# BONUS EXERCISE: IP Whitelist/Blacklist (Hard)
# ────────────────────────────────────────────────────────────────────────────────
# Implement IP-based access control:
# - Create IPList model (ip_address, list_type: 'whitelist'/'blacklist', reason, created_at)
# - Block requests from blacklisted IPs before any processing
# - Optionally: Only allow admin routes from whitelisted IPs
#
# Create admin endpoints:
# - POST /admin/ip-blacklist - add IP to blacklist
# - POST /admin/ip-whitelist - add IP to whitelist
# - DELETE /admin/ip-list/<ip> - remove from any list
#
# HINT: Use @app.before_request to check IP before every request
# ────────────────────────────────────────────────────────────────────────────────


# ================================================================================


if __name__ == '__main__':
    print("=" * 60)
    print("CHAPTER 10: Security Best Practices")
    print("=" * 60)
    print("Server: http://localhost:5010")
    print("")
    print("Security features:")
    print("  - Rate limiting (10 req/min)")
    print("  - Password strength validation")
    print("  - Account lockout (5 failed attempts)")
    print("  - Audit logging")
    print("=" * 60)
    app.run(debug=True, port=5010)
