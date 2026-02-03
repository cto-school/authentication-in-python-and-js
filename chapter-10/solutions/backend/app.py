# ================================================================================
# CHAPTER 10: SOLUTIONS - Security Best Practices
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

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_ch10_solutions.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
SECRET_KEY = 'your-secret-key-keep-it-safe-123'

db = SQLAlchemy(app)

# Rate limiting
rate_limit_store = defaultdict(list)
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX_REQUESTS = 10

# Progressive lockout durations (Exercise 2)
LOCKOUT_DURATIONS = [15, 30, 60, 1440]  # minutes


def is_rate_limited(ip):
    now = time.time()
    rate_limit_store[ip] = [t for t in rate_limit_store[ip] if now - t < RATE_LIMIT_WINDOW]
    if len(rate_limit_store[ip]) >= RATE_LIMIT_MAX_REQUESTS:
        return True
    rate_limit_store[ip].append(now)
    return False


def rate_limit(f):
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
# EXERCISE 1 SOLUTION: Enhanced Password Validation
# ================================================================================

def validate_password_strength(password):
    if len(password) < 8:
        return False, 'Password must be at least 8 characters'

    if not re.search(r'[A-Z]', password):
        return False, 'Password must contain uppercase letter'

    if not re.search(r'[a-z]', password):
        return False, 'Password must contain lowercase letter'

    if not re.search(r'[0-9]', password):
        return False, 'Password must contain a number'

    # EXERCISE 1: Special character requirement
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, 'Password must contain a special character (!@#$%^&*)'

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
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    lockout_count = db.Column(db.Integer, default=0)  # EXERCISE 2

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'last_login': self.last_login.strftime('%Y-%m-%d %H:%M:%S') if self.last_login else None,
            'is_locked': self.is_locked()
        }

    def is_locked(self):
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False

    # EXERCISE 2: Get lockout duration based on lockout count
    def get_lockout_duration(self):
        index = min(self.lockout_count, len(LOCKOUT_DURATIONS) - 1)
        return LOCKOUT_DURATIONS[index]


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, nullable=True)
    action = db.Column(db.String(50), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    details = db.Column(db.String(255), nullable=True)
    success = db.Column(db.Boolean, default=True)


def log_action(action, user_id=None, details=None, success=True):
    log = AuditLog(
        user_id=user_id,
        action=action,
        ip_address=request.remote_addr,
        details=details,
        success=success
    )
    db.session.add(log)
    db.session.commit()


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


@app.route('/')
def index():
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    return send_file(html_path)


@app.route('/register', methods=['POST'])
@rate_limit
def register():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Credentials required'}), 400

    # Exercise 1: Enhanced password validation
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


# ================================================================================
# EXERCISE 2 SOLUTION: Progressive Lockout
# ================================================================================

@app.route('/login', methods=['POST'])
@rate_limit
def login():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Credentials required'}), 400

    user = User.query.filter_by(email=email).first()

    if user and user.is_locked():
        log_action('LOGIN_BLOCKED', user.id, 'Account locked', success=False)
        remaining = (user.locked_until - datetime.utcnow()).seconds
        return jsonify({
            'success': False,
            'message': f'Account locked. Try again in {remaining} seconds.',
            'error': 'ACCOUNT_LOCKED',
            'lockout_level': user.lockout_count
        }), 403

    if not user or not verify_password(password, user.password):
        if user:
            user.failed_login_attempts += 1

            if user.failed_login_attempts >= 5:
                # EXERCISE 2: Progressive lockout
                lockout_minutes = user.get_lockout_duration()
                user.locked_until = datetime.utcnow() + timedelta(minutes=lockout_minutes)
                user.lockout_count += 1
                user.failed_login_attempts = 0
                db.session.commit()
                log_action('ACCOUNT_LOCKED', user.id, f'Locked for {lockout_minutes} min (level {user.lockout_count})', success=False)
                return jsonify({
                    'success': False,
                    'message': f'Account locked for {lockout_minutes} minutes due to failed attempts',
                    'error': 'ACCOUNT_LOCKED',
                    'lockout_duration': lockout_minutes,
                    'lockout_level': user.lockout_count
                }), 403

            db.session.commit()

        log_action('LOGIN_FAILED', user.id if user else None, f'Failed: {email}', success=False)
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

    # Success - reset failed attempts AND lockout count
    user.failed_login_attempts = 0
    user.locked_until = None
    user.lockout_count = 0  # Reset progressive lockout on success
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


# ================================================================================
# EXERCISE 3 SOLUTION: Filtered Audit Logs
# ================================================================================

@app.route('/audit-logs', methods=['GET'])
@token_required
def get_audit_logs():
    query = AuditLog.query

    # Filter by action
    action = request.args.get('action')
    if action:
        query = query.filter_by(action=action)

    # Filter by user_id
    user_id = request.args.get('user_id')
    if user_id:
        query = query.filter_by(user_id=int(user_id))

    # Filter by success
    success = request.args.get('success')
    if success is not None:
        query = query.filter_by(success=success.lower() == 'true')

    # Filter by date range
    from_date = request.args.get('from')
    if from_date:
        try:
            from_dt = datetime.strptime(from_date, '%Y-%m-%d')
            query = query.filter(AuditLog.timestamp >= from_dt)
        except ValueError:
            pass

    to_date = request.args.get('to')
    if to_date:
        try:
            to_dt = datetime.strptime(to_date, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(AuditLog.timestamp < to_dt)
        except ValueError:
            pass

    logs = query.order_by(AuditLog.timestamp.desc()).limit(50).all()

    return jsonify({
        'success': True,
        'filters': {
            'action': action,
            'user_id': user_id,
            'success': success,
            'from': from_date,
            'to': to_date
        },
        'logs': [{
            'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'action': log.action,
            'user_id': log.user_id,
            'ip': log.ip_address,
            'details': log.details,
            'success': log.success
        } for log in logs],
        'count': len(logs)
    })


# ================================================================================
# EXERCISE 4 SOLUTION: Suspicious Activity Detection
# ================================================================================

@app.route('/security-alerts', methods=['GET'])
@token_required
def get_security_alerts():
    alerts = []
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)

    # Find users with multiple failed logins from different IPs
    failed_logins = AuditLog.query.filter(
        AuditLog.action == 'LOGIN_FAILED',
        AuditLog.timestamp >= one_hour_ago,
        AuditLog.success == False
    ).all()

    # Group by user
    user_failures = defaultdict(list)
    for log in failed_logins:
        if log.user_id:
            user_failures[log.user_id].append(log.ip_address)

    for user_id, ips in user_failures.items():
        unique_ips = list(set(ips))
        if len(unique_ips) > 1:
            user = User.query.get(user_id)
            alerts.append({
                'type': 'MULTIPLE_IP_FAILURES',
                'severity': 'high',
                'user_email': user.email if user else f'User #{user_id}',
                'user_id': user_id,
                'ips': unique_ips,
                'failure_count': len(ips),
                'message': f'Multiple failed login attempts from {len(unique_ips)} different IPs'
            })

    # Find locked accounts
    locked_users = User.query.filter(User.locked_until > datetime.utcnow()).all()
    for user in locked_users:
        alerts.append({
            'type': 'ACCOUNT_LOCKED',
            'severity': 'medium',
            'user_email': user.email,
            'user_id': user.id,
            'locked_until': user.locked_until.strftime('%Y-%m-%d %H:%M:%S'),
            'lockout_level': user.lockout_count,
            'message': f'Account locked (level {user.lockout_count})'
        })

    # Find high rate of failed logins (potential brute force)
    total_failures = len(failed_logins)
    if total_failures > 20:
        alerts.append({
            'type': 'HIGH_FAILURE_RATE',
            'severity': 'high',
            'failure_count': total_failures,
            'timeframe': '1 hour',
            'message': f'{total_failures} failed login attempts in the last hour'
        })

    return jsonify({
        'success': True,
        'alerts': alerts,
        'total_alerts': len(alerts),
        'checked_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    })


@app.route('/test-rate-limit', methods=['GET'])
@rate_limit
def test_rate_limit():
    return jsonify({
        'success': True,
        'message': 'Request allowed',
        'limit': f'{RATE_LIMIT_MAX_REQUESTS} requests per {RATE_LIMIT_WINDOW} seconds'
    })


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    print("=" * 60)
    print("CHAPTER 10: SOLUTIONS")
    print("=" * 60)
    print("Server: http://localhost:5010")
    print("")
    print("Exercise Solutions:")
    print("  Special char in password  - Exercise 1")
    print("  Progressive lockout       - Exercise 2")
    print("  GET /audit-logs?filters   - Exercise 3")
    print("  GET /security-alerts      - Exercise 4")
    print("=" * 60)
    app.run(debug=True, port=5010)
