# ================================================================================
# CHAPTER 8: SOLUTIONS - Refresh Tokens
# ================================================================================

from flask import Flask, jsonify, request, g, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import uuid
from datetime import datetime, timedelta
from functools import wraps
import os
import warnings
warnings.filterwarnings('ignore', message='.*Query.get.*')

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_ch8_solutions.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
SECRET_KEY = 'your-secret-key-keep-it-safe-123'

ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
REFRESH_TOKEN_EXPIRES = timedelta(days=7)

db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def to_dict(self):
        return {'id': self.id, 'email': self.email}


class TokenBlacklist(db.Model):
    __tablename__ = 'token_blacklist'
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # For logout-all
    revoked_at = db.Column(db.DateTime, default=datetime.utcnow)


# ================================================================================
# EXERCISE 3 SOLUTION: Active Sessions Tracking
# ================================================================================

class ActiveSession(db.Model):
    __tablename__ = 'active_sessions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    jti = db.Column(db.String(36), unique=True, nullable=False)
    device_info = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime, default=datetime.utcnow)


def hash_password(password):
    return generate_password_hash(password)


def verify_password(plain, hashed):
    return check_password_hash(hashed, plain)


def create_access_token(user):
    return jwt.encode({
        'user_id': user.id,
        'email': user.email,
        'type': 'access',
        'exp': datetime.utcnow() + ACCESS_TOKEN_EXPIRES
    }, SECRET_KEY, algorithm='HS256')


def create_refresh_token(user, device_info=None):
    jti = str(uuid.uuid4())

    # Track session
    session = ActiveSession(
        user_id=user.id,
        jti=jti,
        device_info=device_info or 'Unknown'
    )
    db.session.add(session)

    return jwt.encode({
        'user_id': user.id,
        'type': 'refresh',
        'jti': jti,
        'exp': datetime.utcnow() + REFRESH_TOKEN_EXPIRES
    }, SECRET_KEY, algorithm='HS256')


def is_token_blacklisted(jti):
    return TokenBlacklist.query.filter_by(jti=jti).first() is not None


def access_token_required(f):
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
            if decoded.get('type') != 'access':
                return jsonify({'success': False, 'message': 'Use access token'}), 401
            g.current_user = {'user_id': decoded['user_id'], 'email': decoded['email']}
            g.token_exp = decoded['exp']
        except jwt.ExpiredSignatureError:
            return jsonify({'success': False, 'message': 'Token expired', 'error': 'TOKEN_EXPIRED'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'success': False, 'message': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated


@app.route('/')
def index():
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    return send_file(html_path)


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': 'Email exists'}), 400

    user = User(email=email, password=hash_password(password))
    db.session.add(user)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Registered', 'user': user.to_dict()}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Credentials required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not verify_password(password, user.password):
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

    device_info = request.headers.get('User-Agent', 'Unknown')

    return jsonify({
        'success': True,
        'message': 'Login successful',
        'access_token': create_access_token(user),
        'refresh_token': create_refresh_token(user, device_info),
        'expires_in': int(ACCESS_TOKEN_EXPIRES.total_seconds()),
        'user': user.to_dict()
    })


# ================================================================================
# EXERCISE 4 SOLUTION: Refresh Token Rotation
# ================================================================================

@app.route('/refresh', methods=['POST'])
def refresh():
    data = request.get_json()
    refresh_token = data.get('refresh_token')

    if not refresh_token:
        return jsonify({'success': False, 'message': 'Refresh token required'}), 400

    try:
        decoded = jwt.decode(refresh_token, SECRET_KEY, algorithms=['HS256'])

        if decoded.get('type') != 'refresh':
            return jsonify({'success': False, 'message': 'Use refresh token'}), 401

        jti = decoded.get('jti')
        if is_token_blacklisted(jti):
            return jsonify({'success': False, 'message': 'Token revoked'}), 401

        user = User.query.get(decoded['user_id'])
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404

        # Update last_used for session
        session = ActiveSession.query.filter_by(jti=jti).first()
        if session:
            session.last_used = datetime.utcnow()

        # EXERCISE 4: Token rotation - blacklist old refresh token
        db.session.add(TokenBlacklist(jti=jti, user_id=user.id))

        # Delete old session
        if session:
            db.session.delete(session)

        device_info = request.headers.get('User-Agent', 'Unknown')

        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Token refreshed (old token revoked)',
            'access_token': create_access_token(user),
            'refresh_token': create_refresh_token(user, device_info),  # NEW refresh token
            'expires_in': int(ACCESS_TOKEN_EXPIRES.total_seconds()),
            'note': 'Old refresh token has been revoked - use the new one'
        })

    except jwt.ExpiredSignatureError:
        return jsonify({'success': False, 'message': 'Refresh token expired. Login again.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'success': False, 'message': 'Invalid refresh token'}), 401


@app.route('/logout', methods=['POST'])
def logout():
    data = request.get_json()
    refresh_token = data.get('refresh_token')

    if not refresh_token:
        return jsonify({'success': False, 'message': 'Refresh token required'}), 400

    try:
        decoded = jwt.decode(refresh_token, SECRET_KEY, algorithms=['HS256'])
        jti = decoded.get('jti')

        if is_token_blacklisted(jti):
            return jsonify({'success': True, 'message': 'Already logged out'})

        db.session.add(TokenBlacklist(jti=jti, user_id=decoded['user_id']))

        # Remove session
        ActiveSession.query.filter_by(jti=jti).delete()
        db.session.commit()

        return jsonify({'success': True, 'message': 'Logged out'})

    except jwt.ExpiredSignatureError:
        return jsonify({'success': True, 'message': 'Token already expired'})
    except jwt.InvalidTokenError:
        return jsonify({'success': False, 'message': 'Invalid token'}), 400


# ================================================================================
# EXERCISE 1 SOLUTION: Token Expiry Info
# ================================================================================

@app.route('/token-expiry', methods=['GET'])
@access_token_required
def token_expiry():
    exp_timestamp = g.token_exp
    exp_datetime = datetime.fromtimestamp(exp_timestamp)
    now = datetime.utcnow()
    seconds_remaining = int((exp_datetime - now).total_seconds())

    return jsonify({
        'success': True,
        'expires_at': exp_datetime.strftime('%Y-%m-%d %H:%M:%S'),
        'seconds_remaining': max(0, seconds_remaining),
        'is_expired': seconds_remaining <= 0
    })


# ================================================================================
# EXERCISE 2 SOLUTION: Logout All Sessions
# ================================================================================

@app.route('/logout-all', methods=['POST'])
@access_token_required
def logout_all():
    user_id = g.current_user['user_id']

    # Get all active sessions
    sessions = ActiveSession.query.filter_by(user_id=user_id).all()
    sessions_count = len(sessions)

    # Blacklist all refresh tokens for this user
    for session in sessions:
        if not is_token_blacklisted(session.jti):
            db.session.add(TokenBlacklist(jti=session.jti, user_id=user_id))

    # Delete all sessions
    ActiveSession.query.filter_by(user_id=user_id).delete()
    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Logged out from all devices',
        'sessions_revoked': sessions_count
    })


# ================================================================================
# EXERCISE 3 SOLUTION: List Active Sessions
# ================================================================================

@app.route('/sessions', methods=['GET'])
@access_token_required
def get_sessions():
    user_id = g.current_user['user_id']
    sessions = ActiveSession.query.filter_by(user_id=user_id).all()

    return jsonify({
        'success': True,
        'sessions': [{
            'jti': s.jti[:8] + '...',  # Partial for security
            'device': s.device_info[:50] if s.device_info else 'Unknown',
            'created_at': s.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'last_used': s.last_used.strftime('%Y-%m-%d %H:%M:%S')
        } for s in sessions],
        'total': len(sessions)
    })


@app.route('/profile', methods=['GET'])
@access_token_required
def get_profile():
    user = User.query.get(g.current_user['user_id'])
    return jsonify({'success': True, 'profile': user.to_dict()})


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    print("=" * 60)
    print("CHAPTER 8: SOLUTIONS")
    print("=" * 60)
    print("Server running at: http://localhost:5008")
    print("")
    print("Exercise Solutions:")
    print("  GET /token-expiry  - Exercise 1")
    print("  POST /logout-all   - Exercise 2")
    print("  GET /sessions      - Exercise 3")
    print("  POST /refresh      - Exercise 4 (token rotation)")
    print("=" * 60)
    app.run(debug=True, port=5008)
