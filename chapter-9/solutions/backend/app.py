# ================================================================================
# CHAPTER 9: SOLUTIONS - Role-Based Access Control
# ================================================================================

from flask import Flask, jsonify, request, g, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps
import os
import warnings
warnings.filterwarnings('ignore', message='.*Query.get.*')

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_ch9_solutions.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
SECRET_KEY = 'your-secret-key-keep-it-safe-123'
ADMIN_SECRET = 'make-me-admin-secret'

# Role hierarchy (higher number = more privileges)
ROLE_HIERARCHY = {'user': 1, 'moderator': 2, 'admin': 3}

db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False)
    permissions = db.Column(db.String(500), nullable=True)  # EXERCISE 4: comma-separated
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'role': self.role,
            'permissions': self.permissions.split(',') if self.permissions else [],
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }

    def has_permission(self, permission):
        if not self.permissions:
            return False
        return permission in self.permissions.split(',')


def hash_password(password):
    return generate_password_hash(password)


def verify_password(plain, hashed):
    return check_password_hash(hashed, plain)


def create_token(user):
    return jwt.encode({
        'user_id': user.id,
        'email': user.email,
        'role': user.role,
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
            g.current_user = {
                'user_id': decoded['user_id'],
                'email': decoded['email'],
                'role': decoded.get('role', 'user')
            }
        except jwt.ExpiredSignatureError:
            return jsonify({'success': False, 'message': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'success': False, 'message': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if g.current_user.get('role') != 'admin':
            return jsonify({'success': False, 'message': 'Admin access required', 'error': 'FORBIDDEN'}), 403
        return f(*args, **kwargs)
    return decorated


# ================================================================================
# EXERCISE 1 SOLUTION: Moderator Role
# ================================================================================

def moderator_required(f):
    """Allows both moderators AND admins."""
    @wraps(f)
    def decorated(*args, **kwargs):
        role = g.current_user.get('role')
        if role not in ['moderator', 'admin']:
            return jsonify({
                'success': False,
                'message': 'Moderator or Admin access required',
                'error': 'FORBIDDEN'
            }), 403
        return f(*args, **kwargs)
    return decorated


# ================================================================================
# EXERCISE 4 SOLUTION: Permission-Based Access
# ================================================================================

def permission_required(permission):
    """Decorator factory that checks for specific permission."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = User.query.get(g.current_user['user_id'])
            if not user:
                return jsonify({'success': False, 'message': 'User not found'}), 404

            # Admins have all permissions
            if user.role == 'admin':
                return f(*args, **kwargs)

            if not user.has_permission(permission):
                return jsonify({
                    'success': False,
                    'message': f'Permission required: {permission}',
                    'error': 'FORBIDDEN'
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


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
        return jsonify({'success': False, 'message': 'Credentials required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': 'Email exists'}), 400

    # Default permissions for new users
    default_permissions = 'read:profile,write:profile'

    user = User(email=email, password=hash_password(password), role='user', permissions=default_permissions)
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
# EXERCISE 2 SOLUTION: My Permissions Endpoint
# ================================================================================

@app.route('/my-permissions', methods=['GET'])
@token_required
def my_permissions():
    user = User.query.get(g.current_user['user_id'])
    role = user.role

    # Define permissions based on role
    permissions = {
        'view_own_profile': True,
        'edit_own_profile': True,
        'view_all_users': role in ['moderator', 'admin'],
        'delete_users': role == 'admin',
        'change_roles': role == 'admin',
        'moderate_content': role in ['moderator', 'admin']
    }

    # Include custom permissions
    custom_permissions = user.permissions.split(',') if user.permissions else []

    return jsonify({
        'success': True,
        'role': role,
        'role_permissions': permissions,
        'custom_permissions': custom_permissions
    })


# ================================================================================
# EXERCISE 1 SOLUTION: Moderator Route
# ================================================================================

@app.route('/mod/users', methods=['GET'])
@token_required
@moderator_required
def mod_get_users():
    """Moderators can view users but not modify them."""
    users = User.query.all()
    return jsonify({
        'success': True,
        'users': [u.to_dict() for u in users],
        'total': len(users),
        'accessed_by': g.current_user['role']
    })


# Admin routes
@app.route('/admin/users', methods=['GET'])
@token_required
@admin_required
def get_all_users():
    users = User.query.all()
    return jsonify({
        'success': True,
        'users': [u.to_dict() for u in users],
        'total': len(users)
    })


# ================================================================================
# EXERCISE 3 SOLUTION: Role Hierarchy Check
# ================================================================================

@app.route('/admin/users/<int:user_id>/role', methods=['PUT'])
@token_required
@admin_required
def update_role(user_id):
    data = request.get_json()
    new_role = data.get('role')

    if new_role not in ['user', 'moderator', 'admin']:
        return jsonify({'success': False, 'message': 'Invalid role'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    current_user = User.query.get(g.current_user['user_id'])

    # Prevent self-demotion
    if user.id == current_user.id and new_role != 'admin':
        return jsonify({'success': False, 'message': 'Cannot demote yourself'}), 400

    # EXERCISE 3: Check hierarchy - can only change roles of users below you
    current_level = ROLE_HIERARCHY.get(current_user.role, 0)
    target_level = ROLE_HIERARCHY.get(user.role, 0)
    new_level = ROLE_HIERARCHY.get(new_role, 0)

    if target_level >= current_level:
        return jsonify({
            'success': False,
            'message': 'Cannot modify user with equal or higher role'
        }), 403

    if new_level >= current_level:
        return jsonify({
            'success': False,
            'message': 'Cannot promote to equal or higher role than yourself'
        }), 403

    user.role = new_role
    db.session.commit()

    return jsonify({'success': True, 'message': f'Role updated to {new_role}', 'user': user.to_dict()})


@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    if user.id == g.current_user['user_id']:
        return jsonify({'success': False, 'message': 'Cannot delete yourself'}), 400

    db.session.delete(user)
    db.session.commit()

    return jsonify({'success': True, 'message': 'User deleted'})


# ================================================================================
# EXERCISE 4 SOLUTION: Permission-Based Route
# ================================================================================

@app.route('/admin/users/<int:user_id>/permissions', methods=['PUT'])
@token_required
@admin_required
def update_permissions(user_id):
    """Admin can set custom permissions for a user."""
    data = request.get_json()
    permissions = data.get('permissions', [])

    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    user.permissions = ','.join(permissions)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Permissions updated',
        'user': user.to_dict()
    })


@app.route('/content/delete', methods=['DELETE'])
@token_required
@permission_required('delete:content')
def delete_content():
    """Example endpoint that requires specific permission."""
    return jsonify({
        'success': True,
        'message': 'Content deleted (you have delete:content permission)'
    })


@app.route('/make-admin', methods=['POST'])
def make_admin():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    secret = data.get('secret')

    if secret != ADMIN_SECRET:
        return jsonify({'success': False, 'message': 'Invalid secret'}), 403

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    user.role = 'admin'
    user.permissions = 'read:users,write:users,delete:users,delete:content'
    db.session.commit()

    return jsonify({'success': True, 'message': f'{email} is now admin', 'user': user.to_dict()})


@app.route('/make-moderator', methods=['POST'])
def make_moderator():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    secret = data.get('secret')

    if secret != ADMIN_SECRET:
        return jsonify({'success': False, 'message': 'Invalid secret'}), 403

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    user.role = 'moderator'
    user.permissions = 'read:users,moderate:content'
    db.session.commit()

    return jsonify({'success': True, 'message': f'{email} is now moderator', 'user': user.to_dict()})


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    print("=" * 60)
    print("CHAPTER 9: SOLUTIONS")
    print("=" * 60)
    print("Server running at: http://localhost:5009")
    print("")
    print("Exercise Solutions:")
    print("  GET /mod/users          - Exercise 1 (moderator access)")
    print("  GET /my-permissions     - Exercise 2")
    print("  PUT /admin/users/:id/role - Exercise 3 (hierarchy)")
    print("  DELETE /content/delete  - Exercise 4 (permission-based)")
    print("=" * 60)
    app.run(debug=True, port=5009)
