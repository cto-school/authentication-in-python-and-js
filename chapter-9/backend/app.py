# ================================================================================
# CHAPTER 9: Role-Based Access Control (RBAC)
# ================================================================================
#
# Authentication: WHO are you? (login)
# Authorization: WHAT can you do? (roles, permissions)
#
# RBAC: Assign users to ROLES, each role has PERMISSIONS
#   user  → view profile, edit own profile
#   admin → user permissions + manage users, delete users
#
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

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_ch9.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
SECRET_KEY = 'your-secret-key-keep-it-safe-123'
ADMIN_SECRET = 'make-me-admin-secret'  # For testing only!

db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False)  # 'user' or 'admin'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }


def hash_password(password):
    return generate_password_hash(password)


def verify_password(plain, hashed):
    return check_password_hash(hashed, plain)


def create_token(user):
    """Token includes role for authorization checks."""
    return jwt.encode({
        'user_id': user.id,
        'email': user.email,
        'role': user.role,  # Include role!
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, SECRET_KEY, algorithm='HS256')


def token_required(f):
    """Require valid token (authenticated)."""
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
    """Require admin role. Use AFTER @token_required."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if g.current_user.get('role') != 'admin':
            return jsonify({
                'success': False,
                'message': 'Admin access required',
                'error': 'FORBIDDEN'
            }), 403  # 403 = Forbidden (authenticated but not authorized)
        return f(*args, **kwargs)
    return decorated


@app.route('/')
def index():
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    return send_file(html_path)


@app.route('/register', methods=['POST'])
def register():
    """Register always creates 'user' role (never admin)."""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Credentials required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': 'Email exists'}), 400

    user = User(email=email, password=hash_password(password), role='user')
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
    """Any logged-in user can access."""
    user = User.query.get(g.current_user['user_id'])
    return jsonify({'success': True, 'profile': user.to_dict()})


# ================================================================================
# ADMIN-ONLY ROUTES
# ================================================================================


@app.route('/admin/users', methods=['GET'])
@token_required
@admin_required  # Must be admin!
def get_all_users():
    """List all users - ADMIN ONLY."""
    users = User.query.all()
    return jsonify({
        'success': True,
        'users': [u.to_dict() for u in users],
        'total': len(users)
    })


@app.route('/admin/users/<int:user_id>/role', methods=['PUT'])
@token_required
@admin_required
def update_role(user_id):
    """Change user role - ADMIN ONLY."""
    data = request.get_json()
    new_role = data.get('role')

    if new_role not in ['user', 'admin']:
        return jsonify({'success': False, 'message': 'Invalid role'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    # Prevent self-demotion
    if user.id == g.current_user['user_id'] and new_role != 'admin':
        return jsonify({'success': False, 'message': 'Cannot demote yourself'}), 400

    user.role = new_role
    db.session.commit()

    return jsonify({'success': True, 'message': f'Role updated to {new_role}', 'user': user.to_dict()})


@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_user(user_id):
    """Delete user - ADMIN ONLY."""
    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    # Prevent self-deletion
    if user.id == g.current_user['user_id']:
        return jsonify({'success': False, 'message': 'Cannot delete yourself'}), 400

    db.session.delete(user)
    db.session.commit()

    return jsonify({'success': True, 'message': 'User deleted'})


@app.route('/make-admin', methods=['POST'])
def make_admin():
    """FOR TESTING ONLY - make a user admin."""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    secret = data.get('secret')

    if secret != ADMIN_SECRET:
        return jsonify({'success': False, 'message': 'Invalid secret'}), 403

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    user.role = 'admin'
    db.session.commit()

    return jsonify({'success': True, 'message': f'{email} is now admin', 'user': user.to_dict()})


with app.app_context():
    db.create_all()


# ================================================================================
# KEY TAKEAWAYS - Chapter 9
# ================================================================================
#
# 1. AUTHENTICATION vs AUTHORIZATION:
#    Authentication: WHO are you? (login) → 401 Unauthorized
#    Authorization: WHAT can you do? (roles) → 403 Forbidden
#
# 2. 401 vs 403:
#    401 Unauthorized: "I don't know who you are" (no token / invalid token)
#    403 Forbidden: "I know who you are, but you can't do this" (not admin)
#
# 3. ROLE IN JWT TOKEN:
#    Token payload includes: { user_id, email, role: 'admin' }
#    Server reads role from token - no database lookup needed!
#    But... user must re-login to get updated role in token.
#
# 4. DECORATOR STACKING ORDER:
#    @token_required   ← FIRST: Is user logged in?
#    @admin_required   ← SECOND: Is user an admin?
#    def admin_route():
#
#    @admin_required assumes g.current_user exists from @token_required.
#
# 5. SECURITY RULES:
#    - Registration ALWAYS creates 'user' role (never admin)
#    - Admin can't demote themselves (prevent lockout)
#    - Admin can't delete themselves (prevent orphan data)
#    - Principle of least privilege: start with minimal permissions
#
# 6. FRONTEND: Role-based UI
#    The frontend can show/hide elements based on role from JWT:
#
#    const payload = JSON.parse(atob(token.split('.')[1]));
#    if (payload.role === 'admin') {
#        showAdminPanel();  // Only admins see this
#    }
#
#    TRY THIS - Decode your token and check the role:
#    - Login, then open Developer Tools → Application → Local Storage
#    - Copy the token value
#    - Go to https://jwt.io and paste it
#    - Look for "role": "user" or "role": "admin" in the payload
#    - Make yourself admin with /make-admin, then LOGIN AGAIN
#    - Decode the new token → now "role": "admin"
#
# 7. TRY THIS - Test the 401 vs 403 difference:
#    - Without logging in, try "Get All Users" → 401 (no token)
#    - Login as regular user, try "Get All Users" → 403 (not admin)
#    - Make yourself admin, login again, try "Get All Users" → 200 Success!
#
# NEXT CHAPTER: Security best practices (rate limiting, account lockout, audit logs).
#
# ================================================================================


# ================================================================================
# EXERCISES - Test Your Understanding!
# ================================================================================
#
# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 1: Add Moderator Role (Easy)
# ────────────────────────────────────────────────────────────────────────────────
# Add a third role 'moderator' with permissions between user and admin:
# - Can view all users (like admin)
# - Cannot delete users or change roles (unlike admin)
#
# Create @moderator_required decorator that allows both moderators AND admins.
# Create GET /mod/users endpoint that moderators can access.
#
# Test as user: 403 Forbidden
# Test as moderator: 200 Success (list of users)
# Test as admin: 200 Success (list of users)
#
# HINT: Check if role in ['moderator', 'admin']
# ────────────────────────────────────────────────────────────────────────────────

# YOUR CODE HERE:
# def moderator_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         if g.current_user.get('role') not in ['moderator', 'admin']:
#             return jsonify({'success': False, 'message': 'Moderator access required'}), 403
#         return f(*args, **kwargs)
#     return decorated
#
# @app.route('/mod/users', methods=['GET'])
# @token_required
# @moderator_required
# def mod_get_users():
#     pass


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 2: My Permissions Endpoint (Easy)
# ────────────────────────────────────────────────────────────────────────────────
# Create an endpoint GET /my-permissions that:
# - Returns what the current user can and cannot do based on their role
#
# Test: curl http://localhost:5009/my-permissions \
#       -H "Authorization: Bearer eyJ..."
#
# Expected for 'user': {
#   "role": "user",
#   "permissions": {
#     "view_own_profile": true,
#     "edit_own_profile": true,
#     "view_all_users": false,
#     "delete_users": false,
#     "change_roles": false
#   }
# }
#
# Expected for 'admin': {
#   "role": "admin",
#   "permissions": {
#     "view_own_profile": true,
#     "edit_own_profile": true,
#     "view_all_users": true,
#     "delete_users": true,
#     "change_roles": true
#   }
# }
# ────────────────────────────────────────────────────────────────────────────────

# YOUR CODE HERE:
# @app.route('/my-permissions', methods=['GET'])
# @token_required
# def my_permissions():
#     pass


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 3: Role Hierarchy Check (Medium)
# ────────────────────────────────────────────────────────────────────────────────
# Modify /admin/users/<id>/role to enforce role hierarchy:
# - admin > moderator > user
# - Users can only change roles of users BELOW them in hierarchy
# - Admin can change anyone (except themselves)
# - Moderator cannot change roles at all (only admin can)
#
# Test as moderator trying to make someone admin: 403 "Insufficient privileges"
#
# HINT: Define hierarchy as dict: {'admin': 3, 'moderator': 2, 'user': 1}
# ────────────────────────────────────────────────────────────────────────────────


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 4: Permission-Based Access (Hard)
# ────────────────────────────────────────────────────────────────────────────────
# Instead of role-based, implement permission-based access control:
# - Add 'permissions' field to User model (JSON string or separate table)
# - Each user has specific permissions: ['read:users', 'write:users', 'delete:users']
# - Create @permission_required('delete:users') decorator
#
# This is more flexible than roles - users can have custom permission sets.
#
# Test: Create user with only ['read:users'] permission
#       Try to access an endpoint requiring 'delete:users' → 403
#
# HINT: Store permissions as comma-separated string: "read:users,write:users"
#       Or use a separate UserPermissions table
# ────────────────────────────────────────────────────────────────────────────────

# YOUR CODE HERE:
# def permission_required(permission):
#     def decorator(f):
#         @wraps(f)
#         def decorated(*args, **kwargs):
#             user = User.query.get(g.current_user['user_id'])
#             user_permissions = user.permissions.split(',') if user.permissions else []
#             if permission not in user_permissions:
#                 return jsonify({'success': False, 'message': f'Permission required: {permission}'}), 403
#             return f(*args, **kwargs)
#         return decorated
#     return decorator


# ================================================================================


if __name__ == '__main__':
    print("=" * 60)
    print("CHAPTER 9: Role-Based Access Control")
    print("=" * 60)
    print("Server: http://localhost:5009")
    print("")
    print("User routes:  GET /profile")
    print("Admin routes: GET /admin/users")
    print("              PUT /admin/users/:id/role")
    print("              DELETE /admin/users/:id")
    print("=" * 60)
    app.run(debug=True, port=5009)
