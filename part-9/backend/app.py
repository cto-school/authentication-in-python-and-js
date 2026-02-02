# ================================================================================
# PART 9: ROLE-BASED ACCESS CONTROL (RBAC)
# ================================================================================
#
# This part covers authorization - controlling WHAT users can do based on roles.
#
# AUTHENTICATION vs AUTHORIZATION:
#   - Authentication: "Who are you?" (login, tokens) ← Parts 2-4
#   - Authorization: "What can you do?" (roles, permissions) ← THIS PART
#
# RBAC CONCEPT:
#   Instead of checking individual permissions everywhere, assign users to ROLES.
#   Each role has a set of permissions.
#
#   Example:
#       USER role       → view profile, edit own profile
#       MODERATOR role  → USER permissions + delete comments, view reports
#       ADMIN role      → MODERATOR permissions + manage users, delete users
#
# NEW CONCEPTS IN THIS PART:
#   - Role column in User model
#   - @admin_required decorator (stacks with @token_required)
#   - 401 vs 403 status codes
#   - Preventing role escalation attacks
#   - Self-demotion/self-deletion protection
#
# ================================================================================

from flask import Flask, jsonify, request, g, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
# Password hashing using werkzeug.security (comes built-in with Flask)
from werkzeug.security import generate_password_hash, check_password_hash
import jwt  # From 'pyjwt' package (pip install pyjwt), NOT 'jwt'
from datetime import datetime, timedelta
from functools import wraps
import os

app = Flask(__name__)
CORS(app)


@app.route('/')  # Serve the frontend HTML
def index():
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    return send_file(html_path)


@app.route('/index.html')  # Also serve index.html for direct links
def index_html():
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    return send_file(html_path)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_new.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
SECRET_KEY = 'your-secret-key-keep-it-safe'

# ================================================================================
# ADMIN SECRET - For Testing/Development Only!
# ================================================================================
# This allows creating admin users via /make-admin endpoint.
# In PRODUCTION, you would:
#   1. Create first admin via database migration or CLI command
#   2. Use an admin panel to promote users
#   3. NEVER expose a /make-admin endpoint!
# ================================================================================
ADMIN_SECRET = 'admin-secret-key'

db = SQLAlchemy(app)


# ================================================================================
# USER MODEL WITH ROLE
# ================================================================================
# The 'role' column is the key addition in this part.
#
# Database structure:
#   +--------+---------+-----------+------+------------+
#   | id     | email   | password  | role | created_at |
#   +--------+---------+-----------+------+------------+
#   | 1      | a@b.com | hash...   | user | 2024-01-01 |
#   | 2      | c@d.com | hash...   | admin| 2024-01-02 |
#   +--------+---------+-----------+------+------------+
#
# Common role hierarchies:
#   Simple:   user < admin
#   Extended: user < moderator < admin < super_admin
# ================================================================================


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    # NEW: Role column with default value 'user'
    # - default='user' means new registrations automatically get 'user' role
    # - nullable=False means every user MUST have a role
    role = db.Column(db.String(20), default='user', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        """Convert user to dictionary, including role for frontend to use."""
        return {
            'id': self.id,
            'email': self.email,
            'role': self.role,  # Frontend can show/hide features based on role
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }


# Hash password - converts plain text to secure hash
def hash_password(password):
    return generate_password_hash(password)


# Verify password - compares plain password with stored hash
def check_password(password, hashed_password):
    return check_password_hash(hashed_password, password)


# ================================================================================
# JWT TOKEN WITH ROLE
# ================================================================================
# The role is now included in the JWT payload.
#
# Why include role in token?
#   PROS:
#     - No database query needed to check role on every request
#     - Faster authorization checks
#   CONS:
#     - If role changes, old token still has old role until it expires
#     - User must re-login to get updated role in token
#
# Token payload now looks like:
#   {
#       "user_id": 1,
#       "email": "user@example.com",
#       "role": "admin",           ← NEW!
#       "exp": 1234567890
#   }
# ================================================================================


def create_token(user):
    """Create JWT token with user role included."""
    payload = {
        'user_id': user.id,
        'email': user.email,
        'role': user.role,  # Include role in token
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


def token_required(f):
    """Decorator to require valid JWT token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')

        if not auth_header:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            parts = auth_header.split(' ')
            if len(parts) != 2 or parts[0] != 'Bearer':
                return jsonify({'message': 'Invalid token format!'}), 401

            token = parts[1]
            decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

            # Store user info INCLUDING ROLE for @admin_required to use
            # .get('role', 'user') provides default for old tokens without role
            g.current_user = {
                'user_id': decoded['user_id'],
                'email': decoded['email'],
                'role': decoded.get('role', 'user')  # Default to 'user' if missing
            }

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401

        return f(*args, **kwargs)
    return decorated


# ================================================================================
# ADMIN REQUIRED DECORATOR
# ================================================================================
# This decorator STACKS with @token_required to add role checking.
#
# IMPORTANT: Decorator order matters!
#   @app.route('/admin/users')
#   @token_required      ← Runs FIRST (outer decorator)
#   @admin_required      ← Runs SECOND (inner decorator)
#   def get_all_users():
#
# Python decorators execute from bottom to top when applied,
# but the wrapped functions execute top to bottom.
#
# Flow:
#   1. @token_required checks if user is logged in, stores g.current_user
#   2. @admin_required checks if g.current_user.role == 'admin'
#   3. If both pass, the actual route function runs
#
# HTTP STATUS CODES - 401 vs 403:
#   401 Unauthorized: "I don't know who you are" (not logged in, bad token)
#   403 Forbidden:    "I know who you are, but you can't do this" (no permission)
# ================================================================================


def admin_required(f):
    """
    Decorator to require admin role.
    MUST be used AFTER @token_required (stacked below it).
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if g.current_user.get('role') != 'admin':
            # 403 Forbidden - user is authenticated but not authorized
            return jsonify({
                'message': 'Admin access required!',
                'error': 'FORBIDDEN'
            }), 403

        return f(*args, **kwargs)
    return decorated


@app.route('/register', methods=['POST'])  # Register (always as regular user)
def register():
    data = request.get_json()  # Get JSON data
    email, password = data.get('email'), data.get('password')  # Get email and password

    if not email or not password:  # Validate input
        return jsonify({'message': 'Email and password are required!'}), 400

    if User.query.filter_by(email=email).first():  # Check email exists
        return jsonify({'message': 'Email already exists!'}), 400

    new_user = User(email=email, password=hash_password(password), role='user')  # Create user with 'user' role (never admin on register)
    db.session.add(new_user)  # Add to session
    db.session.commit()  # Save to database

    return jsonify({'message': 'User registered successfully!', 'user': new_user.to_dict()}), 201


@app.route('/login', methods=['POST'])  # Login and get token with role
def login():
    data = request.get_json()  # Get JSON data
    email, password = data.get('email'), data.get('password')  # Get credentials

    if not email or not password:  # Validate input
        return jsonify({'message': 'Email and password are required!'}), 400

    user = User.query.filter_by(email=email).first()  # Find user

    if not user or not check_password(password, user.password):  # Invalid credentials
        return jsonify({'message': 'Invalid email or password!'}), 401

    return jsonify({'message': 'Login successful!', 'token': create_token(user), 'user': user.to_dict()})  # Return token with role


@app.route('/profile', methods=['GET'])  # Get own profile (any logged-in user)
@token_required
def get_profile():
    user = User.query.get(g.current_user['user_id'])  # Get user by ID from token

    if not user:  # User not found
        return jsonify({'message': 'User not found!'}), 404

    return jsonify({'message': 'Profile retrieved!', 'profile': user.to_dict()})


# ================================================================================
# ADMIN-ONLY ROUTES
# ================================================================================
# These routes are protected by BOTH @token_required AND @admin_required.
# Regular users will get 403 Forbidden when trying to access these.
#
# URL Convention: /admin/* prefix makes it clear these are admin routes
# ================================================================================


@app.route('/admin/users', methods=['GET'])
@token_required  # First: Is user logged in?
@admin_required  # Second: Is user an admin?
def get_all_users():
    """
    Get all users in the system. ADMIN ONLY.

    Returns list of all users with their roles.
    Useful for admin dashboard to manage users.
    """
    users = User.query.all()
    return jsonify({
        'message': 'Users retrieved!',
        'users': [user.to_dict() for user in users],
        'total': len(users)
    })


@app.route('/admin/users/<int:user_id>/role', methods=['PUT'])
@token_required
@admin_required
def update_user_role(user_id):
    """
    Change a user's role. ADMIN ONLY.

    Security considerations:
        1. Validate role value (only allow known roles)
        2. Prevent admin from demoting themselves (self-demotion protection)
        3. In production: prevent role escalation (admin can't create super_admin)

    URL parameter: user_id - The ID of the user to update
    Request body: { "role": "admin" } or { "role": "user" }
    """
    data = request.get_json()
    new_role = data.get('role')

    # Validate role - only allow known values
    # This prevents injection of arbitrary roles like "super_admin"
    if new_role not in ['user', 'admin']:
        return jsonify({'message': 'Invalid role! Must be "user" or "admin"'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found!'}), 404

    # ================================================================================
    # SELF-DEMOTION PROTECTION
    # ================================================================================
    # Prevent admins from accidentally (or intentionally) removing their own admin role.
    # Why? If the only admin demotes themselves, no one can manage users anymore!
    #
    # This check: "Is this admin trying to change their OWN role to non-admin?"
    # ================================================================================
    if user.id == g.current_user['user_id'] and new_role != 'admin':
        return jsonify({'message': 'Cannot remove your own admin role!'}), 400

    user.role = new_role
    db.session.commit()

    return jsonify({'message': f'User role updated to {new_role}!', 'user': user.to_dict()})


@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_user(user_id):
    """
    Delete a user. ADMIN ONLY.

    Security considerations:
        1. Prevent admin from deleting themselves (self-deletion protection)
        2. Consider soft-delete instead of hard-delete (mark as inactive)
        3. In production: log who deleted whom (audit trail)
    """
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found!'}), 404

    # ================================================================================
    # SELF-DELETION PROTECTION
    # ================================================================================
    # Prevent admin from deleting their own account.
    # If they want to leave, another admin should delete them.
    # This also prevents accidental "delete all users" bugs from removing the admin.
    # ================================================================================
    if user.id == g.current_user['user_id']:
        return jsonify({'message': 'Cannot delete your own account!'}), 400

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'User deleted successfully!'})


@app.route('/make-admin', methods=['POST'])  # Promote user to admin (FOR TESTING ONLY!)
def make_admin():
    data = request.get_json()  # Get JSON data
    email, secret = data.get('email'), data.get('secret')  # Get email and secret

    if secret != ADMIN_SECRET:  # Check secret key
        return jsonify({'message': 'Invalid secret key!'}), 403

    user = User.query.filter_by(email=email).first()  # Find user
    if not user:  # User not found
        return jsonify({'message': 'User not found!'}), 404

    user.role = 'admin'  # Make admin
    db.session.commit()  # Save changes

    return jsonify({'message': f'{email} is now an admin!', 'user': user.to_dict()})


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    print("=" * 50)
    print("Role-Based Access Control Server Running on http://localhost:5009")
    print("=" * 50)
    app.run(debug=True, port=5009)


# ===========================================
# EXERCISES - Try These!
# ===========================================
"""
EXERCISE 1: Test Admin vs User Access
-------------------------------------
Test:
1. Register two users: user1@test.com and user2@test.com
2. Make user1 an admin using /make-admin
3. Login as user1, try GET /admin/users (should work)
4. Login as user2, try GET /admin/users (should fail with 403)

Question: What's the difference between status codes 401 and 403?
(Hint: 401 = not logged in, 403 = logged in but no permission)


EXERCISE 2: Add a Moderator Role
--------------------------------
Add a third role 'moderator' with limited admin access:

1. Update the role validation:
    if new_role not in ['user', 'moderator', 'admin']:
        return jsonify({'message': 'Invalid role!'}), 400

2. Create a new decorator:
    def moderator_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if g.current_user.get('role') not in ['moderator', 'admin']:
                return jsonify({'message': 'Moderator access required!'}), 403
            return f(*args, **kwargs)
        return decorated

3. Create a moderator-only route:
    @app.route('/moderator/reports', methods=['GET'])
    @token_required
    @moderator_required
    def get_reports():
        return jsonify({'reports': ['Report 1', 'Report 2']})

Test: Can moderator access admin routes? Can admin access moderator routes?
Question: How would you design permissions for: user < moderator < admin?


EXERCISE 3: View Your Own Role
------------------------------
Add a route that shows current user's permissions:

@app.route('/my-permissions', methods=['GET'])
@token_required
def my_permissions():
    role = g.current_user['role']
    permissions = {
        'user': ['view_profile', 'edit_profile'],
        'moderator': ['view_profile', 'edit_profile', 'view_reports', 'delete_comments'],
        'admin': ['view_profile', 'edit_profile', 'view_reports', 'delete_comments', 'manage_users', 'delete_users']
    }
    return jsonify({
        'role': role,
        'permissions': permissions.get(role, [])
    })

Question: Why might you want to show permissions to the user?


EXERCISE 4: Prevent Role Escalation
-----------------------------------
Currently, an admin can make another user an admin. Add protection:

1. Only "super_admin" can create new admins
2. Admins can only create moderators and users

Modify update_user_role():
    if new_role == 'admin' and g.current_user.get('role') != 'super_admin':
        return jsonify({'message': 'Only super admin can create admins!'}), 403

Question: Why is preventing role escalation important for security?


EXERCISE 5: Log Admin Actions
-----------------------------
Track what admins do for audit trail:

1. Create a new model:
    class AdminLog(db.Model):
        __tablename__ = 'admin_logs'
        id = db.Column(db.Integer, primary_key=True)
        admin_id = db.Column(db.Integer, nullable=False)
        action = db.Column(db.String(100), nullable=False)
        target_user_id = db.Column(db.Integer, nullable=True)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)

2. In update_user_role(), before return:
    log = AdminLog(admin_id=g.current_user['user_id'], action=f'changed_role_to_{new_role}', target_user_id=user_id)
    db.session.add(log)

Question: Why is admin action logging important? What actions should be logged?


SELF-STUDY QUESTIONS
--------------------
1. What's the difference between authentication and authorization?
   (Hint: Who are you vs What can you do)

2. Why include role in the JWT token instead of checking database each time?

3. Why can't a user register as admin directly?

4. What is RBAC (Role-Based Access Control)?

5. What is the principle of "least privilege"?
"""
