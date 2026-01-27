from flask import Flask, jsonify, request, g, send_file  # Flask framework
from flask_cors import CORS  # Cross-origin requests
from flask_sqlalchemy import SQLAlchemy  # Database ORM
import bcrypt  # Password hashing
import jwt  # JWT tokens
from datetime import datetime, timedelta  # Date/time
from functools import wraps  # Decorator helper
import os  # For file paths

app = Flask(__name__)  # Create Flask app
CORS(app)  # Enable CORS


@app.route('/')  # Serve the frontend HTML
def index():
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    return send_file(html_path)


@app.route('/index.html')  # Also serve index.html for direct links
def index_html():
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    return send_file(html_path)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable tracking
SECRET_KEY = 'your-secret-key-keep-it-safe'  # JWT secret
ADMIN_SECRET = 'admin-secret-key'  # Secret for making admin (testing only)

db = SQLAlchemy(app)  # Database instance


class User(db.Model):  # User model with role
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)  # Primary key
    email = db.Column(db.String(120), unique=True, nullable=False)  # Unique email
    password = db.Column(db.String(255), nullable=False)  # Hashed password
    role = db.Column(db.String(20), default='user', nullable=False)  # NEW: Role column ('user' or 'admin')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Created time

    def to_dict(self):  # Convert user to dictionary for JSON response
        return {'id': self.id, 'email': self.email, 'role': self.role, 'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')}


def hash_password(password):  # Hash password
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def check_password(password, hashed_password):  # Verify password
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


def create_token(user):  # Create JWT with role included
    payload = {'user_id': user.id, 'email': user.email, 'role': user.role, 'exp': datetime.utcnow() + timedelta(hours=24)}  # Role is in payload
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


def token_required(f):  # Decorator to require valid JWT
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')  # Get auth header

        if not auth_header:  # No header
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            parts = auth_header.split(' ')  # Split "Bearer <token>"
            if len(parts) != 2 or parts[0] != 'Bearer':  # Invalid format
                return jsonify({'message': 'Invalid token format!'}), 401

            token = parts[1]  # Get token
            decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])  # Decode token

            g.current_user = {'user_id': decoded['user_id'], 'email': decoded['email'], 'role': decoded.get('role', 'user')}  # Store user info including role

        except jwt.ExpiredSignatureError:  # Token expired
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:  # Invalid token
            return jsonify({'message': 'Invalid token!'}), 401

        return f(*args, **kwargs)  # Call protected function
    return decorated


def admin_required(f):  # Decorator to require admin role - MUST use AFTER @token_required
    @wraps(f)
    def decorated(*args, **kwargs):
        if g.current_user.get('role') != 'admin':  # Check if user has admin role
            return jsonify({'message': 'Admin access required!', 'error': 'FORBIDDEN'}), 403  # 403 = Forbidden (logged in but no permission)

        return f(*args, **kwargs)  # Call admin function
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


@app.route('/admin/users', methods=['GET'])  # Get all users (ADMIN ONLY)
@token_required  # First check: valid token
@admin_required  # Second check: admin role
def get_all_users():
    users = User.query.all()  # Get all users from database
    return jsonify({'message': 'Users retrieved!', 'users': [user.to_dict() for user in users], 'total': len(users)})


@app.route('/admin/users/<int:user_id>/role', methods=['PUT'])  # Change user role (ADMIN ONLY)
@token_required
@admin_required
def update_user_role(user_id):
    data = request.get_json()  # Get JSON data
    new_role = data.get('role')  # Get new role

    if new_role not in ['user', 'admin']:  # Validate role value
        return jsonify({'message': 'Invalid role! Must be "user" or "admin"'}), 400

    user = User.query.get(user_id)  # Find user by ID
    if not user:  # User not found
        return jsonify({'message': 'User not found!'}), 404

    if user.id == g.current_user['user_id'] and new_role != 'admin':  # Prevent self-demotion
        return jsonify({'message': 'Cannot remove your own admin role!'}), 400

    user.role = new_role  # Update role
    db.session.commit()  # Save changes

    return jsonify({'message': f'User role updated to {new_role}!', 'user': user.to_dict()})


@app.route('/admin/users/<int:user_id>', methods=['DELETE'])  # Delete user (ADMIN ONLY)
@token_required
@admin_required
def delete_user(user_id):
    user = User.query.get(user_id)  # Find user
    if not user:  # User not found
        return jsonify({'message': 'User not found!'}), 404

    if user.id == g.current_user['user_id']:  # Prevent self-deletion
        return jsonify({'message': 'Cannot delete your own account!'}), 400

    db.session.delete(user)  # Delete user
    db.session.commit()  # Save changes

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
