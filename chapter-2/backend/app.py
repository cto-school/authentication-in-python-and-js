# ================================================================================
# CHAPTER 2: User Registration
# ================================================================================
#
# This chapter covers:
#   1. Creating a User database model with SQLAlchemy
#   2. Hashing passwords with werkzeug.security
#   3. Building a /register endpoint
#
# KEY CONCEPT: Never store plain passwords!
#   BAD:  password = "secret123"
#   GOOD: password = "pbkdf2:sha256:600000$salt$hash..."
#
# ================================================================================

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
# ================================================================================
# werkzeug.security - Password Hashing Library
# ================================================================================
# This comes built-in with Flask (no extra installation needed).
#
# Two main functions:
#   generate_password_hash(password) → Returns hashed string
#   check_password_hash(hash, password) → Returns True/False
#
# Why werkzeug.security?
#   - Uses PBKDF2-SHA256 (industry standard)
#   - Automatically adds "salt" (random data) to each hash
#   - Slow on purpose (prevents brute-force attacks)
# ================================================================================
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import warnings
warnings.filterwarnings('ignore', message='.*Query.get.*')

app = Flask(__name__)
CORS(app)

# ================================================================================
# DATABASE CONFIGURATION
# ================================================================================
# SQLite stores data in a file (users.db) - no database server needed!
# Perfect for learning. In production, you'd use PostgreSQL or MySQL.
# ================================================================================
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_ch2.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Suppress warning

db = SQLAlchemy(app)


# ================================================================================
# USER MODEL
# ================================================================================
# This class defines the structure of the 'users' table in our database.
#
# SQLAlchemy ORM (Object-Relational Mapping):
#   - Each class = a database table
#   - Each attribute = a column
#   - Each instance = a row
#
# Columns:
#   id         - Auto-incrementing primary key
#   email      - Must be unique (no duplicate accounts)
#   password   - Stores the HASH, not the actual password!
#   created_at - Automatically set when user is created
# ================================================================================


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Stores HASH!
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        """Convert user to dictionary for JSON response."""
        return {
            'id': self.id,
            'email': self.email,
            # NOTE: We NEVER include password in response!
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }


# ================================================================================
# PASSWORD HASHING HELPER
# ================================================================================
# Wrapping the function makes our code cleaner and easier to test.
# ================================================================================


def hash_password(password):
    """
    Convert plain password to secure hash.

    Example:
        hash_password("secret123")
        → "pbkdf2:sha256:600000$abc123$def456..."

    The hash includes:
        - Algorithm (pbkdf2:sha256)
        - Iterations (600000) - how many times to hash
        - Salt (random string) - makes each hash unique
        - Final hash value
    """
    return generate_password_hash(password)


# ================================================================================
# ROUTES
# ================================================================================


@app.route('/')
def index():
    """Serve the frontend HTML file."""
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    return send_file(html_path)


@app.route('/register', methods=['POST'])
def register():
    """
    Register a new user.

    Expected JSON body:
        {
            "email": "user@example.com",
            "password": "secret123"
        }

    Process:
        1. Get email and password from request
        2. Validate input (both required)
        3. Check if email already exists
        4. Hash the password
        5. Create user in database
        6. Return success response

    Returns:
        201: User created successfully
        400: Validation error or email exists
    """
    # Get JSON data from request body
    data = request.get_json()

    # Extract email and password
    email = data.get('email')
    password = data.get('password')

    # ================================================================================
    # VALIDATION
    # ================================================================================
    # Always validate input! Never trust data from the client.
    # ================================================================================

    if not email or not password:
        return jsonify({'message': 'Email and password are required!'}), 400

    # Check if email already exists
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'message': 'Email already exists!'}), 400

    # ================================================================================
    # CREATE USER
    # ================================================================================
    # 1. Hash the password (NEVER store plain text!)
    # 2. Create User object
    # 3. Add to database session
    # 4. Commit (save) to database
    # ================================================================================

    hashed_password = hash_password(password)

    new_user = User(
        email=email,
        password=hashed_password  # Store the HASH, not the password!
    )

    db.session.add(new_user)
    db.session.commit()

    # Return success (201 = Created)
    return jsonify({
        'message': 'User registered successfully!',
        'user': new_user.to_dict()
    }), 201


@app.route('/users', methods=['GET'])
def get_users():
    """
    Get all users (for testing/debugging).

    In production, this would be an admin-only route!
    """
    users = User.query.all()
    return jsonify({
        'users': [user.to_dict() for user in users],
        'total': len(users)
    })


# ================================================================================
# DATABASE INITIALIZATION
# ================================================================================
# Create all tables when the app starts.
# In production, you'd use migrations (Flask-Migrate).
# ================================================================================

with app.app_context():
    db.create_all()


# ================================================================================
# KEY TAKEAWAYS - Chapter 2
# ================================================================================
#
# 1. NEVER STORE PLAIN PASSWORDS!
#    Always use generate_password_hash() to hash passwords before storing.
#
# 2. TRY THIS - Check the database:
#    - Register a user with password "secret123"
#    - Open the users.db file with a SQLite viewer (or use DB Browser for SQLite)
#    - Look at the 'password' column
#    - You'll see something like: "pbkdf2:sha256:600000$xyz$abc123..."
#    - This is the HASH, not "secret123"!
#
# 3. Why hashing matters:
#    - If database is stolen, attacker only gets hashes
#    - Hashes are one-way (can't reverse to get password)
#    - Even same password creates different hashes (due to salt)
#
# 4. The User.to_dict() method NEVER includes the password field.
#    We never send password data to the frontend, not even the hash.
#
# 5. SQLAlchemy ORM pattern:
#    - Create object: user = User(email=email, password=hashed)
#    - Add to session: db.session.add(user)
#    - Save to database: db.session.commit()
#
# NEXT CHAPTER: We'll add login and create JWT tokens for authenticated users.
#
# ================================================================================


# ================================================================================
# EXERCISES - Test Your Understanding!
# ================================================================================
#
# Complete these exercises in this file, then test them.
#
# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 1: Add Username Field (Easy)
# ────────────────────────────────────────────────────────────────────────────────
# Modify the User model to add a 'username' field:
# - String, max 50 characters, unique, required
# - Update /register to accept and store username
# - Update to_dict() to include username
#
# Test: Register with {"email": "a@b.com", "password": "123", "username": "john"}
#       Then GET /users and verify username appears
#
# HINT: Add to User class: username = db.Column(db.String(50), unique=True, nullable=False)
# NOTE: Delete users.db file and restart server after changing the model!
# ────────────────────────────────────────────────────────────────────────────────


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 2: Check Email Availability Endpoint (Easy)
# ────────────────────────────────────────────────────────────────────────────────
# Create an endpoint POST /check-email that:
# - Accepts JSON body with 'email' field
# - Returns whether the email is available for registration
#
# Test: curl -X POST http://localhost:5002/check-email \
#       -H "Content-Type: application/json" \
#       -d '{"email": "test@example.com"}'
#
# Expected (available): {"available": true, "message": "Email is available"}
# Expected (taken): {"available": false, "message": "Email already registered"}
#
# HINT: Use User.query.filter_by(email=email).first()
# ────────────────────────────────────────────────────────────────────────────────

# YOUR CODE HERE:
# @app.route('/check-email', methods=['POST'])
# def check_email():
#     pass


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 3: Delete User Endpoint (Medium)
# ────────────────────────────────────────────────────────────────────────────────
# Create an endpoint DELETE /users/<int:user_id> that:
# - Deletes the user with the given ID
# - Returns 404 if user doesn't exist
# - Returns success message if deleted
#
# Test: First register a user and note the ID
#       curl -X DELETE http://localhost:5002/users/1
#
# Expected success: {"message": "User deleted", "deleted_id": 1}
# Expected not found: {"message": "User not found"}, 404
#
# HINT: user = User.query.get(user_id)
#       db.session.delete(user)
#       db.session.commit()
# ────────────────────────────────────────────────────────────────────────────────

# YOUR CODE HERE:
# @app.route('/users/<int:user_id>', methods=['DELETE'])
# def delete_user(user_id):
#     pass


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 4: Verify Password Hash (Medium)
# ────────────────────────────────────────────────────────────────────────────────
# Create an endpoint POST /verify-hash that:
# - Accepts JSON body with 'email' and 'password' fields
# - Finds the user and checks if password matches the stored hash
# - Returns whether the password is correct (WITHOUT logging them in)
#
# This is for learning purposes - shows how check_password_hash works!
#
# Test: Register a user, then:
#       curl -X POST http://localhost:5002/verify-hash \
#       -H "Content-Type: application/json" \
#       -d '{"email": "test@example.com", "password": "correct_password"}'
#
# Expected match: {"matches": true}
# Expected no match: {"matches": false}
#
# HINT: Use check_password_hash(user.password, password)
# ────────────────────────────────────────────────────────────────────────────────

# YOUR CODE HERE:
# @app.route('/verify-hash', methods=['POST'])
# def verify_hash():
#     pass


# ================================================================================


if __name__ == '__main__':
    print("=" * 60)
    print("CHAPTER 2: User Registration")
    print("=" * 60)
    print("Server running at: http://localhost:5002")
    print("")
    print("Endpoints:")
    print("  GET  /         - Frontend page")
    print("  POST /register - Register new user")
    print("  GET  /users    - List all users (debug)")
    print("=" * 60)
    app.run(debug=True, port=5002)
