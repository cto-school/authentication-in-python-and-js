# ================================================================================
# CHAPTER 2: SOLUTIONS - User Registration
# ================================================================================
# This file contains solutions to all exercises from Chapter 2.
# Compare your solutions with these after attempting them yourself!
# ================================================================================

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import warnings
warnings.filterwarnings('ignore', message='.*Query.get.*')

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_ch2_solutions.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# ================================================================================
# EXERCISE 1 SOLUTION: Add Username Field
# ================================================================================
# We added 'username' field to the User model.
# Note: Delete users_solutions.db if you change the model structure!
# ================================================================================

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)  # EXERCISE 1: Added username
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'username': self.username,  # EXERCISE 1: Include username
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }


def hash_password(password):
    return generate_password_hash(password)


@app.route('/')
def index():
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    return send_file(html_path)


# Modified register to accept username (Exercise 1)
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    email = data.get('email')
    password = data.get('password')
    username = data.get('username')  # EXERCISE 1: Get username

    # Validate all required fields
    if not email or not password:
        return jsonify({'message': 'Email and password are required!'}), 400

    if not username:
        return jsonify({'message': 'Username is required!'}), 400

    # Check if email already exists
    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already exists!'}), 400

    # EXERCISE 1: Check if username already exists
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already taken!'}), 400

    # Validate username format (letters, numbers, underscores only)
    import re
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return jsonify({'message': 'Username can only contain letters, numbers, and underscores'}), 400

    if len(username) < 3 or len(username) > 50:
        return jsonify({'message': 'Username must be 3-50 characters'}), 400

    new_user = User(
        email=email,
        username=username,
        password=hash_password(password)
    )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({
        'message': 'User registered successfully!',
        'user': new_user.to_dict()
    }), 201


@app.route('/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify({
        'users': [user.to_dict() for user in users],
        'total': len(users)
    })


# ================================================================================
# EXERCISE 2 SOLUTION: Check Email Availability Endpoint
# ================================================================================
# This endpoint checks if an email is available for registration.
# Useful for real-time validation in registration forms.
# ================================================================================

@app.route('/check-email', methods=['POST'])
def check_email():
    data = request.get_json()

    if not data or 'email' not in data:
        return jsonify({
            'error': 'Email is required',
            'available': False
        }), 400

    email = data['email'].strip().lower()

    # Validate email format
    import re
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return jsonify({
            'available': False,
            'message': 'Invalid email format'
        }), 400

    # Check if email exists in database
    existing_user = User.query.filter_by(email=email).first()

    if existing_user:
        return jsonify({
            'available': False,
            'message': 'Email already registered'
        })
    else:
        return jsonify({
            'available': True,
            'message': 'Email is available'
        })


# ================================================================================
# EXERCISE 2B SOLUTION: Check Username Availability
# ================================================================================
# Bonus: Also check username availability
# ================================================================================

@app.route('/check-username', methods=['POST'])
def check_username():
    data = request.get_json()

    if not data or 'username' not in data:
        return jsonify({
            'error': 'Username is required',
            'available': False
        }), 400

    username = data['username'].strip()

    if len(username) < 3:
        return jsonify({
            'available': False,
            'message': 'Username must be at least 3 characters'
        })

    existing_user = User.query.filter_by(username=username).first()

    if existing_user:
        return jsonify({
            'available': False,
            'message': 'Username already taken'
        })
    else:
        return jsonify({
            'available': True,
            'message': 'Username is available'
        })


# ================================================================================
# EXERCISE 3 SOLUTION: Delete User Endpoint
# ================================================================================
# This endpoint deletes a user by ID.
# In production, this would require admin authentication!
# ================================================================================

@app.route('/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    # Find the user by ID
    user = User.query.get(user_id)

    # Check if user exists
    if not user:
        return jsonify({
            'success': False,
            'message': 'User not found'
        }), 404

    # Store info before deleting (for response)
    deleted_email = user.email
    deleted_username = user.username

    # Delete the user
    db.session.delete(user)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'User deleted successfully',
        'deleted_id': user_id,
        'deleted_email': deleted_email,
        'deleted_username': deleted_username
    })


# ================================================================================
# EXERCISE 4 SOLUTION: Verify Password Hash
# ================================================================================
# This endpoint demonstrates how check_password_hash works.
# Educational purpose only - don't expose this in production!
# ================================================================================

@app.route('/verify-hash', methods=['POST'])
def verify_hash():
    data = request.get_json()

    if not data:
        return jsonify({'error': 'Request body required'}), 400

    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    # Find user by email
    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({
            'matches': False,
            'reason': 'User not found'
        }), 404

    # Use check_password_hash to verify
    # This extracts the salt from the stored hash and re-hashes the input
    password_matches = check_password_hash(user.password, password)

    return jsonify({
        'matches': password_matches,
        'email': email,
        # For educational purposes, show partial hash (NEVER do this in production!)
        'stored_hash_preview': user.password[:30] + '...'
    })


# ================================================================================
# BONUS: Show how hashing works
# ================================================================================

@app.route('/demo-hash', methods=['POST'])
def demo_hash():
    """Demonstrate that same password creates different hashes (due to salt)."""
    data = request.get_json()
    password = data.get('password', 'demo123')

    # Generate hash multiple times
    hash1 = generate_password_hash(password)
    hash2 = generate_password_hash(password)
    hash3 = generate_password_hash(password)

    return jsonify({
        'password': password,
        'hash1': hash1,
        'hash2': hash2,
        'hash3': hash3,
        'all_different': hash1 != hash2 != hash3,
        'explanation': 'Each hash is different because of random salt, but check_password_hash will return True for all of them!'
    })


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    print("=" * 60)
    print("CHAPTER 2: SOLUTIONS")
    print("=" * 60)
    print("Server running at: http://localhost:5002")
    print("")
    print("Exercise Solutions:")
    print("  POST /register        - Now requires username (Ex 1)")
    print("  POST /check-email     - Exercise 2")
    print("  POST /check-username  - Exercise 2 Bonus")
    print("  DELETE /users/<id>    - Exercise 3")
    print("  POST /verify-hash     - Exercise 4")
    print("  POST /demo-hash       - Bonus: Hash demonstration")
    print("=" * 60)
    app.run(debug=True, port=5002)
