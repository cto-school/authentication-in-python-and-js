from flask import Flask, jsonify, request, send_file  # Flask web framework
from flask_cors import CORS  # Allow cross-origin requests
from flask_sqlalchemy import SQLAlchemy  # Database ORM
# Password hashing using werkzeug.security (comes built-in with Flask)
# Why werkzeug instead of bcrypt?
# - No extra installation needed (already part of Flask)
# - Simpler API (no manual encoding/decoding of strings)
# - Uses secure algorithms (pbkdf2:sha256 by default)
from werkzeug.security import generate_password_hash
from datetime import datetime  # For timestamps
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


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # SQLite database file path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable modification tracking (saves memory)

db = SQLAlchemy(app)  # Create database instance


class User(db.Model):  # User model - represents 'users' table in database
    __tablename__ = 'users'  # Table name in database

    id = db.Column(db.Integer, primary_key=True)  # Primary key, auto-increments
    email = db.Column(db.String(120), unique=True, nullable=False)  # Email must be unique, cannot be null
    password = db.Column(db.String(255), nullable=False)  # Stores HASHED password, not plain text
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Auto-set to current time


# ============================================
# PASSWORD HASHING - Why do we hash passwords?
# ============================================
# 1. NEVER store plain text passwords in database
# 2. If database is hacked, attackers can't see real passwords
# 3. Hashing is ONE-WAY: you can't reverse a hash to get the password
# 4. Even if two users have same password, their hashes are different (due to salt)
#
# How generate_password_hash() works:
# - Adds a random "salt" to make each hash unique
# - Uses PBKDF2-SHA256 algorithm (secure and slow on purpose - prevents brute force)
# - Returns a string like: "pbkdf2:sha256:600000$salt$hash"
# ============================================
def hash_password(password):
    return generate_password_hash(password)


@app.route('/register', methods=['POST'])  # POST endpoint for registration
def register():
    data = request.get_json()  # Get JSON data from request
    email = data.get('email')  # Extract email
    password = data.get('password')  # Extract password

    if not email:  # Validate email exists
        return jsonify({'message': 'Email is required!'}), 400  # 400 = Bad Request

    if not password:  # Validate password exists
        return jsonify({'message': 'Password is required!'}), 400

    existing_user = User.query.filter_by(email=email).first()  # Check if email already exists in database
    if existing_user:  # If user found, email is taken
        return jsonify({'message': 'Email already exists!'}), 400

    hashed_password = hash_password(password)  # Hash the password - NEVER store plain password!

    new_user = User(email=email, password=hashed_password)  # Create new User object with hashed password
    db.session.add(new_user)  # Add user to database session
    db.session.commit()  # Save changes to database

    return jsonify({  # Return success response
        'message': 'User registered successfully!',
        'user': {'id': new_user.id, 'email': new_user.email}  # Don't return password!
    }), 201  # 201 = Created


@app.route('/users', methods=['GET'])  # GET endpoint to list all users (for testing only)
def get_users():
    users = User.query.all()  # Get all users from database
    users_list = []  # Empty list to store user data
    for user in users:  # Loop through each user
        users_list.append({  # Add user data to list
            'id': user.id,
            'email': user.email,
            'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S')  # Format datetime as string
        })  # Note: We NEVER include password in response

    return jsonify({'users': users_list, 'total': len(users_list)})  # Return users list


with app.app_context():  # Application context needed for database operations
    db.create_all()  # Create all tables defined by models


if __name__ == '__main__':
    print("=" * 50)
    print("Registration Server Running on http://localhost:5002")
    print("=" * 50)
    app.run(debug=True, port=5002)


# ===========================================
# EXERCISES - Try These!
# ===========================================
"""
EXERCISE 1: Add Password Length Validation
------------------------------------------
Current code accepts any password length.

Add this check after "if not password:" (around line 38):

    if len(password) < 6:
        return jsonify({'message': 'Password must be at least 6 characters!'}), 400

Test: Try registering with password "123" - what happens?
Question: Why is minimum password length important?


EXERCISE 2: Add a 'name' Field to User
--------------------------------------
Step 1: Add to User model (after email line):
    name = db.Column(db.String(100), nullable=True)

Step 2: In register(), get name from data:
    name = data.get('name')

Step 3: Add name when creating user:
    new_user = User(email=email, password=hashed_password, name=name)

Step 4: Delete users.db file and restart server (to recreate table)

Test: Register with name, then check /users endpoint
Question: What's the difference between nullable=True and nullable=False?


EXERCISE 3: See How Hashing Works
---------------------------------
Add this temporary route to see hashing in action:

@app.route('/test-hash', methods=['POST'])
def test_hash():
    data = request.get_json()
    password = data.get('password')

    hash1 = hash_password(password)
    hash2 = hash_password(password)

    return jsonify({
        'password': password,
        'hash1': hash1,
        'hash2': hash2,
        'are_same': hash1 == hash2
    })

Test: Send same password twice. Are the hashes the same?
Question: Why are two hashes of the same password different?
(Hint: werkzeug adds a random "salt" to each hash - look at the hash string,
you'll see it contains the salt embedded in it: "pbkdf2:sha256:iterations$salt$hash")


SELF-STUDY QUESTIONS
--------------------
1. What is "salt" in password hashing? Why is it important?

2. If a hacker gets your database, can they see user passwords?

3. Why do we use werkzeug/PBKDF2 instead of simple hashing like MD5?
   (Hint: MD5 is fast - that's bad for passwords! PBKDF2 is intentionally slow)

4. What does db.session.commit() do? What happens if you forget it?

5. Why do we return status code 201 for successful registration?
"""
