from flask import Flask, jsonify, request, send_file  # Flask web framework
from flask_cors import CORS  # Allow cross-origin requests
from flask_sqlalchemy import SQLAlchemy  # Database ORM
import bcrypt  # Password hashing
import jwt  # JWT tokens
from datetime import datetime, timedelta  # For timestamps and token expiration
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


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Database file
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable tracking

SECRET_KEY = 'your-secret-key-keep-it-safe'  # JWT secret key - keep private!

db = SQLAlchemy(app)  # Database instance


class User(db.Model):  # User model
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)  # Auto-increment ID
    email = db.Column(db.String(120), unique=True, nullable=False)  # Unique email
    password = db.Column(db.String(255), nullable=False)  # Hashed password
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Registration time


def hash_password(password):  # Hash plain password
    password_bytes = password.encode('utf-8')  # Convert to bytes
    salt = bcrypt.gensalt()  # Generate salt
    hashed = bcrypt.hashpw(password_bytes, salt)  # Hash with salt
    return hashed.decode('utf-8')  # Return as string


def check_password(password, hashed_password):  # Verify password against hash
    password_bytes = password.encode('utf-8')  # Convert entered password to bytes
    hashed_bytes = hashed_password.encode('utf-8')  # Convert stored hash to bytes
    return bcrypt.checkpw(password_bytes, hashed_bytes)  # Returns True if match, False if not


def create_token(user):  # Create JWT token for user
    payload = {  # Data to store in token
        'user_id': user.id,  # User's ID
        'email': user.email,  # User's email
        'exp': datetime.utcnow() + timedelta(hours=24)  # Expires in 24 hours
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')  # Create token
    return token  # Return token string


@app.route('/register', methods=['POST'])  # Registration endpoint
def register():
    data = request.get_json()  # Get request data
    email = data.get('email')  # Get email
    password = data.get('password')  # Get password

    if not email or not password:  # Validate both fields exist
        return jsonify({'message': 'Email and password are required!'}), 400

    if User.query.filter_by(email=email).first():  # Check email not taken
        return jsonify({'message': 'Email already exists!'}), 400

    new_user = User(email=email, password=hash_password(password))  # Create user with hashed password
    db.session.add(new_user)  # Add to session
    db.session.commit()  # Save to database

    return jsonify({
        'message': 'User registered successfully!',
        'user': {'id': new_user.id, 'email': new_user.email}
    }), 201


@app.route('/login', methods=['POST'])  # Login endpoint
def login():
    data = request.get_json()  # Get request data
    email = data.get('email')  # Get email
    password = data.get('password')  # Get password

    if not email or not password:  # Validate both fields
        return jsonify({'message': 'Email and password are required!'}), 400

    user = User.query.filter_by(email=email).first()  # Find user by email

    if not user:  # User not found
        return jsonify({'message': 'Invalid email or password!'}), 401  # Don't reveal which is wrong

    if not check_password(password, user.password):  # Password doesn't match
        return jsonify({'message': 'Invalid email or password!'}), 401  # Same message for security

    token = create_token(user)  # Create JWT token for this user

    return jsonify({  # Return success with token
        'message': 'Login successful!',
        'token': token,  # Frontend will store this
        'user': {'id': user.id, 'email': user.email}
    })


@app.route('/users', methods=['GET'])  # List users (testing only)
def get_users():
    users = User.query.all()  # Get all users
    users_list = [{'id': u.id, 'email': u.email, 'created_at': u.created_at.strftime('%Y-%m-%d %H:%M:%S')} for u in users]
    return jsonify({'users': users_list, 'total': len(users_list)})


with app.app_context():  # Create tables
    db.create_all()


if __name__ == '__main__':
    print("=" * 50)
    print("Login Server Running on http://localhost:5003")
    print("=" * 50)
    app.run(debug=True, port=5003)


# ===========================================
# EXERCISES - Try These!
# ===========================================
"""
EXERCISE 1: Change Token Expiration Time
----------------------------------------
Current code (line 43):
    'exp': datetime.utcnow() + timedelta(hours=24)

Try changing to:
    'exp': datetime.utcnow() + timedelta(minutes=1)

Test:
1. Login and get token
2. Wait 1 minute
3. Try to decode the token (you can add decode route from Part 1)

Question: What happens to expired tokens? Why is expiration important?


EXERCISE 2: See How check_password Works
----------------------------------------
Add this test route:

@app.route('/test-password', methods=['POST'])
def test_password():
    data = request.get_json()
    password = data.get('password')
    wrong_password = data.get('wrong_password')

    hashed = hash_password(password)

    return jsonify({
        'original_password': password,
        'hashed': hashed,
        'correct_check': check_password(password, hashed),
        'wrong_check': check_password(wrong_password, hashed)
    })

Test with: {"password": "secret123", "wrong_password": "wrong"}
Question: How does bcrypt.checkpw() know the salt?
(Hint: The salt is stored as part of the hash)


EXERCISE 3: Add "Remember Me" Feature
-------------------------------------
Modify login to accept 'remember_me' parameter:

In login():
    remember_me = data.get('remember_me', False)

    if remember_me:
        expiration = timedelta(days=30)  # Long expiration
    else:
        expiration = timedelta(hours=1)  # Short expiration

Update token creation to use this expiration.

Question: Why would users want different token lifetimes?


EXERCISE 4: Add Login Attempt Logging
-------------------------------------
Add print statements to see login attempts:

    print(f"Login attempt for: {email}")  # After getting email

    if not user:
        print(f"Failed: User not found - {email}")

    if not check_password(...):
        print(f"Failed: Wrong password - {email}")

    print(f"Success: {email} logged in")  # Before return

Test: Try login with wrong email, wrong password, correct credentials
Question: Why is logging login attempts important for security?


SELF-STUDY QUESTIONS
--------------------
1. Why do we use the same error message "Invalid email or password"
   for both wrong email and wrong password?

2. What information is stored in the JWT token after login?

3. Where should the frontend store the token? (localStorage, sessionStorage, cookie?)

4. What is the difference between 401 (Unauthorized) and 403 (Forbidden)?

5. Why do we hash passwords before storing, but use checkpw() to verify?
"""
