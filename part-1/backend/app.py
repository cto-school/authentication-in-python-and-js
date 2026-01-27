from flask import Flask, jsonify, request, send_file  # Flask framework
from flask_cors import CORS  # CORS for cross-origin requests
import jwt  # JWT library
from datetime import datetime, timedelta, timezone  # For expiration time
import os  # For file path

app = Flask(__name__)  # Create app
CORS(app)  # Enable CORS for all routes

SECRET_KEY = "my-super-secret-key-123"  # Secret key for JWT


@app.route('/')  # Serve the frontend HTML
def index():
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    return send_file(html_path)


@app.route('/index.html')  # Also serve index.html for direct links
def index_html():
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    return send_file(html_path)


@app.route('/create-token', methods=['POST'])  # Create a new token
def create_token():
    data = request.get_json()  # Get data from request
    user_id = data.get('user_id')  # Get user_id
    name = data.get('name')  # Get name

    payload = {
        'user_id': user_id,
        'name': name,
        'exp': datetime.now(timezone.utc) + timedelta(minutes=30)  # Expires in 30 minutes
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')  # Create token
    return jsonify({'message': 'Token created!', 'token': token})


@app.route('/decode-token', methods=['POST'])  # Decode a token
def decode_token():
    data = request.get_json()  # Get data
    token = data.get('token')  # Get token

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])  # Decode
        return jsonify({'message': 'Decoded!', 'data': decoded})
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token expired!'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token!'}), 401


@app.route('/verify-token', methods=['POST'])  # Verify if token is valid
def verify_token():
    data = request.get_json()  # Get data
    token = data.get('token')  # Get token

    try:
        jwt.decode(token, SECRET_KEY, algorithms=['HS256'])  # Try to decode
        return jsonify({'message': 'Valid!', 'valid': True})
    except:
        return jsonify({'message': 'Invalid!', 'valid': False}), 401


if __name__ == '__main__':
    print("")
    print("=" * 50)
    print("  JWT Server Running!")
    print("=" * 50)
    print("")
    print("  Open in browser: http://127.0.0.1:5001")
    print("")
    print("=" * 50)
    app.run(debug=True, host='127.0.0.1', port=5001)


# ===========================================
# EXERCISES
# ===========================================
"""
EXERCISE 1: Change Expiration Time
----------------------------------
Change line 24 to:
    'exp': datetime.utcnow() + timedelta(seconds=10)

Test: Create token, wait 10 seconds, decode it.
Question: What happens?


EXERCISE 2: Add More Data
-------------------------
Add to payload:
    'role': 'admin',
    'email': 'test@test.com'

Test: Create and decode. See new fields?


EXERCISE 3: Change Secret Key
-----------------------------
1. Create a token
2. Stop server, change SECRET_KEY to "new-secret"
3. Start server, try to decode old token

Question: What happens? Why?


SELF-STUDY QUESTIONS
--------------------
1. What are 3 parts of JWT? (hint: separated by dots)
2. Can anyone read JWT data? (hint: try jwt.io)
3. Why is SECRET_KEY important?
"""
