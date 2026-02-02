from flask import Flask, jsonify, request, send_file  # Flask framework
from flask_cors import CORS  # CORS for cross-origin requests
import jwt  # This is from 'pyjwt' package (pip install pyjwt), NOT the 'jwt' package
from datetime import datetime, timedelta, timezone  # For expiration time
import os  # For file path

app = Flask(__name__)  # Create app
CORS(app)  # Enable CORS for all routes

# SECRET_KEY: Used to sign and verify tokens. Keep this secret!
# If someone knows this key, they can create fake tokens.
SECRET_KEY = "my-super-secret-key-123"


@app.route('/')  # Serve the frontend HTML
def index():
    # os.path.join: Builds the path to index.html (goes up one folder with '..', then into 'frontend')
    # send_file: Sends the file as-is (raw HTML) directly to the browser
    #
    # Difference from render_template:
    # - send_file: Sends ANY file (HTML, images, PDFs) exactly as it is, no processing
    # - render_template: Only for HTML in 'templates/' folder, processes Jinja2 syntax ({{ variable }}, {% for %}, etc.)
    #
    # We use send_file here because our HTML is in 'frontend/' folder (not 'templates/')
    # and we don't need Jinja2 template processing
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

    # Token: A JWT (JSON Web Token) is a compact, URL-safe string that contains encoded JSON data.
    # It has 3 parts separated by dots: header.payload.signature
    # - Header: algorithm info (e.g., HS256)
    # - Payload: your data (user_id, name, exp, etc.) - Base64 encoded, NOT encrypted (anyone can read it!)
    # - Signature: ensures the token hasn't been tampered with (created using SECRET_KEY)
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')  # Create token
    return jsonify({'message': 'Token created!', 'token': token})


@app.route('/decode-token', methods=['POST'])  # Decode a token
def decode_token():
    data = request.get_json()  # Get data
    token = data.get('token')  # Get token

    # Try printing the raw token to see its structure
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])  # Decode
        # Also try printing the decorded token 
        
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
    print("  Open in browser: http://127.0.0.1:5000")
    print("")
    print("=" * 50)
    app.run(debug=True, host='127.0.0.1', port=5000)


# ===========================================
# EXERCISES
# ===========================================
"""
EXERCISE 1: Change Expiration Time
----------------------------------
Change 'exp' in '/create-token route (line 45):
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
