# ================================================================================
# CHAPTER 1: Introduction & Setup Verification
# ================================================================================
#
# This is a minimal Flask app to verify your setup is working.
# It demonstrates the basic concepts we'll build upon:
#   - Flask app creation
#   - A simple route
#   - JWT token creation (preview)
#
# After this chapter, you'll understand:
#   - How Flask handles HTTP requests
#   - How JWT tokens look and are created
#   - That your development environment is ready
#
# ================================================================================

from flask import Flask, jsonify, send_file
from flask_cors import CORS
# ================================================================================
# pyjwt - The JWT Library
# ================================================================================
# IMPORTANT: The package is installed as 'pyjwt' (pip install pyjwt)
# But you import it as 'jwt'
#
# There's another package called 'jwt' which is DIFFERENT and will cause errors!
# Make sure you have: pip install pyjwt
# ================================================================================
import jwt
from datetime import datetime, timedelta
import os

app = Flask(__name__)
CORS(app)  # Enable Cross-Origin requests (so frontend can call backend)

# ================================================================================
# SECRET KEY
# ================================================================================
# This key is used to SIGN JWT tokens. It's like a password for your server.
#
# IMPORTANT:
#   - Keep this SECRET in production (use environment variables)
#   - If someone knows this key, they can forge tokens!
#   - For learning, a simple string is fine
#
# In production, use something like:
#   SECRET_KEY = os.environ.get('SECRET_KEY')
# ================================================================================
SECRET_KEY = 'your-secret-key-for-learning-123'


@app.route('/')
def index():
    """Serve the frontend HTML file."""
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    return send_file(html_path)


@app.route('/health')
def health_check():
    """
    Health check endpoint - verify the server is running.

    Returns basic info about the server status.
    """
    return jsonify({
        'status': 'healthy',
        'message': 'Chapter 1 server is running!',
        'chapter': 1,
        'topic': 'Introduction & Setup'
    })


@app.route('/demo-token')
def demo_token():
    """
    Demonstration of JWT token creation.

    This shows how a JWT token is created and what it contains.
    In real applications, tokens are created after successful login.

    JWT Structure:
        Header.Payload.Signature

    Payload contains:
        - user_id: Who this token belongs to
        - email: User's email (for display)
        - exp: Expiration time (when token becomes invalid)
    """
    # Create a sample payload (the data stored in the token)
    payload = {
        'user_id': 1,
        'email': 'demo@example.com',
        'exp': datetime.utcnow() + timedelta(hours=1)  # Expires in 1 hour
    }

    # Create the JWT token
    # jwt.encode(payload, secret, algorithm) → returns a token string
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

    # Decode it back to show the payload (for learning)
    # In real apps, you decode tokens sent by clients to verify them
    decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

    return jsonify({
        'message': 'This is a demo JWT token',
        'token': token,
        'decoded_payload': {
            'user_id': decoded['user_id'],
            'email': decoded['email'],
            'expires': datetime.fromtimestamp(decoded['exp']).strftime('%Y-%m-%d %H:%M:%S')
        },
        'explanation': {
            'header': 'Contains algorithm info (HS256)',
            'payload': 'Contains your data (user_id, email, exp)',
            'signature': 'Proves the token was created by this server'
        }
    })


# ================================================================================
# KEY TAKEAWAYS - Chapter 1
# ================================================================================
#
# 1. JWT tokens are created with jwt.encode(payload, secret, algorithm)
#    and decoded with jwt.decode(token, secret, algorithms)
#
# 2. The SECRET_KEY is critical - anyone who has it can forge tokens!
#    In production, use environment variables: os.environ.get('SECRET_KEY')
#
# 3. Tokens contain:
#    - Header: Algorithm info (HS256)
#    - Payload: Your data (user_id, email, exp)
#    - Signature: Proves the token wasn't tampered with
#
# 4. The 'exp' claim (expiration) is special - jwt.decode() automatically
#    checks it and raises ExpiredSignatureError if expired.
#
# 5. FRONTEND: Understanding API responses
#
#    TRY THIS - Inspect the API response:
#    - Open the frontend in browser
#    - Open Developer Tools (F12) → "Network" tab
#    - Click "Create Demo Token" button
#    - Click the "demo-token" request in the Network list
#    - Click "Response" tab to see the JSON data
#    - You'll see: token, decoded_payload, and explanation
#
#    TRY THIS - Decode the token yourself:
#    - Copy the token value from the response
#    - Go to https://jwt.io and paste it
#    - See the Header, Payload, and Signature sections
#    - Try changing a character in the payload → Signature becomes invalid!
#
# NEXT CHAPTER: We'll store users in a database with hashed passwords.
#
# ================================================================================


# ================================================================================
# EXERCISES - Test Your Understanding!
# ================================================================================
#
# Complete these exercises in this file, then test them using the frontend or curl.
#
# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 1: Create a Custom Token Endpoint (Easy)
# ────────────────────────────────────────────────────────────────────────────────
# Create an endpoint POST /create-custom-token that:
# - Accepts JSON body with 'name' and 'role' fields
# - Creates a JWT token with those values plus an 'exp' (1 hour)
# - Returns the token
#
# Test: curl -X POST http://localhost:5001/create-custom-token \
#       -H "Content-Type: application/json" \
#       -d '{"name": "John", "role": "admin"}'
#
# Expected: {"token": "eyJ...", "payload": {"name": "John", "role": "admin", ...}}
#
# HINT: Look at the /demo-token endpoint for reference
# ────────────────────────────────────────────────────────────────────────────────

# YOUR CODE HERE:
# @app.route('/create-custom-token', methods=['POST'])
# def create_custom_token():
#     pass


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 2: Decode Any Token Endpoint (Medium)
# ────────────────────────────────────────────────────────────────────────────────
# Create an endpoint POST /decode-token that:
# - Accepts JSON body with 'token' field
# - Decodes the token and returns the payload
# - Handles errors: expired token, invalid token
#
# Test: First get a token from /demo-token, then:
#       curl -X POST http://localhost:5001/decode-token \
#       -H "Content-Type: application/json" \
#       -d '{"token": "eyJ..."}'
#
# Expected success: {"valid": true, "payload": {...}}
# Expected error: {"valid": false, "error": "Token expired"} or "Invalid token"
#
# HINT: Use try/except with jwt.ExpiredSignatureError and jwt.InvalidTokenError
# ────────────────────────────────────────────────────────────────────────────────

# YOUR CODE HERE:
# @app.route('/decode-token', methods=['POST'])
# def decode_token():
#     pass


# ────────────────────────────────────────────────────────────────────────────────
# EXERCISE 3: Token with Custom Expiration (Medium)
# ────────────────────────────────────────────────────────────────────────────────
# Create an endpoint POST /token-with-expiry that:
# - Accepts JSON body with 'user_id' and 'expires_in_minutes' fields
# - Creates a token that expires in the specified number of minutes
# - Returns the token and the exact expiration datetime
#
# Test: curl -X POST http://localhost:5001/token-with-expiry \
#       -H "Content-Type: application/json" \
#       -d '{"user_id": 1, "expires_in_minutes": 5}'
#
# Expected: {"token": "eyJ...", "expires_at": "2024-01-15 10:30:00"}
#
# HINT: timedelta(minutes=expires_in_minutes)
# ────────────────────────────────────────────────────────────────────────────────

# YOUR CODE HERE:
# @app.route('/token-with-expiry', methods=['POST'])
# def token_with_expiry():
#     pass


# ================================================================================


if __name__ == '__main__':
    print("=" * 60)
    print("CHAPTER 1: Introduction & Setup")
    print("=" * 60)
    print("Server running at: http://localhost:5001")
    print("")
    print("Endpoints:")
    print("  GET /        - Frontend page")
    print("  GET /health  - Check if server is running")
    print("  GET /demo-token - See how JWT tokens work")
    print("=" * 60)
    app.run(debug=True, port=5001)
