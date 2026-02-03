# ================================================================================
# CHAPTER 1: SOLUTIONS - Introduction & Setup
# ================================================================================
# This file contains solutions to all exercises from Chapter 1.
# Compare your solutions with these after attempting them yourself!
# ================================================================================

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
import jwt
from datetime import datetime, timedelta
import os

app = Flask(__name__)
CORS(app)

SECRET_KEY = 'your-secret-key-for-learning-123'


@app.route('/')
def index():
    html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
    return send_file(html_path)


@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'message': 'Chapter 1 Solutions server is running!',
        'chapter': 1
    })


@app.route('/demo-token')
def demo_token():
    """Original demo endpoint from the chapter."""
    payload = {
        'user_id': 1,
        'email': 'demo@example.com',
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

    return jsonify({
        'message': 'This is a demo JWT token',
        'token': token,
        'decoded_payload': {
            'user_id': decoded['user_id'],
            'email': decoded['email'],
            'expires': datetime.fromtimestamp(decoded['exp']).strftime('%Y-%m-%d %H:%M:%S')
        }
    })


# ================================================================================
# EXERCISE 1 SOLUTION: Create a Custom Token Endpoint
# ================================================================================
# This endpoint accepts custom data and creates a token with it.
# Key learning: You can put ANY data in the JWT payload!
# ================================================================================

@app.route('/create-custom-token', methods=['POST'])
def create_custom_token():
    # Get JSON data from request body
    data = request.get_json()

    # Validate required fields
    if not data:
        return jsonify({'error': 'Request body required'}), 400

    name = data.get('name')
    role = data.get('role')

    if not name or not role:
        return jsonify({'error': 'Both name and role are required'}), 400

    # Create the payload with custom data
    # We add 'exp' for expiration (required for most real-world tokens)
    payload = {
        'name': name,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=1),
        'iat': datetime.utcnow()  # Issued at - good practice to include
    }

    # Create the token
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

    return jsonify({
        'success': True,
        'token': token,
        'payload': {
            'name': name,
            'role': role,
            'expires_in': '1 hour'
        }
    })


# ================================================================================
# EXERCISE 2 SOLUTION: Decode Any Token Endpoint
# ================================================================================
# This endpoint decodes tokens and handles various error cases.
# Key learning: Always handle jwt.ExpiredSignatureError and jwt.InvalidTokenError!
# ================================================================================

@app.route('/decode-token', methods=['POST'])
def decode_token():
    data = request.get_json()

    if not data or 'token' not in data:
        return jsonify({
            'valid': False,
            'error': 'Token is required in request body'
        }), 400

    token = data['token']

    try:
        # jwt.decode() automatically checks:
        # 1. Signature validity (was it signed with our SECRET_KEY?)
        # 2. Expiration (is 'exp' in the past?)
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

        # Convert exp timestamp to readable format
        if 'exp' in decoded:
            decoded['exp_readable'] = datetime.fromtimestamp(decoded['exp']).strftime('%Y-%m-%d %H:%M:%S')

        return jsonify({
            'valid': True,
            'payload': decoded
        })

    except jwt.ExpiredSignatureError:
        # Token was valid but has expired
        # We can still decode it to see the payload (for debugging)
        # by using options={'verify_exp': False}
        try:
            expired_payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'],
                                         options={'verify_exp': False})
            return jsonify({
                'valid': False,
                'error': 'Token expired',
                'expired_at': datetime.fromtimestamp(expired_payload['exp']).strftime('%Y-%m-%d %H:%M:%S'),
                'payload': expired_payload  # Still show payload for debugging
            }), 401
        except:
            return jsonify({'valid': False, 'error': 'Token expired'}), 401

    except jwt.InvalidTokenError as e:
        # Token is malformed, wrong signature, etc.
        return jsonify({
            'valid': False,
            'error': 'Invalid token',
            'details': str(e)
        }), 401


# ================================================================================
# EXERCISE 3 SOLUTION: Token with Custom Expiration
# ================================================================================
# This endpoint creates tokens with user-specified expiration times.
# Key learning: timedelta() is flexible - you can use minutes, hours, days, etc.
# ================================================================================

@app.route('/token-with-expiry', methods=['POST'])
def token_with_expiry():
    data = request.get_json()

    if not data:
        return jsonify({'error': 'Request body required'}), 400

    user_id = data.get('user_id')
    expires_in_minutes = data.get('expires_in_minutes')

    # Validate inputs
    if user_id is None:
        return jsonify({'error': 'user_id is required'}), 400

    if expires_in_minutes is None:
        return jsonify({'error': 'expires_in_minutes is required'}), 400

    # Validate expiration is reasonable (e.g., 1 minute to 24 hours)
    try:
        expires_in_minutes = int(expires_in_minutes)
        if expires_in_minutes < 1:
            return jsonify({'error': 'expires_in_minutes must be at least 1'}), 400
        if expires_in_minutes > 1440:  # 24 hours
            return jsonify({'error': 'expires_in_minutes cannot exceed 1440 (24 hours)'}), 400
    except ValueError:
        return jsonify({'error': 'expires_in_minutes must be a number'}), 400

    # Calculate expiration time
    expiration_time = datetime.utcnow() + timedelta(minutes=expires_in_minutes)

    # Create the token
    payload = {
        'user_id': user_id,
        'exp': expiration_time,
        'iat': datetime.utcnow()
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

    return jsonify({
        'success': True,
        'token': token,
        'user_id': user_id,
        'expires_at': expiration_time.strftime('%Y-%m-%d %H:%M:%S'),
        'expires_in_minutes': expires_in_minutes
    })


if __name__ == '__main__':
    print("=" * 60)
    print("CHAPTER 1: SOLUTIONS")
    print("=" * 60)
    print("Server running at: http://localhost:5001")
    print("")
    print("Original Endpoints:")
    print("  GET  /demo-token")
    print("")
    print("Exercise Solutions:")
    print("  POST /create-custom-token  - Exercise 1")
    print("  POST /decode-token         - Exercise 2")
    print("  POST /token-with-expiry    - Exercise 3")
    print("=" * 60)
    app.run(debug=True, port=5001)
