# Chapter 3: User Login & JWT Tokens

## What You Will Learn

1. Verify user credentials (email + password)
2. Create JWT tokens using pyjwt
3. Return tokens to the frontend
4. Store tokens in localStorage

---

## Login Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                         LOGIN FLOW                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  [User]              [Frontend]              [Backend]           │
│    │                     │                      │                │
│    │ Enter email/pass    │                      │                │
│    │ ──────────────────► │                      │                │
│    │                     │ POST /login          │                │
│    │                     │ {email, password}    │                │
│    │                     │ ────────────────────►│                │
│    │                     │                      │ Find user      │
│    │                     │                      │ Verify password│
│    │                     │                      │ Create JWT     │
│    │                     │   {token, user}      │                │
│    │                     │ ◄────────────────────│                │
│    │                     │                      │                │
│    │                     │ Store in localStorage│                │
│    │  "Login success!"   │                      │                │
│    │ ◄────────────────── │                      │                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Password Verification

From Chapter 2, we stored hashed passwords. Now we verify them:

```python
from werkzeug.security import check_password_hash

# check_password_hash(stored_hash, entered_password)
# Returns True if password matches, False otherwise

check_password_hash(user.password, entered_password)
```

**Note:** The hash comes first, then the plain password!

---

## Creating JWT Tokens

```python
import jwt
from datetime import datetime, timedelta

def create_token(user):
    payload = {
        'user_id': user.id,
        'email': user.email,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')
```

---

## Storing Tokens on Frontend

```javascript
// After successful login
localStorage.setItem('token', data.token);

// Later, retrieve it
const token = localStorage.getItem('token');

// On logout
localStorage.removeItem('token');
```

---

## API Endpoint

### POST /login

**Request:**
```json
{
    "email": "john@example.com",
    "password": "secret123"
}
```

**Success Response (200):**
```json
{
    "message": "Login successful!",
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "user": {
        "id": 1,
        "email": "john@example.com"
    }
}
```

**Error Response (401):**
```json
{
    "message": "Invalid email or password!"
}
```

---

## Security Note

Always return the **same error message** for:
- User not found
- Wrong password

Why? So attackers can't tell which part was wrong!

---

## How to Run

```bash
cd chapter-3/backend
pip install -r requirements.txt
python app.py
```

---

## Self-Study Questions

1. Why use the same error message for "user not found" and "wrong password"?
2. What data is stored in the JWT token payload?
3. Where should the frontend store the JWT token?
4. What happens when a token expires?
5. Why do we send the user object along with the token?

---

## Next Chapter

Now that we have tokens, let's use them to [protect routes](../chapter-4/README.md)!
