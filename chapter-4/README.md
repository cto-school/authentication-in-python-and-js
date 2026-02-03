# Chapter 4: Protected Routes

## MILESTONE: You now have a working authentication system!

After this chapter, you can:
- Register users with secure password hashing
- Login users and issue JWT tokens
- Protect routes that require authentication

---

## What You Will Learn

1. Python decorator pattern
2. Creating @token_required decorator
3. Flask's g object for request-scoped data
4. Public vs Protected routes

---

## The Decorator Pattern

### Without Decorators (Repetitive)
```python
@app.route('/profile')
def get_profile():
    # Must repeat this in EVERY protected route!
    token = request.headers.get('Authorization')
    if not token:
        return error
    # verify token...
    # actual code...

@app.route('/dashboard')
def get_dashboard():
    # Same code repeated!
    token = request.headers.get('Authorization')
    if not token:
        return error
    # verify token...
    # actual code...
```

### With Decorators (Clean)
```python
@app.route('/profile')
@token_required          # Just add this line!
def get_profile():
    # actual code only

@app.route('/dashboard')
@token_required          # Same here!
def get_dashboard():
    # actual code only
```

---

## How @token_required Works

```
Request: GET /profile
         Authorization: Bearer eyJ...

         ↓

@token_required decorator:
    1. Extract token from header
    2. Verify "Bearer <token>" format
    3. Decode JWT with SECRET_KEY
    4. Check if expired
    5. Store user info in g.current_user
    6. Call actual route function

         ↓

get_profile() runs with g.current_user available
```

---

## Flask's g Object

```python
from flask import g

# In decorator:
g.current_user = {'user_id': 1, 'email': 'user@example.com'}

# In route function:
user_id = g.current_user['user_id']
```

**Key features:**
- Lives for ONE request only
- Automatically cleared after request
- Perfect for passing data from decorator to route

---

## Public vs Protected Routes

| Route | Decorator | Who can access |
|-------|-----------|----------------|
| POST /register | None | Anyone |
| POST /login | None | Anyone |
| GET /profile | @token_required | Logged-in users |
| GET /dashboard | @token_required | Logged-in users |

---

## How to Test

1. **Without token:** Call /profile → Get 401 error
2. **With invalid token:** Call /profile → Get 401 error
3. **With valid token:** Call /profile → Get user data

---

## Frontend: Sending Tokens

```javascript
// Get token from storage
const token = localStorage.getItem('token');

// Send with request
fetch('/profile', {
    headers: {
        'Authorization': `Bearer ${token}`
    }
});
```

---

## How to Run

```bash
cd chapter-4/backend
pip install -r requirements.txt
python app.py
```

---

## Self-Study Questions

1. What is a Python decorator?
2. What does @wraps(f) do?
3. What is Flask's g object used for?
4. Why return 401 for both "missing token" and "invalid token"?
5. What happens if a token has expired?

---

## What's Next?

**Congratulations!** You've completed Tier 1 - Foundation!

Your auth system works, but it needs polish:
- Better error handling
- Email verification
- Password reset

Continue to [Chapter 5: Error Handling](../chapter-5/README.md) (Tier 2: Production-Ready)
