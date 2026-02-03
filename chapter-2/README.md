# Chapter 2: User Registration

## What You Will Learn

1. Create a User database model
2. Hash passwords securely (never store plain text!)
3. Build a `/register` API endpoint
4. Understand why password hashing matters

---

## Why Hash Passwords?

### NEVER Store Plain Passwords!

If your database is ever compromised:

```
BAD (Plain text):
┌─────────────────────────────────────┐
│ users table                         │
│ email          │ password           │
│ john@email.com │ secret123          │  ← Attacker sees actual password!
│ jane@email.com │ mypassword         │
└─────────────────────────────────────┘

GOOD (Hashed):
┌──────────────────────────────────────────────────────┐
│ users table                                          │
│ email          │ password                            │
│ john@email.com │ pbkdf2:sha256:600000$salt$hash...  │  ← Useless to attacker
│ jane@email.com │ pbkdf2:sha256:600000$salt$hash...  │
└──────────────────────────────────────────────────────┘
```

### What is Hashing?

- **Hashing** converts a password into random-looking text
- Same password always gives same hash
- You **CANNOT** reverse a hash to get the password
- We use **werkzeug.security** (built into Flask)

### Example
```python
Password: "hello"
Hash:     "pbkdf2:sha256:600000$abc123$def456..."
```

---

## werkzeug.security - Our Hashing Library

### Why werkzeug.security?

| Feature | Benefit |
|---------|---------|
| Built into Flask | No extra installation |
| Simple API | Just 2 functions |
| Automatic salting | Same password → different hash each time |
| Slow on purpose | Prevents brute-force attacks |

### The Two Functions

```python
from werkzeug.security import generate_password_hash, check_password_hash

# Hash a password (registration)
hashed = generate_password_hash("secret123")
# Result: "pbkdf2:sha256:600000$randomsalt$hashedvalue..."

# Verify a password (login - we'll use this in Chapter 3)
check_password_hash(hashed, "secret123")  # Returns True
check_password_hash(hashed, "wrongpass")  # Returns False
```

---

## Registration Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     REGISTRATION FLOW                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  [User]              [Frontend]              [Backend]           │
│    │                     │                      │                │
│    │ Enter email/pass    │                      │                │
│    │ ──────────────────► │                      │                │
│    │                     │ POST /register       │                │
│    │                     │ {email, password}    │                │
│    │                     │ ────────────────────►│                │
│    │                     │                      │ Email exists?  │
│    │                     │                      │ If yes → Error │
│    │                     │                      │ If no ↓        │
│    │                     │                      │ Hash password  │
│    │                     │                      │ Save to DB     │
│    │                     │    {success, user}   │                │
│    │                     │ ◄────────────────────│                │
│    │  "Registration      │                      │                │
│    │   successful!"      │                      │                │
│    │ ◄────────────────── │                      │                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Database Structure

| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Auto-generated primary key |
| email | String(120) | User's email (unique) |
| password | String(255) | Hashed password (NOT plain text!) |
| created_at | DateTime | When user registered |

---

## API Endpoint

### POST /register

**Request:**
```json
{
    "email": "john@example.com",
    "password": "secret123"
}
```

**Success Response (201 Created):**
```json
{
    "message": "User registered successfully!",
    "user": {
        "id": 1,
        "email": "john@example.com"
    }
}
```

**Error Response (400 Bad Request):**
```json
{
    "message": "Email already exists!"
}
```

---

## How to Run

```bash
cd chapter-2/backend
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5002` in your browser.

---

## Code Highlights

### Password Hashing
```python
def hash_password(password):
    return generate_password_hash(password)
```

### User Model
```python
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Stores HASH, not password
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
```

---

## Self-Study Questions

1. Why should we never store plain passwords?
2. What does `generate_password_hash()` do?
3. Can you reverse a hash to get the original password?
4. Why is the hash different each time for the same password?
5. What happens if someone tries to register with an existing email?

---

## Next Chapter

Once registration works, move to [Chapter 3: User Login & JWT](../chapter-3/README.md)
