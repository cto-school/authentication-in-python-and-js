# Part 2: User Registration

## What You Will Learn

1. Create a User database table
2. Hash passwords (never store plain passwords!)
3. Build a `/register` API
4. Create a registration form

---

## Why Hash Passwords?

### Never Store Plain Passwords!

```
BAD:  password = "secret123"                              (stored as plain text - DANGEROUS!)
GOOD: password = "pbkdf2:sha256:600000$salt$hash..."      (stored as hash - SECURE!)
```

### What is Hashing?

- Hashing converts password into random-looking text
- Same password always gives same hash
- You CANNOT reverse a hash to get the password
- We use **werkzeug.security** for hashing (comes built-in with Flask!)

### Example:
```
Password: "hello"
Hash:     "pbkdf2:sha256:600000$randomSalt$hashedValue..."
```

### Why werkzeug.security?

- **Built into Flask** - No extra installation needed
- **Simple API** - Just `generate_password_hash()` and `check_password_hash()`
- **Secure algorithm** - Uses PBKDF2-SHA256 (slow on purpose to prevent brute-force)
- **Automatic salting** - Each hash is unique even for same password

---

## How Registration Works

```
1. User enters: email + password
2. Frontend sends data to /register API
3. Backend checks: Does email already exist?
4. If NO: Hash password, save user, return success
5. If YES: Return error "Email already exists"
```

---

## Database Structure

We will create a simple `users` table:

| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Auto-generated ID |
| email | String | User's email (unique) |
| password | String | Hashed password |
| created_at | DateTime | When user registered |

---

## Files in This Part

```
part-2/
├── backend/
│   ├── app.py              # Flask API with /register
│   └── requirements.txt    # Required packages
├── frontend/
│   └── index.html          # Registration form
└── README.md               # You are here
```

---

## How to Run

### Step 1: Install packages
```bash
cd part-2/backend
pip install -r requirements.txt
```

### Step 2: Run the server
```bash
python app.py
```
This will also create the database automatically.

### Step 3: Open frontend
```
Open part-2/frontend/index.html in browser
```

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

**Success Response (201):**
```json
{
    "message": "User registered successfully!",
    "user": {
        "id": 1,
        "email": "john@example.com"
    }
}
```

**Error Response (400):**
```json
{
    "message": "Email already exists!"
}
```

---

## Important Concepts

### 1. Password Hashing with werkzeug.security

```python
from werkzeug.security import generate_password_hash, check_password_hash

# Hash a password (simple one-liner!)
hashed = generate_password_hash(password)

# Check if password matches hash
check_password_hash(hashed, password)  # Returns True or False
```

### 2. Why werkzeug.security?

- **No extra install** - Already comes with Flask
- **Simple API** - No encoding/decoding needed
- **Slow on purpose** - Uses PBKDF2 with many iterations (prevents brute-force)
- **Automatic salt** - Same password gives different hash each time
- **Industry standard** - Used by Flask apps worldwide

---

## Test Your Understanding

Before moving to next part, make sure you can answer:

1. Why should we never store plain passwords?
2. What is password hashing?
3. Can you reverse a hash to get the password?
4. What does `generate_password_hash()` do?
5. Why is werkzeug.security convenient for Flask apps?

---

## Next Part

Once registration works, move to [Part 3: User Login](../part-3/README.md)
