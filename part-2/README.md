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
BAD:  password = "secret123"     (stored as plain text)
GOOD: password = "$2b$12$xyz..."  (stored as hash)
```

### What is Hashing?

- Hashing converts password into random-looking text
- Same password always gives same hash
- You CANNOT reverse a hash to get the password
- We use **bcrypt** for hashing (it's secure and slow on purpose)

### Example:
```
Password: "hello"
Hash:     "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.V"
```

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

### 1. Password Hashing with bcrypt

```python
# Hash a password
hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Check if password matches hash
bcrypt.checkpw(password.encode('utf-8'), hashed)
```

### 2. Why bcrypt?

- **Slow on purpose** - Makes brute-force attacks harder
- **Includes salt** - Same password gives different hash each time
- **Industry standard** - Used by major companies

---

## Test Your Understanding

Before moving to next part, make sure you can answer:

1. Why should we never store plain passwords?
2. What is password hashing?
3. Can you reverse a hash to get the password?
4. What does bcrypt do?

---

## Next Part

Once registration works, move to [Part 3: User Login](../part-3/README.md)
