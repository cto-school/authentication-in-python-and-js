# Part 3: User Login

## What You Will Learn

1. Create a `/login` API
2. Validate email and password
3. Return JWT token on successful login
4. Store token in browser's localStorage

---

## How Login Works

```
1. User enters: email + password
2. Frontend sends data to /login API
3. Backend finds user by email
4. Backend checks: Does password match the hash?
5. If YES: Create JWT token, return token
6. If NO: Return error "Invalid credentials"
```

---

## Important: Password Verification

Remember from Part 2:
- We store HASHED password in database
- We CANNOT reverse the hash
- So how do we check if password is correct?

### bcrypt.checkpw()

```python
# This function:
# 1. Takes the plain password user entered
# 2. Hashes it using the same salt from stored hash
# 3. Compares the two hashes
# 4. Returns True if they match, False if not

bcrypt.checkpw(entered_password, stored_hash)
```

---

## JWT Token After Login

When login is successful, we return a JWT token containing:

```json
{
    "user_id": 1,
    "email": "john@example.com",
    "exp": 1234567890
}
```

The frontend will:
1. Store this token in localStorage
2. Send this token with future requests
3. Use this token to access protected APIs (Part 4)

---

## localStorage - Browser Storage

localStorage is a simple key-value storage in the browser:

```javascript
// Save data
localStorage.setItem('token', 'eyJhbG...');

// Get data
const token = localStorage.getItem('token');

// Remove data
localStorage.removeItem('token');
```

**Note:** localStorage data persists even after closing browser.

---

## Files in This Part

```
part-3/
├── backend/
│   ├── app.py              # Flask API with /register and /login
│   └── requirements.txt    # Required packages
├── frontend/
│   └── index.html          # Login and Register forms
└── README.md               # You are here
```

---

## How to Run

### Step 1: Install packages
```bash
cd part-3/backend
pip install -r requirements.txt
```

### Step 2: Run the server
```bash
python app.py
```

### Step 3: Open frontend
```
Open part-3/frontend/index.html in browser
```

---

## API Endpoints

### POST /register (Same as Part 2)

### POST /login (New!)

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

## Flow Summary

```
[User]                    [Frontend]                  [Backend]
  |                           |                           |
  | Enter email/password      |                           |
  |-------------------------->|                           |
  |                           | POST /login               |
  |                           |-------------------------->|
  |                           |                           | Find user by email
  |                           |                           | Check password hash
  |                           |                           | Create JWT token
  |                           |       Token + User info   |
  |                           |<--------------------------|
  |                           | Save token to localStorage|
  |   "Login successful!"     |                           |
  |<--------------------------|                           |
```

---

## Test Your Understanding

Before moving to next part, make sure you can answer:

1. How does bcrypt.checkpw() verify passwords?
2. What data is stored in the JWT token after login?
3. Where does the frontend store the token?
4. Why do we need a token after login?

---

## Next Part

Once login works, move to [Part 4: Protected Routes](../part-4/README.md)
