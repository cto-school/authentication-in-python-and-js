# Part 4: Protected Routes

## What You Will Learn

1. Create protected API endpoints
2. Verify JWT token in backend
3. Send token from frontend in headers
4. Access user data from token

---

## What are Protected Routes?

Some APIs should only be accessible to logged-in users:

| Route | Protected? | Who can access? |
|-------|------------|-----------------|
| /register | No | Anyone |
| /login | No | Anyone |
| /profile | Yes | Only logged-in users |
| /settings | Yes | Only logged-in users |

---

## How Protection Works

```
1. Frontend sends request with token in header
2. Backend reads the token from header
3. Backend verifies the token
4. If valid: Process the request
5. If invalid: Return 401 Unauthorized
```

---

## Sending Token in Header

The token is sent in the `Authorization` header:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

**Why "Bearer"?**
- It's a standard format for token authentication
- "Bearer" means "the person carrying this token"

---

## Frontend: Sending Token

```javascript
// Get token from localStorage
const token = localStorage.getItem('token');

// Send request with token
fetch('/profile', {
    method: 'GET',
    headers: {
        'Authorization': 'Bearer ' + token
    }
});
```

---

## Backend: Verifying Token

```python
# Get token from header
auth_header = request.headers.get('Authorization')

# Extract token (remove "Bearer " prefix)
token = auth_header.split(' ')[1]

# Verify token
decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

# Now you have user_id and email from token
user_id = decoded['user_id']
```

---

## Decorator Pattern

We use a **decorator** to protect routes:

```python
@token_required           # This checks the token
def profile():
    # This code only runs if token is valid
    pass
```

A decorator is a function that wraps another function to add extra behavior.

---

## Files in This Part

```
part-4/
├── backend/
│   ├── app.py              # Flask API with protected routes
│   └── requirements.txt    # Required packages
├── frontend/
│   └── index.html          # Test protected routes
└── README.md               # You are here
```

---

## How to Run

### Step 1: Install packages
```bash
cd part-4/backend
pip install -r requirements.txt
```

### Step 2: Run the server
```bash
python app.py
```

### Step 3: Open frontend
```
Open part-4/frontend/index.html in browser
```

---

## API Endpoints

### Public Routes (No token needed)

| Method | Route | Description |
|--------|-------|-------------|
| POST | /register | Register new user |
| POST | /login | Login and get token |

### Protected Routes (Token required)

| Method | Route | Description |
|--------|-------|-------------|
| GET | /profile | Get current user's profile |
| GET | /dashboard | Get dashboard data |

---

## Testing Flow

1. **First, try without token:**
   - Call /profile without token
   - You should get "Token is missing!" error

2. **Then, login and try again:**
   - Login to get token
   - Call /profile with token
   - You should see your profile data

---

## Error Responses

### No Token
```json
{
    "message": "Token is missing!"
}
```

### Invalid Token
```json
{
    "message": "Token is invalid!"
}
```

### Expired Token
```json
{
    "message": "Token has expired!"
}
```

---

## Test Your Understanding

Before moving to next part, make sure you can answer:

1. What header is used to send the token?
2. What does "Bearer" mean in the header?
3. What happens if no token is sent?
4. How does the backend extract user info from the token?

---

## Next Part

Once protected routes work, move to [Part 5: Forgot Password (Local)](../part-5/README.md)
