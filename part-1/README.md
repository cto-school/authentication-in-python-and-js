# Part 1: Understanding JWT (JSON Web Tokens)

## What You'll Learn
- What is a JWT token
- How to create a token
- How to decode a token
- How to verify a token
- The 3 parts of a JWT

---

## Quick Start (Step by Step)

### Step 1: Install Required Packages

Open terminal/command prompt and navigate to the `backend` folder:

```bash
cd part-1/backend
```

Install the required Python packages:

```bash
pip install flask flask-cors pyjwt
```

Or install from requirements.txt:

```bash
pip install -r requirements.txt
```

### Step 2: Start the Backend Server

Run the Flask server:

```bash
python app.py
```

You should see:
```
============================================================
   JWT Demo Server
============================================================

   Server URL: http://localhost:5000

   Available Endpoints:
   - GET  /          : API info
   - GET  /health    : Check server status
   - POST /create-token  : Create JWT token
   - POST /decode-token  : Decode JWT token
   - POST /verify-token  : Verify JWT token

============================================================
   HOW TO TEST:
   1. Keep this terminal open (server running)
   2. Open frontend/index.html in your browser
   3. Try creating and decoding tokens!
============================================================
```

**Keep this terminal open!** The server must be running.

### Step 3: Open the Frontend

1. Open `frontend/index.html` in your web browser
2. You should see "Server is ONLINE" at the top (green banner)
3. If you see "Server is OFFLINE" (red banner), make sure Step 2 is done

### Step 4: Try It Out!

1. Enter a User ID (e.g., 123)
2. Enter a Name (e.g., John)
3. Click "Create Token"
4. See the generated token
5. Click "Decode Token" to see the data inside!

---

## Understanding the Code

### Backend (app.py)

```python
# Create a token
payload = {
    'user_id': 123,
    'name': 'John',
    'exp': datetime.utcnow() + timedelta(minutes=30)  # Expires in 30 min
}
token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

# Decode a token
decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
# decoded = {'user_id': 123, 'name': 'John', 'exp': ...}
```

### Frontend (index.html)

```javascript
// Call the API to create a token
const response = await fetch('http://localhost:5000/create-token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_id: 123, name: 'John' })
});

const data = await response.json();
console.log(data.token);  // The JWT token
```

---

## JWT Structure

A JWT token looks like this:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjMsIm5hbWUiOiJKb2huIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

It has 3 parts separated by dots:

| Part | What it is | Example (decoded) |
|------|------------|-------------------|
| **Header** | Algorithm info | `{"alg": "HS256", "typ": "JWT"}` |
| **Payload** | Your data | `{"user_id": 123, "name": "John"}` |
| **Signature** | Verification | Created using SECRET_KEY |

**Try it:** Paste any token at [jwt.io](https://jwt.io) to see its contents!

---

## Common Errors & Solutions

### Error: "Failed to fetch" or "Server is OFFLINE"

**Cause:** Backend server is not running

**Solution:**
1. Open terminal in `part-1/backend` folder
2. Run `pip install flask flask-cors pyjwt`
3. Run `python app.py`
4. Keep terminal open
5. Refresh the browser

### Error: "Token has expired"

**Cause:** Token's `exp` time has passed

**Solution:** Create a new token

### Error: "Invalid token"

**Cause:** Token was modified or wrong secret key

**Solution:** Use a valid token or create a new one

---

## Files in This Part

```
part-1/
├── backend/
│   ├── app.py           # Flask server with JWT endpoints
│   └── requirements.txt # Python packages needed
├── frontend/
│   └── index.html       # Web interface to test JWT
└── README.md            # This file
```

---

## What is JWT?

JWT = **J**SON **W**eb **T**oken

Think of it like a **movie ticket**:
- The ticket has your seat number (your data)
- The ticket has a special stamp (signature)
- The theater can verify the stamp is real
- You can't fake the stamp

### Why Use JWT?

| Without JWT (Sessions) | With JWT |
|------------------------|----------|
| Server stores sessions | Server stores nothing |
| Database lookup every request | Just verify signature |
| Hard to scale | Easy to scale |

---

## Important Notes

1. **JWT is NOT encrypted** - Anyone can read the payload
2. **Don't put sensitive data** in JWT (like passwords)
3. **JWT can be verified** - Server can check if it's real
4. **JWT has expiration** - Tokens expire after some time

---

## Exercises

After completing this part, try:

1. **Change token expiration** - Make it expire in 10 seconds instead of 30 minutes
2. **Add more data** - Add `role: 'admin'` to the token payload
3. **Test invalid tokens** - Modify a token and try to decode it
4. **Visit jwt.io** - Paste your token and see its contents

---

## What's Next?

In **Part 2**, you'll learn:
- User registration with passwords
- Storing users in a database
- Password hashing for security
