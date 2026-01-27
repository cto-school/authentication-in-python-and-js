# Part 5: Forgot Password (Local Testing)

## What You Will Learn

1. Generate a password reset token
2. Store reset token with expiration
3. Create a reset link for local testing
4. Build forgot password frontend

---

## How Forgot Password Works

```
1. User clicks "Forgot Password"
2. User enters their email
3. Frontend calls /forgot-password API
4. Backend checks if email exists
5. Backend creates a unique reset token
6. Backend saves token in database (with expiry)
7. Backend returns the reset link (for local testing)
8. In real apps: Send link via email (Part 7)
```

---

## Reset Token

A reset token is a random string used to verify the password reset request.

Example: `a7f8b9c0d1e2f3a4b5c6d7e8f9a0b1c2`

### Why use a reset token?

- **Security**: Only the person with the token can reset
- **One-time use**: Token is deleted after use
- **Expiration**: Token expires after some time (e.g., 1 hour)

---

## Database Changes

We add a new table to store reset tokens:

| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Auto ID |
| user_id | Integer | Which user requested reset |
| token | String | The reset token (unique) |
| expires_at | DateTime | When token expires |
| used | Boolean | Has token been used? |

---

## Files in This Part

```
part-5/
├── backend/
│   ├── app.py              # Flask API with /forgot-password
│   └── requirements.txt    # Required packages
├── frontend/
│   └── index.html          # Forgot password form
└── README.md               # You are here
```

---

## How to Run

### Step 1: Install packages
```bash
cd part-5/backend
pip install -r requirements.txt
```

### Step 2: Run the server
```bash
python app.py
```

### Step 3: Open frontend
```
Open part-5/frontend/index.html in browser
```

---

## API Endpoint

### POST /forgot-password

**Request:**
```json
{
    "email": "john@example.com"
}
```

**Success Response (200):**
```json
{
    "message": "Password reset link generated!",
    "reset_link": "http://localhost:5000/reset-password?token=abc123...",
    "note": "In production, this link would be sent via email"
}
```

**Error Response (404):**
```json
{
    "message": "Email not found!"
}
```

---

## Reset Link Format

The reset link looks like:
```
http://localhost:5000/reset-password?token=abc123def456...
```

- `reset-password` = The page to reset password
- `token=abc123...` = The unique reset token

---

## Security Considerations

1. **Don't reveal if email exists**
   - In real apps, always say "If email exists, we sent a link"
   - This prevents attackers from knowing which emails are registered

2. **Token expiration**
   - Tokens should expire (e.g., 1 hour)
   - Expired tokens should not work

3. **One-time use**
   - Token should be deleted after use
   - Can't use same link twice

---

## Local vs Real Email

| Feature | This Part (Local) | Part 7 (Mailgun) |
|---------|-------------------|------------------|
| Reset link | Shown on screen | Sent to email |
| Testing | Easy to test | Need email setup |
| Production | No | Yes |

---

## Test Your Understanding

Before moving to next part, make sure you can answer:

1. What is a reset token?
2. Why do reset tokens expire?
3. Why should tokens be one-time use?
4. What does the reset link contain?

---

## Next Part

Once forgot password works, move to [Part 6: Reset Password (Local)](../part-6/README.md)
