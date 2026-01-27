# Part 6: Reset Password (Local Testing)

## What You Will Learn

1. Create the `/reset-password` API
2. Validate the reset token
3. Update the user's password
4. Mark token as used
5. Build reset password form

---

## How Reset Password Works

```
1. User opens reset link (from Part 5)
2. Frontend extracts token from URL
3. Frontend verifies token is valid
4. User enters new password
5. Frontend calls /reset-password API
6. Backend validates token again
7. Backend updates password
8. Backend marks token as used
9. User can login with new password
```

---

## Getting Token from URL

When user clicks the reset link:
```
http://localhost:5000/reset-password?token=abc123...
```

JavaScript can extract the token:
```javascript
// Get URL parameters
const params = new URLSearchParams(window.location.search);

// Get 'token' parameter
const token = params.get('token');
// Result: "abc123..."
```

---

## Security Checks

Before resetting password, we check:

1. **Token exists** - Is the token in our database?
2. **Token not used** - Has it been used before?
3. **Token not expired** - Is it still within time limit?
4. **Password valid** - Is new password strong enough?

---

## After Reset

When password is reset:

1. **Mark token as used** - Can't use same token again
2. **Hash new password** - Store securely
3. **Optional: Invalidate other sessions** - Force re-login everywhere

---

## Files in This Part

```
part-6/
├── backend/
│   ├── app.py              # Flask API with /reset-password
│   └── requirements.txt    # Required packages
├── frontend/
│   └── index.html          # Reset password form
└── README.md               # You are here
```

---

## How to Run

### Step 1: Install packages
```bash
cd part-6/backend
pip install -r requirements.txt
```

### Step 2: Run the server
```bash
python app.py
```

### Step 3: Open frontend
```
Open part-6/frontend/index.html in browser
```

---

## API Endpoint

### POST /reset-password

**Request:**
```json
{
    "token": "abc123def456...",
    "new_password": "newSecret123"
}
```

**Success Response (200):**
```json
{
    "message": "Password reset successful! You can now login."
}
```

**Error Responses:**

Token invalid (400):
```json
{
    "message": "Invalid token!"
}
```

Token used (400):
```json
{
    "message": "Token has already been used!"
}
```

Token expired (400):
```json
{
    "message": "Token has expired!"
}
```

---

## Complete Flow

```
[Part 5]                          [Part 6]
   |                                  |
   | User requests reset              |
   | Backend generates token          |
   | Returns reset link               |
   |                                  |
   |--------------------------------->|
   |                                  | User opens reset link
   |                                  | Frontend gets token from URL
   |                                  | User enters new password
   |                                  | Frontend calls /reset-password
   |                                  | Backend validates token
   |                                  | Backend updates password
   |                                  | Backend marks token used
   |                                  |
   |                                  | User can login with new password
```

---

## Testing Steps

1. **Register a user** (if not done in Part 5)
2. **Request reset link** (Part 5)
3. **Copy the token**
4. **Open Part 6 frontend**
5. **Paste token**
6. **Enter new password**
7. **Submit**
8. **Try login with new password**

---

## Test Your Understanding

Before moving to next part, make sure you can answer:

1. How does frontend get the token from URL?
2. Why do we mark tokens as "used"?
3. What checks are done before resetting password?
4. Can the same token be used twice?

---

## Next Part

Once reset password works, move to [Part 7: Mailgun Integration](../part-7/README.md)
