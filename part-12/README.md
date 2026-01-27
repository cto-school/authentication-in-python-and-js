# Part 12: Change Password

## What You Will Learn

1. Allow logged-in users to change their password
2. Verify current password before changing
3. Validate new password
4. Secure password change flow

---

## Difference: Reset vs Change Password

| Feature | Reset Password (Part 5-6) | Change Password (This Part) |
|---------|---------------------------|----------------------------|
| When | Forgot password | Know current password |
| Auth | No login needed (use token) | Must be logged in |
| Verify | Token from email | Current password |
| Use Case | "I forgot my password" | "I want to update my password" |

---

## How Change Password Works

```
1. User is logged in
2. User enters: current password + new password
3. Frontend calls /change-password API with JWT
4. Backend verifies:
   a. JWT token is valid
   b. Current password matches
5. Backend updates password
6. User stays logged in (or optionally logout all devices)
```

---

## Security Checks

Before changing password:

1. **User is logged in** - Valid JWT token
2. **Current password correct** - Prevent unauthorized changes
3. **New password is strong** - Minimum requirements
4. **New password is different** - Can't use same password

---

## Files in This Part

```
part-12/
├── backend/
│   ├── app.py
│   └── requirements.txt
├── frontend/
│   └── index.html
└── README.md
```

---

## How to Run

```bash
cd part-12/backend
pip install -r requirements.txt
python app.py
```

---

## API Endpoint

### POST /change-password

**Headers:**
```
Authorization: Bearer <token>
```

**Request:**
```json
{
    "current_password": "oldPassword123",
    "new_password": "newPassword456"
}
```

**Success Response (200):**
```json
{
    "message": "Password changed successfully!"
}
```

**Error Responses:**

Wrong current password (401):
```json
{
    "message": "Current password is incorrect!"
}
```

Same password (400):
```json
{
    "message": "New password must be different from current password!"
}
```

Weak password (400):
```json
{
    "message": "Password must be at least 6 characters!"
}
```

---

## Flow Diagram

```
[User logged in]
       │
       ▼
[Enter current + new password]
       │
       ▼
[POST /change-password]
       │
       ▼
[Backend checks JWT] ─── Invalid ──► [401 Error]
       │
       │ Valid
       ▼
[Check current password] ─── Wrong ──► [401 Error]
       │
       │ Correct
       ▼
[Validate new password] ─── Invalid ──► [400 Error]
       │
       │ Valid
       ▼
[Update password in DB]
       │
       ▼
[Success!]
```

---

## Best Practices

1. **Always verify current password** - Prevents unauthorized changes
2. **Require strong passwords** - Minimum length, complexity
3. **Consider logout other sessions** - After password change
4. **Log password changes** - For security audit
5. **Rate limit** - Prevent brute force

---

## Congratulations!

You have completed the Authentication Module!

### What You Learned:
1. JWT Tokens
2. User Registration with password hashing
3. User Login
4. Protected Routes
5. Forgot/Reset Password
6. Mailgun Email Integration
7. Error Handling
8. Role-Based Access Control
9. Refresh Tokens & Logout
10. Email Verification
11. Change Password

---

## Next Steps

- Implement OAuth (Google, GitHub login)
- Add Two-Factor Authentication (2FA)
- Build a complete project using these concepts
- Learn about session management

---

## Test Your Understanding

1. Why verify current password before changing?
2. What's the difference between reset and change password?
3. Should you allow the same password as new password?
4. Should you logout the user after password change?
