# Part 11: Email Verification

## What You Will Learn

1. Add email verification to registration
2. Generate verification tokens
3. Send verification emails
4. Verify email via link
5. Restrict access until verified

---

## Why Verify Emails?

- Ensure user owns the email address
- Prevent fake accounts
- Enable email communication
- Security requirement for many apps

---

## How It Works

```
1. User registers with email + password
2. Account created but NOT verified
3. Server generates verification token
4. Server sends email with verification link
5. User clicks link in email
6. Server verifies token and marks email as verified
7. User can now fully use the app
```

---

## Database Changes

Add fields to User model:

```python
class User(db.Model):
    # ... existing fields
    is_verified = db.Column(db.Boolean, default=False)  # NEW
    verification_token = db.Column(db.String(100))       # NEW
```

---

## Verification States

| State | `is_verified` | Can Login? | Full Access? |
|-------|---------------|------------|--------------|
| Just registered | False | Yes (optional) | No |
| Email verified | True | Yes | Yes |

---

## Files in This Part

```
part-11/
├── backend/
│   ├── app.py
│   └── requirements.txt
├── frontend/
│   ├── index.html
│   └── verify.html        # Verification page
└── README.md
```

---

## How to Run

```bash
cd part-11/backend
pip install -r requirements.txt
python app.py
```

---

## API Endpoints

| Method | Route | Description |
|--------|-------|-------------|
| POST | /register | Register (sends verification email) |
| GET | /verify-email?token=xxx | Verify email |
| POST | /resend-verification | Resend verification email |
| GET | /profile | Only for verified users |

---

## Flow Example

### Registration Response
```json
{
    "message": "Registration successful! Please check your email to verify.",
    "user": {
        "id": 1,
        "email": "user@example.com",
        "is_verified": false
    },
    "verification_link": "http://localhost:5500/verify.html?token=abc123..."
}
```

### Verify Email Response
```json
{
    "message": "Email verified successfully! You can now login.",
    "user": {
        "id": 1,
        "email": "user@example.com",
        "is_verified": true
    }
}
```

---

## Security Considerations

1. **Token expiration** - Verification links should expire
2. **One-time use** - Token invalid after verification
3. **Resend limit** - Prevent spam by limiting resend requests
4. **Secure token** - Use cryptographically secure random token

---

## Test Your Understanding

1. Why verify email addresses?
2. Can unverified users login? (Depends on your app design)
3. What happens if verification token expires?
4. Why limit resend requests?

---

## Next Part

[Part 12: Change Password](../part-12/README.md)
