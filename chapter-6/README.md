# Chapter 6: Email Verification

## What You Will Learn

1. Why verify emails (security, spam prevention)
2. Adding verification fields to User model
3. Generating secure verification tokens
4. @verified_required decorator
5. Two-level access (logged in vs verified)

---

## Why Verify Emails?

1. **Prevent fake accounts** - Can't use random emails
2. **Prevent impersonation** - Can't use someone else's email
3. **Enable recovery** - Password reset requires valid email
4. **Reduce spam** - Bots can't easily verify
5. **Legal compliance** - GDPR, etc.

---

## Verification Flow

```
Register → Get Token → Verify → Full Access

User registers
    ↓
Account created (is_verified = false)
    ↓
Verification token generated
    ↓
Link sent (or shown for testing)
    ↓
User clicks link
    ↓
Token validated
    ↓
is_verified = true
    ↓
Full access granted
```

---

## User Model Changes

```python
class User(db.Model):
    # ... existing fields ...

    # NEW: Verification fields
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), unique=True)
    verification_expires = db.Column(db.DateTime)
```

---

## Two-Level Access Control

| Route | Decorator | Who Can Access |
|-------|-----------|----------------|
| /login | None | Anyone |
| /profile-basic | @token_required | Logged in users |
| /profile | @token_required + @verified_required | Verified users only |

---

## Token Generation

```python
import secrets

def generate_verification_token():
    return secrets.token_urlsafe(32)  # Secure random token
```

---

## Verification Endpoint

```python
@app.route('/verify-email')
def verify_email():
    token = request.args.get('token')
    user = User.query.filter_by(verification_token=token).first()

    if not user:
        return error('Invalid token')

    if user.verification_expires < datetime.utcnow():
        return error('Token expired')

    user.is_verified = True
    user.verification_token = None  # Clear token (one-time use)
    db.session.commit()

    return success('Email verified!')
```

---

## How to Run

```bash
cd chapter-6/backend
python app.py
```

---

## Self-Study Questions

1. Why clear the verification token after use?
2. Why have token expiration?
3. Should unverified users be able to login?
4. What's the difference between @token_required and @verified_required?

---

## Next Chapter

[Chapter 7: Password Management](../chapter-7/README.md) - Change password & forgot password
