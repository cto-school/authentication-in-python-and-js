# Chapter 7: Password Management

## MILESTONE: Your app is now Production-Ready!

With Chapters 1-7 complete, you have:
- User registration with secure passwords
- Login with JWT tokens
- Protected routes
- Proper error handling
- Email verification
- Password change and reset

---

## This Chapter Covers Two Flows

### Section A: Change Password
- User IS logged in
- User KNOWS current password
- Verification: Current password

### Section B: Forgot Password / Reset
- User is NOT logged in
- User FORGOT password
- Verification: Email token

---

## Comparison

| Aspect | Change Password | Forgot Password |
|--------|-----------------|-----------------|
| User state | Logged in | NOT logged in |
| Has current password? | Yes | No |
| Verification method | Current password | Email reset token |
| API auth | JWT token | Reset token |
| Use case | Security update | Recovery |

---

## Section A: Change Password Flow

```
User logged in → Enter current + new password → Verify current → Update

POST /change-password
Headers: Authorization: Bearer <jwt>
Body: { "current_password": "...", "new_password": "..." }
```

### Why require current password?
Security: If someone finds your unlocked computer, they can't lock you out without knowing your password.

---

## Section B: Forgot Password Flow

```
Step 1: Request Reset
POST /forgot-password
Body: { "email": "user@example.com" }
→ Server generates reset token, sends email

Step 2: Reset Password
POST /reset-password
Body: { "token": "abc123...", "new_password": "..." }
→ Server verifies token, updates password
```

---

## Password Reset Token Model

```python
class PasswordResetToken(db.Model):
    user_id = db.Column(db.Integer, ForeignKey('users.id'))
    token = db.Column(db.String(100), unique=True)
    expires_at = db.Column(db.DateTime)
    used = db.Column(db.Boolean, default=False)
```

---

## Security Considerations

1. **Don't reveal if email exists** - Same message for found/not found
2. **Token expiration** - Reset tokens expire (1 hour)
3. **One-time use** - Mark token as used after reset
4. **Require current password** - For change password flow

---

## How to Run

```bash
cd chapter-7/backend
python app.py
```

---

## Self-Study Questions

1. Why require current password for change, but not for reset?
2. Why do reset tokens expire?
3. Why mark tokens as "used" instead of deleting them?
4. Should you logout all sessions after password change?

---

## What's Next?

**Congratulations!** Tier 2 complete - Production-Ready!

Continue to Tier 3 (Advanced) for enterprise features:
- [Chapter 8: Refresh Tokens](../chapter-8/README.md)
- [Chapter 9: Role-Based Access Control](../chapter-9/README.md)
- [Chapter 10: Security Best Practices](../chapter-10/README.md)
