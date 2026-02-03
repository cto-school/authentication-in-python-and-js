# Chapter 8: Refresh Tokens

## TIER 3: Advanced

The industry-standard pattern for secure, seamless authentication.

---

## The Problem with Single Tokens

| Short token (15 min) | Long token (7 days) |
|---------------------|---------------------|
| Secure | Risky |
| Annoying (constant re-login) | Good UX |

**Solution:** Use BOTH!

---

## Two-Token Pattern

| Token | Lifetime | Purpose |
|-------|----------|---------|
| Access Token | 15 min | API calls |
| Refresh Token | 7 days | Get new access tokens |

---

## Flow

```
LOGIN
  → Get access_token (15 min) + refresh_token (7 days)

API CALL
  → Send access_token in Authorization header

ACCESS EXPIRED (15 min)
  → Call /refresh with refresh_token
  → Get new access_token
  → Continue using app (no re-login!)

LOGOUT
  → Blacklist refresh_token

REFRESH EXPIRED (7 days)
  → Must login again
```

---

## Token Blacklist

JWTs are stateless - server doesn't track issued tokens.

To "revoke" a refresh token (logout), we blacklist its `jti` (unique ID).

```python
class TokenBlacklist(db.Model):
    jti = db.Column(db.String(36), unique=True)
    revoked_at = db.Column(db.DateTime)
```

---

## Why jti Instead of Full Token?

- jti is 36 characters (UUID)
- Full token is 200+ characters
- Saves database space
- jti is unique, perfect for lookup

---

## API Endpoints

| Endpoint | Purpose |
|----------|---------|
| POST /login | Get both tokens |
| POST /refresh | Get new access token |
| POST /logout | Blacklist refresh token |
| GET /profile | Protected route (needs access token) |

---

## How to Run

```bash
cd chapter-8/backend
python app.py
```

---

## Self-Study Questions

1. Why use two tokens instead of one?
2. Why is the access token short-lived?
3. What is jti and why use it?
4. Can access tokens be revoked?
5. Where should frontend store refresh tokens?

---

## Next Chapter

[Chapter 9: Role-Based Access Control](../chapter-9/README.md)
