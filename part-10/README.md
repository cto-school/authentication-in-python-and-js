# Part 10: Refresh Token & Logout

## What You Will Learn

1. Understand access token vs refresh token
2. Implement token refresh
3. Handle proper logout
4. Token blacklisting

---

## Why Refresh Tokens?

### Problem with Single Token
- If token expires, user must login again
- Long-lived tokens are security risk (if stolen)

### Solution: Two Tokens
| Token | Lifetime | Purpose |
|-------|----------|---------|
| Access Token | Short (15 min - 1 hour) | Used for API calls |
| Refresh Token | Long (7-30 days) | Used to get new access token |

---

## How It Works

```
1. User logs in
2. Server returns: access token + refresh token
3. Frontend stores both tokens
4. Frontend uses access token for API calls
5. When access token expires:
   a. Frontend calls /refresh with refresh token
   b. Server returns new access token
   c. User stays logged in!
6. When refresh token expires:
   - User must login again
```

---

## Token Storage

```javascript
// Store both tokens
localStorage.setItem('accessToken', data.access_token);
localStorage.setItem('refreshToken', data.refresh_token);

// For API calls, use access token
headers: {
    'Authorization': 'Bearer ' + accessToken
}

// For refresh, use refresh token
body: { refresh_token: refreshToken }
```

---

## Logout Strategies

### Simple Logout (Client-side only)
```javascript
// Just remove tokens from browser
localStorage.removeItem('accessToken');
localStorage.removeItem('refreshToken');
```
**Problem**: Token still valid on server

### Proper Logout (Server-side)
```python
# Server adds token to blacklist
blacklisted_tokens.add(token)

# Future requests with this token fail
if token in blacklisted_tokens:
    return "Token has been revoked"
```

---

## Token Blacklist

For proper logout, we track revoked tokens:

```python
class TokenBlacklist(db.Model):
    id = ...
    token = ...           # The revoked token (or its ID)
    revoked_at = ...      # When it was revoked
```

---

## Files in This Part

```
part-10/
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
cd part-10/backend
pip install -r requirements.txt
python app.py
```

---

## API Endpoints

| Method | Route | Description |
|--------|-------|-------------|
| POST | /login | Returns access + refresh tokens |
| POST | /refresh | Get new access token |
| POST | /logout | Revoke refresh token |
| GET | /profile | Protected route (needs access token) |

---

## Request/Response Examples

### Login Response
```json
{
    "access_token": "eyJhbG...",
    "refresh_token": "eyJhbG...",
    "user": { "id": 1, "email": "..." }
}
```

### Refresh Request
```json
{
    "refresh_token": "eyJhbG..."
}
```

### Refresh Response
```json
{
    "access_token": "eyJhbG..."
}
```

---

## Auto-Refresh Pattern

```javascript
async function apiCall(url, options) {
    let response = await fetch(url, options);

    // If 401 (token expired), try refresh
    if (response.status === 401) {
        const refreshed = await refreshToken();

        if (refreshed) {
            // Retry with new token
            response = await fetch(url, options);
        }
    }

    return response;
}
```

---

## Test Your Understanding

1. Why use two tokens instead of one?
2. What happens when access token expires?
3. What happens when refresh token expires?
4. Why is server-side logout important?

---

## Next Part

[Part 11: Email Verification](../part-11/README.md)
