# Chapter 1: Introduction to Authentication

## What You Will Learn

1. What is authentication vs authorization?
2. How web authentication works
3. Session-based vs Token-based authentication
4. What is JWT and why use it?
5. Project setup and structure

---

## Authentication vs Authorization

These terms are often confused, but they're different:

| Concept | Question | Example |
|---------|----------|---------|
| **Authentication** | "Who are you?" | Login with email/password |
| **Authorization** | "What can you do?" | Admin can delete users, regular users cannot |

**Authentication** happens first (verify identity), then **Authorization** (check permissions).

---

## How Web Authentication Works

### The Problem
HTTP is **stateless** - the server doesn't remember you between requests.

```
Request 1: GET /profile  → Server: "Who are you?"
Request 2: GET /settings → Server: "Who are you?" (forgot already!)
```

### The Solution
We need a way to "remember" the user. Two main approaches:

---

## Session-Based vs Token-Based Authentication

### Session-Based (Traditional)
```
1. User logs in
2. Server creates a "session" and stores it in memory/database
3. Server sends session ID in a cookie
4. Browser sends cookie with every request
5. Server looks up session ID to identify user

[Browser] ←→ [Cookie: session_id=abc123] ←→ [Server] ←→ [Session Store]
```

**Pros:** Simple, easy to invalidate sessions
**Cons:** Server must store all sessions (memory/database), harder to scale

### Token-Based (Modern - What we'll use)
```
1. User logs in
2. Server creates a signed token containing user info
3. Server sends token to browser
4. Browser stores token and sends it with every request
5. Server verifies token signature (no database lookup needed!)

[Browser] ←→ [Token: eyJhbG...] ←→ [Server verifies signature]
```

**Pros:** Stateless (no server storage), scales easily, works with mobile apps
**Cons:** Can't easily invalidate tokens, token size larger than session ID

---

## What is JWT?

**JWT** = JSON Web Token (pronounced "jot")

A JWT is a string with three parts separated by dots:

```
eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxfQ.abc123signature
|_____HEADER_____|.|_____PAYLOAD_____|.|___SIGNATURE___|
```

### 1. Header (Algorithm info)
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

### 2. Payload (Your data)
```json
{
  "user_id": 1,
  "email": "john@example.com",
  "exp": 1234567890
}
```

### 3. Signature (Verification)
```
HMACSHA256(
  base64(header) + "." + base64(payload),
  SECRET_KEY
)
```

### Why is JWT Secure?
- The payload is **NOT encrypted** (anyone can read it)
- But the signature **proves** it wasn't tampered with
- Only the server knows the SECRET_KEY
- If someone changes the payload, the signature won't match

---

## JWT Flow Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                         JWT AUTH FLOW                             │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  [1] LOGIN                                                        │
│  ════════                                                         │
│  User                         Server                              │
│    │                            │                                 │
│    │ POST /login                │                                 │
│    │ {email, password}          │                                 │
│    │ ─────────────────────────► │                                 │
│    │                            │ Verify credentials              │
│    │                            │ Create JWT token                │
│    │         {token: "eyJ..."}  │                                 │
│    │ ◄───────────────────────── │                                 │
│    │                            │                                 │
│  Browser stores token                                             │
│                                                                   │
│  [2] PROTECTED REQUEST                                            │
│  ════════════════════                                             │
│  User                         Server                              │
│    │                            │                                 │
│    │ GET /profile               │                                 │
│    │ Header: Authorization:     │                                 │
│    │   Bearer eyJ...            │                                 │
│    │ ─────────────────────────► │                                 │
│    │                            │ Verify JWT signature            │
│    │                            │ Extract user_id from payload    │
│    │                            │ Return user data                │
│    │      {profile: {...}}      │                                 │
│    │ ◄───────────────────────── │                                 │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

Each chapter follows this structure:

```
chapter-X/
├── backend/
│   ├── app.py              # Flask application
│   └── requirements.txt    # Python dependencies
├── frontend/
│   └── index.html          # Simple HTML for testing
└── README.md               # Chapter explanation
```

---

## Technology Stack

| Technology | Purpose |
|------------|---------|
| **Flask** | Python web framework |
| **SQLAlchemy** | Database ORM |
| **SQLite** | Database (file-based, no setup) |
| **pyjwt** | JWT token creation/verification |
| **werkzeug.security** | Password hashing |
| **flask-cors** | Cross-origin requests |

---

## Setup Instructions

### 1. Create Virtual Environment (Recommended)
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 2. Install Dependencies
```bash
cd chapter-1/backend
pip install -r requirements.txt
```

### 3. Run the Server
```bash
python app.py
```

### 4. Open Frontend
Open `chapter-1/frontend/index.html` in your browser, or navigate to `http://localhost:5001`

---

## What's in This Chapter's Code?

This chapter includes a minimal "hello world" to verify your setup:
- A simple Flask server
- Basic JWT token creation example
- Frontend that shows it's working

---

## Key Concepts to Remember

1. **Authentication** = Who are you?
2. **Authorization** = What can you do?
3. **JWT** = A signed token containing user data
4. **Stateless** = Server doesn't store session data
5. **SECRET_KEY** = Used to sign tokens (keep it secret!)

---

## Self-Study Questions

1. Why is HTTP considered "stateless"?
2. What are the three parts of a JWT?
3. Can you read the data inside a JWT without the secret key?
4. Why can't you modify a JWT without the server knowing?
5. What's the main advantage of token-based auth over session-based?

---

## Next Chapter

Once you understand these concepts, move to [Chapter 2: User Registration](../chapter-2/README.md)
