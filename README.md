# Authentication Module - Python (Flask) & JavaScript

A beginner-friendly, step-by-step guide to learn authentication from scratch.

---

## Who Is This For?

Students who have completed:
- Flask Basics
- Flask Database
- JavaScript Basics
- JavaScript Advanced

---

## What You Will Learn

By the end of this module, you will be able to:
- Understand and use JWT tokens
- Build Register & Login system
- Protect API routes
- Implement Forgot/Reset Password (local + real email)
- Handle errors properly
- Add Role-Based Access Control
- Use Refresh Tokens
- Verify user emails
- Allow users to change passwords

---

## Module Structure

Each part contains:
```
part-X/
├── frontend/      # HTML + JavaScript + Bootstrap
├── backend/       # Flask API
└── README.md      # Explanation for that part
```

---

## Parts Overview

| Part | Title | What You Learn |
|------|-------|----------------|
| **Part 1** | Understanding JWT | What is JWT, why we need it, create & decode tokens |
| **Part 2** | User Registration | User model, password hashing, `/register` API |
| **Part 3** | User Login | `/login` API, return JWT token, store in frontend |
| **Part 4** | Protected Routes | Verify JWT, access protected APIs |
| **Part 5** | Forgot Password (Local) | Generate reset token, create local reset link |
| **Part 6** | Reset Password (Local) | Verify token, update password |
| **Part 7** | Mailgun Integration | Send real emails for password reset |
| **Part 8** | Error Handling | Proper error responses, frontend error display |
| **Part 9** | Role-Based Access | Admin vs User roles, protect admin routes |
| **Part 10** | Refresh Token & Logout | Token refresh, proper logout |
| **Part 11** | Email Verification | Verify email after registration |
| **Part 12** | Change Password | Logged-in user changes password |

---

## Flow Diagram

```
PART 1: JWT Basics (Theory)
    │
    ▼
PART 2: Register ──► PART 3: Login ──► PART 4: Protected Routes
                                              │
                                              ▼
                         PART 5: Forgot Password (Local)
                                              │
                                              ▼
                         PART 6: Reset Password (Local)
                                              │
                                              ▼
                         PART 7: Mailgun (Real Email)
                                              │
                                              ▼
                         PART 8: Error Handling
                                              │
                                              ▼
                         PART 9: Role-Based Access
                                              │
                                              ▼
                         PART 10: Refresh Token & Logout
                                              │
                                              ▼
                         PART 11: Email Verification
                                              │
                                              ▼
                         PART 12: Change Password
```

---

## How to Use This Module

1. **Start from Part 1** - Don't skip parts
2. **Read the README** of each part first
3. **Type the code yourself** - Don't copy-paste
4. **Run and test** each part before moving forward
5. **Understand inline comments** - They explain the code

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Python, Flask, SQLite |
| Frontend | HTML, JavaScript, Bootstrap 5 |
| Authentication | JWT (JSON Web Tokens) |
| Email | Mailgun (for real emails) |

---

## Prerequisites

Make sure you have installed:
- Python 3.8+
- pip (Python package manager)
- Any code editor (VS Code recommended)
- Web browser (Chrome recommended)

---

## Quick Start for Each Part

### Backend Setup
```bash
cd part-X/backend
pip install -r requirements.txt
python app.py
```

### Open in Browser
Each part runs on its own port:

| Part | URL |
|------|-----|
| Part 1 | http://localhost:5001 |
| Part 2 | http://localhost:5002 |
| Part 3 | http://localhost:5003 |
| Part 4 | http://localhost:5004 |
| Part 5 | http://localhost:5005 |
| Part 6 | http://localhost:5006 |
| Part 7 | http://localhost:5007 |
| Part 8 | http://localhost:5008 |
| Part 9 | http://localhost:5009 |
| Part 10 | http://localhost:5010 |
| Part 11 | http://localhost:5011 |
| Part 12 | http://localhost:5012 |

---

## Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| Module not found | Run `pip install -r requirements.txt` |
| Port already in use | Change port in `app.py` or kill the process |
| CORS error | Make sure Flask-CORS is installed and configured |
| Token expired | Login again to get new token |
| Password reset email not received | **Check Spam/Junk folder!** Emails from sandbox domains often go to spam |
| "Not Found" error | Make sure you're using the correct port (see table above) |

---

## Let's Begin!

Start with [Part 1: Understanding JWT](./part-1/README.md)

---

Happy Learning!
