# Authentication Mastery - Python (Flask) & JavaScript

A structured, 13-chapter guide to building production-ready authentication systems.

---

## Course Structure

```
TIER 1: Foundation (Chapters 1-4)
Build a working authentication system

    Chapter 1: Introduction & Setup
         |
         v
    Chapter 2: User Registration
         |
         v
    Chapter 3: User Login & JWT
         |
         v
    Chapter 4: Protected Routes
         |
    [MILESTONE: Working Auth System]


TIER 2: Production-Ready (Chapters 5-7)
Make it ready for real users

    Chapter 5: Error Handling
         |
         v
    Chapter 6: Email Verification
         |
         v
    Chapter 7: Password Management
         |
    [MILESTONE: Production-Ready Auth]


TIER 3: Advanced (Chapters 8-10)
Enterprise-grade features

    Chapter 8: Refresh Tokens
         |
         v
    Chapter 9: Role-Based Access Control
         |
         v
    Chapter 10: Security Best Practices
         |
    [MILESTONE: Enterprise-Grade Auth]


TIER 4: Real-World Integration (Chapters 11-13)
Production deployment features

    Chapter 11: Email Integration (Mailgun)
         |
         v
    Chapter 12: Google OAuth
         |
         v
    Chapter 13: Production Boilerplate
         |
    [MILESTONE: Production-Ready Boilerplate]
```

---

## Quick Start

```bash
# Pick any chapter and run:
cd chapter-X/backend
pip install -r requirements.txt
python app.py

# Then open browser to the chapter's port (see table below)
```

---

## Chapter Overview

| Chapter | Title | Port | Key Concepts |
|---------|-------|------|--------------|
| **TIER 1: Foundation** ||||
| 1 | Introduction & Setup | 5001 | JWT basics, environment setup |
| 2 | User Registration | 5002 | Password hashing, User model |
| 3 | User Login & JWT | 5003 | Token creation, verification |
| 4 | Protected Routes | 5004 | Decorators, `@token_required` |
| **TIER 2: Production-Ready** ||||
| 5 | Error Handling | 5005 | Standard responses, validation |
| 6 | Email Verification | 5006 | Verification tokens, `@verified_required` |
| 7 | Password Management | 5007 | Change password, forgot/reset |
| **TIER 3: Advanced** ||||
| 8 | Refresh Tokens | 5008 | Access/refresh pattern, blacklisting |
| 9 | Role-Based Access Control | 5009 | Roles, `@admin_required`, 401 vs 403 |
| 10 | Security Best Practices | 5010 | Rate limiting, lockout, audit logs |
| **TIER 4: Real-World Integration** ||||
| 11 | Email Integration | 5011 | Mailgun, HTML templates, real emails |
| 12 | Google OAuth | 5012 | OAuth 2.0, social login |
| 13 | Production Boilerplate | 5013 | Complete starter, flask-limiter, modular code |

---

## Who Is This For?

Students who have completed:
- Flask Basics
- Flask Database (SQLAlchemy)
- JavaScript Basics

---

## What You Will Learn

By the end of this course, you will be able to:

**Tier 1 - Foundation:**
- Understand JWT tokens and how they work
- Hash passwords securely
- Build Register & Login APIs
- Protect routes with decorators

**Tier 2 - Production-Ready:**
- Handle errors consistently
- Implement email verification
- Build password reset flows

**Tier 3 - Advanced:**
- Use refresh tokens for better security
- Implement role-based access control
- Add rate limiting and audit logging

**Tier 4 - Real-World Integration:**
- Send real emails with Mailgun
- Implement Google OAuth (Sign in with Google)
- Build a production-ready boilerplate you can use

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Python 3.8+, Flask, SQLAlchemy |
| Database | SQLite |
| Frontend | HTML, JavaScript, Bootstrap 5 |
| Authentication | JWT (pyjwt library) |
| Password Security | werkzeug.security |

---

## Project Structure

Each chapter follows a consistent structure:

```
chapter-X/
├── backend/
│   ├── app.py           # Flask application
│   └── requirements.txt # Dependencies
├── frontend/
│   └── index.html       # Test interface
└── README.md            # Chapter explanation
```

---

## Key Concepts Covered

| Concept | Chapter | Description |
|---------|---------|-------------|
| Password Hashing | 2 | Never store plain passwords |
| JWT Tokens | 3 | Stateless authentication |
| Decorators | 4 | `@token_required` pattern |
| HTTP Status Codes | 5 | 400, 401, 403, 404, 409, 500 |
| Email Verification | 6 | Verify user owns email |
| Token Expiry | 7, 8 | Short-lived tokens |
| Refresh Tokens | 8 | Renew access without login |
| RBAC | 9 | Role-based permissions |
| Rate Limiting | 10, 13 | Prevent brute force |
| Account Lockout | 10, 13 | Lock after failed attempts |
| Audit Logging | 10, 13 | Track security events |
| Real Email | 11, 13 | Mailgun integration |
| OAuth 2.0 | 12, 13 | Google Sign-In |
| flask-limiter | 13 | Production rate limiting |

---

## How to Use This Course

1. **Start from Chapter 1** - Each chapter builds on previous ones
2. **Read the README first** - Understand the concept before coding
3. **Type the code yourself** - Don't just copy-paste
4. **Test with the frontend** - Each chapter has a test interface
5. **Read the comments** - They explain WHY, not just WHAT

---

## Prerequisites

- Python 3.8+
- pip (Python package manager)
- Code editor (VS Code recommended)
- Web browser (Chrome recommended)

---

## Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| Module not found | Run `pip install -r requirements.txt` |
| Port already in use | Change port in `app.py` or kill the process |
| CORS error | Make sure Flask-CORS is installed |
| Token expired | Login again to get new token |
| Database locked | Close other connections, restart server |

---

## FAQ

**Q: Can I skip Tier 1 if I know the basics?**
A: Each tier is designed to be self-contained, but concepts build on each other. At minimum, skim the READMEs.

**Q: Do I need to set up email for Chapter 6-7?**
A: No! The chapters simulate email by printing to console. Real email integration is optional.

**Q: Which tier should I complete?**
A: Tier 1 for learning projects, Tier 2 for real applications, Tier 3-4 for production systems.

**Q: Can I use Chapter 13 as a starter for my project?**
A: Yes! Chapter 13 is designed as a production-ready boilerplate. Copy it and customize for your needs.

---

## Let's Begin!

Start with [Chapter 1: Introduction & Setup](./chapter-1/README.md)

---

Happy Learning!
