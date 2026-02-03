# Chapter 13: Production-Ready Authentication Boilerplate

A complete, production-ready authentication system that you can use as a starting point for real projects.

## Features

- **Email/Password Authentication** - Registration, login, password change
- **Google OAuth** - Sign in with Google
- **Email Verification** - Via Mailgun (with development mode fallback)
- **Password Reset** - Secure token-based reset flow
- **JWT Tokens** - Access + Refresh token pattern
- **Rate Limiting** - flask-limiter (Redis-ready)
- **Account Lockout** - Brute force protection
- **Role-Based Access** - User/Admin roles
- **Audit Logging** - Track security events
- **Modular Structure** - Clean, maintainable code

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Copy environment file
cp .env.example .env

# 3. Edit .env with your settings (optional - works without for testing)

# 4. Run the server
cd backend
python app.py

# 5. Open http://localhost:5013
```

## Project Structure

```
chapter-13/
├── backend/
│   ├── app.py              # Main Flask application
│   ├── config.py           # Configuration management
│   ├── models.py           # Database models
│   └── auth/
│       ├── __init__.py     # Blueprint setup
│       ├── routes.py       # All auth endpoints
│       ├── decorators.py   # @token_required, etc.
│       ├── email_service.py # Email sending
│       └── oauth.py        # Google OAuth
├── frontend/
│   ├── index.html          # Landing page
│   ├── login.html          # Login page
│   ├── register.html       # Registration page
│   ├── forgot-password.html
│   ├── reset-password.html
│   ├── verify-email.html
│   ├── dashboard.html      # Protected dashboard
│   └── css/style.css
├── .env.example
├── requirements.txt
└── README.md
```

## API Endpoints

All endpoints are prefixed with `/api`.

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/register` | Register with email/password |
| POST | `/api/login` | Login, returns tokens |
| POST | `/api/refresh` | Refresh access token |
| POST | `/api/logout` | Revoke refresh token |
| POST | `/api/logout-all` | Revoke all sessions |

### Email Verification

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/verify-email` | Verify with token |
| POST | `/api/resend-verification` | Resend verification email |

### Password Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/forgot-password` | Request reset email |
| POST | `/api/reset-password` | Reset with token |
| POST | `/api/change-password` | Change (requires auth) |

### Google OAuth

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/auth/google` | Start OAuth flow |
| GET | `/api/auth/google/callback` | OAuth callback |

### Profile

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/profile` | Get current user |
| PUT | `/api/profile` | Update profile |

## Configuration

### Required for Full Functionality

**Google OAuth** (optional but recommended):
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create OAuth 2.0 credentials
3. Add redirect URI: `http://localhost:5013/api/auth/google/callback`
4. Copy Client ID and Secret to `.env`

**Mailgun** (optional - emails are simulated without it):
1. Sign up at [Mailgun](https://www.mailgun.com/)
2. Get API key and sandbox domain
3. Add authorized recipients (sandbox mode)
4. Copy credentials to `.env`

### Production Deployment

```bash
# Generate secure secrets
python -c "import secrets; print(secrets.token_hex(32))"

# Set in .env
FLASK_ENV=production
SECRET_KEY=<generated-secret>
DATABASE_URL=postgresql://...
REDIS_URL=redis://...
BASE_URL=https://yourdomain.com
```

## Security Features

- **Password Hashing** - Werkzeug's PBKDF2-SHA256
- **JWT Tokens** - Short-lived access (15min), long-lived refresh (7 days)
- **Rate Limiting** - Prevents brute force attacks
- **Account Lockout** - After 5 failed attempts
- **CSRF Protection** - OAuth state parameter
- **Audit Logging** - Track all security events

## Development Mode

Without external services configured:
- Emails are logged to console and links shown in responses
- Google OAuth button will show "not configured"
- All other features work normally

## License

MIT - Use freely in your projects!
