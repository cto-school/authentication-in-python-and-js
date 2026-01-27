# Part 7: Mailgun Integration

## What You Will Learn

1. Set up Mailgun account
2. Configure Mailgun in Flask
3. Send real password reset emails
4. Handle email sending errors

---

## What is Mailgun?

Mailgun is an email service that lets your app send emails.

**Why use Mailgun?**
- Your app can send emails programmatically
- Better deliverability than regular SMTP
- Free tier available (for testing)
- Easy API

---

## Setting Up Mailgun

### Step 1: Create Account

1. Go to [mailgun.com](https://www.mailgun.com/)
2. Sign up for free account
3. Verify your email

### Step 2: Get API Key

1. Go to Dashboard
2. Click on "API Keys" in sidebar
3. Copy your "Private API Key"

### Step 3: Get Domain

1. Mailgun gives you a sandbox domain for testing
2. It looks like: `sandbox123abc.mailgun.org`
3. Copy this domain

### Step 4: Add Authorized Recipient (Sandbox)

For sandbox domain, you can only send to authorized emails:
1. Go to "Sending" > "Domains"
2. Click your sandbox domain
3. Add your email as "Authorized Recipient"
4. Verify by clicking link in email

---

## Environment Variables

Never put API keys directly in code!

Create a `.env` file:
```
MAILGUN_API_KEY=your-api-key-here
MAILGUN_DOMAIN=sandbox123abc.mailgun.org
```

---

## How Email Sending Works

```
1. User requests password reset
2. Backend generates reset token
3. Backend builds email content with reset link
4. Backend calls Mailgun API
5. Mailgun sends email to user
6. User receives email with reset link
```

---

## Files in This Part

```
part-7/
├── backend/
│   ├── app.py              # Flask API with Mailgun
│   ├── requirements.txt    # Required packages
│   └── .env.example        # Example environment file
├── frontend/
│   └── index.html          # Test email sending
└── README.md               # You are here
```

---

## How to Run

### Step 1: Install packages
```bash
cd part-7/backend
pip install -r requirements.txt
```

### Step 2: Create .env file
```bash
# Copy example file
cp .env.example .env

# Edit .env with your Mailgun credentials
```

### Step 3: Run the server
```bash
python app.py
```

### Step 4: Open in browser
```
http://localhost:5007
```

---

## API Changes

### POST /forgot-password

Now sends actual email instead of returning link.

**Request:**
```json
{
    "email": "john@example.com"
}
```

**Success Response (200):**
```json
{
    "message": "Password reset email sent! Check your inbox."
}
```

**Note:** For security, we don't reveal if email exists or not.

---

## Email Template

The email sent looks like:

```
Subject: Password Reset Request

Hello,

You requested to reset your password.

Click the link below to reset your password:
http://localhost:5007/reset-password?token=abc123...

This link expires in 1 hour.

If you didn't request this, ignore this email.
```

> **⚠️ Note:** Reset password emails often go to **Spam/Junk folder**. If you don't receive the email in your inbox, please check your spam folder!

---

## Testing Modes

The app supports two modes:

| Mode | When | What happens |
|------|------|--------------|
| Local | MAILGUN_API_KEY not set | Returns reset link in response |
| Email | MAILGUN_API_KEY set | Sends real email via Mailgun |

This lets you test without Mailgun setup.

---

## Common Issues

### "Unauthorized" Error
- Check if API key is correct
- Make sure no extra spaces in .env file

### "Domain not found"
- Check if domain is correct
- Use sandbox domain for testing

### Email not received
- **⚠️ CHECK SPAM/JUNK FOLDER FIRST!** - Reset emails often go to spam
- Make sure recipient is authorized (sandbox)
- Wait a few minutes (emails can be delayed)
- Check Mailgun logs in dashboard

> **Important:** Password reset emails from sandbox domains are often marked as spam by email providers. Always check your Spam/Junk folder if you don't see the email in your inbox!

---

## Security Best Practices

1. **Never expose API key** - Use environment variables
2. **Don't reveal email existence** - Always say "If email exists..."
3. **Use HTTPS in production** - For reset links
4. **Rate limit** - Prevent email spam (covered in Part 8)

---

## Test Your Understanding

Before moving to next part:

1. Why do we use environment variables for API keys?
2. What is a sandbox domain?
3. Why shouldn't we reveal if email exists?
4. What information is in the reset email?

---

## Next Part

Once email sending works, move to [Part 8: Error Handling](../part-8/README.md)
