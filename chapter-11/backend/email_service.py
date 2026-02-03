# ================================================================================
# CHAPTER 11: Email Service Module
# ================================================================================
# This module handles all email sending functionality using Mailgun API.
#
# WHY MAILGUN?
#   - Free tier: 5,000 emails/month (perfect for learning & small projects)
#   - Simple REST API (no complex SMTP setup)
#   - Excellent deliverability
#   - Easy to switch to SendGrid/AWS SES later (same pattern)
#
# ALTERNATIVES:
#   - SendGrid: Similar free tier, popular choice
#   - AWS SES: Cheapest at scale, more setup required
#   - Postmark: Great deliverability, transactional focus
#
# ================================================================================

import requests
import os
from typing import Optional, Dict, Any

# ================================================================================
# EMAIL CONFIGURATION
# ================================================================================
# These values come from environment variables (never hardcode secrets!)
#
# MAILGUN_API_KEY: Your Mailgun API key (starts with "key-")
# MAILGUN_DOMAIN: Your Mailgun domain (sandbox or custom)
# MAILGUN_FROM_EMAIL: The "from" address for emails
# ================================================================================

MAILGUN_API_KEY = os.environ.get('MAILGUN_API_KEY', '')
MAILGUN_DOMAIN = os.environ.get('MAILGUN_DOMAIN', '')
MAILGUN_FROM_EMAIL = os.environ.get('MAILGUN_FROM_EMAIL', 'noreply@example.com')
MAILGUN_API_URL = f'https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages'


def send_email(
    to_email: str,
    subject: str,
    html_content: str,
    text_content: Optional[str] = None
) -> Dict[str, Any]:
    """
    Send an email using Mailgun API.

    Args:
        to_email: Recipient email address
        subject: Email subject line
        html_content: HTML body of the email
        text_content: Plain text fallback (auto-generated if not provided)

    Returns:
        Dict with 'success' boolean and 'message' or 'error'

    Example:
        result = send_email(
            to_email='user@example.com',
            subject='Verify your email',
            html_content='<h1>Welcome!</h1><p>Click here to verify...</p>'
        )
        if result['success']:
            print('Email sent!')
        else:
            print(f'Failed: {result["error"]}')
    """

    # Check if Mailgun is configured
    if not MAILGUN_API_KEY or not MAILGUN_DOMAIN:
        return {
            'success': False,
            'error': 'Mailgun not configured. Set MAILGUN_API_KEY and MAILGUN_DOMAIN environment variables.',
            'simulated': True
        }

    # Generate plain text from HTML if not provided
    if text_content is None:
        # Simple HTML tag stripping (for production, use a proper library like beautifulsoup)
        import re
        text_content = re.sub(r'<[^>]+>', '', html_content)
        text_content = re.sub(r'\s+', ' ', text_content).strip()

    # Prepare the request
    try:
        response = requests.post(
            MAILGUN_API_URL,
            auth=('api', MAILGUN_API_KEY),
            data={
                'from': MAILGUN_FROM_EMAIL,
                'to': to_email,
                'subject': subject,
                'html': html_content,
                'text': text_content
            },
            timeout=10  # 10 second timeout
        )

        # Check response
        if response.status_code == 200:
            return {
                'success': True,
                'message': 'Email sent successfully',
                'mailgun_id': response.json().get('id')
            }
        else:
            return {
                'success': False,
                'error': f'Mailgun error: {response.status_code} - {response.text}'
            }

    except requests.exceptions.Timeout:
        return {
            'success': False,
            'error': 'Email service timeout. Please try again.'
        }
    except requests.exceptions.RequestException as e:
        return {
            'success': False,
            'error': f'Email service error: {str(e)}'
        }


# ================================================================================
# EMAIL TEMPLATES
# ================================================================================
# These functions generate HTML email content.
# In production, you might use Jinja2 templates stored in files.
# ================================================================================

def get_verification_email_html(username: str, verification_link: str) -> str:
    """Generate HTML for verification email."""
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width: 600px; margin: 0 auto; background-color: #ffffff;">
            <tr>
                <td style="padding: 40px 30px; text-align: center; background-color: #4CAF50;">
                    <h1 style="color: #ffffff; margin: 0; font-size: 28px;">Verify Your Email</h1>
                </td>
            </tr>
            <tr>
                <td style="padding: 40px 30px;">
                    <p style="font-size: 16px; color: #333333; margin-bottom: 20px;">
                        Hi <strong>{username}</strong>,
                    </p>
                    <p style="font-size: 16px; color: #333333; margin-bottom: 20px;">
                        Thank you for registering! Please verify your email address by clicking the button below:
                    </p>
                    <table role="presentation" cellspacing="0" cellpadding="0" style="margin: 30px auto;">
                        <tr>
                            <td style="background-color: #4CAF50; border-radius: 5px;">
                                <a href="{verification_link}"
                                   style="display: inline-block; padding: 15px 30px; color: #ffffff; text-decoration: none; font-size: 16px; font-weight: bold;">
                                    Verify Email Address
                                </a>
                            </td>
                        </tr>
                    </table>
                    <p style="font-size: 14px; color: #666666; margin-top: 30px;">
                        Or copy and paste this link into your browser:
                    </p>
                    <p style="font-size: 12px; color: #4CAF50; word-break: break-all;">
                        {verification_link}
                    </p>
                    <p style="font-size: 14px; color: #666666; margin-top: 30px;">
                        This link will expire in <strong>24 hours</strong>.
                    </p>
                    <p style="font-size: 14px; color: #666666;">
                        If you didn't create an account, you can safely ignore this email.
                    </p>
                </td>
            </tr>
            <tr>
                <td style="padding: 20px 30px; background-color: #f8f8f8; text-align: center;">
                    <p style="font-size: 12px; color: #999999; margin: 0;">
                        This is an automated message. Please do not reply.
                    </p>
                </td>
            </tr>
        </table>
    </body>
    </html>
    '''


def get_password_reset_email_html(username: str, reset_link: str) -> str:
    """Generate HTML for password reset email."""
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width: 600px; margin: 0 auto; background-color: #ffffff;">
            <tr>
                <td style="padding: 40px 30px; text-align: center; background-color: #2196F3;">
                    <h1 style="color: #ffffff; margin: 0; font-size: 28px;">Reset Your Password</h1>
                </td>
            </tr>
            <tr>
                <td style="padding: 40px 30px;">
                    <p style="font-size: 16px; color: #333333; margin-bottom: 20px;">
                        Hi <strong>{username}</strong>,
                    </p>
                    <p style="font-size: 16px; color: #333333; margin-bottom: 20px;">
                        We received a request to reset your password. Click the button below to create a new password:
                    </p>
                    <table role="presentation" cellspacing="0" cellpadding="0" style="margin: 30px auto;">
                        <tr>
                            <td style="background-color: #2196F3; border-radius: 5px;">
                                <a href="{reset_link}"
                                   style="display: inline-block; padding: 15px 30px; color: #ffffff; text-decoration: none; font-size: 16px; font-weight: bold;">
                                    Reset Password
                                </a>
                            </td>
                        </tr>
                    </table>
                    <p style="font-size: 14px; color: #666666; margin-top: 30px;">
                        Or copy and paste this link into your browser:
                    </p>
                    <p style="font-size: 12px; color: #2196F3; word-break: break-all;">
                        {reset_link}
                    </p>
                    <p style="font-size: 14px; color: #666666; margin-top: 30px;">
                        This link will expire in <strong>1 hour</strong>.
                    </p>
                    <div style="margin-top: 30px; padding: 15px; background-color: #fff3cd; border-radius: 5px;">
                        <p style="font-size: 14px; color: #856404; margin: 0;">
                            <strong>Didn't request this?</strong><br>
                            If you didn't request a password reset, please ignore this email or contact support if you're concerned about your account security.
                        </p>
                    </div>
                </td>
            </tr>
            <tr>
                <td style="padding: 20px 30px; background-color: #f8f8f8; text-align: center;">
                    <p style="font-size: 12px; color: #999999; margin: 0;">
                        This is an automated message. Please do not reply.
                    </p>
                </td>
            </tr>
        </table>
    </body>
    </html>
    '''


# ================================================================================
# CONVENIENCE FUNCTIONS
# ================================================================================
# These wrap send_email() with proper templates for common use cases.
# ================================================================================

def send_verification_email(to_email: str, username: str, verification_link: str) -> Dict[str, Any]:
    """
    Send a verification email to a new user.

    Args:
        to_email: User's email address
        username: User's display name (or email if no username)
        verification_link: Full URL for verification

    Returns:
        Result dict from send_email()
    """
    html_content = get_verification_email_html(username, verification_link)
    return send_email(
        to_email=to_email,
        subject='Verify Your Email Address',
        html_content=html_content
    )


def send_password_reset_email(to_email: str, username: str, reset_link: str) -> Dict[str, Any]:
    """
    Send a password reset email.

    Args:
        to_email: User's email address
        username: User's display name (or email if no username)
        reset_link: Full URL for password reset

    Returns:
        Result dict from send_email()
    """
    html_content = get_password_reset_email_html(username, reset_link)
    return send_email(
        to_email=to_email,
        subject='Reset Your Password',
        html_content=html_content
    )


# ================================================================================
# TESTING / DEVELOPMENT MODE
# ================================================================================
# When Mailgun is not configured, we can simulate email sending.
# This is useful for development and testing.
# ================================================================================

def send_email_dev_mode(
    to_email: str,
    subject: str,
    html_content: str,
    text_content: Optional[str] = None
) -> Dict[str, Any]:
    """
    Development mode: Log email instead of sending.
    Useful when Mailgun is not configured.
    """
    print("\n" + "=" * 60)
    print("EMAIL (Development Mode - Not Actually Sent)")
    print("=" * 60)
    print(f"To: {to_email}")
    print(f"Subject: {subject}")
    print("-" * 60)
    if text_content:
        print(text_content[:500] + "..." if len(text_content) > 500 else text_content)
    print("=" * 60 + "\n")

    return {
        'success': True,
        'message': 'Email logged (development mode)',
        'simulated': True
    }
