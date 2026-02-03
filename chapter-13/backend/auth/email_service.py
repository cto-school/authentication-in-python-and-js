# ================================================================================
# Email Service
# ================================================================================
# Handles all email sending functionality using Mailgun.
# ================================================================================

import requests
from flask import current_app
from typing import Optional, Dict, Any


def send_email(
    to_email: str,
    subject: str,
    html_content: str,
    text_content: Optional[str] = None
) -> Dict[str, Any]:
    """Send an email using Mailgun API."""

    api_key = current_app.config.get('MAILGUN_API_KEY')
    domain = current_app.config.get('MAILGUN_DOMAIN')
    from_email = current_app.config.get('MAILGUN_FROM_EMAIL')

    if not api_key or not domain:
        # Development mode - log instead of sending
        current_app.logger.info(f"EMAIL (simulated) to {to_email}: {subject}")
        return {
            'success': True,
            'message': 'Email simulated (Mailgun not configured)',
            'simulated': True
        }

    if text_content is None:
        import re
        text_content = re.sub(r'<[^>]+>', '', html_content)
        text_content = re.sub(r'\s+', ' ', text_content).strip()

    try:
        response = requests.post(
            f'https://api.mailgun.net/v3/{domain}/messages',
            auth=('api', api_key),
            data={
                'from': from_email,
                'to': to_email,
                'subject': subject,
                'html': html_content,
                'text': text_content
            },
            timeout=10
        )

        if response.status_code == 200:
            return {'success': True, 'message': 'Email sent'}
        else:
            current_app.logger.error(f"Mailgun error: {response.status_code} - {response.text}")
            return {'success': False, 'error': f'Email service error: {response.status_code}'}

    except Exception as e:
        current_app.logger.error(f"Email exception: {e}")
        return {'success': False, 'error': str(e)}


def send_verification_email(to_email: str, name: str, verification_link: str) -> Dict[str, Any]:
    """Send verification email."""
    html = f'''
    <!DOCTYPE html>
    <html>
    <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
        <table width="100%" cellspacing="0" cellpadding="0" style="max-width: 600px; margin: 0 auto; background: #fff;">
            <tr>
                <td style="padding: 40px 30px; text-align: center; background: #4CAF50;">
                    <h1 style="color: #fff; margin: 0;">Verify Your Email</h1>
                </td>
            </tr>
            <tr>
                <td style="padding: 40px 30px;">
                    <p>Hi <strong>{name}</strong>,</p>
                    <p>Please verify your email by clicking the button below:</p>
                    <table style="margin: 30px auto;"><tr>
                        <td style="background: #4CAF50; border-radius: 5px;">
                            <a href="{verification_link}" style="display: inline-block; padding: 15px 30px; color: #fff; text-decoration: none; font-weight: bold;">
                                Verify Email
                            </a>
                        </td>
                    </tr></table>
                    <p style="font-size: 12px; color: #666;">Link expires in 24 hours.</p>
                    <p style="font-size: 11px; color: #999; word-break: break-all;">{verification_link}</p>
                </td>
            </tr>
        </table>
    </body>
    </html>
    '''
    return send_email(to_email, 'Verify Your Email', html)


def send_password_reset_email(to_email: str, name: str, reset_link: str) -> Dict[str, Any]:
    """Send password reset email."""
    html = f'''
    <!DOCTYPE html>
    <html>
    <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
        <table width="100%" cellspacing="0" cellpadding="0" style="max-width: 600px; margin: 0 auto; background: #fff;">
            <tr>
                <td style="padding: 40px 30px; text-align: center; background: #2196F3;">
                    <h1 style="color: #fff; margin: 0;">Reset Your Password</h1>
                </td>
            </tr>
            <tr>
                <td style="padding: 40px 30px;">
                    <p>Hi <strong>{name}</strong>,</p>
                    <p>Click the button below to reset your password:</p>
                    <table style="margin: 30px auto;"><tr>
                        <td style="background: #2196F3; border-radius: 5px;">
                            <a href="{reset_link}" style="display: inline-block; padding: 15px 30px; color: #fff; text-decoration: none; font-weight: bold;">
                                Reset Password
                            </a>
                        </td>
                    </tr></table>
                    <p style="font-size: 12px; color: #666;">Link expires in 1 hour.</p>
                    <p style="font-size: 12px; color: #856404; background: #fff3cd; padding: 10px; border-radius: 5px;">
                        If you didn't request this, ignore this email.
                    </p>
                </td>
            </tr>
        </table>
    </body>
    </html>
    '''
    return send_email(to_email, 'Reset Your Password', html)


def send_welcome_email(to_email: str, name: str) -> Dict[str, Any]:
    """Send welcome email after verification."""
    html = f'''
    <!DOCTYPE html>
    <html>
    <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
        <table width="100%" cellspacing="0" cellpadding="0" style="max-width: 600px; margin: 0 auto; background: #fff;">
            <tr>
                <td style="padding: 40px 30px; text-align: center; background: #673AB7;">
                    <h1 style="color: #fff; margin: 0;">Welcome!</h1>
                </td>
            </tr>
            <tr>
                <td style="padding: 40px 30px; text-align: center;">
                    <p style="font-size: 18px;">Hi <strong>{name}</strong>,</p>
                    <p>Your email has been verified. You're all set!</p>
                    <p style="color: #666;">Thank you for joining us.</p>
                </td>
            </tr>
        </table>
    </body>
    </html>
    '''
    return send_email(to_email, 'Welcome!', html)
