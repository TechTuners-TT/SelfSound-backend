import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import logging
from typing import Optional, List
from pydantic import BaseModel
from config import (
    EMAIL_SENDER,
    EMAIL_PASSWORD,
    SMTP_HOST,
    SMTP_PORT,
    FRONTEND_REDIRECT_URL
)

# Set up logging
logger = logging.getLogger(__name__)


class EmailVerification(BaseModel):
    token: str


class EmailConfig:
    """Email configuration class"""

    def __init__(self):
        self.smtp_host = SMTP_HOST
        self.smtp_port = SMTP_PORT
        self.sender_email = EMAIL_SENDER
        self.sender_password = EMAIL_PASSWORD
        self.frontend_url = FRONTEND_REDIRECT_URL

    def validate_config(self):
        """Validate that all required email configuration is present"""
        if not all([self.smtp_host, self.smtp_port, self.sender_email, self.sender_password]):
            raise ValueError("Missing required email configuration. Check your environment variables.")


email_config = EmailConfig()


def create_smtp_connection():
    """Create and return an SMTP connection with improved error handling"""
    try:
        logger.info(f"Connecting to SMTP server: {email_config.smtp_host}:{email_config.smtp_port}")

        # Try SSL connection first for port 465
        if email_config.smtp_port == 465:
            logger.info("Using SSL connection (port 465)")
            server = smtplib.SMTP_SSL(email_config.smtp_host, email_config.smtp_port, timeout=30)
        else:
            # Use regular SMTP for port 587
            logger.info("Using TLS connection (port 587)")
            server = smtplib.SMTP(email_config.smtp_host, email_config.smtp_port, timeout=30)

        # Enable debug mode for troubleshooting
        server.set_debuglevel(0)  # Set to 1 for detailed debug output

        # For non-SSL connections, start TLS
        if email_config.smtp_port != 465:
            # Say hello to the server
            server.ehlo()

            # Enable security
            logger.info("Starting TLS...")
            server.starttls()

            # Say hello again after TLS
            server.ehlo()

        # Login
        logger.info(f"Logging in as: {email_config.sender_email}")
        server.login(email_config.sender_email, email_config.sender_password)

        logger.info("SMTP connection successful")
        return server

    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"SMTP Authentication failed: {str(e)}")
        logger.error("Check your email and app password. Make sure 2FA is enabled and you're using an app password.")
        raise Exception(f"Email authentication failed. Please check your credentials: {str(e)}")

    except smtplib.SMTPServerDisconnected as e:
        logger.error(f"SMTP Server disconnected: {str(e)}")
        logger.error("Gmail may be blocking the connection. Try using port 465 with SSL.")
        raise Exception(f"SMTP server disconnected. Try different port settings: {str(e)}")

    except smtplib.SMTPConnectError as e:
        logger.error(f"Cannot connect to SMTP server: {str(e)}")
        raise Exception(f"Cannot connect to email server. Check your internet connection: {str(e)}")

    except Exception as e:
        logger.error(f"Failed to create SMTP connection: {str(e)}")
        logger.error(f"Error type: {type(e)}")
        raise Exception(f"Email connection failed: {str(e)}")


def send_email(
        to_email: str,
        subject: str,
        html_body: str,
        text_body: Optional[str] = None,
        attachments: Optional[List[str]] = None
):
    """
    Send an email with HTML and optional text body and attachments

    Args:
        to_email: Recipient email address
        subject: Email subject
        html_body: HTML content of the email
        text_body: Optional plain text version
        attachments: Optional list of file paths to attach
    """
    try:
        # Validate email configuration
        email_config.validate_config()

        # Create message
        msg = MIMEMultipart('alternative')
        msg['From'] = email_config.sender_email
        msg['To'] = to_email
        msg['Subject'] = subject

        # Add text part if provided
        if text_body:
            text_part = MIMEText(text_body, 'plain')
            msg.attach(text_part)

        # Add HTML part
        html_part = MIMEText(html_body, 'html')
        msg.attach(html_part)

        # Add attachments if provided
        if attachments:
            for file_path in attachments:
                try:
                    with open(file_path, "rb") as attachment:
                        part = MIMEBase('application', 'octet-stream')
                        part.set_payload(attachment.read())

                    encoders.encode_base64(part)
                    part.add_header(
                        'Content-Disposition',
                        f'attachment; filename= {file_path.split("/")[-1]}'
                    )
                    msg.attach(part)
                except Exception as e:
                    logger.warning(f"Failed to attach file {file_path}: {str(e)}")

        # Send email
        server = create_smtp_connection()
        server.sendmail(email_config.sender_email, to_email, msg.as_string())
        server.quit()

        logger.info(f"Email sent successfully to {to_email}")

    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {str(e)}")
        raise


async def send_verification_email(email: str, token: str):
    """
    Send email verification email to user

    Args:
        email: User's email address
        token: Verification token
    """
    try:
        logger.info(f"Sending verification email to: {email}")

        # Validate email configuration first
        email_config.validate_config()

        # Create verification URL - This will be a direct backend call that redirects
        verification_url = f"https://backend-m5qb.onrender.com/authorization/verify-email?token={token}"
        logger.info(f"Verification URL: {verification_url}")

        # Email subject
        subject = "Verify Your Email Address"

        # HTML email body
        html_body = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Email Verification</title>
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    background-color: #f4f4f4;
                    margin: 0;
                    padding: 20px;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    background-color: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                    overflow: hidden;
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 40px 20px;
                    text-align: center;
                }}
                .header h1 {{
                    margin: 0;
                    font-size: 24px;
                    font-weight: 600;
                }}
                .content {{
                    padding: 40px 20px;
                }}
                .content h2 {{
                    color: #333;
                    margin-bottom: 20px;
                    font-size: 20px;
                }}
                .content p {{
                    margin-bottom: 20px;
                    color: #666;
                }}
                .verify-button {{
                    display: inline-block;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    text-decoration: none;
                    padding: 15px 30px;
                    border-radius: 6px;
                    font-weight: 600;
                    margin: 20px 0;
                    transition: transform 0.2s;
                }}
                .verify-button:hover {{
                    transform: translateY(-2px);
                }}
                .url-fallback {{
                    background-color: #f8f9fa;
                    border: 1px solid #dee2e6;
                    border-radius: 4px;
                    padding: 15px;
                    margin: 20px 0;
                    word-break: break-all;
                    font-family: monospace;
                    font-size: 14px;
                    color: #495057;
                }}
                .footer {{
                    background-color: #f8f9fa;
                    padding: 20px;
                    text-align: center;
                    color: #6c757d;
                    font-size: 14px;
                }}
                .warning {{
                    background-color: #fff3cd;
                    border: 1px solid #ffeaa7;
                    border-radius: 4px;
                    padding: 15px;
                    margin: 20px 0;
                    color: #856404;
                }}
                @media (max-width: 600px) {{
                    .container {{
                        margin: 0;
                        border-radius: 0;
                    }}
                    .content {{
                        padding: 20px;
                    }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Welcome! 🎉</h1>
                </div>

                <div class="content">
                    <h2>Please verify your email address</h2>

                    <p>Thank you for signing up! To complete your registration and secure your account, please verify your email address by clicking the button below:</p>

                    <div style="text-align: center;">
                        <a href="{verification_url}" class="verify-button">
                            Verify Email Address
                        </a>
                    </div>

                    <p>If the button above doesn't work, you can copy and paste the following link into your browser:</p>

                    <div class="url-fallback">
                        {verification_url}
                    </div>

                    <div class="warning">
                        <strong>⏰ Important:</strong> This verification link will expire in 24 hours for security reasons.
                    </div>

                    <p>If you didn't create an account with us, you can safely ignore this email.</p>
                </div>

                <div class="footer">
                    <p>This is an automated email. Please do not reply to this message.</p>
                    <p>If you have any questions, please contact our support team.</p>
                </div>
            </div>
        </body>
        </html>
        """

        # Plain text version (fallback)
        text_body = f"""
        Welcome!

        Please verify your email address to complete your registration.

        Click the link below or copy it into your browser:
        {verification_url}

        This link will expire in 24 hours.

        If you didn't create an account, please ignore this email.
        """

        # Create message
        msg = MIMEMultipart('alternative')
        msg['From'] = email_config.sender_email
        msg['To'] = email
        msg['Subject'] = subject

        # Add text part
        text_part = MIMEText(text_body, 'plain')
        msg.attach(text_part)

        # Add HTML part
        html_part = MIMEText(html_body, 'html')
        msg.attach(html_part)

        # Try multiple SMTP connection attempts
        max_retries = 3
        for attempt in range(max_retries):
            try:
                logger.info(f"Email sending attempt {attempt + 1}/{max_retries}")

                # Create SMTP connection
                server = create_smtp_connection()

                # Send email
                logger.info("Sending email...")
                server.sendmail(email_config.sender_email, email, msg.as_string())

                # Close connection
                server.quit()

                logger.info(f"Verification email sent successfully to {email}")
                return  # Success - exit the function

            except Exception as e:
                logger.error(f"Attempt {attempt + 1} failed: {str(e)}")
                if attempt == max_retries - 1:  # Last attempt
                    raise e
                else:
                    # Wait before retrying
                    import time
                    time.sleep(2)

    except Exception as e:
        logger.error(f"Failed to send verification email to {email}: {str(e)}")
        # Don't raise the exception here since this is called from a background task
        # The signup should still succeed even if email sending fails


async def send_password_reset_email(email: str, reset_token: str):
    """
    Send password reset email to user

    Args:
        email: User's email address
        reset_token: Password reset token
    """
    try:
        logger.info(f"Sending password reset email to: {email}")

        # Create reset URL
        reset_url = f"{email_config.frontend_url}/reset-password?token={reset_token}"

        # Email subject
        subject = "Reset Your Password"

        # HTML email body
        html_body = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Password Reset</title>
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    background-color: #f4f4f4;
                    margin: 0;
                    padding: 20px;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    background-color: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                    overflow: hidden;
                }}
                .header {{
                    background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
                    color: white;
                    padding: 40px 20px;
                    text-align: center;
                }}
                .content {{
                    padding: 40px 20px;
                }}
                .reset-button {{
                    display: inline-block;
                    background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
                    color: white;
                    text-decoration: none;
                    padding: 15px 30px;
                    border-radius: 6px;
                    font-weight: 600;
                    margin: 20px 0;
                }}
                .url-fallback {{
                    background-color: #f8f9fa;
                    border: 1px solid #dee2e6;
                    border-radius: 4px;
                    padding: 15px;
                    margin: 20px 0;
                    word-break: break-all;
                    font-family: monospace;
                    font-size: 14px;
                }}
                .warning {{
                    background-color: #fff3cd;
                    border: 1px solid #ffeaa7;
                    border-radius: 4px;
                    padding: 15px;
                    margin: 20px 0;
                    color: #856404;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔒 Password Reset</h1>
                </div>

                <div class="content">
                    <h2>Reset your password</h2>

                    <p>We received a request to reset your password. Click the button below to create a new password:</p>

                    <div style="text-align: center;">
                        <a href="{reset_url}" class="reset-button">
                            Reset Password
                        </a>
                    </div>

                    <p>Or copy and paste this link:</p>
                    <div class="url-fallback">{reset_url}</div>

                    <div class="warning">
                        <strong>⏰ Important:</strong> This link expires in 1 hour for security reasons.
                    </div>

                    <p>If you didn't request a password reset, please ignore this email or contact support if you have concerns.</p>
                </div>
            </div>
        </body>
        </html>
        """

        # Plain text version
        text_body = f"""
        Password Reset Request

        We received a request to reset your password.

        Click the link below to reset your password:
        {reset_url}

        This link expires in 1 hour.

        If you didn't request this, please ignore this email.
        """

        # Send the email
        send_email(
            to_email=email,
            subject=subject,
            html_body=html_body,
            text_body=text_body
        )

        logger.info(f"Password reset email sent successfully to {email}")

    except Exception as e:
        logger.error(f"Failed to send password reset email to {email}: {str(e)}")
        raise


async def send_welcome_email(email: str, name: str):
    """
    Send welcome email to newly verified user

    Args:
        email: User's email address
        name: User's name
    """
    try:
        logger.info(f"Sending welcome email to: {email}")

        # Email subject
        subject = f"Welcome to our platform, {name}!"

        # HTML email body
        html_body = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Welcome!</title>
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    background-color: #f4f4f4;
                    margin: 0;
                    padding: 20px;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    background-color: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                    overflow: hidden;
                }}
                .header {{
                    background: linear-gradient(135deg, #2ecc71 0%, #27ae60 100%);
                    color: white;
                    padding: 40px 20px;
                    text-align: center;
                }}
                .content {{
                    padding: 40px 20px;
                }}
                .dashboard-button {{
                    display: inline-block;
                    background: linear-gradient(135deg, #2ecc71 0%, #27ae60 100%);
                    color: white;
                    text-decoration: none;
                    padding: 15px 30px;
                    border-radius: 6px;
                    font-weight: 600;
                    margin: 20px 0;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🎉 Welcome, {name}!</h1>
                </div>

                <div class="content">
                    <h2>Your account is now active!</h2>

                    <p>Congratulations! Your email has been verified and your account is ready to use.</p>

                    <p>You can now:</p>
                    <ul>
                        <li>Access your dashboard</li>
                        <li>Customize your profile</li>
                        <li>Explore all features</li>
                    </ul>

                    <div style="text-align: center;">
                        <a href="{email_config.frontend_url}/dashboard" class="dashboard-button">
                            Go to Dashboard
                        </a>
                    </div>

                    <p>If you have any questions, feel free to reach out to our support team.</p>

                    <p>Welcome aboard!</p>
                </div>
            </div>
        </body>
        </html>
        """

        # Plain text version
        text_body = f"""
        Welcome, {name}!

        Your account is now active and ready to use.

        You can now access your dashboard at: {email_config.frontend_url}/dashboard

        If you have any questions, please contact our support team.

        Welcome aboard!
        """

        # Send the email
        send_email(
            to_email=email,
            subject=subject,
            html_body=html_body,
            text_body=text_body
        )

        logger.info(f"Welcome email sent successfully to {email}")

    except Exception as e:
        logger.error(f"Failed to send welcome email to {email}: {str(e)}")
        # Don't raise the exception for welcome emails


def test_email_connection():
    """
    Test email connection and configuration

    Returns:
        dict: Test results
    """
    try:
        email_config.validate_config()

        # Try to create SMTP connection
        server = create_smtp_connection()
        server.quit()

        return {
            "status": "success",
            "message": "Email connection successful",
            "config": {
                "smtp_host": email_config.smtp_host,
                "smtp_port": email_config.smtp_port,
                "sender_email": email_config.sender_email,
                "frontend_url": email_config.frontend_url
            }
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Email connection failed: {str(e)}",
            "config": {
                "smtp_host": email_config.smtp_host,
                "smtp_port": email_config.smtp_port,
                "sender_email": email_config.sender_email,
                "frontend_url": email_config.frontend_url
            }
        }


# Export commonly used classes and functions
__all__ = [
    'EmailVerification',
    'send_verification_email',
    'send_password_reset_email',
    'send_welcome_email',
    'send_email',
    'test_email_connection'
]