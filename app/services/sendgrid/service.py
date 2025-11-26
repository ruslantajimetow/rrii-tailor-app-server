import os
from dotenv import load_dotenv
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from app.models.user import User

load_dotenv()

SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
EMAIL_FROM = os.getenv("EMAIL_FROM")


def send_email_otp(user: User) -> None:
    """
    Sends a 6-digit OTP code to the user's email.
    Assumes:
    - user.email is set
    - user.email_otp_code and user.email_otp_expires_at are set
    """
    if not SENDGRID_API_KEY:
        raise RuntimeError("SENDGRID_API_KEY is not set")
    if not EMAIL_FROM:
        raise RuntimeError("EMAIL_FROM is not set")
    if not user.email:
        return

    subject = "Your verification code for Rrii Tailor Gallery"

    # Plain text email body
    plain_text_content = (
        f"Hi!\n\n"
        f"Your verification code is: {user.email_otp_code}\n\n"
        f"This code will expire at {user.email_otp_expires_at} (UTC).\n"
    )

    # HTML email body
    html_content = f"""
    <p>Hi!</p>
    <p>Your verification code is:</p>
    <p style="font-size: 24px; font-weight: bold;">{user.email_otp_code}</p>
    <p>This code will expire at {user.email_otp_expires_at} (UTC).</p>
    """

    # Build SendGrid Mail object
    message = Mail(
        from_email=EMAIL_FROM,
        to_emails=user.email,
        subject=subject,
        plain_text_content=plain_text_content,
        html_content=html_content,
    )

    # Create client and send the email
    sg = SendGridAPIClient(SENDGRID_API_KEY)
    sg.send(message)
