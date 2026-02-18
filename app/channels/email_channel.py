"""
Email channel via SMTP.
Swap smtplib for SendGrid/Mailgun SDK if preferred — only this file changes.
"""
from __future__ import annotations
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import current_app

from . import BaseChannel, SendResult


class EmailChannel(BaseChannel):
    channel_name = "email"

    def __init__(self):
        self.host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        self.port = int(os.getenv("SMTP_PORT", 587))
        self.username = os.getenv("SMTP_USERNAME", "")
        self.password = os.getenv("SMTP_PASSWORD", "")
        self.from_addr = os.getenv("EMAIL_FROM", self.username)

    def send_otp(self, recipient: str, otp: str, session_id: str) -> SendResult:
        validity = current_app.config.get("OTP_VALIDITY_SECONDS", 300)
        validity_min = validity // 60

        subject = "Your Verification Code"
        text_body = self.build_message(otp, validity)
        html_body = f"""
        <html><body>
          <p>Your verification code is:</p>
          <h2 style="letter-spacing:4px; font-family:monospace;">{otp}</h2>
          <p>This code expires in <strong>{validity_min} minute(s)</strong>.</p>
          <p style="color:#888; font-size:12px;">Do not share this code with anyone.</p>
        </body></html>
        """

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.from_addr
        msg["To"] = recipient
        msg["X-Session-ID"] = session_id
        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        try:
            with smtplib.SMTP(self.host, self.port, timeout=10) as server:
                server.ehlo()
                server.starttls()
                server.login(self.username, self.password)
                server.sendmail(self.from_addr, [recipient], msg.as_string())
            return SendResult(success=True, provider_message_id=f"email-{session_id}")
        except smtplib.SMTPAuthenticationError:
            return SendResult(success=False, error="SMTP authentication failed")
        except smtplib.SMTPException as exc:
            return SendResult(success=False, error=str(exc))
        except Exception as exc:
            return SendResult(success=False, error=str(exc))
