"""
Email channel via Resend HTTP API (primary) with SMTP fallback.
Uses Resend's REST API over HTTPS to avoid SMTP port blocking on cloud platforms.
"""
from __future__ import annotations
import os
import json
import smtplib
import urllib.request
import urllib.error
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
        # Resend HTTP API key (same as SMTP_PASSWORD when using Resend)
        self.resend_api_key = os.getenv("RESEND_API_KEY") or (
            self.password if self.host == "smtp.resend.com" else None
        )

    def _send_via_resend_api(self, recipient: str, otp: str, session_id: str, validity_min: int) -> SendResult:
        """Send email using Resend's HTTP API — works on all platforms."""
        html_body = f"""
        <html><body>
          <p>Your verification code is:</p>
          <h2 style="letter-spacing:4px; font-family:monospace;">{otp}</h2>
          <p>This code expires in <strong>{validity_min} minute(s)</strong>.</p>
          <p style="color:#888; font-size:12px;">Do not share this code with anyone.</p>
        </body></html>
        """
        text_body = self.build_message(otp, validity_min * 60)

        payload = json.dumps({
            "from": self.from_addr,
            "to": [recipient],
            "subject": "Your Verification Code",
            "html": html_body,
            "text": text_body,
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://api.resend.com/emails",
            data=payload,
            headers={
                "Authorization": f"Bearer {self.resend_api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read().decode())
                return SendResult(success=True, provider_message_id=result.get("id", f"resend-{session_id}"))
        except urllib.error.HTTPError as e:
            error_body = e.read().decode()
            return SendResult(success=False, error=f"Resend API error {e.code}: {error_body}")
        except Exception as exc:
            return SendResult(success=False, error=str(exc))

    def _send_via_smtp(self, recipient: str, otp: str, session_id: str, validity_min: int) -> SendResult:
        """Send email via SMTP (fallback)."""
        html_body = f"""
        <html><body>
          <p>Your verification code is:</p>
          <h2 style="letter-spacing:4px; font-family:monospace;">{otp}</h2>
          <p>This code expires in <strong>{validity_min} minute(s)</strong>.</p>
          <p style="color:#888; font-size:12px;">Do not share this code with anyone.</p>
        </body></html>
        """
        text_body = self.build_message(otp, validity_min * 60)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Your Verification Code"
        msg["From"] = self.from_addr
        msg["To"] = recipient
        msg["X-Session-ID"] = session_id
        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        try:
            if self.port == 465:
                with smtplib.SMTP_SSL(self.host, self.port, timeout=15) as server:
                    server.ehlo()
                    server.login(self.username, self.password)
                    server.sendmail(self.from_addr, [recipient], msg.as_string())
            else:
                with smtplib.SMTP(self.host, self.port, timeout=15) as server:
                    server.ehlo()
                    server.starttls()
                    server.ehlo()
                    server.login(self.username, self.password)
                    server.sendmail(self.from_addr, [recipient], msg.as_string())
            return SendResult(success=True, provider_message_id=f"email-{session_id}")
        except smtplib.SMTPAuthenticationError:
            return SendResult(success=False, error="SMTP authentication failed")
        except smtplib.SMTPException as exc:
            return SendResult(success=False, error=str(exc))
        except Exception as exc:
            return SendResult(success=False, error=str(exc))

    def send_otp(self, recipient: str, otp: str, session_id: str) -> SendResult:
        validity = current_app.config.get("OTP_VALIDITY_SECONDS", 300)
        validity_min = validity // 60

        # Use Resend HTTP API if configured (bypasses SMTP port blocking)
        if self.resend_api_key:
            return self._send_via_resend_api(recipient, otp, session_id, validity_min)

        # Fallback to SMTP
        return self._send_via_smtp(recipient, otp, session_id, validity_min)
