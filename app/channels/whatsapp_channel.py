"""
WhatsApp channel.
Default provider: SMS Magic WhatsApp API.
Set WHATSAPP_PROVIDER=twilio to switch (only this file changes).
"""
from __future__ import annotations
import os
import requests
import json
from flask import current_app

from . import BaseChannel, SendResult


class WhatsAppChannel(BaseChannel):
    channel_name = "whatsapp"

    def __init__(self):
        self.provider = os.getenv("WHATSAPP_PROVIDER", "sms_magic")
        self.api_url = os.getenv("SMS_MAGIC_API_URL", "https://api.sms-magic.com")
        self.access_key = os.getenv("SMS_MAGIC_ACCESS_KEY", "")
        self.secret_key = os.getenv("SMS_MAGIC_SECRET_KEY", "")
        self.from_number = os.getenv("WHATSAPP_FROM", "")

    def send_otp(self, recipient: str, otp: str, session_id: str) -> SendResult:
        if self.provider == "twilio":
            return self._send_via_twilio(recipient, otp, session_id)
        return self._send_via_sms_magic(recipient, otp, session_id)

    def _send_via_sms_magic(self, recipient: str, otp: str, session_id: str) -> SendResult:
        validity = current_app.config.get("OTP_VALIDITY_SECONDS", 300)
        payload = {
            "channel": "whatsapp",
            "to": recipient,
            "from": self.from_number,
            "template": {
                "name": "otp_verification",
                "language": {"code": "en"},
                "components": [
                    {"type": "body", "parameters": [
                        {"type": "text", "text": otp},
                        {"type": "text", "text": str(validity // 60)},
                    ]}
                ],
            },
            "reference": session_id,
        }
        try:
            resp = requests.post(
                f"{self.api_url}/v1/whatsapp/send",
                headers={"Content-Type": "application/json", "X-Access-Key": self.access_key},
                data=json.dumps(payload),
                timeout=10,
            )
            data = resp.json()
            if resp.ok:
                return SendResult(success=True, provider_message_id=data.get("message_id"),
                                  raw_response=data)
            return SendResult(success=False, error=data.get("message"), raw_response=data)
        except Exception as exc:
            return SendResult(success=False, error=str(exc))

    def _send_via_twilio(self, recipient: str, otp: str, session_id: str) -> SendResult:
        """Twilio WhatsApp fallback — requires twilio SDK."""
        try:
            from twilio.rest import Client
            account_sid = os.getenv("TWILIO_ACCOUNT_SID")
            auth_token = os.getenv("TWILIO_AUTH_TOKEN")
            client = Client(account_sid, auth_token)
            validity = current_app.config.get("OTP_VALIDITY_SECONDS", 300)
            message = client.messages.create(
                body=self.build_message(otp, validity),
                from_=f"whatsapp:{self.from_number}",
                to=f"whatsapp:{recipient}",
            )
            return SendResult(success=True, provider_message_id=message.sid)
        except ImportError:
            return SendResult(success=False, error="twilio package not installed")
        except Exception as exc:
            return SendResult(success=False, error=str(exc))
