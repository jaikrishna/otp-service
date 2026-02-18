"""
RCS channel stub.
SMS Magic supports RCS via the same API with channel="rcs".
Replace the implementation here if using a different RCS provider.
"""
from __future__ import annotations
import os
import requests
import json
from flask import current_app

from . import BaseChannel, SendResult


class RCSChannel(BaseChannel):
    channel_name = "rcs"

    def __init__(self):
        self.api_url = os.getenv("SMS_MAGIC_API_URL", "https://api.sms-magic.com")
        self.access_key = os.getenv("SMS_MAGIC_ACCESS_KEY", "")
        self.sender_id = os.getenv("SMS_MAGIC_SENDER_ID", "")

    def send_otp(self, recipient: str, otp: str, session_id: str) -> SendResult:
        validity = current_app.config.get("OTP_VALIDITY_SECONDS", 300)
        payload = {
            "channel": "rcs",
            "to": recipient,
            "from": self.sender_id,
            "body": self.build_message(otp, validity),
            "reference": session_id,
        }
        try:
            resp = requests.post(
                f"{self.api_url}/v1/message/send",
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
