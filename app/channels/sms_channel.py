"""
SMS channel via SMS Magic API.
Docs: https://api.sms-magic.com/doc/
"""
from __future__ import annotations
import os
import hashlib
import hmac
import time
import requests
from flask import current_app

from . import BaseChannel, SendResult


class SMSMagicChannel(BaseChannel):
    channel_name = "sms"

    def __init__(self):
        self.api_url = os.getenv("SMS_MAGIC_API_URL", "https://api.sms-magic.com")
        self.access_key = os.getenv("SMS_MAGIC_ACCESS_KEY", "")
        self.secret_key = os.getenv("SMS_MAGIC_SECRET_KEY", "")
        self.sender_id = os.getenv("SMS_MAGIC_SENDER_ID", "")

    # ── Auth ──────────────────────────────────────────────────────────────────

    def _auth_headers(self, body: str) -> dict:
        """
        SMS Magic uses HMAC-SHA256 signed requests.
        Adjust to match the exact header scheme documented at api.sms-magic.com/doc/
        """
        timestamp = str(int(time.time()))
        sig_payload = f"{self.access_key}{timestamp}{body}"
        signature = hmac.new(
            self.secret_key.encode(), sig_payload.encode(), hashlib.sha256
        ).hexdigest()
        return {
            "Content-Type": "application/json",
            "X-Access-Key": self.access_key,
            "X-Timestamp": timestamp,
            "X-Signature": signature,
        }

    # ── Send ──────────────────────────────────────────────────────────────────

    def send_otp(self, recipient: str, otp: str, session_id: str) -> SendResult:
        validity = current_app.config.get("OTP_VALIDITY_SECONDS", 300)
        message = self.build_message(otp, validity)

        payload = {
            "to": recipient,
            "from": self.sender_id,
            "body": message,
            "reference": session_id,   # SMS Magic will echo this in delivery webhooks
        }

        import json
        body_str = json.dumps(payload)

        try:
            resp = requests.post(
                f"{self.api_url}/v1/message/send",
                headers=self._auth_headers(body_str),
                data=body_str,
                timeout=10,
            )
            data = resp.json()

            if resp.status_code in (200, 201, 202) and data.get("status") != "error":
                return SendResult(
                    success=True,
                    provider_message_id=data.get("message_id") or data.get("id"),
                    raw_response=data,
                )
            else:
                return SendResult(
                    success=False,
                    error=data.get("message", f"HTTP {resp.status_code}"),
                    raw_response=data,
                )

        except requests.Timeout:
            return SendResult(success=False, error="SMS Magic API timed out")
        except Exception as exc:
            return SendResult(success=False, error=str(exc))
