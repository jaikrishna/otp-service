"""
Webhook Routes — receive incoming messages from SMS Magic (and other providers).

SMS Magic will POST to:
  /webhooks/sms-magic/incoming   — incoming SMS reply

The webhook handler:
  1. Verifies the request signature/token
  2. Extracts session_id (from the 'reference' echo-back) and OTP from message body
  3. Delegates to validate_otp_from_webhook
  4. Returns 200 to acknowledge receipt (provider retries on non-2xx)
"""
import hashlib
import hmac
import json
import re
import os

from flask import Blueprint, request, jsonify, current_app

from ..services import validate_otp_from_webhook

webhook_bp = Blueprint("webhooks", __name__)


def _verify_sms_magic_signature(payload: bytes, headers: dict) -> bool:
    """
    Verify HMAC-SHA256 webhook signature from SMS Magic.
    Adjust header names to match SMS Magic's actual webhook spec.
    """
    secret = current_app.config.get("INCOMING_WEBHOOK_TOKEN", "")
    if not secret:
        current_app.logger.warning("INCOMING_WEBHOOK_TOKEN not set — skipping signature check")
        return True  # dev mode

    received_sig = headers.get("X-SMS-Magic-Signature", "")
    expected_sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(received_sig, expected_sig)


def _extract_otp_from_text(text: str, otp_length: int = 6) -> str | None:
    """Parse OTP from incoming reply. Handles '123456', 'Code: 123456', '  123456  '."""
    text = text.strip()
    # Direct: message is just the OTP
    if re.fullmatch(r"\d{4,8}", text):
        return text
    # 'Code: 123456' or 'OTP 123456'
    match = re.search(r"\b(\d{4,8})\b", text)
    return match.group(1) if match else None


# ── SMS Magic Incoming Webhook ────────────────────────────────────────────────

@webhook_bp.post("/sms-magic/incoming")
def sms_magic_incoming():
    """
    Receives incoming SMS reply from SMS Magic.

    Expected payload (adjust field names to match SMS Magic's actual schema):
    {
      "from": "+1234567890",
      "to": "+0987654321",
      "body": "123456",
      "reference": "<session_id>",   // echoed from the send request
      "message_id": "msg_abc123"
    }
    """
    raw = request.get_data()

    if not _verify_sms_magic_signature(raw, dict(request.headers)):
        current_app.logger.warning("Webhook signature mismatch — rejecting")
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    current_app.logger.info(f"[webhook] sms-magic incoming: {json.dumps(data)}")

    session_id = data.get("reference") or data.get("session_id")
    body = data.get("body", "").strip()

    if not session_id:
        # Can't map to a session without a reference — acknowledge but skip
        return jsonify({"status": "ignored", "reason": "no session reference"}), 200

    otp = _extract_otp_from_text(body)
    if not otp:
        return jsonify({"status": "ignored", "reason": "no OTP found in message"}), 200

    result, status_code = validate_otp_from_webhook(session_id, otp)
    # Always return 200 to avoid provider retry storms
    return jsonify({"webhook_status": "processed", "validation": result}), 200


# ── Generic Incoming Webhook (for other providers) ────────────────────────────

@webhook_bp.post("/incoming")
def generic_incoming():
    """
    Generic webhook endpoint — call this from no-code tools (Make, Zapier, n8n).

    Body (JSON):
      session_id  str  required
      otp         str  required
      token       str  optional  matches INCOMING_WEBHOOK_TOKEN for auth
    """
    token = current_app.config.get("INCOMING_WEBHOOK_TOKEN", "")
    data = request.get_json(silent=True) or {}

    if token and data.get("token") != token:
        return jsonify({"error": "Unauthorized"}), 401

    session_id = data.get("session_id")
    otp = data.get("otp")

    if not session_id or not otp:
        return jsonify({"error": "'session_id' and 'otp' required"}), 400

    result, status_code = validate_otp_from_webhook(session_id, str(otp))
    return jsonify({"validation": result}), 200


# ── Delivery Receipt Webhook ──────────────────────────────────────────────────

@webhook_bp.post("/sms-magic/delivery")
def sms_magic_delivery_receipt():
    """
    Update delivery status when SMS Magic posts a delivery receipt.
    """
    raw = request.get_data()
    if not _verify_sms_magic_signature(raw, dict(request.headers)):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    message_id = data.get("message_id")
    status = data.get("status")  # "delivered", "failed", etc.

    if message_id and status:
        from ..models.database import db, DeliveryLog
        log = DeliveryLog.query.filter_by(provider_message_id=message_id).first()
        if log:
            log.status = status
            db.session.commit()

    return jsonify({"status": "ok"}), 200
