"""
OTP Service — core business logic.

Responsibilities:
  - Generate cryptographically random OTP
  - Hash it before storing (never plaintext in DB)
  - Send via one or multiple channels
  - Validate incoming OTP
  - Notify external callback URL on success/failure
  - Support resend with cooldown
"""
from __future__ import annotations
import hashlib
import json
import os
import secrets
import string
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests
from flask import current_app

from ..models.database import db, OTPSession, DeliveryLog
from ..channels import get_channel, SUPPORTED_CHANNELS


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── OTP Generation ────────────────────────────────────────────────────────────

def _generate_otp(length: int = 6) -> str:
    """Cryptographically secure numeric OTP."""
    alphabet = string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _hash_otp(otp: str) -> str:
    """SHA-256 hash (sufficient for short-lived codes; add pepper via SECRET_KEY)."""
    pepper = current_app.config.get("SECRET_KEY", "")
    return hashlib.sha256(f"{pepper}{otp}".encode()).hexdigest()


def _verify_otp_hash(otp: str, stored_hash: str) -> bool:
    candidate = _hash_otp(otp)
    return secrets.compare_digest(candidate, stored_hash)


# ── Session Management ────────────────────────────────────────────────────────

def create_otp_session(
    channels: list[str],
    phone_number: Optional[str] = None,
    email_address: Optional[str] = None,
    whatsapp_number: Optional[str] = None,
    callback_url: Optional[str] = None,
    external_ref: Optional[str] = None,
) -> dict:
    """
    Generate OTP, create session, send via all requested channels.

    Returns a response dict (never the OTP itself).
    """
    # Validate channels
    invalid = [c for c in channels if c not in SUPPORTED_CHANNELS]
    if invalid:
        return {"error": f"Unsupported channels: {invalid}"}, 400

    # Validate recipients per channel
    channel_recipient_map = _build_channel_recipient_map(
        channels, phone_number, email_address, whatsapp_number
    )
    if "error" in channel_recipient_map:
        return channel_recipient_map, 400

    cfg = current_app.config
    otp_length = cfg.get("OTP_LENGTH", 6)
    validity_sec = cfg.get("OTP_VALIDITY_SECONDS", 300)
    max_attempts = cfg.get("OTP_MAX_ATTEMPTS", 3)

    otp = _generate_otp(otp_length)
    otp_hash = _hash_otp(otp)

    session = OTPSession(
        channels=",".join(channels),
        phone_number=phone_number,
        email_address=email_address,
        whatsapp_number=whatsapp_number,
        otp_hash=otp_hash,
        otp_length=otp_length,
        max_attempts=max_attempts,
        expires_at=_now() + timedelta(seconds=validity_sec),
        callback_url=callback_url,
        external_ref=external_ref,
        last_sent_at=_now(),
    )
    db.session.add(session)
    db.session.flush()  # get session.id before sending

    # Send via all channels
    send_results = _send_via_channels(session, otp, channel_recipient_map)
    db.session.commit()

    any_sent = any(r["success"] for r in send_results.values())
    if not any_sent:
        session.status = "failed"
        db.session.commit()
        return {
            "error": "Failed to send OTP via any channel",
            "details": send_results,
        }, 502

    return {
        "session_id": session.id,
        "external_ref": external_ref,
        "channels": channels,
        "expires_at": session.expires_at.isoformat(),
        "validity_seconds": validity_sec,
        "send_results": send_results,
        "status": "pending",
    }, 201


def resend_otp(session_id: str) -> tuple[dict, int]:
    """Resend the same OTP (regenerate for security) with cooldown enforcement."""
    session: OTPSession = OTPSession.query.get(session_id)
    if not session:
        return {"error": "Session not found"}, 404

    cooldown = current_app.config.get("OTP_RESEND_COOLDOWN_SECONDS", 60)
    can_resend, reason = session.can_resend(cooldown)
    if not can_resend:
        return {"error": reason}, 429

    if session.is_expired():
        session.status = "expired"
        db.session.commit()
        return {"error": "OTP session has expired. Please request a new one."}, 410

    # Regenerate OTP for security (never reuse the same code on resend)
    otp = _generate_otp(session.otp_length)
    session.otp_hash = _hash_otp(otp)
    session.last_sent_at = _now()
    session.resend_count += 1

    channels = session.channels.split(",")
    channel_recipient_map = _build_channel_recipient_map(
        channels, session.phone_number, session.email_address, session.whatsapp_number
    )
    send_results = _send_via_channels(session, otp, channel_recipient_map)
    db.session.commit()

    return {
        "session_id": session.id,
        "resend_count": session.resend_count,
        "expires_at": session.expires_at.isoformat(),
        "send_results": send_results,
        "status": "pending",
    }, 200


def validate_otp(session_id: str, otp: str) -> tuple[dict, int]:
    """
    Validate OTP submitted by external application (direct API call).
    Also used internally after webhook triggers.
    """
    session: OTPSession = OTPSession.query.get(session_id)
    if not session:
        return {"error": "Session not found"}, 404

    return _perform_validation(session, otp)


def validate_otp_from_webhook(session_id: str, otp: str) -> tuple[dict, int]:
    """Entry point called by webhook handler after parsing incoming SMS reply."""
    return validate_otp(session_id, otp)


def get_session_status(session_id: str) -> tuple[dict, int]:
    session: OTPSession = OTPSession.query.get(session_id)
    if not session:
        return {"error": "Session not found"}, 404

    if session.status == "pending" and session.is_expired():
        session.status = "expired"
        db.session.commit()

    return {
        **session.to_dict(),
        "delivery_logs": [log.to_dict() for log in session.delivery_logs],
    }, 200


# ── Internal helpers ──────────────────────────────────────────────────────────

def _perform_validation(session: OTPSession, otp: str) -> tuple[dict, int]:
    if session.status == "verified":
        return {"error": "Already verified", "session_id": session.id}, 409

    if session.status in ("failed", "expired"):
        return {"error": f"Session is {session.status}", "session_id": session.id}, 410

    if session.is_expired():
        session.status = "expired"
        db.session.commit()
        _notify_callback(session, False, "OTP expired")
        return {"error": "OTP has expired", "session_id": session.id}, 410

    session.attempts += 1

    if _verify_otp_hash(otp.strip(), session.otp_hash):
        session.status = "verified"
        session.verified_at = _now()
        db.session.commit()
        _notify_callback(session, True)
        return {
            "session_id": session.id,
            "status": "verified",
            "external_ref": session.external_ref,
            "verified_at": session.verified_at.isoformat(),
        }, 200

    remaining = session.max_attempts - session.attempts
    if session.attempts >= session.max_attempts:
        session.status = "failed"
        db.session.commit()
        _notify_callback(session, False, "Max attempts exceeded")
        return {
            "error": "OTP verification failed — max attempts exceeded",
            "session_id": session.id,
            "status": "failed",
        }, 401

    db.session.commit()
    return {
        "error": "Invalid OTP",
        "session_id": session.id,
        "attempts_remaining": remaining,
    }, 401


def _build_channel_recipient_map(
    channels: list[str],
    phone_number, email_address, whatsapp_number
) -> dict:
    mapping = {}
    for ch in channels:
        if ch == "sms":
            if not phone_number:
                return {"error": "phone_number required for SMS channel"}
            mapping["sms"] = phone_number
        elif ch == "email":
            if not email_address:
                return {"error": "email_address required for email channel"}
            mapping["email"] = email_address
        elif ch == "whatsapp":
            recipient = whatsapp_number or phone_number
            if not recipient:
                return {"error": "whatsapp_number or phone_number required for WhatsApp channel"}
            mapping["whatsapp"] = recipient
        elif ch == "rcs":
            if not phone_number:
                return {"error": "phone_number required for RCS channel"}
            mapping["rcs"] = phone_number
    return mapping


def _send_via_channels(
    session: OTPSession, otp: str, channel_recipient_map: dict
) -> dict:
    results = {}
    provider_ids = {}

    for ch_name, recipient in channel_recipient_map.items():
        try:
            channel = get_channel(ch_name)
            result = channel.send_otp(recipient, otp, session.id)
        except Exception as exc:
            from ..channels import SendResult
            result = SendResult(success=False, error=str(exc))

        log = DeliveryLog(
            session_id=session.id,
            channel=ch_name,
            recipient=recipient,
            provider=f"{ch_name}_provider",
            provider_message_id=result.provider_message_id,
            status="sent" if result.success else "failed",
            error_message=result.error,
        )
        db.session.add(log)

        if result.provider_message_id:
            provider_ids[ch_name] = result.provider_message_id

        results[ch_name] = {
            "success": result.success,
            "provider_message_id": result.provider_message_id,
            "error": result.error,
        }

    if provider_ids:
        session.provider_message_ids = json.dumps(provider_ids)

    return results


def _notify_callback(session: OTPSession, success: bool, reason: str = "") -> None:
    """Fire-and-forget POST to the external application's callback URL."""
    if not session.callback_url:
        return

    payload = {
        "session_id": session.id,
        "external_ref": session.external_ref,
        "status": "verified" if success else "failed",
        "reason": reason if not success else None,
        "verified_at": session.verified_at.isoformat() if session.verified_at else None,
    }
    try:
        requests.post(session.callback_url, json=payload, timeout=5)
        session.callback_notified = True
        db.session.commit()
    except Exception:
        pass  # Non-blocking — caller can poll /status if needed
