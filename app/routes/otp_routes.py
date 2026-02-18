"""
OTP API Routes — consumed by external applications.

POST   /api/v1/otp/generate     Generate & send OTP
POST   /api/v1/otp/verify       Validate OTP (direct, non-webhook path)
POST   /api/v1/otp/resend       Resend OTP
GET    /api/v1/otp/<id>/status  Poll session status
"""
from flask import Blueprint, request, jsonify, current_app
from ..services import (
    create_otp_session,
    resend_otp,
    validate_otp,
    get_session_status,
)
from ..channels import SUPPORTED_CHANNELS

otp_bp = Blueprint("otp", __name__)


def _json_error(msg: str, status: int):
    return jsonify({"error": msg}), status


# ── Generate ──────────────────────────────────────────────────────────────────

@otp_bp.post("/generate")
def generate():
    """
    Generate and send an OTP.

    Body (JSON):
      channels         list[str]  required  e.g. ["sms"], ["sms","email"]
      phone_number     str        optional  E.164 format (+1234567890)
      email_address    str        optional
      whatsapp_number  str        optional  defaults to phone_number
      callback_url     str        optional  POST endpoint for success/failure notification
      external_ref     str        optional  Caller correlation ID

    Returns 201 with session_id on success.
    """
    data = request.get_json(silent=True) or {}

    channels = data.get("channels")
    if not channels:
        return _json_error("'channels' is required", 400)
    if isinstance(channels, str):
        channels = [channels]
    channels = [c.lower().strip() for c in channels]

    invalid = [c for c in channels if c not in SUPPORTED_CHANNELS]
    if invalid:
        return _json_error(f"Unsupported channels: {invalid}. Supported: {SUPPORTED_CHANNELS}", 400)

    result, status = create_otp_session(
        channels=channels,
        phone_number=data.get("phone_number"),
        email_address=data.get("email_address"),
        whatsapp_number=data.get("whatsapp_number"),
        callback_url=data.get("callback_url"),
        external_ref=data.get("external_ref"),
    )
    return jsonify(result), status


# ── Verify (direct API call) ──────────────────────────────────────────────────

@otp_bp.post("/verify")
def verify():
    """
    Directly verify OTP submitted by the user.
    Use this when the user types the OTP into your app UI.

    Body (JSON):
      session_id  str  required
      otp         str  required
    """
    data = request.get_json(silent=True) or {}
    session_id = data.get("session_id")
    otp = data.get("otp")

    if not session_id or not otp:
        return _json_error("'session_id' and 'otp' are required", 400)

    result, status = validate_otp(session_id, str(otp))
    return jsonify(result), status


# ── Resend ────────────────────────────────────────────────────────────────────

@otp_bp.post("/resend")
def resend():
    """
    Resend OTP (subject to cooldown).

    Body (JSON):
      session_id  str  required
    """
    data = request.get_json(silent=True) or {}
    session_id = data.get("session_id")
    if not session_id:
        return _json_error("'session_id' is required", 400)

    result, status = resend_otp(session_id)
    return jsonify(result), status


# ── Status ────────────────────────────────────────────────────────────────────

@otp_bp.get("/<session_id>/status")
def status(session_id: str):
    """Poll the current status of an OTP session."""
    result, http_status = get_session_status(session_id)
    return jsonify(result), http_status
