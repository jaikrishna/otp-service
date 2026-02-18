"""
Database models for the OTP service.
Uses SQLAlchemy — works with SQLite (dev/light) or PostgreSQL/MySQL (prod).
"""
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
import uuid

db = SQLAlchemy()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class OTPSession(db.Model):
    """
    Represents one OTP verification session requested by an external application.

    Lifecycle:
        pending   → OTP generated, message(s) sent, awaiting reply
        verified  → Correct OTP received via webhook
        failed    → Max attempts exceeded or explicitly failed
        expired   → Validity window elapsed without success
    """
    __tablename__ = "otp_sessions"

    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    external_ref = db.Column(db.String(255), index=True, nullable=True,
                             comment="Caller-supplied correlation ID")

    # Delivery targets — stored as JSON-serialisable primitives
    # channels: comma-separated list, e.g. "sms", "email", "sms,email"
    channels = db.Column(db.String(100), nullable=False, default="sms")
    phone_number = db.Column(db.String(50), nullable=True)
    email_address = db.Column(db.String(255), nullable=True)
    whatsapp_number = db.Column(db.String(50), nullable=True)

    # OTP
    otp_hash = db.Column(db.String(256), nullable=False,
                         comment="bcrypt/sha256 hash of the OTP — never store plaintext")
    otp_length = db.Column(db.Integer, default=6)
    attempts = db.Column(db.Integer, default=0)
    max_attempts = db.Column(db.Integer, default=3)

    # Timing
    created_at = db.Column(db.DateTime(timezone=True), default=_now)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    last_sent_at = db.Column(db.DateTime(timezone=True), nullable=True)
    verified_at = db.Column(db.DateTime(timezone=True), nullable=True)
    resend_count = db.Column(db.Integer, default=0)

    # Status
    status = db.Column(
        db.Enum("pending", "verified", "failed", "expired", name="otp_status"),
        default="pending",
        index=True,
    )

    # Callback
    callback_url = db.Column(db.String(1024), nullable=True,
                              comment="External application notification URL")
    callback_notified = db.Column(db.Boolean, default=False)

    # Provider message IDs (for tracking delivery receipts)
    provider_message_ids = db.Column(db.Text, nullable=True,
                                      comment="JSON: {channel: message_id}")

    # ── Relationships ─────────────────────────────────────────────────────────
    delivery_logs = db.relationship(
        "DeliveryLog", back_populates="session", cascade="all, delete-orphan"
    )

    def is_expired(self) -> bool:
        return _now() > self.expires_at

    def is_active(self) -> bool:
        return self.status == "pending" and not self.is_expired()

    def can_resend(self, cooldown_seconds: int) -> tuple[bool, str]:
        if self.status not in ("pending",):
            return False, f"Session is {self.status}"
        if self.is_expired():
            return False, "OTP has expired"
        if self.last_sent_at:
            from datetime import timedelta
            elapsed = (_now() - self.last_sent_at).total_seconds()
            if elapsed < cooldown_seconds:
                wait = int(cooldown_seconds - elapsed)
                return False, f"Please wait {wait}s before resending"
        return True, ""

    def to_dict(self, include_sensitive: bool = False) -> dict:
        d = {
            "session_id": self.id,
            "external_ref": self.external_ref,
            "channels": self.channels.split(","),
            "status": self.status,
            "attempts": self.attempts,
            "max_attempts": self.max_attempts,
            "resend_count": self.resend_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
        }
        return d


class DeliveryLog(db.Model):
    """
    Audit log for every send/resend attempt across all channels.
    """
    __tablename__ = "delivery_logs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    session_id = db.Column(db.String(36), db.ForeignKey("otp_sessions.id"), index=True)
    channel = db.Column(db.String(50), nullable=False)   # sms | email | whatsapp | rcs
    recipient = db.Column(db.String(255), nullable=True)
    provider = db.Column(db.String(100), nullable=True)
    provider_message_id = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(50), default="sent")    # sent | delivered | failed
    error_message = db.Column(db.Text, nullable=True)
    sent_at = db.Column(db.DateTime(timezone=True), default=_now)

    session = db.relationship("OTPSession", back_populates="delivery_logs")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "channel": self.channel,
            "recipient": self.recipient,
            "provider": self.provider,
            "status": self.status,
            "sent_at": self.sent_at.isoformat() if self.sent_at else None,
        }
