"""
Channel abstraction layer.

Adding a new channel (e.g. RCS, Push):
  1. Create app/channels/rcs_channel.py with a class that extends BaseChannel
  2. Register it in CHANNEL_REGISTRY below
  3. No other files need to change.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class SendResult:
    success: bool
    provider_message_id: Optional[str] = None
    error: Optional[str] = None
    raw_response: Optional[dict] = None


class BaseChannel(ABC):
    """All channels must implement this interface."""

    channel_name: str = "base"

    @abstractmethod
    def send_otp(self, recipient: str, otp: str, session_id: str) -> SendResult:
        """
        Send the OTP to the recipient via this channel.

        Args:
            recipient:  Phone number, email address, etc.
            otp:        Plaintext OTP (only used here — never stored)
            session_id: For message body / tracking

        Returns:
            SendResult
        """
        ...

    def build_message(self, otp: str, validity_seconds: int = 300) -> str:
        validity_min = validity_seconds // 60
        return (
            f"Your verification code is {otp}. "
            f"It expires in {validity_min} minute(s). "
            f"Do not share this code with anyone."
        )


# ── Registry ─────────────────────────────────────────────────────────────────
# Maps channel name → class.  Import lazily to avoid circular deps.

def get_channel(name: str) -> BaseChannel:
    """
    Factory: return a configured channel instance by name.
    Raises ValueError for unknown channels.
    """
    name = name.lower().strip()

    if name == "sms":
        from .sms_channel import SMSMagicChannel
        return SMSMagicChannel()

    if name == "email":
        from .email_channel import EmailChannel
        return EmailChannel()

    if name == "whatsapp":
        from .whatsapp_channel import WhatsAppChannel
        return WhatsAppChannel()

    # Placeholder: RCS uses the same SMS Magic provider with different message type
    if name == "rcs":
        from .rcs_channel import RCSChannel
        return RCSChannel()

    raise ValueError(f"Unknown channel: '{name}'. Supported: sms, email, whatsapp, rcs")


SUPPORTED_CHANNELS = ["sms", "email", "whatsapp", "rcs"]
