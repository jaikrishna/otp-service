from .otp_routes import otp_bp
from .webhook_routes import webhook_bp
from .health_routes import health_bp

__all__ = ["otp_bp", "webhook_bp", "health_bp"]
