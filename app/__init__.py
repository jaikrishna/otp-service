"""
OTP Service — Flask Application Factory
"""
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
import os

from .models.database import db
from .routes.otp_routes import otp_bp
from .routes.webhook_routes import webhook_bp
from .routes.health_routes import health_bp
from .services.cleanup_service import start_cleanup_scheduler

load_dotenv()

limiter = Limiter(key_func=get_remote_address)


def create_app(config_override: dict = None) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)

    # ── Core config ──────────────────────────────────────────────────────────
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "DATABASE_URL", "sqlite:///otp_service.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
        "connect_args": {"check_same_thread": False}   # SQLite only; ignored by Postgres
        if "sqlite" in os.getenv("DATABASE_URL", "sqlite://") else {},
    }

    # OTP settings (readable by services via current_app.config)
    app.config["OTP_LENGTH"] = int(os.getenv("OTP_LENGTH", 6))
    app.config["OTP_VALIDITY_SECONDS"] = int(os.getenv("OTP_VALIDITY_SECONDS", 300))
    app.config["OTP_MAX_ATTEMPTS"] = int(os.getenv("OTP_MAX_ATTEMPTS", 3))
    app.config["OTP_RESEND_COOLDOWN_SECONDS"] = int(
        os.getenv("OTP_RESEND_COOLDOWN_SECONDS", 60)
    )
    app.config["INCOMING_WEBHOOK_TOKEN"] = os.getenv("INCOMING_WEBHOOK_TOKEN", "")

    if config_override:
        app.config.update(config_override)

    # ── Extensions ───────────────────────────────────────────────────────────
    db.init_app(app)
    limiter.init_app(app)

    # ── Blueprints ───────────────────────────────────────────────────────────
    app.register_blueprint(otp_bp, url_prefix="/api/v1/otp")
    app.register_blueprint(webhook_bp, url_prefix="/webhooks")
    app.register_blueprint(health_bp)

    # ── Database init ────────────────────────────────────────────────────────
    with app.app_context():
        db.create_all()

    # ── Background scheduler (cleanup expired OTPs) ──────────────────────────
    if not app.testing:
        start_cleanup_scheduler(app)

    return app
