from flask import Blueprint, jsonify
from ..models.database import db

health_bp = Blueprint("health", __name__)


@health_bp.get("/health")
def health():
    try:
        db.session.execute(db.text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    status = "ok" if db_ok else "degraded"
    return jsonify({"status": status, "db": "ok" if db_ok else "error"}), 200 if db_ok else 503


@health_bp.get("/")
def root():
    return jsonify({
        "service": "OTP Service",
        "version": "1.0.0",
        "docs": "/api/v1/otp/",
    }), 200
