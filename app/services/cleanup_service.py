"""
Scheduled job: mark expired OTP sessions and purge old records.
Uses APScheduler (lightweight, no Redis/Celery needed for SQLite-scale).
"""
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timezone, timedelta


def start_cleanup_scheduler(app):
    scheduler = BackgroundScheduler(daemon=True)

    @scheduler.scheduled_job("interval", minutes=5, id="expire_otps")
    def expire_old_sessions():
        with app.app_context():
            from ..models.database import db, OTPSession
            now = datetime.now(timezone.utc)
            expired = OTPSession.query.filter(
                OTPSession.status == "pending",
                OTPSession.expires_at < now,
            ).all()
            for s in expired:
                s.status = "expired"
            if expired:
                db.session.commit()
                app.logger.info(f"[cleanup] Marked {len(expired)} sessions as expired")

    @scheduler.scheduled_job("interval", hours=24, id="purge_old_sessions")
    def purge_old_sessions():
        """Remove sessions older than 30 days to keep the DB light."""
        with app.app_context():
            from ..models.database import db, OTPSession
            cutoff = datetime.now(timezone.utc) - timedelta(days=30)
            deleted = OTPSession.query.filter(OTPSession.created_at < cutoff).delete()
            db.session.commit()
            if deleted:
                app.logger.info(f"[cleanup] Purged {deleted} old sessions")

    scheduler.start()
    app.logger.info("[scheduler] OTP cleanup scheduler started")
    return scheduler
