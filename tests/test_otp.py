"""
pytest test suite for OTP Service.
Run: pytest tests/ -v
"""
import pytest
import json
from unittest.mock import patch, MagicMock
from app import create_app
from app.models.database import db as _db


@pytest.fixture(scope="session")
def app():
    test_app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "OTP_LENGTH": 6,
        "OTP_VALIDITY_SECONDS": 300,
        "OTP_MAX_ATTEMPTS": 3,
        "OTP_RESEND_COOLDOWN_SECONDS": 0,   # no cooldown in tests
        "SECRET_KEY": "test-secret",
        "INCOMING_WEBHOOK_TOKEN": "",
    })
    with test_app.app_context():
        _db.create_all()
        yield test_app


@pytest.fixture
def client(app):
    return app.test_client()


# ── Helper to mock channel send ───────────────────────────────────────────────

def _mock_send_success(*args, **kwargs):
    from app.channels import SendResult
    return SendResult(success=True, provider_message_id="mock-msg-001")


def _mock_send_failure(*args, **kwargs):
    from app.channels import SendResult
    return SendResult(success=False, error="Provider error")


# ── Generate ──────────────────────────────────────────────────────────────────

class TestGenerate:
    @patch("app.channels.sms_channel.SMSMagicChannel.send_otp", side_effect=_mock_send_success)
    def test_generate_sms_success(self, mock_send, client):
        resp = client.post("/api/v1/otp/generate", json={
            "channels": ["sms"],
            "phone_number": "+1234567890",
            "callback_url": "https://example.com/callback",
        })
        assert resp.status_code == 201
        data = resp.get_json()
        assert "session_id" in data
        assert data["status"] == "pending"
        assert data["send_results"]["sms"]["success"] is True

    def test_generate_missing_channels(self, client):
        resp = client.post("/api/v1/otp/generate", json={"phone_number": "+1"})
        assert resp.status_code == 400

    def test_generate_sms_missing_phone(self, client):
        resp = client.post("/api/v1/otp/generate", json={"channels": ["sms"]})
        assert resp.status_code == 400

    def test_generate_unsupported_channel(self, client):
        resp = client.post("/api/v1/otp/generate", json={
            "channels": ["carrier_pigeon"], "phone_number": "+1"
        })
        assert resp.status_code == 400

    @patch("app.channels.sms_channel.SMSMagicChannel.send_otp", side_effect=_mock_send_success)
    @patch("app.channels.email_channel.EmailChannel.send_otp", side_effect=_mock_send_success)
    def test_generate_multi_channel(self, mock_email, mock_sms, client):
        resp = client.post("/api/v1/otp/generate", json={
            "channels": ["sms", "email"],
            "phone_number": "+1234567890",
            "email_address": "user@example.com",
        })
        assert resp.status_code == 201
        data = resp.get_json()
        assert "sms" in data["send_results"]
        assert "email" in data["send_results"]


# ── Verify ────────────────────────────────────────────────────────────────────

class TestVerify:
    def _create_session(self, client, otp_to_capture: list):
        """Helper: create a session and capture the OTP by patching the hash."""
        with patch("app.channels.sms_channel.SMSMagicChannel.send_otp", side_effect=_mock_send_success):
            with patch("app.services.otp_service._generate_otp", return_value="123456"):
                resp = client.post("/api/v1/otp/generate", json={
                    "channels": ["sms"], "phone_number": "+1"
                })
        otp_to_capture.append("123456")
        return resp.get_json()["session_id"]

    def test_verify_correct_otp(self, client):
        otp = []
        sid = self._create_session(client, otp)
        resp = client.post("/api/v1/otp/verify", json={"session_id": sid, "otp": otp[0]})
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "verified"

    def test_verify_wrong_otp_exhausts_attempts(self, client):
        otp = []
        sid = self._create_session(client, otp)
        for _ in range(3):
            resp = client.post("/api/v1/otp/verify", json={"session_id": sid, "otp": "000000"})
        assert resp.status_code == 401
        assert resp.get_json()["status"] == "failed"

    def test_verify_already_verified(self, client):
        otp = []
        sid = self._create_session(client, otp)
        client.post("/api/v1/otp/verify", json={"session_id": sid, "otp": otp[0]})
        resp = client.post("/api/v1/otp/verify", json={"session_id": sid, "otp": otp[0]})
        assert resp.status_code == 409

    def test_verify_missing_fields(self, client):
        resp = client.post("/api/v1/otp/verify", json={"session_id": "x"})
        assert resp.status_code == 400

    def test_verify_nonexistent_session(self, client):
        resp = client.post("/api/v1/otp/verify", json={
            "session_id": "00000000-0000-0000-0000-000000000000", "otp": "123456"
        })
        assert resp.status_code == 404


# ── Resend ────────────────────────────────────────────────────────────────────

class TestResend:
    @patch("app.channels.sms_channel.SMSMagicChannel.send_otp", side_effect=_mock_send_success)
    def test_resend_success(self, mock_send, client):
        with patch("app.services.otp_service._generate_otp", return_value="111111"):
            resp = client.post("/api/v1/otp/generate", json={
                "channels": ["sms"], "phone_number": "+1"
            })
        sid = resp.get_json()["session_id"]

        with patch("app.channels.sms_channel.SMSMagicChannel.send_otp", side_effect=_mock_send_success):
            resp2 = client.post("/api/v1/otp/resend", json={"session_id": sid})
        assert resp2.status_code == 200
        assert resp2.get_json()["resend_count"] == 1


# ── Status ────────────────────────────────────────────────────────────────────

class TestStatus:
    @patch("app.channels.sms_channel.SMSMagicChannel.send_otp", side_effect=_mock_send_success)
    def test_status_pending(self, mock_send, client):
        resp = client.post("/api/v1/otp/generate", json={
            "channels": ["sms"], "phone_number": "+1"
        })
        sid = resp.get_json()["session_id"]
        status_resp = client.get(f"/api/v1/otp/{sid}/status")
        assert status_resp.status_code == 200
        assert status_resp.get_json()["status"] == "pending"

    def test_status_not_found(self, client):
        resp = client.get("/api/v1/otp/nonexistent/status")
        assert resp.status_code == 404


# ── Webhook ───────────────────────────────────────────────────────────────────

class TestWebhook:
    @patch("app.channels.sms_channel.SMSMagicChannel.send_otp", side_effect=_mock_send_success)
    def test_webhook_validates_otp(self, mock_send, client):
        with patch("app.services.otp_service._generate_otp", return_value="999888"):
            gen = client.post("/api/v1/otp/generate", json={
                "channels": ["sms"], "phone_number": "+1"
            })
        sid = gen.get_json()["session_id"]

        wh_resp = client.post("/webhooks/sms-magic/incoming", json={
            "from": "+1", "body": "999888", "reference": sid
        })
        assert wh_resp.status_code == 200
        result = wh_resp.get_json()["validation"]
        assert result["status"] == "verified"

    def test_webhook_no_reference_ignored(self, client):
        resp = client.post("/webhooks/sms-magic/incoming", json={
            "from": "+1", "body": "123456"
        })
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "ignored"


# ── Health ────────────────────────────────────────────────────────────────────

def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["db"] == "ok"
