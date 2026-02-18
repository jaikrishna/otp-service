"""
MCP (Model Context Protocol) Server for OTP Service.

Exposes OTP operations as MCP tools so Claude Code / any MCP client
can call them in agentic workflows without custom integration code.

Usage:
    python mcp_server.py

Then add to your Claude Code config:
    {
      "mcpServers": {
        "otp": {
          "command": "python",
          "args": ["mcp_server.py"],
          "cwd": "/path/to/otp-service"
        }
      }
    }
"""
import json
import sys
import requests
import os

OTP_SERVICE_BASE = os.getenv("OTP_SERVICE_URL", "http://localhost:5000/api/v1/otp")
WEBHOOK_TOKEN = os.getenv("INCOMING_WEBHOOK_TOKEN", "")


# ── MCP protocol helpers ──────────────────────────────────────────────────────

def _send(msg: dict):
    print(json.dumps(msg), flush=True)


def _read() -> dict:
    line = sys.stdin.readline()
    if not line:
        sys.exit(0)
    return json.loads(line)


# ── Tool definitions ──────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "generate_otp",
        "description": (
            "Generate and send an OTP to a user via one or more channels "
            "(sms, email, whatsapp, rcs). Returns a session_id for tracking."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "channels": {
                    "type": "array", "items": {"type": "string"},
                    "description": "Channels to use: sms, email, whatsapp, rcs",
                    "example": ["sms"]
                },
                "phone_number": {"type": "string", "description": "E.164 phone number"},
                "email_address": {"type": "string", "description": "Email address"},
                "callback_url": {"type": "string", "description": "Callback URL for result notification"},
                "external_ref": {"type": "string", "description": "Your correlation ID"},
            },
            "required": ["channels"],
        },
    },
    {
        "name": "verify_otp",
        "description": "Verify an OTP code submitted by the user against an existing session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "otp": {"type": "string", "description": "The code the user entered"},
            },
            "required": ["session_id", "otp"],
        },
    },
    {
        "name": "resend_otp",
        "description": "Resend the OTP for an existing session (subject to cooldown).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "get_otp_status",
        "description": "Get the current status and delivery logs for an OTP session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
            },
            "required": ["session_id"],
        },
    },
]


# ── Tool execution ────────────────────────────────────────────────────────────

def _call_api(method: str, path: str, body: dict = None) -> dict:
    url = f"{OTP_SERVICE_BASE}{path}"
    try:
        if method == "POST":
            resp = requests.post(url, json=body, timeout=10)
        else:
            resp = requests.get(url, timeout=10)
        return {"status_code": resp.status_code, "body": resp.json()}
    except Exception as exc:
        return {"error": str(exc)}


def execute_tool(name: str, args: dict) -> str:
    if name == "generate_otp":
        result = _call_api("POST", "/generate", args)
    elif name == "verify_otp":
        result = _call_api("POST", "/verify", args)
    elif name == "resend_otp":
        result = _call_api("POST", "/resend", args)
    elif name == "get_otp_status":
        sid = args.get("session_id", "")
        result = _call_api("GET", f"/{sid}/status")
    else:
        result = {"error": f"Unknown tool: {name}"}

    return json.dumps(result, indent=2)


# ── MCP event loop ────────────────────────────────────────────────────────────

def main():
    while True:
        msg = _read()
        method = msg.get("method")
        msg_id = msg.get("id")

        if method == "initialize":
            _send({
                "jsonrpc": "2.0", "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "otp-service", "version": "1.0.0"},
                },
            })

        elif method == "tools/list":
            _send({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}})

        elif method == "tools/call":
            tool_name = msg["params"]["name"]
            tool_args = msg["params"].get("arguments", {})
            content = execute_tool(tool_name, tool_args)
            _send({
                "jsonrpc": "2.0", "id": msg_id,
                "result": {"content": [{"type": "text", "text": content}]},
            })

        elif method == "notifications/initialized":
            pass  # No response needed

        else:
            if msg_id:
                _send({
                    "jsonrpc": "2.0", "id": msg_id,
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                })


if __name__ == "__main__":
    main()
