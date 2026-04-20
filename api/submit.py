import hashlib
import hmac
import json
import os
import re
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler

TELEGRAM_BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
TELEGRAM_CHAT_ID = os.environ["TELEGRAM_CHAT_ID"]
APPROVE_SECRET = os.environ["APPROVE_SECRET"]
APP_URL = os.environ["APP_URL"].rstrip("/")


def make_sig(url: str) -> str:
    return hmac.new(
        APPROVE_SECRET.encode(),
        url.encode(),
        hashlib.sha256
    ).hexdigest()


def send_telegram(text: str, reply_markup: dict) -> None:
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "reply_markup": json.dumps(reply_markup)
    }
    data = urllib.parse.urlencode(payload).encode()
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
        data=data
    )
    urllib.request.urlopen(req, timeout=10)


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(content_length)

        try:
            body = json.loads(raw)
        except Exception:
            self._respond(400, {"error": "Invalid JSON"})
            return

        url = (body.get("url") or "").strip().lower()
        reason = (body.get("reason") or "").strip()

        # Strip protocol if provided
        url = re.sub(r'^https?://', '', url).strip("/")

        if not url:
            self._respond(400, {"error": "URL is required"})
            return

        sig = make_sig(url)
        approve_url = f"{APP_URL}/api/approve?url={urllib.parse.quote(url)}&sig={sig}"
        deny_url = f"{APP_URL}/api/deny?url={urllib.parse.quote(url)}&sig={sig}"

        reason_line = f"\n<i>Reason: {reason}</i>" if reason else ""
        text = (
            f"🔗 <b>Website Request</b>\n\n"
            f"<b>{url}</b>{reason_line}\n\n"
            f"Tap Approve to allow Chrome access."
        )
        reply_markup = {
            "inline_keyboard": [[
                {"text": "✅ Approve", "url": approve_url},
                {"text": "❌ Deny", "url": deny_url}
            ]]
        }

        try:
            send_telegram(text, reply_markup)
            self._respond(200, {"ok": True})
        except Exception as e:
            self._respond(500, {"error": str(e)})

    def _respond(self, status: int, body: dict):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(payload))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass
