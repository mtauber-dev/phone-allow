import hashlib
import hmac
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler

APPROVE_SECRET = os.environ["APPROVE_SECRET"]


def verify_sig(url: str, sig: str) -> bool:
    expected = hmac.new(
        APPROVE_SECRET.encode(),
        url.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, sig)


HTML_DENIED = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Denied</title>
<style>
body{font-family:-apple-system,sans-serif;background:#f0f2f5;display:flex;align-items:center;
justify-content:center;min-height:100vh;padding:24px;margin:0}
.card{background:white;border-radius:16px;padding:32px 28px;max-width:360px;width:100%;
text-align:center;box-shadow:0 4px 24px rgba(0,0,0,0.08)}
.icon{font-size:48px;margin-bottom:16px}
h1{font-size:20px;font-weight:700;margin-bottom:8px;color:#1a1a1a}
p{font-size:14px;color:#666}
</style></head>
<body><div class="card">
<div class="icon">❌</div>
<h1>Request Denied</h1>
<p>Access to <b>{url}</b> was not approved.</p>
</div></body></html>"""


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        params = dict(urllib.parse.parse_qsl(
            urllib.parse.urlparse(self.path).query
        ))
        url = params.get("url", "").strip()
        sig = params.get("sig", "").strip()

        if not url or not sig or not verify_sig(url, sig):
            url = "that site"

        self._html(200, HTML_DENIED.format(url=url))

    def _html(self, status: int, body: str):
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(payload))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass
