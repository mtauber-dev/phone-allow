import hashlib
import hmac
import json
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler

from google.oauth2 import service_account
from googleapiclient.discovery import build

APPROVE_SECRET = os.environ["APPROVE_SECRET"]
SA_KEY_JSON = os.environ["SA_KEY_JSON"]

ENTERPRISE_ID = "enterprises/LC01pmydxo"
POLICY_NAME = f"{ENTERPRISE_ID}/policies/private-device"
DEVICE_NAME = f"{ENTERPRISE_ID}/devices/3cd647d05b0130a5"
AMAPI_SCOPES = ["https://www.googleapis.com/auth/androidmanagement"]


def verify_sig(url: str, sig: str) -> bool:
    expected = hmac.new(
        APPROVE_SECRET.encode(),
        url.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, sig)


def get_service():
    sa_info = json.loads(SA_KEY_JSON)
    credentials = service_account.Credentials.from_service_account_info(
        sa_info, scopes=AMAPI_SCOPES
    )
    return build("androidmanagement", "v1", credentials=credentials, cache_discovery=False)


def add_url_to_allowlist(url: str) -> None:
    service = get_service()
    policy = service.enterprises().policies().get(name=POLICY_NAME).execute()

    apps = policy.get("applications", [])
    chrome = None
    for app in apps:
        if app.get("packageName") == "com.android.chrome":
            chrome = app
            break
    if chrome is None:
        chrome = {"packageName": "com.android.chrome"}
        apps.append(chrome)

    mc = chrome.setdefault("managedConfiguration", {})
    mc.setdefault("URLBlocklist", ["*"])
    allowlist = mc.setdefault("URLAllowlist", [])

    if url not in allowlist:
        allowlist.append(url)
        policy["applications"] = apps
        service.enterprises().policies().patch(name=POLICY_NAME, body=policy).execute()
        service.enterprises().devices().patch(
            name=DEVICE_NAME, updateMask="policyName",
            body={"policyName": POLICY_NAME}
        ).execute()


HTML_SUCCESS = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Approved</title>
<style>
body{font-family:-apple-system,sans-serif;background:#f0f2f5;display:flex;align-items:center;
justify-content:center;min-height:100vh;padding:24px;margin:0}
.card{background:white;border-radius:16px;padding:32px 28px;max-width:360px;width:100%;
text-align:center;box-shadow:0 4px 24px rgba(0,0,0,0.08)}
.icon{font-size:48px;margin-bottom:16px}
h1{font-size:20px;font-weight:700;margin-bottom:8px;color:#1a1a1a}
p{font-size:14px;color:#666}
.url{font-weight:600;color:#4f6ef7;word-break:break-all}
</style></head>
<body><div class="card">
<div class="icon">✅</div>
<h1>Approved</h1>
<p>Access to <span class="url">{url}</span> has been granted. It may take a moment to apply.</p>
</div></body></html>"""

HTML_ALREADY = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Already Allowed</title>
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
<div class="icon">ℹ️</div>
<h1>Already Allowed</h1>
<p>{url} was already in the allowlist.</p>
</div></body></html>"""

HTML_ERROR = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Error</title>
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
<h1>Error</h1>
<p>{error}</p>
</div></body></html>"""


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        params = dict(urllib.parse.parse_qsl(
            urllib.parse.urlparse(self.path).query
        ))
        url = params.get("url", "").strip()
        sig = params.get("sig", "").strip()

        if not url or not sig or not verify_sig(url, sig):
            self._html(403, HTML_ERROR.format(error="Invalid or expired approval link."))
            return

        try:
            service = get_service()
            policy = service.enterprises().policies().get(name=POLICY_NAME).execute()
            for app in policy.get("applications", []):
                if app.get("packageName") == "com.android.chrome":
                    existing = app.get("managedConfiguration", {}).get("URLAllowlist", [])
                    if url in existing:
                        self._html(200, HTML_ALREADY.format(url=url))
                        return

            add_url_to_allowlist(url)
            self._html(200, HTML_SUCCESS.format(url=url))

        except Exception as e:
            self._html(500, HTML_ERROR.format(error=str(e)))

    def _html(self, status: int, body: str):
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(payload))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass
