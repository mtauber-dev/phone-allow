import hashlib
import hmac
import json
import os
import re
import urllib.parse
import urllib.request

from flask import Flask, request, jsonify, send_from_directory
from google.oauth2 import service_account
from googleapiclient.discovery import build

app = Flask(__name__, static_folder="../public")

TELEGRAM_BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
TELEGRAM_CHAT_ID = os.environ["TELEGRAM_CHAT_ID"]
APPROVE_SECRET = os.environ["APPROVE_SECRET"]
SA_KEY_JSON = os.environ["SA_KEY_JSON"]
APP_URL = os.environ["APP_URL"].rstrip("/")

ENTERPRISE_ID = "enterprises/LC01pmydxo"
POLICY_NAME = f"{ENTERPRISE_ID}/policies/private-device"
DEVICE_NAME = f"{ENTERPRISE_ID}/devices/3cd647d05b0130a5"
AMAPI_SCOPES = ["https://www.googleapis.com/auth/androidmanagement"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_sig(url: str) -> str:
    return hmac.new(APPROVE_SECRET.encode(), url.encode(), hashlib.sha256).hexdigest()


def verify_sig(url: str, sig: str) -> bool:
    return hmac.compare_digest(make_sig(url), sig)


def send_telegram(text: str, reply_markup: dict) -> None:
    payload = json.dumps({
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "reply_markup": reply_markup
    }).encode()
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    urllib.request.urlopen(req, timeout=10)


def get_amapi_service():
    sa_info = json.loads(SA_KEY_JSON)
    creds = service_account.Credentials.from_service_account_info(sa_info, scopes=AMAPI_SCOPES)
    return build("androidmanagement", "v1", credentials=creds, cache_discovery=False)


def add_url_to_allowlist(url: str) -> bool:
    """Returns True if added, False if already present."""
    service = get_amapi_service()
    policy = service.enterprises().policies().get(name=POLICY_NAME).execute()

    apps = policy.get("applications", [])
    chrome = next((a for a in apps if a.get("packageName") == "com.android.chrome"), None)
    if chrome is None:
        chrome = {"packageName": "com.android.chrome"}
        apps.append(chrome)

    mc = chrome.setdefault("managedConfiguration", {})
    mc.setdefault("URLBlocklist", ["*"])
    allowlist = mc.setdefault("URLAllowlist", [])

    if url in allowlist:
        return False

    allowlist.append(url)
    policy["applications"] = apps
    service.enterprises().policies().patch(name=POLICY_NAME, body=policy).execute()
    service.enterprises().devices().patch(
        name=DEVICE_NAME, updateMask="policyName",
        body={"policyName": POLICY_NAME}
    ).execute()
    return True


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/submit", methods=["POST"])
def submit():
    body = request.get_json(silent=True) or {}
    url = re.sub(r'^https?://', '', (body.get("url") or "").strip().lower()).strip("/")
    reason = (body.get("reason") or "").strip()

    if not url:
        return jsonify({"error": "URL is required"}), 400

    sig = make_sig(url)
    approve_url = f"{APP_URL}/api/approve?url={urllib.parse.quote(url)}&sig={sig}"
    deny_url = f"{APP_URL}/api/deny?url={urllib.parse.quote(url)}&sig={sig}"

    reason_line = f"\n<i>Reason: {reason}</i>" if reason else ""
    text = f"🔗 <b>Website Request</b>\n\n<b>{url}</b>{reason_line}\n\nTap Approve to allow Chrome access."
    reply_markup = {
        "inline_keyboard": [[
            {"text": "✅ Approve", "url": approve_url},
            {"text": "❌ Deny", "url": deny_url}
        ]]
    }

    try:
        send_telegram(text, reply_markup)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/approve")
def approve():
    url = request.args.get("url", "").strip()
    sig = request.args.get("sig", "").strip()

    if not url or not sig or not verify_sig(url, sig):
        return _html_page("❌", "Invalid Link", "This approval link is invalid or expired.", "#c62828"), 403

    try:
        added = add_url_to_allowlist(url)
        if added:
            return _html_page("✅", "Approved", f"Access to <b>{url}</b> has been granted. It may take a moment to apply.", "#2e7d32")
        else:
            return _html_page("ℹ️", "Already Allowed", f"{url} was already in the allowlist.", "#1565c0")
    except Exception as e:
        return _html_page("❌", "Error", str(e), "#c62828"), 500


@app.route("/api/deny")
def deny():
    url = request.args.get("url", "").strip()
    sig = request.args.get("sig", "").strip()
    display = url if (url and sig and verify_sig(url, sig)) else "that site"
    return _html_page("❌", "Request Denied", f"Access to <b>{display}</b> was not approved.", "#c62828")


def _html_page(icon: str, title: str, body: str, color: str) -> str:
    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
body{{font-family:-apple-system,sans-serif;background:#f0f2f5;display:flex;align-items:center;
justify-content:center;min-height:100vh;padding:24px;margin:0}}
.card{{background:white;border-radius:16px;padding:32px 28px;max-width:360px;width:100%;
text-align:center;box-shadow:0 4px 24px rgba(0,0,0,0.08)}}
.icon{{font-size:48px;margin-bottom:16px}}
h1{{font-size:20px;font-weight:700;margin-bottom:8px;color:{color}}}
p{{font-size:14px;color:#555;line-height:1.5}}
</style></head>
<body><div class="card">
<div class="icon">{icon}</div>
<h1>{title}</h1>
<p>{body}</p>
</div></body></html>"""
