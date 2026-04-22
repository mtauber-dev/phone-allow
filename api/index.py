import hashlib
import hmac
import json
import os
import re
import urllib.parse
import urllib.request

from flask import Flask, request, jsonify
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

app = Flask(__name__)

# Cache of apps that AMAPI rejects managedConfiguration for — persists for lifetime of function instance
_url_policy_unsupported_apps: set[str] = set()

def _env(key: str) -> str:
    val = os.environ.get(key)
    if not val:
        raise RuntimeError(f"Missing environment variable: {key}")
    return val

ENTERPRISE_ID = "enterprises/LC01pmydxo"
POLICY_NAME = f"{ENTERPRISE_ID}/policies/private-device"
DEVICE_NAME = f"{ENTERPRISE_ID}/devices/3cd647d05b0130a5"
AMAPI_SCOPES = ["https://www.googleapis.com/auth/androidmanagement"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_sig(url: str) -> str:
    return hmac.new(_env("APPROVE_SECRET").encode(), url.encode(), hashlib.sha256).hexdigest()


def verify_sig(url: str, sig: str) -> bool:
    return hmac.compare_digest(make_sig(url), sig)


def send_telegram(text: str, reply_markup: dict) -> None:
    payload = json.dumps({
        "chat_id": _env("TELEGRAM_CHAT_ID"),
        "text": text,
        "parse_mode": "HTML",
        "reply_markup": reply_markup
    }).encode()
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{_env('TELEGRAM_BOT_TOKEN')}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    urllib.request.urlopen(req, timeout=10)


def get_amapi_service():
    sa_info = json.loads(_env("SA_KEY_JSON"))
    creds = service_account.Credentials.from_service_account_info(sa_info, scopes=AMAPI_SCOPES)
    return build("androidmanagement", "v1", credentials=creds, cache_discovery=False)


def propagate_url_policy(policy: dict) -> None:
    """Copy Chrome's URLBlocklist/URLAllowlist to every non-blocked, non-disabled app.
    Skips apps known to not support managedConfiguration."""
    apps = policy.get("applications", [])
    chrome = next((a for a in apps if a.get("packageName") == "com.android.chrome"), None)
    if not chrome:
        return
    chrome_mc = chrome.get("managedConfiguration", {})
    blocklist = list(chrome_mc.get("URLBlocklist", []))
    allowlist = list(chrome_mc.get("URLAllowlist", []))

    for app_entry in apps:
        pkg = app_entry.get("packageName", "")
        if pkg == "com.android.chrome":
            continue
        if pkg in _url_policy_unsupported_apps:
            continue
        if app_entry.get("installType") == "BLOCKED":
            continue
        if app_entry.get("disabled"):
            continue
        mc = app_entry.setdefault("managedConfiguration", {})
        mc["URLBlocklist"] = blocklist
        mc["URLAllowlist"] = allowlist


def strip_managed_config(policy: dict, package_name: str) -> None:
    for app_entry in policy.get("applications", []):
        if app_entry.get("packageName") == package_name:
            mc = app_entry.get("managedConfiguration", {})
            mc.pop("URLBlocklist", None)
            mc.pop("URLAllowlist", None)
            if not mc:
                app_entry.pop("managedConfiguration", None)
            break


def safe_patch_policy(service, policy: dict, max_retries: int = 20):
    """Patch policy, removing managedConfiguration from unsupported apps and retrying."""
    for _ in range(max_retries):
        try:
            return service.enterprises().policies().patch(name=POLICY_NAME, body=policy).execute()
        except HttpError as e:
            text = str(e)
            m = re.search(r"not supported for (\S+?)[\"'\)\.]", text + '"')
            if m:
                pkg = m.group(1).rstrip(".,;:")
                _url_policy_unsupported_apps.add(pkg)
                strip_managed_config(policy, pkg)
                continue
            raise
    raise RuntimeError("Too many retries stripping unsupported apps")


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
    propagate_url_policy(policy)
    safe_patch_policy(service, policy)
    service.enterprises().devices().patch(
        name=DEVICE_NAME, updateMask="policyName",
        body={"policyName": POLICY_NAME}
    ).execute()
    return True


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Request a Website</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f0f2f5;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
    .card{background:white;border-radius:16px;padding:32px 28px;width:100%;max-width:420px;box-shadow:0 4px 24px rgba(0,0,0,0.08)}
    h1{font-size:22px;font-weight:700;color:#1a1a1a;margin-bottom:6px}
    p.subtitle{font-size:14px;color:#666;margin-bottom:28px}
    label{display:block;font-size:13px;font-weight:600;color:#444;margin-bottom:6px}
    input,textarea{width:100%;padding:12px 14px;border:1.5px solid #e0e0e0;border-radius:10px;font-size:16px;color:#1a1a1a;outline:none;transition:border-color 0.2s;margin-bottom:18px}
    input:focus,textarea:focus{border-color:#4f6ef7}
    textarea{resize:none;height:90px;font-family:inherit}
    button{width:100%;padding:14px;background:#4f6ef7;color:white;border:none;border-radius:10px;font-size:16px;font-weight:600;cursor:pointer;transition:background 0.2s}
    button:hover{background:#3a57e8}
    button:disabled{background:#a0a0a0;cursor:not-allowed}
    .message{margin-top:18px;padding:12px 14px;border-radius:10px;font-size:14px;display:none}
    .message.success{background:#e8f5e9;color:#2e7d32}
    .message.error{background:#fdecea;color:#c62828}
  </style>
</head>
<body>
  <div class="card">
    <h1>Request a Website</h1>
    <p class="subtitle">Submit a site you'd like access to. Dad will get notified to approve it.</p>
    <form id="form">
      <label for="url">Website</label>
      <input type="text" id="url" name="url" placeholder="e.g. wikipedia.org" autocapitalize="none" autocorrect="off" required>
      <label for="reason">Reason <span style="font-weight:400;color:#999">(optional)</span></label>
      <textarea id="reason" name="reason" placeholder="Why do you need this site?"></textarea>
      <button type="submit" id="btn">Send Request</button>
    </form>
    <div class="message" id="msg"></div>
  </div>
  <script>
    document.getElementById('form').addEventListener('submit', async function(e) {
      e.preventDefault();
      const btn = document.getElementById('btn');
      const msg = document.getElementById('msg');
      btn.disabled = true;
      btn.textContent = 'Sending...';
      msg.style.display = 'none';
      const url = document.getElementById('url').value.trim();
      const reason = document.getElementById('reason').value.trim();
      try {
        const res = await fetch('/api/submit', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({url, reason})
        });
        const data = await res.json();
        if (res.ok) {
          msg.className = 'message success';
          msg.textContent = 'Request sent! Dad will review it.';
          document.getElementById('form').reset();
        } else {
          msg.className = 'message error';
          msg.textContent = data.error || 'Something went wrong. Try again.';
        }
      } catch {
        msg.className = 'message error';
        msg.textContent = 'Network error. Try again.';
      }
      msg.style.display = 'block';
      btn.disabled = false;
      btn.textContent = 'Send Request';
    });
  </script>
</body>
</html>"""


@app.route("/")
def index():
    return INDEX_HTML


@app.route("/api/submit", methods=["POST"])
def submit():
    body = request.get_json(silent=True) or {}
    url = re.sub(r'^https?://', '', (body.get("url") or "").strip().lower()).strip("/")
    reason = (body.get("reason") or "").strip()

    if not url:
        return jsonify({"error": "URL is required"}), 400

    sig = make_sig(url)
    app_url = _env("APP_URL").rstrip("/")
    approve_url = f"{app_url}/api/approve?url={urllib.parse.quote(url)}&sig={sig}"
    deny_url = f"{app_url}/api/deny?url={urllib.parse.quote(url)}&sig={sig}"

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
