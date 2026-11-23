from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    session,
    Response,
    stream_with_context,
)
import smtplib
import ssl
import re
import os
import json
import sys
import traceback
import urllib.request
import urllib.parse
import secrets
import time
import html as html_lib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr, formatdate, make_msgid
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)
handler = app

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "").strip()
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "").strip()
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "").strip()

if not SESSION_SECRET or not LOGIN_PASSWORD:
    raise RuntimeError("SESSION_SECRET and LOGIN_PASSWORD are required.")

app.secret_key = SESSION_SECRET
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
)

MAX_RECIPIENTS = 25
SEND_DELAY_SECONDS = 0.5
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25

EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")


def log(msg):
    """Simple console logger so you can see what's actually happening on the server."""
    print(f"[mailer] {msg}", file=sys.stderr, flush=True)


def valid_email(v):
    return isinstance(v, str) and 0 < len(v.strip()) <= 254 and bool(EMAIL_RE.fullmatch(v.strip()))


def normalize_email(v):
    return str(v or "").strip().lower()


def authenticated():
    return session.get("authenticated") is True


def turnstile_verified():
    return session.get("turnstile_verified") is True


def clean_header(v, limit=998):
    return str(v or "").replace("\r", " ").replace("\n", " ").strip()[:limit]


def to_bool(v):
    """Accepts real booleans AND string/number forms ('true', '1', 1, etc.)."""
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v == 1
    if isinstance(v, str):
        return v.strip().lower() in ("true", "1", "yes", "on")
    return False


def personalize(text, r):
    out = str(text or "")
    for k in ("hi", "hello", "thanks", "name", "email", "ref_code"):
        out = out.replace(f"{{{{{k}}}}}", str(r.get(k, "") or ""))
    return out


def to_plain(raw_html):
    text = re.sub(r"<br\s*/?>", "\n", str(raw_html or ""), flags=re.I)
    text = re.sub(r"</p\s*>", "\n\n", text, flags=re.I)
    text = re.sub(r"<[^>]+>", "", text)
    return re.sub(r"\n{3,}", "\n\n", html_lib.unescape(text)).strip()


def verify_turnstile(token, remote_ip=None):
    if not TURNSTILE_SECRET_KEY:
        return False, "TURNSTILE_SECRET_KEY is not configured."
    token = str(token or "").strip()
    if not token:
        return False, "Cloudflare verification is required."

    payload = {"secret": TURNSTILE_SECRET_KEY, "response": token}
    if remote_ip:
        payload["remoteip"] = remote_ip

    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=urllib.parse.urlencode(payload).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if data.get("success") is True:
            return True, None
        codes = data.get("error-codes") or []
        log(f"Turnstile failed: {codes}")
        if "timeout-or-duplicate" in codes:
            return False, "Cloudflare token expired or already used. Verify again."
        return False, f"Cloudflare verification failed ({', '.join(codes) or 'unknown'})."
    except Exception:
        log("Turnstile verification exception:\n" + traceback.format_exc())
        return False, "Unable to verify Cloudflare."


@app.route("/login", methods=["GET", "POST"])
def login():
    if authenticated():
        return redirect(url_for("home"))
    if request.method == "GET":
        return render_template("login.html", error=None, turnstile_site_key=TURNSTILE_SITE_KEY)

    if not secrets.compare_digest(str(request.form.get("password", "")), LOGIN_PASSWORD):
        return render_template("login.html", error="Incorrect password.", turnstile_site_key=TURNSTILE_SITE_KEY), 401

    session.clear()
    session.permanent = True
    session["authenticated"] = True
    session["turnstile_verified"] = False
    return redirect(url_for("home"))


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def home():
    if not authenticated():
        return redirect(url_for("login"))
    return render_template(
        "index.html",
        turnstile_site_key=TURNSTILE_SITE_KEY,
        turnstile_verified=turnstile_verified(),
    )


def build_message(gmail, sender_name, subject, body, is_html, recipient):
    clean_body = str(body or "").replace("\x00", "")
    if is_html:
        msg = MIMEMultipart("alternative")
        msg.attach(MIMEText(to_plain(clean_body) or " ", "plain", "utf-8"))
        msg.attach(MIMEText(clean_body, "html", "utf-8"))
    else:
        msg = MIMEText(clean_body, "plain", "utf-8")

    msg["Subject"] = subject
    msg["From"] = formataddr((sender_name, gmail))
    msg["To"] = recipient
    msg["Reply-To"] = gmail
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="gmail.com")
    return msg


def open_smtp(gmail, app_password):
    clean_pwd = re.sub(r"\s+", "", app_password)
    server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ssl.create_default_context(), timeout=SMTP_TIMEOUT)
    server.ehlo()
    server.login(gmail, clean_pwd)
    log(f"SMTP login OK for {gmail}")
    return server


def close_smtp(server):
    if server:
        try:
            server.quit()
        except Exception:
            pass


def send_smtp_with_reconnect(server, gmail, app_password, sender_name, subject, body, is_html, recipient):
    msg = build_message(gmail, sender_name, subject, body, is_html, recipient)
    raw_msg = msg.as_string()

    for attempt in range(2):
        try:
            if server is None:
                server = open_smtp(gmail, app_password)
            refused = server.sendmail(gmail, [recipient], raw_msg)
            if refused:
                log(f"SMTP refused {recipient}: {refused}")
                return server, {"email": recipient, "result": "failed", "error": f"SMTP refused recipient: {refused}"}
            log(f"SMTP accepted message for {recipient} (Message-ID: {msg['Message-ID']})")
            return server, {"email": recipient, "result": "sent"}
        except smtplib.SMTPAuthenticationError as e:
            log(f"SMTP auth error for {gmail}: {e}")
            close_smtp(server)
            return None, {"email": recipient, "result": "failed", "error": "Gmail authentication failed. Check the App Password (not your normal Gmail password)."}
        except Exception as e:
            log(f"SMTP error sending to {recipient} (attempt {attempt + 1}): {traceback.format_exc()}")
            close_smtp(server)
            server = None
            if attempt == 1:
                return None, {"email": recipient, "result": "failed", "error": f"SMTP error: {str(e)[:220]}"}


@app.route("/send-batch", methods=["POST"])
def send_batch():
    if not authenticated():
        return jsonify({"success": False, "message": "Authentication required.", "login_required": True}), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "message": "Invalid JSON request."}), 400

    sender_name = clean_header(data.get("sender_name", ""), 200)
    gmail = clean_header(data.get("gmail", ""), 254).lower()
    app_password = str(data.get("app_password", "")).strip()
    subject = clean_header(data.get("subject", ""), 998)
    body = str(data.get("body", ""))
    is_html = to_bool(data.get("is_html", False))
    recipients = data.get("recipients", [])
    turnstile_token = str(data.get("turnstile_token", "")).strip()

    if not sender_name:
        return jsonify({"success": False, "message": "Sender Name is required."}), 400
    if not valid_email(gmail) or not gmail.endswith("@gmail.com"):
        return jsonify({"success": False, "message": "Enter a valid @gmail.com address."}), 400
    if not app_password:
        return jsonify({"success": False, "message": "Google App Password is required."}), 400
    if not subject or not body.strip():
        return jsonify({"success": False, "message": "Subject and message body are required."}), 400
    if not isinstance(recipients, list):
        return jsonify({"success": False, "message": "Invalid recipient list."}), 400

    clean_recipients = []
    seen = set()
    for item in recipients:
        if isinstance(item, str):
            item = {"email": item}
        if not isinstance(item, dict):
            continue
        email = normalize_email(item.get("email", ""))
        if not valid_email(email) or email in seen:
            continue
        seen.add(email)
        clean_recipients.append({
            "email": email,
            "name": clean_header(item.get("name", ""), 200),
            "hi": clean_header(item.get("hi", ""), 100),
            "hello": clean_header(item.get("hello", ""), 100),
            "thanks": clean_header(item.get("thanks", ""), 100),
            "ref_code": clean_header(item.get("ref_code", ""), 200),
        })
        if len(clean_recipients) >= MAX_RECIPIENTS:
            break

    if not clean_recipients:
        return jsonify({"success": False, "message": "No valid recipients found."}), 400

    if not turnstile_verified():
        ip = (request.headers.get("X-Forwarded-For") or "").split(",", 1)[0].strip() or request.remote_addr
        ok, err = verify_turnstile(turnstile_token, ip)
        if not ok:
            return jsonify({"success": False, "message": err}), 403
        session["turnstile_verified"] = True

    # Fail fast: try logging in once *before* opening the stream, so a bad
    # app password / 2FA issue is reported clearly instead of silently
    # failing per-recipient inside the stream.
    try:
        test_server = open_smtp(gmail, app_password)
        close_smtp(test_server)
    except smtplib.SMTPAuthenticationError:
        log(f"Pre-flight SMTP auth failed for {gmail}")
        return jsonify({
            "success": False,
            "message": "Gmail authentication failed. Make sure 2-Step Verification is ON and you're using a 16-character App Password (not your login password).",
        }), 401
    except Exception as e:
        log("Pre-flight SMTP check failed:\n" + traceback.format_exc())
        return jsonify({"success": False, "message": f"Could not connect to Gmail SMTP: {str(e)[:220]}"}), 502

    @stream_with_context
    def generate():
        total = len(clean_recipients)
        sent = 0
        failed = 0

        yield json.dumps({"type": "start", "total": total, "sent": 0, "failed": 0, "remaining": total}) + "\n"

        smtp_server = None
        try:
            smtp_server = open_smtp(gmail, app_password)
        except Exception:
            log("Could not open SMTP connection for batch:\n" + traceback.format_exc())
            smtp_server = None

        try:
            for idx, r in enumerate(clean_recipients):
                if idx > 0 and SEND_DELAY_SECONDS > 0:
                    time.sleep(SEND_DELAY_SECONDS)

                p_subj = personalize(subject, r)
                p_body = personalize(body, r)

                smtp_server, res = send_smtp_with_reconnect(
                    smtp_server, gmail, app_password, sender_name, p_subj, p_body, is_html, r["email"]
                )

                if res["result"] == "sent":
                    sent += 1
                else:
                    failed += 1

                yield json.dumps({
                    "type": "progress",
                    "email": r["email"],
                    "result": res["result"],
                    "error": res.get("error"),
                    "total": total,
                    "sent": sent,
                    "failed": failed,
                    "remaining": total - sent - failed,
                }) + "\n"
        finally:
            close_smtp(smtp_server)

        log(f"Batch complete: {sent} sent, {failed} failed, {total} total")
        yield json.dumps({
            "type": "complete",
            "success": True,
            "message": "Sending completed.",
            "total": total,
            "sent": sent,
            "failed": failed,
            "remaining": total - sent - failed,
        }) + "\n"

    resp = Response(generate(), content_type="application/x-ndjson; charset=utf-8")
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, no-transform, max-age=0"
    resp.headers["X-Accel-Buffering"] = "no"
    return resp


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "mailer": "Gmail SMTP",
        "turnstile_verified": turnstile_verified(),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
