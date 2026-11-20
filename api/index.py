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
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "").strip()
DEFAULT_FROM_EMAIL = os.environ.get("FROM_EMAIL", "").strip()

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
SEND_DELAY_SECONDS = 0.8
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")


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
        if "timeout-or-duplicate" in codes:
            return False, "Cloudflare token expired or already used. Verify again."
        return False, f"Cloudflare verification failed ({', '.join(codes) or 'unknown'})."
    except Exception:
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


def send_resend(from_addr, sender_name, subject, body, is_html, recipient):
    from_hdr = f"{clean_header(sender_name, 100)} <{from_addr}>" if sender_name else from_addr
    payload = {
        "from": from_hdr,
        "reply_to": from_addr,
        "to": [recipient],
        "subject": subject,
        "text": to_plain(body) if is_html else body,
    }
    if is_html:
        payload["html"] = body

    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            res = json.loads(resp.read().decode("utf-8"))
        return {"email": recipient, "result": "sent"} if res.get("id") else {
            "email": recipient, "result": "failed", "error": "No ID returned by Resend."
        }
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", errors="ignore")
        return {"email": recipient, "result": "failed", "error": f"Resend {e.code}: {err[:250]}"}
    except Exception as e:
        return {"email": recipient, "result": "failed", "error": str(e)[:250]}


def build_smtp_msg(from_email, sender_name, subject, body, is_html, recipient):
    clean_body = str(body or "").replace("\x00", "")
    domain = from_email.split("@", 1)[1] if "@" in from_email else "gmail.com"
    if is_html:
        msg = MIMEMultipart("alternative")
        msg.attach(MIMEText(to_plain(clean_body) or " ", "plain", "utf-8"))
        msg.attach(MIMEText(clean_body, "html", "utf-8"))
    else:
        msg = MIMEText(clean_body, "plain", "utf-8")

    msg["Subject"] = subject
    msg["From"] = formataddr((sender_name, from_email))
    msg["Reply-To"] = from_email
    msg["To"] = recipient
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=domain)
    return msg


def open_smtp(gmail, app_password):
    clean_pwd = re.sub(r"\s+", "", app_password)
    server = smtplib.SMTP_SSL("smtp.gmail.com", 465, context=ssl.create_default_context(), timeout=20)
    server.ehlo()
    server.login(gmail, clean_pwd)
    return server


def close_smtp(server):
    if server:
        try:
            server.quit()
        except Exception:
            pass


def send_smtp_with_reconnect(server, gmail, app_password, sender_name, subject, body, is_html, recipient):
    msg = build_smtp_msg(gmail, sender_name, subject, body, is_html, recipient)
    raw_msg = msg.as_string()

    # Try existing connection once, and if disconnected/dropped, open a fresh one once
    for attempt in range(2):
        try:
            if server is None:
                server = open_smtp(gmail, app_password)
            refused = server.sendmail(gmail, [recipient], raw_msg)
            if refused:
                return server, {"email": recipient, "result": "failed", "error": "Recipient refused by SMTP."}
            return server, {"email": recipient, "result": "sent"}
        except smtplib.SMTPAuthenticationError as e:
            close_smtp(server)
            return None, {"email": recipient, "result": "failed", "error": f"Auth failed: {str(e)[:200]}"}
        except Exception as e:
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
    from_override = clean_header(data.get("from_email", ""), 254).lower()
    app_password = str(data.get("app_password", "")).strip()
    subject = clean_header(data.get("subject", ""), 998)
    body = str(data.get("body", ""))
    is_html = data.get("is_html", False) is True
    recipients = data.get("recipients", [])
    turnstile_token = str(data.get("turnstile_token", "")).strip()

    if not sender_name or not subject or not body.strip():
        return jsonify({"success": False, "message": "Sender name, subject, and body are required."}), 400

    if not RESEND_API_KEY and (not valid_email(gmail) or not gmail.endswith("@gmail.com") or not app_password):
        return jsonify({"success": False, "message": "Valid @gmail.com and App Password are required."}), 400

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

    @stream_with_context
    def generate():
        total = len(clean_recipients)
        sent = 0
        failed = 0

        yield json.dumps({"type": "start", "total": total, "sent": 0, "failed": 0, "remaining": total}) + "\n"

        smtp_server = None
        if not RESEND_API_KEY:
            try:
                smtp_server = open_smtp(gmail, app_password)
            except Exception:
                smtp_server = None

        try:
            for idx, r in enumerate(clean_recipients):
                if idx > 0 and SEND_DELAY_SECONDS > 0:
                    time.sleep(SEND_DELAY_SECONDS)

                p_subj = personalize(subject, r)
                p_body = personalize(body, r)

                if RESEND_API_KEY:
                    from_addr = from_override if valid_email(from_override) else DEFAULT_FROM_EMAIL
                    if not valid_email(from_addr):
                        res = {"email": r["email"], "result": "failed", "error": "Set FROM_EMAIL in env."}
                    else:
                        res = send_resend(from_addr, sender_name, p_subj, p_body, is_html, r["email"])
                else:
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
        "provider": "Resend API" if RESEND_API_KEY else "Gmail SMTP",
        "turnstile_verified": turnstile_verified(),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
