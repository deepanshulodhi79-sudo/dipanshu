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


# =========================================================
# APP (TOP-LEVEL ENTRYPOINT FOR VERCEL)
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)

handler = app


# =========================================================
# ENV VARIABLES
# =========================================================

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "").strip()
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "").strip()
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "").strip()

# Best for Inbox placement: Resend API + verified custom domain
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "").strip()
DEFAULT_FROM_EMAIL = os.environ.get("FROM_EMAIL", "").strip()

if not SESSION_SECRET:
    raise RuntimeError("SESSION_SECRET is not configured in Vercel.")

if not LOGIN_PASSWORD:
    raise RuntimeError("LOGIN_PASSWORD is not configured in Vercel.")

app.secret_key = SESSION_SECRET

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
)


# =========================================================
# INBOX-FRIENDLY MAIL SETTINGS
# =========================================================

MAX_RECIPIENTS = 25

# Sequential sending avoids burst patterns that trigger spam filters
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25
SEND_DELAY_SECONDS = 1.2


# =========================================================
# HELPERS
# =========================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def valid_email(value):
    if not isinstance(value, str):
        return False
    value = value.strip()
    if not value or len(value) > 254:
        return False
    return bool(EMAIL_RE.fullmatch(value))


def normalize_email(value):
    return str(value or "").strip().lower()


def authenticated():
    return session.get("authenticated") is True


def turnstile_already_verified():
    return session.get("turnstile_verified") is True


def clean_header(value, max_length=998):
    value = str(value or "")
    value = value.replace("\r", " ").replace("\n", " ")
    return value.strip()[:max_length]


def personalize_template(template, recipient):
    result = str(template or "")
    values = {
        "{{hi}}": str(recipient.get("hi", "") or ""),
        "{{hello}}": str(recipient.get("hello", "") or ""),
        "{{thanks}}": str(recipient.get("thanks", "") or ""),
        "{{name}}": str(recipient.get("name", "") or ""),
        "{{email}}": str(recipient.get("email", "") or ""),
        "{{ref_code}}": str(recipient.get("ref_code", "") or ""),
    }
    for placeholder, value in values.items():
        result = result.replace(placeholder, value)
    return result


def html_to_plain_text(raw_html):
    text = str(raw_html or "")
    text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.I | re.S)
    text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.I | re.S)
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.I)
    text = re.sub(r"</p\s*>", "\n\n", text, flags=re.I)
    text = re.sub(r"</div\s*>", "\n", text, flags=re.I)
    text = re.sub(r"<li\s*>", "- ", text, flags=re.I)
    text = re.sub(r"</li\s*>", "\n", text, flags=re.I)
    text = re.sub(r"<[^>]+>", "", text)
    text = html_lib.unescape(text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def wrap_clean_html(body_html):
    stripped = str(body_html or "").strip()
    if "<html" in stripped.lower():
        return stripped
    return (
        "<!DOCTYPE html>"
        "<html><head><meta charset=\"utf-8\"></head>"
        "<body style=\"font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:1.5;color:#222222;\">"
        f"{stripped}"
        "</body></html>"
    )


# =========================================================
# TURNSTILE VERIFICATION
# =========================================================

def verify_turnstile(token, remote_ip=None):
    if not TURNSTILE_SECRET_KEY:
        return False, "TURNSTILE_SECRET_KEY is not configured."

    token = str(token or "").strip()
    if not token:
        return False, "Cloudflare verification is required."

    payload = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token,
    }
    if remote_ip:
        payload["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(payload).encode("utf-8")

    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=encoded,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            result = json.loads(response.read().decode("utf-8"))

        if result.get("success") is True:
            return True, None

        error_codes = result.get("error-codes") or []
        print("Turnstile error-codes:", error_codes)

        if "timeout-or-duplicate" in error_codes:
            return False, "Cloudflare token already used or expired. Please verify again."

        return False, f"Cloudflare verification failed ({', '.join(error_codes) or 'unknown'})."

    except Exception as e:
        print("Turnstile exception:", str(e))
        return False, "Unable to verify Cloudflare."


# =========================================================
# AUTH & ROUTES
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if authenticated():
        return redirect(url_for("home"))

    if request.method == "GET":
        return render_template(
            "login.html",
            error=None,
            turnstile_site_key=TURNSTILE_SITE_KEY,
        )

    password = str(request.form.get("password", ""))
    if not secrets.compare_digest(password, LOGIN_PASSWORD):
        return render_template(
            "login.html",
            error="Incorrect password.",
            turnstile_site_key=TURNSTILE_SITE_KEY,
        ), 401

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
        turnstile_verified=turnstile_already_verified(),
    )


# =========================================================
# RECIPIENT NORMALIZATION
# =========================================================

def normalize_recipient(item):
    if isinstance(item, str):
        return {
            "email": normalize_email(item),
            "name": "",
            "hi": "",
            "hello": "",
            "thanks": "",
            "ref_code": "",
        }

    if not isinstance(item, dict):
        return None

    def clean_field(key, limit):
        val = str(item.get(key, "") or "").strip()
        return val.replace("\r", " ").replace("\n", " ")[:limit]

    return {
        "email": normalize_email(item.get("email", "")),
        "name": clean_field("name", 200),
        "hi": clean_field("hi", 100),
        "hello": clean_field("hello", 100),
        "thanks": clean_field("thanks", 100),
        "ref_code": clean_field("ref_code", 200),
    }


# =========================================================
# MESSAGE BUILDER & SENDERS
# =========================================================

def build_smtp_message(from_email, sender_name, subject, body, is_html, recipient):
    clean_body = str(body or "").replace("\x00", "")
    sender_domain = from_email.split("@", 1)[1] if "@" in from_email else "gmail.com"

    if is_html:
        msg = MIMEMultipart("alternative")
        plain_part = html_to_plain_text(clean_body) or " "
        html_part = wrap_clean_html(clean_body)
        msg.attach(MIMEText(plain_part, "plain", "utf-8"))
        msg.attach(MIMEText(html_part, "html", "utf-8"))
    else:
        msg = MIMEText(clean_body, "plain", "utf-8")

    msg["MIME-Version"] = "1.0"
    msg["Subject"] = subject
    msg["From"] = formataddr((sender_name, from_email))
    msg["Reply-To"] = from_email
    msg["To"] = recipient
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=sender_domain)
    return msg


def send_via_resend(from_address, sender_name, subject, body, is_html, recipient):
    clean_from = clean_header(sender_name, 100)
    formatted_from = f"{clean_from} <{from_address}>" if clean_from else from_address
    plain_text = html_to_plain_text(body) if is_html else body

    payload = {
        "from": formatted_from,
        "reply_to": from_address,
        "to": [recipient],
        "subject": subject,
        "text": plain_text or " ",
    }
    if is_html:
        payload["html"] = wrap_clean_html(body)

    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
            "User-Agent": "MailConsole/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("id"):
                return {"email": recipient, "result": "sent"}
            return {"email": recipient, "result": "failed", "error": "Resend did not return message id."}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="ignore")
        return {"email": recipient, "result": "failed", "error": f"Resend HTTP {e.code}: {err_body[:300]}"}
    except Exception as e:
        return {"email": recipient, "result": "failed", "error": str(e)[:300]}


def create_smtp_connection(gmail, app_password):
    clean_pwd = re.sub(r"\s+", "", str(app_password or ""))
    context = ssl.create_default_context()
    server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=SMTP_TIMEOUT)
    server.ehlo()
    server.login(gmail, clean_pwd)
    return server


# =========================================================
# SEND BATCH (SEQUENTIAL SINGLE-CONNECTION FOR INBOX HEALTH)
# =========================================================

@app.route("/send-batch", methods=["POST"])
def send_batch():
    if not authenticated():
        return jsonify({
            "success": False,
            "message": "Authentication required.",
            "login_required": True,
        }), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "message": "Invalid JSON request.",
        }), 400

    sender_name = clean_header(data.get("sender_name", ""), 200)
    gmail = clean_header(data.get("gmail", ""), 254).lower()
    from_override = clean_header(data.get("from_email", ""), 254).lower()
    app_password = str(data.get("app_password", "")).strip()
    subject = clean_header(data.get("subject", ""), 998)
    body = str(data.get("body", ""))
    is_html = data.get("is_html", False) is True
    recipients = data.get("recipients", [])
    turnstile_token = str(data.get("turnstile_token", "")).strip()

    if not sender_name:
        return jsonify({"success": False, "message": "Sender Name is required."}), 400

    if not RESEND_API_KEY:
        if not valid_email(gmail) or not gmail.endswith("@gmail.com"):
            return jsonify({"success": False, "message": "Enter a valid @gmail.com address."}), 400
        if not app_password:
            return jsonify({"success": False, "message": "Google App Password is required."}), 400

    if not subject:
        return jsonify({"success": False, "message": "Email subject is required."}), 400

    if not body.strip():
        return jsonify({"success": False, "message": "Message body is required."}), 400

    if len(body) > 100_000:
        return jsonify({"success": False, "message": "Message body is too large."}), 400

    if not isinstance(recipients, list):
        return jsonify({"success": False, "message": "Invalid recipient list."}), 400

    clean_recipients = []
    seen = set()

    for item in recipients:
        recipient = normalize_recipient(item)
        if not recipient:
            continue
        email = recipient["email"]
        if not valid_email(email) or email in seen:
            continue
        seen.add(email)
        clean_recipients.append(recipient)

    clean_recipients = clean_recipients[:MAX_RECIPIENTS]

    if not clean_recipients:
        return jsonify({"success": False, "message": "No valid recipients found."}), 400

    if not turnstile_already_verified():
        forwarded_for = request.headers.get("X-Forwarded-For")
        remote_ip = forwarded_for.split(",", 1)[0].strip() if forwarded_for else request.remote_addr

        verified, verify_error = verify_turnstile(turnstile_token, remote_ip)
        if not verified:
            return jsonify({"success": False, "message": verify_error}), 403

        session["turnstile_verified"] = True

    @stream_with_context
    def generate():
        total = len(clean_recipients)
        sent_count = 0
        failed_count = 0

        yield json.dumps({
            "type": "start",
            "total": total,
            "sent": 0,
            "failed": 0,
            "remaining": total,
        }, ensure_ascii=False) + "\n"

        smtp_server = None
        smtp_init_error = None

        if not RESEND_API_KEY:
            try:
                smtp_server = create_smtp_connection(gmail, app_password)
            except smtplib.SMTPAuthenticationError:
                smtp_init_error = "Gmail authentication failed. Check Gmail and App Password."
            except Exception as exc:
                smtp_init_error = f"SMTP connection failed: {str(exc)[:300]}"

        try:
            for index, recipient_data in enumerate(clean_recipients):
                recipient = recipient_data["email"]
                personalized_subject = personalize_template(subject, recipient_data)
                personalized_body = personalize_template(body, recipient_data)

                if index > 0 and SEND_DELAY_SECONDS > 0:
                    time.sleep(SEND_DELAY_SECONDS)

                if RESEND_API_KEY:
                    sender_email = from_override if valid_email(from_override) else DEFAULT_FROM_EMAIL
                    if not valid_email(sender_email):
                        res = {
                            "email": recipient,
                            "result": "failed",
                            "error": "Configure FROM_EMAIL (verified domain) in Vercel env.",
                        }
                    else:
                        res = send_via_resend(
                            from_address=sender_email,
                            sender_name=sender_name,
                            subject=personalized_subject,
                            body=personalized_body,
                            is_html=is_html,
                            recipient=recipient,
                        )
                else:
                    if smtp_init_error:
                        res = {"email": recipient, "result": "failed", "error": smtp_init_error}
                    else:
                        try:
                            msg = build_smtp_message(
                                from_email=gmail,
                                sender_name=sender_name,
                                subject=personalized_subject,
                                body=personalized_body,
                                is_html=is_html,
                                recipient=recipient,
                            )
                            refused = smtp_server.sendmail(gmail, [recipient], msg.as_string())
                            if refused:
                                res = {"email": recipient, "result": "failed", "error": "SMTP refused recipient."}
                            else:
                                res = {"email": recipient, "result": "sent"}
                        except Exception as exc:
                            res = {"email": recipient, "result": "failed", "error": str(exc)[:400]}

                if res.get("result") == "sent":
                    sent_count += 1
                    event = {
                        "type": "progress",
                        "email": recipient,
                        "result": "sent",
                        "total": total,
                        "sent": sent_count,
                        "failed": failed_count,
                        "remaining": total - sent_count - failed_count,
                    }
                else:
                    failed_count += 1
                    event = {
                        "type": "progress",
                        "email": recipient,
                        "result": "failed",
                        "error": res.get("error", "Delivery failed."),
                        "total": total,
                        "sent": sent_count,
                        "failed": failed_count,
                        "remaining": total - sent_count - failed_count,
                    }

                yield json.dumps(event, ensure_ascii=False) + "\n"

        finally:
            if smtp_server is not None:
                try:
                    smtp_server.quit()
                except Exception:
                    pass

        yield json.dumps({
            "type": "complete",
            "success": True,
            "message": "Sending completed.",
            "total": total,
            "sent": sent_count,
            "failed": failed_count,
            "remaining": total - sent_count - failed_count,
        }, ensure_ascii=False) + "\n"

    response = Response(
        generate(),
        content_type="application/x-ndjson; charset=utf-8",
    )
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, no-transform, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["X-Accel-Buffering"] = "no"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


# =========================================================
# HEALTH & LOCAL RUN
# =========================================================

@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "provider": "Resend API" if RESEND_API_KEY else "Gmail SMTP (Sequential)",
        "turnstile_verified_in_session": turnstile_already_verified(),
        "authenticated": authenticated(),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
