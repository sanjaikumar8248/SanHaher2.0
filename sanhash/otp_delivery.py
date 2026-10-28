"""Real OTP delivery over email (SMTP), used instead of showing the code on
screen once a deployment has configured it.

Configuration (environment variables — set these on your host, never commit
them to the repo):
    SMTP_HOST       e.g. smtp.gmail.com
    SMTP_PORT       e.g. 587  (defaults to 587 / STARTTLS)
    SMTP_USER       the account SanHasher sends from, e.g. you@gmail.com
    SMTP_PASSWORD   an app password (NOT your normal account password —
                     see README for how to create one for Gmail)
    SMTP_FROM       optional display "From" address; defaults to SMTP_USER

If these aren't set, email_configured() returns False and every caller in
web.py falls back to showing the OTP on screen (the original local/dev
behavior) instead of failing the login flow outright.
"""
import os
import smtplib
import ssl
from email.mime.text import MIMEText


def email_configured() -> bool:
    return bool(os.environ.get("SMTP_HOST") and os.environ.get("SMTP_USER") and os.environ.get("SMTP_PASSWORD"))


def _send(to_email: str, subject: str, body: str) -> None:
    host = os.environ["SMTP_HOST"]
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ["SMTP_USER"]
    password = os.environ["SMTP_PASSWORD"]
    sender = os.environ.get("SMTP_FROM", user)

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = to_email

    context = ssl.create_default_context()
    with smtplib.SMTP(host, port, timeout=15) as server:
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(user, password)
        server.sendmail(sender, [to_email], msg.as_string())


def deliver_otp(user_name: str, to_email: str, otp: str, purpose: str = "Login") -> bool:
    """Attempts to email the OTP. Returns True if it was actually sent,
    False if email isn't configured or sending failed — callers must fall
    back to on-screen display in that case so no one gets locked out."""
    if not email_configured():
        return False
    try:
        _send(
            to_email,
            f"SanHasher {purpose} verification code",
            f"Hello {user_name},\n\n"
            f"Your SanHasher {purpose} one-time code is: {otp}\n\n"
            f"This code expires in 5 minutes and can be used at most twice before it is invalidated.\n"
            f"If you did not request this, you can safely ignore this email — no action was taken on your account.\n",
        )
        return True
    except Exception as exc:  # noqa: BLE001 - never let an SMTP hiccup lock someone out of login
        print(f"[otp_delivery] failed to send OTP email to {to_email}: {exc}")
        return False
