from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session, jsonify
from werkzeug.utils import secure_filename

from . import db
from .paths import resource_base, data_base
from .core import hash_text, hash_file, base64_text, file_info, ALGORITHMS
from .passwords import dictionary_check, analyze_hash
from .identify import identify_hash, likelihood
from .merkle import merkle_layers, merkle_root
from .case import rebuild_merkle, verify_case, make_report
from .auth import make_otp, otp_hash, expiry, valid_otp, password_hash, password_ok
from .otp_delivery import deliver_otp, email_configured
from functools import wraps
from datetime import datetime, timezone
import os
import secrets as _secrets

# Evidence above this size (bytes) should go through the chunked/resumable upload endpoints
# below rather than the plain single-POST form, which buffers the whole request.
LARGE_UPLOAD_THRESHOLD = 150 * 1024 * 1024  # 150 MB
CHUNK_UPLOAD_MAX_BYTES = 64 * 1024 * 1024   # reject any single chunk larger than this

RESOURCE_BASE = resource_base()   # bundled, read-only: templates/, static/
BASE = data_base()                # persistent, writable: database, evidence, cases, reports
UPLOADS = BASE / "uploads"
WORDLISTS = BASE / "wordlists"
CASES = BASE / "cases"
REPORTS = BASE / "reports"

for p in (UPLOADS, WORDLISTS, CASES, REPORTS, BASE / "data"):
    p.mkdir(parents=True, exist_ok=True)

db.init_db()
app = Flask(__name__, template_folder=str(RESOURCE_BASE / "templates"), static_folder=str(RESOURCE_BASE / "static"))
# Caps any single HTTP request body (the plain small-file form, or one chunk of a large-file
# upload). This keeps the dev server from ever buffering an entire multi-GB file in memory;
# anything bigger than LARGE_UPLOAD_THRESHOLD must go through the chunked endpoints below,
# which only ever send CHUNK_UPLOAD_MAX_BYTES at a time.
app.config["MAX_CONTENT_LENGTH"] = LARGE_UPLOAD_THRESHOLD + CHUNK_UPLOAD_MAX_BYTES

# Secret key: prefer an explicit SANHASHER_SECRET from the host's environment/secret manager
# (this is what any real deployment should set). If it's absent, we never fall back to a known,
# hardcoded string — that would let anyone who has read this source code forge session cookies
# on a deployment that forgot to set one. Instead we generate a random key once and persist it
# next to the database, so sessions still survive normal restarts in local/dev use.
_secret_env = os.environ.get("SANHASHER_SECRET")
if _secret_env:
    app.secret_key = _secret_env
else:
    _secret_file = BASE / "data" / ".secret_key"
    _secret_file.parent.mkdir(parents=True, exist_ok=True)
    if _secret_file.exists():
        app.secret_key = _secret_file.read_text().strip()
    else:
        _generated = _secrets.token_hex(32)
        _secret_file.write_text(_generated)
        app.secret_key = _generated

def current_user():
    uid = session.get("user_id")
    return db.get_user(uid) if uid else None

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper

@app.before_request
def require_login():
    db.expire_deleted_evidence()
    public = {"login", "login_otp", "register", "forgot_password", "forgot_password_otp", "authority_register", "authority_login", "authority_login_otp", "static"}
    public_paths = {"/login", "/login/otp", "/register", "/forgot-password", "/forgot-password/otp", "/authority-register", "/authority-login", "/authority-login/otp"}
    # Registration/login pages must be reachable before anyone has an account.
    # Use both endpoint and path checks so an authentication redirect can never
    # swallow the Authority Registration page.
    if request.endpoint not in public and request.path not in public_paths and not current_user():
        if "/evidence/chunked/" in request.path or request.path.endswith("/evidence/chunked/start"):
            return jsonify(error="Not logged in."), 401
        return redirect(url_for("login", next=request.path))
    # Case-level isolation: room membership alone does not grant case access.
    if current_user() and request.path.startswith("/case/"):
        parts=request.path.split("/")
        if len(parts) >= 3 and parts[2]:
            case_obj=db.get_case(parts[2], room_id=current_user().get("room_id"))
            if case_obj and not db.user_can_access_case(parts[2], current_user()["id"]):
                db.audit(current_user()["id"],"CASE_ACCESS_DENIED",request.remote_addr or "unknown",
                         request.user_agent.string,f"Denied access to case {parts[2]}")
                flash("You are not assigned to this case.","error")
                return redirect(url_for("cases"))

@app.context_processor
def auth_context():
    u=current_user()
    if u: db.expire_deleted_evidence()
    return {"current_user": u, "unread_notifications": db.unread_notification_count(u["id"]) if u else 0}

def is_authority():
    u=current_user()
    return bool(u and u.get("role","").upper()=="HIGHER_AUTHORITY")

def authority_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user(): return redirect(url_for("login", next=request.path))
        if not is_authority():
            db.audit(current_user()["id"],"AUTHORITY_ACCESS_DENIED",request.remote_addr or "unknown",request.user_agent.string,f"Attempted privileged route: {request.path}")
            flash("Higher Authority access required.","error")
            return redirect(url_for("dashboard"))
        return fn(*args, **kwargs)
    return wrapper


def save_upload(file, folder):
    name = Path(file.filename or "").name
    if not name:
        raise ValueError("No filename supplied.")
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / name
    if target.exists():
        stem, suffix = target.stem, target.suffix
        i = 1
        while (folder / f"{stem}_{i}{suffix}").exists():
            i += 1
        target = folder / f"{stem}_{i}{suffix}"
    file.save(target)
    return target


@app.context_processor
def globals():
    u = current_user()
    cases = db.list_cases_for_user(u["room_id"], u["id"], u.get("role")=="HIGHER_AUTHORITY") if u else []
    total_evidence = sum(len(db.list_evidence(c["case_id"], include_deleted=False)) for c in cases)
    verified = modified = missing = 0
    for c in cases:
        for e in db.list_evidence(c["case_id"], include_deleted=False):
            p = Path(e["stored_path"])
            if not p.exists():
                missing += 1
            elif hash_file(p)["SHA-256"].lower() == e["sha256"].lower():
                verified += 1
            else:
                modified += 1
    return {"nav_cases": cases, "stats": {"cases": len(cases), "evidence": total_evidence,
            "verified": verified, "modified": modified, "missing": missing},
            "algorithms": [x[0] for x in ALGORITHMS]}


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user():
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        name=request.form.get("name","").strip()
        email=request.form.get("email","").strip()
        mobile=request.form.get("mobile","").strip()
        role=request.form.get("role","EXAMINER").strip().upper()
        password=request.form.get("password","")
        confirm=request.form.get("confirm_password","")
        room_code_input=request.form.get("room_code","").strip().upper()
        if role not in ("EXAMINER","ANALYST","INVESTIGATOR"):
            role="EXAMINER"
        room=db.get_room_by_code(room_code_input)
        if not name or not email or not mobile or not password:
            flash("All fields are required.","error")
        elif len(password)<8:
            flash("Password must be at least 8 characters.","error")
        elif password!=confirm:
            flash("Passwords do not match.","error")
        elif db.get_user_by_mobile(mobile) or db.get_user_by_email(email):
            flash("An account with that email or mobile already exists.","error")
        elif not room_code_input or not room:
            flash("Enter the Room ID provided by the Authority.","error")
        else:
            uid=db.create_user(name,email,mobile,password_hash(password),role=role,verified=False,status="PENDING",room_id=room["id"])
            db.audit(None,"USER_REGISTRATION_SUBMITTED",request.remote_addr or "unknown",request.user_agent.string,
                     f"Registration request #{uid} ({name}, {role}) submitted to room {room['room_code']}; pending Authority approval")
            db.notify_room(room["id"],"New Registration Pending",
                           f"{name} ({email}, role {role}) requested to join this room.","INFO")
            flash("Registration submitted. Authority approval is required before login.","success")
            return redirect(url_for("login"))
    return render_template("register.html",title="Member Registration")

@app.route("/authority-register", methods=["GET","POST"])
def authority_register():
    if current_user(): return redirect(url_for("dashboard"))
    if request.method=="POST":
        name=request.form.get("name","").strip(); email=request.form.get("email","").strip()
        mobile=request.form.get("mobile","").strip(); password=request.form.get("password","")
        confirm=request.form.get("confirm_password",""); room_name=request.form.get("room_name","").strip()
        if not name or not email or not mobile or not password: flash("All fields are required.","error")
        elif len(password)<8: flash("Password must be at least 8 characters.","error")
        elif password!=confirm: flash("Passwords do not match.","error")
        elif db.get_user_by_mobile(mobile) or db.get_user_by_email(email): flash("That mobile or email is already registered. Use Authority Login if this is your existing Authority account.","error")
        else:
            try:
                uid,rid,code=db.create_authority_account(name,email,mobile,password_hash(password),room_name)
                db.record_access_grant(uid,"HIGHER_AUTHORITY","ACCESS_GRANTED",uid,"Authority account and first room created",room_id=rid)
                db.audit(uid,"ROOM_CREATED",request.remote_addr or "unknown",request.user_agent.string,f"Authority created room {code}")
                flash(f"Authority account created successfully. Permanent Room ID: {code}","success")
                return redirect(url_for("authority_login"))
            except Exception as exc:
                flash(f"Authority registration failed: {exc}","error")
    return render_template("authority_register.html",title="Authority Registration")

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        user = db.get_user_by_identifier(identifier)
        if user and user.get("role") == "HIGHER_AUTHORITY":
            # Officers own their room; there is no one above them to approve a reset request,
            # so they recover their own account via an OTP sent to their own registered identity.
            otp = make_otp()
            db.create_otp(user["id"], user["name"], user["email"], user["mobile"], user["password_hash"], "PASSWORD_RESET_SELF", otp_hash(otp), expiry())
            session["pwreset_identity"] = user["mobile"]
            sent = deliver_otp(user["name"], user["email"], otp, "Password Reset")
            session["pwreset_demo"] = None if sent else otp
            db.audit(user["id"], "PASSWORD_RESET_SELF_OTP_SENT", request.remote_addr or "unknown", request.user_agent.string,
                      f"Higher Authority self-service password reset OTP generated (delivered by {'email' if sent else 'on-screen demo'})")
            flash((f"A password reset code has been emailed to {user['email']}. It's valid for 5 minutes."
                   if sent else f"Password reset OTP: {otp} (local demo mode — no email delivery configured; valid for 5 minutes)"), "success")
            return redirect(url_for("forgot_password_otp"))
        if user:
            db.create_password_reset_request(user["id"])
            db.audit(user["id"], "PASSWORD_RESET_REQUESTED", request.remote_addr or "unknown", request.user_agent.string, "Password reset requested; pending Higher Authority approval")
            db.notify_room(user["room_id"], "Password Reset Request", f"{user['name']} ({user['email']}) has requested a password reset and is awaiting Higher Authority approval.", "WARNING")
        flash("If that account exists, a reset has been initiated. Members are notified once their room's officer decides; an officer's own request continues straight to an OTP step.", "success")
        return redirect(url_for("login"))
    return render_template("forgot_password.html", title="Forgot Password")

@app.route("/forgot-password/otp", methods=["GET", "POST"])
def forgot_password_otp():
    mobile = session.get("pwreset_identity")
    if not mobile:
        return redirect(url_for("forgot_password"))
    user = db.get_user_by_mobile(mobile)
    row = db.get_latest_otp(user["email"], user["mobile"], "PASSWORD_RESET_SELF") if user else None
    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        new_password = request.form.get("new_password", ""); confirm = request.form.get("confirm_password", "")
        if not user or not row:
            flash("Reset session expired. Start again.", "error"); return redirect(url_for("forgot_password"))
        if not valid_otp(row, otp):
            attempts = db.register_failed_otp(row["id"])
            if attempts >= db.MAX_OTP_ATTEMPTS:
                db.audit(user["id"], "PASSWORD_RESET_OTP_LOCKED", request.remote_addr or "unknown", request.user_agent.string, "Too many incorrect OTP attempts on self-service password reset; reset session cancelled")
                session.pop("pwreset_identity", None); session.pop("pwreset_demo", None)
                flash("Too many incorrect OTP attempts. Please request a new reset.", "error")
                return redirect(url_for("forgot_password"))
            flash(f"Incorrect OTP. {db.MAX_OTP_ATTEMPTS - attempts} attempt(s) remaining before this reset is cancelled.", "error")
            return render_template("forgot_password_otp.html", title="Reset Password", demo_otp=session.get("pwreset_demo"))
        if len(new_password) < 8:
            flash("New password must be at least 8 characters.", "error")
        elif new_password != confirm:
            flash("Passwords do not match.", "error")
        else:
            db.consume_otp(row["id"])
            db.set_user_password(user["id"], password_hash(new_password))
            db.reset_failed_login(user["id"])
            db.audit(user["id"], "PASSWORD_RESET_SELF_COMPLETE", request.remote_addr or "unknown", request.user_agent.string, "Higher Authority completed self-service password reset via OTP")
            session.pop("pwreset_identity", None); session.pop("pwreset_demo", None)
            flash("Password reset. You can log in with your new password now.", "success")
            return redirect(url_for("login"))
    return render_template("forgot_password_otp.html", title="Reset Password", demo_otp=session.get("pwreset_demo"))

@app.route("/authority-login", methods=["GET","POST"])
def authority_login():
    if current_user():
        if current_user().get("role")=="HIGHER_AUTHORITY": return redirect(url_for("authority_dashboard"))
        session.clear()
    if request.method=="POST":
        identifier=request.form.get("identifier","").strip(); password=request.form.get("password","")
        user=db.get_user_by_identifier(identifier)
        if user and user.get("role")=="HIGHER_AUTHORITY" and db.is_locked(user):
            flash(f"This account is suspended until {user['locked_until']} (server time) after too many failed login attempts.","error")
            return render_template("authority_login.html",title="Authority Login")
        if not user or user.get("role")!="HIGHER_AUTHORITY" or not password_ok(user["password_hash"],password):
            if user and user.get("role")=="HIGHER_AUTHORITY":
                suspended, locked_until = db.register_failed_login(user["id"])
                db.audit(user["id"],"AUTHORITY_LOGIN_FAILED",request.remote_addr or "unknown",request.user_agent.string,f"Failed Authority login for '{identifier}'")
                if suspended:
                    db.audit(user["id"],"ACCOUNT_SUSPENDED",request.remote_addr or "unknown",request.user_agent.string,f"Suspended for {db.LOCKOUT_MINUTES} minutes after {db.MAX_LOGIN_ATTEMPTS}+ failed login attempts")
                    flash(f"Too many failed login attempts. This account is suspended for {db.LOCKOUT_MINUTES} minutes.","error")
                    return render_template("authority_login.html",title="Authority Login")
            else:
                db.audit(user["id"] if user else None,"AUTHORITY_LOGIN_FAILED",request.remote_addr or "unknown",request.user_agent.string,f"Failed Authority login for '{identifier}'")
            flash("Invalid Authority credentials.","error")
            return render_template("authority_login.html",title="Authority Login")
        db.reset_failed_login(user["id"])
        otp=make_otp()
        db.create_otp(user["id"],user["name"],user["email"],user["mobile"],user["password_hash"],"AUTHORITY_LOGIN",otp_hash(otp),expiry())
        session["authority_login_identity"]=user["mobile"]
        sent = deliver_otp(user["name"], user["email"], otp, "Authority Login")
        session["authority_login_demo"] = None if sent else otp
        flash((f"A login code has been emailed to {user['email']}. It's valid for 5 minutes." if sent
               else f"Authority Login OTP: {otp} (local demo mode — no email delivery configured; valid for 5 minutes)"),"success")
        return redirect(url_for("authority_login_otp"))
    return render_template("authority_login.html",title="Authority Login")

@app.route("/authority-login/otp", methods=["GET","POST"])
def authority_login_otp():
    mobile=session.get("authority_login_identity")
    if not mobile: return redirect(url_for("authority_login"))
    user=db.get_user_by_mobile(mobile); row=db.get_latest_otp(user["email"],user["mobile"],"AUTHORITY_LOGIN") if user else None
    if request.method=="POST":
        otp_input=request.form.get("otp","").strip()
        if user and user.get("role")=="HIGHER_AUTHORITY" and user["verified"] and valid_otp(row,otp_input):
            db.consume_otp(row["id"]); session["user_id"]=user["id"]; db.set_last_login(user["id"])
            db.audit(user["id"],"AUTHORITY_LOGIN",""+(request.remote_addr or "unknown"),request.user_agent.string,"Successful Authority password + OTP login")
            session.pop("authority_login_identity",None); session.pop("authority_login_demo",None)
            return redirect(url_for("authority_dashboard"))
        if row:
            attempts=db.register_failed_otp(row["id"])
            if attempts>=db.MAX_OTP_ATTEMPTS:
                if user: db.audit(user["id"],"AUTHORITY_LOGIN_OTP_LOCKED",request.remote_addr or "unknown",request.user_agent.string,f"Logged out after {db.MAX_OTP_ATTEMPTS} incorrect OTP attempts; must log in again")
                session.pop("authority_login_identity",None); session.pop("authority_login_demo",None)
                flash(f"Too many incorrect OTP attempts ({db.MAX_OTP_ATTEMPTS} max). Please log in again; there is no extra waiting time.","error")
                return redirect(url_for("authority_login"))
            flash(f"Invalid or expired OTP. {db.MAX_OTP_ATTEMPTS - attempts} attempt(s) remaining before you're logged out.","error")
        else:
            flash("Invalid or expired OTP.","error")
    return render_template("login_otp.html",title="Authority OTP Login",identity=mobile,demo_otp=session.get("authority_login_demo"))

@app.route("/login", methods=["GET","POST"])
def login():
    if current_user():
        return redirect(request.args.get("next") or url_for("dashboard"))
    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")
        user = db.get_user_by_identifier(identifier)
        if user and db.is_locked(user):
            flash(f"This account is suspended until {user['locked_until']} (server time) after too many failed login attempts. Please try again later.", "error")
            return render_template("login.html", title="Login")
        if not user or not password_ok(user["password_hash"], password):
            if user:
                suspended, locked_until = db.register_failed_login(user["id"])
                db.audit(user["id"], "LOGIN_FAILED", request.remote_addr or "unknown", request.user_agent.string, f"Failed login attempt for '{identifier}'")
                if suspended:
                    db.audit(user["id"], "ACCOUNT_SUSPENDED", request.remote_addr or "unknown", request.user_agent.string, f"Suspended for {db.LOCKOUT_MINUTES} minutes after {db.MAX_LOGIN_ATTEMPTS}+ failed login attempts")
                    flash(f"Too many failed login attempts. This account is suspended for {db.LOCKOUT_MINUTES} minutes.", "error")
                    return render_template("login.html", title="Login")
            else:
                db.audit(None, "LOGIN_FAILED", request.remote_addr or "unknown", request.user_agent.string, f"Failed login attempt for unknown identifier '{identifier}'")
            flash("Invalid email/mobile or password.", "error")
            return render_template("login.html", title="Login")
        if user.get("status") == "PENDING":
            flash("Your registration is still awaiting Higher Authority approval.", "error")
            return render_template("login.html", title="Login")
        if user.get("status") == "REJECTED" or not user["verified"]:
            flash("This account does not have active access. Contact a Higher Authority officer.", "error")
            return render_template("login.html", title="Login")
        db.reset_failed_login(user["id"])
        otp = make_otp()
        db.create_otp(user["id"], user["name"], user["email"], user["mobile"], user["password_hash"], "LOGIN", otp_hash(otp), expiry())
        session["login_otp_identity"] = user["mobile"]
        sent = deliver_otp(user["name"], user["email"], otp, "Login")
        session["login_otp_demo"] = None if sent else otp
        session["login_next"] = request.form.get("next") or request.args.get("next") or url_for("dashboard")
        db.audit(user["id"], "Login OTP Generated", request.remote_addr or "unknown", request.user_agent.string,
                  f"OTP generated after password verification; delivered by {'email' if sent else 'on-screen demo'}")
        flash((f"A login code has been emailed to {user['email']}. It's valid for 5 minutes." if sent
               else f"Login OTP: {otp} (local demo mode — no email delivery configured; valid for 5 minutes)"), "success")
        return redirect(url_for("login_otp"))
    return render_template("login.html", title="Login", next=request.args.get("next", ""))

@app.route("/login/otp", methods=["GET", "POST"])
def login_otp():
    mobile = session.get("login_otp_identity")
    if not mobile:
        return redirect(url_for("login"))
    user = db.get_user_by_mobile(mobile)
    row = db.get_latest_otp(user["email"], user["mobile"], "LOGIN") if user else None
    if request.method == "POST":
        otp_input = request.form.get("otp", "").strip()
        if user and user["verified"] and valid_otp(row, otp_input):
            db.consume_otp(row["id"])
            session["user_id"] = user["id"]
            db.set_last_login(user["id"])
            db.audit(user["id"], "Login - OTP", request.remote_addr or "unknown", request.user_agent.string, "Successful password + OTP login")
            next_url = session.pop("login_next", None) or url_for("dashboard")
            session.pop("login_otp_identity", None)
            session.pop("login_otp_demo", None)
            return redirect(next_url)
        if row:
            attempts = db.register_failed_otp(row["id"])
            if attempts >= db.MAX_OTP_ATTEMPTS:
                if user:
                    db.audit(user["id"], "LOGIN_OTP_LOCKED", request.remote_addr or "unknown", request.user_agent.string, f"Logged out after {db.MAX_OTP_ATTEMPTS} incorrect OTP attempts; must log in again")
                session.pop("login_otp_identity", None); session.pop("login_otp_demo", None); session.pop("login_next", None)
                flash(f"Too many incorrect OTP attempts ({db.MAX_OTP_ATTEMPTS} max). You've been logged out — please log in again; there is no extra waiting time for this.", "error")
                return redirect(url_for("login"))
            flash(f"Invalid or expired OTP. {db.MAX_OTP_ATTEMPTS - attempts} attempt(s) remaining before you're logged out.", "error")
        else:
            flash("Invalid or expired OTP.", "error")
    return render_template("login_otp.html", title="OTP Login", identity=mobile, demo_otp=session.get("login_otp_demo"))

@app.route("/authority")
@authority_required
def authority_dashboard():
    room_id=current_user()["room_id"]; room=db.get_room(room_id)
    users=db.list_users(room_id); grants=db.list_access_grants(room_id=room_id); integrity=db.verify_access_grants()
    pending=db.list_pending_registrations(room_id); resets=db.list_password_reset_requests("PENDING",room_id=room_id)
    case_requests=db.list_case_requests(room_id)
    db.audit(current_user()["id"],"AUTHORITY_DASHBOARD_VIEWED",request.remote_addr or "unknown",request.user_agent.string,"Viewed authority administration dashboard")
    return render_template("authority.html",title="Higher Authority Control Center",users=users,grants=grants,integrity=integrity,
                           pending=pending,resets=resets,case_requests=case_requests,room=room,has_profile_pw=True)

@app.route("/authority/registrations/<int:user_id>/decide", methods=["POST"])
@authority_required
def authority_decide_registration(user_id):
    user=db.get_user(user_id)
    if not user or user.get("status")!="PENDING" or user.get("room_id")!=current_user()["room_id"]:
        flash("No pending registration found in your room for that user.","error"); return redirect(url_for("authority_dashboard"))
    decision=request.form.get("decision")
    if decision=="APPROVE":
        db.approve_registration(user_id)
        db.record_access_grant(user_id,user["role"],"ACCESS_GRANTED",current_user()["id"],"Self-registration approved by Higher Authority",room_id=current_user()["room_id"])
        db.audit(current_user()["id"],"REGISTRATION_APPROVED",request.remote_addr or "unknown",request.user_agent.string,f"Approved registration #{user_id} ({user['name']})")
        db.add_notification(user_id,"Access Granted","Your registration was approved. You can now log in with your email/mobile, password and OTP.","SUCCESS")
        flash(f"{user['name']} approved and granted access.","success")
    else:
        db.reject_registration(user_id)
        db.audit(current_user()["id"],"REGISTRATION_REJECTED",request.remote_addr or "unknown",request.user_agent.string,f"Rejected registration #{user_id} ({user['name']})")
        flash(f"Registration for {user['name']} rejected.","success")
    return redirect(url_for("authority_dashboard"))

@app.route("/authority/password-resets/<int:request_id>/decide", methods=["POST"])
@authority_required
def authority_decide_reset(request_id):
    req=db.get_password_reset_request(request_id)
    if not req or req.get("status")!="PENDING":
        flash("No pending reset request found.","error"); return redirect(url_for("authority_dashboard"))
    user=db.get_user(req["user_id"])
    if not user or user.get("room_id")!=current_user()["room_id"]:
        flash("That reset request does not belong to your room.","error"); return redirect(url_for("authority_dashboard"))
    decision=request.form.get("decision")
    if decision=="APPROVE":
        import secrets
        temp_password=secrets.token_urlsafe(9)
        db.set_user_password(user["id"],password_hash(temp_password))
        db.decide_password_reset(request_id,"APPROVED",current_user()["id"],"Temporary password issued")
        db.audit(current_user()["id"],"PASSWORD_RESET_APPROVED",request.remote_addr or "unknown",request.user_agent.string,f"Approved password reset for user #{user['id']} ({user['name']})")
        db.add_notification(user["id"],"Password Reset Approved","Your password reset was approved by Higher Authority. Contact the officer securely to receive your new temporary password, then change it after logging in.","WARNING")
        flash(f"Reset approved. Temporary password for {user['name']}: {temp_password} (relay this to the user through a secure channel; it is shown only once).","success")
    else:
        db.decide_password_reset(request_id,"REJECTED",current_user()["id"],"Rejected by Higher Authority")
        db.audit(current_user()["id"],"PASSWORD_RESET_REJECTED",request.remote_addr or "unknown",request.user_agent.string,f"Rejected password reset for user #{user['id']} ({user['name']})")
        db.add_notification(user["id"],"Password Reset Rejected","Your password reset request was rejected by Higher Authority.","ERROR")
        flash("Reset request rejected.","success")
    return redirect(url_for("authority_dashboard"))

@app.route("/authority/profile-view-password", methods=["GET", "POST"])
@authority_required
def authority_set_profile_view_password():
    user=current_user()
    if request.method=="POST":
        current=request.form.get("current_login_password","")
        new=request.form.get("new_password",""); confirm=request.form.get("confirm_password","")
        if not password_ok(user["password_hash"],current):
            flash("Your login password is incorrect.","error")
        elif len(new)<8:
            flash("Profile-view password must be at least 8 characters.","error")
        elif new==current:
            flash("The profile-view password must be different from your login password.","error")
        elif new!=confirm:
            flash("New profile-view passwords do not match.","error")
        else:
            db.set_profile_view_password(user["id"],password_hash(new))
            db.audit(user["id"],"PROFILE_VIEW_PASSWORD_SET",request.remote_addr or "unknown",request.user_agent.string,"Higher Authority set/changed the dedicated profile-view password")
            flash("Profile-view password saved. It will be required, together with an OTP, every time you open a user's full profile.","success")
            return redirect(url_for("authority_dashboard"))
    return render_template("authority_profile_password.html",title="Profile-View Password")

def profile_unlocked_for(user_id):
    until = session.get("profile_unlock_until")
    return session.get("profile_unlock_user_id")==user_id and until and datetime.now().astimezone().timestamp() < until

@app.route("/authority/user/<int:user_id>/unlock", methods=["GET", "POST"])
@authority_required
def authority_profile_unlock(user_id):
    target=db.get_user(user_id)
    if not target or target.get("room_id")!=current_user()["room_id"]:
        flash("User not found in your room.","error"); return redirect(url_for("authority_dashboard"))
    authority=current_user()
    if not authority.get("profile_view_password_hash"):
        flash("Set your profile-view password first.","error"); return redirect(url_for("authority_set_profile_view_password"))
    if request.method=="POST":
        pw=request.form.get("profile_view_password","")
        if not password_ok(authority["profile_view_password_hash"],pw):
            db.audit(authority["id"],"PROFILE_VIEW_PASSWORD_FAILED",request.remote_addr or "unknown",request.user_agent.string,f"Incorrect profile-view password attempt for user #{user_id}")
            flash("Incorrect profile-view password.","error")
        else:
            otp=make_otp()
            db.create_otp(authority["id"],authority["name"],authority["email"],authority["mobile"],authority["password_hash"],f"PROFILE_VIEW_{user_id}",otp_hash(otp),expiry())
            session["profile_otp_target"]=user_id
            sent = deliver_otp(authority["name"], authority["email"], otp, "Profile View")
            session["profile_otp_demo"] = None if sent else otp
            db.audit(authority["id"],"PROFILE_VIEW_OTP_GENERATED",request.remote_addr or "unknown",request.user_agent.string,
                      f"Profile-view OTP generated for user #{user_id} (delivered by {'email' if sent else 'on-screen demo'})")
            flash((f"A profile-view code has been emailed to {authority['email']}. It's valid for 5 minutes." if sent
                   else f"Profile-view OTP: {otp} (local demo mode — no email delivery configured; valid for 5 minutes)"),"success")
            return redirect(url_for("authority_profile_otp",user_id=user_id))
    return render_template("authority_profile_unlock.html",title="Verify to View Profile",target=target)

@app.route("/authority/user/<int:user_id>/unlock/otp", methods=["GET", "POST"])
@authority_required
def authority_profile_otp(user_id):
    if session.get("profile_otp_target")!=user_id:
        return redirect(url_for("authority_profile_unlock",user_id=user_id))
    authority=current_user()
    row=db.get_latest_otp(authority["email"],authority["mobile"],f"PROFILE_VIEW_{user_id}")
    if request.method=="POST":
        otp_input=request.form.get("otp","").strip()
        if valid_otp(row,otp_input):
            db.consume_otp(row["id"])
            session["profile_unlock_user_id"]=user_id
            session["profile_unlock_until"]=datetime.now().astimezone().timestamp()+300
            session.pop("profile_otp_target",None); session.pop("profile_otp_demo",None)
            db.audit(authority["id"],"PROFILE_VIEW_UNLOCKED",request.remote_addr or "unknown",request.user_agent.string,f"Unlocked profile view for user #{user_id} (5-minute window)")
            return redirect(url_for("authority_profile",user_id=user_id))
        if row:
            attempts=db.register_failed_otp(row["id"])
            if attempts>=db.MAX_OTP_ATTEMPTS:
                db.audit(authority["id"],"PROFILE_VIEW_OTP_LOCKED",request.remote_addr or "unknown",request.user_agent.string,f"Too many incorrect OTP attempts unlocking profile for user #{user_id}; cancelled")
                session.pop("profile_otp_target",None); session.pop("profile_otp_demo",None)
                flash(f"Too many incorrect OTP attempts ({db.MAX_OTP_ATTEMPTS} max). Start over from your profile-view password.","error")
                return redirect(url_for("authority_profile_unlock",user_id=user_id))
            flash(f"Invalid or expired OTP. {db.MAX_OTP_ATTEMPTS - attempts} attempt(s) remaining.","error")
        else:
            flash("Invalid or expired OTP.","error")
    return render_template("authority_profile_unlock_otp.html",title="Profile-View OTP",user_id=user_id,demo_otp=session.get("profile_otp_demo"))

@app.route("/authority/room/regenerate-id", methods=["POST"])
@authority_required
def authority_regenerate_room_id():
    officer=current_user()
    current=request.form.get("current_login_password","")
    if not password_ok(officer["password_hash"],current):
        flash("Your login password is incorrect — Room ID changes require confirming it.","error")
        return redirect(url_for("authority_dashboard"))
    try:
        new_code, change_no = db.regenerate_room_code(officer["room_id"], officer["mobile"])
    except Exception as exc:
        flash(f"Could not change the Room ID: {exc}","error")
        return redirect(url_for("authority_dashboard"))
    db.audit(officer["id"],"ROOM_ID_CHANGED",request.remote_addr or "unknown",request.user_agent.string,
              f"Room ID changed (change #{change_no}) to {new_code}")
    db.notify_room(officer["room_id"],"Room ID Changed",
                    f"Your room's officer changed the Room/Registration ID. New members must use the new ID: {new_code}.","WARNING")
    ordinal = "first" if change_no==1 else ("second" if change_no==2 else f"{change_no}th")
    basis = "your mobile number" if change_no<=1 else "a hash of the previous Room ID"
    flash(f"Room ID changed ({ordinal} change, based on {basis}). New Room ID: {new_code}. Anyone who still has the old ID can no longer use it to register.","success")
    return redirect(url_for("authority_dashboard"))

@app.route("/authority/users", methods=["GET","POST"])
@authority_required
def authority_users():
    if request.method=="POST":
        name=request.form.get("name","").strip(); email=request.form.get("email","").strip(); mobile=request.form.get("mobile","").strip(); role=request.form.get("role","EXAMINER").strip().upper()
        initial_password=request.form.get("initial_password","")
        room_id=current_user()["room_id"]
        if not name or not email or not mobile: flash("Name, email and mobile are required.","error")
        elif db.get_user_by_mobile(mobile) or db.get_user_by_email(email): flash("A user with that mobile or email is already registered to a room.","error")
        elif role=="HIGHER_AUTHORITY": flash("A member cannot be added as Higher Authority here. They must register their own room at /authority-register.","error")
        else:
            import secrets
            auto_generated = not initial_password
            if auto_generated:
                initial_password = secrets.token_urlsafe(9)  # readable temp password, shown to the officer below
            elif len(initial_password) < 8:
                flash("Initial password must be at least 8 characters (or leave it blank to auto-generate one).","error")
                return redirect(url_for("authority_dashboard"))
            uid=db.create_user(name,email,mobile,password_hash(initial_password),role=role,verified=True,room_id=room_id)
            db.record_access_grant(uid,role,"ACCESS_GRANTED",current_user()["id"],"Account provisioned directly by Higher Authority",room_id=room_id)
            db.audit(current_user()["id"],"USER_CREATED",request.remote_addr or "unknown",request.user_agent.string,f"Created user #{uid} ({name}) with role {role} in own room")
            note = " (auto-generated — this is shown only once)" if auto_generated else ""
            flash(f"User {name} created. Initial login password{note}: {initial_password} — relay this to them through a secure channel; they should change it after their first login.","success")
    return redirect(url_for("authority_dashboard"))

@app.route("/authority/user/<int:user_id>")
@authority_required
def authority_profile(user_id):
    user=db.get_user(user_id)
    if not user or user.get("room_id")!=current_user()["room_id"]: flash("User not found in your room.","error"); return redirect(url_for("authority_dashboard"))
    if not profile_unlocked_for(user_id):
        return redirect(url_for("authority_profile_unlock",user_id=user_id))
    db.audit(current_user()["id"],"USER_PROFILE_VIEWED",request.remote_addr or "unknown",request.user_agent.string,f"Viewed profile of user #{user_id} ({user['name']}) — profile-view password + OTP verified")
    grants=[g for g in db.list_access_grants(500,room_id=current_user()["room_id"]) if g["user_id"]==user_id]
    custody_events=[c for c in [row for cid in [c["case_id"] for c in db.list_cases(room_id=current_user()["room_id"])] for row in db.list_custody(cid)] if c.get("analyst")==user["name"]]
    return render_template("authority_profile.html",title=f"User Profile — {user['name']}",user=user,grants=grants,custody_events=custody_events[:50])

@app.route("/authority/user/<int:user_id>/role", methods=["POST"])
@authority_required
def authority_change_role(user_id):
    user=db.get_user(user_id); role=request.form.get("role","EXAMINER").strip().upper()
    if not user or user.get("room_id")!=current_user()["room_id"]: flash("User not found in your room.","error"); return redirect(url_for("authority_dashboard"))
    if user_id==current_user()["id"]:
        flash("You cannot change your own role. As the sole Higher Authority for this room, downgrading yourself would leave the room without an officer able to approve members or manage access.","error")
        return redirect(url_for("authority_dashboard"))
    if role=="HIGHER_AUTHORITY":
        flash("A member cannot be promoted to Higher Authority here. They must register their own room separately.","error"); return redirect(url_for("authority_profile",user_id=user_id))
    old=user["role"]; db.set_user_role(user_id,role); db.record_access_grant(user_id,role,"ROLE_CHANGED",current_user()["id"],f"Previous role: {old}; new role: {role}",room_id=current_user()["room_id"])
    db.audit(current_user()["id"],"ROLE_CHANGED",request.remote_addr or "unknown",request.user_agent.string,f"User #{user_id}: {old} -> {role}")
    flash("Role changed. The previous grant event remains immutable.","success")
    return redirect(url_for("authority_profile",user_id=user_id))

@app.route("/authority/user/<int:user_id>/access", methods=["POST"])
@authority_required
def authority_access(user_id):
    user=db.get_user(user_id)
    if not user or user.get("room_id")!=current_user()["room_id"]: flash("User not found in your room.","error"); return redirect(url_for("authority_dashboard"))
    action=request.form.get("action")
    if user_id==current_user()["id"] and action=="REVOKE":
        flash("You cannot revoke your own access. As the sole Higher Authority for this room, that would lock the room with no one able to manage it.","error")
        return redirect(url_for("authority_dashboard"))
    if action=="REVOKE":
        db.set_user_verified(user_id,False); db.record_access_grant(user_id,user["role"],"ACCESS_REVOKED",current_user()["id"],"Access revoked by Higher Authority",room_id=current_user()["room_id"])
        db.audit(current_user()["id"],"ACCESS_REVOKED",request.remote_addr or "unknown",request.user_agent.string,f"Revoked access for user #{user_id} ({user['name']})")
        flash("Access revoked. The grant history remains immutable.","success")
    elif action=="RESTORE":
        db.set_user_verified(user_id,True); db.record_access_grant(user_id,user["role"],"ACCESS_GRANTED",current_user()["id"],"Access restored by Higher Authority",room_id=current_user()["room_id"])
        db.audit(current_user()["id"],"ACCESS_RESTORED",request.remote_addr or "unknown",request.user_agent.string,f"Restored access for user #{user_id} ({user['name']})")
        flash("Access restored and recorded as a new immutable event.","success")
    return redirect(url_for("authority_profile",user_id=user_id))

@app.route("/notifications")
@login_required
def notifications():
    return render_template("notifications.html",title="Mandatory Notifications",notifications=db.list_notifications(current_user()["id"]))

@app.route("/notifications/<int:notification_id>/read", methods=["POST"])
@login_required
def notification_read(notification_id):
    db.mark_notification_read(notification_id,current_user()["id"]); return redirect(url_for("notifications"))

@app.route("/account/password", methods=["GET", "POST"])
@login_required
def account_password():
    user=current_user()
    if request.method=="POST":
        current=request.form.get("current_password",""); new=request.form.get("new_password",""); confirm=request.form.get("confirm_password","")
        if not password_ok(user["password_hash"],current):
            flash("Current password is incorrect.","error")
        elif len(new)<8:
            flash("New password must be at least 8 characters.","error")
        elif new!=confirm:
            flash("New passwords do not match.","error")
        else:
            db.set_user_password(user["id"],password_hash(new))
            db.audit(user["id"],"PASSWORD_CHANGED",request.remote_addr or "unknown",request.user_agent.string,"User changed their own login password")
            flash("Password updated.","success")
            return redirect(url_for("dashboard"))
    return render_template("account_password.html",title="Change Password")

@app.route("/logout")
def logout():
    uid=session.get("user_id");
    if uid: db.audit(uid,"Logout",request.remote_addr or "unknown",request.user_agent.string,"User logged out")
    session.clear(); flash("Logged out.","success"); return redirect(url_for("login"))

@app.route("/")
def dashboard():
    return render_template("dashboard.html", title="Investigation Dashboard")


@app.route("/text-hash", methods=["GET", "POST"])
def text_hash():
    result = None; text = ""
    if request.method == "POST":
        text = request.form.get("text", "")
        result = hash_text(text); result["Base64"] = base64_text(text)
    return render_template("text_hash.html", title="Text Hash Generator", result=result, text=text)


@app.route("/file-hash", methods=["GET", "POST"])
def file_hash():
    result = None
    if request.method == "POST":
        f = request.files.get("file")
        if not f or not f.filename:
            flash("Select a file first.", "error")
        else:
            try:
                p = save_upload(f, UPLOADS)
                result = {"info": file_info(p), "hashes": hash_file(p), "path": str(p)}
            except Exception as e:
                flash(f"Could not process file: {e}", "error")
    return render_template("file_hash.html", title="File Hash Generator", result=result)


@app.route("/password-analysis", methods=["GET", "POST"])
def password_analysis():
    result = None; target = ""; algorithm = "MD5"; hash_analysis = None
    if request.method == "POST":
        target = request.form.get("target_hash", "").strip()
        algorithm = request.form.get("algorithm", "MD5")
        hash_analysis = analyze_hash(target, algorithm)
        wl = request.files.get("wordlist")
        if algorithm not in dict(ALGORITHMS):
            flash("Unsupported algorithm.", "error")
        elif not hash_analysis["format_valid"]:
            flash("Target hash format does not match the selected algorithm.", "error")
        elif not wl or not wl.filename:
            flash("Upload a wordlist (.txt/.lst/.dic).", "error")
        else:
            try:
                p = save_upload(wl, WORDLISTS)
                result = dictionary_check(target, algorithm, p)
            except Exception as e:
                flash(f"Could not analyze wordlist: {e}", "error")
    return render_template("password_analysis.html", title="Password Hash Analysis",
                           result=result, target=target, algorithm=algorithm, hash_analysis=hash_analysis)


@app.route("/hash-identifier", methods=["GET", "POST"])
def hash_identifier():
    value = ""; result = None
    if request.method == "POST":
        value = request.form.get("hash_value", "")
        result = [(x, likelihood(x, value)) for x in identify_hash(value)]
    return render_template("hash_identifier.html", title="Automatic Hash Identifier", value=value, result=result)


@app.route("/hash-to-text", methods=["GET", "POST"])
def hash_to_text():
    """Recover a hash candidate using a user-supplied offline wordlist.

    This intentionally performs local candidate matching only. It does not
    attempt online authentication or access any external account.
    """
    result = None
    target = ""
    algorithm = "MD5"
    wordlist_name = ""
    if request.method == "POST":
        target = request.form.get("target_hash", "").strip().lower()
        algorithm = request.form.get("algorithm", "MD5")
        wl = request.files.get("wordlist")
        if algorithm not in dict(ALGORITHMS):
            flash("Unsupported algorithm.", "error")
        elif not target:
            flash("Enter a target hash.", "error")
        else:
            analysis = analyze_hash(target, algorithm)
            if not analysis["format_valid"]:
                flash("Target hash format does not match the selected algorithm.", "error")
            elif not wl or not wl.filename:
                flash("Upload a wordlist (.txt/.lst/.dic).", "error")
            else:
                try:
                    p = save_upload(wl, WORDLISTS)
                    wordlist_name = p.name
                    result = dictionary_check(target, algorithm, p)
                    result["wordlist"] = p.name
                    result["candidate_count"] = result.get("attempts", 0)
                except Exception as e:
                    flash(f"Could not process wordlist: {e}", "error")
    return render_template(
        "hash_to_text.html",
        title="Hash → Text Recovery",
        result=result,
        target=target,
        algorithm=algorithm,
        wordlist_name=wordlist_name,
    )


@app.route("/compare", methods=["GET", "POST"])
def compare():
    result = None
    if request.method == "POST":
        a, b = request.files.get("file_a"), request.files.get("file_b")
        if not a or not a.filename or not b or not b.filename:
            flash("Select both files.", "error")
        else:
            pa, pb = save_upload(a, UPLOADS), save_upload(b, UPLOADS)
            ha, hb = hash_file(pa), hash_file(pb)
            result = {"a": {"info": file_info(pa), "hashes": ha}, "b": {"info": file_info(pb), "hashes": hb},
                      "identical": ha["SHA-256"] == hb["SHA-256"]}
    return render_template("compare.html", title="File Hash Comparison", result=result)


@app.route("/cases", methods=["GET","POST"])
def cases():
    u=current_user()
    if request.method=="POST":
        action=request.form.get("action","CREATE")
        if action=="REQUEST":
            case_id=request.form.get("case_id","").strip(); title=request.form.get("case_title","").strip()
            desc=request.form.get("description","").strip()
            if u.get("role")=="HIGHER_AUTHORITY":
                flash("Authority should create the case directly.","error")
            elif not case_id or not title:
                flash("Case ID and title are required.","error")
            else:
                try:
                    db.create_case_request(case_id,title,desc,u["id"])
                    db.notify_room(u["room_id"],"New Case Request",f"{u['name']} requested case {case_id}. Authority approval is required.", "INFO")
                    db.audit(u["id"],"CASE_REQUESTED",request.remote_addr or "unknown",request.user_agent.string,f"Requested case {case_id}")
                    flash("Case request sent to Authority.","success")
                except Exception as e: flash(f"Could not submit request: {e}","error")
        elif action=="CREATE":
            if u.get("role")!="HIGHER_AUTHORITY":
                flash("Only Authority can create a case directly. Use Request New Case.","error")
            else:
                case_id=request.form.get("case_id","").strip(); title=request.form.get("case_title","").strip()
                lead=request.form.get("team_lead","").strip()
                if not case_id or not title: flash("Case ID and title are required.","error")
                else:
                    try:
                        db.create_case(case_id,title,u["name"],u["room_id"])
                        if lead:
                            lead_user=db.get_user(int(lead))
                            if not lead_user or lead_user.get("room_id")!=u["room_id"] or not lead_user.get("verified"):
                                raise ValueError("Selected Team Lead is not an active member of this room.")
                            db.add_case_member(case_id,lead_user["id"],"TEAM_LEAD",u["id"])
                        db.audit(u["id"],"CASE_CREATED",request.remote_addr or "unknown",request.user_agent.string,f"Authority created case {case_id}; Team Lead: {lead or 'Not assigned'}")
                        flash("Case created.","success")
                    except Exception as e: flash(f"Could not create case: {e}","error")
        return redirect(url_for("cases"))
    room_users=db.list_users(u["room_id"]) if u.get("room_id") else []
    visible=db.list_cases_for_user(u["room_id"],u["id"],u.get("role")=="HIGHER_AUTHORITY")
    pending=db.list_case_requests(u["room_id"]) if u.get("role")=="HIGHER_AUTHORITY" else []
    return render_template("cases.html",title="Forensic Case Management",room_users=room_users,case_requests=pending,visible_cases=visible)


@app.route("/authority/case-requests/<int:request_id>/decide", methods=["POST"])
@authority_required
def authority_decide_case_request(request_id):
    req=db.get_case_request(request_id); u=current_user()
    if not req or req["status"]!="PENDING":
        flash("Case request not found.","error"); return redirect(url_for("authority_dashboard"))
    requester=db.get_user(req["requested_by"])
    if not requester or requester.get("room_id")!=u["room_id"]:
        flash("That request is not from your room.","error"); return redirect(url_for("authority_dashboard"))
    decision=request.form.get("decision")
    if decision=="APPROVE":
        try:
            db.create_case(req["case_id"],req["title"],requester["name"],u["room_id"])
            db.add_case_member(req["case_id"],requester["id"],"TEAM_LEAD",u["id"])
            db.decide_case_request(request_id,"APPROVED",u["id"])
            db.audit(u["id"],"CASE_REQUEST_APPROVED",request.remote_addr or "unknown",request.user_agent.string,
                     f"Approved {req['case_id']} and assigned requester {requester['name']} as Team Lead")
            db.add_notification(requester["id"],"Case Approved",f"{req['case_id']} was approved. You are the Team Lead.","SUCCESS",req["case_id"])
            flash(f"{req['case_id']} created and assigned to {requester['name']} as Team Lead.","success")
        except Exception as e: flash(f"Could not approve request: {e}","error")
    else:
        db.decide_case_request(request_id,"REJECTED",u["id"])
        db.audit(u["id"],"CASE_REQUEST_REJECTED",request.remote_addr or "unknown",request.user_agent.string,f"Rejected case request {req['case_id']}")
        db.add_notification(requester["id"],"Case Request Rejected",f"Your request for {req['case_id']} was rejected.","WARNING")
        flash("Case request rejected.","success")
    return redirect(url_for("authority_dashboard"))

@app.route("/case/<case_id>/members", methods=["POST"])
@authority_required
def case_members_manage(case_id):
    u=current_user(); case=db.get_case(case_id,room_id=u["room_id"])
    if not case: flash("Case not found.","error"); return redirect(url_for("cases"))
    action=request.form.get("action","ADD")
    uid=int(request.form.get("user_id","0") or 0)
    target=db.get_user(uid) if uid else None
    if not target or target.get("room_id")!=u["room_id"] or not target.get("verified"):
        flash("Select an active member of this room.","error")
    elif action=="ADD":
        role=request.form.get("case_role","MEMBER").upper()
        if role not in ("MEMBER","TEAM_LEAD"): role="MEMBER"
        if role=="TEAM_LEAD":
            # Team Lead transfer is authority-only and creates a new immutable event.
            for m in db.list_case_members(case_id):
                if m["case_role"]=="TEAM_LEAD": db.add_case_member(case_id,m["user_id"],"MEMBER",u["id"])
        db.add_case_member(case_id,uid,role,u["id"])
        db.record_access_grant(uid,role,"CASE_ASSIGNMENT",u["id"],f"Assigned to case {case_id}",room_id=u["room_id"])
        db.audit(u["id"],"CASE_MEMBER_ASSIGNED",request.remote_addr or "unknown",request.user_agent.string,f"Assigned {target['name']} to {case_id} as {role}")
        db.add_notification(uid,"Case Assignment",f"You were assigned to {case_id} as {role}.","SUCCESS",case_id)
        flash(f"{target['name']} assigned to {case_id} as {role}.","success")
    elif action=="REMOVE":
        if db.get_case_membership(case_id,uid):
            db.remove_case_member(case_id,uid)
            db.record_access_grant(uid,target.get("role","MEMBER"),"CASE_ACCESS_REVOKED",u["id"],f"Removed from case {case_id}",room_id=u["room_id"])
            db.audit(u["id"],"CASE_MEMBER_REMOVED",request.remote_addr or "unknown",request.user_agent.string,f"Removed {target['name']} from {case_id}")
            db.add_notification(uid,"Case Access Revoked",f"Your access to {case_id} was revoked by Authority.","WARNING",case_id)
            flash(f"{target['name']} removed from {case_id}.","success")
    return redirect(url_for("case_detail",case_id=case_id))

@app.route("/case/<case_id>", methods=["GET", "POST"])
def case_detail(case_id):
    case = db.get_case(case_id, room_id=current_user()["room_id"])
    if not case:
        flash("Case not found in your room.", "error"); return redirect(url_for("cases"))
    if request.method == "POST":
        f = request.files.get("evidence")
        analyst = current_user()["name"]
        if not f or not f.filename:
            flash("Select evidence to upload.", "error")
        else:
            try:
                p = save_upload(f, CASES / case_id)
                info = file_info(p); sha = hash_file(p)["SHA-256"]
                eid = db.add_evidence(case_id, info["name"], str(p), info["size"], info["mime"], sha)
                if request.form.get("notes"):
                    db.add_custody(case_id, eid, "Evidence Note", analyst, request.form["notes"])
                rebuild_merkle(case_id)
                flash(f"Evidence registered: {info['name']}", "success")
            except Exception as e:
                flash(f"Could not register evidence: {e}", "error")
        return redirect(url_for("case_detail", case_id=case_id))
    return render_template("case_detail.html", title=f"Case {case_id}", case=case,
                           evidence=db.list_evidence(case_id, include_deleted=False), custody=db.list_custody(case_id),
                           members=db.list_case_members(case_id), room_users=db.list_users(current_user()["room_id"]))


def _owned_upload_session(session_id):
    """Fetch an upload session and verify it belongs to the current user's room and account.
    Never trust a session_id alone — someone else's room must not be able to read/write it."""
    s = db.get_upload_session(session_id)
    u = current_user()
    if not s or not u or s["room_id"] != u["room_id"] or s["user_id"] != u["id"]:
        return None
    return s

@app.route("/case/<case_id>/evidence/chunked/start", methods=["POST"])
def chunked_upload_start(case_id):
    """Step 1 of the resumable upload: register the file's name/size, pre-allocate nothing
    (the file is created empty and simply grows as chunks land), and hand back a session_id
    the browser will PATCH chunks against. Large evidence never passes through this process's
    memory — only CHUNK_UPLOAD_MAX_BYTES at a time ever does, via the PATCH step below."""
    case = db.get_case(case_id, room_id=current_user()["room_id"])
    if not case:
        return jsonify(error="Case not found in your room."), 404
    data = request.get_json(silent=True) or {}
    filename = secure_filename(data.get("filename") or "")
    total_size = data.get("total_size")
    notes = (data.get("notes") or "").strip()
    try:
        total_size = int(total_size)
    except (TypeError, ValueError):
        total_size = -1
    if not filename:
        return jsonify(error="A filename is required."), 400
    if total_size <= 0:
        return jsonify(error="total_size must be a positive number of bytes."), 400
    folder = CASES / case_id
    folder.mkdir(parents=True, exist_ok=True)
    session_id = _secrets.token_urlsafe(24)
    target = folder / f".upload_{session_id}_{filename}"
    target.touch(exist_ok=False)
    db.create_upload_session(session_id, case_id, current_user()["room_id"], current_user()["id"],
                              filename, str(target), total_size, notes)
    db.audit(current_user()["id"], "LARGE_EVIDENCE_UPLOAD_STARTED", request.remote_addr or "unknown",
              request.user_agent.string, f"Started chunked upload of '{filename}' ({total_size} bytes) for case {case_id}")
    return jsonify(session_id=session_id, offset=0, chunk_size_hint=16*1024*1024)

@app.route("/case/<case_id>/evidence/chunked/<session_id>", methods=["GET"])
def chunked_upload_status(case_id, session_id):
    """Lets the browser ask 'how much of this did you already receive?' after a dropped
    connection or a page reload, so it can resume from the right byte instead of restarting."""
    s = _owned_upload_session(session_id)
    if not s or s["case_id"] != case_id:
        return jsonify(error="Upload session not found."), 404
    return jsonify(offset=s["received_bytes"], total_size=s["total_size"], status=s["status"], filename=s["filename"])

@app.route("/case/<case_id>/evidence/chunked/<session_id>", methods=["PATCH"])
def chunked_upload_chunk(case_id, session_id):
    """Step 2, called repeatedly: append the next raw chunk at the exact byte offset the server
    says it's expecting. If the browser's idea of the offset is stale (e.g. two tabs, or a retry
    after an ambiguous network failure), the server rejects it with 409 and the real offset, and
    the client resyncs instead of corrupting the file by writing at the wrong place."""
    s = _owned_upload_session(session_id)
    if not s or s["case_id"] != case_id:
        return jsonify(error="Upload session not found."), 404
    if s["status"] != "IN_PROGRESS":
        return jsonify(error=f"This upload is {s['status'].lower()}, not in progress."), 409
    try:
        client_offset = int(request.headers.get("Upload-Offset", ""))
    except ValueError:
        return jsonify(error="Missing or invalid Upload-Offset header."), 400
    if client_offset != s["received_bytes"]:
        return jsonify(error="Offset mismatch; resync and retry from the reported offset.",
                        offset=s["received_bytes"]), 409
    chunk = request.get_data(cache=False)  # one chunk only (<= CHUNK_UPLOAD_MAX_BYTES, enforced by MAX_CONTENT_LENGTH)
    if not chunk:
        return jsonify(error="Empty chunk."), 400
    new_total = s["received_bytes"] + len(chunk)
    if new_total > s["total_size"]:
        return jsonify(error="This chunk would exceed the file's declared total_size."), 400
    with open(s["stored_path"], "ab") as fh:
        fh.write(chunk)
    db.advance_upload_session(session_id, new_total)
    return jsonify(offset=new_total, total_size=s["total_size"], complete=(new_total == s["total_size"]))

@app.route("/case/<case_id>/evidence/chunked/<session_id>/finish", methods=["POST"])
def chunked_upload_finish(case_id, session_id):
    """Step 3: once every byte has landed, stream-hash the assembled file (hash_file() reads it
    in 1 MB chunks, so this never loads the file into memory either) and register it as evidence
    through the exact same path a small direct upload uses, so nothing downstream has to know
    or care which upload tier produced the file."""
    s = _owned_upload_session(session_id)
    if not s or s["case_id"] != case_id:
        return jsonify(error="Upload session not found."), 404
    if s["status"] != "IN_PROGRESS":
        return jsonify(error=f"This upload is already {s['status'].lower()}."), 409
    if s["received_bytes"] != s["total_size"]:
        return jsonify(error=f"Only {s['received_bytes']} of {s['total_size']} bytes received; keep uploading.",
                        offset=s["received_bytes"]), 409
    case = db.get_case(case_id, room_id=current_user()["room_id"])
    if not case:
        return jsonify(error="Case not found in your room."), 404
    stored_path = Path(s["stored_path"])
    final_path = stored_path.parent / s["filename"]
    i = 1
    while final_path.exists():
        final_path = stored_path.parent / f"{Path(s['filename']).stem}_{i}{Path(s['filename']).suffix}"
        i += 1
    stored_path.rename(final_path)
    info = file_info(final_path)
    sha = hash_file(final_path)["SHA-256"]
    eid = db.add_evidence(case_id, info["name"], str(final_path), info["size"], info["mime"], sha)
    note = s.get("notes") or ""
    db.add_custody(case_id, eid, "Large Evidence Upload Completed", current_user()["name"],
                    f"Resumable chunked upload finished ({info['size']} bytes)." + (f" Notes: {note}" if note else ""))
    rebuild_merkle(case_id)
    db.set_upload_session_status(session_id, "COMPLETE")
    db.audit(current_user()["id"], "LARGE_EVIDENCE_UPLOAD_COMPLETE", request.remote_addr or "unknown",
              request.user_agent.string, f"Completed chunked upload: evidence #{eid} ({info['name']}, {info['size']} bytes) in case {case_id}")
    return jsonify(ok=True, evidence_id=eid, name=info["name"], size=info["size"], sha256=sha,
                    redirect=url_for("case_detail", case_id=case_id))

@app.route("/case/<case_id>/evidence/chunked/<session_id>", methods=["DELETE"])
def chunked_upload_abort(case_id, session_id):
    """Cancel an in-progress large upload and remove the partial file."""
    s = _owned_upload_session(session_id)
    if not s or s["case_id"] != case_id:
        return jsonify(error="Upload session not found."), 404
    try:
        Path(s["stored_path"]).unlink(missing_ok=True)
    except Exception:
        pass
    db.set_upload_session_status(session_id, "ABORTED")
    db.audit(current_user()["id"], "LARGE_EVIDENCE_UPLOAD_ABORTED", request.remote_addr or "unknown",
              request.user_agent.string, f"Aborted chunked upload '{s['filename']}' for case {case_id}")
    return jsonify(ok=True)

@app.route("/case/<case_id>/evidence/<int:evidence_id>/view")
def view_evidence(case_id, evidence_id):
    case = db.get_case(case_id, room_id=current_user()["room_id"])
    if not case:
        flash("Case not found.", "error")
        return redirect(url_for("cases"))
    evidence = next((e for e in db.list_evidence(case_id) if e["id"] == evidence_id), None)
    if not evidence:
        flash("Evidence not found.", "error")
        return redirect(url_for("case_detail", case_id=case_id))
    p = Path(evidence["stored_path"])
    if not p.exists():
        flash("Evidence file is missing from the case storage.", "error")
        return redirect(url_for("case_detail", case_id=case_id))
    # Viewing is read-only with respect to the evidence bytes, but the access itself
    # is recorded in the chain-of-custody audit trail.
    analyst = current_user()["name"]
    db.add_custody(
        case_id, evidence_id, "Evidence Viewed", analyst,
        f"Read-only evidence access | IP: {request.remote_addr or 'unknown'} | User-Agent: {request.user_agent.string[:200]}"
    )
    response = send_file(p, as_attachment=False, conditional=True)
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route("/case/<case_id>/evidence/<int:evidence_id>/edit", methods=["GET", "POST"])
def edit_evidence(case_id, evidence_id):
    case = db.get_case(case_id, room_id=current_user()["room_id"]); evidence = db.get_evidence(evidence_id)
    if not case or not evidence or evidence["case_id"] != case_id:
        flash("Evidence not found.", "error"); return redirect(url_for("case_detail", case_id=case_id))
    p = Path(evidence["stored_path"])
    if not p.exists():
        flash("Current evidence version is missing.", "error"); return redirect(url_for("case_detail", case_id=case_id))
    analyst = current_user()["name"]
    if request.method == "GET":
        try: text = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            flash("This editor supports UTF-8 text evidence only. The original remains preserved.", "error")
            return redirect(url_for("case_detail", case_id=case_id))
        db.add_custody(case_id,evidence_id,"Evidence Edit Opened",analyst,f"Working-copy editor opened | IP: {request.remote_addr or 'unknown'}")
        return render_template("edit_evidence.html",title=f"Edit Evidence #{evidence['evidence_no']}",case=case,evidence=evidence,text=text)
    text=request.form.get("content","")
    try:
        versions=db.list_versions(evidence_id); next_no=(versions[0]["version_no"]+1 if versions else 2)
        version_dir=CASES/case_id/"versions"; version_dir.mkdir(parents=True,exist_ok=True)
        safe=Path(evidence["name"]).name; target=version_dir/f"v{next_no}_{safe}"
        target.write_text(text,encoding="utf-8")
        current_sha=hash_file(target)["SHA-256"]
        db.add_version(evidence_id,str(target),current_sha,target.stat().st_size,analyst,"Edited working version; original evidence preserved")
        db.add_custody(case_id,evidence_id,"Evidence Version Created",analyst,f"Version {next_no} saved. Original baseline SHA-256: {evidence['sha256']} | New version SHA-256: {current_sha}")
        db.update_evidence_status(evidence_id,"MODIFIED" if current_sha.lower()!=evidence["sha256"].lower() else "VERIFIED")
        verify_case(case_id)
        flash(f"Version {next_no} saved. Original evidence was preserved. Current integrity: {'VERIFIED' if current_sha.lower()==evidence['sha256'].lower() else 'MODIFIED'}.","success" if current_sha.lower()==evidence['sha256'].lower() else "error")
    except Exception as e: flash(f"Could not save version: {e}","error")
    return redirect(url_for("evidence_versions",case_id=case_id,evidence_id=evidence_id))

@app.route("/case/<case_id>/evidence/<int:evidence_id>/edit-upload", methods=["GET", "POST"])
def edit_upload_evidence(case_id, evidence_id):
    case=db.get_case(case_id, room_id=current_user()["room_id"]); evidence=db.get_evidence(evidence_id)
    if not case or not evidence or evidence["case_id"]!=case_id:
        flash("Evidence not found.","error"); return redirect(url_for("case_detail",case_id=case_id))
    analyst=current_user()["name"]
    if request.method=="GET":
        db.add_custody(case_id,evidence_id,"Evidence Working Copy Requested",analyst,
                       f"Prepared for modification without overwriting original | IP: {request.remote_addr or 'unknown'}")
        return render_template("edit_upload.html",title=f"Create Evidence Version — #{evidence['evidence_no']}",case=case,evidence=evidence)
    f=request.files.get("modified_file")
    note=(request.form.get("change_note") or "Modified working copy").strip()
    if not f or not f.filename:
        flash("Select the modified working-copy file.","error"); return redirect(url_for("edit_upload_evidence",case_id=case_id,evidence_id=evidence_id))
    try:
        versions=db.list_versions(evidence_id); next_no=(versions[0]["version_no"]+1 if versions else 2)
        version_dir=CASES/case_id/"versions"; version_dir.mkdir(parents=True,exist_ok=True)
        safe=Path(f.filename).name
        target=version_dir/f"v{next_no}_{safe}"
        f.save(target)
        current_sha=hash_file(target)["SHA-256"]
        status="VERIFIED" if current_sha.lower()==evidence["sha256"].lower() else "MODIFIED"
        db.add_version(evidence_id,str(target),current_sha,target.stat().st_size,analyst,note)
        db.update_evidence_status(evidence_id,status)
        db.add_custody(case_id,evidence_id,"Evidence Version Created",analyst,
                       f"Version {next_no} uploaded as working version | Original SHA-256: {evidence['sha256']} | New SHA-256: {current_sha} | Note: {note}")
        verify_case(case_id)
        flash(f"Version {next_no} saved. Original evidence preserved. Current integrity: {status}.",
              "success" if status=="VERIFIED" else "error")
    except Exception as e:
        flash(f"Could not save evidence version: {e}","error")
    return redirect(url_for("evidence_versions",case_id=case_id,evidence_id=evidence_id))


@app.route("/case/<case_id>/evidence/<int:evidence_id>/versions")
def evidence_versions(case_id,evidence_id):
    case=db.get_case(case_id, room_id=current_user()["room_id"]); evidence=db.get_evidence(evidence_id)
    if not case or not evidence or evidence["case_id"]!=case_id:
        flash("Evidence not found.","error"); return redirect(url_for("case_detail",case_id=case_id))
    return render_template("evidence_versions.html",title=f"Evidence #{evidence['evidence_no']} Versions",case=case,evidence=evidence,versions=db.list_versions(evidence_id))

@app.route("/case/<case_id>/evidence/<int:evidence_id>/version/<int:version_no>/view")
def view_evidence_version(case_id,evidence_id,version_no):
    case=db.get_case(case_id, room_id=current_user()["room_id"]); evidence=db.get_evidence(evidence_id); version=db.get_version(evidence_id,version_no)
    if not case or not evidence or evidence["case_id"]!=case_id or not version:
        flash("Evidence version not found.","error"); return redirect(url_for("case_detail",case_id=case_id))
    p=Path(version["path"])
    if not p.exists(): flash("Version file is missing.","error"); return redirect(url_for("evidence_versions",case_id=case_id,evidence_id=evidence_id))
    db.add_custody(case_id,evidence_id,"Evidence Version Viewed",current_user()["name"],f"Viewed version {version_no} | SHA-256: {version['sha256']} | IP: {request.remote_addr or 'unknown'}")
    return send_file(p,as_attachment=False,conditional=True,mimetype=evidence.get("mime") or "application/octet-stream")

@app.route("/case/<case_id>/evidence/<int:evidence_id>/delete", methods=["POST"])
def delete_evidence(case_id,evidence_id):
    if not is_authority():
        db.audit(current_user()["id"],"EVIDENCE_DELETE_DENIED",request.remote_addr or "unknown",request.user_agent.string,f"Denied delete attempt for evidence #{evidence_id} in case {case_id}")
        flash("Only Higher Authority can delete evidence.","error"); return redirect(url_for("case_detail",case_id=case_id))
    case=db.get_case(case_id, room_id=current_user()["room_id"]); evidence=db.get_evidence(evidence_id)
    if not case or not evidence or evidence["case_id"]!=case_id: flash("Evidence not found.","error"); return redirect(url_for("case_detail",case_id=case_id))
    db.soft_delete_evidence(evidence_id,current_user()["name"])
    db.add_custody(case_id,evidence_id,"Evidence Deleted",current_user()["name"],f"Moved to Recently Deleted for 30-day recovery window | IP: {request.remote_addr or 'unknown'}")
    db.audit(current_user()["id"],"EVIDENCE_DELETED",request.remote_addr or "unknown",request.user_agent.string,f"Deleted evidence #{evidence_id} ({evidence['name']}) in case {case_id}; 30-day recovery window")
    db.notify_room(current_user()["room_id"],"MANDATORY: Evidence Deleted",f"Evidence {evidence['name']} (#{evidence['evidence_no']}) in case {case_id} was deleted by Higher Authority on {db.now()}. It is in Recently Deleted for 30 days and may only be restored by Higher Authority.","WARNING",case_id,evidence_id)
    flash("Evidence deleted and all authorized users notified. It is retained in Recently Deleted for 30 days; no permanent deletion is available.","success")
    return redirect(url_for("case_detail",case_id=case_id))

@app.route("/case/<case_id>/recently-deleted")
def recently_deleted(case_id):
    case=db.get_case(case_id, room_id=current_user()["room_id"])
    if not case: flash("Case not found.","error"); return redirect(url_for("cases"))
    deleted=[e for e in db.list_evidence(case_id) if e.get("deleted_at")]
    return render_template("recently_deleted.html",title="Recently Deleted Evidence",case=case,evidence=deleted,authority=is_authority())

@app.route("/case/<case_id>/evidence/<int:evidence_id>/restore", methods=["POST"])
def restore_evidence(case_id,evidence_id):
    if not is_authority():
        db.audit(current_user()["id"],"EVIDENCE_RESTORE_DENIED",request.remote_addr or "unknown",request.user_agent.string,f"Denied restore attempt for evidence #{evidence_id} in case {case_id}")
        flash("Only Higher Authority can restore deleted evidence.","error"); return redirect(url_for("recently_deleted",case_id=case_id))
    evidence=db.get_evidence(evidence_id)
    if not evidence or evidence["case_id"]!=case_id: flash("Evidence not found.","error"); return redirect(url_for("recently_deleted",case_id=case_id))
    if evidence.get("status")!="DELETED": flash("The 30-day restore window has expired. The evidence remains retained as an archive record and cannot be permanently deleted.","error"); return redirect(url_for("recently_deleted",case_id=case_id))
    db.restore_evidence(evidence_id)
    pth=Path(evidence["stored_path"])
    restored_status="MISSING" if not pth.exists() else ("VERIFIED" if hash_file(pth)["SHA-256"].lower()==evidence["sha256"].lower() else "MODIFIED")
    db.update_evidence_status(evidence_id,restored_status)
    db.add_custody(case_id,evidence_id,"Evidence Restored",current_user()["name"],f"Restored by Higher Authority from Recently Deleted | Integrity after restore: {restored_status}")
    db.audit(current_user()["id"],"EVIDENCE_RESTORED",request.remote_addr or "unknown",request.user_agent.string,f"Restored evidence #{evidence_id} ({evidence['name']}) in case {case_id}")
    db.notify_room(current_user()["room_id"],"MANDATORY: Evidence Restored",f"Evidence {evidence['name']} (#{evidence['evidence_no']}) in case {case_id} was restored by Higher Authority on {db.now()}.","INFO",case_id,evidence_id)
    flash("Evidence restored. All authorized users were notified.","success"); return redirect(url_for("recently_deleted",case_id=case_id))

@app.route("/case/<case_id>/evidence/<int:evidence_id>/download")
def download_evidence(case_id, evidence_id):
    case = db.get_case(case_id, room_id=current_user()["room_id"])
    if not case:
        flash("Case not found.", "error")
        return redirect(url_for("cases"))
    evidence = next((e for e in db.list_evidence(case_id) if e["id"] == evidence_id), None)
    if not evidence:
        flash("Evidence not found.", "error")
        return redirect(url_for("case_detail", case_id=case_id))
    p = Path(evidence["stored_path"])
    if not p.exists():
        flash("Evidence file is missing from the case storage.", "error")
        return redirect(url_for("case_detail", case_id=case_id))
    analyst = current_user()["name"]
    db.add_custody(
        case_id, evidence_id, "Evidence Downloaded", analyst,
        f"Evidence copy downloaded | IP: {request.remote_addr or 'unknown'} | User-Agent: {request.user_agent.string[:200]}"
    )
    return send_file(p, as_attachment=True, download_name=evidence["name"])


@app.route("/case/<case_id>/evidence/<int:evidence_id>/verify", methods=["POST"])
def verify_single_evidence(case_id, evidence_id):
    case = db.get_case(case_id, room_id=current_user()["room_id"])
    if not case:
        flash("Case not found.", "error")
        return redirect(url_for("cases"))
    evidence = db.get_evidence(evidence_id)
    if not evidence or evidence["case_id"] != case_id:
        flash("Evidence not found in this case.", "error")
        return redirect(url_for("case_detail", case_id=case_id))

    p = Path(evidence["stored_path"])
    if not p.exists():
        verification = "MISSING"
        current_sha = None
    else:
        current_sha = hash_file(p)["SHA-256"]
        verification = "VERIFIED" if current_sha.lower() == evidence["sha256"].lower() else "MODIFIED"

    db.update_evidence_status(evidence_id, verification)
    db.add_custody(
        case_id, evidence_id,
        "Evidence Integrity Verified" if verification == "VERIFIED" else f"Evidence Verification {verification}",
        case.get("analyst") or "SanHasher Analyst",
        f"Stored SHA-256: {evidence['sha256']} | Current SHA-256: {current_sha or 'N/A'}"
    )

    # Re-evaluate the complete case after the individual verification.
    verify_case(case_id)
    if verification == "VERIFIED":
        flash(f"Evidence #{evidence['evidence_no']} verified successfully.", "success")
    elif verification == "MODIFIED":
        flash(f"Evidence #{evidence['evidence_no']} has been MODIFIED. Integrity check failed.", "error")
    else:
        flash(f"Evidence #{evidence['evidence_no']} is MISSING.", "error")
    return redirect(url_for("case_detail", case_id=case_id))


@app.route("/case/<case_id>/verify", methods=["POST"])
def case_verify(case_id):
    if not db.get_case(case_id, room_id=current_user()["room_id"]):
        flash("Case not found.", "error"); return redirect(url_for("cases"))
    results, status = verify_case(case_id)
    for r in results:
        action = "Integrity Verified" if r["verification"] == "VERIFIED" else f"Verification {r['verification']}"
        db.add_custody(case_id, r["id"], action, current_user()["name"], f"Stored SHA-256: {r['sha256']} | Current: {r['current_sha256'] or 'N/A'}")
    flash(status, "success" if status == "INTEGRITY VERIFIED" else "error")
    return redirect(url_for("case_detail", case_id=case_id))


@app.route("/case/<case_id>/merkle")
def case_merkle(case_id):
    case = db.get_case(case_id, room_id=current_user()["room_id"])
    if not case:
        flash("Case not found.", "error"); return redirect(url_for("cases"))
    ev = db.list_evidence(case_id, include_deleted=False); leaves = [e["sha256"] for e in ev]
    layers = merkle_layers(leaves); root = layers[-1][0] if layers else None
    return render_template("merkle.html", title="Merkle Verification", case=case, evidence=ev,
                           layers=list(enumerate(layers)), root=root)


@app.route("/case/<case_id>/custody")
def case_custody(case_id):
    case = db.get_case(case_id, room_id=current_user()["room_id"])
    if not case:
        flash("Case not found.", "error"); return redirect(url_for("cases"))
    return render_template("custody.html", title="Chain of Custody", case=case, custody=db.list_custody(case_id))


@app.route("/reports", methods=["GET", "POST"])
def reports():
    if request.method == "POST":
        case_id = request.form.get("case_id")
        if not db.get_case(case_id, room_id=current_user()["room_id"]):
            flash("Case not found.", "error")
        else:
            try:
                path = make_report(case_id)
                db.add_custody(case_id, None, "Forensic Report Generated", current_user()["name"], f"Report: {Path(path).name}")
                flash(f"Report generated: {Path(path).name}", "success")
            except Exception as e:
                flash(f"Could not generate report: {e}", "error")
        return redirect(url_for("reports"))
    files = sorted(REPORTS.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True)
    return render_template("reports.html", title="Forensic Reports", reports=files)


@app.route("/reports/<name>")
def download_report(name):
    p = REPORTS / Path(name).name
    if not p.exists():
        flash("Report not found.", "error"); return redirect(url_for("reports"))
    # Report downloads are also auditable.
    case_id = request.args.get("case_id")
    if case_id and db.get_case(case_id, room_id=current_user()["room_id"]):
        db.add_custody(case_id, None, "Forensic Report Downloaded", current_user()["name"], f"Report: {p.name} | IP: {request.remote_addr or 'unknown'}")
    return send_file(p, as_attachment=True)


@app.route("/audit")
@authority_required
def audit_log():
    room_id=current_user()["room_id"]
    return render_template("audit.html", title="Room Security Audit Log", events=db.list_audit(300,room_id=room_id), grants=db.list_access_grants(300,room_id=room_id), grant_integrity=db.verify_access_grants())

@app.route("/about")
def about():
    return render_template("about.html", title="About SanHasher 2.0")
