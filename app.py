import argparse
import base64
import hashlib
import os
import secrets
import smtplib

import pytz
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from functools import wraps
from pathlib import Path

from flask import Flask, abort, g, jsonify, redirect, render_template, request, session, url_for
from garminconnect import Garmin
from waitress import serve
from werkzeug.middleware.proxy_fix import ProxyFix

from omronconnect import BPMeasurement, DeviceCategory, OmronClient
from secure_store import SecureStore

app = Flask(__name__)


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


_is_production = _env_flag("PRODUCTION", False) or _env_flag("RENDER", False) or (
    os.getenv("FLASK_ENV", "").strip().lower() == "production"
)
_trust_proxy_count = int(os.getenv("TRUST_PROXY_COUNT", "1" if _env_flag("RENDER", False) else "0"))
if _trust_proxy_count > 0:
    app.wsgi_app = ProxyFix(
        app.wsgi_app,  # type: ignore[assignment]
        x_for=_trust_proxy_count,
        x_proto=_trust_proxy_count,
        x_host=_trust_proxy_count,
    )

_secret_from_env = os.getenv("FLASK_SECRET_KEY", "").strip()
_credential_key_from_env = os.getenv("CREDENTIALS_ENCRYPTION_KEY", "").strip()

if _is_production and not _secret_from_env:
    raise RuntimeError("FLASK_SECRET_KEY must be set in production.")
if _is_production and not _credential_key_from_env:
    raise RuntimeError("CREDENTIALS_ENCRYPTION_KEY must be set in production.")

if _secret_from_env:
    app.secret_key = _secret_from_env
else:
    app.secret_key = secrets.token_urlsafe(48)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "1") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=int(os.getenv("SESSION_LIFETIME_HOURS", "12"))),
)


def _resolve_encryption_key() -> str:
    if _credential_key_from_env:
        return _credential_key_from_env
    digest = hashlib.sha256(f"{app.secret_key}|credential-vault".encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii")


_database_url = os.getenv("DATABASE_URL", "").strip()
_sqlite_path = os.getenv("APP_DB_PATH", str(Path(__file__).resolve().parent / "data" / "app.db"))
_login_max_attempts = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))
_login_window_seconds = int(os.getenv("LOGIN_WINDOW_SECONDS", "900"))
_login_lockout_seconds = int(os.getenv("LOGIN_LOCKOUT_SECONDS", "900"))
_password_reset_ttl_seconds = int(os.getenv("PASSWORD_RESET_TOKEN_TTL_SECONDS", "3600"))
_login_throttle_retention_seconds = int(os.getenv("LOGIN_THROTTLE_RETENTION_SECONDS", "604800"))
_login_throttle_max_rows = int(os.getenv("LOGIN_THROTTLE_MAX_ROWS", "50000"))
_audit_retention_days = int(os.getenv("AUDIT_RETENTION_DAYS", "180"))
_audit_max_rows = int(os.getenv("AUDIT_MAX_ROWS", "200000"))
_hsts_enabled = _env_flag("HSTS_ENABLED", _is_production)

STORE = SecureStore(
    encryption_key=_resolve_encryption_key(),
    db_path=_sqlite_path if not _database_url else None,
    database_url=_database_url or None,
    login_max_attempts=_login_max_attempts,
    login_window_seconds=_login_window_seconds,
    login_lockout_seconds=_login_lockout_seconds,
    throttle_retention_seconds=_login_throttle_retention_seconds,
    throttle_max_rows=_login_throttle_max_rows,
    audit_retention_seconds=max(1, _audit_retention_days) * 86400,
    audit_max_rows=_audit_max_rows,
)

if _database_url:
    app.logger.info("Credential store backend: PostgreSQL (DATABASE_URL).")
else:
    app.logger.info("Credential store backend: SQLite (%s).", _sqlite_path)
    app.logger.warning(
        "SQLite on ephemeral filesystems may lose accounts/credentials after redeploy. "
        "Set DATABASE_URL for persistent storage."
    )

if not _secret_from_env:
    app.logger.warning("FLASK_SECRET_KEY is not set. Generated an ephemeral key for this process.")

if not _credential_key_from_env:
    app.logger.warning("CREDENTIALS_ENCRYPTION_KEY is not set. Deriving encryption key from FLASK_SECRET_KEY.")

if _trust_proxy_count > 0:
    app.logger.info("ProxyFix enabled with TRUST_PROXY_COUNT=%s", _trust_proxy_count)


def _current_user_id() -> int | None:
    value = session.get("user_id")
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _session_version_from_user(user: dict[str, str | int | bool]) -> int:
    try:
        return int(user.get("session_version", 1))
    except (TypeError, ValueError):
        return 1


def _current_user() -> dict[str, str | int | bool] | None:
    if getattr(g, "_current_user_loaded", False):
        return getattr(g, "current_user", None)

    g._current_user_loaded = True
    user_id = _current_user_id()
    if user_id is None:
        g.current_user = None
        return None

    user = STORE.get_user_by_id(user_id)
    if not user or not bool(user.get("is_active")):
        session.clear()
        g.current_user = None
        return None

    expected_session_version = _session_version_from_user(user)
    try:
        session_version = int(session.get("session_version", -1))
    except (TypeError, ValueError):
        session_version = -1
    if session_version != expected_session_version:
        session.clear()
        g.current_user = None
        _record_audit_event(
            "session.invalidated",
            outcome="success",
            target_user_id=int(user["id"]),
            username=str(user["username"]),
            details={
                "reason": "session_version_mismatch",
                "expected": expected_session_version,
                "received": session_version,
            },
        )
        return None

    session["username"] = str(user["username"])
    session["is_admin"] = bool(user.get("is_admin"))
    session["session_version"] = expected_session_version
    g.current_user = user
    return user


def _registration_open() -> bool:
    if _env_flag("ALLOW_REGISTRATION", False):
        return True
    return STORE.user_count() == 0


def _csrf_token() -> str:
    token = session.get("csrf_token")
    if not isinstance(token, str) or not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


@app.context_processor
def _inject_globals():
    return {
        "csrf_token": _csrf_token(),
        "session_username": session.get("username", ""),
        "session_is_admin": bool(session.get("is_admin", False)),
    }


@app.before_request
def _csrf_protect():
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return

    expected = session.get("csrf_token")
    provided = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    if not expected or not provided or not secrets.compare_digest(str(expected), str(provided)):
        abort(403)


@app.after_request
def _set_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

    response.headers.setdefault(
        "Content-Security-Policy",
        (
            "default-src 'self'; "
            "img-src 'self' data: https://github.githubassets.com https://stripe.com; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; "
            "connect-src 'self'; "
            "font-src 'self' data:; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'"
        ),
    )

    if _hsts_enabled and request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

    return response


def _wants_json_response() -> bool:
    accept_header = request.headers.get("Accept", "").lower()
    return request.path.startswith("/api/") or "application/json" in accept_header


def _auth_required_response():
    if _wants_json_response():
        return jsonify({"error": "Authentication required."}), 401
    return redirect(url_for("login_page"))


def _forbidden_response(message: str):
    if _wants_json_response():
        return jsonify({"error": message}), 403
    return redirect(url_for("index"))


def _client_ip() -> str:
    return (request.remote_addr or "").strip()


def _record_audit_event(
    event_type: str,
    outcome: str = "success",
    actor_user_id: int | None = None,
    target_user_id: int | None = None,
    username: str | None = None,
    details: dict[str, object] | None = None,
) -> None:
    try:
        STORE.record_audit_event(
            event_type=event_type,
            outcome=outcome,
            actor_user_id=actor_user_id if actor_user_id is not None else _current_user_id(),
            target_user_id=target_user_id,
            username=username,
            ip_address=_client_ip(),
            details=details,
        )
    except Exception:  # pylint: disable=broad-except
        app.logger.exception("Audit event write failed for %s", event_type)


def _set_authenticated_session(user: dict[str, str | int | bool]) -> None:
    session.clear()
    session["user_id"] = int(user["id"])
    session["username"] = str(user["username"])
    session["is_admin"] = bool(user.get("is_admin"))
    session["session_version"] = _session_version_from_user(user)
    session["csrf_token"] = secrets.token_urlsafe(32)
    session.permanent = True


def _format_duration(seconds: int) -> str:
    remaining = max(1, int(seconds))
    minutes, secs = divmod(remaining, 60)
    if minutes == 0:
        return f"{secs} seconds"
    if secs == 0:
        return f"{minutes} minutes"
    return f"{minutes}m {secs}s"


def _app_base_url() -> str:
    configured = os.getenv("APP_BASE_URL", "").strip().rstrip("/")
    if configured:
        return configured
    return request.url_root.rstrip("/")


def _json_no_store(payload: dict[str, object], status_code: int = 200):
    response = jsonify(payload)
    response.status_code = status_code
    response.headers["Cache-Control"] = "no-store"
    return response


def _readiness_payload() -> tuple[dict[str, object], int]:
    database_ok, database_reason = STORE.check_database()
    crypto_ok, crypto_reason = STORE.check_crypto()
    is_ready = database_ok and crypto_ok

    database_check: dict[str, object] = {
        "status": "ok" if database_ok else "fail",
        "backend": STORE.backend_name(),
    }
    if not database_ok:
        database_check["reason"] = database_reason

    crypto_check: dict[str, object] = {
        "status": "ok" if crypto_ok else "fail",
    }
    if not crypto_ok:
        crypto_check["reason"] = crypto_reason

    payload: dict[str, object] = {
        "status": "ready" if is_ready else "not_ready",
        "checks": {
            "database": database_check,
            "crypto": crypto_check,
        },
        "time_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    return payload, (200 if is_ready else 503)


def _send_password_reset_email(recipient: str, reset_link: str) -> bool:
    smtp_host = os.getenv("SMTP_HOST", "").strip()
    smtp_from = os.getenv("SMTP_FROM", "").strip()
    if not smtp_host or not smtp_from:
        app.logger.warning("Password reset email not sent: SMTP_HOST/SMTP_FROM not configured.")
        return False
    if "@" not in recipient:
        app.logger.warning("Password reset email not sent: username is not an email address.")
        return False

    smtp_port_default = "587" if _env_flag("SMTP_USE_TLS", True) else "25"
    smtp_port = int(os.getenv("SMTP_PORT", smtp_port_default))
    smtp_timeout = int(os.getenv("SMTP_TIMEOUT_SECONDS", "10"))
    smtp_username = os.getenv("SMTP_USERNAME", "").strip()
    smtp_password = os.getenv("SMTP_PASSWORD", "")
    smtp_use_tls = _env_flag("SMTP_USE_TLS", True)

    ttl_minutes = max(1, _password_reset_ttl_seconds // 60)
    message = EmailMessage()
    message["Subject"] = "Omron to Garmin Sync - Password reset"
    message["From"] = smtp_from
    message["To"] = recipient
    message.set_content(
        (
            "A password reset was requested for your Omron to Garmin Sync account.\n\n"
            f"Reset link: {reset_link}\n\n"
            f"This link expires in about {ttl_minutes} minutes and can be used only once.\n"
            "If you did not request this, you can ignore this email.\n"
        )
    )

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=smtp_timeout) as smtp:
            if smtp_use_tls:
                smtp.starttls()
            if smtp_username:
                smtp.login(smtp_username, smtp_password)
            smtp.send_message(message)
        return True
    except Exception:  # pylint: disable=broad-except
        app.logger.exception("Password reset email delivery failed.")
        return False


def login_required(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        if _current_user() is not None:
            return func(*args, **kwargs)
        return _auth_required_response()

    return wrapped


def admin_required(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        user = _current_user()
        if user is None:
            return _auth_required_response()
        if not bool(user.get("is_admin")):
            return _forbidden_response("Admin access required.")
        return func(*args, **kwargs)

    return wrapped


@app.route("/healthz", methods=["GET"])
def healthz():
    return _json_no_store(
        {
            "status": "alive",
            "service": "omron-to-garmin-sync",
            "time_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
    )


@app.route("/readyz", methods=["GET"])
def readyz():
    payload, status_code = _readiness_payload()
    return _json_no_store(payload, status_code)


@app.route("/login", methods=["GET"])
def login_page():
    if _current_user() is not None:
        return redirect(url_for("index"))
    return render_template("login.html", error=None, registration_open=_registration_open())


@app.route("/forgot-password", methods=["GET"])
def forgot_password_page():
    if _current_user() is not None:
        return redirect(url_for("index"))
    return render_template("forgot_password.html", error=None, success=None)


@app.route("/forgot-password", methods=["POST"])
def forgot_password_action():
    if _current_user() is not None:
        return redirect(url_for("index"))

    username = request.form.get("username", "").strip().lower()
    if not username:
        return render_template("forgot_password.html", error="Username is required.", success=None), 400

    created, recipient, token = STORE.create_password_reset_token(
        username,
        ttl_seconds=_password_reset_ttl_seconds,
    )
    if created:
        reset_link = f"{_app_base_url()}/reset-password/{token}"
        _send_password_reset_email(recipient, reset_link)

    _record_audit_event(
        "auth.password_reset.requested",
        outcome="success",
        username=username,
        details={"account_exists": created},
    )

    return render_template(
        "forgot_password.html",
        error=None,
        success="If an account exists for that username, a password reset link has been sent.",
    )


@app.route("/login", methods=["POST"])
def login_action():
    if _current_user() is not None:
        return redirect(url_for("index"))

    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")
    client_ip = _client_ip()

    lockout_seconds = STORE.get_login_lockout_seconds(username, client_ip)
    if lockout_seconds > 0:
        _record_audit_event(
            "auth.login.blocked",
            outcome="blocked",
            username=username,
            details={"reason": "lockout", "remaining_seconds": lockout_seconds},
        )
        return (
            render_template(
                "login.html",
                error=f"Too many failed attempts. Try again in {_format_duration(lockout_seconds)}.",
                registration_open=_registration_open(),
            ),
            429,
        )

    user = STORE.authenticate_user(username, password)
    if not user:
        STORE.record_login_failure(username, client_ip)
        lockout_after_failure = STORE.get_login_lockout_seconds(username, client_ip)
        if lockout_after_failure > 0:
            error_message = (
                f"Too many failed attempts. Try again in {_format_duration(lockout_after_failure)}."
            )
            status_code = 429
            outcome = "blocked"
        else:
            error_message = "Invalid username or password."
            status_code = 401
            outcome = "failure"
        _record_audit_event(
            "auth.login.failed",
            outcome=outcome,
            username=username,
            details={"status_code": status_code},
        )
        return (
            render_template(
                "login.html",
                error=error_message,
                registration_open=_registration_open(),
            ),
            status_code,
        )

    STORE.clear_login_failures(username, client_ip)
    _set_authenticated_session(user)
    _record_audit_event(
        "auth.login.success",
        outcome="success",
        actor_user_id=int(user["id"]),
        target_user_id=int(user["id"]),
        username=str(user["username"]),
    )
    return redirect(url_for("index"))


def _render_reset_password_page(token: str, error: str | None = None, status_code: int = 200):
    valid, message = STORE.validate_password_reset_token(token)
    if not valid and not error:
        error = message
    return (
        render_template(
            "reset_password.html",
            token=token,
            valid=valid,
            error=error,
            success=None,
        ),
        status_code,
    )


@app.route("/reset-password/<token>", methods=["GET"])
def reset_password_page(token: str):
    if _current_user() is not None:
        return redirect(url_for("index"))
    return _render_reset_password_page(token)


@app.route("/reset-password/<token>", methods=["POST"])
def reset_password_action(token: str):
    if _current_user() is not None:
        return redirect(url_for("index"))

    valid, message = STORE.validate_password_reset_token(token)
    if not valid:
        _record_audit_event(
            "auth.password_reset.failed",
            outcome="failure",
            details={"reason": message},
        )
        return _render_reset_password_page(token, error=message, status_code=400)

    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")
    if new_password != confirm_password:
        _record_audit_event(
            "auth.password_reset.failed",
            outcome="failure",
            details={"reason": "password_mismatch"},
        )
        return _render_reset_password_page(token, error="Passwords do not match.", status_code=400)

    reset_ok, reset_message, user_id, reset_username = STORE.consume_password_reset_token(token, new_password)
    if not reset_ok:
        _record_audit_event(
            "auth.password_reset.failed",
            outcome="failure",
            username=reset_username or None,
            target_user_id=user_id if user_id is not None else None,
            details={"reason": reset_message},
        )
        return _render_reset_password_page(token, error=reset_message, status_code=400)

    _record_audit_event(
        "auth.password_reset.success",
        outcome="success",
        target_user_id=user_id if user_id is not None else None,
        username=reset_username or None,
    )

    return render_template(
        "login.html",
        error="Password reset successful. Please sign in.",
        registration_open=_registration_open(),
    )


@app.route("/register", methods=["POST"])
def register_action():
    if not _registration_open():
        _record_audit_event(
            "auth.register.blocked",
            outcome="blocked",
            details={"reason": "registration_closed"},
        )
        return (
            render_template(
                "login.html",
                error="Registration is disabled.",
                registration_open=False,
            ),
            403,
        )

    username = request.form.get("register_username", "").strip().lower()
    password = request.form.get("register_password", "")
    confirm = request.form.get("register_confirm_password", "")

    if not username:
        _record_audit_event(
            "auth.register.failed",
            outcome="failure",
            details={"reason": "missing_username"},
        )
        return (
            render_template(
                "login.html",
                error="Username is required.",
                registration_open=True,
            ),
            400,
        )

    if password != confirm:
        _record_audit_event(
            "auth.register.failed",
            outcome="failure",
            username=username or None,
            details={"reason": "password_mismatch"},
        )
        return (
            render_template(
                "login.html",
                error="Passwords do not match.",
                registration_open=True,
            ),
            400,
        )

    created, message = STORE.create_user(username, password)
    if not created:
        _record_audit_event(
            "auth.register.failed",
            outcome="failure",
            username=username or None,
            details={"reason": message},
        )
        return (
            render_template(
                "login.html",
                error=message,
                registration_open=True,
            ),
            400,
        )

    user = STORE.authenticate_user(username, password)
    if not user:
        _record_audit_event(
            "auth.register.failed",
            outcome="failure",
            username=username or None,
            details={"reason": "authenticate_after_create_failed"},
        )
        return (
            render_template(
                "login.html",
                error="Registration succeeded but login failed. Please try logging in.",
                registration_open=_registration_open(),
            ),
            500,
        )

    _set_authenticated_session(user)
    _record_audit_event(
        "auth.register.success",
        outcome="success",
        actor_user_id=int(user["id"]),
        target_user_id=int(user["id"]),
        username=str(user["username"]),
    )
    return redirect(url_for("index"))


@app.route("/logout", methods=["POST"])
@login_required
def logout_action():
    user = _current_user()
    if user is not None:
        _record_audit_event(
            "auth.logout",
            outcome="success",
            actor_user_id=int(user["id"]),
            target_user_id=int(user["id"]),
            username=str(user["username"]),
        )
    session.clear()
    return redirect(url_for("login_page"))


def _render_account_page(error: str | None = None, success: str | None = None, status_code: int = 200):
    user = _current_user()
    if user is None:
        return _auth_required_response()
    return (
        render_template(
            "account.html",
            username=str(user["username"]),
            is_admin=bool(user.get("is_admin")),
            error=error,
            success=success,
        ),
        status_code,
    )


@app.route("/account", methods=["GET"])
@login_required
def account_page():
    return _render_account_page()


@app.route("/account/password", methods=["POST"])
@login_required
def change_password_action():
    user = _current_user()
    if user is None:
        return _auth_required_response()

    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not current_password:
        return _render_account_page(error="Current password is required.", status_code=400)
    if new_password != confirm_password:
        return _render_account_page(error="New passwords do not match.", status_code=400)

    changed, message = STORE.change_password(int(user["id"]), current_password, new_password)
    if not changed:
        _record_audit_event(
            "auth.password_change.failed",
            outcome="failure",
            actor_user_id=int(user["id"]),
            target_user_id=int(user["id"]),
            username=str(user["username"]),
            details={"reason": message},
        )
        return _render_account_page(error=message, status_code=400)

    _record_audit_event(
        "auth.password_change.success",
        outcome="success",
        actor_user_id=int(user["id"]),
        target_user_id=int(user["id"]),
        username=str(user["username"]),
    )
    session.clear()
    return render_template(
        "login.html",
        error="Password updated successfully. Please sign in again.",
        registration_open=_registration_open(),
    )


@app.route("/account/delete", methods=["POST"])
@login_required
def delete_account_action():
    user = _current_user()
    if user is None:
        return _auth_required_response()

    current_password = request.form.get("delete_current_password", "")
    confirmation = request.form.get("delete_confirmation", "").strip().upper()

    if not current_password:
        return _render_account_page(error="Current password is required to delete account.", status_code=400)
    if confirmation != "DELETE":
        return _render_account_page(error='Type "DELETE" to confirm account deletion.', status_code=400)

    deleted, message = STORE.delete_own_account(int(user["id"]), current_password)
    if not deleted:
        _record_audit_event(
            "auth.account_delete.failed",
            outcome="failure",
            actor_user_id=int(user["id"]),
            target_user_id=int(user["id"]),
            username=str(user["username"]),
            details={"reason": message},
        )
        return _render_account_page(error=message, status_code=400)

    _record_audit_event(
        "auth.account_delete.success",
        outcome="success",
        actor_user_id=int(user["id"]),
        target_user_id=int(user["id"]),
        username=str(user["username"]),
    )
    session.clear()
    return render_template(
        "login.html",
        error="Account deleted.",
        registration_open=_registration_open(),
    )


@app.route("/admin/users", methods=["GET"])
@admin_required
def admin_users_page():
    user = _current_user()
    if user is None:
        return _auth_required_response()

    return render_template(
        "admin_users.html",
        username=str(user["username"]),
        current_user_id=int(user["id"]),
        users=STORE.list_users(),
        audit_events=STORE.list_audit_events(limit=100),
        error=request.args.get("error", "").strip() or None,
        success=request.args.get("success", "").strip() or None,
    )


@app.route("/admin/users/<int:target_user_id>/<action>", methods=["POST"])
@admin_required
def admin_user_action(target_user_id: int, action: str):
    user = _current_user()
    if user is None:
        return _auth_required_response()

    actor_user_id = int(user["id"])
    action_clean = action.strip().lower()

    if action_clean == "disable":
        ok, message = STORE.set_user_active(actor_user_id, target_user_id, False)
        success_message = "User disabled."
        event_type = "admin.user.disable"
    elif action_clean == "enable":
        ok, message = STORE.set_user_active(actor_user_id, target_user_id, True)
        success_message = "User enabled."
        event_type = "admin.user.enable"
    elif action_clean == "delete":
        ok, message = STORE.delete_user(actor_user_id, target_user_id)
        success_message = "User deleted."
        event_type = "admin.user.delete"
    else:
        abort(404)

    if ok:
        _record_audit_event(
            event_type,
            outcome="success",
            actor_user_id=actor_user_id,
            target_user_id=target_user_id,
            details={"action": action_clean},
        )
        return redirect(url_for("admin_users_page", success=success_message))
    _record_audit_event(
        event_type,
        outcome="failure",
        actor_user_id=actor_user_id,
        target_user_id=target_user_id,
        details={"action": action_clean, "reason": message},
    )
    return redirect(url_for("admin_users_page", error=message))


@app.route("/api/credentials", methods=["GET"])
@login_required
def credential_status():
    user = _current_user()
    if user is None:
        return jsonify({"error": "Authentication required."}), 401
    return jsonify(STORE.get_status(int(user["id"])))


@app.route("/api/credentials/<provider>", methods=["DELETE"])
@login_required
def clear_credentials(provider: str):
    if provider not in {"garmin", "omron"}:
        return jsonify({"error": "Unknown provider."}), 404

    user = _current_user()
    if user is None:
        return jsonify({"error": "Authentication required."}), 401

    try:
        STORE.clear_provider(int(user["id"]), provider)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify({"message": f"Cleared saved {provider} credentials."})

def sync_to_garmin(
    readings: list[dict[str, int | datetime]],
    email: str,
    password: str,
    is_cn: bool,
) -> int:
    if not email or not password:
        raise ValueError('Garmin credentials are required.')

    gc = Garmin(email=email, password=password, is_cn=is_cn, prompt_mfa=None)
    logged_in = gc.login()

    if not logged_in:
        raise ValueError('Garmin login failed. Please check your credentials.')

    local_tz = datetime.now().astimezone().tzinfo
    existing = get_existing_bp_timestamps(gc, readings, local_tz)

    added = 0
    for r in readings:
        dt = r['timestamp']
        if not isinstance(dt, datetime):
            continue
        dt_local = dt.replace(tzinfo=local_tz) if dt.tzinfo is None else dt
        dt_utc = dt_local.astimezone(timezone.utc)
        lookup = int(dt_utc.timestamp())

        if lookup in existing:
            continue

        pulse_value = r['hr'] if r['hr'] and r['hr'] > 0 else None
        try:
            gc.set_blood_pressure(
                timestamp=dt_local.isoformat(timespec='seconds'),
                systolic=r['systolic'],
                diastolic=r['diastolic'],
                pulse=pulse_value,
                notes=None,
            )
        except Exception as exc:  # pylint: disable=broad-except
            raise ValueError(
                f"Garmin upload failed for reading at {dt_local.isoformat(timespec='seconds')}."
            ) from exc
        added += 1
    return added


def login_omron(
    email: str,
    password: str,
    country: str,
) -> tuple[OmronClient, str]:
    if not country:
        raise ValueError('OMRON country code is required.')

    if not email or not password:
        raise ValueError('OMRON credentials are required.')

    oc = OmronClient(country)
    refresh_token = None

    refresh_token = oc.login(email, password)

    if not refresh_token:
        raise ValueError('OMRON login failed. Please check your credentials.')

    return oc, refresh_token


def load_omron_measurements(
    email: str,
    password: str,
    country: str,
    days: int,
) -> list[BPMeasurement]:
    oc, _ = login_omron(email, password, country)

    devices = oc.get_registered_devices(days=None) or []
    bpm_devices = [dev for dev in devices if dev.category == DeviceCategory.BPM]
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    start_ms = int((datetime.now(timezone.utc).timestamp() - (days * 86400)) * 1000)

    if bpm_devices:
        device = bpm_devices[0]
        measurements = oc.get_measurements(device, searchDateFrom=start_ms, searchDateTo=now_ms)
        return [m for m in measurements if isinstance(m, BPMeasurement)]

    # Fallback: try API v2 direct BP sync if device listing returns empty
    active_client = getattr(oc, "_active_client", None)
    if active_client and hasattr(active_client, "get_bp_measurements"):
        raw = active_client.get_bp_measurements(lastSyncedTime=start_ms)
        results: list[BPMeasurement] = []
        for item in raw or []:
            try:
                results.append(
                    BPMeasurement(
                        systolic=int(item["systolic"]),
                        diastolic=int(item["diastolic"]),
                        pulse=int(item["pulse"]),
                        measurementDate=int(item["measurementDate"]),
                        timeZone=pytz.FixedOffset(int(item["timeZone"]) // 60),
                        irregularHB=int(item.get("irregularHB", 0)) != 0,
                        movementDetect=int(item.get("movementDetect", 0)) != 0,
                        cuffWrapDetect=int(item.get("cuffWrapDetect", 0)) != 0,
                        notes=item.get("notes", ""),
                    )
                )
            except Exception:
                continue
        if results:
            return results

    raise ValueError('No OMRON blood pressure devices found on your account.')


def get_existing_bp_timestamps(gc: Garmin, readings: list[dict[str, int | datetime]], local_tz) -> set[int]:
    dates: list[datetime] = []
    for r in readings:
        dt = r['timestamp']
        if isinstance(dt, datetime):
            dates.append(dt)

    if not dates:
        return set()

    min_dt = min(dates)
    max_dt = max(dates)
    min_local = min_dt.replace(tzinfo=local_tz) if min_dt.tzinfo is None else min_dt
    max_local = max_dt.replace(tzinfo=local_tz) if max_dt.tzinfo is None else max_dt

    startdate = min_local.date().isoformat()
    enddate = max_local.date().isoformat()

    gc_data = gc.get_blood_pressure(startdate=startdate, enddate=enddate)
    summaries = gc_data.get('measurementSummaries', []) if isinstance(gc_data, dict) else []

    existing: set[int] = set()
    for summary in summaries:
        for metric in summary.get('measurements', []):
            timestamp_gmt = metric.get('measurementTimestampGMT')
            if not timestamp_gmt:
                continue
            try:
                dt_utc = datetime.fromisoformat(f"{timestamp_gmt}Z")
            except ValueError:
                continue
            existing.add(int(dt_utc.timestamp()))

    return existing


@app.route('/', methods=['GET'])
@login_required
def index():
    user = _current_user()
    if user is None:
        return redirect(url_for("login_page"))
    return render_template(
        'index.html',
        username=str(user["username"]),
        is_admin=bool(user.get("is_admin")),
        credential_status=STORE.get_status(int(user["id"])),
    )


@app.route("/sync-history", methods=["GET"])
@login_required
def sync_history_page():
    user = _current_user()
    if user is None:
        return _auth_required_response()

    user_id = int(user["id"])
    return render_template(
        "sync_history.html",
        username=str(user["username"]),
        is_admin=bool(user.get("is_admin")),
        history=STORE.list_sync_history(user_id, limit=100),
        counts=STORE.get_sync_history_counts(user_id),
        error=request.args.get("error", "").strip() or None,
        success=request.args.get("success", "").strip() or None,
    )


def _sync_omron_core(
    user_id: int,
    form_data,
    trigger_source: str = "manual",
    retry_of_id: int | None = None,
) -> tuple[dict[str, object], int]:
    saved = STORE.get_credentials_for_sync(user_id)
    save_garmin = str(form_data.get("save_garmin", "") or "").strip() == "on"
    save_omron = str(form_data.get("save_omron", "") or "").strip() == "on"

    history_id = STORE.start_sync_history(
        user_id=user_id,
        trigger_source=trigger_source,
        retry_of_id=retry_of_id,
        save_garmin_requested=save_garmin,
        save_omron_requested=save_omron,
    )

    def fail(
        message: str,
        status_code: int,
        status: str = "failed",
        readings_found: int | None = None,
        readings_uploaded: int | None = None,
    ) -> tuple[dict[str, object], int]:
        STORE.finish_sync_history(
            history_id=history_id,
            status=status,
            readings_found=readings_found,
            readings_uploaded=readings_uploaded,
            error_message=message,
            message=None,
        )
        _record_audit_event(
            "sync.run.failed" if status == "failed" else "sync.run.partial",
            outcome="failure" if status == "failed" else "warning",
            actor_user_id=user_id,
            target_user_id=user_id,
            details={
                "source": trigger_source,
                "history_id": history_id,
                "retry_of_id": retry_of_id,
                "status": status,
                "http_status": status_code,
                "reason": message,
            },
        )
        return {"error": message, "history_id": history_id}, status_code

    email = str(form_data.get("omron_email", "") or "").strip() or saved.get("omron_email", "")
    password = str(form_data.get("omron_password", "") or "") or saved.get("omron_password", "")
    country = (
        str(form_data.get("omron_country", "") or "").strip().upper()
        or saved.get("omron_country", "").upper()
    )
    days = 30

    try:
        measurements = load_omron_measurements(email, password, country, days)
    except ValueError as exc:
        return fail(str(exc), 400)
    except Exception:  # pylint: disable=broad-except
        app.logger.exception('OMRON sync failed unexpectedly.')
        return fail('OMRON sync failed due to an internal server error.', 500)

    readings: list[dict[str, int | datetime]] = []
    for bpm in measurements:
        dt = datetime.fromtimestamp(bpm.measurementDate / 1000, tz=bpm.timeZone)
        readings.append(
            {
                'timestamp': dt,
                'systolic': bpm.systolic,
                'diastolic': bpm.diastolic,
                'hr': bpm.pulse,
            }
        )

    if not readings:
        return fail('No OMRON readings found for the selected range.', 400, readings_found=0, readings_uploaded=0)

    garmin_email = str(form_data.get('garmin_email', '') or '').strip() or saved.get("garmin_email", "")
    garmin_password = str(form_data.get('garmin_password', '') or '') or saved.get("garmin_password", "")
    if not (garmin_email and garmin_password):
        return fail(
            'Garmin credentials required for sync.',
            400,
            readings_found=len(readings),
            readings_uploaded=0,
        )

    try:
        added = sync_to_garmin(readings, garmin_email, garmin_password, False)
    except ValueError as exc:
        return fail(str(exc), 400, readings_found=len(readings), readings_uploaded=0)
    except Exception:  # pylint: disable=broad-except
        app.logger.exception('Garmin sync failed unexpectedly.')
        return fail(
            'Garmin sync failed due to an internal server error.',
            500,
            readings_found=len(readings),
            readings_uploaded=0,
        )

    try:
        if save_garmin and garmin_email and garmin_password:
            STORE.save_garmin_credentials(user_id, garmin_email, garmin_password)
        if save_omron and email and password and country:
            STORE.save_omron_credentials(user_id, email, password, country)
    except Exception:  # pylint: disable=broad-except
        app.logger.exception("Saving encrypted credentials failed unexpectedly.")
        return fail(
            'Sync succeeded but saving credentials failed.',
            500,
            status="partial",
            readings_found=len(readings),
            readings_uploaded=added,
        )

    message = f'Successfully synced {added} readings from OMRON to Garmin Connect.'
    STORE.finish_sync_history(
        history_id=history_id,
        status="success",
        readings_found=len(readings),
        readings_uploaded=added,
        message=message,
        error_message=None,
    )
    _record_audit_event(
        "sync.run.success",
        outcome="success",
        actor_user_id=user_id,
        target_user_id=user_id,
        details={
            "source": trigger_source,
            "history_id": history_id,
            "retry_of_id": retry_of_id,
            "readings_found": len(readings),
            "readings_uploaded": added,
        },
    )
    return (
        {
            'message': message,
            'saved': {
                'garmin': save_garmin,
                'omron': save_omron,
            },
            'history_id': history_id,
        },
        200,
    )


@app.route('/sync-omron', methods=['POST'])
@login_required
def sync_omron():
    user = _current_user()
    if user is None:
        return jsonify({"error": "Authentication required."}), 401
    user_id = int(user["id"])
    payload, status_code = _sync_omron_core(user_id, request.form, trigger_source="manual")
    return jsonify(payload), status_code


@app.route("/sync-history/<int:history_id>/retry", methods=["POST"])
@login_required
def retry_sync_history_action(history_id: int):
    user = _current_user()
    if user is None:
        return _auth_required_response()

    user_id = int(user["id"])
    entry = STORE.get_sync_history_entry(user_id, history_id)
    if not entry:
        abort(404)

    retry_form: dict[str, str] = {}
    if bool(entry.get("save_garmin_requested")):
        retry_form["save_garmin"] = "on"
    if bool(entry.get("save_omron_requested")):
        retry_form["save_omron"] = "on"

    payload, status_code = _sync_omron_core(
        user_id,
        retry_form,
        trigger_source="retry",
        retry_of_id=history_id,
    )

    if status_code == 200:
        message = str(payload.get("message") or "Retry sync completed.")[:240]
        return redirect(url_for("sync_history_page", success=message))
    error_message = str(payload.get("error") or "Retry sync failed.")[:240]
    return redirect(url_for("sync_history_page", error=error_message))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=5000)
    args = parser.parse_args()
    serve(app, host=args.host, port=args.port)
