import argparse
import base64
import hashlib
import os
import secrets

import pytz
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for
from garminconnect import Garmin
from waitress import serve

from omronconnect import BPMeasurement, DeviceCategory, OmronClient
from secure_store import SecureStore

app = Flask(__name__)

_secret_from_env = os.getenv("FLASK_SECRET_KEY", "").strip()
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
    configured = os.getenv("CREDENTIALS_ENCRYPTION_KEY", "").strip()
    if configured:
        return configured
    digest = hashlib.sha256(f"{app.secret_key}|credential-vault".encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii")


STORE = SecureStore(
    db_path=os.getenv("APP_DB_PATH", str(Path(__file__).resolve().parent / "data" / "app.db")),
    encryption_key=_resolve_encryption_key(),
)

if not _secret_from_env:
    app.logger.warning("FLASK_SECRET_KEY is not set. Generated an ephemeral key for this process.")

if not os.getenv("CREDENTIALS_ENCRYPTION_KEY", "").strip():
    app.logger.warning("CREDENTIALS_ENCRYPTION_KEY is not set. Deriving encryption key from FLASK_SECRET_KEY.")


def _current_user_id() -> int | None:
    value = session.get("user_id")
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _registration_open() -> bool:
    return STORE.user_count() == 0 or os.getenv("ALLOW_REGISTRATION", "0") == "1"


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
    }


@app.before_request
def _csrf_protect():
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return

    expected = session.get("csrf_token")
    provided = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    if not expected or not provided or not secrets.compare_digest(str(expected), str(provided)):
        abort(403)


def login_required(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        if _current_user_id() is not None:
            return func(*args, **kwargs)

        accept_header = request.headers.get("Accept", "").lower()
        wants_json = request.path.startswith("/api/") or "application/json" in accept_header
        if wants_json:
            return jsonify({"error": "Authentication required."}), 401
        return redirect(url_for("login_page"))

    return wrapped


@app.route("/login", methods=["GET"])
def login_page():
    if _current_user_id() is not None:
        return redirect(url_for("index"))
    return render_template("login.html", error=None, registration_open=_registration_open())


@app.route("/login", methods=["POST"])
def login_action():
    if _current_user_id() is not None:
        return redirect(url_for("index"))

    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")
    user = STORE.authenticate_user(username, password)
    if not user:
        return (
            render_template(
                "login.html",
                error="Invalid username or password.",
                registration_open=_registration_open(),
            ),
            401,
        )

    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["csrf_token"] = secrets.token_urlsafe(32)
    session.permanent = True
    return redirect(url_for("index"))


@app.route("/register", methods=["POST"])
def register_action():
    if not _registration_open():
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
        return (
            render_template(
                "login.html",
                error="Username is required.",
                registration_open=True,
            ),
            400,
        )

    if password != confirm:
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
        return (
            render_template(
                "login.html",
                error="Registration succeeded but login failed. Please try logging in.",
                registration_open=_registration_open(),
            ),
            500,
        )

    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["csrf_token"] = secrets.token_urlsafe(32)
    session.permanent = True
    return redirect(url_for("index"))


@app.route("/logout", methods=["POST"])
@login_required
def logout_action():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/api/credentials", methods=["GET"])
@login_required
def credential_status():
    user_id = _current_user_id()
    if user_id is None:
        return jsonify({"error": "Authentication required."}), 401
    return jsonify(STORE.get_status(user_id))


@app.route("/api/credentials/<provider>", methods=["DELETE"])
@login_required
def clear_credentials(provider: str):
    if provider not in {"garmin", "omron"}:
        return jsonify({"error": "Unknown provider."}), 404

    user_id = _current_user_id()
    if user_id is None:
        return jsonify({"error": "Authentication required."}), 401

    try:
        STORE.clear_provider(user_id, provider)
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
    user_id = _current_user_id()
    if user_id is None:
        return redirect(url_for("login_page"))
    return render_template(
        'index.html',
        username=session.get("username", ""),
        credential_status=STORE.get_status(user_id),
    )


@app.route('/sync-omron', methods=['POST'])
@login_required
def sync_omron():
    user_id = _current_user_id()
    if user_id is None:
        return jsonify({"error": "Authentication required."}), 401

    saved = STORE.get_credentials_for_sync(user_id)

    email = request.form.get('omron_email', '').strip() or saved.get("omron_email", "")
    password = request.form.get('omron_password', '') or saved.get("omron_password", "")
    country = request.form.get('omron_country', '').strip().upper() or saved.get("omron_country", "").upper()
    days = 30

    try:
        measurements = load_omron_measurements(email, password, country, days)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except Exception:  # pylint: disable=broad-except
        app.logger.exception('OMRON sync failed unexpectedly.')
        return jsonify({'error': 'OMRON sync failed due to an internal server error.'}), 500

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
        return jsonify({'error': 'No OMRON readings found for the selected range.'}), 400

    garmin_email = request.form.get('garmin_email', '').strip() or saved.get("garmin_email", "")
    garmin_password = request.form.get('garmin_password', '') or saved.get("garmin_password", "")
    if not (garmin_email and garmin_password):
        return jsonify({'error': 'Garmin credentials required for sync.'}), 400

    save_garmin = request.form.get('save_garmin') == 'on'
    save_omron = request.form.get('save_omron') == 'on'

    try:
        added = sync_to_garmin(readings, garmin_email, garmin_password, False)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except Exception:  # pylint: disable=broad-except
        app.logger.exception('Garmin sync failed unexpectedly.')
        return jsonify({'error': 'Garmin sync failed due to an internal server error.'}), 500

    try:
        if save_garmin and garmin_email and garmin_password:
            STORE.save_garmin_credentials(user_id, garmin_email, garmin_password)
        if save_omron and email and password and country:
            STORE.save_omron_credentials(user_id, email, password, country)
    except Exception:  # pylint: disable=broad-except
        app.logger.exception("Saving encrypted credentials failed unexpectedly.")
        return jsonify({'error': 'Sync succeeded but saving credentials failed.'}), 500

    return jsonify(
        {
            'message': f'Successfully synced {added} readings from OMRON to Garmin Connect.',
            'saved': {
                'garmin': save_garmin,
                'omron': save_omron,
            },
        }
    )

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=5000)
    args = parser.parse_args()
    serve(app, host=args.host, port=args.port)
