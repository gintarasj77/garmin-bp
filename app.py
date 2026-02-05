import argparse
import os

import pytz
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template, request
from garminconnect import Garmin
from waitress import serve

from omronconnect import BPMeasurement, DeviceCategory, OmronClient

app = Flask(__name__)

def sync_to_garmin(
    readings: list[dict[str, int | datetime]],
    email: str,
    password: str,
    is_cn: bool,
) -> int:
    if not email or not password:
        raise ValueError('Garmin credentials are required for each sync in client-only mode.')

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
            raise ValueError(f"Garmin API error while uploading {dt_local.isoformat(timespec='seconds')}: {exc}") from exc
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
        raise ValueError('OMRON credentials are required for each sync in client-only mode.')

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
def index():
    return render_template('index.html')


@app.route('/sync-omron', methods=['POST'])
def sync_omron():
    email = request.form.get('omron_email', '').strip()
    password = request.form.get('omron_password', '')
    country = request.form.get('omron_country', '').strip().upper()
    days = 30

    try:
        measurements = load_omron_measurements(email, password, country, days)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except Exception as exc:  # pylint: disable=broad-except
        return jsonify({'error': f'OMRON sync failed: {exc}'}), 500

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

    garmin_email = request.form.get('garmin_email', '').strip()
    garmin_password = request.form.get('garmin_password', '')
    if not (garmin_email and garmin_password):
        return jsonify({'error': 'Garmin credentials required for sync.'}), 400

    try:
        added = sync_to_garmin(readings, garmin_email, garmin_password, False)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except Exception as exc:  # pylint: disable=broad-except
        return jsonify({'error': f'Garmin sync failed: {exc}'}), 500

    return jsonify({'message': f'Successfully synced {added} readings from OMRON to Garmin Connect.'})

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=5000)
    args = parser.parse_args()
    serve(app, host=args.host, port=args.port)
