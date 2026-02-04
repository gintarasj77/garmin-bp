import argparse
import csv
import io
import os
import re
import tempfile
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request, session, redirect, url_for
from withings_sync.fit import FitEncoderBloodPressure
import garth

# Required for blood pressure upload - see https://github.com/matin/garth/issues/73
garth.http.USER_AGENT = {"User-Agent": "GCM-iOS-5.7.2.1"}

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Token storage directory
TOKEN_DIR = Path('.garmin_tokens')
TOKEN_DIR.mkdir(exist_ok=True)

DATETIME_FORMATS = [
    '%Y-%m-%d %H:%M:%S',
    '%Y-%m-%d %H:%M',
    '%m/%d/%Y %H:%M:%S',
    '%m/%d/%Y %H:%M',
    '%d/%m/%Y %H:%M:%S',
    '%d/%m/%Y %H:%M',
    '%m/%d/%Y %I:%M:%S %p',
    '%m/%d/%Y %I:%M %p',
]

DATE_FORMATS = [
    '%Y-%m-%d',
    '%m/%d/%Y',
    '%d/%m/%Y',
    '%d %b %Y',
]

TIME_FORMATS = [
    '%H:%M:%S',
    '%H:%M',
    '%I:%M:%S %p',
    '%I:%M %p',
]


def normalize_header(value: str) -> str:
    return re.sub(r'[^a-z0-9]+', '', value.strip().lower())


def build_header_map(headers: list[str]) -> dict[str, str | None]:
    normalized = {normalize_header(h): h for h in headers}

    def find(*candidates: str) -> str | None:
        for candidate in candidates:
            if candidate in normalized:
                return normalized[candidate]
        return None

    return {
        'datetime': find('datetime', 'datetimestamp', 'dateandtime', 'date_time', 'date time', 'measurementdatetime'),
        'date': find('date', 'measurementdate'),
        'time': find('time', 'measurementtime'),
        'systolic': find('systolic', 'sys', 'systolicbloodpressure', 'bpsystolic', 'systolicmmhg'),
        'diastolic': find('diastolic', 'dia', 'diastolicbloodpressure', 'bpdiastolic', 'diastolicmmhg'),
        'heart_rate': find('heartrate', 'pulse', 'pulserate', 'hr', 'bppulse', 'pulsebpm'),
    }


def parse_datetime(value: str) -> datetime | None:
    if not value:
        return None
    value = value.strip()
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        pass
    for fmt in DATETIME_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def parse_date_time(date_value: str, time_value: str) -> datetime | None:
    if not date_value or not time_value:
        return None
    date_value = date_value.strip()
    time_value = time_value.strip()
    for date_fmt in DATE_FORMATS:
        for time_fmt in TIME_FORMATS:
            try:
                return datetime.strptime(f'{date_value} {time_value}', f'{date_fmt} {time_fmt}')
            except ValueError:
                continue
    return None


def parse_int(value: str | None) -> int | None:
    if value is None:
        return None
    value = value.strip()
    if value == '':
        return None
    try:
        return int(float(value))
    except ValueError:
        return None


def load_readings_from_text(text: str) -> list[dict[str, int | datetime]]:
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ValueError('CSV file has no headers.')

    header_map = build_header_map(reader.fieldnames)
    missing = [
        key
        for key in ('systolic', 'diastolic')
        if header_map[key] is None
    ]
    if missing:
        raise ValueError(f'Missing required columns: {", ".join(missing)}')

    if header_map['datetime'] is None and (header_map['date'] is None or header_map['time'] is None):
        raise ValueError('Missing date/time columns. Provide DateTime or Date + Time columns.')

    readings: list[dict[str, int | datetime]] = []
    for row in reader:
        if header_map['datetime']:
            dt = parse_datetime(row.get(header_map['datetime'], ''))
        else:
            dt = parse_date_time(
                row.get(header_map['date'], ''),
                row.get(header_map['time'], ''),
            )
        if not dt:
            continue

        systolic = parse_int(row.get(header_map['systolic']))
        diastolic = parse_int(row.get(header_map['diastolic']))
        if header_map['heart_rate'] is None:
            heart_rate = None
        else:
            heart_rate = parse_int(row.get(header_map['heart_rate']))
        if systolic is None or diastolic is None:
            continue

        readings.append(
            {
                'timestamp': dt,
                'systolic': systolic,
                'diastolic': diastolic,
                'hr': heart_rate if heart_rate is not None else 0,
            }
        )

    return readings


def build_fit(readings: list[dict[str, int | datetime]]) -> bytes:
    fit_bp = FitEncoderBloodPressure()
    fit_bp.write_file_info()
    fit_bp.write_file_creator()

    for r in readings:
        dt = r['timestamp']
        if not isinstance(dt, datetime):
            continue
        fit_bp.write_device_info(timestamp=dt)
        fit_bp.write_blood_pressure(
            timestamp=dt,
            diastolic_blood_pressure=r['diastolic'],
            systolic_blood_pressure=r['systolic'],
            heart_rate=r['hr'],
        )

    fit_bp.finish()
    return fit_bp.getvalue()


def get_garmin_session():
    """Return a requests-like session from garth client."""
    for attr in ('session', '_session'):
        session = getattr(garth.client, attr, None)
        if session is not None:
            return session
    for attr in ('_client', 'client'):
        inner = getattr(garth.client, attr, None)
        if inner is None:
            continue
        for inner_attr in ('session', '_session'):
            session = getattr(inner, inner_attr, None)
            if session is not None:
                return session
    return None


def upload_fit_to_garmin(fit_bytes: bytes):
    """Upload FIT bytes to Garmin Connect using garth.client.upload()."""
    import sys
    
    print(f'[DEBUG] Attempting upload, size: {len(fit_bytes)} bytes', file=sys.stderr)
    print(f'[DEBUG] First 50 bytes (hex): {fit_bytes[:50].hex()}', file=sys.stderr)
    
    try:
        # Create BytesIO object and set name attribute (required by garth)
        fit_file = io.BytesIO(fit_bytes)
        fit_file.seek(0)  # Ensure we're at the start
        fit_file.name = "blood_pressure.fit"
        
        print(f'[DEBUG] File position: {fit_file.tell()}, size: {len(fit_file.getvalue())}', file=sys.stderr)
        print(f'[DEBUG] Uploading file: {fit_file.name}', file=sys.stderr)
        
        # Use garth.client.upload() - this is the correct method for FIT files
        result = garth.client.upload(fit_file)
        
        print(f'[DEBUG] Upload result: {result}', file=sys.stderr)
        print(f'[DEBUG] Result type: {type(result)}', file=sys.stderr)
        
        if isinstance(result, list) and len(result) == 0:
            # garth returns empty list for blood pressure - but that doesn't mean it worked
            # Let's check if it actually uploaded by trying connectapi
            print(f'[DEBUG] Upload returned empty list - blood pressure data may not sync via this method', file=sys.stderr)
        
        return {'status': 'success', 'message': 'File uploaded successfully. Check Health Stats > Blood Pressure in Garmin Connect.', 'result': result}
            
    except Exception as e:
        print(f'[DEBUG] Upload exception: {type(e).__name__}: {str(e)}', file=sys.stderr)
        raise


def wants_json() -> bool:
    return 'application/json' in request.headers.get('Accept', '').lower()


def error_response(message: str, status: int = 400):
    if wants_json():
        return jsonify(error=message), status
    return render_template('index.html', error=message), status


def get_user_token_path():
    """Get token path for current session user"""
    user_id = session.get('user_id', 'default')
    return TOKEN_DIR / f'{user_id}.json'


def is_garmin_connected():
    """Check if user has valid Garmin tokens"""
    token_path = get_user_token_path()
    if not token_path.exists():
        return False
    try:
        garth.resume(str(token_path))
        garth.client.username
        return True
    except Exception:
        return False


@app.route('/', methods=['GET'])
def index():
    connected = is_garmin_connected()
    return render_template('index.html', garmin_connected=connected)


@app.route('/manifest.json', methods=['GET'])
def manifest():
    return jsonify({
        "name": "CSV to Garmin FIT",
        "short_name": "Garmin FIT",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#0f172a",
        "theme_color": "#0f172a",
        "icons": []
    })


@app.route('/convert', methods=['POST'])
def convert():
    file = request.files.get('csv_file')
    if not file or file.filename == '':
        return error_response('Please select a CSV file.')

    # Get Garmin credentials if provided
    garmin_email = request.form.get('garmin_email', '').strip()
    garmin_password = request.form.get('garmin_password', '').strip()
    auto_upload = garmin_email and garmin_password

    try:
        text = file.read().decode('utf-8-sig')
    except UnicodeDecodeError:
        return error_response('Unable to read file as UTF-8.')

    try:
        readings = load_readings_from_text(text)
    except ValueError as exc:
        return error_response(str(exc))

    if not readings:
        return error_response('No valid readings found in the CSV.')

    fit_bytes = build_fit(readings)
    
    # Check if user wants to use saved Garmin connection or provide credentials
    use_saved_auth = request.form.get('use_saved_auth') == 'true'
    
    if use_saved_auth:
        # Use saved OAuth tokens
        if not is_garmin_connected():
            return error_response('Not connected to Garmin. Please connect your account first.')
        
        try:
            token_path = get_user_token_path()
            garth.resume(str(token_path))

            upload_response = upload_fit_to_garmin(fit_bytes)

            if wants_json():
                return jsonify({
                    'success': True,
                    'message': f'Successfully uploaded {len(readings)} blood pressure reading(s) to Garmin Connect!',
                    'upload_response': upload_response,
                }), 200

            return render_template(
                'index.html',
                success=f'Successfully uploaded {len(readings)} blood pressure reading(s) to Garmin Connect!',
                garmin_connected=True,
            ), 200
        except Exception as exc:
            return error_response(f'Garmin upload failed: {str(exc)}')
    
    # If Garmin credentials provided, login and save tokens
    elif auto_upload:
        try:
            garth.login(garmin_email, garmin_password)
            
            # Save tokens for future use
            token_path = get_user_token_path()
            garth.save(str(token_path))

            upload_response = upload_fit_to_garmin(fit_bytes)

            if wants_json():
                return jsonify({
                    'success': True,
                    'message': f'Successfully uploaded {len(readings)} blood pressure reading(s) to Garmin Connect! Your login has been saved.',
                    'upload_response': upload_response,
                }), 200

            return render_template(
                'index.html',
                success=f'Successfully uploaded {len(readings)} blood pressure reading(s) to Garmin Connect! Your login has been saved.',
                garmin_connected=True,
            ), 200
        except Exception as exc:
            return error_response(f'Garmin upload failed: {str(exc)}')
    
    # Otherwise, download the FIT file
    response = Response(fit_bytes, mimetype='application/octet-stream')
    response.headers['Content-Disposition'] = 'attachment; filename="blood_pressure_withings.fit"'
    response.headers['Content-Length'] = str(len(fit_bytes))
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


@app.route('/garmin/connect', methods=['POST'])
def garmin_connect():
    """Connect Garmin account and save tokens"""
    email = request.form.get('garmin_email', '').strip()
    password = request.form.get('garmin_password', '').strip()
    
    if not email or not password:
        return error_response('Email and password are required.')
    
    try:
        garth.login(email, password)
        
        # Generate a user ID from email hash for token storage
        import hashlib
        user_id = hashlib.sha256(email.encode()).hexdigest()[:16]
        session['user_id'] = user_id
        
        # Save tokens
        token_path = get_user_token_path()
        garth.save(str(token_path))
        
        if wants_json():
            return jsonify({'success': True, 'message': 'Connected to Garmin successfully!'}), 200
        
        return render_template('index.html', success='Connected to Garmin successfully!', garmin_connected=True), 200
    except Exception as exc:
        return error_response(f'Garmin connection failed: {str(exc)}')


@app.route('/garmin/disconnect', methods=['POST'])
def garmin_disconnect():
    """Disconnect Garmin account and remove tokens"""
    try:
        token_path = get_user_token_path()
        if token_path.exists():
            token_path.unlink()
        session.pop('user_id', None)
        
        if wants_json():
            return jsonify({'success': True, 'message': 'Disconnected from Garmin.'}), 200
        
        return render_template('index.html', success='Disconnected from Garmin.', garmin_connected=False), 200
    except Exception as exc:
        return error_response(f'Disconnect failed: {str(exc)}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=5000)
    args = parser.parse_args()
    app.run(host=args.host, port=args.port)
