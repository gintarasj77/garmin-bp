import argparse
import csv
import io
import re
from datetime import datetime

from flask import Flask, Response, jsonify, render_template, request
from withings_sync.fit import FitEncoderBloodPressure

app = Flask(__name__)

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


def wants_json() -> bool:
    return 'application/json' in request.headers.get('Accept', '').lower()


def error_response(message: str, status: int = 400):
    if wants_json():
        return jsonify(error=message), status
    return render_template('index.html', error=message), status


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


@app.route('/convert', methods=['POST'])
def convert():
    file = request.files.get('csv_file')
    if not file or file.filename == '':
        return error_response('Please select a CSV file.')

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
    response = Response(fit_bytes, mimetype='application/octet-stream')
    response.headers['Content-Disposition'] = 'attachment; filename="blood_pressure_withings.fit"'
    response.headers['Content-Length'] = str(len(fit_bytes))
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=5000)
    args = parser.parse_args()
    app.run(host=args.host, port=args.port)
