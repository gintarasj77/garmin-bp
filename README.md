# Omron CSV to Garmin FIT

Simple Flask web app to convert Omron CSV exports into a Garmin-importable FIT file.

## Features

- Convert Omron blood pressure CSV files to Garmin FIT format
- Download FIT file and import into Garmin Connect manually
- No data storage - all processing happens in memory
- Supports flexible date/time formats in CSV

## Local run

1. Create a virtual environment and install dependencies:
   - `python -m venv .venv`
   - `.venv\Scripts\python -m pip install -r requirements.txt`
2. Start the app:
   - `.venv\Scripts\python app.py`
3. Open http://localhost:5000

## Render deploy

1. Push this folder to a Git repository.
2. In Render, create a **Web Service** from the repo.
3. Use:
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn app:app`

The app uses a `Procfile` so Render can autodetect the start command.

## Usage

1. Export your blood pressure data from Omron as CSV
2. Upload the CSV file to the app
3. Click "Convert to FIT File" to generate the Garmin FIT file
4. Open [Garmin Connect Import](https://connect.garmin.com/modern/import-data)
5. Upload the downloaded FIT file
6. Your blood pressure data will appear in Garmin Connect under **Health Stats > Blood Pressure**

## CSV Format

The app automatically detects common date/time column formats. Your CSV should include:
- **Blood pressure readings**: `Systolic` and `Diastolic` columns (required)
- **Date/Time**: Either a single `DateTime` column OR separate `Date` + `Time` columns
- **Optional**: `Heart Rate` or `Pulse` column
