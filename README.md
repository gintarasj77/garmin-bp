# Omron to Garmin Sync

Simple Flask web app to sync OMRON Connect blood pressure readings directly to Garmin Connect.

## Requirements

- Python 3.11+ (this project uses `enum.StrEnum`)

## Features

- Sync OMRON Connect blood pressure readings to Garmin Connect
- No server-side credential storage
- Passwords are never written to browser storage
- Optional browser storage only for Garmin email and OMRON email/country
- No data storage on the server; processing is in memory only
- No third-party analytics/tracking script in the app page

## Local run

1. Create a virtual environment and install dependencies:
   - `python -m venv .venv`
   - `.venv\Scripts\python -m pip install -r requirements.txt`
2. Start the app (Waitress, no dev-server warning):
   - `.venv\Scripts\python app.py`
3. Open http://127.0.0.1:5000

By default, the app binds to `127.0.0.1`. For LAN/public exposure, pass an explicit host:
- `.venv\Scripts\python app.py --host 0.0.0.0 --port 5000`

## Render deploy

1. Push this folder to a Git repository.
2. In Render, create a **Web Service** from the repo.
3. Use:
   - Build command: `pip install -r requirements.txt`
   - Start command: `python app.py --host 0.0.0.0 --port $PORT`

The app uses a `Procfile` so Render can autodetect the start command.

## Usage

1. Enter your OMRON Connect credentials and country code.
2. Enter your Garmin Connect credentials.
3. Click "Sync from OMRON to Garmin".
4. Your blood pressure data appears in Garmin Connect under **Health Stats > Blood Pressure**.

## Credential handling

This app does **not** store credentials on the server.

If you choose to save values in the browser, only these are stored in `localStorage`:
- Garmin email
- OMRON email
- OMRON country code

Passwords are not stored in `localStorage`; they are sent only for the current sync request.
