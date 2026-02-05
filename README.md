# Omron to Garmin Sync

Simple Flask web app to sync OMRON Connect blood pressure readings directly to Garmin Connect.

## Features

- Sync OMRON Connect blood pressure readings to Garmin Connect
- No server-side credential storage (client-only local storage)
- No data storage - all processing happens in memory

## Local run

1. Create a virtual environment and install dependencies:
   - `python -m venv .venv`
   - `.venv\Scripts\python -m pip install -r requirements.txt`
2. Start the app (Waitress, no dev-server warning):
   - `.venv\Scripts\python app.py`
3. Open http://localhost:5000

## Render deploy

1. Push this folder to a Git repository.
2. In Render, create a **Web Service** from the repo.
3. Use:
   - Build command: `pip install -r requirements.txt`
   - Start command: `python app.py --host 0.0.0.0 --port $PORT`

The app uses a `Procfile` so Render can autodetect the start command.

## Usage

1. Enter your OMRON Connect credentials and country code
2. Enter your Garmin Connect credentials
3. Click “Sync from OMRON to Garmin”
4. Your blood pressure data will appear in Garmin Connect under **Health Stats > Blood Pressure**

### Client-only credential storage

This app does **not** store credentials on the server. If you choose to save them, they are stored
in your browser’s local storage on your device. The server receives credentials only for the current
request.

 
