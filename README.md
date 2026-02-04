# Omron CSV to Garmin FIT

Simple Flask web app to convert Omron CSV exports into a Garmin-importable FIT file with optional automatic upload to Garmin Connect.

## Features

- Convert Omron blood pressure CSV files to Garmin FIT format
- **Auto-upload to Garmin Connect** - Enter your Garmin credentials to upload directly
- Download FIT file for manual import (leave credentials blank)
- No data storage - all processing happens in memory

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
   - Start command: `python app.py --host 0.0.0.0 --port $PORT`

The app uses a `Procfile` so Render can autodetect the start command.

## Usage

1. Upload your Omron CSV file
2. **Optional:** Enter your Garmin Connect email and password to auto-upload
3. Click "Convert & Upload"
   - If credentials provided: Data uploads directly to Garmin Connect
   - If blank: FIT file downloads for manual import
