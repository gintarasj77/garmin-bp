# Omron CSV to Garmin FIT

Simple Flask web app to convert Omron CSV exports into a Garmin-importable FIT file.

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
