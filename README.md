# Omron to Garmin Sync

Flask web app to sync OMRON Connect blood pressure readings to Garmin Connect.

## Requirements

- Python 3.11+ (project uses `enum.StrEnum`)
- Dependencies in `requirements.txt` (includes `cryptography` for encrypted credential vault)

## Security model

- App users authenticate with username/password (hashed with PBKDF2-SHA256)
- Sync credentials can be stored encrypted server-side per app user
- Sync credentials are decrypted only at request time for sync operations
- Session uses secure cookie settings (`HttpOnly`, `SameSite=Lax`)
- CSRF protection is enforced for write operations (`POST/PUT/PATCH/DELETE`)

## Required environment variables (production)

- `FLASK_SECRET_KEY`:
  - Long random secret for session signing
- `CREDENTIALS_ENCRYPTION_KEY`:
  - Fernet key used to encrypt stored OMRON/Garmin credentials
  - Generate with:
    - `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`

## Optional environment variables

- `SESSION_COOKIE_SECURE`:
  - `1` (default) for HTTPS deployment
  - Set `0` for local HTTP testing
- `SESSION_LIFETIME_HOURS`:
  - Session lifetime in hours (default `12`)
- `APP_DB_PATH`:
  - SQLite database path (default `data/app.db`)

## Local run

1. Create a virtual environment and install dependencies:
   - `python -m venv .venv`
   - `.venv\Scripts\python -m pip install -r requirements.txt`
2. Set local env vars (PowerShell example):
   - `$env:FLASK_SECRET_KEY = "replace-with-long-random-secret"`
   - `$env:CREDENTIALS_ENCRYPTION_KEY = "replace-with-generated-fernet-key"`
   - `$env:SESSION_COOKIE_SECURE = "0"`
3. Start the app:
   - `.venv\Scripts\python app.py`
4. Open `http://127.0.0.1:5000`

By default, app binds to `127.0.0.1`. For LAN/public exposure:
- `.venv\Scripts\python app.py --host 0.0.0.0 --port 5000`

## Render deploy

1. Push this folder to a Git repository.
2. In Render, create a **Web Service** from the repo.
3. Set environment variables in Render:
   - `FLASK_SECRET_KEY`
   - `CREDENTIALS_ENCRYPTION_KEY`
   - `SESSION_COOKIE_SECURE=1`
4. Use:
   - Build command: `pip install -r requirements.txt`
   - Start command: `python app.py --host 0.0.0.0 --port $PORT`

The app includes a `Procfile` for start-command autodetection.

## First-time setup

1. Open the app and create the first account.
2. Sign in with that account.

## Usage

1. Sign in.
2. Enter OMRON + Garmin credentials.
3. Optionally check "Save ... credentials encrypted on server" for one-click reuse.
4. Click "Sync from OMRON to Garmin".
5. Use "Disconnect" on each provider section to revoke and clear saved credentials.

## Notes

- Stored credentials are per app user account.
- If `CREDENTIALS_ENCRYPTION_KEY` changes, previously saved credentials cannot be decrypted.
- Use HTTPS in production.
