# Omron to Garmin Sync

Flask web app to sync OMRON Connect blood pressure readings to Garmin Connect.

## Requirements

- Python 3.11+ (project uses `enum.StrEnum`)
- Dependencies in `requirements.txt` (includes `cryptography` + `psycopg` for encrypted credential vault storage)

## Security model

- App users authenticate with username/password (hashed with PBKDF2-SHA256)
- First registered user becomes admin
- Sync credentials can be stored encrypted server-side per app user
- Sync credentials are decrypted only at request time for sync operations
- Session uses secure cookie settings (`HttpOnly`, `SameSite=Lax`)
- CSRF protection is enforced for write operations (`POST/PUT/PATCH/DELETE`)
- Security response headers are set (CSP, frame deny, content-type nosniff, referrer policy, permissions policy, HSTS on HTTPS)
- Brute-force protection is enabled for login (rate limit + temporary lockout)
- Forgot-password flow uses one-time expiring reset tokens (email delivery)
- Admin page supports listing users and disabling/deleting accounts
- Users can change their own password from the account page
- Password change/reset invalidates active sessions
- Audit trail stores security/admin events (logins, password flows, admin actions)
- Sync history stores run status, counts, and error reasons with retry support

## Required environment variables (production)

- `FLASK_SECRET_KEY`:
  - Long random secret for session signing
- `CREDENTIALS_ENCRYPTION_KEY`:
  - Fernet key used to encrypt stored OMRON/Garmin credentials
  - Generate with:
    - `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
- In production, app startup fails fast if either key is missing.

## Optional environment variables

- `SESSION_COOKIE_SECURE`:
  - `1` (default) for HTTPS deployment
  - Set `0` for local HTTP testing
- `SESSION_LIFETIME_HOURS`:
  - Session lifetime in hours (default `12`)
- `DATABASE_URL`:
  - PostgreSQL connection string (recommended for Render free and production)
  - Example: `postgresql://user:pass@host:5432/dbname?sslmode=require`
- `APP_DB_PATH`:
  - SQLite database path (default `data/app.db`)
  - Used only when `DATABASE_URL` is not set
- `LOGIN_MAX_ATTEMPTS`:
  - Failed login attempts before lockout (default `5`)
- `LOGIN_WINDOW_SECONDS`:
  - Rolling window for failed attempts (default `900`)
- `LOGIN_LOCKOUT_SECONDS`:
  - Temporary lockout duration when limit is reached (default `900`)
- `LOGIN_THROTTLE_RETENTION_SECONDS`:
  - Retain login throttle records for this many seconds before cleanup (default `604800`)
- `LOGIN_THROTTLE_MAX_ROWS`:
  - Hard cap target for `login_throttle` table size (default `50000`)
- `ALLOW_REGISTRATION`:
  - `0` (default): only first account can self-register; after that public signup closes
  - `1`: keep public registration enabled
- `TRUST_PROXY_COUNT`:
  - Number of trusted proxy hops for `X-Forwarded-*` processing via Werkzeug `ProxyFix`
  - Default: `1` on Render, otherwise `0`
- `HSTS_ENABLED`:
  - `1` in production by default; set `0` to disable `Strict-Transport-Security`
- `PASSWORD_RESET_TOKEN_TTL_SECONDS`:
  - Password reset token lifetime in seconds (default `3600`)
- `AUDIT_RETENTION_DAYS`:
  - How long to keep audit trail rows (default `180`)
- `AUDIT_MAX_ROWS`:
  - Hard cap target for audit trail table size (default `200000`)
- `APP_BASE_URL`:
  - Public app base URL used in reset email links (for example, `https://your-app.onrender.com`)
- `SMTP_HOST` / `SMTP_PORT` / `SMTP_USE_TLS`:
  - SMTP server settings for password reset emails
- `SMTP_USERNAME` / `SMTP_PASSWORD`:
  - SMTP auth credentials (if required)
- `SMTP_FROM`:
  - Sender address for password reset emails

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

## Tests

- Run auth/security tests:
  - `.venv\Scripts\python -m unittest discover -s tests -p "test_*.py" -v`

## Health checks

- `GET /healthz`:
  - Liveness check (process is running)
  - Returns `200` with JSON status
- `GET /readyz`:
  - Readiness check (database + encryption subsystem)
  - Returns `200` when ready, `503` when not ready

## CI/CD

- GitHub Actions workflow: `.github/workflows/ci.yml`
- Runs tests automatically on every `push` and `pull_request`.
- To block bad merges/deploys, set this workflow as a **required status check** in GitHub branch protection for your main branch.

## Render deploy

1. Push this folder to a Git repository.
2. In Render, create a **Web Service** from the repo.
3. Set environment variables in Render:
   - `FLASK_SECRET_KEY`
   - `CREDENTIALS_ENCRYPTION_KEY`
   - `SESSION_COOKIE_SECURE=1`
   - `DATABASE_URL=<your-postgres-connection-string>`
4. Use:
   - Build command: `pip install -r requirements.txt`
   - Start command: `python app.py --host 0.0.0.0 --port $PORT`
5. In Render service settings, set:
   - Health Check Path: `/readyz`

The app includes a `Procfile` for start-command autodetection.

## First-time setup

1. Open the app and create the first account.
2. Sign in with that account.
3. If you want open self-signup for more users, set `ALLOW_REGISTRATION=1`.

## Usage

1. Sign in.
2. Enter OMRON + Garmin credentials.
3. Optionally check "Save ... credentials encrypted on server" for one-click reuse.
4. Click "Sync from OMRON to Garmin".
5. Use "Disconnect" on each provider section to revoke and clear saved credentials.
6. Open `History` to review sync outcomes and retry failed runs.
7. Open `Account` to change your app password.
8. Open `Account` to delete your own account (requires password + `DELETE` confirmation).
9. If you are admin, open `Admin` to disable/delete user accounts.
10. Admin page shows recent security events (audit trail).
11. Use `Forgot password?` on sign-in page to request email reset link.

## Notes

- Stored credentials are per app user account.
- Prefer `DATABASE_URL` for persistent storage on Render free (ephemeral filesystem can lose SQLite data on redeploy).
- If `CREDENTIALS_ENCRYPTION_KEY` changes, previously saved credentials cannot be decrypted.
- Use HTTPS in production.
