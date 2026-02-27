import base64
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from cryptography.fernet import Fernet, InvalidToken

PBKDF2_ITERATIONS = 600_000
PASSWORD_RESET_TOKEN_BYTES = 32
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _normalize_username(username: str) -> str:
    return username.strip().lower()


def _is_valid_email(value: str) -> bool:
    return bool(EMAIL_PATTERN.fullmatch(value.strip()))


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    salt_b64 = base64.b64encode(salt).decode("ascii")
    digest_b64 = base64.b64encode(digest).decode("ascii")
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt_b64}${digest_b64}"


def _verify_password(password: str, encoded_hash: str) -> bool:
    try:
        algorithm, iterations_str, salt_b64, digest_b64 = encoded_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_str)
        salt = base64.b64decode(salt_b64.encode("ascii"))
        expected = base64.b64decode(digest_b64.encode("ascii"))
    except (ValueError, TypeError):
        return False

    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)


def _derive_fernet_key(raw: str) -> bytes:
    raw_bytes = raw.strip().encode("utf-8")
    try:
        decoded = base64.urlsafe_b64decode(raw_bytes)
        if len(decoded) == 32:
            return raw_bytes
    except (TypeError, ValueError):
        pass

    digest = hashlib.sha256(raw_bytes).digest()
    return base64.urlsafe_b64encode(digest)


def _hash_reset_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "t", "yes", "y", "on"}
    return False


class SecureStore:
    def __init__(
        self,
        encryption_key: str,
        db_path: str | None = None,
        database_url: str | None = None,
        login_max_attempts: int = 5,
        login_window_seconds: int = 900,
        login_lockout_seconds: int = 900,
        throttle_retention_seconds: int = 604_800,
        throttle_max_rows: int = 50_000,
        audit_retention_seconds: int = 15_552_000,
        audit_max_rows: int = 200_000,
    ):
        self._backend = "postgres" if database_url else "sqlite"
        self._integrity_error = sqlite3.IntegrityError
        self._psycopg = None
        self._dict_row_factory = None

        self.login_max_attempts = max(1, int(login_max_attempts))
        self.login_window_seconds = max(60, int(login_window_seconds))
        self.login_lockout_seconds = max(60, int(login_lockout_seconds))
        self.throttle_retention_seconds = max(3600, int(throttle_retention_seconds))
        self.throttle_max_rows = max(1000, int(throttle_max_rows))
        self.audit_retention_seconds = max(86_400, int(audit_retention_seconds))
        self.audit_max_rows = max(1000, int(audit_max_rows))

        if database_url:
            normalized = self._normalize_database_url(database_url)
            try:
                import psycopg  # type: ignore[import-not-found]
                from psycopg.rows import dict_row  # type: ignore[import-not-found]
            except ImportError as exc:
                raise RuntimeError(
                    "DATABASE_URL is set but psycopg is not installed. Install psycopg[binary]."
                ) from exc

            self.database_url = normalized
            self._psycopg = psycopg
            self._dict_row_factory = dict_row
            self._integrity_error = psycopg.IntegrityError
        else:
            if not db_path:
                raise ValueError("db_path is required when DATABASE_URL is not set.")
            self.db_path = Path(db_path)
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._fernet = Fernet(_derive_fernet_key(encryption_key))
        self._init_db()
        self._ensure_admin_exists()

    @staticmethod
    def _normalize_database_url(url: str) -> str:
        clean = url.strip()
        if clean.startswith("postgres://"):
            return "postgresql://" + clean[len("postgres://") :]
        return clean

    def _is_postgres(self) -> bool:
        return self._backend == "postgres"

    def _adapt_query(self, query: str) -> str:
        if not self._is_postgres():
            return query
        return query.replace("?", "%s")

    def _connect(self):
        if self._is_postgres():
            assert self._psycopg is not None
            return self._psycopg.connect(self.database_url, row_factory=self._dict_row_factory)

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _execute(self, query: str, params: tuple[Any, ...] = ()) -> None:
        with self._connect() as conn:
            conn.execute(self._adapt_query(query), params)
            conn.commit()

    def _fetchone(self, query: str, params: tuple[Any, ...] = ()) -> Mapping[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(self._adapt_query(query), params).fetchone()
            if row is None:
                return None
            if isinstance(row, sqlite3.Row):
                return dict(row)
            return row

    def _fetchall(self, query: str, params: tuple[Any, ...] = ()) -> list[Mapping[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(self._adapt_query(query), params).fetchall()
            results: list[Mapping[str, Any]] = []
            for row in rows:
                if isinstance(row, sqlite3.Row):
                    results.append(dict(row))
                else:
                    results.append(row)
            return results

    def _ensure_user_columns(self, conn) -> None:
        if self._is_postgres():
            conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE")
            conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE")
            conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS session_version INTEGER NOT NULL DEFAULT 1")
            return

        rows = conn.execute("PRAGMA table_info(users)").fetchall()
        existing = {str(row["name"]) for row in rows}
        if "is_admin" not in existing:
            conn.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
        if "is_active" not in existing:
            conn.execute("ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
        if "session_version" not in existing:
            conn.execute("ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 1")

    def _init_db(self) -> None:
        with self._connect() as conn:
            if not self._is_postgres():
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        is_admin INTEGER NOT NULL DEFAULT 0,
                        is_active INTEGER NOT NULL DEFAULT 1,
                        session_version INTEGER NOT NULL DEFAULT 1
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS user_credentials (
                        user_id INTEGER PRIMARY KEY,
                        garmin_email TEXT,
                        garmin_password TEXT,
                        omron_email TEXT,
                        omron_password TEXT,
                        omron_country TEXT,
                        updated_at TEXT NOT NULL,
                        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS login_throttle (
                        scope TEXT NOT NULL,
                        key_value TEXT NOT NULL,
                        failures INTEGER NOT NULL,
                        first_failed_at TEXT NOT NULL,
                        locked_until TEXT,
                        updated_at TEXT NOT NULL,
                        PRIMARY KEY (scope, key_value)
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS password_reset_tokens (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        token_hash TEXT UNIQUE NOT NULL,
                        expires_at TEXT NOT NULL,
                        used_at TEXT,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS sync_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        trigger_source TEXT NOT NULL,
                        retry_of_id INTEGER,
                        status TEXT NOT NULL,
                        readings_found INTEGER,
                        readings_uploaded INTEGER,
                        message TEXT,
                        error_message TEXT,
                        save_garmin_requested INTEGER NOT NULL DEFAULT 0,
                        save_omron_requested INTEGER NOT NULL DEFAULT 0,
                        started_at TEXT NOT NULL,
                        completed_at TEXT,
                        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                        FOREIGN KEY(retry_of_id) REFERENCES sync_history(id) ON DELETE SET NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_sync_history_user_started
                    ON sync_history(user_id, started_at DESC)
                    """
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_sync_history_retry_of
                    ON sync_history(retry_of_id)
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type TEXT NOT NULL,
                        outcome TEXT NOT NULL,
                        actor_user_id INTEGER,
                        target_user_id INTEGER,
                        username TEXT,
                        ip_address TEXT,
                        details TEXT,
                        created_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_audit_events_created_at
                    ON audit_events(created_at DESC)
                    """
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_audit_events_event_type
                    ON audit_events(event_type)
                    """
                )
            else:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id BIGSERIAL PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        is_admin BOOLEAN NOT NULL DEFAULT FALSE,
                        is_active BOOLEAN NOT NULL DEFAULT TRUE,
                        session_version INTEGER NOT NULL DEFAULT 1
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS user_credentials (
                        user_id BIGINT PRIMARY KEY,
                        garmin_email TEXT,
                        garmin_password TEXT,
                        omron_email TEXT,
                        omron_password TEXT,
                        omron_country TEXT,
                        updated_at TEXT NOT NULL,
                        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS login_throttle (
                        scope TEXT NOT NULL,
                        key_value TEXT NOT NULL,
                        failures INTEGER NOT NULL,
                        first_failed_at TEXT NOT NULL,
                        locked_until TEXT,
                        updated_at TEXT NOT NULL,
                        PRIMARY KEY (scope, key_value)
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS password_reset_tokens (
                        id BIGSERIAL PRIMARY KEY,
                        user_id BIGINT NOT NULL,
                        token_hash TEXT UNIQUE NOT NULL,
                        expires_at TEXT NOT NULL,
                        used_at TEXT,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS sync_history (
                        id BIGSERIAL PRIMARY KEY,
                        user_id BIGINT NOT NULL,
                        trigger_source TEXT NOT NULL,
                        retry_of_id BIGINT,
                        status TEXT NOT NULL,
                        readings_found INTEGER,
                        readings_uploaded INTEGER,
                        message TEXT,
                        error_message TEXT,
                        save_garmin_requested BOOLEAN NOT NULL DEFAULT FALSE,
                        save_omron_requested BOOLEAN NOT NULL DEFAULT FALSE,
                        started_at TEXT NOT NULL,
                        completed_at TEXT,
                        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                        FOREIGN KEY(retry_of_id) REFERENCES sync_history(id) ON DELETE SET NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_sync_history_user_started
                    ON sync_history(user_id, started_at DESC)
                    """
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_sync_history_retry_of
                    ON sync_history(retry_of_id)
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_events (
                        id BIGSERIAL PRIMARY KEY,
                        event_type TEXT NOT NULL,
                        outcome TEXT NOT NULL,
                        actor_user_id BIGINT,
                        target_user_id BIGINT,
                        username TEXT,
                        ip_address TEXT,
                        details TEXT,
                        created_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_audit_events_created_at
                    ON audit_events(created_at DESC)
                    """
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_audit_events_event_type
                    ON audit_events(event_type)
                    """
                )

            self._ensure_user_columns(conn)
            conn.commit()

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def _encrypt(self, value: str | None) -> str | None:
        if not value:
            return None
        return self._fernet.encrypt(value.encode("utf-8")).decode("ascii")

    def _decrypt(self, token: str | None) -> str | None:
        if not token:
            return None
        try:
            return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError):
            return None

    def backend_name(self) -> str:
        return self._backend

    def check_database(self) -> tuple[bool, str]:
        try:
            row = self._fetchone("SELECT 1 AS ok")
        except Exception:
            return False, "database query failed"

        if not row:
            return False, "database returned no result"

        try:
            if int(row["ok"]) != 1:
                return False, "database returned unexpected result"
        except (TypeError, ValueError, KeyError):
            pass

        return True, ""

    def check_crypto(self) -> tuple[bool, str]:
        try:
            probe = secrets.token_urlsafe(16)
            encrypted = self._fernet.encrypt(probe.encode("utf-8"))
            decrypted = self._fernet.decrypt(encrypted).decode("utf-8")
        except Exception:
            return False, "encryption round-trip failed"

        if decrypted != probe:
            return False, "encryption round-trip mismatch"

        return True, ""

    def user_count(self) -> int:
        row = self._fetchone("SELECT COUNT(*) AS count FROM users")
        return int(row["count"]) if row else 0

    def _admin_count(self, active_only: bool = False) -> int:
        if active_only:
            row = self._fetchone(
                "SELECT COUNT(*) AS count FROM users WHERE is_admin = ? AND is_active = ?",
                (True, True),
            )
        else:
            row = self._fetchone("SELECT COUNT(*) AS count FROM users WHERE is_admin = ?", (True,))
        return int(row["count"]) if row else 0

    def _ensure_admin_exists(self) -> None:
        if self.user_count() == 0:
            return

        if self._admin_count() > 0:
            return

        row = self._fetchone("SELECT id FROM users ORDER BY id ASC LIMIT 1")
        if row:
            self._execute("UPDATE users SET is_admin = ? WHERE id = ?", (True, int(row["id"])))

    def create_user(self, username: str, password: str) -> tuple[bool, str]:
        username_normalized = _normalize_username(username)
        if not username_normalized:
            return False, "Email is required."
        if not _is_valid_email(username_normalized):
            return False, "Email must be a valid address."
        if len(password) < 10:
            return False, "Password must be at least 10 characters."

        password_hash = _hash_password(password)
        is_admin = self.user_count() == 0
        try:
            self._execute(
                """
                INSERT INTO users (username, password_hash, created_at, is_admin, is_active, session_version)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (username_normalized, password_hash, self._now_iso(), is_admin, True, 1),
            )
            return True, ""
        except self._integrity_error as exc:
            if getattr(exc, "sqlstate", "") == "23505" or "unique" in str(exc).lower():
                return False, "That username already exists."
            return False, "Could not create account."

    def get_user_by_id(self, user_id: int) -> dict[str, str | int | bool] | None:
        row = self._fetchone(
            "SELECT id, username, created_at, is_admin, is_active, session_version FROM users WHERE id = ?",
            (user_id,),
        )
        if not row:
            return None
        return {
            "id": int(row["id"]),
            "username": str(row["username"]),
            "created_at": str(row["created_at"]),
            "is_admin": _to_bool(row.get("is_admin")),
            "is_active": _to_bool(row.get("is_active")),
            "session_version": int(row.get("session_version") or 1),
        }

    def is_admin(self, user_id: int) -> bool:
        row = self._fetchone("SELECT is_admin FROM users WHERE id = ?", (user_id,))
        if not row:
            return False
        return _to_bool(row.get("is_admin"))

    def authenticate_user(self, username: str, password: str) -> dict[str, str | int | bool] | None:
        username_normalized = _normalize_username(username)
        row = self._fetchone(
            """
            SELECT id, username, password_hash, is_admin, is_active, session_version
            FROM users
            WHERE username = ?
            """,
            (username_normalized,),
        )
        if not row:
            return None
        if not _to_bool(row.get("is_active")):
            return None
        if not _verify_password(password, str(row["password_hash"])):
            return None
        return {
            "id": int(row["id"]),
            "username": str(row["username"]),
            "is_admin": _to_bool(row.get("is_admin")),
            "session_version": int(row.get("session_version") or 1),
        }

    def change_password(self, user_id: int, current_password: str, new_password: str) -> tuple[bool, str]:
        if len(new_password) < 10:
            return False, "New password must be at least 10 characters."

        row = self._fetchone("SELECT username, password_hash FROM users WHERE id = ?", (user_id,))
        if not row:
            return False, "User not found."

        current_hash = str(row["password_hash"])
        if not _verify_password(current_password, current_hash):
            return False, "Current password is incorrect."
        if _verify_password(new_password, current_hash):
            return False, "New password must be different from current password."

        self._execute(
            "UPDATE users SET password_hash = ?, session_version = COALESCE(session_version, 1) + 1 WHERE id = ?",
            (_hash_password(new_password), user_id),
        )
        username = str(row["username"])
        self.clear_login_failures(username, "")
        return True, ""

    def delete_own_account(self, user_id: int, current_password: str) -> tuple[bool, str]:
        row = self._fetchone(
            "SELECT username, password_hash, is_admin FROM users WHERE id = ?",
            (user_id,),
        )
        if not row:
            return False, "User not found."

        current_hash = str(row["password_hash"])
        if not _verify_password(current_password, current_hash):
            return False, "Current password is incorrect."

        if _to_bool(row.get("is_admin")) and self._admin_count() <= 1:
            others_row = self._fetchone(
                "SELECT COUNT(*) AS count FROM users WHERE id <> ?",
                (user_id,),
            )
            other_users = int(others_row["count"]) if others_row else 0
            if other_users > 0:
                return False, "Cannot delete the last admin while other users exist."

        username = str(row["username"])
        self._execute("DELETE FROM users WHERE id = ?", (user_id,))
        self.clear_login_failures(username, "")
        return True, ""

    def create_password_reset_token(
        self,
        username: str,
        ttl_seconds: int = 3600,
    ) -> tuple[bool, str, str]:
        username_normalized = _normalize_username(username)
        if not username_normalized:
            return False, "", ""

        user_row = self._fetchone(
            "SELECT id, username, is_active FROM users WHERE username = ?",
            (username_normalized,),
        )
        if not user_row:
            return False, "", ""
        if not _to_bool(user_row.get("is_active")):
            return False, "", ""

        token = secrets.token_urlsafe(PASSWORD_RESET_TOKEN_BYTES)
        token_hash = _hash_reset_token(token)
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat(timespec="seconds")
        ttl = max(300, int(ttl_seconds))
        expires_at = (now + timedelta(seconds=ttl)).isoformat(timespec="seconds")
        user_id = int(user_row["id"])

        # Invalidate older outstanding reset tokens for this user.
        self._execute(
            """
            UPDATE password_reset_tokens
            SET used_at = ?
            WHERE user_id = ? AND used_at IS NULL
            """,
            (now_iso, user_id),
        )

        self._execute(
            """
            INSERT INTO password_reset_tokens (
                user_id,
                token_hash,
                expires_at,
                used_at,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, token_hash, expires_at, None, now_iso),
        )

        return True, str(user_row["username"]), token

    def validate_password_reset_token(self, token: str) -> tuple[bool, str]:
        token_hash = _hash_reset_token(token.strip())
        row = self._fetchone(
            """
            SELECT id, user_id, expires_at, used_at
            FROM password_reset_tokens
            WHERE token_hash = ?
            """,
            (token_hash,),
        )
        if not row:
            return False, "Invalid reset link."
        if row.get("used_at"):
            return False, "This reset link has already been used."

        expires_at = _parse_iso_datetime(str(row["expires_at"]))
        if not expires_at or expires_at <= datetime.now(timezone.utc):
            return False, "This reset link has expired."

        user = self._fetchone("SELECT is_active FROM users WHERE id = ?", (int(row["user_id"]),))
        if not user or not _to_bool(user.get("is_active")):
            return False, "Reset is not available for this account."
        return True, ""

    def consume_password_reset_token(self, token: str, new_password: str) -> tuple[bool, str, int | None, str]:
        if len(new_password) < 10:
            return False, "New password must be at least 10 characters.", None, ""

        token_hash = _hash_reset_token(token.strip())
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat(timespec="seconds")

        with self._connect() as conn:
            token_row = conn.execute(
                self._adapt_query(
                    """
                    SELECT id, user_id, expires_at, used_at
                    FROM password_reset_tokens
                    WHERE token_hash = ?
                    """
                ),
                (token_hash,),
            ).fetchone()

            if token_row is None:
                return False, "Invalid reset link.", None, ""

            token_data = dict(token_row) if isinstance(token_row, sqlite3.Row) else token_row
            if token_data.get("used_at"):
                return False, "This reset link has already been used.", None, ""

            expires_at = _parse_iso_datetime(str(token_data["expires_at"]))
            if not expires_at or expires_at <= now:
                return False, "This reset link has expired.", None, ""

            user_id = int(token_data["user_id"])
            user_row = conn.execute(
                self._adapt_query("SELECT username, is_active FROM users WHERE id = ?"),
                (user_id,),
            ).fetchone()
            if user_row is None:
                return False, "User not found.", None, ""

            user_data = dict(user_row) if isinstance(user_row, sqlite3.Row) else user_row
            if not _to_bool(user_data.get("is_active")):
                return False, "Reset is not available for this account.", None, ""

            conn.execute(
                self._adapt_query(
                    "UPDATE users SET password_hash = ?, session_version = COALESCE(session_version, 1) + 1 WHERE id = ?"
                ),
                (_hash_password(new_password), user_id),
            )
            conn.execute(
                self._adapt_query(
                    """
                    UPDATE password_reset_tokens
                    SET used_at = ?
                    WHERE user_id = ? AND used_at IS NULL
                    """
                ),
                (now_iso, user_id),
            )
            conn.commit()

            username = str(user_data["username"])
            self.clear_login_failures(username, "")
            return True, "", user_id, username

    def list_users(self) -> list[dict[str, str | int | bool]]:
        rows = self._fetchall(
            """
            SELECT
                u.id,
                u.username,
                u.created_at,
                u.is_admin,
                u.is_active,
                CASE
                    WHEN c.user_id IS NULL THEN 0
                    WHEN c.garmin_email IS NOT NULL THEN 1
                    WHEN c.garmin_password IS NOT NULL THEN 1
                    WHEN c.omron_email IS NOT NULL THEN 1
                    WHEN c.omron_password IS NOT NULL THEN 1
                    WHEN c.omron_country IS NOT NULL THEN 1
                    ELSE 0
                END AS has_saved_credentials
            FROM users AS u
            LEFT JOIN user_credentials AS c
                ON c.user_id = u.id
            ORDER BY u.id ASC
            """
        )
        users: list[dict[str, str | int | bool]] = []
        for row in rows:
            users.append(
                {
                    "id": int(row["id"]),
                    "username": str(row["username"]),
                    "created_at": str(row["created_at"]),
                    "is_admin": _to_bool(row.get("is_admin")),
                    "is_active": _to_bool(row.get("is_active")),
                    "has_saved_credentials": _to_bool(row.get("has_saved_credentials")),
                }
            )
        return users

    def set_user_active(
        self,
        actor_user_id: int,
        target_user_id: int,
        is_active: bool,
    ) -> tuple[bool, str]:
        if actor_user_id == target_user_id and not is_active:
            return False, "You cannot disable your own account."

        row = self._fetchone(
            "SELECT username, is_admin, is_active FROM users WHERE id = ?",
            (target_user_id,),
        )
        if not row:
            return False, "User not found."

        target_is_admin = _to_bool(row.get("is_admin"))
        target_is_active = _to_bool(row.get("is_active"))
        if not is_active and target_is_admin and target_is_active and self._admin_count(active_only=True) <= 1:
            return False, "Cannot disable the last active admin."

        self._execute(
            "UPDATE users SET is_active = ? WHERE id = ?",
            (is_active, target_user_id),
        )

        if not is_active:
            self.clear_login_failures(str(row["username"]), "")

        return True, ""

    def delete_user(self, actor_user_id: int, target_user_id: int) -> tuple[bool, str]:
        if actor_user_id == target_user_id:
            return False, "You cannot delete your own account."

        row = self._fetchone(
            "SELECT username, is_admin FROM users WHERE id = ?",
            (target_user_id,),
        )
        if not row:
            return False, "User not found."

        target_is_admin = _to_bool(row.get("is_admin"))
        if target_is_admin and self._admin_count() <= 1:
            return False, "Cannot delete the last admin."

        username = str(row["username"])
        self._execute("DELETE FROM users WHERE id = ?", (target_user_id,))
        self.clear_login_failures(username, "")
        return True, ""

    def _throttle_keys(self, username: str, client_ip: str) -> list[tuple[str, str]]:
        keys: list[tuple[str, str]] = []
        username_normalized = _normalize_username(username)
        ip_value = client_ip.strip()
        if username_normalized:
            keys.append(("user", username_normalized))
        if ip_value:
            keys.append(("ip", ip_value))
        return keys

    def _get_throttle_row(self, scope: str, key_value: str) -> Mapping[str, Any] | None:
        return self._fetchone(
            """
            SELECT scope, key_value, failures, first_failed_at, locked_until, updated_at
            FROM login_throttle
            WHERE scope = ? AND key_value = ?
            """,
            (scope, key_value),
        )

    def _upsert_throttle_row(
        self,
        scope: str,
        key_value: str,
        failures: int,
        first_failed_at: str,
        locked_until: str | None,
    ) -> None:
        self._execute(
            """
            INSERT INTO login_throttle (
                scope,
                key_value,
                failures,
                first_failed_at,
                locked_until,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(scope, key_value) DO UPDATE SET
                failures = excluded.failures,
                first_failed_at = excluded.first_failed_at,
                locked_until = excluded.locked_until,
                updated_at = excluded.updated_at
            """,
            (
                scope,
                key_value,
                int(failures),
                first_failed_at,
                locked_until,
                self._now_iso(),
            ),
        )

    def prune_login_throttle(self) -> None:
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat(timespec="seconds")
        retention_cutoff = (now - timedelta(seconds=self.throttle_retention_seconds)).isoformat(
            timespec="seconds"
        )

        self._execute(
            """
            DELETE FROM login_throttle
            WHERE updated_at < ?
              AND (locked_until IS NULL OR locked_until < ?)
            """,
            (retention_cutoff, now_iso),
        )

        count_row = self._fetchone("SELECT COUNT(*) AS count FROM login_throttle")
        current_count = int(count_row["count"]) if count_row else 0
        overflow = current_count - self.throttle_max_rows
        if overflow <= 0:
            return

        oldest_rows = self._fetchall(
            """
            SELECT scope, key_value
            FROM login_throttle
            ORDER BY updated_at ASC
            LIMIT ?
            """,
            (overflow,),
        )
        for row in oldest_rows:
            self._execute(
                "DELETE FROM login_throttle WHERE scope = ? AND key_value = ?",
                (str(row["scope"]), str(row["key_value"])),
            )

    def get_login_lockout_seconds(self, username: str, client_ip: str) -> int:
        if secrets.randbelow(100) == 0:
            self.prune_login_throttle()

        now = datetime.now(timezone.utc)
        max_remaining = 0
        for scope, key_value in self._throttle_keys(username, client_ip):
            row = self._get_throttle_row(scope, key_value)
            if not row:
                continue

            locked_until = _parse_iso_datetime(row.get("locked_until"))
            if not locked_until:
                continue

            remaining = int((locked_until - now).total_seconds())
            if remaining <= 0:
                self._execute(
                    "UPDATE login_throttle SET locked_until = ?, updated_at = ? WHERE scope = ? AND key_value = ?",
                    (None, self._now_iso(), scope, key_value),
                )
                continue
            if remaining > max_remaining:
                max_remaining = remaining
        return max_remaining

    def record_login_failure(self, username: str, client_ip: str) -> None:
        now = datetime.now(timezone.utc)
        window = timedelta(seconds=self.login_window_seconds)
        lockout = timedelta(seconds=self.login_lockout_seconds)

        for scope, key_value in self._throttle_keys(username, client_ip):
            row = self._get_throttle_row(scope, key_value)
            if not row:
                failures = 1
                first_failed_at = now
            else:
                first_failed_at = _parse_iso_datetime(row.get("first_failed_at")) or now
                failures = int(row.get("failures", 0))
                if (now - first_failed_at) > window:
                    failures = 0
                    first_failed_at = now
                failures += 1

            locked_until_iso: str | None = None
            if failures >= self.login_max_attempts:
                locked_until_iso = (now + lockout).isoformat(timespec="seconds")

            self._upsert_throttle_row(
                scope=scope,
                key_value=key_value,
                failures=failures,
                first_failed_at=first_failed_at.isoformat(timespec="seconds"),
                locked_until=locked_until_iso,
            )

        # Run cleanup periodically to bound storage growth under abuse.
        if secrets.randbelow(20) == 0:
            self.prune_login_throttle()

    def clear_login_failures(self, username: str, client_ip: str) -> None:
        keys = self._throttle_keys(username, client_ip)
        for scope, key_value in keys:
            self._execute(
                "DELETE FROM login_throttle WHERE scope = ? AND key_value = ?",
                (scope, key_value),
            )

    def clear_login_failures_for_username(self, username: str) -> None:
        username_normalized = _normalize_username(username)
        if not username_normalized:
            return
        self._execute(
            "DELETE FROM login_throttle WHERE scope = ? AND key_value = ?",
            ("user", username_normalized),
        )

    def _read_credential_row(self, user_id: int) -> Mapping[str, Any] | None:
        return self._fetchone(
            """
            SELECT user_id, garmin_email, garmin_password, omron_email, omron_password, omron_country
            FROM user_credentials
            WHERE user_id = ?
            """,
            (user_id,),
        )

    def get_credentials_for_sync(self, user_id: int) -> dict[str, str]:
        row = self._read_credential_row(user_id)
        if not row:
            return {}
        return {
            "garmin_email": self._decrypt(row["garmin_email"]) or "",
            "garmin_password": self._decrypt(row["garmin_password"]) or "",
            "omron_email": self._decrypt(row["omron_email"]) or "",
            "omron_password": self._decrypt(row["omron_password"]) or "",
            "omron_country": (self._decrypt(row["omron_country"]) or "").upper(),
        }

    def get_status(self, user_id: int) -> dict[str, dict[str, str | bool]]:
        creds = self.get_credentials_for_sync(user_id)
        garmin_saved = bool(creds.get("garmin_email") and creds.get("garmin_password"))
        omron_saved = bool(
            creds.get("omron_email")
            and creds.get("omron_password")
            and creds.get("omron_country")
        )
        return {
            "garmin": {
                "saved": garmin_saved,
                "email": creds.get("garmin_email", "") if garmin_saved else "",
            },
            "omron": {
                "saved": omron_saved,
                "email": creds.get("omron_email", "") if omron_saved else "",
                "country": creds.get("omron_country", "") if omron_saved else "",
            },
        }

    def _upsert_credentials(
        self,
        user_id: int,
        garmin_email: str | None,
        garmin_password: str | None,
        omron_email: str | None,
        omron_password: str | None,
        omron_country: str | None,
    ) -> None:
        self._execute(
            """
            INSERT INTO user_credentials (
                user_id,
                garmin_email,
                garmin_password,
                omron_email,
                omron_password,
                omron_country,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                garmin_email = excluded.garmin_email,
                garmin_password = excluded.garmin_password,
                omron_email = excluded.omron_email,
                omron_password = excluded.omron_password,
                omron_country = excluded.omron_country,
                updated_at = excluded.updated_at
            """,
            (
                user_id,
                self._encrypt(garmin_email),
                self._encrypt(garmin_password),
                self._encrypt(omron_email),
                self._encrypt(omron_password),
                self._encrypt(omron_country),
                self._now_iso(),
            ),
        )

    def save_garmin_credentials(self, user_id: int, email: str, password: str) -> None:
        current = self.get_credentials_for_sync(user_id)
        self._upsert_credentials(
            user_id=user_id,
            garmin_email=email.strip(),
            garmin_password=password,
            omron_email=current.get("omron_email") or None,
            omron_password=current.get("omron_password") or None,
            omron_country=current.get("omron_country") or None,
        )

    def save_omron_credentials(self, user_id: int, email: str, password: str, country: str) -> None:
        current = self.get_credentials_for_sync(user_id)
        self._upsert_credentials(
            user_id=user_id,
            garmin_email=current.get("garmin_email") or None,
            garmin_password=current.get("garmin_password") or None,
            omron_email=email.strip(),
            omron_password=password,
            omron_country=country.strip().upper(),
        )

    def clear_provider(self, user_id: int, provider: str) -> None:
        current = self.get_credentials_for_sync(user_id)
        if provider == "garmin":
            self._upsert_credentials(
                user_id=user_id,
                garmin_email=None,
                garmin_password=None,
                omron_email=current.get("omron_email") or None,
                omron_password=current.get("omron_password") or None,
                omron_country=current.get("omron_country") or None,
            )
            return

        if provider == "omron":
            self._upsert_credentials(
                user_id=user_id,
                garmin_email=current.get("garmin_email") or None,
                garmin_password=current.get("garmin_password") or None,
                omron_email=None,
                omron_password=None,
                omron_country=None,
            )
            return

        raise ValueError("Unknown provider.")

    def record_audit_event(
        self,
        event_type: str,
        outcome: str = "success",
        actor_user_id: int | None = None,
        target_user_id: int | None = None,
        username: str | None = None,
        ip_address: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        event_value = event_type.strip()[:120]
        outcome_value = outcome.strip().lower()[:32] or "success"
        username_value = (username or "").strip().lower()[:255] or None
        ip_value = (ip_address or "").strip()[:64] or None
        details_value = json.dumps(dict(details), sort_keys=True, separators=(",", ":")) if details else None

        self._execute(
            """
            INSERT INTO audit_events (
                event_type,
                outcome,
                actor_user_id,
                target_user_id,
                username,
                ip_address,
                details,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_value,
                outcome_value,
                actor_user_id,
                target_user_id,
                username_value,
                ip_value,
                details_value,
                self._now_iso(),
            ),
        )

        # Keep audit storage bounded under long-term operation.
        if secrets.randbelow(25) == 0:
            self.prune_audit_events()

    def prune_audit_events(self) -> None:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=self.audit_retention_seconds)).isoformat(
            timespec="seconds"
        )
        self._execute("DELETE FROM audit_events WHERE created_at < ?", (cutoff,))

        count_row = self._fetchone("SELECT COUNT(*) AS count FROM audit_events")
        current_count = int(count_row["count"]) if count_row else 0
        overflow = current_count - self.audit_max_rows
        if overflow <= 0:
            return

        oldest_rows = self._fetchall(
            """
            SELECT id
            FROM audit_events
            ORDER BY created_at ASC, id ASC
            LIMIT ?
            """,
            (overflow,),
        )
        for row in oldest_rows:
            self._execute("DELETE FROM audit_events WHERE id = ?", (int(row["id"]),))

    def list_audit_events(self, limit: int = 100) -> list[dict[str, str | int | None]]:
        safe_limit = max(1, min(int(limit), 1000))
        rows = self._fetchall(
            """
            SELECT
                id,
                event_type,
                outcome,
                actor_user_id,
                target_user_id,
                username,
                ip_address,
                details,
                created_at
            FROM audit_events
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (safe_limit,),
        )

        events: list[dict[str, str | int | None]] = []
        for row in rows:
            details_text = row.get("details")
            details_json: str | None = None
            if isinstance(details_text, str) and details_text:
                try:
                    details_json = json.dumps(json.loads(details_text), ensure_ascii=True, sort_keys=True)
                except (TypeError, ValueError):
                    details_json = details_text

            events.append(
                {
                    "id": int(row["id"]),
                    "event_type": str(row["event_type"]),
                    "outcome": str(row["outcome"]),
                    "actor_user_id": int(row["actor_user_id"]) if row.get("actor_user_id") is not None else None,
                    "target_user_id": int(row["target_user_id"]) if row.get("target_user_id") is not None else None,
                    "username": str(row["username"]) if row.get("username") else None,
                    "ip_address": str(row["ip_address"]) if row.get("ip_address") else None,
                    "details": details_json,
                    "created_at": str(row["created_at"]),
                }
            )
        return events

    def start_sync_history(
        self,
        user_id: int,
        trigger_source: str = "manual",
        retry_of_id: int | None = None,
        save_garmin_requested: bool = False,
        save_omron_requested: bool = False,
    ) -> int:
        started_at = self._now_iso()
        source = (trigger_source or "manual").strip().lower()[:32]

        with self._connect() as conn:
            if self._is_postgres():
                row = conn.execute(
                    self._adapt_query(
                        """
                        INSERT INTO sync_history (
                            user_id,
                            trigger_source,
                            retry_of_id,
                            status,
                            save_garmin_requested,
                            save_omron_requested,
                            started_at,
                            completed_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        RETURNING id
                        """
                    ),
                    (
                        user_id,
                        source,
                        retry_of_id,
                        "running",
                        bool(save_garmin_requested),
                        bool(save_omron_requested),
                        started_at,
                        None,
                    ),
                ).fetchone()
                conn.commit()
                if row is None:
                    raise RuntimeError("Failed to create sync history entry.")
                return int(row["id"])

            cursor = conn.execute(
                self._adapt_query(
                    """
                    INSERT INTO sync_history (
                        user_id,
                        trigger_source,
                        retry_of_id,
                        status,
                        save_garmin_requested,
                        save_omron_requested,
                        started_at,
                        completed_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """
                ),
                (
                    user_id,
                    source,
                    retry_of_id,
                    "running",
                    1 if save_garmin_requested else 0,
                    1 if save_omron_requested else 0,
                    started_at,
                    None,
                ),
            )
            conn.commit()
            return int(cursor.lastrowid)

    def finish_sync_history(
        self,
        history_id: int,
        status: str,
        readings_found: int | None = None,
        readings_uploaded: int | None = None,
        message: str | None = None,
        error_message: str | None = None,
    ) -> None:
        completed_at = self._now_iso()
        status_value = (status or "failed").strip().lower()[:32]
        self._execute(
            """
            UPDATE sync_history
            SET
                status = ?,
                readings_found = ?,
                readings_uploaded = ?,
                message = ?,
                error_message = ?,
                completed_at = ?
            WHERE id = ?
            """,
            (
                status_value,
                readings_found,
                readings_uploaded,
                message,
                error_message,
                completed_at,
                history_id,
            ),
        )

    def list_sync_history(self, user_id: int, limit: int = 100) -> list[dict[str, str | int | bool | None]]:
        safe_limit = max(1, min(int(limit), 1000))
        rows = self._fetchall(
            """
            SELECT
                id,
                user_id,
                trigger_source,
                retry_of_id,
                status,
                readings_found,
                readings_uploaded,
                message,
                error_message,
                save_garmin_requested,
                save_omron_requested,
                started_at,
                completed_at
            FROM sync_history
            WHERE user_id = ?
            ORDER BY started_at DESC, id DESC
            LIMIT ?
            """,
            (user_id, safe_limit),
        )
        history: list[dict[str, str | int | bool | None]] = []
        for row in rows:
            history.append(
                {
                    "id": int(row["id"]),
                    "user_id": int(row["user_id"]),
                    "trigger_source": str(row["trigger_source"]),
                    "retry_of_id": int(row["retry_of_id"]) if row.get("retry_of_id") is not None else None,
                    "status": str(row["status"]),
                    "readings_found": (
                        int(row["readings_found"]) if row.get("readings_found") is not None else None
                    ),
                    "readings_uploaded": (
                        int(row["readings_uploaded"]) if row.get("readings_uploaded") is not None else None
                    ),
                    "message": str(row["message"]) if row.get("message") else None,
                    "error_message": str(row["error_message"]) if row.get("error_message") else None,
                    "save_garmin_requested": _to_bool(row.get("save_garmin_requested")),
                    "save_omron_requested": _to_bool(row.get("save_omron_requested")),
                    "started_at": str(row["started_at"]),
                    "completed_at": str(row["completed_at"]) if row.get("completed_at") else None,
                }
            )
        return history

    def get_sync_history_entry(
        self,
        user_id: int,
        history_id: int,
    ) -> dict[str, str | int | bool | None] | None:
        row = self._fetchone(
            """
            SELECT
                id,
                user_id,
                trigger_source,
                retry_of_id,
                status,
                readings_found,
                readings_uploaded,
                message,
                error_message,
                save_garmin_requested,
                save_omron_requested,
                started_at,
                completed_at
            FROM sync_history
            WHERE user_id = ? AND id = ?
            """,
            (user_id, history_id),
        )
        if not row:
            return None
        return {
            "id": int(row["id"]),
            "user_id": int(row["user_id"]),
            "trigger_source": str(row["trigger_source"]),
            "retry_of_id": int(row["retry_of_id"]) if row.get("retry_of_id") is not None else None,
            "status": str(row["status"]),
            "readings_found": int(row["readings_found"]) if row.get("readings_found") is not None else None,
            "readings_uploaded": (
                int(row["readings_uploaded"]) if row.get("readings_uploaded") is not None else None
            ),
            "message": str(row["message"]) if row.get("message") else None,
            "error_message": str(row["error_message"]) if row.get("error_message") else None,
            "save_garmin_requested": _to_bool(row.get("save_garmin_requested")),
            "save_omron_requested": _to_bool(row.get("save_omron_requested")),
            "started_at": str(row["started_at"]),
            "completed_at": str(row["completed_at"]) if row.get("completed_at") else None,
        }

    def get_sync_history_counts(self, user_id: int) -> dict[str, int]:
        row = self._fetchone(
            """
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) AS success,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
                SUM(CASE WHEN status = 'partial' THEN 1 ELSE 0 END) AS partial,
                SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) AS running
            FROM sync_history
            WHERE user_id = ?
            """,
            (user_id,),
        )
        if not row:
            return {"total": 0, "success": 0, "failed": 0, "partial": 0, "running": 0}
        return {
            "total": int(row.get("total") or 0),
            "success": int(row.get("success") or 0),
            "failed": int(row.get("failed") or 0),
            "partial": int(row.get("partial") or 0),
            "running": int(row.get("running") or 0),
        }
