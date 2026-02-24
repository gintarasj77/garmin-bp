import base64
import hashlib
import hmac
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from cryptography.fernet import Fernet, InvalidToken

PBKDF2_ITERATIONS = 600_000


def _normalize_username(username: str) -> str:
    return username.strip().lower()


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
    ):
        self._backend = "postgres" if database_url else "sqlite"
        self._integrity_error = sqlite3.IntegrityError
        self._psycopg = None
        self._dict_row_factory = None

        self.login_max_attempts = max(1, int(login_max_attempts))
        self.login_window_seconds = max(60, int(login_window_seconds))
        self.login_lockout_seconds = max(60, int(login_lockout_seconds))

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
            return

        rows = conn.execute("PRAGMA table_info(users)").fetchall()
        existing = {str(row["name"]) for row in rows}
        if "is_admin" not in existing:
            conn.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
        if "is_active" not in existing:
            conn.execute("ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")

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
                        is_active INTEGER NOT NULL DEFAULT 1
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
            else:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id BIGSERIAL PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        is_admin BOOLEAN NOT NULL DEFAULT FALSE,
                        is_active BOOLEAN NOT NULL DEFAULT TRUE
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
        if len(username_normalized) < 3:
            return False, "Username must be at least 3 characters."
        if len(password) < 10:
            return False, "Password must be at least 10 characters."

        password_hash = _hash_password(password)
        is_admin = self.user_count() == 0
        try:
            self._execute(
                """
                INSERT INTO users (username, password_hash, created_at, is_admin, is_active)
                VALUES (?, ?, ?, ?, ?)
                """,
                (username_normalized, password_hash, self._now_iso(), is_admin, True),
            )
            return True, ""
        except self._integrity_error as exc:
            if getattr(exc, "sqlstate", "") == "23505" or "unique" in str(exc).lower():
                return False, "That username already exists."
            return False, "Could not create account."

    def get_user_by_id(self, user_id: int) -> dict[str, str | int | bool] | None:
        row = self._fetchone(
            "SELECT id, username, created_at, is_admin, is_active FROM users WHERE id = ?",
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
            SELECT id, username, password_hash, is_admin, is_active
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
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (_hash_password(new_password), user_id),
        )
        username = str(row["username"])
        self.clear_login_failures(username, "")
        return True, ""

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

    def get_login_lockout_seconds(self, username: str, client_ip: str) -> int:
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

    def clear_login_failures(self, username: str, client_ip: str) -> None:
        keys = self._throttle_keys(username, client_ip)
        for scope, key_value in keys:
            self._execute(
                "DELETE FROM login_throttle WHERE scope = ? AND key_value = ?",
                (scope, key_value),
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
