import base64
import hashlib
import hmac
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

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


class SecureStore:
    def __init__(self, db_path: str, encryption_key: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._fernet = Fernet(_derive_fernet_key(encryption_key))
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
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
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()
            return int(row["count"]) if row else 0

    def create_user(self, username: str, password: str) -> tuple[bool, str]:
        username_normalized = _normalize_username(username)
        if len(username_normalized) < 3:
            return False, "Username must be at least 3 characters."
        if len(password) < 10:
            return False, "Password must be at least 10 characters."

        password_hash = _hash_password(password)
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                    (username_normalized, password_hash, self._now_iso()),
                )
                conn.commit()
            return True, ""
        except sqlite3.IntegrityError:
            return False, "That username already exists."

    def authenticate_user(self, username: str, password: str) -> dict[str, str | int] | None:
        username_normalized = _normalize_username(username)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?",
                (username_normalized,),
            ).fetchone()
        if not row:
            return None
        if not _verify_password(password, str(row["password_hash"])):
            return None
        return {"id": int(row["id"]), "username": str(row["username"])}

    def _read_credential_row(self, user_id: int) -> sqlite3.Row | None:
        with self._connect() as conn:
            return conn.execute(
                """
                SELECT user_id, garmin_email, garmin_password, omron_email, omron_password, omron_country
                FROM user_credentials
                WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()

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
        with self._connect() as conn:
            conn.execute(
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
            conn.commit()

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
