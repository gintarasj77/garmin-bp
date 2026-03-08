import atexit
import os
import re
import shutil
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path


TMP_DIR = Path(__file__).resolve().parent / ".tmp"
TMP_DIR.mkdir(parents=True, exist_ok=True)
atexit.register(lambda: shutil.rmtree(TMP_DIR, ignore_errors=True))

os.environ["APP_DB_PATH"] = str(TMP_DIR / "test_app.db")
os.environ["DATABASE_URL"] = ""
os.environ["SESSION_COOKIE_SECURE"] = "0"
os.environ["PRODUCTION"] = "0"
os.environ["TRUST_PROXY_COUNT"] = "0"
os.environ["HSTS_ENABLED"] = "0"
os.environ["LOGIN_MAX_ATTEMPTS"] = "3"
os.environ["LOGIN_WINDOW_SECONDS"] = "900"
os.environ["LOGIN_LOCKOUT_SECONDS"] = "900"
os.environ["FLASK_SECRET_KEY"] = "unit-test-secret-key"
os.environ["CREDENTIALS_ENCRYPTION_KEY"] = "unit-test-credential-key"

import app as app_module  # noqa: E402  pylint: disable=wrong-import-position
from secure_store import SecureStore  # noqa: E402  pylint: disable=wrong-import-position


def _extract_csrf(html: str) -> str:
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    if not match:
        raise AssertionError("CSRF token not found in HTML response.")
    return match.group(1)


class AuthSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = app_module.app
        cls.app.config.update(TESTING=True)
        cls.store = app_module.STORE

    def setUp(self):
        os.environ.pop("ALLOW_REGISTRATION", None)
        self._reset_store()

    def _reset_store(self):
        self.store._execute("DELETE FROM audit_events")
        self.store._execute("DELETE FROM sync_history")
        self.store._execute("DELETE FROM login_throttle")
        self.store._execute("DELETE FROM password_reset_tokens")
        self.store._execute("DELETE FROM user_credentials")
        self.store._execute("DELETE FROM users")

    def _login_csrf(self, client):
        response = client.get("/login")
        self.assertEqual(response.status_code, 200)
        return _extract_csrf(response.get_data(as_text=True))

    def _account_csrf(self, client):
        response = client.get("/account")
        self.assertEqual(response.status_code, 200)
        return _extract_csrf(response.get_data(as_text=True))

    def _csrf_for_path(self, client, path: str):
        response = client.get(path)
        self.assertEqual(response.status_code, 200)
        return _extract_csrf(response.get_data(as_text=True))

    def _register(self, client, username: str, password: str):
        csrf = self._login_csrf(client)
        return client.post(
            "/register",
            data={
                "csrf_token": csrf,
                "register_username": username,
                "register_password": password,
                "register_confirm_password": password,
            },
            follow_redirects=False,
        )

    def _login(self, client, username: str, password: str):
        csrf = self._login_csrf(client)
        return client.post(
            "/login",
            data={
                "csrf_token": csrf,
                "username": username,
                "password": password,
            },
            follow_redirects=False,
        )

    def _user_id(self, username: str) -> int:
        for user in self.store.list_users():
            if str(user["username"]) == username:
                return int(user["id"])
        raise AssertionError(f"User not found: {username}")

    def test_registration_only_for_first_account_by_default(self):
        client = self.app.test_client()
        first = self._register(client, "adminuser@example.com", "Password123!")
        self.assertEqual(first.status_code, 302)

        second_client = self.app.test_client()
        second = self._register(second_client, "seconduser@example.com", "Password456!")
        self.assertEqual(second.status_code, 403)
        self.assertIn("Registration is disabled", second.get_data(as_text=True))

    def test_registration_requires_valid_email(self):
        client = self.app.test_client()
        response = self._register(client, "not-an-email", "Password123!")
        self.assertEqual(response.status_code, 400)
        self.assertIn("Email must be a valid address", response.get_data(as_text=True))

    def test_forgot_password_returns_generic_message(self):
        created, message = self.store.create_user("resetuser@example.com", "ResetPass123!")
        self.assertTrue(created, message)

        client = self.app.test_client()
        csrf = self._csrf_for_path(client, "/forgot-password")
        existing = client.post(
            "/forgot-password",
            data={"csrf_token": csrf, "username": "resetuser@example.com"},
            follow_redirects=False,
        )
        self.assertEqual(existing.status_code, 200)
        self.assertIn("If an account exists", existing.get_data(as_text=True))

        csrf = self._csrf_for_path(client, "/forgot-password")
        missing = client.post(
            "/forgot-password",
            data={"csrf_token": csrf, "username": "missinguser"},
            follow_redirects=False,
        )
        self.assertEqual(missing.status_code, 200)
        self.assertIn("If an account exists", missing.get_data(as_text=True))

    def test_forgot_password_is_rate_limited(self):
        created, message = self.store.create_user("ratelimituser@example.com", "RateLimitPass123!")
        self.assertTrue(created, message)

        client = self.app.test_client()

        for _ in range(3):
            csrf = self._csrf_for_path(client, "/forgot-password")
            response = client.post(
                "/forgot-password",
                data={"csrf_token": csrf, "username": "ratelimituser@example.com"},
                follow_redirects=False,
            )
            self.assertEqual(response.status_code, 200)

        csrf = self._csrf_for_path(client, "/forgot-password")
        blocked = client.post(
            "/forgot-password",
            data={"csrf_token": csrf, "username": "ratelimituser@example.com"},
            follow_redirects=False,
        )
        self.assertEqual(blocked.status_code, 429)
        self.assertIn("Too many reset attempts", blocked.get_data(as_text=True))

    def test_post_requests_require_csrf_token(self):
        client = self.app.test_client()
        response = client.post(
            "/login",
            data={"username": "nouser", "password": "nopassword"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 403)

    def test_login_lockout_after_failed_attempts(self):
        created, message = self.store.create_user("lockuser@example.com", "CorrectPass123!")
        self.assertTrue(created, message)

        client = self.app.test_client()
        csrf = self._login_csrf(client)

        for _ in range(2):
            response = client.post(
                "/login",
                data={"csrf_token": csrf, "username": "lockuser@example.com", "password": "wrong-pass"},
                follow_redirects=False,
            )
            self.assertEqual(response.status_code, 401)

        locked = client.post(
            "/login",
            data={"csrf_token": csrf, "username": "lockuser@example.com", "password": "wrong-pass"},
            follow_redirects=False,
        )
        self.assertEqual(locked.status_code, 429)
        self.assertIn("Too many failed attempts", locked.get_data(as_text=True))

        still_locked = client.post(
            "/login",
            data={"csrf_token": csrf, "username": "lockuser@example.com", "password": "CorrectPass123!"},
            follow_redirects=False,
        )
        self.assertEqual(still_locked.status_code, 429)

    def test_valid_login_still_succeeds_during_shared_ip_lockout(self):
        created_locked, locked_msg = self.store.create_user("iplockuser@example.com", "IpLockPass123!")
        self.assertTrue(created_locked, locked_msg)
        created_ok, ok_msg = self.store.create_user("ipokuser@example.com", "IpOkPass123!")
        self.assertTrue(created_ok, ok_msg)

        client = self.app.test_client()
        csrf = self._login_csrf(client)

        for _ in range(3):
            failed = client.post(
                "/login",
                data={"csrf_token": csrf, "username": "iplockuser@example.com", "password": "wrong-pass"},
                follow_redirects=False,
            )
            if _ < 2:
                self.assertEqual(failed.status_code, 401)
            else:
                self.assertEqual(failed.status_code, 429)

        success_other = client.post(
            "/login",
            data={"csrf_token": csrf, "username": "ipokuser@example.com", "password": "IpOkPass123!"},
            follow_redirects=False,
        )
        self.assertEqual(success_other.status_code, 302)
        self.assertTrue(success_other.headers.get("Location", "").endswith("/"))

        blocked_client = self.app.test_client()
        csrf_blocked = self._login_csrf(blocked_client)
        still_blocked = blocked_client.post(
            "/login",
            data={"csrf_token": csrf_blocked, "username": "missing@example.com", "password": "wrong-pass"},
            follow_redirects=False,
        )
        self.assertEqual(still_blocked.status_code, 429)
        self.assertIn("Too many failed attempts", still_blocked.get_data(as_text=True))

        locked_client = self.app.test_client()
        csrf_locked = self._login_csrf(locked_client)
        post_success_attempt = locked_client.post(
            "/login",
            data={"csrf_token": csrf_locked, "username": "iplockuser@example.com", "password": "IpLockPass123!"},
            follow_redirects=False,
        )
        self.assertEqual(post_success_attempt.status_code, 429)

    def test_reset_password_token_flow_and_one_time_use(self):
        created, message = self.store.create_user("tokenuser@example.com", "StartPass123!")
        self.assertTrue(created, message)
        issued, _, token = self.store.create_password_reset_token("tokenuser@example.com", ttl_seconds=3600)
        self.assertTrue(issued)
        self.assertTrue(token)

        active_session_client = self.app.test_client()
        active_login = self._login(active_session_client, "tokenuser@example.com", "StartPass123!")
        self.assertEqual(active_login.status_code, 302)

        client = self.app.test_client()
        csrf = self._csrf_for_path(client, f"/reset-password/{token}")

        mismatch = client.post(
            f"/reset-password/{token}",
            data={
                "csrf_token": csrf,
                "new_password": "NewTokenPass123!",
                "confirm_password": "DifferentPass123!",
            },
            follow_redirects=False,
        )
        self.assertEqual(mismatch.status_code, 400)
        self.assertIn("Passwords do not match", mismatch.get_data(as_text=True))

        csrf = self._csrf_for_path(client, f"/reset-password/{token}")
        reset = client.post(
            f"/reset-password/{token}",
            data={
                "csrf_token": csrf,
                "new_password": "NewTokenPass123!",
                "confirm_password": "NewTokenPass123!",
            },
            follow_redirects=False,
        )
        self.assertEqual(reset.status_code, 200)
        self.assertIn("Password reset successful", reset.get_data(as_text=True))

        invalidated = active_session_client.get("/", follow_redirects=False)
        self.assertEqual(invalidated.status_code, 302)
        self.assertTrue(invalidated.headers.get("Location", "").endswith("/login"))

        old_login_client = self.app.test_client()
        old_login = self._login(old_login_client, "tokenuser@example.com", "StartPass123!")
        self.assertEqual(old_login.status_code, 401)

        new_login_client = self.app.test_client()
        new_login = self._login(new_login_client, "tokenuser@example.com", "NewTokenPass123!")
        self.assertEqual(new_login.status_code, 302)

        reuse_client = self.app.test_client()
        csrf_reuse = self._login_csrf(reuse_client)
        reused = reuse_client.post(
            f"/reset-password/{token}",
            data={
                "csrf_token": csrf_reuse,
                "new_password": "ReusePass123!",
                "confirm_password": "ReusePass123!",
            },
            follow_redirects=False,
        )
        self.assertEqual(reused.status_code, 400)
        self.assertIn("already been used", reused.get_data(as_text=True))

        events = self.store.list_audit_events(limit=100)
        self.assertTrue(
            any(
                event.get("event_type") == "auth.password_reset.success"
                and event.get("username") == "tokenuser@example.com"
                for event in events
            )
        )

    def test_admin_page_access_control(self):
        created_admin, message_admin = self.store.create_user("adminone@example.com", "AdminPass123!")
        self.assertTrue(created_admin, message_admin)
        created_user, message_user = self.store.create_user("regularone@example.com", "UserPass123!")
        self.assertTrue(created_user, message_user)

        regular_client = self.app.test_client()
        login_regular = self._login(regular_client, "regularone@example.com", "UserPass123!")
        self.assertEqual(login_regular.status_code, 302)
        forbidden = regular_client.get("/admin/users", follow_redirects=False)
        self.assertEqual(forbidden.status_code, 302)
        self.assertTrue(forbidden.headers.get("Location", "").endswith("/"))

        admin_client = self.app.test_client()
        login_admin = self._login(admin_client, "adminone@example.com", "AdminPass123!")
        self.assertEqual(login_admin.status_code, 302)
        allowed = admin_client.get("/admin/users", follow_redirects=False)
        self.assertEqual(allowed.status_code, 200)
        self.assertIn("Admin users", allowed.get_data(as_text=True))

    def test_password_change_requires_current_password_and_updates_login(self):
        created, message = self.store.create_user("changepass@example.com", "OldPassword123!")
        self.assertTrue(created, message)

        client = self.app.test_client()
        login = self._login(client, "changepass@example.com", "OldPassword123!")
        self.assertEqual(login.status_code, 302)

        other_client = self.app.test_client()
        other_login = self._login(other_client, "changepass@example.com", "OldPassword123!")
        self.assertEqual(other_login.status_code, 302)

        csrf = self._account_csrf(client)
        wrong_current = client.post(
            "/account/password",
            data={
                "csrf_token": csrf,
                "current_password": "bad-current",
                "new_password": "NewPassword123!",
                "confirm_password": "NewPassword123!",
            },
            follow_redirects=False,
        )
        self.assertEqual(wrong_current.status_code, 400)
        self.assertIn("Current password is incorrect", wrong_current.get_data(as_text=True))

        csrf = self._account_csrf(client)
        changed = client.post(
            "/account/password",
            data={
                "csrf_token": csrf,
                "current_password": "OldPassword123!",
                "new_password": "NewPassword123!",
                "confirm_password": "NewPassword123!",
            },
            follow_redirects=False,
        )
        self.assertEqual(changed.status_code, 200)
        self.assertIn("Please sign in again", changed.get_data(as_text=True))

        current_session_after_change = client.get("/", follow_redirects=False)
        self.assertEqual(current_session_after_change.status_code, 302)
        self.assertTrue(current_session_after_change.headers.get("Location", "").endswith("/login"))

        other_session_after_change = other_client.get("/", follow_redirects=False)
        self.assertEqual(other_session_after_change.status_code, 302)
        self.assertTrue(other_session_after_change.headers.get("Location", "").endswith("/login"))

        old_login_client = self.app.test_client()
        old_login = self._login(old_login_client, "changepass@example.com", "OldPassword123!")
        self.assertEqual(old_login.status_code, 401)

        new_login_client = self.app.test_client()
        new_login = self._login(new_login_client, "changepass@example.com", "NewPassword123!")
        self.assertEqual(new_login.status_code, 302)

        events = self.store.list_audit_events(limit=100)
        self.assertTrue(
            any(
                event.get("event_type") == "auth.password_change.success"
                and event.get("username") == "changepass@example.com"
                for event in events
            )
        )

    def test_admin_actions_are_audited(self):
        created_admin, msg_admin = self.store.create_user("adminaudit@example.com", "AdminAudit123!")
        self.assertTrue(created_admin, msg_admin)
        created_user, msg_user = self.store.create_user("memberaudit@example.com", "MemberAudit123!")
        self.assertTrue(created_user, msg_user)

        admin_id = self._user_id("adminaudit@example.com")
        member_id = self._user_id("memberaudit@example.com")

        client = self.app.test_client()
        login = self._login(client, "adminaudit@example.com", "AdminAudit123!")
        self.assertEqual(login.status_code, 302)

        csrf = self._csrf_for_path(client, "/admin/users")
        disable = client.post(
            f"/admin/users/{member_id}/disable",
            data={"csrf_token": csrf},
            follow_redirects=False,
        )
        self.assertEqual(disable.status_code, 302)

        events = self.store.list_audit_events(limit=100)
        self.assertTrue(
            any(
                event.get("event_type") == "admin.user.disable"
                and event.get("outcome") == "success"
                and event.get("actor_user_id") == admin_id
                and event.get("target_user_id") == member_id
                for event in events
            )
        )

    def test_sync_history_records_success_and_counts(self):
        created, message = self.store.create_user("syncuser@example.com", "SyncUserPass123!")
        self.assertTrue(created, message)
        user_id = self._user_id("syncuser@example.com")

        class FakeMeasurement:
            def __init__(self, systolic: int, diastolic: int, pulse: int, offset_minutes: int):
                self.systolic = systolic
                self.diastolic = diastolic
                self.pulse = pulse
                self.timeZone = timezone.utc
                base = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
                self.measurementDate = int((base.timestamp() + offset_minutes * 60) * 1000)

        original_load = app_module.load_omron_measurements
        original_sync = app_module.sync_to_garmin
        app_module.load_omron_measurements = lambda *_args, **_kwargs: [
            FakeMeasurement(120, 80, 65, 0),
            FakeMeasurement(122, 82, 66, 5),
        ]
        app_module.sync_to_garmin = lambda readings, *_args, **_kwargs: len(readings)

        try:
            client = self.app.test_client()
            login = self._login(client, "syncuser@example.com", "SyncUserPass123!")
            self.assertEqual(login.status_code, 302)

            csrf = self._csrf_for_path(client, "/")
            response = client.post(
                "/sync-omron",
                data={
                    "csrf_token": csrf,
                    "omron_email": "omron@example.com",
                    "omron_password": "omron-secret",
                    "omron_country": "US",
                    "garmin_email": "garmin@example.com",
                    "garmin_password": "garmin-secret",
                    "save_garmin": "on",
                    "save_omron": "on",
                },
                headers={"Accept": "application/json"},
                follow_redirects=False,
            )
        finally:
            app_module.load_omron_measurements = original_load
            app_module.sync_to_garmin = original_sync

        self.assertEqual(response.status_code, 200)
        payload = response.get_json() or {}
        self.assertIn("history_id", payload)

        history = self.store.list_sync_history(user_id, limit=20)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].get("status"), "success")
        self.assertEqual(history[0].get("readings_found"), 2)
        self.assertEqual(history[0].get("readings_uploaded"), 2)

        counts = self.store.get_sync_history_counts(user_id)
        self.assertEqual(counts.get("total"), 1)
        self.assertEqual(counts.get("success"), 1)

        page = self.app.test_client()
        login_page = self._login(page, "syncuser@example.com", "SyncUserPass123!")
        self.assertEqual(login_page.status_code, 302)
        history_page = page.get("/sync-history", follow_redirects=False)
        self.assertEqual(history_page.status_code, 200)
        html = history_page.get_data(as_text=True)
        self.assertIn("Sync history", html)
        self.assertIn("Successfully synced", html)

    def test_sync_saves_garmin_region_and_retry_reuses_it(self):
        created, message = self.store.create_user("garmincn@example.com", "GarminCnPass123!")
        self.assertTrue(created, message)

        class FakeMeasurement:
            def __init__(self):
                self.systolic = 121
                self.diastolic = 81
                self.pulse = 64
                self.timeZone = timezone.utc
                self.measurementDate = int(datetime(2026, 1, 4, 7, 0, tzinfo=timezone.utc).timestamp() * 1000)

        original_load = app_module.load_omron_measurements
        original_sync = app_module.sync_to_garmin
        sync_regions: list[bool] = []
        app_module.load_omron_measurements = lambda *_args, **_kwargs: [FakeMeasurement()]

        def fake_sync(readings, email, password, is_cn):
            self.assertTrue(email)
            self.assertTrue(password)
            self.assertEqual(len(readings), 1)
            sync_regions.append(bool(is_cn))
            return len(readings)

        app_module.sync_to_garmin = fake_sync

        try:
            client = self.app.test_client()
            login = self._login(client, "garmincn@example.com", "GarminCnPass123!")
            self.assertEqual(login.status_code, 302)

            csrf = self._csrf_for_path(client, "/")
            first_sync = client.post(
                "/sync-omron",
                data={
                    "csrf_token": csrf,
                    "omron_email": "omron@example.com",
                    "omron_password": "omron-secret",
                    "omron_country": "US",
                    "garmin_email": "garmin@example.com",
                    "garmin_password": "garmin-secret",
                    "garmin_region": "CN",
                    "save_garmin": "on",
                    "save_omron": "on",
                },
                headers={"Accept": "application/json"},
                follow_redirects=False,
            )
            self.assertEqual(first_sync.status_code, 200)
            history_id = int((first_sync.get_json() or {}).get("history_id"))

            status_response = client.get("/api/credentials", follow_redirects=False)
            self.assertEqual(status_response.status_code, 200)
            status_payload = status_response.get_json() or {}
            self.assertTrue(status_payload.get("garmin", {}).get("saved"))
            self.assertEqual(status_payload.get("garmin", {}).get("region"), "CN")
            self.assertTrue(status_payload.get("garmin", {}).get("is_cn"))

            csrf = self._csrf_for_path(client, "/sync-history")
            retry = client.post(
                f"/sync-history/{history_id}/retry",
                data={"csrf_token": csrf},
                follow_redirects=False,
            )
            self.assertEqual(retry.status_code, 302)
        finally:
            app_module.load_omron_measurements = original_load
            app_module.sync_to_garmin = original_sync

        self.assertEqual(sync_regions, [True, True])

    def test_load_omron_measurements_aggregates_all_bpm_devices(self):
        class FakeDevice:
            def __init__(self, device_id: str, category):
                self.device_id = device_id
                self.category = category

        class FakeOmronClient:
            def __init__(self):
                self.closed = False

            def get_registered_devices(self, days=None):
                return [
                    FakeDevice("bpm-1", app_module.DeviceCategory.BPM),
                    FakeDevice("bpm-2", app_module.DeviceCategory.BPM),
                    FakeDevice("scale-1", app_module.DeviceCategory.SCALE),
                ]

            def get_measurements(self, device, searchDateFrom=0, searchDateTo=0):
                if device.device_id == "bpm-1":
                    return [
                        app_module.BPMeasurement(
                            systolic=120,
                            diastolic=80,
                            pulse=65,
                            measurementDate=1000,
                            timeZone=timezone.utc,
                        ),
                        app_module.BPMeasurement(
                            systolic=122,
                            diastolic=82,
                            pulse=66,
                            measurementDate=2000,
                            timeZone=timezone.utc,
                        ),
                    ]
                if device.device_id == "bpm-2":
                    return [
                        app_module.BPMeasurement(
                            systolic=120,
                            diastolic=80,
                            pulse=65,
                            measurementDate=1000,
                            timeZone=timezone.utc,
                        ),
                        app_module.BPMeasurement(
                            systolic=124,
                            diastolic=84,
                            pulse=67,
                            measurementDate=3000,
                            timeZone=timezone.utc,
                        ),
                    ]
                return []

            def close(self):
                self.closed = True

        fake_client = FakeOmronClient()
        original_login = app_module.login_omron
        app_module.login_omron = lambda *_args, **_kwargs: (fake_client, "refresh-token")
        try:
            measurements = app_module.load_omron_measurements("omron@example.com", "omron-secret", "US", 30)
        finally:
            app_module.login_omron = original_login

        self.assertTrue(fake_client.closed)
        self.assertEqual([measurement.measurementDate for measurement in measurements], [1000, 2000, 3000])

    def test_sync_history_retry_creates_retry_entry(self):
        created, message = self.store.create_user("retrysync@example.com", "RetrySyncPass123!")
        self.assertTrue(created, message)
        user_id = self._user_id("retrysync@example.com")

        class FakeMeasurement:
            def __init__(self):
                self.systolic = 118
                self.diastolic = 79
                self.pulse = 62
                self.timeZone = timezone.utc
                self.measurementDate = int(datetime(2026, 1, 2, 8, 0, tzinfo=timezone.utc).timestamp() * 1000)

        original_load = app_module.load_omron_measurements
        original_sync = app_module.sync_to_garmin

        call_count = {"value": 0}

        def fake_load(email, password, country, _days):
            self.assertTrue(email)
            self.assertTrue(password)
            self.assertTrue(country)
            call_count["value"] += 1
            return [FakeMeasurement()]

        app_module.load_omron_measurements = fake_load
        app_module.sync_to_garmin = lambda readings, *_args, **_kwargs: len(readings)

        try:
            client = self.app.test_client()
            login = self._login(client, "retrysync@example.com", "RetrySyncPass123!")
            self.assertEqual(login.status_code, 302)

            csrf = self._csrf_for_path(client, "/")
            first_sync = client.post(
                "/sync-omron",
                data={
                    "csrf_token": csrf,
                    "omron_email": "omron@example.com",
                    "omron_password": "omron-secret",
                    "omron_country": "US",
                    "garmin_email": "garmin@example.com",
                    "garmin_password": "garmin-secret",
                    "save_garmin": "on",
                    "save_omron": "on",
                },
                headers={"Accept": "application/json"},
                follow_redirects=False,
            )
            self.assertEqual(first_sync.status_code, 200)
            first_history_id = int((first_sync.get_json() or {}).get("history_id"))

            csrf = self._csrf_for_path(client, "/sync-history")
            retry = client.post(
                f"/sync-history/{first_history_id}/retry",
                data={"csrf_token": csrf},
                follow_redirects=False,
            )
            self.assertEqual(retry.status_code, 302)
        finally:
            app_module.load_omron_measurements = original_load
            app_module.sync_to_garmin = original_sync

        history = self.store.list_sync_history(user_id, limit=20)
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0].get("trigger_source"), "retry")
        self.assertEqual(history[0].get("retry_of_id"), first_history_id)
        self.assertEqual(history[0].get("status"), "success")
        self.assertGreaterEqual(call_count["value"], 2)

    def test_sync_history_retry_requires_saved_credentials(self):
        created, message = self.store.create_user("retrynosave@example.com", "RetryNoSavePass123!")
        self.assertTrue(created, message)
        user_id = self._user_id("retrynosave@example.com")

        class FakeMeasurement:
            def __init__(self):
                self.systolic = 117
                self.diastolic = 78
                self.pulse = 61
                self.timeZone = timezone.utc
                self.measurementDate = int(datetime(2026, 1, 3, 9, 0, tzinfo=timezone.utc).timestamp() * 1000)

        original_load = app_module.load_omron_measurements
        original_sync = app_module.sync_to_garmin
        app_module.load_omron_measurements = lambda *_args, **_kwargs: [FakeMeasurement()]
        app_module.sync_to_garmin = lambda readings, *_args, **_kwargs: len(readings)

        try:
            client = self.app.test_client()
            login = self._login(client, "retrynosave@example.com", "RetryNoSavePass123!")
            self.assertEqual(login.status_code, 302)

            csrf = self._csrf_for_path(client, "/")
            first_sync = client.post(
                "/sync-omron",
                data={
                    "csrf_token": csrf,
                    "omron_email": "omron@example.com",
                    "omron_password": "omron-secret",
                    "omron_country": "US",
                    "garmin_email": "garmin@example.com",
                    "garmin_password": "garmin-secret",
                },
                headers={"Accept": "application/json"},
                follow_redirects=False,
            )
            self.assertEqual(first_sync.status_code, 200)
            first_history_id = int((first_sync.get_json() or {}).get("history_id"))

            csrf = self._csrf_for_path(client, "/sync-history")
            retry = client.post(
                f"/sync-history/{first_history_id}/retry",
                data={"csrf_token": csrf},
                follow_redirects=False,
            )
        finally:
            app_module.load_omron_measurements = original_load
            app_module.sync_to_garmin = original_sync

        self.assertEqual(retry.status_code, 302)
        location = retry.headers.get("Location", "")
        self.assertIn("/sync-history?error=", location)
        self.assertIn("Retry+requires+saved+Garmin+and+OMRON+credentials", location)

        history = self.store.list_sync_history(user_id, limit=20)
        self.assertEqual(len(history), 1)

    def test_concurrent_user_creation_assigns_single_admin(self):
        race_db_path = TMP_DIR / "race_store.db"
        if race_db_path.exists():
            race_db_path.unlink()

        race_store = SecureStore(
            encryption_key="race-store-key",
            db_path=str(race_db_path),
            login_max_attempts=3,
            login_window_seconds=900,
            login_lockout_seconds=900,
        )
        barrier = threading.Barrier(2)
        original_begin = race_store._begin_user_write

        def synchronized_begin(conn):
            barrier.wait()
            return original_begin(conn)

        race_store._begin_user_write = synchronized_begin  # type: ignore[method-assign]

        results: list[tuple[bool, str]] = []
        errors: list[Exception] = []
        results_lock = threading.Lock()

        def worker(username: str):
            try:
                result = race_store.create_user(username, "ConcurrentPass123!")
                with results_lock:
                    results.append(result)
            except Exception as exc:  # pylint: disable=broad-except
                with results_lock:
                    errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=("concurrent-one@example.com",)),
            threading.Thread(target=worker, args=("concurrent-two@example.com",)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        self.assertTrue(all(result[0] for result in results))

        admins = [user for user in race_store.list_users() if bool(user.get("is_admin"))]
        self.assertEqual(len(admins), 1)

    def test_concurrent_admin_disable_keeps_one_active_admin(self):
        race_db_path = TMP_DIR / "disable_race_store.db"
        if race_db_path.exists():
            race_db_path.unlink()

        race_store = SecureStore(
            encryption_key="disable-race-key",
            db_path=str(race_db_path),
            login_max_attempts=3,
            login_window_seconds=900,
            login_lockout_seconds=900,
        )
        created_one, msg_one = race_store.create_user("disable-one@example.com", "DisableOnePass123!")
        self.assertTrue(created_one, msg_one)
        created_two, msg_two = race_store.create_user("disable-two@example.com", "DisableTwoPass123!")
        self.assertTrue(created_two, msg_two)
        race_store._execute(
            "UPDATE users SET is_admin = ? WHERE username = ?",
            (True, "disable-two@example.com"),
        )

        users = {user["username"]: int(user["id"]) for user in race_store.list_users()}
        barrier = threading.Barrier(2)
        original_begin = race_store._begin_user_write

        def synchronized_begin(conn):
            barrier.wait()
            return original_begin(conn)

        race_store._begin_user_write = synchronized_begin  # type: ignore[method-assign]

        results: list[tuple[bool, str]] = []
        results_lock = threading.Lock()

        def worker(actor_user_id: int, target_user_id: int):
            result = race_store.set_user_active(actor_user_id, target_user_id, False)
            with results_lock:
                results.append(result)

        threads = [
            threading.Thread(
                target=worker,
                args=(users["disable-one@example.com"], users["disable-two@example.com"]),
            ),
            threading.Thread(
                target=worker,
                args=(users["disable-two@example.com"], users["disable-one@example.com"]),
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(len(results), 2)
        self.assertEqual(sum(1 for ok, _ in results if ok), 1)
        self.assertEqual(sum(1 for ok, _ in results if not ok), 1)
        self.assertTrue(any("last active admin" in message for ok, message in results if not ok))

        active_admins = [user for user in race_store.list_users() if user["is_admin"] and user["is_active"]]
        self.assertEqual(len(active_admins), 1)

    def test_account_delete_flow(self):
        created, message = self.store.create_user("deleteuser@example.com", "DeletePass123!")
        self.assertTrue(created, message)

        client = self.app.test_client()
        login = self._login(client, "deleteuser@example.com", "DeletePass123!")
        self.assertEqual(login.status_code, 302)

        csrf = self._account_csrf(client)
        bad_confirm = client.post(
            "/account/delete",
            data={
                "csrf_token": csrf,
                "delete_current_password": "DeletePass123!",
                "delete_confirmation": "NOPE",
            },
            follow_redirects=False,
        )
        self.assertEqual(bad_confirm.status_code, 400)
        self.assertIn("confirm account deletion", bad_confirm.get_data(as_text=True))

        csrf = self._account_csrf(client)
        bad_password = client.post(
            "/account/delete",
            data={
                "csrf_token": csrf,
                "delete_current_password": "WrongPass123!",
                "delete_confirmation": "DELETE",
            },
            follow_redirects=False,
        )
        self.assertEqual(bad_password.status_code, 400)
        self.assertIn("Current password is incorrect", bad_password.get_data(as_text=True))

        csrf = self._account_csrf(client)
        deleted = client.post(
            "/account/delete",
            data={
                "csrf_token": csrf,
                "delete_current_password": "DeletePass123!",
                "delete_confirmation": "DELETE",
            },
            follow_redirects=False,
        )
        self.assertEqual(deleted.status_code, 200)
        self.assertIn("Account deleted", deleted.get_data(as_text=True))

        self.assertIsNone(self.store.authenticate_user("deleteuser@example.com", "DeletePass123!"))

    def test_last_admin_cannot_self_delete_when_other_users_exist(self):
        created_admin, message_admin = self.store.create_user("adminkeep@example.com", "AdminKeep123!")
        self.assertTrue(created_admin, message_admin)
        created_user, message_user = self.store.create_user("memberuser@example.com", "MemberPass123!")
        self.assertTrue(created_user, message_user)

        client = self.app.test_client()
        login = self._login(client, "adminkeep@example.com", "AdminKeep123!")
        self.assertEqual(login.status_code, 302)

        csrf = self._account_csrf(client)
        blocked = client.post(
            "/account/delete",
            data={
                "csrf_token": csrf,
                "delete_current_password": "AdminKeep123!",
                "delete_confirmation": "DELETE",
            },
            follow_redirects=False,
        )
        self.assertEqual(blocked.status_code, 400)
        self.assertIn("last active admin", blocked.get_data(as_text=True))

    def test_last_active_admin_cannot_self_delete_when_only_disabled_admin_remains(self):
        created_admin, message_admin = self.store.create_user("activeadmin@example.com", "ActiveAdmin123!")
        self.assertTrue(created_admin, message_admin)
        created_other, message_other = self.store.create_user("disabledadmin@example.com", "DisabledAdmin123!")
        self.assertTrue(created_other, message_other)
        self.store._execute(
            "UPDATE users SET is_admin = ?, is_active = ? WHERE username = ?",
            (True, False, "disabledadmin@example.com"),
        )

        client = self.app.test_client()
        login = self._login(client, "activeadmin@example.com", "ActiveAdmin123!")
        self.assertEqual(login.status_code, 302)

        csrf = self._account_csrf(client)
        blocked = client.post(
            "/account/delete",
            data={
                "csrf_token": csrf,
                "delete_current_password": "ActiveAdmin123!",
                "delete_confirmation": "DELETE",
            },
            follow_redirects=False,
        )
        self.assertEqual(blocked.status_code, 400)
        self.assertIn("last active admin", blocked.get_data(as_text=True))

    def test_store_recovers_broken_state_to_one_active_admin(self):
        recovery_db_path = TMP_DIR / "recovery_store.db"
        if recovery_db_path.exists():
            recovery_db_path.unlink()

        initial_store = SecureStore(
            encryption_key="recovery-store-key",
            db_path=str(recovery_db_path),
            login_max_attempts=3,
            login_window_seconds=900,
            login_lockout_seconds=900,
        )
        created_admin, msg_admin = initial_store.create_user("recoveradmin@example.com", "RecoverAdmin123!")
        self.assertTrue(created_admin, msg_admin)
        created_user, msg_user = initial_store.create_user("recoveruser@example.com", "RecoverUser123!")
        self.assertTrue(created_user, msg_user)
        initial_store._execute(
            "UPDATE users SET is_active = ? WHERE username = ?",
            (False, "recoveradmin@example.com"),
        )

        recovered_store = SecureStore(
            encryption_key="recovery-store-key",
            db_path=str(recovery_db_path),
            login_max_attempts=3,
            login_window_seconds=900,
            login_lockout_seconds=900,
        )
        active_admins = [user for user in recovered_store.list_users() if user["is_admin"] and user["is_active"]]
        self.assertEqual(len(active_admins), 1)
        self.assertEqual(active_admins[0]["username"], "recoveradmin@example.com")

    def test_healthz_returns_alive(self):
        client = self.app.test_client()
        response = client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload.get("status"), "alive")
        self.assertEqual(response.headers.get("Cache-Control"), "no-store")

    def test_readyz_returns_ready_when_dependencies_ok(self):
        client = self.app.test_client()
        response = client.get("/readyz")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        checks = payload.get("checks", {})

        self.assertEqual(payload.get("status"), "ready")
        self.assertEqual(checks.get("database", {}).get("status"), "ok")
        self.assertEqual(checks.get("crypto", {}).get("status"), "ok")
        self.assertEqual(response.headers.get("Cache-Control"), "no-store")

    def test_readyz_returns_503_when_database_check_fails(self):
        client = self.app.test_client()
        original_check_database = self.store.check_database
        self.store.check_database = lambda: (False, "database query failed")
        try:
            response = client.get("/readyz")
        finally:
            self.store.check_database = original_check_database

        self.assertEqual(response.status_code, 503)
        payload = response.get_json()
        checks = payload.get("checks", {})
        self.assertEqual(payload.get("status"), "not_ready")
        self.assertEqual(checks.get("database", {}).get("status"), "fail")

    def test_security_headers_present(self):
        client = self.app.test_client()
        response = client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(response.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")
        self.assertIn("default-src 'self'", response.headers.get("Content-Security-Policy", ""))
        self.assertIn("frame-ancestors 'none'", response.headers.get("Content-Security-Policy", ""))


if __name__ == "__main__":
    unittest.main(verbosity=2)

