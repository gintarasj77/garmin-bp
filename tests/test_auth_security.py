import atexit
import os
import re
import shutil
import unittest
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
        first = self._register(client, "adminuser", "Password123!")
        self.assertEqual(first.status_code, 302)

        second_client = self.app.test_client()
        second = self._register(second_client, "seconduser", "Password456!")
        self.assertEqual(second.status_code, 403)
        self.assertIn("Registration is disabled", second.get_data(as_text=True))

    def test_forgot_password_returns_generic_message(self):
        created, message = self.store.create_user("resetuser", "ResetPass123!")
        self.assertTrue(created, message)

        client = self.app.test_client()
        csrf = self._csrf_for_path(client, "/forgot-password")
        existing = client.post(
            "/forgot-password",
            data={"csrf_token": csrf, "username": "resetuser"},
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

    def test_post_requests_require_csrf_token(self):
        client = self.app.test_client()
        response = client.post(
            "/login",
            data={"username": "nouser", "password": "nopassword"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 403)

    def test_login_lockout_after_failed_attempts(self):
        created, message = self.store.create_user("lockuser", "CorrectPass123!")
        self.assertTrue(created, message)

        client = self.app.test_client()
        csrf = self._login_csrf(client)

        for _ in range(2):
            response = client.post(
                "/login",
                data={"csrf_token": csrf, "username": "lockuser", "password": "wrong-pass"},
                follow_redirects=False,
            )
            self.assertEqual(response.status_code, 401)

        locked = client.post(
            "/login",
            data={"csrf_token": csrf, "username": "lockuser", "password": "wrong-pass"},
            follow_redirects=False,
        )
        self.assertEqual(locked.status_code, 429)
        self.assertIn("Too many failed attempts", locked.get_data(as_text=True))

        still_locked = client.post(
            "/login",
            data={"csrf_token": csrf, "username": "lockuser", "password": "CorrectPass123!"},
            follow_redirects=False,
        )
        self.assertEqual(still_locked.status_code, 429)

    def test_reset_password_token_flow_and_one_time_use(self):
        created, message = self.store.create_user("tokenuser", "StartPass123!")
        self.assertTrue(created, message)
        issued, _, token = self.store.create_password_reset_token("tokenuser", ttl_seconds=3600)
        self.assertTrue(issued)
        self.assertTrue(token)

        active_session_client = self.app.test_client()
        active_login = self._login(active_session_client, "tokenuser", "StartPass123!")
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
        old_login = self._login(old_login_client, "tokenuser", "StartPass123!")
        self.assertEqual(old_login.status_code, 401)

        new_login_client = self.app.test_client()
        new_login = self._login(new_login_client, "tokenuser", "NewTokenPass123!")
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
                and event.get("username") == "tokenuser"
                for event in events
            )
        )

    def test_admin_page_access_control(self):
        created_admin, message_admin = self.store.create_user("adminone", "AdminPass123!")
        self.assertTrue(created_admin, message_admin)
        created_user, message_user = self.store.create_user("regularone", "UserPass123!")
        self.assertTrue(created_user, message_user)

        regular_client = self.app.test_client()
        login_regular = self._login(regular_client, "regularone", "UserPass123!")
        self.assertEqual(login_regular.status_code, 302)
        forbidden = regular_client.get("/admin/users", follow_redirects=False)
        self.assertEqual(forbidden.status_code, 302)
        self.assertTrue(forbidden.headers.get("Location", "").endswith("/"))

        admin_client = self.app.test_client()
        login_admin = self._login(admin_client, "adminone", "AdminPass123!")
        self.assertEqual(login_admin.status_code, 302)
        allowed = admin_client.get("/admin/users", follow_redirects=False)
        self.assertEqual(allowed.status_code, 200)
        self.assertIn("Admin users", allowed.get_data(as_text=True))

    def test_password_change_requires_current_password_and_updates_login(self):
        created, message = self.store.create_user("changepass", "OldPassword123!")
        self.assertTrue(created, message)

        client = self.app.test_client()
        login = self._login(client, "changepass", "OldPassword123!")
        self.assertEqual(login.status_code, 302)

        other_client = self.app.test_client()
        other_login = self._login(other_client, "changepass", "OldPassword123!")
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
        old_login = self._login(old_login_client, "changepass", "OldPassword123!")
        self.assertEqual(old_login.status_code, 401)

        new_login_client = self.app.test_client()
        new_login = self._login(new_login_client, "changepass", "NewPassword123!")
        self.assertEqual(new_login.status_code, 302)

        events = self.store.list_audit_events(limit=100)
        self.assertTrue(
            any(
                event.get("event_type") == "auth.password_change.success"
                and event.get("username") == "changepass"
                for event in events
            )
        )

    def test_admin_actions_are_audited(self):
        created_admin, msg_admin = self.store.create_user("adminaudit", "AdminAudit123!")
        self.assertTrue(created_admin, msg_admin)
        created_user, msg_user = self.store.create_user("memberaudit", "MemberAudit123!")
        self.assertTrue(created_user, msg_user)

        admin_id = self._user_id("adminaudit")
        member_id = self._user_id("memberaudit")

        client = self.app.test_client()
        login = self._login(client, "adminaudit", "AdminAudit123!")
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

    def test_account_delete_flow(self):
        created, message = self.store.create_user("deleteuser", "DeletePass123!")
        self.assertTrue(created, message)

        client = self.app.test_client()
        login = self._login(client, "deleteuser", "DeletePass123!")
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

        self.assertIsNone(self.store.authenticate_user("deleteuser", "DeletePass123!"))

    def test_last_admin_cannot_self_delete_when_other_users_exist(self):
        created_admin, message_admin = self.store.create_user("adminkeep", "AdminKeep123!")
        self.assertTrue(created_admin, message_admin)
        created_user, message_user = self.store.create_user("memberuser", "MemberPass123!")
        self.assertTrue(created_user, message_user)

        client = self.app.test_client()
        login = self._login(client, "adminkeep", "AdminKeep123!")
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
        self.assertIn("last admin", blocked.get_data(as_text=True))

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
