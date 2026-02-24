import os
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts import db_backup


class DatabaseBackupScriptTests(unittest.TestCase):
    def test_build_backup_filename_uses_prefix_and_utc_stamp(self):
        ts = datetime(2026, 2, 24, 13, 45, 6, tzinfo=timezone.utc)
        name = db_backup.build_backup_filename(prefix="neon", ts=ts)
        self.assertEqual(name, "neon-20260224-134506.dump")

    def test_build_backup_command_uses_custom_dump(self):
        cmd = db_backup.build_backup_command(
            pg_dump_bin="pg_dump",
            database_url="postgresql://user:pass@host:5432/db",
            output_file=Path("backups/test.dump"),
            compress=9,
        )
        self.assertIn("--format=custom", cmd)
        self.assertIn("--no-owner", cmd)
        self.assertIn("--no-privileges", cmd)
        self.assertIn("--compress", cmd)

    def test_build_restore_command_uses_safe_flags(self):
        cmd = db_backup.build_restore_command(
            pg_restore_bin="pg_restore",
            database_url="postgresql://user:pass@host:5432/db",
            input_file=Path("backups/test.dump"),
        )
        self.assertIn("--clean", cmd)
        self.assertIn("--if-exists", cmd)
        self.assertIn("--single-transaction", cmd)
        self.assertIn("--exit-on-error", cmd)

    def test_restore_requires_force_flag(self):
        parser = db_backup.create_parser()
        args = parser.parse_args(["restore", "--input", "backups/test.dump"])
        with self.assertRaises(RuntimeError):
            db_backup.command_restore(args)

    def test_resolve_database_url_prefers_explicit_then_env(self):
        os.environ["NEON_DATABASE_URL"] = "postgresql://from-env"
        try:
            self.assertEqual(
                db_backup._resolve_database_url("postgresql://explicit", ("NEON_DATABASE_URL",)),
                "postgresql://explicit",
            )
            self.assertEqual(
                db_backup._resolve_database_url(None, ("NEON_DATABASE_URL",)),
                "postgresql://from-env",
            )
        finally:
            os.environ.pop("NEON_DATABASE_URL", None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
