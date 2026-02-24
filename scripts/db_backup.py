from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence


def _tool_path(explicit: str | None, default_name: str) -> str:
    if explicit:
        return explicit
    resolved = shutil.which(default_name)
    if not resolved:
        raise RuntimeError(f"Required tool not found on PATH: {default_name}")
    return resolved


def _resolve_database_url(explicit: str | None, env_candidates: Sequence[str]) -> str:
    if explicit and explicit.strip():
        return explicit.strip()
    for env_name in env_candidates:
        value = os.getenv(env_name, "").strip()
        if value:
            return value
    joined = ", ".join(env_candidates)
    raise RuntimeError(
        f"Database URL is required. Pass --database-url or set one of: {joined}"
    )


def _run_command(command: list[str]) -> None:
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode == 0:
        return

    stderr = (completed.stderr or "").strip()
    stdout = (completed.stdout or "").strip()
    details = stderr or stdout or "no output"
    raise RuntimeError(f"Command failed (exit {completed.returncode}): {details}")


def build_backup_filename(prefix: str = "neon-backup", ts: datetime | None = None) -> str:
    timestamp = ts or datetime.now(timezone.utc)
    stamp = timestamp.strftime("%Y%m%d-%H%M%S")
    return f"{prefix}-{stamp}.dump"


def build_backup_command(
    pg_dump_bin: str,
    database_url: str,
    output_file: Path,
    compress: int,
) -> list[str]:
    return [
        pg_dump_bin,
        "--dbname",
        database_url,
        "--format=custom",
        "--compress",
        str(compress),
        "--no-owner",
        "--no-privileges",
        "--file",
        str(output_file),
    ]


def build_restore_command(
    pg_restore_bin: str,
    database_url: str,
    input_file: Path,
) -> list[str]:
    return [
        pg_restore_bin,
        "--dbname",
        database_url,
        "--clean",
        "--if-exists",
        "--no-owner",
        "--no-privileges",
        "--exit-on-error",
        "--single-transaction",
        str(input_file),
    ]


def command_backup(args: argparse.Namespace) -> int:
    database_url = _resolve_database_url(args.database_url, ("NEON_DATABASE_URL", "DATABASE_URL"))
    pg_dump_bin = _tool_path(args.pg_dump_bin, "pg_dump")
    pg_restore_bin = _tool_path(args.pg_restore_bin, "pg_restore")

    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    filename = args.filename or build_backup_filename(prefix=args.prefix)
    output_file = output_dir / filename
    if output_file.exists() and not args.overwrite:
        raise RuntimeError(
            f"Backup file already exists: {output_file}. Use --overwrite or choose another filename."
        )

    backup_cmd = build_backup_command(
        pg_dump_bin=pg_dump_bin,
        database_url=database_url,
        output_file=output_file,
        compress=args.compress,
    )
    _run_command(backup_cmd)

    if args.verify:
        verify_cmd = [pg_restore_bin, "--list", str(output_file)]
        _run_command(verify_cmd)

    print(f"Backup created: {output_file}")
    return 0


def command_restore(args: argparse.Namespace) -> int:
    if not args.force:
        raise RuntimeError(
            "Restore is destructive. Re-run with --force when you are sure about target database."
        )

    database_url = _resolve_database_url(
        args.database_url,
        ("TARGET_DATABASE_URL", "DATABASE_URL"),
    )
    pg_restore_bin = _tool_path(args.pg_restore_bin, "pg_restore")
    input_file = Path(args.input).resolve()
    if not input_file.exists():
        raise RuntimeError(f"Backup file does not exist: {input_file}")
    if not input_file.is_file():
        raise RuntimeError(f"Backup path is not a file: {input_file}")

    restore_cmd = build_restore_command(
        pg_restore_bin=pg_restore_bin,
        database_url=database_url,
        input_file=input_file,
    )
    _run_command(restore_cmd)
    print(f"Restore completed from: {input_file}")
    return 0


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Backup and restore PostgreSQL databases (Neon-compatible)."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    backup = subparsers.add_parser("backup", help="Create a pg_dump custom-format backup.")
    backup.add_argument("--database-url", default=None, help="Database URL. Falls back to NEON_DATABASE_URL.")
    backup.add_argument("--output-dir", default="backups", help="Directory where backup file is written.")
    backup.add_argument("--filename", default=None, help="Backup filename. Default: <prefix>-<UTC timestamp>.dump")
    backup.add_argument("--prefix", default="neon-backup", help="Filename prefix when --filename is omitted.")
    backup.add_argument("--compress", type=int, default=9, help="pg_dump compression level (0-9).")
    backup.add_argument("--verify", action="store_true", default=True, help="Verify backup with pg_restore --list.")
    backup.add_argument(
        "--no-verify",
        action="store_false",
        dest="verify",
        help="Skip backup verification step.",
    )
    backup.add_argument("--overwrite", action="store_true", help="Allow overwriting existing backup file.")
    backup.add_argument("--pg-dump-bin", default=None, help="Path to pg_dump binary.")
    backup.add_argument("--pg-restore-bin", default=None, help="Path to pg_restore binary.")
    backup.set_defaults(handler=command_backup)

    restore = subparsers.add_parser("restore", help="Restore a backup into target database.")
    restore.add_argument("--input", required=True, help="Path to .dump file produced by backup command.")
    restore.add_argument("--database-url", default=None, help="Target DB URL. Falls back to TARGET_DATABASE_URL.")
    restore.add_argument("--force", action="store_true", help="Required confirmation flag for destructive restore.")
    restore.add_argument("--pg-restore-bin", default=None, help="Path to pg_restore binary.")
    restore.set_defaults(handler=command_restore)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
