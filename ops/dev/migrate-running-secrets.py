#!/usr/bin/env python3
"""Move active Orion dev container secrets into protected files without rotating them."""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import unquote, urlsplit


SECRET_KEYS = ("DEV_DB_PASSWORD", "DEV_SESSION_SECRET")


class MigrationError(Exception):
    pass


def inspect_service(root: Path, project: str, service: str) -> dict[str, str]:
    try:
        result = subprocess.run(
            [
                "docker", "compose", "-f", str(root / "ops/dev/compose.dev.yaml"),
                "--env-file", str(root / ".env"), "-p", project, "ps", "-q", service,
            ],
            check=True, capture_output=True, text=True,
        )
        container_id = result.stdout.strip().splitlines()[0]
        inspected = subprocess.run(
            ["docker", "inspect", container_id], check=True, capture_output=True, text=True,
        )
        env_items = json.loads(inspected.stdout)[0]["Config"]["Env"]
        return dict(item.split("=", 1) for item in env_items if "=" in item)
    except (subprocess.SubprocessError, IndexError, KeyError, ValueError, json.JSONDecodeError):
        raise MigrationError("Could not safely read the active container configuration") from None


def atomic_secret(path: Path, value: str, gid: int) -> None:
    if not value or "\x00" in value:
        raise MigrationError("An active required secret is empty or invalid")
    if path.exists() or path.is_symlink():
        if (
            path.is_symlink()
            or not stat.S_ISREG(path.lstat().st_mode)
            or path.read_text(encoding="utf-8") != value
        ):
            raise MigrationError("An existing protected secret differs; no files were changed")
        os.chown(path, os.getuid(), gid)
        os.chmod(path, 0o440)
        return
    fd, temp_name = tempfile.mkstemp(prefix=".secret-", dir=path.parent)
    temp = Path(temp_name)
    try:
        os.fchmod(fd, 0o440)
        os.fchown(fd, -1, gid)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    except Exception:
        temp.unlink(missing_ok=True)
        raise


def update_env(path: Path, gid: int) -> None:
    content = path.read_text(encoding="utf-8")
    lines = [line for line in content.splitlines() if line.split("=", 1)[0] not in SECRET_KEYS]
    lines = [line for line in lines if not line.startswith("DEV_SECRET_GID=")]
    lines.append(f"DEV_SECRET_GID={gid}")
    fd, temp_name = tempfile.mkstemp(prefix=".env-", dir=path.parent)
    temp = Path(temp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write("\n".join(lines) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    except Exception:
        temp.unlink(missing_ok=True)
        raise


def migrate(root: Path, project: str) -> None:
    compose_env = inspect_service(root, project, "postgres")
    api_env = inspect_service(root, project, "api")
    pg_password = compose_env.get("POSTGRES_PASSWORD", "")
    session = api_env.get("ORION_SESSION_SECRET", "")
    database_url = api_env.get("ORION_DATABASE_URL", "")
    parsed = urlsplit(database_url)
    database_password = unquote(parsed.password or "")
    if not pg_password or not session or not parsed.username or not database_password:
        raise MigrationError("Required active database/session settings are unavailable")
    if database_password != pg_password:
        raise MigrationError("Active PostgreSQL credentials do not match; no migration was applied")

    secret_dir = root / "data" / "secrets"
    secret_dir.mkdir(mode=0o710, parents=True, exist_ok=True)
    if secret_dir.is_symlink() or not secret_dir.is_dir():
        raise MigrationError("The protected secret path is not a regular directory")
    os.chmod(secret_dir, 0o710)
    gid = os.stat(secret_dir).st_gid
    secrets = (
        ("postgres_password", pg_password),
        ("database_password", database_password),
        ("session_secret", session),
    )
    # Check every pre-existing destination before creating any new file.
    for name, value in secrets:
        existing = secret_dir / name
        if (existing.exists() or existing.is_symlink()) and (
            existing.is_symlink()
            or not stat.S_ISREG(existing.lstat().st_mode)
            or existing.read_text(encoding="utf-8") != value
        ):
            raise MigrationError("An existing protected secret differs; no files were changed")
    for name, value in secrets:
        atomic_secret(secret_dir / name, value, gid)
    postgres_file = secret_dir / "postgres_password"
    database_file = secret_dir / "database_password"
    if postgres_file.read_text(encoding="utf-8") != database_file.read_text(encoding="utf-8"):
        raise MigrationError("PostgreSQL secret copies do not match")
    env_path = root / ".env"
    if env_path.is_symlink() or not stat.S_ISREG(env_path.lstat().st_mode):
        raise MigrationError("The deployment .env file is not a regular file")
    update_env(env_path, gid)
    print("Protected secret files created; direct dev secrets removed from .env")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path.cwd(), help="Sandbox Compose deployment directory")
    parser.add_argument("--project", default="orion-dev", help="Compose project containing the running stack")
    args = parser.parse_args()
    try:
        migrate(args.directory.resolve(), args.project)
    except (MigrationError, OSError, UnicodeError):
        print("Secret migration stopped safely; inspect prerequisites without displaying secret values", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
