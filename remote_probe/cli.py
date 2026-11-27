"""Native service entry point for a remotely managed Orion probe."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import signal
import stat
from pathlib import Path
from typing import Any

from remote_probe.agent import ProbeAgent
from remote_probe.http_api import create_https_server

MAX_CONFIG_BYTES = 16 * 1024
CONFIG_FIELDS = {
    "listen_address",
    "port",
    "certificate_file",
    "private_key_file",
    "state_dir",
    "allowed_networks",
    "token_hash",
    "pairing_code_hash",
    "pairing_expires_at",
    "workers",
}


def load_config(path: Path) -> dict[str, Any]:
    """Read a service-owned, private JSON config without following symlinks."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid not in {0, os.getuid()}
                or info.st_mode & 0o022
                or info.st_mode & 0o007
                or (
                    info.st_uid != os.getuid()
                    and (
                        info.st_gid not in {*os.getgroups(), os.getgid()}
                        or not info.st_mode & 0o040
                    )
                )
                or (info.st_uid == os.getuid() and not info.st_mode & 0o400)
                or info.st_size > MAX_CONFIG_BYTES
            ):
                raise ValueError(
                    "probe config must be private, regular and readable by the service user"
                )
            raw = stream.read(MAX_CONFIG_BYTES + 1)
    except OSError:
        raise ValueError("probe config cannot be read") from None
    try:
        config = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("probe config is not valid JSON") from None
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("probe config exceeds the maximum size")
    if not isinstance(config, dict) or set(config) - CONFIG_FIELDS:
        raise ValueError("probe config has an unsupported shape")
    try:
        address = str(ipaddress.IPv4Address(config["listen_address"]))
        port = config["port"]
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
        ):
            raise TypeError
        networks = config["allowed_networks"]
        if not isinstance(networks, list) or not networks or len(networks) > 64:
            raise ValueError
        normalized = sorted(
            {str(ipaddress.ip_network(item, strict=False)) for item in networks}
        )
        workers = config.get("workers", 2)
        if (
            isinstance(workers, bool)
            or not isinstance(workers, int)
            or not 1 <= workers <= 8
        ):
            raise ValueError
        state_dir = Path(config["state_dir"])
        certificate = Path(config["certificate_file"])
        private_key = Path(config["private_key_file"])
        if (
            not state_dir.is_absolute()
            or not certificate.is_absolute()
            or not private_key.is_absolute()
        ):
            raise ValueError
        if not isinstance(config.get("token_hash", ""), str) or not isinstance(
            config.get("pairing_code_hash", ""), str
        ):
            raise TypeError
        expiry = config.get("pairing_expires_at", 0)
        if isinstance(expiry, bool) or not isinstance(expiry, int) or expiry < 0:
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise ValueError("probe config values are invalid") from None

    for file_path, private in ((certificate, False), (private_key, True)):
        try:
            file_info = file_path.lstat()
        except OSError:
            raise ValueError("probe TLS identity file is unavailable") from None
        if not stat.S_ISREG(file_info.st_mode) or file_info.st_uid != os.getuid():
            raise ValueError(
                "probe TLS identity files must be regular and service-owned"
            )
        if private and file_info.st_mode & 0o077:
            raise ValueError("probe private key permissions are too broad")
    return {
        **config,
        "listen_address": address,
        "allowed_networks": normalized,
        "state_dir": state_dir,
        "certificate_file": certificate,
        "private_key_file": private_key,
        "workers": workers,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the native Orion remote probe service"
    )
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    config = load_config(args.config)
    agent = ProbeAgent(
        config["state_dir"],
        config.get("token_hash", ""),
        config["allowed_networks"],
        workers=config["workers"],
        pairing_code_hash=config.get("pairing_code_hash", ""),
        pairing_expires_at=config.get("pairing_expires_at", 0),
    )
    server = create_https_server(
        config["listen_address"],
        config["port"],
        str(config["certificate_file"]),
        str(config["private_key_file"]),
        agent,
    )

    def stop(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        agent.close()


if __name__ == "__main__":
    main()
