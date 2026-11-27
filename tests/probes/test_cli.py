from __future__ import annotations

import json

import pytest

from remote_probe.cli import load_config


def _write_config(tmp_path, mode=0o600):
    certificate = tmp_path / "probe.crt"
    private_key = tmp_path / "probe.key"
    certificate.write_text("certificate", encoding="utf-8")
    private_key.write_text("private key", encoding="utf-8")
    private_key.chmod(0o600)
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "listen_address": "192.0.2.40",
                "port": 9443,
                "certificate_file": str(certificate),
                "private_key_file": str(private_key),
                "state_dir": str(tmp_path / "state"),
                "allowed_networks": ["192.0.2.0/24"],
                "token_hash": "",
                "pairing_code_hash": "a" * 64,
                "pairing_expires_at": 1_795_800_000,
                "workers": 2,
            }
        ),
        encoding="utf-8",
    )
    config.chmod(mode)
    return config


def test_load_config_accepts_private_service_config(tmp_path):
    config = load_config(_write_config(tmp_path))

    assert config["listen_address"] == "192.0.2.40"
    assert config["allowed_networks"] == ["192.0.2.0/24"]
    assert config["state_dir"] == tmp_path / "state"


def test_load_config_rejects_group_or_world_readable_config(tmp_path):
    config_path = _write_config(tmp_path, mode=0o644)

    with pytest.raises(ValueError, match="private, regular"):
        load_config(config_path)


def test_load_config_rejects_symlink(tmp_path):
    original = _write_config(tmp_path)
    link = tmp_path / "config-link.json"
    link.symlink_to(original)

    with pytest.raises(ValueError, match="cannot be read"):
        load_config(link)
