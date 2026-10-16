"""Offline checks for backup directory containment."""

import xml.etree.ElementTree as ET
from datetime import UTC, datetime

import pytest

from custom_components.paloalto_firewall.services import _write_backup


@pytest.mark.parametrize("serial,hostname", [(".", "fw"), ("..", "fw"), ("serial", "."), ("serial", "..")])
def test_backup_rejects_dot_components(tmp_path, serial, hostname) -> None:
    root = tmp_path / "backups"
    outside = tmp_path / "fw_20261016T000000000000Z.xml"
    outside.write_text("keep me")
    with pytest.raises(ValueError, match="Invalid backup path component"):
        _write_backup(root, serial, hostname, ET.Element("config"), 1, datetime.now(UTC))
    assert outside.read_text() == "keep me"
    assert not root.exists()


def test_backup_rejects_symlinked_folder(tmp_path) -> None:
    root = tmp_path / "backups"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "serial").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="escapes"):
        _write_backup(root, "serial", "fw", ET.Element("config"), 1, datetime.now(UTC))
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("target_exists", [False, True])
def test_backup_rejects_symlinked_file_before_write_or_prune(tmp_path, target_exists) -> None:
    root = tmp_path / "backups"
    folder = root / "serial"
    folder.mkdir(parents=True)
    outside = tmp_path / "outside.xml"
    if target_exists:
        outside.write_text("keep me")
    (folder / "fw_20261016T000000000000Z.xml").symlink_to(outside)
    with pytest.raises(ValueError, match="escapes"):
        _write_backup(root, "serial", "fw", ET.Element("config"), 1, datetime.now(UTC))
    assert list(folder.iterdir()) == [folder / "fw_20261016T000000000000Z.xml"]
    if target_exists:
        assert outside.read_text() == "keep me"
    else:
        assert not outside.exists()
