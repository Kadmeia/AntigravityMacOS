from __future__ import annotations

import importlib.util
import json
import plistlib
import shutil
import subprocess
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "restore_official_macos.py"
spec = importlib.util.spec_from_file_location("restore_official_macos", MODULE_PATH)
assert spec and spec.loader
restore_tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(restore_tool)


def app(path: Path, bundle_id: str, version: str, marker: str = "") -> Path:
    (path / "Contents").mkdir(parents=True)
    with (path / "Contents" / "Info.plist").open("wb") as handle:
        plistlib.dump({"CFBundleIdentifier": bundle_id, "CFBundleShortVersionString": version}, handle)
    (path / "marker").write_text(marker)
    return path


def test_vendor_check_requires_expected_team_and_bundle(tmp_path, monkeypatch):
    source = app(tmp_path / "Antigravity.app", "com.google.antigravity", "2.15.1")
    calls = []

    def fake_run(*args):
        calls.append(args)
        detail = "TeamIdentifier=UNTRUSTED\n" if "-dv" in args else ""
        return subprocess.CompletedProcess(args, 0, "", detail)

    monkeypatch.setattr(restore_tool, "run", fake_run)
    with pytest.raises(restore_tool.RestoreError, match="Google"):
        restore_tool.verify_vendor_app(source, "com.google.antigravity")
    assert not any("spctl" in call[0] for call in calls)
    with pytest.raises(restore_tool.RestoreError, match="идентификатор"):
        restore_tool.verify_vendor_app(source, "com.google.antigravity-ide")


def test_restore_dry_run_does_not_modify_installed_app(tmp_path, monkeypatch):
    source = app(tmp_path / "source.app", "com.google.antigravity-ide", "2.5.5", "official")
    target = app(tmp_path / "Antigravity IDE.app", "com.google.antigravity-ide", "2.5.4", "old")
    monkeypatch.setattr(restore_tool, "verify_vendor_app", lambda *_: "2.5.5")
    monkeypatch.setattr(restore_tool, "assert_not_running", lambda *_: None)

    version, backup = restore_tool.restore(source, target, "com.google.antigravity-ide", apply=False)

    assert version == "2.5.5" and backup is None
    assert (target / "marker").read_text() == "old"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["Antigravity IDE.app", "source.app"]


def test_restore_keeps_original_app_as_backup(tmp_path, monkeypatch):
    source = app(tmp_path / "source.app", "com.google.antigravity", "2.15.1", "official")
    target = app(tmp_path / "Antigravity.app", "com.google.antigravity", "2.14.0", "old")
    monkeypatch.setattr(restore_tool, "verify_vendor_app", lambda *_: "2.15.1")
    monkeypatch.setattr(restore_tool, "assert_not_running", lambda *_: None)
    disabled = []
    monkeypatch.setattr(restore_tool, "disable_managed_target", disabled.append)

    def fake_run(*args):
        if args[0].endswith("ditto"):
            shutil.copytree(args[-2], args[-1])
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(restore_tool, "run", fake_run)
    version, backup = restore_tool.restore(
        source, target, "com.google.antigravity", apply=True, app_id="antigravity_desktop"
    )

    assert version == "2.15.1"
    assert disabled == ["antigravity_desktop"]
    assert backup and (backup / "marker").read_text() == "old"
    assert (target / "marker").read_text() == "official"


def test_failed_installed_verification_restores_previous_app(tmp_path, monkeypatch):
    source = app(tmp_path / "source.app", "com.google.antigravity", "2.15.1", "official")
    target = app(tmp_path / "Antigravity.app", "com.google.antigravity", "2.14.0", "old")

    def fake_verify(path, _bundle_id):
        if path == target and (target / "marker").read_text() == "official":
            raise restore_tool.RestoreError("verification failed")
        return "2.15.1"

    def fake_run(*args):
        if args[0].endswith("ditto"):
            shutil.copytree(args[-2], args[-1])
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(restore_tool, "verify_vendor_app", fake_verify)
    monkeypatch.setattr(restore_tool, "assert_not_running", lambda *_: None)
    monkeypatch.setattr(restore_tool, "run", fake_run)
    monkeypatch.setattr(restore_tool, "disable_managed_target", lambda *_: None)

    with pytest.raises(restore_tool.RestoreError, match="verification failed"):
        restore_tool.restore(
            source, target, "com.google.antigravity", apply=True, app_id="antigravity_desktop"
        )

    assert (target / "marker").read_text() == "old"
    assert not list(tmp_path.glob("Antigravity.app.restore-backup-*"))


def test_running_check_is_scoped_to_selected_app(tmp_path, monkeypatch):
    desktop = app(tmp_path / "Antigravity.app", "com.google.antigravity", "2.15.1")
    ide = app(tmp_path / "Antigravity IDE.app", "com.google.antigravity-ide", "2.5.5")
    ps_output = f"123 {ide}/Contents/MacOS/Electron\n456 /usr/bin/python3\n"
    monkeypatch.setattr(
        restore_tool, "run",
        lambda *args: subprocess.CompletedProcess(args, 0, ps_output, ""),
    )

    restore_tool.assert_not_running(desktop)
    with pytest.raises(restore_tool.RestoreError, match="PID 123"):
        restore_tool.assert_not_running(ide)


def test_disable_managed_target_uses_authenticated_local_api(tmp_path, monkeypatch):
    config_dir = tmp_path / ".agunlocker_mac"
    config_dir.mkdir()
    (config_dir / "api-token").write_text("x" * 32)
    (config_dir / "config.json").write_text(json.dumps({"web_port": 53128}))
    monkeypatch.setattr(restore_tool.Path, "home", lambda: tmp_path)
    captured = []

    class Response:
        status = 200

        def read(self):
            return b'{"success": true}'

    class Connection:
        def __init__(self, host, port, timeout):
            captured.append((host, port, timeout))

        def request(self, method, path, body, headers):
            captured.append((method, path, json.loads(body), headers))

        def getresponse(self):
            return Response()

        def close(self):
            pass

    monkeypatch.setattr(restore_tool.http.client, "HTTPConnection", Connection)
    restore_tool.disable_managed_target("antigravity_ide")

    assert captured[0] == ("127.0.0.1", 53128, 5)
    assert captured[1][:3] == ("POST", "/api/managed/disable", {"app_id": "antigravity_ide"})
    assert captured[1][3]["X-Antigravity-Token"] == "x" * 32


def test_restore_aborts_before_copy_when_watchdog_cannot_be_disabled(tmp_path, monkeypatch):
    source = app(tmp_path / "source.app", "com.google.antigravity", "2.15.1", "official")
    target = app(tmp_path / "Antigravity.app", "com.google.antigravity", "2.14.0", "old")
    monkeypatch.setattr(restore_tool, "verify_vendor_app", lambda *_: "2.15.1")
    monkeypatch.setattr(restore_tool, "assert_not_running", lambda *_: None)
    monkeypatch.setattr(
        restore_tool, "disable_managed_target",
        lambda *_: (_ for _ in ()).throw(restore_tool.RestoreError("watchdog unavailable")),
    )

    with pytest.raises(restore_tool.RestoreError, match="watchdog unavailable"):
        restore_tool.restore(
            source, target, "com.google.antigravity", apply=True, app_id="antigravity_desktop"
        )
    assert (target / "marker").read_text() == "old"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["Antigravity.app", "source.app"]
