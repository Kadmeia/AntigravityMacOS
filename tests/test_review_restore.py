from __future__ import annotations

import importlib.util
import plistlib
import shutil
import subprocess
from pathlib import Path

import pytest

from backend import patcher


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "restore_official_macos.py"
spec = importlib.util.spec_from_file_location("restore_official_macos_review", MODULE_PATH)
assert spec and spec.loader
restore_tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(restore_tool)


@pytest.mark.parametrize(
    ("patcher_fn", "suffix", "original", "patched"),
    [
        (patcher.patch_binary_file, ".agybak", b"original binary", b"inexigible AG_LS_PROXY"),
        (patcher.patch_js_file, ".ag_backup", b"original js", b"resetIsTierGCPTos(),true"),
    ],
)
def test_patch_refuses_existing_backup_with_bad_checksum(
    tmp_path, patcher_fn, suffix, original, patched
):
    live = tmp_path / ("language_server" if suffix == ".agybak" else "main.js")
    live.write_bytes(patched)
    backup = Path(str(live) + suffix)
    backup.write_bytes(original)
    Path(str(backup) + ".sha256").write_text("0" * 64 + "\n", encoding="ascii")

    ok, message = patcher_fn(str(live))

    assert ok is False
    assert "Контрольная сумма" in message
    assert live.read_bytes() == patched


def test_patch_app_preflights_both_backups_before_binary(tmp_path, monkeypatch):
    binary = tmp_path / "language_server"
    javascript = tmp_path / "main.js"
    binary.write_bytes(b"binary")
    javascript.write_text("javascript", encoding="utf-8")
    binary_backup = Path(str(binary) + ".agybak")
    binary_backup.write_bytes(b"original binary")
    Path(str(binary_backup) + ".sha256").write_text(
        patcher._sha256_file(str(binary_backup)) + "\n", encoding="ascii"
    )
    js_backup = Path(str(javascript) + ".ag_backup")
    js_backup.write_bytes(b"original js")
    Path(str(js_backup) + ".sha256").write_text("0" * 64 + "\n", encoding="ascii")
    calls = []
    monkeypatch.setattr(patcher, "patch_binary_file", lambda *args: calls.append("binary"))

    ok, message = patcher.patch_app_fully(
        {"bin_path": str(binary), "js_path": str(javascript), "app_path": None}
    )

    assert ok is False
    assert "Непригодная резервная копия" in message
    assert calls == []
    assert binary.read_bytes() == b"binary"
    assert javascript.read_text(encoding="utf-8") == "javascript"


def test_patch_app_stops_after_binary_failure(tmp_path, monkeypatch):
    binary = tmp_path / "language_server"
    javascript = tmp_path / "main.js"
    binary.write_bytes(b"binary")
    javascript.write_text("javascript", encoding="utf-8")
    js_calls = []
    monkeypatch.setattr(patcher, "patch_binary_file", lambda *_: (False, "binary failed"))
    monkeypatch.setattr(patcher, "patch_js_file", lambda *_: js_calls.append(True))

    ok, message = patcher.patch_app_fully(
        {"bin_path": str(binary), "js_path": str(javascript), "app_path": None}
    )

    assert ok is False
    assert "binary failed" in message
    assert "остальные компоненты не обрабатывались" in message
    assert js_calls == []


def test_patch_app_reports_partial_state_when_js_fails(tmp_path, monkeypatch):
    binary = tmp_path / "language_server"
    javascript = tmp_path / "main.js"
    binary.write_bytes(b"binary")
    javascript.write_text("javascript", encoding="utf-8")
    monkeypatch.setattr(patcher, "patch_binary_file", lambda *_: (True, "бинарник применён"))
    monkeypatch.setattr(patcher, "patch_js_file", lambda *_: (False, "JS сигнатура не найдена"))

    ok, message = patcher.patch_app_fully(
        {"bin_path": str(binary), "js_path": str(javascript), "app_path": None}
    )

    assert ok is False
    assert "Частичное состояние" in message
    assert "Binary: бинарник применён" in message
    assert "JS: JS сигнатура не найдена" in message
    assert "Автоматический откат не выполнен" in message
    assert "откат из резервной копии" in message


def _app(path: Path, bundle_id: str, version: str, marker: str) -> Path:
    contents = path / "Contents"
    contents.mkdir(parents=True)
    with (contents / "Info.plist").open("wb") as handle:
        plistlib.dump(
            {"CFBundleIdentifier": bundle_id, "CFBundleShortVersionString": version}, handle
        )
    (path / "marker").write_text(marker, encoding="utf-8")
    return path


def test_restore_reports_backup_path_when_failed_version_cannot_be_moved(tmp_path, monkeypatch):
    source = _app(tmp_path / "source.app", "com.google.antigravity", "2.15.1", "official")
    target = _app(tmp_path / "Antigravity.app", "com.google.antigravity", "2.14.0", "old")
    def verify(path, _bundle_id):
        if Path(path) == target and (target / "marker").read_text(encoding="utf-8") == "official":
            raise restore_tool.RestoreError("simulated installed verification failure")
        return "2.15.1"

    monkeypatch.setattr(restore_tool, "verify_vendor_app", verify)
    monkeypatch.setattr(restore_tool, "assert_not_running", lambda *_: None)
    monkeypatch.setattr(restore_tool, "disable_managed_target", lambda *_: None)

    def fake_run(*args):
        if args[0].endswith("ditto"):
            shutil.copytree(args[-2], args[-1])
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(restore_tool, "run", fake_run)
    real_rename = restore_tool.os.rename
    attempted_backup_restore = []

    def fail_move_of_unverified_app(src, dst):
        src_path, dst_path = Path(src), Path(dst)
        if src_path == target and ".restore-stage-" in dst_path.name:
            raise OSError("simulated rollback rename failure")
        if ".restore-backup-" in src_path.name and dst_path == target:
            attempted_backup_restore.append(src_path)
            raise OSError("simulated backup restore failure")
        return real_rename(src, dst)

    monkeypatch.setattr(restore_tool.os, "rename", fail_move_of_unverified_app)
    with pytest.raises(restore_tool.RestoreError) as caught:
        restore_tool.restore(
            source, target, "com.google.antigravity", apply=True, app_id="antigravity_desktop"
        )

    assert "simulated rollback rename failure" in str(caught.value)
    assert "simulated backup restore failure" in str(caught.value)
    assert attempted_backup_restore
    backup = attempted_backup_restore[0]
    assert str(backup) in str(caught.value)
    assert (backup / "marker").read_text(encoding="utf-8") == "old"
