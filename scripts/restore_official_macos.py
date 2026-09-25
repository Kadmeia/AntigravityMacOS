#!/usr/bin/env python3
"""Restore one Antigravity application from a vendor-signed macOS DMG.

This tool is intentionally dry-run by default.  It never edits user data or
the other Antigravity application.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path


GOOGLE_TEAM_ID = "EQHXZ8M8AV"
TARGETS = {
    "ide": ("com.google.antigravity-ide", "Antigravity IDE.app"),
    "desktop": ("com.google.antigravity", "Antigravity.app"),
}
APP_IDS = {"ide": "antigravity_ide", "desktop": "antigravity_desktop"}


class RestoreError(RuntimeError):
    pass


def run(*args: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, text=True, capture_output=True, check=False, timeout=180)
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise RestoreError(f"{' '.join(args[:2])} завершилась с ошибкой: {detail}")
    return result


def bundle_info(app: Path) -> tuple[str, str]:
    if app.is_symlink() or not app.is_dir():
        raise RestoreError(f"Неверный путь к приложению: {app}")
    try:
        with (app / "Contents" / "Info.plist").open("rb") as handle:
            info = plistlib.load(handle)
    except (OSError, ValueError, plistlib.InvalidFileException) as exc:
        raise RestoreError(f"Не удалось прочитать Info.plist: {app}: {exc}") from exc
    bundle_id = info.get("CFBundleIdentifier")
    version = info.get("CFBundleShortVersionString") or info.get("CFBundleVersion")
    if not isinstance(bundle_id, str) or not isinstance(version, str) or not version.strip():
        raise RestoreError(f"В приложении отсутствуют идентификатор или версия: {app}")
    return bundle_id, version


def verify_vendor_app(app: Path, expected_bundle_id: str) -> str:
    bundle_id, version = bundle_info(app)
    if bundle_id != expected_bundle_id:
        raise RestoreError(f"Неверный идентификатор приложения: {bundle_id}")
    run("/usr/bin/codesign", "--verify", "--deep", "--strict", str(app))
    details = run("/usr/bin/codesign", "-dv", "--verbose=4", str(app)).stderr
    team = re.search(r"^TeamIdentifier=([^\s]+)$", details, re.MULTILINE)
    if team is None or team.group(1) != GOOGLE_TEAM_ID or "Signature=adhoc" in details:
        raise RestoreError("Подпись приложения не принадлежит ожидаемой команде Google")
    run("/usr/sbin/spctl", "--assess", "--type", "execute", str(app))
    return version


def mount_dmg(dmg: Path, mountpoint: Path) -> None:
    run(
        "/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse", "-noautoopen",
        "-mountpoint", str(mountpoint), str(dmg),
    )
    if not os.path.ismount(mountpoint):
        raise RestoreError("DMG не смонтирован в ожидаемую папку")


def find_app(mountpoint: Path, expected_bundle_id: str) -> Path:
    matches: list[Path] = []
    for root, dirs, _files in os.walk(mountpoint, followlinks=False):
        relative_depth = len(Path(root).relative_to(mountpoint).parts)
        if relative_depth > 2:
            dirs[:] = []
            continue
        for dirname in list(dirs):
            candidate = Path(root) / dirname
            if dirname.endswith(".app"):
                dirs.remove(dirname)
                if candidate.is_symlink():
                    continue
                try:
                    bundle_id, _ = bundle_info(candidate)
                except RestoreError:
                    continue
                if bundle_id == expected_bundle_id:
                    matches.append(candidate)
    if len(matches) != 1:
        raise RestoreError(f"В DMG найдено {len(matches)} подходящих приложений; ожидалось одно")
    return matches[0]


def assert_not_running(target: Path) -> None:
    output = run("/bin/ps", "-axo", "pid=,comm=").stdout
    prefix = str(target.resolve()) + os.sep
    for line in output.splitlines():
        pid_and_command = line.strip().split(None, 1)
        if len(pid_and_command) != 2:
            continue
        command = pid_and_command[1]
        if command.startswith(prefix) or os.path.realpath(command).startswith(prefix):
            raise RestoreError(f"Приложение ещё запущено (PID {pid_and_command[0]}). Закройте его и повторите.")


def disable_managed_target(app_id: str) -> None:
    """Stop the running Unlocker watchdog from re-patching the restored app."""
    config_dir = Path.home() / ".agunlocker_mac"
    try:
        token = (config_dir / "api-token").read_text(encoding="utf-8").strip()
        if len(token) < 32:
            raise ValueError("короткий токен")
        config_path = config_dir / "config.json"
        settings = json.loads(config_path.read_text(encoding="utf-8")) if config_path.exists() else {}
        if not isinstance(settings, dict):
            raise ValueError("некорректный файл настроек")
        port = settings.get("web_port", 53128)
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("некорректный порт службы")
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise RestoreError(f"Не удалось прочитать настройки локальной службы: {exc}") from exc

    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(
            "POST", "/api/managed/disable", body=json.dumps({"app_id": app_id}),
            headers={"Content-Type": "application/json", "X-Antigravity-Token": token},
        )
        response = connection.getresponse()
        data = json.loads(response.read().decode("utf-8"))
        if response.status != 200 or not isinstance(data, dict) or data.get("success") is not True:
            raise RestoreError("Служба не подтвердила отключение автопатча для выбранного приложения")
    except (OSError, http.client.HTTPException, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RestoreError(f"Локальная служба недоступна: {exc}") from exc
    finally:
        connection.close()


def restore(source: Path, target: Path, bundle_id: str, *, apply: bool, app_id: str | None = None) -> tuple[str, Path | None]:
    source_version = verify_vendor_app(source, bundle_id)
    if not target.is_dir() or target.is_symlink():
        raise RestoreError(f"Установленное приложение не найдено: {target}")
    current_id, _current_version = bundle_info(target)
    if current_id != bundle_id:
        raise RestoreError(f"Установленная программа имеет другой идентификатор: {current_id}")
    assert_not_running(target)
    if not apply:
        return source_version, None
    if app_id not in APP_IDS.values():
        raise RestoreError("Неизвестная цель для отключения автопатча")
    disable_managed_target(app_id)

    # Keep the backup on the same volume, so both swaps are atomic renames.
    suffix = uuid.uuid4().hex[:12]
    stage = target.parent / f".{target.name}.restore-stage-{suffix}"
    backup = target.parent / f"{target.name}.restore-backup-{suffix}"
    if stage.exists() or backup.exists():
        raise RestoreError("Временное имя уже занято; повторите операцию")
    try:
        run("/usr/bin/ditto", "--rsrc", "--extattr", str(source), str(stage))
        staged_version = verify_vendor_app(stage, bundle_id)
        if staged_version != source_version:
            raise RestoreError("Версия скопированного приложения отличается от версии в DMG")
        assert_not_running(target)
        os.rename(target, backup)
        try:
            os.rename(stage, target)
            installed_version = verify_vendor_app(target, bundle_id)
            if installed_version != source_version:
                raise RestoreError("Проверка установленной версии не прошла")
        except Exception as exc:
            # Restore the original app if installation or verification failed.
            move_error: OSError | None = None
            if target.exists():
                try:
                    os.rename(target, stage)
                except OSError as rollback_move_exc:
                    move_error = rollback_move_exc
            try:
                os.rename(backup, target)
            except OSError as rollback_exc:
                detail = f"Не удалось вернуть прежнее приложение: {rollback_exc}. "
                if move_error is not None:
                    detail += f"Не удалось убрать не прошедшую проверку версию: {move_error}. "
                raise RestoreError(
                    detail +
                    f"Его копия осталась здесь: {backup}"
                ) from exc
            if move_error is not None:
                raise RestoreError(
                    f"Не удалось убрать не прошедшую проверку версию: {move_error}. "
                    "Прежнее приложение возвращено."
                ) from exc
            raise
        return installed_version, backup
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=TARGETS, required=True, help="ide или desktop")
    parser.add_argument("--dmg", type=Path, required=True, help="официальный DMG")
    parser.add_argument("--apply", action="store_true", help="выполнить замену после проверки")
    args = parser.parse_args(argv)
    dmg = args.dmg.expanduser()
    if dmg.is_symlink() or not dmg.is_file() or dmg.suffix.lower() != ".dmg":
        parser.error("нужен существующий файл .dmg без символической ссылки")
    bundle_id, app_name = TARGETS[args.target]
    target = Path("/Applications") / app_name
    try:
        with tempfile.TemporaryDirectory(prefix="ag-official-restore-") as temporary:
            mountpoint = Path(temporary) / "mounted"
            mountpoint.mkdir()
            mounted = False
            try:
                mount_dmg(dmg, mountpoint)
                mounted = True
                source = find_app(mountpoint, bundle_id)
                version, backup = restore(source, target, bundle_id, apply=args.apply, app_id=APP_IDS[args.target])
            finally:
                if mounted:
                    run("/usr/bin/hdiutil", "detach", str(mountpoint))
    except (RestoreError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"Ошибка восстановления: {exc}", file=sys.stderr)
        return 1
    if backup:
        print(f"Установлена официальная версия {version}. Прежняя программа сохранена: {backup}")
    else:
        print(f"Проверка пройдена: официальная версия {version}. Для замены повторите с --apply.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
