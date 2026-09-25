from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from typing import Any

from . import detector

# ARM64 Signatures
_ARM64_TBZ_W3_BIT0 = rb"[\x03\x23\x43\x63\x83\xa3\xc3\xe3]..\x36"
_ARM64_TOKEN_SETUP = rb"(?:....){1,2}\x03\x10\x06\xa9"
ARM64_SIG_UNPATCHED = re.compile(rb"\x03\x20\x40\x39" + _ARM64_TBZ_W3_BIT0 + _ARM64_TOKEN_SETUP, re.S)
ARM64_REPLACEMENT = b"\x23\x00\x80\x52\x03\x20\x00\x39"

IDE_RE = re.compile(r"(resetIsTierGCPTos\(\),)this\.[A-Za-z_$0-9]+\.isGoogleInternal")
IDE_DONE = "resetIsTierGCPTos(),true"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def run_cmd(cmd: list[str]) -> tuple[bool, str, str]:
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        return res.returncode == 0, res.stdout, res.stderr
    except Exception as e:
        return False, "", str(e)

def sign_macos(path: str, deep: bool = False) -> bool:
    """Ad-hoc sign a binary or app bundle so Gatekeeper / Hardened Runtime accepts it."""
    cmd = ["/usr/bin/codesign", "--force"]
    if deep:
        cmd.append("--deep")
    cmd.extend(["--sign", "-", path])
    ok, out, err = run_cmd(cmd)
    if not ok:
        logging.warning(f"codesign warning on {path}: {err.strip()}")
        return False
    verify_cmd = ["/usr/bin/codesign", "--verify", "--strict"]
    if deep:
        verify_cmd.append("--deep")
    verify_cmd.append(path)
    verified, _, verify_err = run_cmd(verify_cmd)
    if not verified:
        logging.warning(f"codesign verification failed on {path}: {verify_err.strip()}")
    return verified

def clear_ide_cache() -> None:
    """Clear cached compiled V8 JS data so the IDE loads our patched main.js."""
    base = os.path.expanduser("~/Library/Application Support/Antigravity IDE")
    dirs_to_clear = [
        os.path.join(base, "CachedData"),
        os.path.join(base, "Code Cache", "js")
    ]
    for d in dirs_to_clear:
        if os.path.exists(d):
            try:
                shutil.rmtree(d, ignore_errors=True)
                logging.info(f"Cleared IDE cache: {d}")
            except Exception as e:
                logging.warning(f"Could not clear cache {d}: {e}")

def kill_language_server(target_path: str | None = None) -> None:
    """
    Safely terminates language_server instances.
    If target_path is provided, targets processes matching that specific executable/bundle.
    """
    if target_path:
        try:
            # macOS `comm` is the executable path.  Compare canonical paths so
            # a targeted patch never terminates another installation's server.
            target_real = os.path.realpath(target_path)
            res = subprocess.run(
                ["ps", "-axo", "pid=,comm="],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    parts = line.strip().split(None, 1)
                    if len(parts) == 2:
                        pid_str, executable = parts
                        if os.path.realpath(executable) == target_real:
                            try:
                                pid = int(pid_str)
                                os.kill(pid, 15)  # SIGTERM
                            except (ValueError, ProcessLookupError, PermissionError):
                                pass
        except Exception as e:
            logging.debug(f"Targeted process termination failed: {e}")
        # A supplied path is a hard scope boundary.  Never fall back to killing
        # every process that happens to use a common language_server name.
        time.sleep(0.3)
        return

    # Untargeted use is reserved for the explicit application restart flow.
    if target_path is None:
        for p in ["language_server", "language_server_macos_arm", "language_server_macos_x64"]:
            run_cmd(["pkill", "-x", p])

    time.sleep(0.3)


def _copy_replace_metadata(source: str, destination: str) -> None:
    """Preserve safe file metadata when an atomic replacement is prepared."""
    source_stat = os.stat(source, follow_symlinks=False)
    os.chmod(destination, stat.S_IMODE(source_stat.st_mode), follow_symlinks=False)
    shutil.copystat(source, destination, follow_symlinks=False)
    if hasattr(os, "listxattr"):
        try:
            for name in os.listxattr(source, follow_symlinks=False):
                try:
                    value = os.getxattr(source, name, follow_symlinks=False)
                    os.setxattr(destination, name, value, follow_symlinks=False)
                except OSError:
                    logging.debug("Could not copy xattr %s from %s", name, source)
        except OSError:
            pass


def _resign_app_bundle(app_bundle_path: str | None) -> bool:
    if not app_bundle_path:
        return True
    if not os.path.isdir(app_bundle_path):
        logging.warning("Application bundle not found for re-signing: %s", app_bundle_path)
        return False
    return sign_macos(app_bundle_path, deep=True)


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_backup_checksum(backup_path: str) -> None:
    checksum_path = backup_path + ".sha256"
    fd, temporary = tempfile.mkstemp(
        prefix=f".{os.path.basename(checksum_path)}-",
        suffix=".tmp",
        dir=os.path.dirname(checksum_path),
    )
    try:
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(_sha256_file(backup_path) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, checksum_path)
        temporary = ""
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def _verify_backup_checksum(backup_path: str) -> bool:
    if not os.path.isfile(backup_path) or os.path.islink(backup_path):
        return False
    checksum_path = backup_path + ".sha256"
    if not os.path.exists(checksum_path):
        # Compatibility with backups created by versions before 1.2.0.
        logging.warning("Legacy backup has no SHA-256 manifest: %s", backup_path)
        return True
    try:
        with open(checksum_path, "r", encoding="ascii") as handle:
            expected = handle.read().strip().lower()
    except OSError:
        return False
    try:
        actual = _sha256_file(backup_path)
    except OSError:
        return False
    return len(expected) == 64 and expected == actual

def patch_binary_file(bin_path: str, app_bundle_path: str | None = None) -> tuple[bool, str]:
    """
    Patches language_server binary:
    1. Backup to .agybak
    2. ineligible -> inexigible (Protobuf bypass)
    3. https_proxy -> AG_LS_PROXY (Private proxy variable)
    4. ARM64 manager gate (Machine code bypass)
    5. Codesign & permission fix
    """
    if not os.path.isfile(bin_path) or os.path.islink(bin_path):
        return False, "Файл не найден"

    try:
        with open(bin_path, "rb") as f:
            data = bytearray(f.read())
    except Exception as e:
        return False, f"Ошибка чтения бинарника: {e}"

    orig_len = len(data)
    already_patched = (
        data.count(b"inexigible") > 0
        and data.count(b"ineligible") == 0
        and data.count(b"AG_LS_PROXY") > 0
    )
    has_existing_patch = (
        data.count(b"inexigible") > 0
        or data.count(b"AG_LS_PROXY") > 0
        or bool(detector.ARM64_SIG_PATCHED.search(data))
    )

    backup_path = bin_path + ".agybak"
    if os.path.lexists(backup_path):
        if not _verify_backup_checksum(backup_path):
            return False, "Контрольная сумма резервной копии не совпадает; патч отменён"
    else:
        if has_existing_patch:
            logging.warning(f"Файл {bin_path} уже пропатчен, резервная копия оригинала не может быть создана")
        else:
            try:
                shutil.copy2(bin_path, backup_path)
                _write_backup_checksum(backup_path)
                logging.info(f"Создан бэкап: {backup_path}")
            except Exception as e:
                for incomplete in (backup_path, backup_path + ".sha256"):
                    try:
                        if os.path.exists(incomplete):
                            os.unlink(incomplete)
                    except OSError:
                        pass
                return False, f"Не удалось создать бэкап: {e}"

    changes: list[str] = []

    # 1. String replacements (same length)
    count_ineligible = data.count(b"ineligible")
    if count_ineligible > 0:
        data = bytearray(bytes(data).replace(b"ineligible", b"inexigible"))
        changes.append(f"ineligible -> inexigible ({count_ineligible})")

    count_tiers = data.count(b"ineligible_tiers")
    if count_tiers > 0:
        data = bytearray(bytes(data).replace(b"ineligible_tiers", b"inexigible_tiers"))
        changes.append(f"ineligible_tiers ({count_tiers})")

    count_proxy = data.count(b"https_proxy")
    if count_proxy > 0:
        data = bytearray(bytes(data).replace(b"https_proxy", b"AG_LS_PROXY"))
        changes.append(f"https_proxy -> AG_LS_PROXY ({count_proxy})")

    # 2. ARM64 Gate replacement
    m = ARM64_SIG_UNPATCHED.search(data)
    if m:
        start = m.start()
        data[start:start + len(ARM64_REPLACEMENT)] = ARM64_REPLACEMENT
        changes.append("ARM64 Manager Gate (hasValidAuth=true)")

    if len(data) != orig_len:
        return False, "Размер бинарника изменился — аварийная остановка для предотвращения повреждения"

    if not changes:
        if already_patched:
            return True, "Уже пропатчен"
        return False, "Сигнатуры для патча не найдены"

    # Atomic write
    tmp_path: str | None = None
    try:
        fd, tmp_path = tempfile.mkstemp(prefix=f".{os.path.basename(bin_path)}-", suffix=".agtmp", dir=os.path.dirname(bin_path))
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        _copy_replace_metadata(bin_path, tmp_path)
        kill_language_server(bin_path)
        os.replace(tmp_path, bin_path)
        tmp_path = None
    except Exception as e:
        return False, f"Ошибка записи файла: {e}"
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    # Re-sign the modified binary
    if not sign_macos(bin_path, deep=False) or not _resign_app_bundle(app_bundle_path):
        if os.path.exists(backup_path):
            shutil.copy2(backup_path, bin_path)
            _resign_app_bundle(app_bundle_path)
        return False, "Не удалось проверить подпись изменённого приложения; оригинал восстановлен"

    detector.clear_detection_cache()
    logging.info(f"Успешно пропатчен {bin_path}: {', '.join(changes)}")
    return True, f"Успешно применено: {', '.join(changes)}"

def unpatch_binary_file(bin_path: str, app_bundle_path: str | None = None) -> tuple[bool, str]:
    """Restores binary from .agybak."""
    if not os.path.isfile(bin_path) or os.path.islink(bin_path):
        return False, "Файл не найден"

    backup_path = bin_path + ".agybak"
    if os.path.exists(backup_path):
        if not _verify_backup_checksum(backup_path):
            return False, "Контрольная сумма резервной копии не совпадает; восстановление отменено"
        try:
            shutil.copy2(backup_path, bin_path)
            os.chmod(bin_path, 0o755)
            if not sign_macos(bin_path, deep=False) or not _resign_app_bundle(app_bundle_path):
                return False, "Оригинал восстановлен, но проверка подписи бинарника не прошла"
            kill_language_server(bin_path)
            detector.clear_detection_cache()
            logging.info(f"Восстановлен оригинальный бинарник из {backup_path}")
            return True, "Восстановлен из бэкапа"
        except Exception as e:
            return False, f"Ошибка восстановления из бэкапа: {e}"
    return False, "Файл резервной копии (.agybak) не найден. Безопасный откат машинного кода невозможен."

def patch_js_file(js_path: str, app_bundle_path: str | None = None) -> tuple[bool, str]:
    """
    Patches Antigravity IDE main.js:
    resetIsTierGCPTos(),this.xxx.isGoogleInternal -> resetIsTierGCPTos(),true
    """
    if not os.path.isfile(js_path) or os.path.islink(js_path):
        return False, "JS файл не найден"

    backup_path = js_path + ".ag_backup"
    if os.path.lexists(backup_path):
        if not _verify_backup_checksum(backup_path):
            return False, "Контрольная сумма резервной копии JS не совпадает; патч отменён"
    else:
        try:
            shutil.copy2(js_path, backup_path)
            _write_backup_checksum(backup_path)
            logging.info(f"Создан бэкап JS: {backup_path}")
        except Exception as e:
            for incomplete in (backup_path, backup_path + ".sha256"):
                try:
                    if os.path.exists(incomplete):
                        os.unlink(incomplete)
                except OSError:
                    pass
            return False, f"Не удалось создать бэкап JS: {e}"

    try:
        with open(js_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        if IDE_DONE in content and not IDE_RE.search(content):
            return True, "Уже пропатчен"

        if not IDE_RE.search(content):
            return False, "Сигнатура isGoogleInternal не найдена"

        new_content = IDE_RE.sub(r"\1true", content)
        tmp_path: str | None = None
        try:
            fd, tmp_path = tempfile.mkstemp(prefix=f".{os.path.basename(js_path)}-", suffix=".agtmp", dir=os.path.dirname(js_path))
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(new_content)
                f.flush()
                os.fsync(f.fileno())
            _copy_replace_metadata(js_path, tmp_path)
            os.replace(tmp_path, js_path)
            tmp_path = None
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        if not _resign_app_bundle(app_bundle_path):
            shutil.copy2(backup_path, js_path)
            _resign_app_bundle(app_bundle_path)
            return False, "Не удалось проверить подпись приложения; исходный JS восстановлен"

        clear_ide_cache()
        detector.clear_detection_cache()
        logging.info(f"Успешно пропатчен {js_path} (isGoogleInternal -> true)")
        return True, "Патч isGoogleInternal успешно применен"
    except Exception as e:
        return False, f"Ошибка патча JS: {e}"

def unpatch_js_file(js_path: str, app_bundle_path: str | None = None) -> tuple[bool, str]:
    """Restores main.js from .ag_backup."""
    if not os.path.isfile(js_path) or os.path.islink(js_path):
        return False, "JS файл не найден"

    backup_path = js_path + ".ag_backup"
    if os.path.exists(backup_path):
        if not _verify_backup_checksum(backup_path):
            return False, "Контрольная сумма резервной копии JS не совпадает; восстановление отменено"
        try:
            shutil.copy2(backup_path, js_path)
            if not _resign_app_bundle(app_bundle_path):
                return False, "JS восстановлен, но проверка подписи приложения не прошла"
            clear_ide_cache()
            detector.clear_detection_cache()
            logging.info(f"Восстановлен оригинальный JS из {backup_path}")
            return True, "JS восстановлен из бэкапа"
        except Exception as e:
            return False, f"Ошибка восстановления JS: {e}"
    return False, "Бэкап JS отсутствует"

def patch_app_fully(app_info: dict[str, Any]) -> tuple[bool, str]:
    """Patches both binary and JS (if present) for given app."""
    bin_path = app_info.get("bin_path")
    js_path = app_info.get("js_path")
    app_path = app_info.get("app_path")

    # Validate every pre-existing recovery point before the first component is
    # touched. This prevents a later component failure from leaving a partial
    # patch whose original backup was already known to be unusable.
    components = []
    if bin_path and os.path.exists(bin_path):
        components.append((bin_path, ".agybak"))
    if js_path and os.path.exists(js_path):
        components.append((js_path, ".ag_backup"))
    for path, suffix in components:
        backup_path = path + suffix
        if os.path.lexists(backup_path) and not _verify_backup_checksum(backup_path):
            return False, f"Непригодная резервная копия {backup_path}; патч отменён до изменений"

    results: list[str] = []
    binary_message: str | None = None
    if bin_path and os.path.exists(bin_path):
        ok, msg = patch_binary_file(bin_path, app_path)
        results.append(f"Binary: {msg}")
        binary_message = msg
        if not ok:
            return False, f"Binary: {msg}; остальные компоненты не обрабатывались"
    if js_path and os.path.exists(js_path):
        ok_j, msg_j = patch_js_file(js_path, app_path)
        results.append(f"JS: {msg_j}")
        if not ok_j:
            binary_state = binary_message or "не применён"
            return False, (
                f"Частичное состояние: Binary: {binary_state}; JS: {msg_j}. "
                "Автоматический откат не выполнен. Используйте откат из резервной копии "
                "для восстановления компонентов."
            )

    if not results:
        return False, "Поддерживаемые файлы для патча не найдены"
    return True, "; ".join(results)

def unpatch_app_fully(app_info: dict[str, Any]) -> tuple[bool, str]:
    """Restore selected components only after every backup passes preflight."""
    bin_path = app_info.get("bin_path")
    js_path = app_info.get("js_path")
    app_path = app_info.get("app_path")

    components = []
    if bin_path and os.path.exists(bin_path):
        components.append((bin_path, ".agybak"))
    if js_path and os.path.exists(js_path):
        components.append((js_path, ".ag_backup"))
    if not components:
        return False, "Файлы для восстановления не найдены"
    for path, suffix in components:
        backup = path + suffix
        if not _verify_backup_checksum(backup):
            return False, f"Нет пригодной резервной копии: {backup}"
        if not os.access(os.path.dirname(path), os.W_OK):
            return False, f"Нет доступа на запись в {os.path.dirname(path)}"

    results: list[str] = []
    if bin_path and os.path.exists(bin_path):
        ok, msg = unpatch_binary_file(bin_path, app_path)
        results.append(f"Binary: {msg}")
        if not ok:
            return False, "; ".join(results)
    if js_path and os.path.exists(js_path):
        ok_j, msg_j = unpatch_js_file(js_path, app_path)
        results.append(f"JS: {msg_j}")
        if not ok_j:
            return False, "; ".join(results)
    return True, "; ".join(results)

def _running_bundle_pids(app_path: str) -> list[int]:
    ok, output, error = run_cmd(["ps", "-axo", "pid=,comm="])
    if not ok:
        raise OSError(error or "Не удалось проверить процессы")
    executable_dir = os.path.realpath(app_path) + os.sep + "Contents" + os.sep + "MacOS" + os.sep
    pids = []
    for line in output.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) != 2:
            continue
        if os.path.realpath(parts[1]).startswith(executable_dir):
            try:
                pids.append(int(parts[0]))
            except ValueError:
                continue
    return pids


def restart_app(app_name: str, proxy_url: str | None = None, app_path: str | None = None) -> tuple[bool, str]:
    """Stop the selected bundle, launch it with proxy env, and verify its process."""
    candidate = next(
        (
            item
            for item in detector.KNOWN_APP_CANDIDATES
            if item.get("name") == app_name
            or item.get("id") == app_name
            or (item.get("id") == "antigravity_desktop" and app_name in {"Antigravity", "Antigravity 2.0 (Desktop)"})
        ),
        None,
    )
    if candidate is None:
        return False, "Неизвестное приложение"
    allowed_paths = {os.path.realpath(path) for path in candidate["paths"]}
    app_path = app_path or next((path for path in candidate["paths"] if os.path.isdir(path)), None)
    if not app_path or os.path.realpath(app_path) not in allowed_paths or not os.path.isdir(app_path):
        return False, "Установленная программа не найдена"
    logging.info("Перезапуск приложения: %s", app_path)
    try:
        old_pids = _running_bundle_pids(app_path)
        for pid in old_pids:
            os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 8.0
        while old_pids and time.monotonic() < deadline:
            if not set(old_pids).intersection(_running_bundle_pids(app_path)):
                break
            time.sleep(0.1)
        else:
            if old_pids:
                return False, f"{app_name} не завершился; повторный запуск отменён"
    except (OSError, PermissionError) as exc:
        return False, f"Не удалось завершить {app_name}: {exc}"

    binary_path = next(
        (os.path.join(app_path, rel) for rel in candidate["binary_rel"] if os.path.isfile(os.path.join(app_path, rel))),
        None,
    )
    if binary_path:
        kill_language_server(binary_path)
    open_cmd = ["open"]
    if proxy_url:
        # A GUI app that was already running before launchctl setenv keeps its
        # old environment. Pass the local proxy to this new process explicitly.
        open_cmd.extend([
            "--env", f"AG_LS_PROXY={proxy_url}",
            "--env", f"HTTPS_PROXY={proxy_url}",
            "--env", f"https_proxy={proxy_url}",
        ])
    open_cmd.extend(["-a", app_path])
    ok, _, err = run_cmd(open_cmd)
    if not ok:
        return False, f"Не удалось запустить {app_name}: {err.strip()}"
    try:
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if _running_bundle_pids(app_path):
                return True, f"Приложение {app_name} запущено через локальную службу"
            time.sleep(0.2)
    except OSError as exc:
        return False, f"Не удалось проверить запуск {app_name}: {exc}"
    return False, f"{app_name} не запустился после команды открытия"
