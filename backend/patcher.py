from __future__ import annotations

import getpass
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

# IDE main.js regex (confeden/Antigravity full onboarding + fallback)
CONFEDEN_IDE_RE = re.compile(
    r"async\s+([A-Za-z_$0-9]+)\(([A-Za-z_$0-9]+)\)\s*\{\s*if\(this\.([A-Za-z_$0-9]+)\.send\(\{type:[A-Za-z_$0-9]+\.isGcpTos\?\"GCP_SIGN_IN\":\"SIGN_IN\"\}\),this\.([A-Za-z_$0-9]+)\.resetIsTierGCPTos\(\),this\.[A-Za-z_$0-9]+\.isGoogleInternal\)\{try\{await this\.([A-Za-z_$0-9]+)\.loadCodeAssist\([A-Za-z_$0-9]+\);const\{settings:([A-Za-z_$0-9]+),userTier:([A-Za-z_$0-9]+)\}=await this\.refreshUserStatus\([A-Za-z_$0-9]+\),([A-Za-z_$0-9]+)=([A-Za-z_$0-9]+)\([A-Za-z_$0-9]+\);this\.([A-Za-z_$0-9]+)\.pushUpdate\([A-Za-z_$0-9]+\),this\.[A-Za-z_$0-9]+\.send\(\{type:\"AUTH_SUCCESS\",tokenInfo:[A-Za-z_$0-9]+\}\),this\.([A-Za-z_$0-9]+)\.fire\(\{settings:[A-Za-z_$0-9]+,userTier:[A-Za-z_$0-9]+\}\)\}catch\(([A-Za-z_$0-9]+)\)\{.*?(?:return\}|return;\s*\})"
)
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
    try:
        source_stat = os.stat(source, follow_symlinks=False)
        os.chmod(destination, stat.S_IMODE(source_stat.st_mode), follow_symlinks=False)
        try:
            shutil.copystat(source, destination, follow_symlinks=False)
        except OSError:
            pass
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
    except OSError as e:
        logging.debug("Could not copy metadata from %s to %s: %s", source, destination, e)


def ensure_bundle_writable(target_path: str, app_bundle_path: str | None = None) -> bool:
    """
    Checks if target_path or its directory is writable.
    If not, attempts to fix permissions (via chmod, or osascript administrator prompt).
    """
    directory = os.path.dirname(target_path)
    if os.path.exists(directory) and os.access(directory, os.W_OK):
        if not os.path.exists(target_path) or os.access(target_path, os.W_OK):
            return True

    # Try local chmod if owned by current user
    try:
        if os.path.exists(directory):
            os.chmod(directory, 0o755)
        if os.path.exists(target_path):
            os.chmod(target_path, 0o755)
        if os.access(directory, os.W_OK) and (not os.path.exists(target_path) or os.access(target_path, os.W_OK)):
            return True
    except OSError:
        pass

    # Find the app bundle root to grant permissions
    bundle_to_fix = app_bundle_path
    if not bundle_to_fix and ".app/" in target_path:
        bundle_to_fix = target_path[:target_path.find(".app/") + 4]

    if not bundle_to_fix:
        bundle_to_fix = directory

    # Request elevation via standard macOS dialog
    try:
        current_user = getpass.getuser()
        escaped = bundle_to_fix.replace('"', '\\"')
        cmd = f'do shell script "chown -R {current_user} \\"{escaped}\\" && chmod -R u+w \\"{escaped}\\"" with administrator privileges'
        res = subprocess.run(["osascript", "-e", cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        if res.returncode == 0:
            logging.info(f"Granted write permissions on {bundle_to_fix} via macOS elevation")
            return True
        else:
            logging.warning(f"Elevation rejected or failed: {res.stderr.strip()}")
    except Exception as e:
        logging.warning(f"Could not request elevation: {e}")

    return os.path.exists(directory) and os.access(directory, os.W_OK)


def _safe_copy_file(src: str, dst: str, app_bundle_path: str | None = None) -> None:
    """
    Safely copies src to dst.
    Handles macOS xattr / copystat EPERM errors, and elevates permissions if needed.
    """
    try:
        shutil.copy2(src, dst)
        return
    except OSError as err:
        # If destination was already written by copyfile before copystat failed with EPERM on metadata/chflags
        if os.path.exists(dst) and os.path.getsize(dst) == os.path.getsize(src):
            try:
                os.chmod(dst, 0o755)
            except OSError:
                pass
            return

        # Attempt to ensure write permissions and retry
        if err.errno in (1, 13):  # EPERM or EACCES
            if ensure_bundle_writable(dst, app_bundle_path):
                try:
                    shutil.copyfile(src, dst)
                    try:
                        os.chmod(dst, 0o755)
                    except OSError:
                        pass
                    return
                except OSError:
                    pass

        # Try plain copyfile without metadata copying
        try:
            shutil.copyfile(src, dst)
            try:
                os.chmod(dst, 0o755)
            except OSError:
                pass
            return
        except OSError:
            pass

        hint = ""
        if err.errno == 1:
            hint = " (macOS заблокировала изменение файлов в /Applications. Предоставьте доступ в «Системные настройки → Конфиденциальность → Управление приложениями» для Терминала/Unlocker, либо выполните в Терминале: sudo chown -R $(whoami) '/Applications/Antigravity.app')"
        elif err.errno == 13:
            hint = f" (Нет прав на запись. Выполните в Терминале: sudo chown -R $(whoami) '{app_bundle_path or os.path.dirname(dst)}')"
        raise OSError(err.errno, f"{err.strerror}{hint}")


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
                _safe_copy_file(bin_path, backup_path, app_bundle_path)
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
        ensure_bundle_writable(bin_path, app_bundle_path)
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
            _safe_copy_file(backup_path, bin_path, app_bundle_path)
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
            ensure_bundle_writable(bin_path, app_bundle_path)
            _safe_copy_file(backup_path, bin_path, app_bundle_path)
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
            _safe_copy_file(js_path, backup_path, app_bundle_path)
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

        is_already_patched = (
            ("onboardUser(\"standard-tier\"" in content)
            or ("// UNLOCKED" in content)
            or (IDE_DONE in content and not IDE_RE.search(content))
        )
        if is_already_patched:
            return True, "Уже пропатчен"

        m_confeden = CONFEDEN_IDE_RE.search(content)
        if m_confeden:
            fname = m_confeden.group(1)
            var_t = m_confeden.group(2)
            var_t_send = m_confeden.group(3)
            var_y = m_confeden.group(4)
            var_i = m_confeden.group(8)
            var_func = m_confeden.group(9)
            var_f = m_confeden.group(10)
            var_h = m_confeden.group(11)

            payload = (
                f"async {fname}({var_t}){{\n"
                f"    this.{var_t_send}.send({{type:{var_t}.isGcpTos?\"GCP_SIGN_IN\":\"SIGN_IN\"}});\n"
                f"    this.{var_y}.resetIsTierGCPTos();\n"
                f"    try {{\n"
                f"        try {{ await this.{var_y}.loadCodeAssist({var_t}); }} catch(_) {{}}\n"
                f"        try {{ await this.{var_y}.onboardUser(\"standard-tier\", {var_t}); }} catch(_) {{\n"
                f"            try {{ await this.{var_y}.onboardUser(\"free-tier\", {var_t}); }} catch(__) {{}}\n"
                f"        }}\n"
                f"        let __res = {{ settings: {{}}, userTier: {{ id: \"pro\", description: \"Pro\" }} }};\n"
                f"        try {{ __res = await this.refreshUserStatus({var_t}); }} catch(_) {{}}\n"
                f"        const {var_i} = {var_func}({var_t});\n"
                f"        try {{ this.{var_f}.pushUpdate({var_i}); }} catch(_) {{}}\n"
                f"        this.{var_t_send}.send({{type:\"AUTH_SUCCESS\",tokenInfo:{var_t}}});\n"
                f"        this.{var_h}.fire({{settings:__res.settings, userTier:__res.userTier}});\n"
                f"    }} catch(e) {{}}\n"
                f"    return;\n"
                f"}}"
            )
            new_content = content[:m_confeden.start()] + payload + content[m_confeden.end():]
            if not new_content.endswith("\n// UNLOCKED\n") and not new_content.endswith("\n// UNLOCKED"):
                new_content += "\n// UNLOCKED\n"
            patch_msg = "Патч Antigravity Pro Onboarding успешно применен"
        elif IDE_RE.search(content):
            new_content = IDE_RE.sub(r"\1true", content)
            patch_msg = "Патч isGoogleInternal успешно применен"
        else:
            return False, "Сигнатура для патча авторизации не найдена"

        tmp_path: str | None = None
        try:
            fd, tmp_path = tempfile.mkstemp(prefix=f".{os.path.basename(js_path)}-", suffix=".agtmp", dir=os.path.dirname(js_path))
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(new_content)
                f.flush()
                os.fsync(f.fileno())
            _copy_replace_metadata(js_path, tmp_path)
            ensure_bundle_writable(js_path, app_bundle_path)
            os.replace(tmp_path, js_path)
            tmp_path = None
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        if not _resign_app_bundle(app_bundle_path):
            _safe_copy_file(backup_path, js_path, app_bundle_path)
            _resign_app_bundle(app_bundle_path)
            return False, "Не удалось проверить подпись приложения; исходный JS восстановлен"

        clear_ide_cache()
        detector.clear_detection_cache()
        logging.info(f"Успешно пропатчен {js_path}: {patch_msg}")
        return True, patch_msg
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
            ensure_bundle_writable(js_path, app_bundle_path)
            _safe_copy_file(backup_path, js_path, app_bundle_path)
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
