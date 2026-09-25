from __future__ import annotations

import json
import os
import plistlib
import re
import shutil
import subprocess
from typing import Any

# ARM64 Manager Gate signature from AvenCores / Open Antigravity Patcher
_ARM64_TBZ_W3_BIT0 = rb"[\x03\x23\x43\x63\x83\xa3\xc3\xe3]..\x36"
_ARM64_TOKEN_SETUP = rb"(?:....){1,2}\x03\x10\x06\xa9"
ARM64_SIG_UNPATCHED = re.compile(rb"\x03\x20\x40\x39" + _ARM64_TBZ_W3_BIT0 + _ARM64_TOKEN_SETUP, re.S)
ARM64_SIG_PATCHED = re.compile(rb"\x23\x00\x80\x52\x03\x20\x00\x39" + _ARM64_TOKEN_SETUP, re.S)

# IDE main.js regex
IDE_RE = re.compile(r"(resetIsTierGCPTos\(\),)this\.[A-Za-z_$0-9]+\.isGoogleInternal")
IDE_DONE = "resetIsTierGCPTos(),true"

KNOWN_APP_CANDIDATES: list[dict[str, Any]] = [
    {
        "id": "antigravity_ide",
        "name": "Antigravity IDE",
        "icon_type": "ide",
        "paths": [
            "/Applications/Antigravity IDE.app",
            os.path.expanduser("~/Applications/Antigravity IDE.app")
        ],
        "binary_rel": [
            "Contents/Resources/app/extensions/antigravity/bin/language_server_macos_arm",
            "Contents/Resources/app/extensions/antigravity/bin/language_server_macos_x64",
            "Contents/Resources/app/extensions/antigravity/bin/language_server"
        ],
        "js_rel": "Contents/Resources/app/out/main.js"
    },
    {
        "id": "antigravity_desktop",
        "name": "Antigravity 2.0 (Desktop)",
        "icon_type": "desktop",
        "paths": [
            "/Applications/Antigravity.app",
            os.path.expanduser("~/Applications/Antigravity.app")
        ],
        "binary_rel": [
            "Contents/Resources/bin/language_server"
        ],
        "js_rel": None
    }
]

def get_app_version(app_path: str) -> str:
    info_plist = os.path.join(app_path, "Contents", "Info.plist")
    if os.path.exists(info_plist):
        try:
            with open(info_plist, "rb") as f:
                plist = plistlib.load(f)
                return plist.get("CFBundleShortVersionString") or plist.get("CFBundleVersion") or "Unknown"
        except Exception:
            pass
    # Fallback to package.json
    pkg_json = os.path.join(app_path, "Contents", "Resources", "app", "package.json")
    if os.path.exists(pkg_json):
        try:
            with open(pkg_json, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("version", "Unknown")
        except Exception:
            pass
    return "Unknown"

_MAX_CACHE_ENTRIES = 64
_BINARY_STATUS_CACHE: dict[tuple[str, float, int, bool], dict[str, Any]] = {}
_JS_STATUS_CACHE: dict[tuple[str, float, int, bool], dict[str, Any]] = {}

def clear_detection_cache() -> None:
    global _BINARY_STATUS_CACHE, _JS_STATUS_CACHE
    _BINARY_STATUS_CACHE.clear()
    _JS_STATUS_CACHE.clear()

def check_binary_status(bin_path: str | None) -> dict[str, Any]:
    if not bin_path or not os.path.exists(bin_path):
        return {
            "exists": False,
            "patched": False,
            "has_backup": False,
            "details": "Файл не найден"
        }

    has_backup = os.path.exists(bin_path + ".agybak")
    try:
        st = os.stat(bin_path)
        mtime = st.st_mtime
        size = st.st_size
    except Exception as e:
        return {
            "exists": True,
            "patched": False,
            "has_backup": has_backup,
            "details": f"Ошибка stat: {e}"
        }

    cache_key = (bin_path, mtime, size, has_backup)
    if cache_key in _BINARY_STATUS_CACHE:
        return _BINARY_STATUS_CACHE[cache_key]

    try:
        with open(bin_path, "rb") as f:
            data = f.read()

        inexigible_count = data.count(b"inexigible")
        ag_ls_proxy_count = data.count(b"AG_LS_PROXY")
        arm64_patched = bool(ARM64_SIG_PATCHED.search(data))
        
        ineligible_count = data.count(b"ineligible")
        arm64_unpatched = bool(ARM64_SIG_UNPATCHED.search(data))

        is_patched = (
            (inexigible_count > 0 or arm64_patched)
            and ineligible_count == 0
            and ag_ls_proxy_count > 0
        )

        detail_parts: list[str] = []
        if inexigible_count > 0:
            detail_parts.append("Protobuf bypass")
        if ag_ls_proxy_count > 0:
            detail_parts.append("AG_LS_PROXY route")
        if arm64_patched:
            detail_parts.append("ARM64 Gate OK")

        if is_patched:
            details = "Защита снята (" + ", ".join(detail_parts) + ")"
        elif ag_ls_proxy_count == 0 and (inexigible_count > 0 or arm64_patched):
            details = "Требуется патч маршрутизации через локальную службу"
        elif ineligible_count > 0 or arm64_unpatched:
            details = "Требуется патч"
        else:
            details = "Неизвестное состояние"

        res: dict[str, Any] = {
            "exists": True,
            "patched": is_patched,
            "has_backup": has_backup,
            "details": details,
            "size_mb": round(len(data) / (1024 * 1024), 1)
        }
        if len(_BINARY_STATUS_CACHE) >= _MAX_CACHE_ENTRIES:
            _BINARY_STATUS_CACHE.clear()
        _BINARY_STATUS_CACHE[cache_key] = res
        return res
    except Exception as e:
        return {
            "exists": True,
            "patched": False,
            "has_backup": has_backup,
            "details": f"Ошибка чтения: {e}"
        }

def check_js_status(js_path: str | None) -> dict[str, Any]:
    if not js_path or not os.path.exists(js_path):
        return {
            "exists": False,
            "patched": False,
            "has_backup": False,
            "details": "JS не требуется или не найден"
        }

    has_backup = os.path.exists(js_path + ".ag_backup")
    try:
        st = os.stat(js_path)
        mtime = st.st_mtime
        size = st.st_size
    except Exception as e:
        return {
            "exists": True,
            "patched": False,
            "has_backup": has_backup,
            "details": f"Ошибка stat JS: {e}"
        }

    cache_key = (js_path, mtime, size, has_backup)
    if cache_key in _JS_STATUS_CACHE:
        return _JS_STATUS_CACHE[cache_key]

    try:
        with open(js_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        is_patched = (IDE_DONE in content) and not bool(IDE_RE.search(content))
        unpatched = bool(IDE_RE.search(content))

        if is_patched:
            details = "isGoogleInternal -> true (патч активен)"
        elif unpatched:
            details = "Требуется патч isGoogleInternal"
        else:
            details = "Сигнатура не найдена или не требуется"

        res: dict[str, Any] = {
            "exists": True,
            "patched": is_patched,
            "has_backup": has_backup,
            "details": details
        }
        if len(_JS_STATUS_CACHE) >= _MAX_CACHE_ENTRIES:
            _JS_STATUS_CACHE.clear()
        _JS_STATUS_CACHE[cache_key] = res
        return res
    except Exception as e:
        return {
            "exists": True,
            "patched": False,
            "has_backup": has_backup,
            "details": f"Ошибка чтения JS: {e}"
        }

def is_process_running(proc_name: str, exact: bool = False) -> bool:
    try:
        cmd = ["pgrep", "-x" if exact else "-f", proc_name]
        out = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return out.returncode == 0 and len(out.stdout.strip()) > 0
    except Exception:
        return False

def detect_all_apps(custom_paths: list[str] | None = None) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    # 1. Standard apps
    for candidate in KNOWN_APP_CANDIDATES:
        found_app_path: str | None = None
        for p in candidate["paths"]:
            if os.path.exists(p):
                found_app_path = p
                break

        if not found_app_path:
            results.append({
                "id": candidate["id"],
                "name": candidate["name"],
                "installed": False,
                "app_path": None,
                "bin_path": None,
                "js_path": None,
                "version": None,
                "icon_type": candidate["icon_type"],
                "is_patched": False,
                "binary_status": {"exists": False, "patched": False, "has_backup": False, "details": "Не установлено"},
                "js_status": {"exists": False, "patched": False, "has_backup": False, "details": "N/A"},
                "is_running": False
            })
            continue

        version = get_app_version(found_app_path)
        
        # Locate binary
        bin_path: str | None = None
        for rel in candidate["binary_rel"]:
            full_b = os.path.join(found_app_path, rel)
            if os.path.exists(full_b):
                bin_path = full_b
                break

        # Locate JS
        js_path: str | None = None
        if candidate["js_rel"]:
            full_j = os.path.join(found_app_path, candidate["js_rel"])
            if os.path.exists(full_j):
                js_path = full_j

        bin_status = check_binary_status(bin_path)
        js_status = check_js_status(js_path) if js_path else {"exists": False, "patched": True, "details": "N/A"}

        # Overall patched status
        if js_path and js_status["exists"]:
            overall_patched = bin_status["patched"] and js_status["patched"]
        else:
            overall_patched = bin_status["patched"]

        bundle_base = os.path.splitext(os.path.basename(found_app_path))[0]
        running = (
            is_process_running(candidate["name"])
            or is_process_running(bundle_base)
            or (bool(bin_path) and is_process_running(os.path.basename(bin_path or "")))
        )

        results.append({
            "id": candidate["id"],
            "name": candidate["name"],
            "installed": True,
            "app_path": found_app_path,
            "bin_path": bin_path,
            "js_path": js_path,
            "version": version,
            "icon_type": candidate["icon_type"],
            "is_patched": overall_patched,
            "binary_status": bin_status,
            "js_status": js_status,
            "is_running": running
        })

    # 2. CLI agy check
    agy_path = shutil.which("agy")
    if not agy_path:
        for common_cli in [os.path.expanduser("~/.local/bin/agy"), "/usr/local/bin/agy"]:
            if os.path.exists(common_cli):
                agy_path = common_cli
                break

    if agy_path:
        agy_status = check_binary_status(agy_path)
        results.append({
            "id": "antigravity_cli",
            "name": "Antigravity CLI (agy)",
            "installed": True,
            "app_path": agy_path,
            "bin_path": agy_path,
            "js_path": None,
            "version": "CLI",
            "icon_type": "cli",
            "is_patched": agy_status["patched"],
            "binary_status": agy_status,
            "js_status": {"exists": False, "patched": True, "details": "N/A"},
            "is_running": is_process_running("agy", exact=True)
        })

    # 3. Custom paths
    if custom_paths:
        for idx, cp in enumerate(custom_paths):
            if os.path.exists(cp):
                ver = get_app_version(cp) if cp.endswith(".app") else "Custom"
                b_stat = check_binary_status(cp)
                results.append({
                    "id": f"custom_{idx}",
                    "name": f"Пользовательский ({os.path.basename(cp)})",
                    "installed": True,
                    "app_path": cp,
                    "bin_path": cp,
                    "js_path": None,
                    "version": ver,
                    "icon_type": "custom",
                    "is_patched": b_stat["patched"],
                    "binary_status": b_stat,
                    "js_status": {"exists": False, "patched": True, "details": "N/A"},
                    "is_running": False
                })

    return results
