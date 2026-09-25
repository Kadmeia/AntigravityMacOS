from __future__ import annotations

import copy
import json
import logging
import os
import secrets
import subprocess
import sys
import threading
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Any
from urllib.parse import urlsplit

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
APP_ROOT = getattr(sys, "_MEIPASS", os.path.dirname(CURRENT_DIR))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

try:
    from . import config, detector, patcher, proxy, session_logger, tester
except ImportError:  # Direct execution: python backend/server.py
    import config
    import detector
    import patcher
    import proxy
    import session_logger
    import tester

APP_VERSION = "1.0"
API_TOKEN = config.load_or_create_api_token()
MAX_REQUEST_BODY = 64 * 1024
OPERATION_LOCK = threading.RLock()
APP_CONFIG_LOCK = threading.RLock()
ALLOWED_TARGETS = {"all", "antigravity_ide", "antigravity_desktop", "antigravity_cli"}
RESTART_APPS: dict[str, str] = {
    "antigravity_ide": "Antigravity IDE",
    "antigravity_desktop": "Antigravity",
}
FIRST_LOGIN_ENDPOINTS = (
    ("oauth2.googleapis.com", "/token"),
    ("daily-cloudcode-pa.googleapis.com", "/"),
)

# In-memory log buffer for Web UI
LOG_BUFFER: list[dict[str, str]] = []
LOG_LOCK = threading.Lock()

def add_log(msg: str, level: str = "INFO") -> None:
    entry = {
        "time": time.strftime("%H:%M:%S"),
        "level": level,
        "message": msg
    }
    with LOG_LOCK:
        LOG_BUFFER.insert(0, entry)
        if len(LOG_BUFFER) > 100:
            LOG_BUFFER.pop()
    logging.info(f"[{level}] {msg}")

# Initialize configuration
app_config: dict[str, Any] = config.load_config()


def get_config_snapshot() -> dict[str, Any]:
    with APP_CONFIG_LOCK:
        return copy.deepcopy(app_config)


def commit_config(updated: dict[str, Any]) -> bool:
    """Persist first, then publish an in-memory configuration atomically."""
    with APP_CONFIG_LOCK:
        if not config.save_config(updated):
            return False
        app_config.clear()
        app_config.update(copy.deepcopy(updated))
    return True

# Global proxy instance
local_proxy = proxy.LocalProxyServer(
    host="127.0.0.1",
    port=app_config.get("proxy_port", 53129),
    config_getter=get_config_snapshot,
)


def check_first_login_ready() -> tuple[bool, str]:
    """Check the actual local proxy and HTTPS routes before launching the GUI."""
    if not get_config_snapshot().get("master_enabled", False) or not local_proxy.running:
        return False, "Локальная служба ещё не готова"
    proxy_url = f"http://127.0.0.1:{local_proxy.port}"
    if proxy.get_macos_proxy_env() != proxy_url:
        return False, "Адрес локальной службы не передан macOS"
    for host, path in FIRST_LOGIN_ENDPOINTS:
        result: dict[str, Any] = {}
        reachable = False
        for attempt in range(3):
            result = tester.test_endpoint(host, proxy_url=proxy_url, timeout=5.0, path=path)
            error = result.get("error") or ""
            reachable = bool(result.get("success")) or (
                isinstance(result.get("http_code"), int)
                and "User location is not supported" not in error
            )
            if reachable:
                break
            if attempt < 2:
                time.sleep(0.75 * (attempt + 1))
        if not reachable:
            return False, f"Нет HTTPS-связи с {host} через службу: {result.get('error') or 'неизвестная ошибка'}"
    return True, proxy_url

# Background Watchdog for Auto-Repatch upon Antigravity update
WATCHDOG_FAILS: dict[str, tuple[int, float]] = {}

def watchdog_worker() -> None:
    while True:
        try:
            time.sleep(10)
            current_config = get_config_snapshot()
            if not current_config.get("auto_patch_on_launch", True):
                continue
            if not current_config.get("master_enabled", False):
                continue

            with OPERATION_LOCK:
                current_config = get_config_snapshot()
                if not current_config.get("master_enabled", False) or not current_config.get("auto_patch_on_launch", True):
                    continue
                managed = set(current_config.get("managed_targets", []))
                if not managed:
                    continue
                apps = detector.detect_all_apps(current_config.get("custom_app_paths", []))
                now = time.time()
                for app in apps:
                    app_id = app["id"]
                    if app_id not in managed:
                        continue
                    if app["installed"] and not app["is_patched"]:
                        # Check fail cooldown to prevent kill_language_server storms
                        if app_id in WATCHDOG_FAILS:
                            fail_count, last_fail = WATCHDOG_FAILS[app_id]
                            if fail_count >= 5:
                                continue  # Give up auto-retrying this session to avoid DoS on LSP
                            cooldown = 30.0 * (2 ** min(fail_count - 1, 3))
                            if now - last_fail < cooldown:
                                continue

                        add_log(f"Обнаружено обновление {app['name']}! Выполняется автопатч...", "ACTION")
                        ok, msg = patcher.patch_app_fully(app)
                        if ok:
                            WATCHDOG_FAILS.pop(app_id, None)
                            add_log(f"Автопатч {app['name']} успешно завершен: {msg}", "SUCCESS")
                        else:
                            count = WATCHDOG_FAILS.get(app_id, (0, 0))[0] + 1
                            WATCHDOG_FAILS[app_id] = (count, now)
                            add_log(f"Ошибка автопатча {app['name']}: {msg}", "ERROR")
                    elif app["installed"] and app["is_patched"]:
                        WATCHDOG_FAILS.pop(app_id, None)
        except Exception as e:
            logging.debug(f"Watchdog exception: {e}")

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class AntigravityAPIHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.frontend_dir = os.path.join(APP_ROOT, "frontend")
        super().__init__(*args, directory=self.frontend_dir, **kwargs)

    def do_GET(self) -> None:
        if not self._is_loopback_request():
            self._send_json({"error": "Forbidden host"}, status=403)
            return

        origin = self.headers.get("Origin")
        if origin and not self._is_allowed_origin(origin):
            self._send_json({"error": "Cross-origin request rejected"}, status=403)
            return

        request_path = urlsplit(self.path).path
        if request_path == "/api/health":
            self._send_json({"product": "antigravity-unlocker", "version": APP_VERSION})
        elif request_path.startswith("/api/") and not self._is_valid_api_token():
            self._send_json({"error": "Недействительный токен сессии"}, status=403)
        elif request_path == "/api/ping":
            self._send_json(
                {"product": "antigravity-unlocker", "version": APP_VERSION, "success": True}
            )
        elif request_path == "/api/status":
            self._handle_get_status()
        elif request_path == "/api/report":
            self._handle_get_report()
        elif request_path == "/api/logs":
            self._handle_get_logs()
        elif request_path == "/api/session/logs":
            self._handle_get_session_logs()
        elif request_path == "/api/session/summary":
            self._handle_get_session_summary()
        else:
            super().do_GET()

    def do_POST(self) -> None:
        try:
            content_len = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_len = 0

        # Drain body if within limits to avoid TCP RST on unread socket buffers in BSD/macOS
        body = b""
        if 0 < content_len <= MAX_REQUEST_BODY:
            body = self.rfile.read(content_len)

        validation_error = self._validate_mutating_request()
        if validation_error:
            status, message = validation_error
            self._send_json({"success": False, "error": message}, status=status)
            return

        try:
            req_data = json.loads(body.decode("utf-8")) if body else {}
            if not isinstance(req_data, dict):
                raise ValueError("JSON object required")
        except Exception:
            self._send_json({"success": False, "error": "Некорректный JSON"}, status=400)
            return

        if self.path == "/api/patch_now":
            self._handle_patch_now(req_data)
        elif self.path == "/api/unpatch_now":
            self._handle_unpatch_now(req_data)
        elif self.path == "/api/master/toggle":
            self._handle_master_toggle(req_data)
        elif self.path == "/api/patch/app":
            self._handle_patch_app(req_data)
        elif self.path == "/api/unpatch/app":
            self._handle_unpatch_app(req_data)
        elif self.path == "/api/managed/disable":
            self._handle_disable_managed(req_data)
        elif self.path == "/api/restart_app":
            self._handle_restart_app(req_data)
        elif self.path == "/api/settings":
            self._handle_save_settings(req_data)
        elif self.path == "/api/test":
            self._handle_run_test(req_data)
        elif self.path == "/api/open-url":
            self._handle_open_url(req_data)
        else:
            self._send_json({"error": "Not found"}, status=404)

    def _send_json(self, data: Any, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
        )
        super().end_headers()

    def _is_loopback_request(self) -> bool:
        try:
            host = urlsplit("//" + self.headers.get("Host", "")).hostname
            return host in {"127.0.0.1", "localhost", "::1"}
        except ValueError:
            return False

    def _is_allowed_origin(self, origin: str) -> bool:
        try:
            parsed = urlsplit(origin)
            expected_port = self.server.server_port
            origin_port = parsed.port or (443 if parsed.scheme == "https" else 80)
            return (
                parsed.scheme == "http"
                and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
                and origin_port == expected_port
            )
        except ValueError:
            return False

    def _validate_mutating_request(self) -> tuple[int, str] | None:
        if not self._is_loopback_request():
            return 403, "Forbidden host"
        try:
            content_len = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return 400, "Некорректная длина запроса"
        if content_len < 0 or content_len > MAX_REQUEST_BODY:
            return 413, "Запрос слишком большой"
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            return 415, "Требуется Content-Type: application/json"
        if not self._is_valid_api_token():
            return 403, "Недействительный токен сессии"
        origin = self.headers.get("Origin")
        if origin and not self._is_allowed_origin(origin):
            return 403, "Cross-origin request rejected"
        return None

    def _is_valid_api_token(self) -> bool:
        return secrets.compare_digest(self.headers.get("X-Antigravity-Token", ""), API_TOKEN)

    def _is_valid_target(self, target: Any) -> bool:
        if not isinstance(target, str):
            return False
        if target in ALLOWED_TARGETS or target.startswith("custom_"):
            return True
        return False

    def _status_data(self) -> dict[str, Any]:
        current_config = get_config_snapshot()
        apps = detector.detect_all_apps(current_config.get("custom_app_paths", []))
        env_val = proxy.get_macos_proxy_env()
        with local_proxy.lock:
            proxy_stat = local_proxy.stats.copy()
            proxy_stat["running"] = local_proxy.running
            proxy_stat["port"] = local_proxy.port
            # Deep copy of recent_requests list prevents RuntimeError: list changed size during iteration
            proxy_stat["recent_requests"] = list(local_proxy.stats.get("recent_requests", []))
        with LOG_LOCK:
            logs = list(LOG_BUFFER[:30])
        installed_apps = [a for a in apps if a["installed"]]
        return {
            "version": APP_VERSION,
            "master_enabled": current_config.get("master_enabled", False),
            "all_patched": bool(installed_apps) and all(a["is_patched"] for a in installed_apps),
            "selected_target": current_config.get("selected_target", "all"),
            "managed_targets": current_config.get("managed_targets", []),
            "proxy": proxy_stat,
            "env_var": env_val,
            "apps": apps,
            "config": {
                "route_mode": current_config.get("route_mode", "smart"),
                "custom_proxy": copy.deepcopy(current_config.get("custom_proxy", {})),
                "auto_patch_on_launch": current_config.get("auto_patch_on_launch", True),
                "selected_target": current_config.get("selected_target", "all"),
            },
            "logs": logs,
        }

    def _handle_get_status(self) -> None:
        self._send_json(self._status_data())

    def _handle_patch_now(self, req_data: dict[str, Any]) -> None:
        target = req_data.get("target", "all")
        if not self._is_valid_target(target):
            self._send_json({"success": False, "error": "Неизвестная цель"}, status=400)
            return
        with OPERATION_LOCK:
            current_config = get_config_snapshot()
            first_activation = not current_config.get("master_enabled", False)
            apps = detector.detect_all_apps(current_config.get("custom_app_paths", []))
            targets_to_patch = ([a for a in apps if a["installed"]] if target == "all"
                                else [a for a in apps if a["id"] == target and a["installed"]])
            if not targets_to_patch:
                self._send_json({"success": False, "error": "Установленные приложения не найдены"}, status=404)
                return

            add_log(f"Запуск снятия защиты для: {target}...", "ACTION")
            results = []
            for app in targets_to_patch:
                ok, msg = patcher.patch_app_fully(app)
                results.append({"app_id": app["id"], "success": ok, "message": msg})
                add_log(f"{app['name']}: {msg}", "SUCCESS" if ok else "ERROR")

            patched_ids = {item["app_id"] for item in results if item["success"]}
            managed = set(current_config.get("managed_targets", [])) | patched_ids
            current_config["managed_targets"] = sorted(managed)
            current_config["selected_target"] = target
            proxy_ok = local_proxy.start() if managed else False
            env_ok = proxy.set_macos_proxy_env(local_proxy.port) if proxy_ok else False
            success = all(item["success"] for item in results) and proxy_ok and env_ok
            current_config["master_enabled"] = bool(managed and proxy_ok and env_ok)
            if not commit_config(current_config):
                success = False
            if not current_config["master_enabled"]:
                local_proxy.stop()
                proxy.unset_macos_proxy_env()
            launch_result = None
            if success and first_activation and req_data.get("launch_after_patch") is True:
                gui_apps = [app for app in targets_to_patch if app["id"] in RESTART_APPS]
                gui_apps.sort(key=lambda app: app["id"] != "antigravity_desktop")
                if gui_apps:
                    app = gui_apps[0]
                    ready, detail = check_first_login_ready()
                    if ready:
                        launched, detail = patcher.restart_app(
                            RESTART_APPS[app["id"]], proxy_url=detail, app_path=app["app_path"]
                        )
                    else:
                        launched = False
                    launch_result = {"app_id": app["id"], "success": launched, "message": detail}
                    if not launched:
                        success = False
            if launch_result and launch_result["success"]:
                message = f"Патч установлен; {RESTART_APPS[launch_result['app_id']]} запущен через локальную службу"
            elif launch_result:
                message = f"Патч установлен, но первый запуск не выполнен: {launch_result['message']}"
            elif success and all("Уже пропатчен" in item["message"] for item in results):
                message = "Патч уже актуален; локальная служба проверена"
            else:
                message = "Изменения применены" if success else "Операция завершилась с ошибкой"
                failures = [item["message"] for item in results if not item["success"]]
                if failures:
                    message += ": " + "; ".join(failures)
            add_log(message, "SUCCESS" if success else "ERROR")
            data = self._status_data()
            data["action"] = {"success": success, "message": message, "results": results, "launch": launch_result}
            self._send_json(data, status=200 if success else 500)

    def _handle_unpatch_now(self, req_data: dict[str, Any]) -> None:
        target = req_data.get("target", "all")
        if not self._is_valid_target(target):
            self._send_json({"success": False, "error": "Неизвестная цель"}, status=400)
            return
        with OPERATION_LOCK:
            current_config = get_config_snapshot()
            apps = detector.detect_all_apps(current_config.get("custom_app_paths", []))
            targets_to_unpatch = ([a for a in apps if a["installed"]] if target == "all"
                                  else [a for a in apps if a["id"] == target and a["installed"]])
            if not targets_to_unpatch:
                self._send_json({"success": False, "error": "Установленные приложения не найдены"}, status=404)
                return
            # Persist opt-out before touching files. A failed restore must never
            # let the watchdog repatch this app on its next scan.
            removed_ids = {app["id"] for app in targets_to_unpatch}
            current_config["managed_targets"] = [item for item in current_config.get("managed_targets", [])
                                                 if item not in removed_ids]
            if not commit_config(current_config):
                self._send_json({"success": False, "error": "Не удалось отключить автопатч"}, status=500)
                return
            add_log(f"Запуск отката защиты для: {target}...", "ACTION")
            results = []
            for app in targets_to_unpatch:
                ok, msg = patcher.unpatch_app_fully(app)
                results.append({"app_id": app["id"], "success": ok, "message": msg})
                add_log(f"Откат {app['name']}: {msg}", "INFO" if ok else "ERROR")
            success = all(item["success"] for item in results)
            if not current_config["managed_targets"]:
                local_proxy.stop()
                proxy.unset_macos_proxy_env()
                current_config["master_enabled"] = False
                commit_config(current_config)
            if success:
                message = "Патч выбранной программы снят из резервной копии"
            elif any("Operation not permitted" in item["message"] for item in results):
                message = (
                    "macOS запретила фоновой службе изменять файлы в /Applications. "
                    "Откат не выполнен. Доступ нужен процессу службы Python; "
                    "разрешения одному Терминалу недостаточно."
                )
            else:
                message = "Не все файлы удалось восстановить"
            data = self._status_data()
            data["action"] = {"success": success, "message": message, "results": results}
            self._send_json(data, status=200 if success else 500)

    def _handle_master_toggle(self, req_data: dict[str, Any]) -> None:
        target_state = req_data.get("enabled")
        if target_state is None:
            target_state = not get_config_snapshot().get("master_enabled", False)
        elif not isinstance(target_state, bool):
            self._send_json({"success": False, "error": "Некорректное состояние"}, status=400)
            return

        if target_state:
            self._handle_patch_now({"target": get_config_snapshot().get("selected_target", "all")})
        else:
            self._handle_unpatch_now({"target": get_config_snapshot().get("selected_target", "antigravity_desktop")})

    def _handle_patch_app(self, req_data: dict[str, Any]) -> None:
        self._handle_patch_now({"target": req_data.get("app_id")})

    def _handle_unpatch_app(self, req_data: dict[str, Any]) -> None:
        self._handle_unpatch_now({"target": req_data.get("app_id")})

    def _handle_disable_managed(self, req_data: dict[str, Any]) -> None:
        """Opt one selected app out before restoring it from an official DMG."""
        app_id = req_data.get("app_id")
        if not self._is_valid_target(app_id) or app_id == "all":
            self._send_json({"success": False, "error": "Неизвестная программа"}, status=400)
            return
        with OPERATION_LOCK:
            candidate = get_config_snapshot()
            candidate["managed_targets"] = [item for item in candidate.get("managed_targets", [])
                                            if item != app_id]
            if not candidate["managed_targets"]:
                candidate["master_enabled"] = False
            if not commit_config(candidate):
                self._send_json({"success": False, "error": "Не удалось отключить автопатч"}, status=500)
                return
            if not candidate["master_enabled"]:
                local_proxy.stop()
                proxy.unset_macos_proxy_env()
            self._send_json({"success": True, "managed_targets": candidate["managed_targets"]})

    def _handle_restart_app(self, req_data: dict[str, Any]) -> None:
        app_id = req_data.get("app_id", "antigravity_ide")
        app_name = RESTART_APPS.get(app_id) if isinstance(app_id, str) else None
        if not app_name:
            self._send_json({"success": False, "error": "Неизвестное приложение"}, status=400)
            return
        with OPERATION_LOCK:
            app = next((item for item in detector.detect_all_apps() if item["id"] == app_id), None)
            if not app or not app["installed"] or not app["is_patched"]:
                self._send_json({"success": False, "error": "Сначала установите патч для выбранной программы"}, status=409)
                return
            ready, detail = check_first_login_ready()
            if not ready:
                self._send_json({"success": False, "error": detail}, status=503)
                return
            add_log(f"Перезапуск {app_name}...", "ACTION")
            ok, msg = patcher.restart_app(app_name, proxy_url=detail, app_path=app["app_path"])
            add_log(msg, "SUCCESS" if ok else "ERROR")
            self._send_json({"success": ok, "message": msg})

    def _handle_save_settings(self, req_data: dict[str, Any]) -> None:
        # Serialize the entire read/modify/write transaction with patch actions.
        with OPERATION_LOCK:
            self._save_settings_locked(req_data)

    def _save_settings_locked(self, req_data: dict[str, Any]) -> None:
        candidate = get_config_snapshot()
        old_mode = candidate.get("route_mode")
        if "route_mode" in req_data:
            if (not isinstance(req_data["route_mode"], str)
                    or req_data["route_mode"] not in {"smart", "tls_split", "custom", "direct"}):
                self._send_json({"success": False, "error": "Некорректный режим маршрутизации"}, status=400)
                return
            candidate["route_mode"] = req_data["route_mode"]

        if "custom_proxy" in req_data:
            custom = req_data["custom_proxy"]
            if (not isinstance(custom, dict)
                    or not isinstance(custom.get("type"), str)
                    or custom.get("type") not in {"http", "socks5"}):
                self._send_json({"success": False, "error": "Некорректный тип прокси"}, status=400)
                return
            host = custom.get("host")
            try:
                port = int(custom.get("port"))
            except (TypeError, ValueError):
                port = 0
            if not isinstance(host, str) or not host.strip() or len(host) > 253 or not 1 <= port <= 65535:
                self._send_json({"success": False, "error": "Некорректный адрес прокси"}, status=400)
                return
            candidate["custom_proxy"] = {"type": custom["type"], "host": host.strip(), "port": port}

        if "auto_patch_on_launch" in req_data:
            if not isinstance(req_data["auto_patch_on_launch"], bool):
                self._send_json({"success": False, "error": "Некорректное значение автопатча"}, status=400)
                return
            candidate["auto_patch_on_launch"] = req_data["auto_patch_on_launch"]

        if "selected_target" in req_data:
            if not self._is_valid_target(req_data["selected_target"]):
                self._send_json({"success": False, "error": "Некорректная цель"}, status=400)
                return
            candidate["selected_target"] = req_data["selected_target"]

        if "custom_app_paths" in req_data:
            if not isinstance(req_data["custom_app_paths"], list):
                self._send_json({"success": False, "error": "Некорректный список путей"}, status=400)
                return
            valid_paths = []
            for value in req_data["custom_app_paths"]:
                if not isinstance(value, str):
                    continue
                path = os.path.realpath(value.strip())
                if os.path.isabs(path) and os.path.isfile(path) and not os.path.islink(path):
                    valid_paths.append(path)
            candidate["custom_app_paths"] = valid_paths

        if not commit_config(candidate):
            self._send_json({"success": False, "error": "Не удалось сохранить настройки"}, status=500)
            return
        if old_mode != candidate.get("route_mode"):
            session_logger.log_config_change("route_mode", old_mode, candidate["route_mode"])
        add_log("Настройки сохранены", "INFO")
        self._send_json({"success": True, "config": candidate})

    def _handle_run_test(self, req_data: dict[str, Any]) -> None:
        add_log("Запуск теста связи с серверами Google...", "ACTION")
        p_url = f"http://127.0.0.1:{local_proxy.port}" if local_proxy.running else None
        res = tester.run_all_tests(proxy_url=p_url)
        for r in res:
            if r["success"]:
                add_log(f"Тест {r['host']}: OK ({r['latency_ms']} ms)", "SUCCESS")
            else:
                add_log(f"Тест {r['host']}: Ошибка ({r.get('error')})", "WARN")
        self._send_json({"results": res})

    def _handle_open_url(self, req_data: dict[str, Any]) -> None:
        url = str(req_data.get("url", "")).strip()
        try:
            parsed = urlsplit(url)
            valid_url = parsed.scheme in {"http", "https"} and bool(parsed.hostname)
        except ValueError:
            valid_url = False
        if valid_url:
            try:
                subprocess.run(["open", url], check=False)
                self._send_json({"success": True})
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=500)
        else:
            self._send_json({"success": False, "error": "Недопустимый URL"}, status=400)

    def _handle_get_report(self) -> None:
        current_config = get_config_snapshot()
        apps = detector.detect_all_apps(current_config.get("custom_app_paths", []))
        env_val = proxy.get_macos_proxy_env()
        with local_proxy.lock:
            proxy_stat = local_proxy.stats.copy()
            proxy_stat["running"] = local_proxy.running
            proxy_stat["port"] = local_proxy.port
            proxy_stat["recent_requests"] = list(local_proxy.stats.get("recent_requests", []))
        report_text = tester.generate_diagnostic_report(apps, proxy_stat, env_val, current_config)
        summary = session_logger.generate_session_summary()
        failures = summary.get("recent_failures", [])
        if failures:
            report_text += "\n\n--- Недавние сбои подключения (Session Log) ---\n"
            for f in failures:
                report_text += f"  [{f.get('time')}] {f.get('host')} через {f.get('route')}: {f.get('error')}\n"
        self._send_json({"report": report_text})

    def _handle_get_logs(self) -> None:
        with LOG_LOCK:
            logs = list(LOG_BUFFER)
        self._send_json({"logs": logs})

    def _handle_get_session_logs(self) -> None:
        recent = session_logger.get_recent_logs(100)
        file_tail = session_logger.get_session_file_tail(150)
        summary = session_logger.generate_session_summary()
        self._send_json({
            "recent": recent,
            "raw_tail": file_tail,
            "summary": summary,
        })

    def _handle_get_session_summary(self) -> None:
        summary = session_logger.generate_session_summary()
        self._send_json(summary)

def start_server(port: int = 53128) -> None:
    server = ThreadedHTTPServer(("127.0.0.1", port), AntigravityAPIHandler)
    current_config = get_config_snapshot()
    session_logger.log_session_start(
        port=port,
        proxy_port=local_proxy.port,
        route_mode=current_config.get("route_mode", "smart"),
    )
    if current_config.get("master_enabled", False):
        proxy_started = local_proxy.start()
        env_set = proxy.set_macos_proxy_env(local_proxy.port) if proxy_started else False
        if not (proxy_started and env_set):
            local_proxy.stop()
            proxy.unset_macos_proxy_env()
            current_config["master_enabled"] = False
            commit_config(current_config)
            add_log("Не удалось восстановить локальную службу после запуска", "ERROR")

    # Start watchdog thread
    w_thread = threading.Thread(target=watchdog_worker, daemon=True)
    w_thread.start()
    add_log(f"Сервер запущен на http://127.0.0.1:{port}", "SUCCESS")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        local_proxy.stop()
        proxy.unset_macos_proxy_env()

if __name__ == "__main__":
    p = get_config_snapshot().get("web_port", 53128)
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        p = int(sys.argv[1])
    start_server(p)
