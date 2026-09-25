from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
import os
import platform
import threading
import time
from typing import Any

from . import config

SESSION_LOG_FILE = os.path.join(config.CONFIG_DIR, "session.log")
_LOCK = threading.RLock()
_LOGGER: logging.Logger | None = None
_RECENT_MEMORY_LOGS: list[dict[str, Any]] = []
_MAX_MEMORY_LOGS = 200
_CONNECTION_COUNTS = {"CONNECT": 0, "CONNECT_FAIL": 0}


def _get_logger() -> logging.Logger:
    global _LOGGER
    with _LOCK:
        if _LOGGER is not None:
            return _LOGGER
        config.ensure_config_dir()
        logger = logging.getLogger("antigravity.session")
        logger.setLevel(logging.DEBUG)
        logger.propagate = False

        # Rotating file handler (max 3 MB, 3 backups)
        file_handler = RotatingFileHandler(
            SESSION_LOG_FILE,
            maxBytes=3 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        try:
            if os.path.exists(SESSION_LOG_FILE):
                os.chmod(SESSION_LOG_FILE, 0o600)
        except Exception:
            pass

        _LOGGER = logger
        return _LOGGER


def log_event(level: str, tag: str, message: str, extra: dict[str, Any] | None = None) -> None:
    logger = _get_logger()
    entry = {
        "time": time.strftime("%H:%M:%S"),
        "timestamp": time.time(),
        "level": level.upper(),
        "tag": tag,
        "message": message,
        "extra": extra or {},
    }
    with _LOCK:
        if tag == "SESSION_START":
            _RECENT_MEMORY_LOGS.clear()
            _CONNECTION_COUNTS.update(CONNECT=0, CONNECT_FAIL=0)
        elif tag in _CONNECTION_COUNTS:
            _CONNECTION_COUNTS[tag] += 1
        _RECENT_MEMORY_LOGS.insert(0, entry)
        if len(_RECENT_MEMORY_LOGS) > _MAX_MEMORY_LOGS:
            _RECENT_MEMORY_LOGS.pop()

    log_text = f"[{tag}] {message}"
    if level.upper() == "ERROR":
        logger.error(log_text)
    elif level.upper() in {"WARNING", "WARN"}:
        logger.warning(log_text)
    elif level.upper() == "DEBUG":
        logger.debug(log_text)
    else:
        logger.info(log_text)


def log_session_start(port: int, proxy_port: int, route_mode: str) -> None:
    sys_info = f"macOS {platform.mac_ver()[0]} ({platform.machine()}), Python {platform.python_version()}"
    log_event(
        "INFO",
        "SESSION_START",
        f"Служба запущена: API={port}, Proxy={proxy_port}, Режим={route_mode}. {sys_info}",
    )


def log_connection_success(host: str, port: int, route: str, duration_ms: float) -> None:
    log_event(
        "INFO",
        "CONNECT",
        f"{host}:{port} через {route} [OK {duration_ms}мс]",
        extra={"host": host, "port": port, "route": route, "duration_ms": duration_ms},
    )


def log_connection_error(
    host: str,
    port: int,
    route: str,
    error: Exception | str,
    duration_ms: float = 0.0,
) -> None:
    err_str = str(error).strip() or type(error).__name__
    log_event(
        "ERROR",
        "CONNECT_FAIL",
        f"{host}:{port} через {route} [FAIL {duration_ms}мс]: {err_str}",
        extra={"host": host, "port": port, "route": route, "error": err_str, "duration_ms": duration_ms},
    )


def log_route_fallback(host: str, from_route: str, to_route: str, reason: str) -> None:
    log_event(
        "WARN",
        "FALLBACK",
        f"{host}: прямое подключение ({reason}) -> переход на {to_route}",
    )


def log_config_change(key: str, old_val: Any, new_val: Any) -> None:
    log_event("INFO", "CONFIG", f"Параметр {key}: '{old_val}' -> '{new_val}'")


def get_recent_logs(limit: int = 100) -> list[dict[str, Any]]:
    with _LOCK:
        return list(_RECENT_MEMORY_LOGS[:limit])


def get_session_file_tail(max_lines: int = 100) -> str:
    with _LOCK:
        if not os.path.exists(SESSION_LOG_FILE):
            return "Журнал сессии пока пуст."
        try:
            with open(SESSION_LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                return "".join(lines[-max_lines:])
        except Exception as e:
            return f"Ошибка чтения журнала сессии: {e}"


def generate_session_summary() -> dict[str, Any]:
    with _LOCK:
        logs = list(_RECENT_MEMORY_LOGS)
        success_conns = _CONNECTION_COUNTS["CONNECT"]
        failed_conns = _CONNECTION_COUNTS["CONNECT_FAIL"]

    total_conns = success_conns + failed_conns
    failures: list[dict[str, Any]] = []

    for l in logs:
        tag = l.get("tag")
        if tag == "CONNECT_FAIL":
            failures.append({
                "time": l.get("time"),
                "host": l.get("extra", {}).get("host"),
                "route": l.get("extra", {}).get("route"),
                "error": l.get("extra", {}).get("error"),
            })

    return {
        "total_connections": total_conns,
        "success_connections": success_conns,
        "failed_connections": failed_conns,
        "recent_failures": failures[:10],
        "log_file_path": SESSION_LOG_FILE,
    }
