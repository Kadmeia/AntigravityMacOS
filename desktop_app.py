#!/usr/bin/env python3
"""
Antigravity Unlocker by Kadmeia — Нативное приложение для macOS (pywebview Cocoa/WebKit).
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import platform
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.parse
from typing import Any

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

def run_packaged_self_test() -> int:
    """Validate frozen runtime and bundled UI without starting services or a GUI."""
    root = getattr(sys, "_MEIPASS", CURRENT_DIR)
    required = [
        os.path.join(root, "frontend", "index.html"),
        os.path.join(root, "frontend", "app.js"),
        os.path.join(root, "frontend", "styles.css"),
    ]
    missing = [path for path in required if not os.path.isfile(path)]
    try:
        import webview  # noqa: F401
        webview_available = True
    except Exception:
        webview_available = False
    result: dict[str, Any] = {
        "success": not missing and webview_available,
        "frozen": bool(getattr(sys, "frozen", False)),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "webview": webview_available,
        "missing_resources": missing,
    }
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["success"] else 1

if __name__ == "__main__" and "--self-test" in sys.argv:
    raise SystemExit(run_packaged_self_test())

from backend import config, proxy, server

def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

def get_backend_health(port: int) -> dict[str, Any] | None:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=1.0) as response:
            data = json.loads(response.read().decode("utf-8"))
        return data if isinstance(data, dict) and data.get("product") == "antigravity-unlocker" else None
    except Exception:
        return None


def get_authenticated_backend_ping(port: int) -> dict[str, Any] | None:
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/ping",
            headers={"X-Antigravity-Token": server.API_TOKEN},
        )
        with urllib.request.urlopen(request, timeout=1.0) as response:
            data = json.loads(response.read().decode("utf-8"))
        if (
            isinstance(data, dict)
            and data.get("product") == "antigravity-unlocker"
            and data.get("success") is True
        ):
            return data
    except Exception:
        pass
    return None

def shutdown_backend() -> None:
    server.local_proxy.stop()
    proxy.unset_macos_proxy_env()

def _candidate_ports(preferred_port: int) -> list[int]:
    # 53129 is reserved for the local CONNECT proxy.
    fallbacks = [port for port in range(53130, 53150) if port != preferred_port]
    return [preferred_port, *fallbacks]


def _select_runtime_proxy_port() -> int:
    preferred_port = int(server.local_proxy.port)
    if not is_port_in_use(preferred_port):
        return preferred_port
    for port in range(53150, 53170):
        if not is_port_in_use(port):
            logging.warning(
                "Порт локального прокси %s занят; используется порт %s",
                preferred_port,
                port,
            )
            server.local_proxy.port = port
            return port
    raise RuntimeError("Нет свободного локального порта для прокси")


def start_backend(preferred_port: int) -> int:
    # Reuse a compatible process on any known UI port. This makes repeated app
    # launches open normally instead of failing with "already running".
    for port in _candidate_ports(preferred_port):
        if is_port_in_use(port) and get_authenticated_backend_ping(port):
            return port

    selected_port = next(
        (port for port in _candidate_ports(preferred_port) if not is_port_in_use(port)),
        None,
    )
    if selected_port is None:
        raise RuntimeError("Нет свободного локального порта для запуска приложения")

    _select_runtime_proxy_port()

    if selected_port != preferred_port:
        occupied = get_backend_health(preferred_port)
        if occupied:
            logging.warning(
                "Порт %s занят Antigravity Unlocker %s; используется порт %s",
                preferred_port,
                occupied.get("version", "неизвестной версии"),
                selected_port,
            )
        else:
            logging.warning(
                "Порт %s занят другим процессом; используется порт %s",
                preferred_port,
                selected_port,
            )

    thread = threading.Thread(target=server.start_server, args=(selected_port,), daemon=True)
    thread.start()
    for _ in range(50):
        if get_authenticated_backend_ping(selected_port):
            atexit.register(shutdown_backend)
            return selected_port
        time.sleep(0.1)
    raise RuntimeError("Локальная служба не запустилась")

def run_native_app() -> None:
    cfg = config.load_config()
    web_port = int(cfg.get("web_port", 53128))

    # 1. Start local backend
    web_port = start_backend(web_port)

    protected_url = (
        f"http://127.0.0.1:{web_port}/#token="
        f"{urllib.parse.quote(server.API_TOKEN, safe='')}"
    )

    # 2. Check if pywebview is available
    try:
        import webview
        logging.info("Запуск нативного окна pywebview (Cocoa/WebKit)...")

        # Create compact, elegant desktop window (like Amnezia VPN)
        webview.create_window(
            title="Antigravity Unlocker — by Kadmeia",
            url=protected_url,
            width=435,
            height=720,
            resizable=True,
            easy_drag=True,
            on_top=False
        )

        webview.start(gui="cocoa", debug=False)
    except Exception as e:
        logging.warning(f"Не удалось запустить pywebview: {e}. Открытие в браузере...")
        subprocess.run(["open", protected_url], check=False)
        print(f"\n[Antigravity Unlocker] Сервер запущен на http://127.0.0.1:{web_port}/")
        print("Веб-интерфейс открыт в браузере. Для завершения работы нажмите Ctrl+C...")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nЗавершение работы...")

if __name__ == "__main__":
    run_native_app()
