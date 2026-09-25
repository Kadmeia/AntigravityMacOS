from __future__ import annotations

import platform
import time
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any

TEST_HOSTS: list[tuple[str, int]] = [
    ("cloudcode-pa.googleapis.com", 443),
    ("daily-cloudcode-pa.googleapis.com", 443),
    ("generativelanguage.googleapis.com", 443)
]

def test_endpoint(host: str, port: int = 443, proxy_url: str | None = None, timeout: float = 5.0, path: str = "/") -> dict[str, Any]:
    start = time.time()
    result: dict[str, Any] = {
        "host": host,
        "port": port,
        "success": False,
        "latency_ms": 0,
        "http_code": None,
        "server": None,
        "error": None
    }

    try:
        if proxy_url:
            proxy_handler = urllib.request.ProxyHandler({
                "http": proxy_url,
                "https": proxy_url
            })
            opener = urllib.request.build_opener(proxy_handler)
        else:
            opener = urllib.request.build_opener()

        req = urllib.request.Request(
            f"https://{host}{path}",
            headers={"User-Agent": f"Antigravity-Unlocker/1.1 (macOS; {platform.machine()})"}
        )
        
        try:
            with opener.open(req, timeout=timeout) as response:
                latency = round((time.time() - start) * 1000)
                result["success"] = True
                result["latency_ms"] = latency
                result["http_code"] = response.getcode()
                result["server"] = response.headers.get("Server", "Unknown")
        except urllib.error.HTTPError as he:
            latency = round((time.time() - start) * 1000)
            result["latency_ms"] = latency
            result["http_code"] = he.code
            result["server"] = he.headers.get("Server", "Unknown")
            # 404, 401, 403 on Google Frontend (ESF) is normal and means connection succeeded
            if he.code in [404, 401, 403]:
                result["success"] = True
            elif he.code == 400:
                # HTTP 400 alone does not identify a regional restriction. The
                # actual model request uses a different path and credentials.
                body = he.read(4096).decode("utf-8", errors="replace").lower()
                if "user location is not supported" in body:
                    result["error"] = "Error 400: User location is not supported"
                else:
                    result["error"] = "HTTP 400 (причина неизвестна)"
            else:
                result["success"] = False
                result["error"] = f"HTTP {he.code}"
    except Exception as e:
        latency = round((time.time() - start) * 1000)
        result["latency_ms"] = latency
        result["error"] = str(e)

    return result

def run_all_tests(proxy_url: str | None = None) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for host, port in TEST_HOSTS:
        res = test_endpoint(host, port, proxy_url)
        results.append(res)
    return results

def generate_diagnostic_report(
    app_list: list[dict[str, Any]],
    proxy_status: dict[str, Any],
    env_val: str | None,
    config: dict[str, Any]
) -> str:
    proxy_port = proxy_status.get("port", config.get("proxy_port", 53129))
    test_results = run_all_tests(
        proxy_url=f"http://127.0.0.1:{proxy_port}" if proxy_status.get("running") else None
    )
    
    mac_ver = platform.mac_ver()[0]
    arch = platform.machine()
    py_ver = platform.python_version()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "=== Antigravity Unlocker (macOS) Diagnostic Report ===",
        f"Время отчёта: {timestamp}",
        f"Система: macOS {mac_ver} ({arch}) | Python {py_ver}",
        f"Мастер-режим: {'ВКЛЮЧЕН' if config.get('master_enabled') else 'ВЫКЛЮЧЕН'}",
        f"Режим маршрутизации: {config.get('route_mode', 'smart')}",
        "",
        "--- Локальный прокси и окружение ---",
        f"Статус службы прокси: {'Работает' if proxy_status.get('running') else 'Остановлен'} (порт {proxy_port})",
        f"Переменная launchctl AG_LS_PROXY: {env_val or 'НЕ УСТАНОВЛЕНА'}",
        f"Всего подключений через прокси: {proxy_status.get('total_connections', 0)}",
        f"Активных туннелей сейчас: {proxy_status.get('active_connections', 0)}",
        "",
        "--- Обнаруженные приложения Antigravity ---"
    ]

    for app in app_list:
        lines.append(f"[{app['name']}]")
        lines.append(f"  Установлено: {'Да' if app['installed'] else 'Нет'}")
        if app['installed']:
            lines.append(f"  Путь: {app['app_path']}")
            lines.append(f"  Версия: {app['version']}")
            lines.append(f"  Общий статус: {'ПРОПАТЧЕНО (Защита снята)' if app['is_patched'] else 'НЕ ПРОПАТЧЕНО'}")
            lines.append(f"  Бинарник: {app['binary_status'].get('details', '')} (бэкап: {'Да' if app['binary_status'].get('has_backup') else 'Нет'})")
            if app.get("js_path"):
                lines.append(f"  JS (IDE): {app['js_status'].get('details', '')} (бэкап: {'Да' if app['js_status'].get('has_backup') else 'Нет'})")
            lines.append(f"  Запущен процесс: {'Да' if app.get('is_running') else 'Нет'}")
        lines.append("")

    lines.append("--- Проверка соединения с серверами Google ---")
    for tr in test_results:
        status_str = f"OK ({tr['latency_ms']} ms, HTTP {tr['http_code']})" if tr['success'] else f"FAIL ({tr.get('error')})"
        lines.append(f"  {tr['host']}: {status_str}")

    lines.append("\n=== Конец отчёта ===")
    return "\n".join(lines)
