from __future__ import annotations

import copy
import http.client
import io
import json
import os
import subprocess
import threading
import urllib.request
import urllib.error

import desktop_app
from backend import config, detector, patcher, proxy, server, session_logger, tester


def test_config_deep_merges_custom_proxy(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(config, "CONFIG_FILE", str(tmp_path / "config.json"))
    (tmp_path / "config.json").write_text(
        json.dumps({"custom_proxy": {"host": "proxy.local"}}), encoding="utf-8"
    )

    loaded = config.load_config()

    assert loaded["custom_proxy"] == {
        "type": "http",
        "host": "proxy.local",
        "port": 7890,
    }


def test_legacy_config_enrolls_only_desktop_for_auto_patch(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(config, "CONFIG_FILE", str(tmp_path / "config.json"))
    (tmp_path / "config.json").write_text(
        json.dumps({"master_enabled": True, "selected_target": "all"}), encoding="utf-8"
    )

    assert config.load_config()["managed_targets"] == ["antigravity_desktop"]


def test_api_token_is_stable_and_private(tmp_path, monkeypatch):
    token_path = tmp_path / "api-token"
    monkeypatch.setattr(config, "CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(config, "API_TOKEN_FILE", str(token_path))

    first = config.load_or_create_api_token()
    second = config.load_or_create_api_token()

    assert first == second
    assert len(first) >= 32
    assert (token_path.stat().st_mode & 0o777) == 0o600


def test_start_backend_reuses_compatible_process(monkeypatch):
    monkeypatch.setattr(desktop_app, "is_port_in_use", lambda port: port == 53130)
    monkeypatch.setattr(
        desktop_app,
        "get_authenticated_backend_ping",
        lambda port: {"success": True} if port == 53130 else None,
    )

    assert desktop_app.start_backend(53128) == 53130


def test_start_backend_falls_back_when_old_version_owns_default_port(monkeypatch):
    started = []

    class ImmediateThread:
        def __init__(self, target, args, daemon):
            self.target = target
            self.args = args

        def start(self):
            self.target(*self.args)

    monkeypatch.setattr(desktop_app, "is_port_in_use", lambda port: port == 53128)
    monkeypatch.setattr(desktop_app, "get_backend_health", lambda port: {"version": "0.9.0"})
    monkeypatch.setattr(desktop_app.threading, "Thread", ImmediateThread)
    monkeypatch.setattr(desktop_app.server, "start_server", lambda port: started.append(port))
    monkeypatch.setattr(
        desktop_app,
        "get_authenticated_backend_ping",
        lambda port: {"success": True} if port in started else None,
    )

    assert desktop_app.start_backend(53128) == 53130
    assert started == [53130]


def test_patch_app_propagates_component_failure(tmp_path, monkeypatch):
    binary = tmp_path / "language_server"
    javascript = tmp_path / "main.js"
    binary.write_bytes(b"binary")
    javascript.write_text("js", encoding="utf-8")
    monkeypatch.setattr(patcher, "patch_binary_file", lambda *_: (True, "binary ok"))
    monkeypatch.setattr(patcher, "patch_js_file", lambda *_: (False, "js failed"))

    ok, message = patcher.patch_app_fully(
        {"bin_path": str(binary), "js_path": str(javascript), "app_path": None}
    )

    assert ok is False
    assert "js failed" in message


def test_unpatch_without_components_is_failure():
    ok, message = patcher.unpatch_app_fully(
        {"bin_path": None, "js_path": None, "app_path": None}
    )
    assert ok is False
    assert "не найдены" in message


def _post_request(port, path, *, token=None, origin=None, body=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Antigravity-Token"] = token
    if origin:
        headers["Origin"] = origin
    connection.request("POST", path, body=json.dumps(body or {}), headers=headers)
    response = connection.getresponse()
    data = json.loads(response.read().decode("utf-8"))
    connection.close()
    return response.status, data


def _get_request(port, path, *, token=None, origin=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    headers = {}
    if origin:
        headers["Origin"] = origin
    if token:
        headers["X-Antigravity-Token"] = token
    connection.request("GET", path, headers=headers)
    response = connection.getresponse()
    data = json.loads(response.read().decode("utf-8"))
    connection.close()
    return response.status, data


def test_api_rejects_missing_token_and_cross_origin(monkeypatch):
    original_config = copy.deepcopy(server.app_config)
    monkeypatch.setattr(server.config, "save_config", lambda _: True)
    httpd = server.ThreadedHTTPServer(("127.0.0.1", 0), server.AntigravityAPIHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    port = httpd.server_port
    try:
        status, _ = _post_request(port, "/api/settings", body={"route_mode": "direct"})
        assert status == 403

        status, _ = _post_request(
            port,
            "/api/settings",
            token=server.API_TOKEN,
            origin="https://attacker.invalid",
            body={"route_mode": "direct"},
        )
        assert status == 403

        status, data = _post_request(
            port,
            "/api/settings",
            token=server.API_TOKEN,
            origin=f"http://127.0.0.1:{port}",
            body={"route_mode": "direct"},
        )
        assert status == 200
        assert data["success"] is True
    finally:
        server.app_config.clear()
        server.app_config.update(original_config)
        httpd.shutdown()
        httpd.server_close()


def test_api_rejects_unknown_restart_target(monkeypatch):
    monkeypatch.setattr(server.config, "save_config", lambda _: True)
    httpd = server.ThreadedHTTPServer(("127.0.0.1", 0), server.AntigravityAPIHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        status, data = _post_request(
            httpd.server_port,
            "/api/restart_app",
            token=server.API_TOKEN,
            body={"app_id": "\"; do shell script \"touch /tmp/nope"},
        )
        assert status == 400
        assert data["success"] is False
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_parse_connect_target():
    # IPv4 / standard domain
    host, port = proxy.parse_connect_target("cloudcode-pa.googleapis.com:443")
    assert host == "cloudcode-pa.googleapis.com"
    assert port == 443

    # IPv6 bracketed
    host6, port6 = proxy.parse_connect_target("[::1]:8443")
    assert host6 == "::1"
    assert port6 == 8443

    # IPv6 long
    host_long, port_long = proxy.parse_connect_target("[2001:db8::1]:443")
    assert host_long == "2001:db8::1"
    assert port_long == 443

    # Default port
    host_def, port_def = proxy.parse_connect_target("example.com")
    assert host_def == "example.com"
    assert port_def == 443

    assert proxy.is_safe_connect_target("127.0.0.1", 443) is False
    assert proxy.is_safe_connect_target("10.0.0.1", 443) is False
    assert proxy.is_safe_connect_target("8.8.8.8", 443) is True
    assert proxy.is_safe_connect_target("8.8.8.8", 8443) is False


def test_cloudcode_connect_fallback_does_not_require_system_dns(monkeypatch):
    def no_dns(*args, **kwargs):
        raise OSError("DNS unavailable")

    monkeypatch.setattr(proxy.socket, "getaddrinfo", no_dns)
    for host in proxy.CLOUDCODE_HOSTS:
        assert proxy.is_safe_connect_target(host, 443) is True
    assert proxy.is_safe_connect_target("private.example", 443) is False


def test_diagnostic_400_requires_explicit_location_message(monkeypatch):
    class FailingOpener:
        def __init__(self, body):
            self.body = body

        def open(self, *args, **kwargs):
            raise urllib.error.HTTPError(
                "https://daily-cloudcode-pa.googleapis.com/", 400,
                "Bad Request", {}, io.BytesIO(self.body),
            )

    monkeypatch.setattr(tester.urllib.request, "build_opener", lambda *args: FailingOpener(b"invalid request"))
    generic = tester.test_endpoint("daily-cloudcode-pa.googleapis.com")
    assert generic["error"] == "HTTP 400 (причина неизвестна)"

    monkeypatch.setattr(tester.urllib.request, "build_opener", lambda *args: FailingOpener(b"User location is not supported"))
    regional = tester.test_endpoint("daily-cloudcode-pa.googleapis.com")
    assert regional["error"] == "Error 400: User location is not supported"


def test_restart_passes_local_proxy_to_new_gui_process(monkeypatch, tmp_path):
    app = tmp_path / "Antigravity.app"
    app.mkdir()
    monkeypatch.setattr(detector, "KNOWN_APP_CANDIDATES", [{
        "name": "Antigravity", "paths": [str(app)], "binary_rel": [],
    }])
    commands = []
    monkeypatch.setattr(patcher, "run_cmd", lambda cmd: (commands.append(cmd) or True, "", ""))
    monkeypatch.setattr(patcher.time, "sleep", lambda _: None)
    processes = iter([[], [123]])
    monkeypatch.setattr(patcher, "_running_bundle_pids", lambda _: next(processes))

    ok, _ = patcher.restart_app("Antigravity", "http://127.0.0.1:53129", str(app))

    assert ok is True
    assert commands[-1] == [
        "open",
        "--env", "AG_LS_PROXY=http://127.0.0.1:53129",
        "--env", "HTTPS_PROXY=http://127.0.0.1:53129",
        "--env", "https_proxy=http://127.0.0.1:53129",
        "-a", str(app),
    ]


def test_first_login_readiness_checks_oauth_and_cloudcode(monkeypatch):
    monkeypatch.setattr(server, "get_config_snapshot", lambda: {"master_enabled": True})
    monkeypatch.setattr(server.local_proxy, "running", True)
    monkeypatch.setattr(server.proxy, "get_macos_proxy_env", lambda: "http://127.0.0.1:53129")
    checked = []

    def check(host, **kwargs):
        checked.append((host, kwargs["path"], kwargs["proxy_url"]))
        return {"success": True}

    monkeypatch.setattr(server.tester, "test_endpoint", check)
    ok, url = server.check_first_login_ready()

    assert ok is True
    assert url == "http://127.0.0.1:53129"
    assert checked == [
        ("oauth2.googleapis.com", "/token", url),
        ("daily-cloudcode-pa.googleapis.com", "/", url),
    ]


def test_binary_without_local_proxy_hook_is_not_ready_for_first_login(tmp_path):
    binary = tmp_path / "language_server"
    binary.write_bytes(b"inexigible but no proxy hook")

    status = detector.check_binary_status(str(binary))
    ok, message = patcher.patch_binary_file(str(binary))

    assert status["patched"] is False
    assert "маршрутизации" in status["details"]
    assert ok is False
    assert "Сигнатуры" in message
    assert not (tmp_path / "language_server.agybak").exists()


def test_first_login_gate_accepts_an_http_response_without_geoblock(monkeypatch):
    monkeypatch.setattr(server, "get_config_snapshot", lambda: {"master_enabled": True})
    monkeypatch.setattr(server.local_proxy, "running", True)
    monkeypatch.setattr(server.proxy, "get_macos_proxy_env", lambda: "http://127.0.0.1:53129")
    monkeypatch.setattr(server.tester, "test_endpoint", lambda *args, **kwargs: {
        "success": False, "http_code": 400, "error": "HTTP 400 (причина неизвестна)",
    })

    ready, _ = server.check_first_login_ready()

    assert ready is True


def test_first_patch_launches_desktop_only_after_readiness(monkeypatch):
    events = []
    app = {"id": "antigravity_desktop", "name": "Antigravity 2.0 (Desktop)",
           "installed": True, "app_path": "/Applications/Antigravity.app"}
    monkeypatch.setattr(server, "get_config_snapshot", lambda: {"master_enabled": False})
    monkeypatch.setattr(server.detector, "detect_all_apps", lambda *args: [app])
    monkeypatch.setattr(server.patcher, "patch_app_fully", lambda _: (events.append("patch") or True, "Применено"))
    monkeypatch.setattr(server.local_proxy, "start", lambda: events.append("proxy") or True)
    monkeypatch.setattr(server.proxy, "set_macos_proxy_env", lambda _: events.append("env") or True)
    monkeypatch.setattr(server, "commit_config", lambda _: events.append("config") or True)
    monkeypatch.setattr(server, "check_first_login_ready", lambda: (events.append("ready") or True, "http://127.0.0.1:53129"))
    monkeypatch.setattr(server.patcher, "restart_app", lambda *args, **kwargs: (events.append("launch") or True, "Запущено"))
    monkeypatch.setattr(server, "add_log", lambda *args: None)
    handler = server.AntigravityAPIHandler.__new__(server.AntigravityAPIHandler)
    handler._status_data = lambda: {}
    responses = []
    handler._send_json = lambda data, status=200: responses.append((status, data))

    handler._handle_patch_now({"target": "antigravity_desktop", "launch_after_patch": True})

    assert events == ["patch", "proxy", "env", "config", "ready", "launch"]
    assert responses[0][0] == 200
    assert responses[0][1]["action"]["launch"]["success"] is True


def test_watchdog_ignores_ide_when_only_desktop_is_managed(monkeypatch):
    apps = [
        {"id": "antigravity_ide", "name": "IDE", "installed": True, "is_patched": False},
        {"id": "antigravity_desktop", "name": "Desktop", "installed": True, "is_patched": False},
    ]
    monkeypatch.setattr(server, "get_config_snapshot", lambda: {
        "master_enabled": True, "auto_patch_on_launch": True,
        "managed_targets": ["antigravity_desktop"],
    })
    monkeypatch.setattr(server.detector, "detect_all_apps", lambda *_: apps)
    patched = []
    monkeypatch.setattr(server.patcher, "patch_app_fully", lambda app: (patched.append(app["id"]) or True, "ok"))
    monkeypatch.setattr(server, "add_log", lambda *args: None)
    def stop_loop(_):
        if patched:
            raise KeyboardInterrupt
    monkeypatch.setattr(server.time, "sleep", stop_loop)
    try:
        server.watchdog_worker()
    except KeyboardInterrupt:
        pass
    assert patched == ["antigravity_desktop"]


def test_selected_rollback_disables_ide_auto_patch_before_restore(monkeypatch):
    state = {"master_enabled": True, "managed_targets": ["antigravity_desktop", "antigravity_ide"]}
    app = {"id": "antigravity_ide", "name": "IDE", "installed": True}
    monkeypatch.setattr(server, "get_config_snapshot", lambda: copy.deepcopy(state))
    monkeypatch.setattr(server.detector, "detect_all_apps", lambda *_: [app])
    monkeypatch.setattr(server, "commit_config", lambda value: state.update(copy.deepcopy(value)) or True)
    def restore(_):
        assert state["managed_targets"] == ["antigravity_desktop"]
        return False, "No permission"
    monkeypatch.setattr(server.patcher, "unpatch_app_fully", restore)
    monkeypatch.setattr(server, "add_log", lambda *args: None)
    handler = server.AntigravityAPIHandler.__new__(server.AntigravityAPIHandler)
    handler._status_data = lambda: {}
    responses = []
    handler._send_json = lambda data, status=200: responses.append((status, data))

    handler._handle_unpatch_now({"target": "antigravity_ide"})

    assert state["managed_targets"] == ["antigravity_desktop"]
    assert state["master_enabled"] is True
    assert responses[0][0] == 500


def test_proxy_environment_changes_do_not_kill_ide_servers(monkeypatch):
    commands = []
    current = {"value": None}
    def run(command, **kwargs):
        commands.append(command)
        if command[1] == "setenv":
            current["value"] = command[3]
        elif command[1] == "unsetenv":
            current["value"] = None
        return subprocess.CompletedProcess(command, 0)
    monkeypatch.setattr(proxy.subprocess, "run", run)
    monkeypatch.setattr(proxy, "get_macos_proxy_env", lambda: current["value"])
    monkeypatch.setattr(proxy, "_managed_proxy_env", None)
    monkeypatch.setattr(proxy, "_previous_proxy_env", None)

    assert proxy.set_macos_proxy_env(53129)
    assert proxy.unset_macos_proxy_env()
    assert commands == [
        ["launchctl", "setenv", "AG_LS_PROXY", "http://127.0.0.1:53129"],
        ["launchctl", "unsetenv", "AG_LS_PROXY"],
    ]


def test_official_restore_disables_only_selected_app(monkeypatch):
    state = {"master_enabled": True, "managed_targets": ["antigravity_desktop", "antigravity_ide"]}
    monkeypatch.setattr(server, "get_config_snapshot", lambda: copy.deepcopy(state))
    monkeypatch.setattr(server, "commit_config", lambda value: state.update(copy.deepcopy(value)) or True)
    handler = server.AntigravityAPIHandler.__new__(server.AntigravityAPIHandler)
    responses = []
    handler._send_json = lambda data, status=200: responses.append((status, data))

    handler._handle_disable_managed({"app_id": "antigravity_ide"})

    assert state == {"master_enabled": True, "managed_targets": ["antigravity_desktop"]}
    assert responses == [(200, {"success": True, "managed_targets": ["antigravity_desktop"]})]


def test_restart_does_not_open_app_when_oauth_route_is_unready(monkeypatch):
    app = {"id": "antigravity_desktop", "installed": True, "is_patched": True,
           "app_path": "/Applications/Antigravity.app"}
    monkeypatch.setattr(server.detector, "detect_all_apps", lambda *args: [app])
    monkeypatch.setattr(server, "check_first_login_ready", lambda: (False, "OAuth недоступен"))
    monkeypatch.setattr(server.patcher, "restart_app", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("must not launch")))
    handler = server.AntigravityAPIHandler.__new__(server.AntigravityAPIHandler)
    responses = []
    handler._send_json = lambda data, status=200: responses.append((status, data))

    handler._handle_restart_app({"app_id": "antigravity_desktop"})

    assert responses == [(503, {"success": False, "error": "OAuth недоступен"})]


def test_binary_patch_idempotency_and_backup(tmp_path, monkeypatch):
    bin_file = tmp_path / "mock_server"
    content = b"header_data_ineligible_tiers_and_https_proxy_trailer"
    bin_file.write_bytes(content)

    monkeypatch.setattr(patcher, "sign_macos", lambda *args, **kwargs: True)
    monkeypatch.setattr(patcher, "kill_language_server", lambda *args, **kwargs: None)

    # 1. First patch
    ok, msg = patcher.patch_binary_file(str(bin_file))
    assert ok is True
    assert "ineligible -> inexigible" in msg
    assert "AG_LS_PROXY" in msg
    assert (tmp_path / "mock_server.agybak").exists()
    assert (tmp_path / "mock_server.agybak.sha256").exists()

    patched_content = bin_file.read_bytes()
    assert b"inexigible_tiers" in patched_content
    assert b"AG_LS_PROXY" in patched_content
    assert len(patched_content) == len(content)

    # 2. Second patch (idempotent - should not rewrite or error)
    ok_second, msg_second = patcher.patch_binary_file(str(bin_file))
    assert ok_second is True
    assert "Уже пропатчен" in msg_second

    # 3. Unpatch
    ok_unpatch, msg_unpatch = patcher.unpatch_binary_file(str(bin_file))
    assert ok_unpatch is True
    assert "Восстановлен из бэкапа" in msg_unpatch
    assert bin_file.read_bytes() == content


def test_unpatch_rejects_tampered_backup(tmp_path, monkeypatch):
    binary = tmp_path / "language_server"
    binary.write_bytes(b"ineligible_https_proxy")
    monkeypatch.setattr(patcher, "sign_macos", lambda *args, **kwargs: True)
    monkeypatch.setattr(patcher, "kill_language_server", lambda *args, **kwargs: None)
    ok, _ = patcher.patch_binary_file(str(binary))
    assert ok is True
    backup = tmp_path / "language_server.agybak"
    backup.write_bytes(b"tampered")

    restored, message = patcher.unpatch_binary_file(str(binary))

    assert restored is False
    assert "Контрольная сумма" in message


def test_detector_cache_clearing(tmp_path):
    bin_file = tmp_path / "cache_test_bin"
    bin_file.write_bytes(b"some_test_content_ineligible")

    status1 = detector.check_binary_status(str(bin_file))
    assert status1["patched"] is False
    assert status1["details"] == "Требуется патч"

    # Verify cache hit
    key = (str(bin_file), bin_file.stat().st_mtime, bin_file.stat().st_size, False)
    assert key in detector._BINARY_STATUS_CACHE

    detector.clear_detection_cache()
    assert len(detector._BINARY_STATUS_CACHE) == 0


def test_status_data_deep_copy_during_proxy_concurrency():
    local_proxy = server.local_proxy
    with local_proxy.lock:
        local_proxy.stats["recent_requests"] = [{"time": "12:00:00", "host": "test.com"}]

    handler = server.AntigravityAPIHandler.__new__(server.AntigravityAPIHandler)
    status_data = handler._status_data()

    # Verify recent_requests is a separate list, not referencing the same instance
    assert status_data["proxy"]["recent_requests"] == [{"time": "12:00:00", "host": "test.com"}]
    assert status_data["proxy"]["recent_requests"] is not local_proxy.stats["recent_requests"]

    # Simulating proxy thread appending does not affect already fetched status_data
    with local_proxy.lock:
        local_proxy.stats["recent_requests"].append({"time": "12:00:01", "host": "other.com"})
    assert len(status_data["proxy"]["recent_requests"]) == 1


def test_read_api_requires_token_and_rejects_cross_origin():
    httpd = server.ThreadedHTTPServer(("127.0.0.1", 0), server.AntigravityAPIHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    port = httpd.server_port
    try:
        # Cross origin rejected
        status, data = _get_request(
            port,
            "/api/status",
            token=server.API_TOKEN,
            origin="https://evil.attacker.com",
        )
        assert status == 403
        assert "Cross-origin" in data.get("error", "")

        status_missing, _ = _get_request(
            port,
            "/api/status",
            origin=f"http://127.0.0.1:{port}",
        )
        assert status_missing == 403

        # Same origin with the launch token is allowed.
        status_ok, data_ok = _get_request(
            port,
            "/api/status",
            token=server.API_TOKEN,
            origin=f"http://127.0.0.1:{port}",
        )
        assert status_ok == 200
        assert "apps" in data_ok
        assert "custom_app_paths" not in data_ok["config"]
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_settings_validation_is_transactional(monkeypatch):
    original_config = copy.deepcopy(server.app_config)
    monkeypatch.setattr(server.config, "save_config", lambda _: True)
    httpd = server.ThreadedHTTPServer(("127.0.0.1", 0), server.AntigravityAPIHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        status, _ = _post_request(
            httpd.server_port,
            "/api/settings",
            token=server.API_TOKEN,
            body={"route_mode": "direct", "custom_proxy": {"type": "invalid"}},
        )
        assert status == 400
        assert server.app_config == original_config
    finally:
        server.app_config.clear()
        server.app_config.update(original_config)
        httpd.shutdown()
        httpd.server_close()


def test_target_validation_handles_non_string():
    handler = server.AntigravityAPIHandler.__new__(server.AntigravityAPIHandler)
    assert handler._is_valid_target(None) is False
    assert handler._is_valid_target(123) is False


def test_targeted_process_stop_has_no_global_fallback(monkeypatch, tmp_path):
    target = tmp_path / "language_server"
    target.write_bytes(b"")
    ps_result = subprocess.CompletedProcess(
        ["ps"],
        0,
        stdout=f"123 {target}\n456 /other/language_server\n",
        stderr="",
    )
    monkeypatch.setattr(patcher.subprocess, "run", lambda *args, **kwargs: ps_result)
    killed = []
    broad_calls = []
    monkeypatch.setattr(patcher.os, "kill", lambda pid, signal: killed.append(pid))
    monkeypatch.setattr(patcher, "run_cmd", lambda cmd: broad_calls.append(cmd) or (True, "", ""))
    monkeypatch.setattr(patcher.time, "sleep", lambda _: None)

    patcher.kill_language_server(str(target))

    assert killed == [123]
    assert broad_calls == []


def test_js_patch_resigns_bundle_and_preserves_mode(tmp_path, monkeypatch):
    app = tmp_path / "Antigravity IDE.app"
    js_path = app / "Contents" / "Resources" / "app" / "out" / "main.js"
    js_path.parent.mkdir(parents=True)
    js_path.write_text("resetIsTierGCPTos(),this.x.isGoogleInternal", encoding="utf-8")
    os.chmod(js_path, 0o640)
    signed = []
    monkeypatch.setattr(patcher, "sign_macos", lambda path, deep=False: signed.append((path, deep)) or True)
    monkeypatch.setattr(patcher, "clear_ide_cache", lambda: None)

    ok, _ = patcher.patch_js_file(str(js_path), str(app))

    assert ok is True
    assert js_path.read_text(encoding="utf-8") == "resetIsTierGCPTos(),true"
    assert (os.stat(js_path).st_mode & 0o777) == 0o640
    assert signed == [(str(app), True)]


def test_open_url_endpoint(monkeypatch):
    opened = []
    monkeypatch.setattr(server.subprocess, "run", lambda cmd, **kwargs: opened.append(cmd))
    httpd = server.ThreadedHTTPServer(("127.0.0.1", 0), server.AntigravityAPIHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    port = httpd.server_port
    try:
        status, data = _post_request(
            port,
            "/api/open-url",
            token=server.API_TOKEN,
            origin=f"http://127.0.0.1:{port}",
            body={"url": "https://t.me/pro_servitude"},
        )
        assert status == 200
        assert data["success"] is True
        assert opened == [["open", "https://t.me/pro_servitude"]]

        # Invalid URL scheme
        status_bad, data_bad = _post_request(
            port,
            "/api/open-url",
            token=server.API_TOKEN,
            origin=f"http://127.0.0.1:{port}",
            body={"url": "file:///etc/passwd"},
        )
        assert status_bad == 400
        assert data_bad["success"] is False
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_proxy_smart_connect_uses_direct_when_available(monkeypatch):
    local_proxy = proxy.LocalProxyServer()
    direct_called = []

    class DummySocket:
        def close(self): pass

    def mock_connect_direct(host, port, timeout=8.0):
        direct_called.append((host, port, timeout))
        return DummySocket()

    monkeypatch.setattr(local_proxy, "_connect_public_direct", mock_connect_direct)

    sock, route = local_proxy._connect_smart("daily-cloudcode-pa.googleapis.com", 443)

    assert route == "direct"
    assert len(direct_called) == 1
    assert direct_called[0][0] == "daily-cloudcode-pa.googleapis.com"
    assert direct_called[0][2] == 1.2  # Fast probe timeout


def test_proxy_smart_connect_falls_back_to_clean_esf_when_direct_fails(monkeypatch):
    local_proxy = proxy.LocalProxyServer()

    class DummySocket:
        def __init__(self):
            self.timeout = None
        def settimeout(self, t):
            self.timeout = t
        def connect(self, addr):
            pass
        def close(self): pass

    def mock_connect_direct(host, port, timeout=8.0):
        raise OSError(65, "No route to host")

    monkeypatch.setattr(local_proxy, "_connect_public_direct", mock_connect_direct)
    monkeypatch.setattr(proxy.socket, "socket", lambda *args, **kwargs: DummySocket())

    sock, route = local_proxy._connect_smart("daily-cloudcode-pa.googleapis.com", 443)

    assert "smart-esf" in route
    assert local_proxy._last_working_esf_ip is not None


def test_tls_split_setting_accepted_by_api(monkeypatch):
    original_config = copy.deepcopy(server.app_config)
    monkeypatch.setattr(server.config, "save_config", lambda _: True)
    httpd = server.ThreadedHTTPServer(("127.0.0.1", 0), server.AntigravityAPIHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        status, data = _post_request(
            httpd.server_port,
            "/api/settings",
            token=server.API_TOKEN,
            origin=f"http://127.0.0.1:{httpd.server_port}",
            body={"route_mode": "tls_split"},
        )
        assert status == 200
        assert data["success"] is True
        assert server.app_config["route_mode"] == "tls_split"
    finally:
        server.app_config.clear()
        server.app_config.update(original_config)
        httpd.shutdown()
        httpd.server_close()


def test_pipe_sockets_tls_split_segments_client_hello(monkeypatch):
    local_proxy = proxy.LocalProxyServer()
    local_proxy.running = True

    sent_chunks = []

    class MockSocket:
        def __init__(self, incoming=None):
            self.incoming = list(incoming or [])
            self.closed = False
        def recv(self, size):
            if self.incoming:
                return self.incoming.pop(0)
            return b""
        def sendall(self, data):
            sent_chunks.append(data)
        def setsockopt(self, *args):
            pass
        def close(self):
            self.closed = True

    # Dummy TLS ClientHello packet starting with 0x16 0x03
    fake_client_hello = b"\x16\x03\x01\x00\x20" + b"A" * 32
    client_sock = MockSocket(incoming=[fake_client_hello])
    upstream_sock = MockSocket()

    monkeypatch.setattr(proxy.select, "select", lambda r, w, x, t: ([client_sock], [], []))
    local_proxy._pipe_sockets(client_sock, upstream_sock, split_tls=True)

    # Must be split into first 2 bytes and remaining bytes
    assert len(sent_chunks) == 2
    assert sent_chunks[0] == b"\x16\x03"
    assert sent_chunks[1] == fake_client_hello[2:]


def test_session_logger_events_and_summary(tmp_path, monkeypatch):
    log_file = tmp_path / "test_session.log"
    monkeypatch.setattr(session_logger, "SESSION_LOG_FILE", str(log_file))
    monkeypatch.setattr(session_logger, "_LOGGER", None)
    monkeypatch.setattr(session_logger, "_RECENT_MEMORY_LOGS", [])

    session_logger.log_session_start(53128, 53129, "tls_split")
    session_logger.log_connection_success("daily-cloudcode-pa.googleapis.com", 443, "tls_split", 120.5)
    session_logger.log_connection_error("generativelanguage.googleapis.com", 443, "direct", "Connection timed out", 1500.0)

    summary = session_logger.generate_session_summary()
    assert summary["total_connections"] == 2
    assert summary["success_connections"] == 1
    assert summary["failed_connections"] == 1
    assert len(summary["recent_failures"]) == 1
    assert summary["recent_failures"][0]["host"] == "generativelanguage.googleapis.com"
    assert "timed out" in summary["recent_failures"][0]["error"]

    tail = session_logger.get_session_file_tail(50)
    assert "SESSION_START" in tail
    assert "daily-cloudcode-pa.googleapis.com" in tail


def test_session_logs_endpoint_serves_structured_data(monkeypatch):
    httpd = server.ThreadedHTTPServer(("127.0.0.1", 0), server.AntigravityAPIHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        status, data = _get_request(
            httpd.server_port,
            "/api/session/logs",
            token=server.API_TOKEN,
            origin=f"http://127.0.0.1:{httpd.server_port}",
        )
        assert status == 200
        assert "recent" in data
        assert "raw_tail" in data
        assert "summary" in data
        assert isinstance(data["recent"], list)
    finally:
        httpd.shutdown()
        httpd.server_close()


