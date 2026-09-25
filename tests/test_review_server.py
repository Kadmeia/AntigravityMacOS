from __future__ import annotations

import copy
import threading

import pytest

from backend import server, tester


def handler():
    obj = server.AntigravityAPIHandler.__new__(server.AntigravityAPIHandler)
    responses = []
    obj._send_json = lambda data, status=200: responses.append((status, data))
    return obj, responses


@pytest.mark.parametrize('payload', [
    {'route_mode': []}, {'route_mode': {}},
    {'custom_proxy': {'type': []}}, {'custom_proxy': {'type': {}}},
])
def test_settings_rejects_non_string_enum(payload):
    obj, responses = handler()
    obj._handle_save_settings(payload)
    assert responses[0][0] == 400


def test_restart_rejects_non_string_app():
    obj, responses = handler()
    obj._handle_restart_app({'app_id': []})
    assert responses[0][0] == 400


def test_open_url_rejects_malformed_ipv6():
    obj, responses = handler()
    obj._handle_open_url({'url': 'https://[bad'})
    assert responses[0][0] == 400


def test_rejected_settings_do_not_log_changes(monkeypatch):
    events = []
    monkeypatch.setattr(server.session_logger, 'log_config_change', lambda *args: events.append(args))
    obj, responses = handler()
    obj._handle_save_settings({'route_mode': 'direct', 'custom_proxy': {'type': 'bad'}})
    assert responses[0][0] == 400
    assert events == []


def test_settings_waits_for_patch_transaction(monkeypatch):
    state = copy.deepcopy(server.app_config)
    state['managed_targets'] = []
    monkeypatch.setattr(server, 'app_config', state)
    monkeypatch.setattr(server.config, 'save_config', lambda _: True)
    started, snapshot_read = threading.Event(), threading.Event()
    original_snapshot = server.get_config_snapshot

    def snapshot():
        snapshot_read.set()
        return original_snapshot()

    monkeypatch.setattr(server, 'get_config_snapshot', snapshot)
    obj, responses = handler()

    def save():
        started.set()
        obj._handle_save_settings({'auto_patch_on_launch': False})

    with server.OPERATION_LOCK:
        worker = threading.Thread(target=save)
        worker.start()
        assert started.wait(1)
        read_while_locked = snapshot_read.wait(0.1)
        state['managed_targets'] = ['antigravity_desktop']
    worker.join(2)
    assert not worker.is_alive()
    assert not read_while_locked
    assert responses[0][0] == 200
    assert state['managed_targets'] == ['antigravity_desktop']
    assert state['auto_patch_on_launch'] is False


def test_report_uses_running_proxy_port(monkeypatch):
    urls = []
    monkeypatch.setattr(tester, 'run_all_tests', lambda proxy_url: urls.append(proxy_url) or [])
    report = tester.generate_diagnostic_report([], {'running': True, 'port': 53150}, None, {'proxy_port': 53129})
    assert urls == ['http://127.0.0.1:53150']
    assert '(порт 53150)' in report


def test_watchdog_rechecks_disabled_state_after_lock(monkeypatch):
    states = iter([
        {'master_enabled': True, 'auto_patch_on_launch': True},
        {'master_enabled': True, 'auto_patch_on_launch': False, 'managed_targets': ['antigravity_desktop']},
    ])
    monkeypatch.setattr(server, 'get_config_snapshot', lambda: next(states))
    sleeps = []
    def sleep(_):
        if sleeps:
            raise KeyboardInterrupt
        sleeps.append(True)
    monkeypatch.setattr(server.time, 'sleep', sleep)
    def unexpected(*args):
        pytest.fail('watchdog must not scan after autopatch is disabled')
    monkeypatch.setattr(server.detector, 'detect_all_apps', unexpected)
    with pytest.raises(KeyboardInterrupt):
        server.watchdog_worker()


def test_session_totals_survive_ring_buffer_eviction(monkeypatch):
    from backend import session_logger as logs
    class Logger:
        def info(self, *args): pass
        def error(self, *args): pass
    monkeypatch.setattr(logs, '_LOGGER', Logger())
    monkeypatch.setattr(logs, '_RECENT_MEMORY_LOGS', [])
    monkeypatch.setattr(logs, '_CONNECTION_COUNTS', {'CONNECT': 0, 'CONNECT_FAIL': 0})
    logs.log_session_start(1, 2, 'direct')
    logs.log_connection_error('example.com', 443, 'direct', 'failed')
    for _ in range(205):
        logs.log_connection_success('example.com', 443, 'direct', 1)
    summary = logs.generate_session_summary()
    assert summary['total_connections'] == 206
    assert summary['failed_connections'] == 1
    assert len(logs.get_recent_logs(1000)) == 200
    logs.log_session_start(1, 2, 'direct')
    assert logs.generate_session_summary()['total_connections'] == 0
