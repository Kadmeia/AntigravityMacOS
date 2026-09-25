from __future__ import annotations

import concurrent.futures
import socket

import pytest

from backend import config, proxy


@pytest.fixture(autouse=True)
def _disable_session_file_logging(monkeypatch):
    monkeypatch.setattr(proxy.session_logger, "log_connection_success", lambda *_args: None)
    monkeypatch.setattr(proxy.session_logger, "log_connection_error", lambda *_args: None)


def test_token_creation_is_serialized_and_replaces_invalid_file(tmp_path, monkeypatch):
    token_path = tmp_path / "api-token"
    token_path.write_text("short", encoding="utf-8")
    monkeypatch.setattr(config, "CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(config, "API_TOKEN_FILE", str(token_path))

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        tokens = list(pool.map(lambda _: config.load_or_create_api_token(), range(16)))

    assert len(set(tokens)) == 1
    assert token_path.read_text(encoding="utf-8") == tokens[0]
    assert (token_path.stat().st_mode & 0o777) == 0o600
    assert (tmp_path / "api-token.lock").exists()
    assert (tmp_path / "api-token.lock").stat().st_mode & 0o077 == 0


def test_token_persistence_failure_returns_process_local_token(tmp_path, monkeypatch):
    token_path = tmp_path / "api-token"
    token_path.write_text("invalid", encoding="utf-8")
    monkeypatch.setattr(config, "CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(config, "API_TOKEN_FILE", str(token_path))

    def fail_replace(*_args):
        raise OSError("read-only filesystem")

    monkeypatch.setattr(config.os, "replace", fail_replace)
    token = config.load_or_create_api_token()

    assert len(token) >= 32
    assert token != "invalid"
    assert token_path.read_text(encoding="utf-8") == "invalid"


def test_token_read_only_lock_reuses_existing_token(tmp_path, monkeypatch):
    token_path = tmp_path / "api-token"
    token_path.write_text("persisted-token-value-long-enough-to-be-valid", encoding="utf-8")
    monkeypatch.setattr(config, "CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(config, "API_TOKEN_FILE", str(token_path))
    real_open = config.os.open

    def fail_lock_open(path, flags, *args, **kwargs):
        if str(path).endswith("api-token.lock"):
            raise OSError("read-only filesystem")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(config.os, "open", fail_lock_open)

    assert config.load_or_create_api_token() == token_path.read_text(encoding="utf-8")


def test_token_replaces_invalid_utf8_file(tmp_path, monkeypatch):
    token_path = tmp_path / "api-token"
    token_path.write_bytes(b"\xff\xfe")
    monkeypatch.setattr(config, "CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(config, "API_TOKEN_FILE", str(token_path))

    token = config.load_or_create_api_token()

    assert len(token) >= 32
    assert token_path.read_text(encoding="utf-8") == token


def test_custom_proxy_target_is_pinned_to_validated_public_ip(monkeypatch):
    calls = []

    def getaddrinfo(host, port, **kwargs):
        calls.append((host, port, kwargs))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    monkeypatch.setattr(proxy.socket, "getaddrinfo", getaddrinfo)

    assert proxy.resolve_public_target_ip("public.example", 443) == "8.8.8.8"
    assert calls == [("public.example", 443, {"type": socket.SOCK_STREAM})]


def test_custom_proxy_target_rejects_private_dns_answer(monkeypatch):
    monkeypatch.setattr(
        proxy.socket,
        "getaddrinfo",
        lambda host, port, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.10", port))
        ],
    )

    try:
        proxy.resolve_public_target_ip("public.example", 443)
    except ValueError as exc:
        assert "Private" in str(exc)
    else:
        raise AssertionError("private DNS answer should be rejected")


def test_custom_route_passes_pinned_ip_to_http_proxy(monkeypatch):
    local_proxy = proxy.LocalProxyServer(config_getter=lambda: {
        "route_mode": "custom",
        "custom_proxy": {"type": "http", "host": "proxy.local", "port": 8080},
    })
    client = _FakeSocket([b"CONNECT public.example:443 HTTP/1.1\r\n\r\n"])
    upstream = _FakeSocket([])
    connected = []
    monkeypatch.setattr(proxy, "is_safe_connect_target", lambda host, port: True)
    monkeypatch.setattr(proxy, "resolve_public_target_ip", lambda host, port: "8.8.8.8")
    monkeypatch.setattr(
        local_proxy,
        "_connect_upstream_http",
        lambda host, port, target, target_port: connected.append((host, port, target, target_port)) or upstream,
    )
    monkeypatch.setattr(local_proxy, "_pipe_sockets", lambda *_args, **_kwargs: None)

    local_proxy._handle_client(client, ("127.0.0.1", 12345))

    assert connected == [("proxy.local", 8080, "8.8.8.8", 443)]
    assert client.sent == [b"HTTP/1.1 200 Connection Established\r\n\r\n"]


def test_custom_route_passes_pinned_ip_to_socks5_proxy(monkeypatch):
    local_proxy = proxy.LocalProxyServer(config_getter=lambda: {
        "route_mode": "custom",
        "custom_proxy": {"type": "socks5", "host": "proxy.local", "port": 1080},
    })
    client = _FakeSocket([b"CONNECT public.example:443 HTTP/1.1\r\n\r\n"])
    upstream = _FakeSocket([])
    connected = []
    monkeypatch.setattr(proxy, "is_safe_connect_target", lambda host, port: True)
    monkeypatch.setattr(proxy, "resolve_public_target_ip", lambda host, port: "2001:4860:4860::8888")
    monkeypatch.setattr(
        local_proxy,
        "_connect_upstream_socks5",
        lambda host, port, target, target_port: connected.append((host, port, target, target_port)) or upstream,
    )
    monkeypatch.setattr(local_proxy, "_pipe_sockets", lambda *_args, **_kwargs: None)

    local_proxy._handle_client(client, ("127.0.0.1", 12345))

    assert connected == [("proxy.local", 1080, "2001:4860:4860::8888", 443)]


def test_http_custom_proxy_formats_ipv6_connect_authority(monkeypatch):
    fake = _FakeSocket([b"HTTP/1.1 200 Connection Established\r\n\r\n"])
    monkeypatch.setattr(proxy.socket, "socket", lambda *_args, **_kwargs: fake)

    returned = proxy.LocalProxyServer()._connect_upstream_http(
        "proxy.local", 8080, "2001:4860:4860::8888", 443
    )

    assert returned is fake
    request = fake.sent[0].decode("ascii")
    assert request.startswith("CONNECT [2001:4860:4860::8888]:443 HTTP/1.1\r\n")
    assert "Host: [2001:4860:4860::8888]:443\r\n" in request


def test_tls_split_buffers_short_client_reads_before_splitting(monkeypatch):
    local_proxy = proxy.LocalProxyServer()
    local_proxy.running = True
    client = _FakeSocket([b"\x16\x03", b"\x01\x00\x00\x10", b""])
    upstream = _FakeSocket([])
    monkeypatch.setattr(proxy.select, "select", lambda *_args: ([client], [], []))
    monkeypatch.setattr(proxy.time, "sleep", lambda _seconds: None)

    local_proxy._pipe_sockets(client, upstream, split_tls=True)

    assert upstream.sent == [b"\x16\x03", b"\x01\x00\x00\x10"]


def test_tls_split_flushes_short_prefix_when_client_closes(monkeypatch):
    local_proxy = proxy.LocalProxyServer()
    local_proxy.running = True
    client = _FakeSocket([b"\x16\x03", b""])
    upstream = _FakeSocket([])
    monkeypatch.setattr(proxy.select, "select", lambda *_args: ([client], [], []))

    local_proxy._pipe_sockets(client, upstream, split_tls=True)

    assert upstream.sent == [b"\x16\x03"]


class _FakeSocket:
    def __init__(self, reads):
        self.reads = list(reads)
        self.sent = []
        self.timeout = None
        self.closed = False

    def settimeout(self, value):
        self.timeout = value

    def connect(self, _address):
        pass

    def sendall(self, data):
        self.sent.append(bytes(data))

    def recv(self, _size):
        return self.reads.pop(0) if self.reads else b""

    def setsockopt(self, *_args):
        pass

    def close(self):
        self.closed = True
