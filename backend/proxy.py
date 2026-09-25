from __future__ import annotations

import ipaddress
import logging
import os
import select
import socket
import subprocess
import threading
import time
from typing import Any, Callable

try:
    from . import session_logger
except ImportError:
    import session_logger

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Clean Google Edge Server Frontend (ESF) addresses that accept Google TLS SNI
# even when local ISPs/DPI in restricted regions block standard IPs or return "no route to host".
SMART_GOOGLE_ESF_IPS: list[str] = [
    "64.233.161.95",
    "64.233.162.95",
    "64.233.164.95",
    "216.152.150.131",
    "209.85.233.95",
    "173.194.221.95",
    "74.125.131.95",
]

# Backwards compatibility alias
SMART_RESOLVERS: list[str] = SMART_GOOGLE_ESF_IPS

CLOUDCODE_HOSTS = frozenset({
    "cloudcode-pa.googleapis.com",
    "daily-cloudcode-pa.googleapis.com",
    "generativelanguage.googleapis.com",
    "oauth2.googleapis.com",
    "accounts.google.com",
    "antigravity.google",
    "antigravity-unleash.goog",
})


_PROXY_ENV_LOCK = threading.Lock()
_previous_proxy_env: str | None = None
_managed_proxy_env: str | None = None

def parse_connect_target(dest: str) -> tuple[str, int]:
    """Parse CONNECT destination target_host and target_port with IPv6 support."""
    dest = dest.strip()
    if dest.startswith("[") and "]:" in dest:
        host_part, port_part = dest[1:].split("]:", 1)
        host, port = host_part, int(port_part)
    elif ":" in dest:
        host_part, port_part = dest.rsplit(":", 1)
        host, port = host_part.strip("[]"), int(port_part)
    else:
        host, port = dest.strip("[]"), 443
    host = host.rstrip(".").strip()
    if not host or len(host) > 253 or any(ch.isspace() or ch == "\x00" for ch in host):
        raise ValueError("Invalid CONNECT host")
    if not 1 <= port <= 65535:
        raise ValueError("Invalid CONNECT port")
    return host, port


def is_safe_connect_target(host: str, port: int) -> bool:
    """Allow public TLS destinations while blocking access to local networks."""
    if port != 443:
        return False
    normalized = host.rstrip(".").lower()
    if normalized == "localhost" or normalized.endswith(".localhost"):
        return False
    # These exact Google service names may use the fixed public ESF fallback
    # when the system resolver is unavailable. Other names still need DNS
    # validation to prevent tunnelling to local/private addresses.
    if normalized in CLOUDCODE_HOSTS:
        return True
    try:
        addresses = {ipaddress.ip_address(normalized)}
    except ValueError:
        try:
            addresses = {
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(normalized, port, type=socket.SOCK_STREAM)
            }
        except (OSError, ValueError):
            return False
    return bool(addresses) and all(address.is_global for address in addresses)


def resolve_public_target(host: str, port: int) -> list[tuple[int, int, int, str, tuple[Any, ...]]]:
    """Resolve once, reject mixed/private answers, and return connectable addresses."""
    if port != 443:
        raise ValueError("Only public TLS destinations on port 443 are allowed")
    results = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not results:
        raise OSError("Destination did not resolve")
    addresses = [ipaddress.ip_address(item[4][0]) for item in results]
    if not all(address.is_global for address in addresses):
        raise ValueError("Private or special-use destinations are not allowed")
    return results


def resolve_public_target_ip(host: str, port: int) -> str:
    """Resolve and pin a public IP before passing a target through a custom proxy.

    A custom HTTP or SOCKS proxy may resolve names independently. Passing the
    hostname after validating only the local resolver would let its resolver
    select a private address. CONNECT still carries the original TLS SNI from
    the client even when its authority is an IP literal.
    """
    results = resolve_public_target(host, port)
    return ipaddress.ip_address(results[0][4][0]).compressed

class LocalProxyServer:
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 53129,
        config_getter: Callable[[], dict[str, Any]] | None = None
    ) -> None:
        self.host = host
        self.port = port
        self.config_getter = config_getter
        self.server_socket: socket.socket | None = None
        self.running = False
        self.thread: threading.Thread | None = None
        self.stats: dict[str, Any] = {
            "started_at": 0.0,
            "total_connections": 0,
            "active_connections": 0,
            "last_request": None,
            "recent_requests": []
        }
        self.lock = threading.Lock()
        self.connection_slots = threading.BoundedSemaphore(128)
        self._last_working_esf_ip: str | None = None

    def start(self) -> bool:
        if self.running:
            return True

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(64)
            self.running = True
            self.stats["started_at"] = time.time()
            
            self.thread = threading.Thread(target=self._serve_loop, daemon=True)
            self.thread.start()
            logging.info(f"Локальный прокси запущен на {self.host}:{self.port}")
            session_logger.log_event("INFO", "PROXY_START", f"Локальный прокси запущен на {self.host}:{self.port}")
            return True
        except Exception as e:
            logging.error(f"Не удалось запустить прокси на {self.host}:{self.port}: {e}")
            session_logger.log_event("ERROR", "PROXY_ERROR", f"Не удалось запустить прокси на {self.host}:{self.port}: {e}")
            self.running = False
            if self.server_socket is not None:
                try:
                    self.server_socket.close()
                except OSError:
                    pass
                self.server_socket = None
            return False

    def stop(self) -> None:
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
            self.server_socket = None
        logging.info("Локальный прокси остановлен")
        session_logger.log_event("INFO", "PROXY_STOP", "Локальный прокси остановлен")

    def _serve_loop(self) -> None:
        while self.running and self.server_socket:
            try:
                client_sock, client_addr = self.server_socket.accept()
                if not self.connection_slots.acquire(blocking=False):
                    client_sock.close()
                    continue
                t = threading.Thread(target=self._handle_client_guarded, args=(client_sock, client_addr), daemon=True)
                t.start()
            except Exception:
                if not self.running:
                    break
                time.sleep(0.05)

    def _get_config(self) -> dict[str, Any]:
        if self.config_getter:
            return self.config_getter()
        return {}

    @staticmethod
    def _recv_exact(sock: socket.socket, size: int) -> bytes:
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = sock.recv(remaining)
            if not chunk:
                raise IOError("Unexpected end of proxy response")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _handle_client_guarded(self, client_sock: socket.socket, client_addr: tuple[str, int]) -> None:
        try:
            self._handle_client(client_sock, client_addr)
        finally:
            self.connection_slots.release()

    def _connect_upstream_socks5(self, proxy_host: str, proxy_port: int, target_host: str, target_port: int) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(10.0)
            s.connect((proxy_host, proxy_port))

            # Greeting: No auth
            s.sendall(b"\x05\x01\x00")
            resp = self._recv_exact(s, 2)
            if len(resp) < 2 or resp[0] != 5 or resp[1] != 0:
                raise IOError("SOCKS5 proxy authentication failed")

            # Connect command with the correct SOCKS5 address type.
            try:
                ip_value = ipaddress.ip_address(target_host)
            except ValueError:
                th_bytes = target_host.encode("idna")
                if len(th_bytes) > 255:
                    raise ValueError("SOCKS5 destination name is too long")
                address = b"\x03" + bytes([len(th_bytes)]) + th_bytes
            else:
                address = (b"\x01" if ip_value.version == 4 else b"\x04") + ip_value.packed
            req = b"\x05\x01\x00" + address + target_port.to_bytes(2, "big")
            s.sendall(req)

            resp2 = self._recv_exact(s, 4)
            if resp2[1] != 0:
                raise IOError(f"SOCKS5 connect error code: {resp2[1]}")
            atyp = resp2[3]
            if atyp == 1:
                self._recv_exact(s, 4)
            elif atyp == 3:
                name_len = self._recv_exact(s, 1)[0]
                self._recv_exact(s, name_len)
            elif atyp == 4:
                self._recv_exact(s, 16)
            else:
                raise IOError("Invalid SOCKS5 address type")
            self._recv_exact(s, 2)

            s.settimeout(None)
            return s
        except Exception:
            try:
                s.close()
            except Exception:
                pass
            raise

    def _connect_upstream_http(self, proxy_host: str, proxy_port: int, target_host: str, target_port: int) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(10.0)
            s.connect((proxy_host, proxy_port))

            display_host = f"[{target_host}]" if ":" in target_host else target_host
            req = f"CONNECT {display_host}:{target_port} HTTP/1.1\r\nHost: {display_host}:{target_port}\r\nProxy-Connection: Keep-Alive\r\n\r\n"
            s.sendall(req.encode("utf-8"))

            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if len(resp) > 65536:
                    raise IOError("Upstream HTTP proxy response is too large")

            header_end = resp.find(b"\r\n\r\n")
            header_block = resp[:header_end] if header_end >= 0 else resp
            status_line_bytes = header_block.split(b"\r\n", 1)[0]
            if not status_line_bytes.startswith(b"HTTP/") or len(status_line_bytes.split()) < 2 or status_line_bytes.split()[1] != b"200":
                status_line = status_line_bytes.decode("utf-8", errors="ignore")
                raise IOError(f"Upstream HTTP proxy error: {status_line}")

            s.settimeout(None)
            return s
        except Exception:
            try:
                s.close()
            except Exception:
                pass
            raise

    @staticmethod
    def _connect_public_direct(target_host: str, target_port: int, timeout: float = 8.0) -> socket.socket:
        errors: list[Exception] = []
        for family, socktype, proto, _, sockaddr in resolve_public_target(target_host, target_port):
            direct_socket = socket.socket(family, socktype, proto)
            try:
                direct_socket.settimeout(timeout)
                direct_socket.connect(sockaddr)
                direct_socket.settimeout(None)
                return direct_socket
            except Exception as exc:
                errors.append(exc)
                direct_socket.close()
        if errors:
            raise errors[-1]
        raise OSError("No public destination address available")

    def _connect_smart(self, target_host: str, target_port: int) -> tuple[socket.socket, str]:
        """Connects directly (instant with VPN) or falls back to clean Google ESF route (unblocks without VPN)."""
        norm_host = target_host.rstrip(".").lower()
        cloudcode_hosts = {
            *CLOUDCODE_HOSTS,
            "generativelanguage.googleapis.com",
            "oauth2.googleapis.com",
            "accounts.google.com",
            "antigravity.google",
        }
        is_google_service = (
            norm_host in cloudcode_hosts
            or norm_host.endswith(".googleapis.com")
            or norm_host.endswith(".google.com")
            or norm_host.endswith(".goog")
            or norm_host.endswith(".gstatic.com")
            or norm_host.endswith(".googleusercontent.com")
            or norm_host == "antigravity.google"
        )

        # 1. Fast direct probe first.
        # When VPN is ON (or direct internet is unblocked), connects in ~100-200ms with zero overhead!
        try:
            # 1.2s timeout for Google services allows instant failover if blocked by DPI / no route to host.
            probe_timeout = 1.2 if is_google_service else 8.0
            direct_sock = self._connect_public_direct(target_host, target_port, timeout=probe_timeout)
            return direct_sock, "direct"
        except Exception as direct_err:
            if not is_google_service:
                raise direct_err
            reason_str = str(direct_err).strip() or type(direct_err).__name__
            session_logger.log_route_fallback(target_host, "direct", "smart-esf", reason_str)
            logging.info(
                f"Прямое подключение к {target_host} не удалось ({direct_err}), переход на чистые IP Google ESF..."
            )

        # 2. Fallback to clean Google ESF IPs that accept TLS SNI for target_host without DPI blocks.
        preferred = getattr(self, "_last_working_esf_ip", None)
        ips_to_try = [preferred] + [ip for ip in SMART_GOOGLE_ESF_IPS if ip != preferred] if preferred else list(SMART_GOOGLE_ESF_IPS)

        for ip in ips_to_try:
            if not ip:
                continue
            s: socket.socket | None = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.5)
                s.connect((ip, target_port))
                s.settimeout(None)
                self._last_working_esf_ip = ip
                return s, f"smart-esf ({ip})"
            except Exception:
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
                continue

        # If all ESF endpoints also failed, try direct one last time with standard timeout to raise the exact error
        return self._connect_public_direct(target_host, target_port), "direct"

    def _handle_client(self, client_sock: socket.socket, client_addr: tuple[str, int]) -> None:
        with self.lock:
            self.stats["total_connections"] += 1
            self.stats["active_connections"] += 1

        start_time = time.monotonic()
        target_host = ""
        target_port = 443
        route_desc = "unknown"
        upstream_sock: socket.socket | None = None

        try:
            client_sock.settimeout(10.0)
            req_data = client_sock.recv(4096)
            if not req_data:
                return

            first_line = req_data.split(b"\r\n")[0].decode("utf-8", errors="ignore")
            parts = first_line.split(" ")
            if len(parts) < 2 or parts[0].upper() != "CONNECT":
                # Only CONNECT proxy is supported for TLS tunneling
                client_sock.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                return

            dest = parts[1]
            try:
                target_host, target_port = parse_connect_target(dest)
            except Exception:
                client_sock.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                return
            if not is_safe_connect_target(target_host, target_port):
                client_sock.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                return

            cfg = self._get_config()
            route_mode = cfg.get("route_mode", "smart")
            custom_proxy = cfg.get("custom_proxy", {})

            split_tls = False
            if route_mode == "custom" and custom_proxy.get("host") and custom_proxy.get("port"):
                p_type = str(custom_proxy.get("type", "http")).lower()
                p_host = str(custom_proxy.get("host"))
                p_port = int(custom_proxy.get("port"))
                route_desc = f"Custom {p_type.upper()} ({p_host}:{p_port})"
                # The custom proxy must connect to the exact public address we
                # validated here; otherwise its DNS resolver could direct the
                # tunnel to a private or link-local host.
                custom_target_host = resolve_public_target_ip(target_host, target_port)
                if p_type == "socks5":
                    upstream_sock = self._connect_upstream_socks5(p_host, p_port, custom_target_host, target_port)
                else:
                    upstream_sock = self._connect_upstream_http(p_host, p_port, custom_target_host, target_port)
            elif route_mode == "direct":
                upstream_sock = self._connect_public_direct(target_host, target_port)
                route_desc = "Direct"
            elif route_mode == "tls_split":
                upstream_sock, base_route = self._connect_smart(target_host, target_port)
                route_desc = f"TLS Split ({base_route})"
                split_tls = True
            else:
                # Smart mode
                upstream_sock, route_desc = self._connect_smart(target_host, target_port)

            # Send 200 Connection Established to client
            client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            client_sock.settimeout(None)

            # Record stats
            duration_ms = round((time.monotonic() - start_time) * 1000, 1)
            req_record = {
                "time": time.strftime("%H:%M:%S"),
                "host": target_host,
                "port": target_port,
                "route": route_desc,
                "status": "connected",
                "duration_ms": duration_ms,
            }
            with self.lock:
                self.stats["last_request"] = req_record
                self.stats["recent_requests"].insert(0, req_record)
                if len(self.stats["recent_requests"]) > 50:
                    self.stats["recent_requests"].pop()

            session_logger.log_connection_success(target_host, target_port, route_desc, duration_ms)

            # Bidirectional forwarding
            self._pipe_sockets(client_sock, upstream_sock, split_tls=split_tls)

        except Exception as e:
            duration_ms = round((time.monotonic() - start_time) * 1000, 1)
            logging.error(f"Proxy error handling {target_host}:{target_port} via {route_desc}: {e}")
            session_logger.log_connection_error(target_host or "unknown", target_port, route_desc, e, duration_ms)
            err_record = {
                "time": time.strftime("%H:%M:%S"),
                "host": target_host or "unknown",
                "port": target_port,
                "route": route_desc,
                "status": f"error: {e}",
                "duration_ms": duration_ms,
            }
            with self.lock:
                self.stats["last_request"] = err_record
                self.stats["recent_requests"].insert(0, err_record)
                if len(self.stats["recent_requests"]) > 50:
                    self.stats["recent_requests"].pop()
            try:
                client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            except Exception:
                pass
        finally:
            if upstream_sock is not None:
                try:
                    upstream_sock.close()
                except Exception:
                    pass
            try:
                client_sock.close()
            except Exception:
                pass
            with self.lock:
                self.stats["active_connections"] = max(0, self.stats["active_connections"] - 1)

    def _pipe_sockets(self, s1: socket.socket, s2: socket.socket, split_tls: bool = False) -> None:
        sockets = [s1, s2]
        split_decided = not split_tls
        client_prefix = bytearray()
        prefix_deadline: float | None = None
        while self.running:
            try:
                # Check on every pass: upstream traffic can keep select ready
                # and must not postpone flushing a short client prefix.
                if client_prefix and prefix_deadline is not None and time.monotonic() >= prefix_deadline:
                    s2.sendall(client_prefix)
                    client_prefix.clear()
                    split_decided = True
                # 1.5s timeout allows prompt worker shutdown when proxy is stopped
                r, _, x = select.select(sockets, [], sockets, 1.5)
                if x:
                    break
                if not r:
                    # A peer may send only a short TLS prefix and pause. Flush
                    # it after a bounded wait so the tunnel cannot stall.
                    if client_prefix and prefix_deadline is not None and time.monotonic() >= prefix_deadline:
                        s2.sendall(client_prefix)
                        client_prefix.clear()
                        split_decided = True
                    continue
                closed = False
                for s in r:
                    data = s.recv(32768)
                    if not data:
                        if s is s1 and client_prefix:
                            # Preserve bytes already read even if the client
                            # closes before a complete TLS prefix arrives.
                            s2.sendall(client_prefix)
                            client_prefix.clear()
                            split_decided = True
                        closed = True
                        break
                    if s is s1:
                        if not split_decided:
                            client_prefix.extend(data)
                            if len(client_prefix) >= 1 and client_prefix[0] != 0x16:
                                s2.sendall(client_prefix)
                                client_prefix.clear()
                                split_decided = True
                                continue
                            elif len(client_prefix) >= 2 and client_prefix[1] != 0x03:
                                s2.sendall(client_prefix)
                                client_prefix.clear()
                                split_decided = True
                                continue
                            elif len(client_prefix) >= 6:
                                try:
                                    s2.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                                except Exception:
                                    pass
                                # Split at byte 2 (ByeDPI split 2) with a 3ms gap to defeat DPI SNI filters
                                s2.sendall(client_prefix[:2])
                                time.sleep(0.003)
                                s2.sendall(client_prefix[2:])
                                client_prefix.clear()
                                split_decided = True
                                continue
                            else:
                                if prefix_deadline is None:
                                    prefix_deadline = time.monotonic() + 1.5
                                continue
                        s2.sendall(data)
                    else:
                        s1.sendall(data)
                if closed:
                    break
            except Exception:
                break
        try:
            s1.close()
        except Exception:
            pass
        try:
            s2.close()
        except Exception:
            pass

def set_macos_proxy_env(port: int = 53129) -> bool:
    """Sets launchctl AG_LS_PROXY so macOS GUI apps see our local proxy."""
    global _managed_proxy_env, _previous_proxy_env
    url = f"http://127.0.0.1:{port}"
    with _PROXY_ENV_LOCK:
        try:
            if _managed_proxy_env is None:
                _previous_proxy_env = get_macos_proxy_env() or None
            subprocess.run(["launchctl", "setenv", "AG_LS_PROXY", url], check=True)
            os.environ["AG_LS_PROXY"] = url
            _managed_proxy_env = url
            logging.info(f"Установлена переменная launchctl AG_LS_PROXY={url}")
            return True
        except Exception as e:
            logging.error(f"Ошибка установки launchctl AG_LS_PROXY: {e}")
            return False

def unset_macos_proxy_env() -> bool:
    """Restore the value replaced by this process without clobbering others."""
    global _managed_proxy_env, _previous_proxy_env
    with _PROXY_ENV_LOCK:
        try:
            current = get_macos_proxy_env() or None
            if _managed_proxy_env is None:
                return True
            if current != _managed_proxy_env:
                logging.info("AG_LS_PROXY изменена другим процессом; значение сохранено")
                _managed_proxy_env = None
                _previous_proxy_env = None
                return True
            if _previous_proxy_env:
                subprocess.run(
                    ["launchctl", "setenv", "AG_LS_PROXY", _previous_proxy_env],
                    check=True,
                )
                os.environ["AG_LS_PROXY"] = _previous_proxy_env
                logging.info("Восстановлено предыдущее значение AG_LS_PROXY")
            else:
                subprocess.run(["launchctl", "unsetenv", "AG_LS_PROXY"], check=True)
                os.environ.pop("AG_LS_PROXY", None)
                logging.info("Снята переменная launchctl AG_LS_PROXY")
            _managed_proxy_env = None
            _previous_proxy_env = None
            return True
        except Exception as e:
            logging.error(f"Ошибка восстановления launchctl AG_LS_PROXY: {e}")
            return False

def get_macos_proxy_env() -> str | None:
    """Reads current launchctl AG_LS_PROXY environment variable."""
    try:
        res = subprocess.run(["launchctl", "getenv", "AG_LS_PROXY"], stdout=subprocess.PIPE, text=True)
        val = res.stdout.strip()
        return val if val else None
    except Exception:
        return None
