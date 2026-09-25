from __future__ import annotations

import copy
import fcntl
import json
import logging
import os
import secrets
import tempfile
import threading
from typing import Any

CONFIG_DIR = os.path.expanduser("~/.agunlocker_mac")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
LOG_FILE = os.path.join(CONFIG_DIR, "app.log")
API_TOKEN_FILE = os.path.join(CONFIG_DIR, "api-token")

CONFIG_LOCK = threading.RLock()

DEFAULT_CONFIG: dict[str, Any] = {
    "master_enabled": False,
    "proxy_port": 53129,
    "web_port": 53128,
    "route_mode": "smart",  # "smart", "tls_split", "custom", "direct"
    "selected_target": "antigravity_desktop",
    "managed_targets": [],  # Only explicit patch actions enroll an app in auto-patch.
    "custom_proxy": {
        "type": "http",      # "http", "socks5"
        "host": "127.0.0.1",
        "port": 7890
    },
    "auto_patch_on_launch": True,
    "auto_resign": True,
    "custom_app_paths": []
}

def ensure_config_dir() -> None:
    try:
        if not os.path.exists(CONFIG_DIR):
            os.makedirs(CONFIG_DIR, exist_ok=True)
        os.chmod(CONFIG_DIR, 0o700)
    except Exception as e:
        logging.error(f"Failed to create config dir {CONFIG_DIR}: {e}")


def load_or_create_api_token() -> str:
    """Return one private localhost API token shared by this user's app processes."""
    ensure_config_dir()
    token_path = API_TOKEN_FILE
    lock_path = token_path + ".lock"
    fallback_token = secrets.token_urlsafe(32)

    try:
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    except OSError as exc:
        logging.warning(f"Failed to open API token lock {lock_path}: {exc}")
        # A read-only installation can still reuse a previously persisted
        # token; only generate a process-local token when no valid one exists.
        try:
            with open(token_path, "r", encoding="utf-8") as handle:
                existing = handle.read().strip()
            if len(existing) >= 32:
                return existing
        except (OSError, UnicodeError):
            pass
        return fallback_token

    locked = False
    try:
        os.fchmod(lock_fd, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        locked = True
        try:
            with open(token_path, "r", encoding="utf-8") as handle:
                existing = handle.read().strip()
            if len(existing) >= 32:
                os.chmod(token_path, 0o600)
                return existing
        except FileNotFoundError:
            pass
        except (OSError, UnicodeError):
            # Replace unreadable or malformed state while holding the lock.
            logging.warning(f"Replacing unreadable API token at {token_path}")

        fd, temporary = tempfile.mkstemp(prefix="api-token-", dir=os.path.dirname(token_path))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(fallback_token)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, token_path)
            dir_fd = os.open(os.path.dirname(token_path), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
            return fallback_token
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    except OSError as exc:
        logging.warning(f"Failed to persist API token to {token_path}: {exc}")
        return fallback_token
    finally:
        try:
            if locked:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)

def load_config() -> dict[str, Any]:
    with CONFIG_LOCK:
        ensure_config_dir()
        if not os.path.exists(CONFIG_FILE):
            save_config(DEFAULT_CONFIG)
            return copy.deepcopy(DEFAULT_CONFIG)
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                if not isinstance(cfg, dict):
                    return copy.deepcopy(DEFAULT_CONFIG)
                # Merge with defaults in case new keys were added
                merged = copy.deepcopy(DEFAULT_CONFIG)
                merged.update({key: value for key, value in cfg.items() if key != "custom_proxy"})
                if isinstance(cfg.get("custom_proxy"), dict):
                    merged["custom_proxy"].update(cfg["custom_proxy"])
                if "managed_targets" not in cfg:
                    # Older versions patched every installed app. Preserve the
                    # active Desktop setup without silently enrolling the IDE.
                    merged["managed_targets"] = (["antigravity_desktop"]
                                                 if cfg.get("master_enabled") else [])
                elif not isinstance(cfg["managed_targets"], list):
                    merged["managed_targets"] = []
                else:
                    merged["managed_targets"] = [item for item in cfg["managed_targets"]
                                                 if isinstance(item, str) and item != "all"]
                return merged
        except Exception as e:
            logging.error(f"Error loading config from {CONFIG_FILE}: {e}")
            return copy.deepcopy(DEFAULT_CONFIG)

def save_config(cfg: dict[str, Any]) -> bool:
    with CONFIG_LOCK:
        ensure_config_dir()
        tmp_path = None
        try:
            fd, tmp_path = tempfile.mkstemp(prefix="config-", suffix=".json", dir=CONFIG_DIR)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, CONFIG_FILE)
            return True
        except Exception as e:
            logging.error(f"Error saving config to {CONFIG_FILE}: {e}")
            return False
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
