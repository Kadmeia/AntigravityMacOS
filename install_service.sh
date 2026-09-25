#!/bin/bash
# Installs Antigravity background LaunchAgent so proxy & watchdog run automatically at login
set -e

PLIST="$HOME/Library/LaunchAgents/com.antigravity.proxy.plist"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$HOME/.agunlocker_mac"
SERVICE_DIR="$HOME/Library/Application Support/Antigravity Unlocker/service"
PYTHON_BIN="$(command -v python3.11 || command -v python3)"
"$PYTHON_BIN" -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ required"'

mkdir -p "$HOME/Library/LaunchAgents"
mkdir -p "$LOG_DIR"
mkdir -p "$SERVICE_DIR"
chmod 700 "$LOG_DIR"
chmod 700 "$SERVICE_DIR"
touch "$LOG_DIR/service.log" "$LOG_DIR/service.err"
chmod 600 "$LOG_DIR/service.log" "$LOG_DIR/service.err"

launchctl unload "$PLIST" 2>/dev/null || true
ditto "$DIR/backend" "$SERVICE_DIR/backend"
ditto "$DIR/frontend" "$SERVICE_DIR/frontend"

"$PYTHON_BIN" - "$PLIST" "$SERVICE_DIR" "$LOG_DIR/service.log" "$LOG_DIR/service.err" <<'PY'
import plistlib
import sys

plist_path, service_dir, stdout_path, stderr_path = sys.argv[1:]
payload = {
    "Label": "com.antigravity.proxy",
    "ProgramArguments": [sys.executable, "-m", "backend.server", "53128"],
    "WorkingDirectory": service_dir,
    "RunAtLoad": True,
    "KeepAlive": True,
    "StandardOutPath": stdout_path,
    "StandardErrorPath": stderr_path,
}
with open(plist_path, "wb") as handle:
    plistlib.dump(payload, handle, sort_keys=True)
PY
chmod 600 "$PLIST"
plutil -lint "$PLIST" >/dev/null

launchctl load "$PLIST"

echo "✅ Служба автозапуска успешно установлена в $PLIST"
echo "Теперь Antigravity будет работать автоматически при каждом входе в систему!"
