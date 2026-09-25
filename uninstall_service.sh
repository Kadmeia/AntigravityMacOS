#!/bin/bash
PLIST="$HOME/Library/LaunchAgents/com.antigravity.proxy.plist"

# Remove only the value managed by this application; preserve user overrides.
CURRENT_PROXY="$(launchctl getenv AG_LS_PROXY 2>/dev/null || true)"
if [ "$CURRENT_PROXY" = "http://127.0.0.1:53129" ]; then
    launchctl unsetenv AG_LS_PROXY 2>/dev/null || true
fi

if [ -f "$PLIST" ]; then
    launchctl unload "$PLIST" 2>/dev/null || true
    rm -f "$PLIST"
    echo "✅ Служба автозапуска успешно удалена, переменная AG_LS_PROXY очищена."
else
    echo "Служба не была установлена. Переменная AG_LS_PROXY очищена."
fi
