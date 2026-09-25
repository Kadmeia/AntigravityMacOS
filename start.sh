#!/bin/bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="$DIR:$PYTHONPATH"

echo "=========================================================="
echo "    🚀 Antigravity Unlocker macOS by Kadmeia"
echo "=========================================================="

# 1. Check or initialize virtual environment
if [ ! -d "$DIR/.venv" ]; then
    echo "🔍 Поиск подходящей версии Python..."
    if [ -x "/opt/homebrew/bin/python3.11" ]; then
        BASE_PYTHON="/opt/homebrew/bin/python3.11"
    elif command -v python3.11 >/dev/null 2>&1; then
        BASE_PYTHON="$(command -v python3.11)"
    elif command -v python3 >/dev/null 2>&1; then
        BASE_PYTHON="$(command -v python3)"
    else
        echo "❌ Ошибка: Python 3 не найден в системе. Установите Python 3."
        exit 1
    fi

    echo "⚙️  Первый запуск: создание окружения (.venv)..."
    echo "    Интерпретатор: $($BASE_PYTHON --version 2>&1)"
    "$BASE_PYTHON" -m venv "$DIR/.venv"
fi

PYTHON_EXEC="$DIR/.venv/bin/python3"
PIP_EXEC="$DIR/.venv/bin/pip"

# 2. Check if required dependencies are installed in .venv
if ! "$PYTHON_EXEC" -c "import webview" >/dev/null 2>&1; then
    echo "📦 Установка графических компонентов (pywebview)..."
    "$PIP_EXEC" install -q -r "$DIR/requirements.txt"
    echo "✅ Компоненты успешно установлены!"
fi

echo "✨ Запуск приложения: $($PYTHON_EXEC --version 2>&1)"
echo "=========================================================="

exec "$PYTHON_EXEC" "$DIR/desktop_app.py" "$@"
