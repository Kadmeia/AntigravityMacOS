# Инструкция по улучшению приложения

## Реализовано в 1.3.0 (Встроенный обход DPI через TLS-фрагментацию и поддержка Antigravity 2.0)

1. **Встроенный обход DPI (механика ByeDPI без сторонних программ):**
   - В [backend/proxy.py](file:///Volumes/CodeOS/Antigravity/backend/proxy.py) реализована сегментация пакета TLS ClientHello (`split 2` с микрозадержкой и `TCP_NODELAY`). Пакет рукопожатия делится на 2 TCP-сегмента, скрывая имя домена от ТСПУ/DPI провайдера.
   - Добавлен 4-й режим маршрутизации: `tls_split` («🛡️ Обход DPI (Фрагментация TLS)»).
2. **Интеграция с UI и API:**
   - В меню настроек [frontend/index.html](file:///Volumes/CodeOS/Antigravity/frontend/index.html) и [frontend/app.js](file:///Volumes/CodeOS/Antigravity/frontend/app.js) добавлен удобный пункт переключения в 1 клик с адаптивными уведомлениями.
   - В [backend/server.py](file:///Volumes/CodeOS/Antigravity/backend/server.py) валидация настроек расширена для поддержки режима `tls_split`.
3. **Бесперебойный доступ к Gemini и облаку Google:**
   - В `CLOUDCODE_HOSTS` добавлены `generativelanguage.googleapis.com`, `oauth2.googleapis.com`, `accounts.google.com`, `antigravity.google`, `antigravity-unleash.goog`, а также зоны `.goog`, `.gstatic.com`, `.googleusercontent.com`.
4. **Исправление перезапуска Antigravity 2.0 (Desktop):**
   - Устранено несовпадение имени кандидата (`"Antigravity"` vs `"Antigravity 2.0 (Desktop)"`) в [backend/patcher.py](file:///Volumes/CodeOS/Antigravity/backend/patcher.py).
5. **Автоматическое тестирование:**
   - Добавлены тесты фрагментации ClientHello и валидации режима в [tests/test_core.py](file:///Volumes/CodeOS/Antigravity/tests/test_core.py). Тестовый набор расширен до 43 тестов.

## Реализовано в 1.2.0 (Обновление Python 3.11 и доработки после ревью)

1. **Миграция на Python 3.11:**
   - Настроено виртуальное окружение на базе Python 3.11.15 (`/opt/homebrew/bin/python3.11`).
   - Кодовая база переписана с использованием нативных возможностей Python 3.11 (типизация `|`, `tuple[...]`, `dict[str, Any]`, `from __future__ import annotations`).
   - Обновлены скрипты запуска `start.sh` и `install_service.sh` для приоритетного использования Python 3.11.
   - Добавлен `pytest.ini` и расширен тестовый набор до 10 автоматических тестов.
2. **Устранение критической гонки потоков:**
   - В `_status_data()` реализовано глубокое копирование `recent_requests` под `local_proxy.lock`, предотвращающее падение с `RuntimeError: list changed size during iteration`.
3. **Предотвращение DoS и шторма перезапусков в Watchdog:**
   - В `watchdog_worker()` добавлен экспоненциальный cooldown и лимит неудачных попыток патча, устраняющий бесконечный цикл завершения `language_server`.
4. **Устранение утечек сокетов и поддержка IPv6:**
   - В `proxy.py` гарантировано закрытие сокетов в блоках `except` для `SMART_RESOLVERS`, SOCKS5 и HTTP upstream.
   - Добавлена корректная обработка IPv6 адресов в CONNECT-запросах (`[::1]:8443`).
   - Таймаут `select.select()` уменьшен до 1.5 с для мгновенной остановки фоновых потоков при выключении службы.
5. **Безопасное завершение процессов:**
   - Широкий `pkill -f` заменен на целевой поиск PID процессов внутри бандла Antigravity и точные имена бинарников (`-x`), защищая сторонние LSP разработчиков.
6. **Корректный Browser Fallback:**
   - В `desktop_app.py` предотвращено мгновенное завершение процесса при сбое `pywebview`, сервер продолжает обслуживать запросы браузера.
7. **Очистка окружения macOS:**
   - В `uninstall_service.sh` добавлено снятие `launchctl unsetenv AG_LS_PROXY`.
8. **Оптимизация UI и батареи:**
   - В `frontend/app.js` селектор приложений стал динамическим, а polling адаптируется к видимости вкладки (`document.hidden`).

## Реализовано ранее в 1.1.0

1. Защищен localhost API: убран wildcard CORS, добавлен случайный токен сессии, проверка Host/Origin, JSON Content-Type, лимит тела и allowlist действий.
2. Убрано внедрение команд из перезапуска: клиент передаёт только известный ID, backend сопоставляет его с разрешённым приложением.
3. Устранено ложное отображение успеха: агрегированы результаты binary/JS операций.
4. Конфигурация сделана атомарной и приватной (`0700` для каталога, `0600` для файла).
5. Проверка `codesign` после изменения и восстановление оригинала при ошибке. Запрещен небезопасный побайтовый откат без точного backup.
6. Воспроизводимый PyInstaller builder для отдельных автономных arm64 и x86_64 `.app`, проверка Mach-O, подписи и DMG.

## Следующий этап

1. Добавить fixture-based golden tests для бинарников каждой новой поддерживаемой версии Antigravity.
2. Проверить релизы на чистых физических системах (Apple Silicon и физический Intel Mac).
3. Оформить Developer ID, notarization и stapling для публичного релиза.
