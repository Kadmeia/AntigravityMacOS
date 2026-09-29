# Attribution and modifications

Antigravity Unlocker for macOS — by Kadmeia.

This project is a macOS-oriented fork and adaptation of
[Antigravity](https://github.com/confeden/Antigravity) ("Antigravity в России без VPN и смены региона аккаунта Google"),
whose original author is [confeden](https://github.com/confeden) (Justin / Telegram: [t.me/nova_txt](https://t.me/nova_txt/69864)).

Material changes and adaptations in this macOS fork include:
- Native macOS WebKit graphical interface (pywebview / Cocoa).
- Python backend tailored for macOS architecture with ad-hoc `codesign` validation.
- Clean Google Edge Server Frontend (ESF) routing with TLS ClientHello packet fragmentation for Russian ISP/DPI bypass without third-party VPN.
- Localhost security API with token protection and strict request origin validation.
- macOS launchctl daemon services (`install_service.sh` / `uninstall_service.sh`).
- Separate thin Apple Silicon (`arm64`) and Intel (`x86_64`) PKG / DMG distribution packages.
- Atomic configuration and persistent session logging in `~/.agunlocker_mac`.

This project is unofficial and is not affiliated with or endorsed by Google.
