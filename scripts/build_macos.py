#!/usr/bin/env python3
"""Build and verify one thin, self-contained macOS application bundle."""

from __future__ import annotations

import argparse
import hashlib
from importlib import metadata as importlib_metadata
import os
from pathlib import Path
import platform
import plistlib
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent
APP_NAME = "Antigravity Unlocker"
APP_VERSION = "1.0"
SUPPORTED_ARCHES = {"arm64", "x86_64"}
LEGAL_FILES = (
    "LICENSE",
    "EULA.md",
    "EULA.txt",
    "EULA.html",
    "NOTICE.md",
    "THIRD_PARTY_NOTICES.md",
)
NOTICE_DISTRIBUTIONS = (
    "pywebview",
    "pyobjc-core",
    "pyobjc-framework-Cocoa",
    "pyobjc-framework-WebKit",
    "bottle",
    "proxy-tools",
    "typing-extensions",
    "pyinstaller",
    "altgraph",
    "macholib",
)


def run(command: list[str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(command), flush=True)
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True)
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    if result.returncode:
        raise RuntimeError(f"Command failed with exit code {result.returncode}: {command[0]}")
    return result


def macho_arches(path: Path) -> list[str]:
    description = subprocess.run(["file", "-b", str(path)], capture_output=True, text=True).stdout
    if "Mach-O" not in description:
        return []
    result = run(["lipo", "-archs", str(path)])
    return result.stdout.strip().split()


def verify_thin_bundle(app_path: Path, arch: str) -> None:
    checked = 0
    for path in app_path.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        arches = macho_arches(path)
        if not arches:
            continue
        checked += 1
        if arches != [arch]:
            raise RuntimeError(f"Architecture mismatch: {path} contains {arches}, expected only {arch}")
    if checked == 0:
        raise RuntimeError("No Mach-O files found in application bundle")
    print(f"Verified {checked} Mach-O files: thin {arch}")


def patch_info_plist(app_path: Path, arch: str) -> None:
    plist_path = app_path / "Contents" / "Info.plist"
    with plist_path.open("rb") as handle:
        info = plistlib.load(handle)
    info.update(
        {
            "CFBundleName": APP_NAME,
            "CFBundleDisplayName": "Antigravity Unlocker by Kadmeia",
            "CFBundleIdentifier": "ru.kadmeia.antigravity-unlocker",
            "CFBundleShortVersionString": APP_VERSION,
            "CFBundleVersion": APP_VERSION,
            "LSMinimumSystemVersion": "14.0",
            "NSHighResolutionCapable": True,
            "NSHumanReadableCopyright": (
                "macOS fork by Kadmeia; based on Open AG Patcher by AvenCores (GPL-3.0)"
            ),
        }
    )
    with plist_path.open("wb") as handle:
        plistlib.dump(info, handle, sort_keys=True)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_distribution_licenses(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for distribution_name in NOTICE_DISTRIBUTIONS:
        try:
            distribution = importlib_metadata.distribution(distribution_name)
        except importlib_metadata.PackageNotFoundError:
            print(f"Warning: license metadata not found for {distribution_name}", file=sys.stderr)
            continue
        safe_name = distribution.metadata["Name"].replace("/", "-")
        version = distribution.version
        copied = 0
        for relative in distribution.files or ():
            basename = Path(str(relative)).name.lower()
            if not (basename.startswith("license") or basename.startswith("copying")):
                continue
            source = Path(distribution.locate_file(relative))
            if not source.is_file() or source.stat().st_size > 2 * 1024 * 1024:
                continue
            target = destination / f"{safe_name}-{version}-{copied + 1}-{source.name}"
            shutil.copy2(source, target)
            copied += 1
        if copied == 0:
            print(f"Warning: no license file copied for {distribution_name}", file=sys.stderr)


def copy_corresponding_source(destination: Path) -> None:
    ignored = shutil.ignore_patterns(
        ".git",
        ".venv",
        ".pytest_cache",
        "__pycache__",
        "*.pyc",
        ".DS_Store",
        "build",
        "release",
    )
    shutil.copytree(ROOT, destination, ignore=ignored)


def update_checksums(output_dir: Path) -> None:
    artifacts = sorted([*output_dir.glob("*.dmg"), *output_dir.glob("*.pkg")])
    lines = [f"{sha256(path)}  {path.name}" for path in artifacts]
    checksum_path = output_dir / "SHA256SUMS.txt"
    temporary = checksum_path.with_suffix(".tmp")
    temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    temporary.replace(checksum_path)


def build_installer_package(app_path: Path, arch: str, build_root: Path, output_path: Path) -> None:
    package_root = build_root / "pkg-root"
    applications_dir = package_root / "Applications"
    applications_dir.mkdir(parents=True)
    shutil.copytree(app_path, applications_dir / f"{APP_NAME}.app", symlinks=True)
    run(["xattr", "-cr", str(package_root)])

    component_plist = build_root / "components.plist"
    run(["pkgbuild", "--analyze", "--root", str(package_root), str(component_plist)])
    with component_plist.open("rb") as handle:
        components = plistlib.load(handle)
    for component in components:
        if component.get("RootRelativeBundlePath") == f"Applications/{APP_NAME}.app":
            component["BundleIsRelocatable"] = False
            component["BundleIsVersionChecked"] = False
            component["BundleHasStrictIdentifier"] = True
            component["BundleOverwriteAction"] = "upgrade"
    with component_plist.open("wb") as handle:
        plistlib.dump(components, handle, sort_keys=True)

    component_pkg = build_root / "Antigravity-Unlocker-component.pkg"
    package_identifier = "ru.kadmeia.antigravity-unlocker"
    run(
        [
            "pkgbuild",
            "--root",
            str(package_root),
            "--component-plist",
            str(component_plist),
            "--identifier",
            package_identifier,
            "--version",
            APP_VERSION,
            "--install-location",
            "/",
            "--ownership",
            "recommended",
            str(component_pkg),
        ]
    )

    installer_resources = build_root / "installer-resources"
    installer_resources.mkdir()
    run(
        [
            "textutil",
            "-convert",
            "rtf",
            "-output",
            str(installer_resources / "EULA.rtf"),
            str(ROOT / "EULA.html"),
        ]
    )
    (installer_resources / "Welcome.txt").write_text(
        f"{APP_NAME} {APP_VERSION}\n\n"
        "Установщик поместит приложение в папку «Программы».\n"
        "Выберите пакет, соответствующий процессору вашего Mac.\n",
        encoding="utf-8",
    )
    (installer_resources / "ReadMe.txt").write_text(
        "Сборка имеет локальную ad-hoc подпись и не нотариализована Apple. "
        "При предупреждении macOS используйте правый клик → «Открыть».\n",
        encoding="utf-8",
    )
    distribution = build_root / "Distribution.xml"
    distribution.write_text(
        f'''<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
  <title>{APP_NAME} {APP_VERSION} ({arch})</title>
  <welcome file="Welcome.txt"/>
  <license file="EULA.rtf" mime-type="text/rtf"/>
  <readme file="ReadMe.txt"/>
  <options customize="never" rootVolumeOnly="true" hostArchitectures="{arch}"/>
  <domains enable_localSystem="true" enable_currentUserHome="false" enable_anywhere="false"/>
  <choices-outline>
    <line choice="default"/>
  </choices-outline>
  <choice id="default" visible="false">
    <pkg-ref id="{package_identifier}"/>
  </choice>
  <pkg-ref id="{package_identifier}" version="{APP_VERSION}" auth="Root">{component_pkg.name}</pkg-ref>
</installer-gui-script>
''',
        encoding="utf-8",
    )
    run(
        [
            "productbuild",
            "--distribution",
            str(distribution),
            "--resources",
            str(installer_resources),
            "--package-path",
            str(build_root),
            str(output_path),
        ]
    )
    run(["pkgutil", "--payload-files", str(output_path)])


def build(arch: str, output_dir: Path, *, keep_build: bool = False) -> tuple[Path, Path, Path]:
    if arch not in SUPPORTED_ARCHES:
        raise ValueError(f"Unsupported architecture: {arch}")
    if platform.system() != "Darwin" or platform.machine() != arch:
        raise RuntimeError(
            f"Builder must run as {arch}; current platform is {platform.system()} {platform.machine()}"
        )

    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    final_app = output_dir / f"{APP_NAME}-{arch}.app"
    final_dmg = output_dir / f"Antigravity-Unlocker-{APP_VERSION}-macOS-{arch}.dmg"
    final_pkg = output_dir / f"Antigravity-Unlocker-{APP_VERSION}-macOS-{arch}-Installer.pkg"
    for target in (final_app, final_dmg, final_pkg):
        if target.exists():
            if target.is_dir():
                shutil.rmtree(target)
            else:
                target.unlink()

    build_parent = ROOT / "build"
    build_parent.mkdir(parents=True, exist_ok=True)
    build_root = Path(tempfile.mkdtemp(prefix=f"antigravity-{arch}-", dir=build_parent))
    dist_dir = build_root / "dist"
    work_dir = build_root / "work"
    spec_dir = build_root / "spec"
    config_dir = build_root / "pyinstaller-config"
    for directory in (dist_dir, work_dir, spec_dir, config_dir):
        directory.mkdir(parents=True, exist_ok=True)

    try:
        env = os.environ.copy()
        env["PYINSTALLER_CONFIG_DIR"] = str(config_dir)
        command = [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--windowed",
            "--onedir",
            "--name",
            APP_NAME,
            "--icon",
            str(ROOT / "assets" / "icon.icns"),
            "--add-data",
            f"{ROOT / 'frontend'}:frontend",
            "--hidden-import",
            "webview.platforms.cocoa",
            "--collect-data",
            "webview",
            "--exclude-module",
            "cryptography",
            "--exclude-module",
            "jinja2",
            "--exclude-module",
            "markupsafe",
            "--exclude-module",
            "PIL",
            "--exclude-module",
            "numpy",
            "--osx-bundle-identifier",
            "ru.kadmeia.antigravity-unlocker",
            "--target-architecture",
            arch,
            "--distpath",
            str(dist_dir),
            "--workpath",
            str(work_dir),
            "--specpath",
            str(spec_dir),
            str(ROOT / "desktop_app.py"),
        ]
        for legal_file in LEGAL_FILES:
            legal_path = ROOT / legal_file
            if not legal_path.is_file():
                raise FileNotFoundError(f"Required legal file is missing: {legal_path}")
            command[command.index("--hidden-import"):command.index("--hidden-import")] = [
                "--add-data",
                f"{legal_path}:.",
            ]
        print("+", " ".join(command), flush=True)
        result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        if result.returncode:
            raise RuntimeError(f"PyInstaller failed with exit code {result.returncode}")

        built_app = dist_dir / f"{APP_NAME}.app"
        if not built_app.exists():
            raise RuntimeError(f"PyInstaller did not create {built_app}")
        patch_info_plist(built_app, arch)
        resources_dir = built_app / "Contents" / "Resources"
        collect_distribution_licenses(resources_dir / "third_party_licenses")
        copy_corresponding_source(resources_dir / "corresponding_source")
        run(["xattr", "-cr", str(built_app)])
        run(["codesign", "--force", "--deep", "--sign", "-", str(built_app)])
        run(["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(built_app)])
        verify_thin_bundle(built_app, arch)
        executable = built_app / "Contents" / "MacOS" / APP_NAME
        run([str(executable), "--self-test"])
        shutil.copytree(built_app, final_app, symlinks=True)

        staging = build_root / "dmg-staging"
        staging.mkdir()
        shutil.copytree(final_app, staging / f"{APP_NAME}.app", symlinks=True)
        (staging / "Applications").symlink_to("/Applications")
        for legal_file in LEGAL_FILES:
            shutil.copy2(ROOT / legal_file, staging / legal_file)
        collect_distribution_licenses(staging / "third_party_licenses")
        copy_corresponding_source(staging / "Source Code")
        run(
            [
                "hdiutil",
                "create",
                "-volname",
                f"Antigravity Unlocker {arch}",
                "-srcfolder",
                str(staging),
                "-ov",
                "-format",
                "UDZO",
                str(final_dmg),
            ]
        )
        run(["hdiutil", "verify", str(final_dmg)])
        build_installer_package(final_app, arch, build_root, final_pkg)
        update_checksums(output_dir)
        print(f"APP: {final_app}")
        print(f"DMG: {final_dmg}")
        print(f"PKG: {final_pkg}")
        print(f"SHA256: {sha256(final_dmg)}  {final_dmg.name}")
        print(f"SHA256: {sha256(final_pkg)}  {final_pkg.name}")
        return final_app, final_dmg, final_pkg
    finally:
        if not keep_build and build_root.exists():
            shutil.rmtree(build_root, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", required=True, choices=sorted(SUPPORTED_ARCHES))
    parser.add_argument("--output-dir", type=Path, default=ROOT / "release")
    parser.add_argument("--keep-build", action="store_true", help="Keep intermediate build directory")
    args = parser.parse_args()
    build(args.arch, args.output_dir, keep_build=args.keep_build)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
