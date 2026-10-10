"""Discover apps from authoritative manager inventories and explicit user install locations."""

import json
import os
import re
import shlex
import shutil
from pathlib import Path

from .model import App, Inventory, Refusal
from .runtime import capture, file_fingerprint, parse_size, xdg_dir

KINDS = ("apt", "flatpak", "snap", "appimage", "extension")
PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?\Z")
SNAP_NAME = re.compile(r"[a-z0-9][a-z0-9-]*(?:_[a-z0-9]+)?\Z")
FLATPAK_REF = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*/[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+\Z")


def flatpak_flag(scope):
    return {"user": "--user", "system": "--system"}.get(scope, "--installation=" + scope)


def apt_apps():
    fmt = (
        "${binary:Package}\t${db:Status-Status}\t${Version}\t${Installed-Size}"
        "\t${Essential}\t${Protected}\t${Priority}\t${binary:Summary}\n"
    )
    apps = []
    for line in capture(["dpkg-query", "-W", "-f=" + fmt]).splitlines():
        fields = line.split("\t", 7)
        if len(fields) != 8 or fields[1] != "installed":
            continue
        package, _, version, size, essential, protected, priority, summary = fields
        if not PACKAGE.fullmatch(package):
            raise Refusal("Identificador de paquete APT inesperado")
        apps.append(
            App(
                f"apt:{package}",
                "apt",
                package,
                package,
                version,
                size_bytes=int(size) * 1024 if size.isdigit() else None,
                size_label="Installed-Size de dpkg; estimación nominal",
                protected=essential == "yes" or protected == "yes" or priority == "required",
                fingerprint=version,
            )
        )
    return apps


def flatpak_apps():
    output = capture(["flatpak", "list", "--app", "--columns=ref,name,installation,size"])
    apps = []
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) != 4:
            raise Refusal("Formato de inventario Flatpak inesperado")
        ref, name, scope, size = fields
        if not FLATPAK_REF.fullmatch(ref) or not re.fullmatch(r"[A-Za-z0-9_-]+", scope):
            raise Refusal("Referencia o instalación Flatpak inesperada")
        flag = flatpak_flag(scope)
        commit = capture(["flatpak", "info", flag, "--show-commit", ref]).strip()
        apps.append(
            App(
                f"flatpak:{scope}:{ref}",
                "flatpak",
                ref,
                name,
                ref.rsplit("/", 1)[-1],
                scope,
                parse_size(size),
                "tamaño nominal; objetos compartidos, no espacio recuperable",
                fingerprint=commit,
            )
        )
    return apps


def snap_apps():
    output = capture(["snap", "list"], timeout=8)
    apps = []
    for line in output.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 3:
            continue
        name, version, revision = fields[:3]
        if not SNAP_NAME.fullmatch(name) or not re.fullmatch(r"[0-9]+|x[0-9]+", revision):
            raise Refusal("Inventario Snap inesperado")
        # All installed revision archives are removed by snap remove; shared bases remain.
        archives = sorted(Path("/var/lib/snapd/snaps").glob(name + "_*.snap"))
        size = sum(p.stat().st_blocks * 512 for p in archives) if archives else None
        protected = name in {"snapd", "bare"} or name.startswith(
            ("core", "gnome-", "gtk-", "kf", "mesa-")
        )
        apps.append(
            App(
                f"snap:{name}",
                "snap",
                name,
                name,
                version,
                size_bytes=size,
                size_label="archivos de revisiones; la instantánea puede reducir el espacio liberado",
                protected=protected,
                fingerprint=revision,
            )
        )
    return apps


def safe_user_file(path, home):
    """Reject symlinks (including parent symlinks), foreign ownership and paths outside HOME."""
    try:
        return (
            path.is_absolute()
            and path.is_relative_to(home)
            and path.resolve() == path
            and path.is_file()
            and not path.is_symlink()
            and path.stat().st_uid == os.getuid()
        )
    except OSError:
        return False


def appimage_apps(home, data, extra_dirs=()):
    found = {}
    launchers = data / "applications"
    for desktop in sorted(launchers.glob("*.desktop")):
        if not safe_user_file(desktop, home):
            continue
        values = {}
        in_entry = False
        for line in desktop.read_text(errors="replace").splitlines():
            if line.startswith("["):
                in_entry = line == "[Desktop Entry]"
            elif in_entry and "=" in line:
                key, value = line.split("=", 1)
                values[key] = value
        try:
            tokens = shlex.split(values.get("Exec", ""))
        except ValueError:
            continue
        for token in tokens:
            path = Path(token)
            if path.suffix.lower() == ".appimage" and safe_user_file(path, home):
                item = found.setdefault(path, {"name": values.get("Name", path.stem), "paths": []})
                item["paths"].append(str(desktop))
    for directory in (home / "Applications", home / "AppImages", home / ".local/bin", *extra_dirs):
        directory = Path(directory).expanduser().absolute()
        if directory.resolve() != directory or not directory.is_relative_to(home):
            raise Refusal(f"Directorio AppImage fuera de HOME o enlazado: {directory}")
        for path in sorted(directory.glob("*")):
            if path.suffix.lower() == ".appimage" and safe_user_file(path, home):
                found.setdefault(path, {"name": path.stem, "paths": []})
    return [
        App(
            f"appimage:{path}",
            "appimage",
            str(path),
            item["name"],
            size_bytes=path.stat().st_blocks * 512,
            size_label="asignado al archivo; mover a Papelera no libera espacio todavía",
            paths=[str(path), *item["paths"]],
            fingerprint="|".join(file_fingerprint(Path(p)) for p in [str(path), *item["paths"]]),
        )
        for path, item in sorted(found.items())
    ]


def extension_apps(home, data):
    apps = []
    for directory in sorted((data / "gnome-shell/extensions").glob("*")):
        if directory.is_symlink() or directory.resolve() != directory:
            continue
        metadata = directory / "metadata.json"
        if not safe_user_file(metadata, home):
            continue
        try:
            values = json.loads(metadata.read_text())
        except (ValueError, OSError):
            continue
        uuid = values.get("uuid", "")
        if uuid != directory.name or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@+-]*", uuid):
            continue
        apps.append(
            App(
                f"extension:{uuid}",
                "extension",
                uuid,
                values.get("name", uuid),
                str(values.get("version", "")),
                "user",
                paths=[str(directory)],
                fingerprint=file_fingerprint(metadata),
            )
        )
    return apps


def discover(kinds=KINDS, extra_dirs=()):
    home = Path.home().resolve()
    data = xdg_dir("XDG_DATA_HOME", home / ".local/share")
    inventory = Inventory()
    backends = {
        "apt": ("dpkg-query", apt_apps),
        "flatpak": ("flatpak", flatpak_apps),
        "snap": ("snap", snap_apps),
        "appimage": (None, lambda: appimage_apps(home, data, extra_dirs)),
        "extension": (None, lambda: extension_apps(home, data)),
    }
    for kind in kinds:
        executable, function = backends[kind]
        if executable and not shutil.which(executable):
            inventory.notes.append(f"{kind}: gestor no instalado")
            continue
        try:
            inventory.apps.extend(function())
        except (Refusal, OSError, ValueError) as exc:
            inventory.errors[kind] = str(exc)
    inventory.apps.sort(key=lambda app: (app.kind, app.name.casefold(), app.key))
    return inventory
