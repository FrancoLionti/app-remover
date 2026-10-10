"""Resolve requests, simulate APT transactions and explain each native removal operation."""

import re
import shutil
from pathlib import Path

from .inventory import flatpak_flag
from .model import Plan, Refusal, Step
from .runtime import capture, xdg_dir

APT_OPTIONS = [
    "--no-upgrade",
    "-o",
    "APT::Get::AutomaticRemove=false",
    "-o",
    "APT::Get::Assume-Yes=false",
    "-o",
    "APT::Get::allow-remove-essential=false",
    "-o",
    "APT::Get::allow-change-held-packages=false",
    "-o",
    "APT::Get::Purge=false",
]


def normalize(value):
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def canonical_names(app):
    identifier = app.identifier.split("/")[0]
    if app.kind == "extension":
        identifier = app.identifier.split("@")[0]
    elif app.kind == "flatpak":
        identifier = identifier.split(".")[-1]
    elif app.kind == "apt":
        identifier = identifier.removeprefix("gnome-shell-extension-")
    elif app.kind == "appimage":
        identifier = Path(app.identifier).stem
    return {normalize(app.name), normalize(identifier)} - {""}


def related_apps(apps, inventory):
    """Conservative name matches for reporting only, never an automatic removal decision."""

    selected_keys = {app.key for app in apps}
    selected_names = set().union(*(canonical_names(app) for app in apps))
    return [
        app
        for app in inventory.apps
        if app.key not in selected_keys and selected_names.intersection(canonical_names(app))
    ]


def resolve(selectors, inventory, choose=None):
    """Exact identities take priority; human names and substrings require unique matches."""
    selected = {}
    for selector in selectors:
        if not selector or selector.startswith("-"):
            raise Refusal("La búsqueda no puede estar vacía ni comenzar con '-'")
        exact_key = [app for app in inventory.apps if app.key == selector]
        if exact_key:
            candidates = exact_key
        else:
            if ":" in selector:
                raise Refusal(f"Identificador no instalado: {selector}")
            if inventory.errors:
                raise Refusal(
                    "Inventario incompleto; usá --type o un identificador exacto. "
                    + "; ".join(f"{k}: {v}" for k, v in inventory.errors.items())
                )
            query = normalize(selector)
            if not query:
                raise Refusal("La búsqueda necesita letras o números")
            candidates = [app for app in inventory.apps if query in canonical_names(app)]
            if not candidates:
                candidates = [
                    app
                    for app in inventory.apps
                    if query in normalize(app.name) or query in normalize(app.identifier)
                ]
        if not candidates:
            raise Refusal(f"No encontré una app instalada para: {selector}")
        if len(candidates) > 1:
            if choose is None:
                raise Refusal(
                    "Búsqueda ambigua: "
                    + selector
                    + "\n"
                    + "\n".join("  " + app.key for app in candidates)
                )
            candidates = choose(selector, candidates)
            if not candidates:
                raise Refusal("Selección cancelada")
        for app in candidates:
            if app.kind in inventory.errors:
                raise Refusal(f"Inventario {app.kind} incompleto")
            if app.protected:
                raise Refusal(f"Bloqueado por protección del sistema: {app.key}")
            selected[app.key] = app
    return list(selected.values())


def apt_transaction(apps, inventory):
    packages = [app.identifier for app in apps]
    native = ["apt-get", *APT_OPTIONS, "remove", *packages]
    simulation = capture(["apt-get", "-s", *APT_OPTIONS, "remove", *packages], timeout=60)
    if re.search(r"^(Inst|Conf|Purg) ", simulation, re.MULTILINE):
        raise Refusal("APT propone instalar/configurar/purgar paquetes; operación bloqueada")
    affected = re.findall(r"^Remv (\S+)", simulation, re.MULTILINE)
    if not affected:
        raise Refusal("APT no confirmó ningún paquete para eliminar")
    known = {app.identifier: app for app in inventory.apps if app.kind == "apt"}
    resolved = []
    for package in affected:
        candidate = known.get(package)
        if candidate is None:
            matches = [app for key, app in known.items() if key.split(":")[0] == package]
            if len(matches) == 1:
                candidate = matches[0]
        if candidate is None:
            raise Refusal(f"APT propone retirar un paquete sin identificar: {package}")
        if candidate.protected:
            raise Refusal(f"APT afectaría un paquete protegido: {package}")
        resolved.append(candidate)
    if not set(packages).issubset({app.identifier for app in resolved}):
        raise Refusal("La simulación APT no incluye todos los paquetes solicitados")
    size = (
        sum(app.size_bytes for app in resolved)
        if all(app.size_bytes is not None for app in resolved)
        else None
    )
    notes = ["Conserva configuración; no ejecuta autoremove. APT vuelve a pedir confirmación."]
    extras = [app.identifier for app in resolved if app.identifier not in packages]
    if extras:
        notes.append("También retira dependientes: " + ", ".join(extras))
    if "automatically installed and are no longer required" in simulation:
        notes.append("APT detectó dependencias huérfanas; quedan instaladas (ver simulación).")
    for app in apps:
        paths = capture(["dpkg-query", "-L", app.identifier]).splitlines()
        services = [p for p in paths if p.endswith(".service") and "/systemd/" in p]
        if services:
            notes.append(
                app.identifier + " proporciona unidades de servicio: " + ", ".join(services)
            )
    return Step(
        "apt",
        [app.key for app in apps],
        ["sudo", *native],
        affected,
        size,
        "Installed-Size de la transacción; estimación nominal",
        notes,
        simulation,
    )


def leftover_candidates(apps):
    home = Path.home().resolve()
    roots = [
        xdg_dir("XDG_CONFIG_HOME", home / ".config"),
        xdg_dir("XDG_CACHE_HOME", home / ".cache"),
        xdg_dir("XDG_DATA_HOME", home / ".local/share"),
    ]
    candidates = {}
    aliases = {
        "simplescreenrecorder": ["simplescreenrecorder", "SimpleScreenRecorder"],
        "webtorrent-desktop": ["WebTorrent", "webtorrent"],
        "teams-for-linux": ["teams-for-linux"],
        "sunshine": ["sunshine"],
    }
    for app in apps:
        if app.kind == "flatpak":
            paths = [home / ".var/app" / app.identifier.split("/")[0]]
            note = "Datos de Flatpak conservados"
        elif app.kind == "snap":
            paths = [home / "snap" / app.identifier, Path("/var/snap") / app.identifier]
            note = "Datos actuales; Snap puede guardarlos en una instantánea al quitar la app"
        elif app.kind == "extension":
            paths = []
            note = ""
        else:
            names = aliases.get(
                app.identifier, [app.name, Path(app.identifier).stem, app.identifier.split(":")[0]]
            )
            names = [name for name in names if name not in (".", "..") and "/" not in name]
            paths = [root / name for root in roots for name in names]
            note = "Coincidencia de nombre; posible configuración/caché, no se borra"
        for path in paths:
            if path.exists() or path.is_symlink():
                key = str(path)
                item = candidates.setdefault(key, {"path": key, "apps": [], "note": note})
                if app.key not in item["apps"]:
                    item["apps"].append(app.key)
    return sorted(candidates.values(), key=lambda item: item["path"])


def make_plan(apps, inventory):
    if not apps:
        raise Refusal("Seleccioná al menos una app")
    steps = []
    apt = [app for app in apps if app.kind == "apt"]
    if apt:
        steps.append(apt_transaction(apt, inventory))
    for app in apps:
        if app.kind == "apt":
            continue
        notes = []
        if app.kind == "flatpak":
            argv = ["flatpak", "uninstall", flatpak_flag(app.scope), "--app", app.identifier]
            notes = [
                "Conserva ~/.var/app; el gestor muestra las extensiones relacionadas antes de confirmar.",
                "No elimina runtimes compartidos sin uso. No hay simulación nativa equivalente a APT.",
            ]
        elif app.kind == "snap":
            argv = ["sudo", "snap", "remove", app.identifier]
            notes = [
                "Quita todas las revisiones de esta app; conserva bases compartidas.",
                "Snap borra los datos de la app y normalmente crea una instantánea recuperable.",
                "Si las instantáneas automáticas están deshabilitadas, no habrá copia; revisá snap get system snapshots.",
                "Sin --purge; no hay simulación nativa. Si otras apps la necesitan, Snap puede rechazar la operación.",
            ]
            try:
                retention = capture(
                    ["snap", "get", "system", "snapshots.automatic.retention"], timeout=8
                ).strip()
                if retention == "no":
                    notes.append(
                        "ATENCIÓN: instantáneas automáticas deshabilitadas; los datos de Snap se perderán."
                    )
                else:
                    notes.append("Retención de instantáneas configurada: " + retention)
            except Refusal:
                notes.append(
                    "No se pudo verificar la política de instantáneas; consultá snap get system snapshots."
                )
        elif app.kind == "appimage":
            if not shutil.which("gio"):
                raise Refusal("Necesitás gio para mover AppImages a la Papelera")
            argv = ["gio", "trash", "--", *app.paths]
            notes = [
                "Mueve este archivo y sus lanzadores de usuario identificados a Papelera.",
                "Recuperable; libera espacio recién al vaciar la Papelera. No borra datos de la app.",
            ]
        elif app.kind == "extension":
            if not shutil.which("gnome-extensions"):
                raise Refusal("Necesitás gnome-extensions para quitar esta extensión de usuario")
            argv = ["gnome-extensions", "uninstall", app.identifier]
            notes = [
                "Quita la copia de usuario de GNOME Shell; la copia APT es independiente.",
                "Puede requerir cerrar sesión para dejar de estar cargada. Los ajustes dconf permanecen.",
            ]
        else:
            raise Refusal(f"Origen no soportado: {app.kind}")
        size = 0 if app.kind == "appimage" else app.size_bytes
        steps.append(
            Step(
                app.kind,
                [app.key],
                argv,
                [app.identifier],
                size,
                "0 inmediato; Papelera" if app.kind == "appimage" else app.size_label,
                notes,
            )
        )
    notes = [
        *inventory.notes,
        "Las estimaciones no se suman: Flatpak comparte objetos y Snap puede crear instantáneas.",
        "Los restos son detecciones parciales; no se infiere ni elimina información personal.",
    ]
    notes.extend(
        f"Inventario {kind} no disponible: {error}" for kind, error in inventory.errors.items()
    )
    duplicates = related_apps(apps, inventory)
    if duplicates:
        notes.append(
            "Otras instalaciones con nombre coincidente, no seleccionadas: "
            + ", ".join(app.key for app in duplicates)
        )
    return Plan(apps, steps, leftover_candidates(apps), notes)
