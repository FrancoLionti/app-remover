"""A plain CLI: discovery is optional; removal always shows a plan and asks first."""

import argparse
import json
import os
import shlex
import sys

from . import __version__
from .execution import execute
from .inventory import KINDS, discover
from .model import Refusal
from .planning import make_plan, resolve
from .runtime import clean, human_size


def show_apps(apps):
    for app in apps:
        print(
            f"{clean(app.kind):10} {clean(app.name):32} {human_size(app.size_bytes):>12}  {clean(app.key)}"
        )


def choose(selector, candidates):
    print(f"Hay varias coincidencias para {clean(selector)}:")
    for number, app in enumerate(candidates, 1):
        print(f"  {number}. {clean(app.name)} [{clean(app.key)}]")
    answer = input("Números separados por coma; Enter cancela: ").strip()
    if not answer:
        return []
    try:
        indices = [int(value.strip()) - 1 for value in answer.split(",")]
        if any(index < 0 or index >= len(candidates) for index in indices):
            raise ValueError
        return [candidates[index] for index in dict.fromkeys(indices)]
    except ValueError as exc:
        raise Refusal("Selección inválida") from exc


def show_plan(plan, verbose=False):
    print("Plan de desinstalación (todavía sin cambios):")
    show_apps(plan.apps)
    for index, step in enumerate(plan.steps, 1):
        print(f"\n{index}. {step.kind.upper()} · {clean(shlex.join(step.argv))}")
        print(f"   Espacio: {human_size(step.estimated_bytes)} — {clean(step.estimate_label)}")
        print("   Afecta: " + clean(", ".join(step.affected)))
        for note in step.notes:
            print("   " + clean(note))
        if verbose and step.simulation:
            print("   Simulación APT:")
            for line in step.simulation.splitlines():
                print("     " + clean(line))
    if plan.leftovers:
        print("\nDatos/restos detectados (no se limpian automáticamente):")
        for item in plan.leftovers:
            print("  " + clean(item["path"]) + " — " + clean(item["note"]))
    for note in plan.notes:
        print("\n" + clean(note))


def parser():
    root = argparse.ArgumentParser(
        prog="desinstalar", description="Detecta el origen, explica y desinstala con confirmación."
    )
    root.add_argument("--version", action="version", version=__version__)
    sub = root.add_subparsers(dest="action", required=True)
    for action, help_text in (
        ("list", "Explorar apps instaladas"),
        ("plan", "Diagnóstico sin cambios"),
        ("remove", "Mostrar plan, confirmar y desinstalar"),
    ):
        command = sub.add_parser(action, help=help_text)
        command.add_argument("apps", nargs="*" if action == "list" else "+", metavar="APP")
        command.add_argument("--type", choices=KINDS, help="Limitar a un origen")
        command.add_argument(
            "--appimage-dir",
            action="append",
            default=[],
            metavar="DIR",
            help="Directorio adicional de AppImages dentro de HOME",
        )
        if action != "remove":
            command.add_argument("--json", action="store_true", help="Salida estructurada")
        if action != "list":
            command.add_argument(
                "--verbose", action="store_true", help="Incluye simulación APT completa"
            )
    return root


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        args = ["--help"]
    elif not args[0].startswith("-") and args[0] not in {"list", "plan", "remove"}:
        args.insert(0, "remove")
    options = parser().parse_args(args)
    try:
        if options.action == "remove" and os.geteuid() == 0:
            raise Refusal("No uses sudo desinstalar; el comando pide privilegios por gestor")
        kinds = (options.type,) if options.type else KINDS

        def rediscover():
            return discover(kinds, options.appimage_dir)

        inventory = rediscover()
        if options.action == "list":
            apps = inventory.apps
            if options.apps:
                queries = [value.casefold() for value in options.apps]
                apps = [
                    app
                    for app in apps
                    if any(value in (app.name + " " + app.key).casefold() for value in queries)
                ]
            if options.json:
                from dataclasses import asdict

                print(
                    json.dumps(
                        {
                            "apps": [asdict(app) for app in apps],
                            "errors": inventory.errors,
                            "notes": inventory.notes,
                        },
                        indent=2,
                        ensure_ascii=False,
                    )
                )
            else:
                show_apps(apps)
                for kind, error in inventory.errors.items():
                    print(clean(f"AVISO {kind}: {error}"), file=sys.stderr)
            return 1 if inventory.errors else 0
        interactive = sys.stdin.isatty() and sys.stdout.isatty()
        chooser = choose if interactive and not getattr(options, "json", False) else None
        apps = resolve(options.apps, inventory, chooser)
        plan = make_plan(apps, inventory)
        if options.action == "plan" and options.json:
            print(json.dumps(plan.to_dict(), indent=2, ensure_ascii=False))
        else:
            show_plan(plan, options.verbose)
        if options.action == "plan":
            return 0
        if not interactive:
            raise Refusal(
                "La eliminación requiere una terminal interactiva; usá plan --json para automatizar diagnósticos"
            )
        answer = input("\nEscribí DESINSTALAR para ejecutar este plan; Enter cancela: ").strip()
        if answer != "DESINSTALAR":
            print("Cancelado. Sin cambios.")
            return 0
        path, report, code = execute(plan, rediscover)
        print("\nResultado: " + report["status"])
        for item in report["verification"]:
            print("  " + clean(item["key"]) + ": " + item["status"])
        for item in report["disk_change"]:
            print(
                f"  Cambio de espacio libre en {clean(item['path'])}: {human_size(item['free_bytes_delta'])}"
            )
        print("  " + report["disk_note"])
        if report["leftovers"]:
            print("  Restos/datos detectados:")
            for item in report["leftovers"]:
                print("    " + clean(item["path"]))
        for key in report["remaining_related_apps"]:
            print("  Otra instalación con nombre coincidente: " + clean(key))
        for path_left in report["remaining_removal_paths"]:
            print("  Ruta prevista para quitar que todavía existe: " + clean(path_left))
        print("  Reporte local: " + clean(path))
        return code
    except (Refusal, OSError) as exc:
        for index, line in enumerate(str(exc).splitlines()):
            print(("Error: " if index == 0 else "  ") + clean(line), file=sys.stderr)
        return 2
    except (EOFError, KeyboardInterrupt):
        print("\nCancelado.", file=sys.stderr)
        return 130
