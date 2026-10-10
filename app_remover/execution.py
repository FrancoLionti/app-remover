"""Revalidate approved plans, execute native tools and leave a private audit report."""

import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .model import Refusal
from .planning import make_plan, leftover_candidates, related_apps
from .runtime import capture, xdg_dir


def disk_snapshot():
    result = {}
    for path in (Path("/"), Path.home(), Path("/var/lib/flatpak"), Path("/var/lib/snapd")):
        try:
            device = str(path.stat().st_dev)
            result.setdefault(
                device, {"path": str(path), "free_bytes": shutil.disk_usage(path).free}
            )
        except OSError:
            continue
    return result


def disk_deltas(before, after):
    return [
        {"path": value["path"], "free_bytes_delta": after[key]["free_bytes"] - value["free_bytes"]}
        for key, value in before.items()
        if key in after
    ]


def report_file():
    directory = xdg_dir("XDG_STATE_HOME", Path.home() / ".local/state") / "app-remover/reports"
    if directory.resolve() != directory:
        raise Refusal("Directorio de reportes enlazado")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.resolve() != directory or directory.stat().st_uid != os.getuid():
        raise Refusal("Directorio de reportes enlazado o con propietario distinto")
    fd, name = tempfile.mkstemp(prefix="removal-", suffix=".json", dir=directory)
    os.close(fd)
    return Path(name)


def write_report(path, report):
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")


def execute(plan, rediscover, run=None):
    if os.geteuid() == 0:
        raise Refusal("Ejecutá como usuario normal; solo los gestores que lo necesitan usan sudo")
    fresh = rediscover()
    by_key = {app.key: app for app in fresh.apps}
    if any(app.key not in by_key or app.kind in fresh.errors for app in plan.apps):
        raise Refusal("El inventario cambió o no se puede verificar; generá un nuevo plan")
    new_plan = make_plan([by_key[app.key] for app in plan.apps], fresh)
    if new_plan.signature() != plan.signature():
        raise Refusal("Cambió el plan desde la confirmación; revisá un nuevo plan")
    path = report_file()  # Audit storage must succeed before the first mutation.
    before = disk_snapshot()
    report = {
        "schema_version": 1,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "status": "running",
        "plan": plan.to_dict(),
        "steps": [],
        "disk_before": before,
    }
    write_report(path, report)
    failed = False
    interrupted = False
    unexpected = None
    try:
        for step in plan.steps:
            item = {"kind": step.kind, "argv": step.argv, "status": "running"}
            report["steps"].append(item)
            write_report(path, report)
            try:
                result = (run or subprocess.run)(step.argv, check=False)
                item.update(
                    status="succeeded" if result.returncode == 0 else "failed",
                    returncode=result.returncode,
                )
            except OSError as exc:
                item.update(status="failed", error=str(exc))
            if item["status"] != "succeeded":
                failed = True
                break  # No cross-manager transaction or automatic rollback is claimed.
            write_report(path, report)
    except KeyboardInterrupt:
        interrupted = True
        failed = True
        report["steps"][-1]["status"] = "interrupted"
    except Exception as exc:
        failed = True
        unexpected = str(exc)
    after_inventory = rediscover()
    installed = {app.key for app in after_inventory.apps}
    verification = []
    affected = {app.key: app.kind for app in plan.apps}
    for step in plan.steps:
        if step.kind == "apt":
            for name in step.affected:
                matches = [
                    app
                    for app in fresh.apps
                    if app.kind == "apt"
                    and (app.identifier == name or app.identifier.split(":")[0] == name)
                ]
                for app in matches:
                    affected[app.key] = "apt"
    for key, kind in affected.items():
        status = (
            "unknown"
            if kind in after_inventory.errors
            else ("still_installed" if key in installed else "removed")
        )
        verification.append({"key": key, "status": status})
        if status != "removed":
            failed = True
    report.update(
        finished_at=datetime.now(timezone.utc).isoformat(),
        status="interrupted" if interrupted else ("incomplete" if failed else "complete"),
        verification=verification,
        inventory_errors=after_inventory.errors,
        leftovers=leftover_candidates(plan.apps),
        disk_change=disk_deltas(before, disk_snapshot()),
        disk_note="Cambio neto observado por filesystem; incluye actividad concurrente y snapshots.",
        cleanup_suggestions=[
            "apt-get -s autoremove",
            "flatpak uninstall --unused (pide confirmación)",
        ],
        remaining_related_apps=[app.key for app in related_apps(plan.apps, after_inventory)],
        remaining_removal_paths=[
            p for app in plan.apps for p in app.paths if Path(p).exists() or Path(p).is_symlink()
        ],
    )
    if unexpected:
        report["error"] = unexpected
    if any(step.kind == "snap" for step in plan.steps):
        try:
            report["snapshots_after"] = capture(["snap", "saved"], timeout=8)
        except Refusal as exc:
            report["snapshots_after_error"] = str(exc)
    write_report(path, report)
    return path, report, 130 if interrupted else (1 if failed else 0)
