"""Bounded read-only subprocesses and plain-text rendering helpers."""

import os
import re
import subprocess
from pathlib import Path

from .model import Refusal


def capture(argv, timeout=15):
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refusal(f"{argv[0]}: {exc}") from exc
    if result.returncode:
        raise Refusal(f"{argv[0]}: {(result.stderr or result.stdout).strip()[:1500]}")
    return result.stdout


def clean(value):
    # Terminal escape sequences in app metadata must not control the terminal.
    return "".join(c if c.isprintable() else " " for c in str(value))


def human_size(size):
    if size is None:
        return "desconocido"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(size) < 1024 or unit == "TiB":
            return f"{size:.1f} {unit}"
        size /= 1024


def parse_size(value):
    match = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?i?B)\s*", value)
    if not match:
        return None
    unit = match[2]
    power = {"B": 0, "KB": 1, "MB": 2, "GB": 3, "TB": 4, "KiB": 1, "MiB": 2, "GiB": 3, "TiB": 4}[
        unit
    ]
    return int(float(match[1]) * (1024 if "i" in unit else 1000) ** power)


def xdg_dir(variable, fallback):
    value = Path(os.environ.get(variable, str(fallback)))
    if not value.is_absolute():
        raise Refusal(f"{variable} debe ser una ruta absoluta")
    return value


def file_fingerprint(path):
    stat = path.lstat()
    return f"{stat.st_dev}:{stat.st_ino}:{stat.st_size}:{stat.st_mtime_ns}:{stat.st_mode}"
