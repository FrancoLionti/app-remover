"""Serializable inventory and plan records. Commands are argument arrays, never shell strings."""

from dataclasses import asdict, dataclass, field


class Refusal(Exception):
    """A request cannot be carried out safely or unambiguously."""


@dataclass
class App:
    key: str
    kind: str
    identifier: str
    name: str
    version: str = ""
    scope: str = ""
    size_bytes: int | None = None
    size_label: str = "desconocido"
    protected: bool = False
    paths: list[str] = field(default_factory=list)
    fingerprint: str = ""


@dataclass
class Inventory:
    apps: list[App] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


@dataclass
class Step:
    kind: str
    keys: list[str]
    argv: list[str]
    affected: list[str] = field(default_factory=list)
    estimated_bytes: int | None = None
    estimate_label: str = "desconocido"
    notes: list[str] = field(default_factory=list)
    simulation: str = ""


@dataclass
class Plan:
    apps: list[App]
    steps: list[Step]
    leftovers: list[dict]
    notes: list[str]

    def to_dict(self):
        return asdict(self)

    def signature(self):
        # Also detects version, path/inode, residual data and APT transaction changes.
        return self.to_dict()
