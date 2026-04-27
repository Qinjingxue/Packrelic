from dataclasses import dataclass, field
from typing import Any, Literal


RepairStatus = Literal[
    "repaired",
    "partial",
    "unrepairable",
    "unsupported",
    "needs_password",
    "skipped",
    "error",
]


@dataclass(frozen=True)
class RepairResult:
    status: RepairStatus
    confidence: float = 0.0
    format: str = ""
    repaired_input: dict[str, Any] | None = None
    actions: list[str] = field(default_factory=list)
    damage_flags: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    workspace_paths: list[str] = field(default_factory=list)
    partial: bool = False
    module_name: str = ""
    diagnosis: dict[str, Any] = field(default_factory=dict)
    message: str = ""

    @property
    def ok(self) -> bool:
        return self.status in {"repaired", "partial"} and self.repaired_input is not None
