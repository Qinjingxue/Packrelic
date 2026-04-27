from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class RepairJob:
    source_input: dict[str, Any]
    format: str = ""
    confidence: float = 0.0
    analysis_evidence: Any = None
    extraction_failure: dict[str, Any] | None = None
    damage_flags: list[str] = field(default_factory=list)
    password: str | None = None
    archive_key: str = ""
    workspace: str = ""
    attempts: int = 0

    @property
    def has_extraction_failure(self) -> bool:
        return bool(self.extraction_failure)
