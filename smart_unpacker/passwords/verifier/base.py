from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol


VerifierStatus = Literal[
    "match",
    "no_match",
    "unknown_need_fallback",
    "damaged",
    "unsupported_method",
    "backend_unavailable",
]


@dataclass(frozen=True)
class PasswordBatchVerification:
    ok: bool
    status: VerifierStatus = "unknown_need_fallback"
    matched_index: int = -1
    attempts: int = 0
    test_result: object = None
    error_text: str = ""
    terminal: bool = False


class PasswordVerifier(Protocol):
    def verify_batch(
        self,
        archive_path: str,
        passwords: list[str],
        *,
        part_paths: list[str] | None = None,
    ) -> PasswordBatchVerification:
        ...
