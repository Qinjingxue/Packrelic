from __future__ import annotations

import os
from dataclasses import dataclass

from sunpack_native import scan_watch_candidates as _native_scan_watch_candidates
from sunpack_native import watch_candidate_for_path as _native_watch_candidate_for_path

from sunpack.config.fields.watch import DEFAULT_WATCH_ARCHIVE_SUFFIXES

WATCH_ARCHIVE_SUFFIXES = set(DEFAULT_WATCH_ARCHIVE_SUFFIXES)


@dataclass(frozen=True)
class WatchCandidate:
    path: str
    size: int
    mtime: float


def scan_watch_candidates(roots: list[str], *, recursive: bool = True, archive_suffixes: list[str] | None = None) -> list[WatchCandidate]:
    suffixes = _normalize_suffixes(archive_suffixes)
    return [
        candidate for candidate in (_candidate_from_native(item) for item in _native_scan_watch_candidates(list(roots or []), bool(recursive)))
        if looks_like_archive(candidate.path, archive_suffixes=suffixes)
    ]


def _candidate_for(path: str) -> WatchCandidate | None:
    item = _native_watch_candidate_for_path(str(path))
    if item is None:
        return None
    return _candidate_from_native(item)


def _looks_like_archive(name: str, *, archive_suffixes: list[str] | None = None) -> bool:
    suffixes = _normalize_suffixes(archive_suffixes)
    if any(name.endswith(suffix) for suffix in suffixes):
        return True
    return False


def looks_like_archive(path: str, *, archive_suffixes: list[str] | None = None) -> bool:
    return _looks_like_archive(os.path.basename(path).lower(), archive_suffixes=archive_suffixes)


def _candidate_from_native(item: dict) -> WatchCandidate:
    return WatchCandidate(
        path=str(item.get("path") or ""),
        size=int(item.get("size", 0) or 0),
        mtime=float(item.get("mtime", 0.0) or 0.0),
    )


def _normalize_suffixes(value: list[str] | None) -> list[str]:
    if value is None:
        return sorted(WATCH_ARCHIVE_SUFFIXES)
    suffixes = []
    for item in value:
        suffix = str(item or "").strip().lower()
        if not suffix:
            continue
        if not suffix.startswith("."):
            suffix = f".{suffix}"
        suffixes.append(suffix)
    return list(dict.fromkeys(suffixes))
