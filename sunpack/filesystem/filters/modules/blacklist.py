import re
from pathlib import Path
from typing import Any

from sunpack.filesystem.filters.base import ScanCandidate, ScanDecision, keep, prune, reject


class BlacklistScanFilter:
    name = "blacklist"
    stage = "path"

    def __init__(self, patterns=None, blocked_extensions=None, prune_dirs=None, path_globs=None, prune_dir_globs=None):
        self.patterns = [
            *[str(pattern) for pattern in (patterns or []) if isinstance(pattern, str)],
            *[_path_glob_to_regex(pattern) for pattern in (path_globs or []) if isinstance(pattern, str) and pattern.strip()],
        ]
        self.prune_dirs = [
            *[str(pattern) for pattern in (prune_dirs or []) if isinstance(pattern, str)],
            *[_dir_glob_to_regex(pattern) for pattern in (prune_dir_globs or []) if isinstance(pattern, str) and pattern.strip()],
        ]
        self.blocked_extensions = {
            ext if ext.startswith(".") else f".{ext}"
            for ext in (str(item).strip().lower() for item in (blocked_extensions or []))
            if ext
        }

    @classmethod
    def from_config(cls, config: dict[str, Any]):
        return cls(
            patterns=config.get("patterns") or [],
            blocked_extensions=config.get("blocked_extensions") or [],
            prune_dirs=config.get("prune_dirs") or [],
            path_globs=config.get("path_globs") or [],
            prune_dir_globs=config.get("prune_dir_globs") or [],
        )

    def evaluate(self, candidate: ScanCandidate) -> ScanDecision:
        path = candidate.path
        ext = path.suffix.lower()
        if candidate.kind == "file" and ext and ext in self.blocked_extensions:
            return reject(f"Blocked extension: {ext}")

        candidates = self._path_candidates(path)
        if candidate.kind == "dir":
            for pattern in self.prune_dirs:
                if self._matches(pattern, candidates):
                    return prune(f"Pruned directory: {pattern}")

        for pattern in self.patterns:
            if self._matches(pattern, candidates):
                if candidate.kind == "dir":
                    return prune(f"Hit blacklist: {pattern}")
                return reject(f"Hit blacklist: {pattern}")
        return keep()

    def _path_candidates(self, path: Path) -> list[str]:
        candidates = [
            path.name,
            str(path.parent),
            str(path),
        ]
        return [item.replace("\\", "/") for item in candidates if item]

    def _matches(self, pattern: str, candidates: list[str]) -> bool:
        return any(re.search(pattern, item, re.IGNORECASE) for item in candidates)


def _normalize_glob(value: str) -> str:
    return str(value).strip().replace("\\", "/").strip("/")


def _glob_body_to_regex(value: str) -> str:
    output = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "*":
            if index + 1 < len(value) and value[index + 1] == "*":
                output.append(".*")
                index += 2
                continue
            output.append("[^/]*")
        elif char == "?":
            output.append("[^/]")
        else:
            output.append(re.escape(char))
        index += 1
    return "".join(output)


def _path_glob_to_regex(value: str) -> str:
    glob = _normalize_glob(value)
    if not glob:
        return r"a\A"
    if glob.endswith("/**"):
        base = glob[:-3].rstrip("/")
        return rf"(^|/){_glob_body_to_regex(base)}($|/.*)"
    return rf"(^|/){_glob_body_to_regex(glob)}($|/)"


def _dir_glob_to_regex(value: str) -> str:
    glob = _normalize_glob(value).rstrip("/")
    if not glob:
        return r"a\A"
    return rf"^{_glob_body_to_regex(glob)}$"
