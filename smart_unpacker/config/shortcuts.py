from typing import Any


ARCHIVE_CLEANUP_ALIASES = {
    "d": "delete",
    "r": "recycle",
    "k": "keep",
}

DIRECTORY_SCAN_ALIASES = {
    "*": "recursive",
    "-": "current_dir_only",
}

def normalize_archive_cleanup_mode(value: Any, default: str = "r") -> str:
    raw = default if value is None else str(value).strip().lower()
    mode = ARCHIVE_CLEANUP_ALIASES.get(raw)
    if mode is None:
        raise ValueError("archive_cleanup_mode must be one of: d, r, k")
    return mode


def normalize_directory_scan_mode(value: Any, default: str = "*") -> str:
    raw = default if value is None else str(value).strip().lower()
    mode = DIRECTORY_SCAN_ALIASES.get(raw)
    if mode is None:
        raise ValueError("filesystem.directory_scan_mode must be one of: *, -")
    return mode


def normalize_recursive_extract(value: Any, default: Any = 1) -> dict[str, Any]:
    if value is None:
        value = default

    raw = str(value).strip().lower()
    if raw == "*":
        return {"mode": "infinite", "max_rounds": 999}
    if raw == "?":
        return {"mode": "prompt", "max_rounds": 999}
    try:
        rounds = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError('recursive_extract must be "*", "?", or a positive integer') from exc
    if rounds <= 0:
        raise ValueError('recursive_extract must be "*", "?", or a positive integer')
    return {"mode": "fixed", "max_rounds": rounds}
