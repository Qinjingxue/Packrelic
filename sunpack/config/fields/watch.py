from typing import Any

from sunpack.config.schema import ConfigField


DEFAULT_WATCH_ARCHIVE_SUFFIXES = [
    ".zip", ".rar", ".7z", ".gz", ".bz2", ".xz", ".zst", ".tar",
    ".tgz", ".tbz", ".tbz2", ".txz", ".tzst", ".001", ".exe",
]

DEFAULT_WATCH_CONFIG = {
    "interval_seconds": 5.0,
    "stable_seconds": 10.0,
    "recursive": True,
    "initial_scan": True,
    "max_folders": 16,
    "observer_stop_timeout_seconds": 5.0,
    "archive_suffixes": DEFAULT_WATCH_ARCHIVE_SUFFIXES,
}


def normalize_watch_config(value: Any) -> dict[str, Any]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError("watch must be an object")
    config = dict(DEFAULT_WATCH_CONFIG)
    config.update(value)
    config["interval_seconds"] = max(0.1, _float_field(config, "interval_seconds"))
    config["stable_seconds"] = max(0.0, _float_field(config, "stable_seconds"))
    config["recursive"] = bool(config.get("recursive", True))
    config["initial_scan"] = bool(config.get("initial_scan", True))
    config["max_folders"] = max(1, _int_field(config, "max_folders"))
    config["observer_stop_timeout_seconds"] = max(0.0, _float_field(config, "observer_stop_timeout_seconds"))
    config["archive_suffixes"] = _normalize_suffixes(config.get("archive_suffixes"))
    return config


def _float_field(config: dict[str, Any], name: str) -> float:
    try:
        return float(config.get(name))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"watch.{name} must be a number") from exc


def _int_field(config: dict[str, Any], name: str) -> int:
    try:
        return int(config.get(name))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"watch.{name} must be an integer") from exc


def _normalize_suffixes(value: Any) -> list[str]:
    if not isinstance(value, list):
        raise ValueError("watch.archive_suffixes must be a list")
    suffixes = []
    for item in value:
        suffix = str(item or "").strip().lower()
        if not suffix:
            continue
        if not suffix.startswith("."):
            suffix = f".{suffix}"
        suffixes.append(suffix)
    return list(dict.fromkeys(suffixes))


CONFIG_FIELDS = (
    ConfigField(
        path=("watch",),
        default=DEFAULT_WATCH_CONFIG,
        normalize=normalize_watch_config,
        owner=__name__,
    ),
)
