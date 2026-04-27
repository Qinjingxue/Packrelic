from typing import Any


DEFAULT_ANALYSIS_CONFIG = {
    "enabled": True,
    "parallel": True,
    "max_workers": 3,
    "max_concurrent_reads": 1,
    "shared_cache_mb": 64,
    "max_read_mb_per_archive": 256,
    "prepass": {
        "enabled": True,
        "head_bytes": 1024 * 1024,
        "tail_bytes": 1024 * 1024,
    },
    "thresholds": {
        "extractable_confidence": 0.85,
        "repair_confidence": 0.35,
    },
    "modules": [
        {"name": "zip", "enabled": True},
        {"name": "rar", "enabled": True},
        {"name": "seven_zip", "enabled": True},
        {"name": "tar", "enabled": True},
        {"name": "gzip", "enabled": True},
        {"name": "bzip2", "enabled": True},
        {"name": "xz", "enabled": True},
        {"name": "zstd", "enabled": True},
        {"name": "tar_gz", "enabled": True},
        {"name": "tar_bz2", "enabled": True},
        {"name": "tar_xz", "enabled": True},
        {"name": "tar_zst", "enabled": True},
    ],
}


def analysis_config(config: dict[str, Any] | None) -> dict[str, Any]:
    payload = dict((config or {}).get("analysis") or {})
    return _merge(DEFAULT_ANALYSIS_CONFIG, payload)


def enabled_module_configs(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    modules = config.get("modules")
    if not isinstance(modules, list):
        return {}
    result = {}
    for item in modules:
        if not isinstance(item, dict) or not item.get("enabled", False):
            continue
        name = item.get("name")
        if isinstance(name, str) and name.strip():
            result[name.strip()] = {key: value for key, value in item.items() if key not in {"name", "enabled"}}
    return result


def _merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result
