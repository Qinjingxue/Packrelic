from typing import Any

from smart_unpacker.config.detection_view import filesystem_config
from smart_unpacker.config.shortcuts import (
    normalize_archive_cleanup_mode,
    normalize_directory_scan_mode,
    normalize_recursive_extract,
)
from smart_unpacker.detection import validate_detection_contracts


def validate_config_payload(payload: dict) -> dict[str, Any]:
    detection_result = validate_detection_contracts(payload)
    errors = list(detection_result["errors"])
    errors.extend(_validate_shortcut_fields(payload))
    return {
        "ok": not errors,
        "errors": errors,
        "warnings": detection_result["warnings"],
        "configured_rules": detection_result["configured_rules"],
        "available_rules": detection_result["available_rules"],
        "registered_facts": detection_result["registered_facts"],
    }


def _validate_shortcut_fields(payload: dict) -> list[str]:
    errors = []
    try:
        normalize_recursive_extract(payload.get("recursive_extract"))
    except ValueError as exc:
        errors.append(str(exc))

    post_extract = payload.get("post_extract") if isinstance(payload.get("post_extract"), dict) else {}
    try:
        normalize_archive_cleanup_mode(post_extract.get("archive_cleanup_mode"))
    except ValueError as exc:
        errors.append(str(exc))

    try:
        normalize_directory_scan_mode(filesystem_config(payload).get("directory_scan_mode"))
    except ValueError as exc:
        errors.append(str(exc))
    return errors
