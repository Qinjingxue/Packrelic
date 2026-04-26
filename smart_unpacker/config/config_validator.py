from typing import Any

from smart_unpacker.config.schema import validate_external_config
from smart_unpacker.detection import validate_detection_contracts


def validate_config_payload(payload: dict) -> dict[str, Any]:
    detection_result = validate_detection_contracts(payload)
    errors = list(detection_result["errors"])
    errors.extend(validate_external_config(payload))
    return {
        "ok": not errors,
        "errors": errors,
        "warnings": detection_result["warnings"],
        "configured_rules": detection_result["configured_rules"],
        "available_rules": detection_result["available_rules"],
        "registered_facts": detection_result["registered_facts"],
    }
