import os
from typing import Any

from smart_unpacker.detection.pipeline.processors.context import FactProcessorContext
from smart_unpacker.detection.pipeline.processors.registry import register_processor


RAR4_SIGNATURE = b"Rar!\x1a\x07\x00"
RAR5_SIGNATURE = b"Rar!\x1a\x07\x01\x00"
RAR4_KNOWN_BLOCK_TYPES = {0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B}


def _empty_result(error: str = "") -> dict[str, Any]:
    return {
        "plausible": False,
        "error": error,
        "format": "",
        "detected_ext": "",
        "version": 0,
        "first_header_offset": 0,
        "first_header_size": 0,
        "first_header_type": 0,
        "confidence": "none",
        "evidence": [],
    }


def _read_vint(data: bytes, offset: int) -> tuple[int, int] | None:
    value = 0
    shift = 0
    for index in range(offset, min(len(data), offset + 10)):
        byte = data[index]
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, index + 1
        shift += 7
    return None


def _inspect_rar4(data: bytes, file_size: int) -> dict[str, Any]:
    first_header_offset = len(RAR4_SIGNATURE)
    if file_size < first_header_offset + 7 or len(data) < first_header_offset + 7:
        return _empty_result("rar4_first_header_too_small")
    header = data[first_header_offset:first_header_offset + 7]
    header_type = header[2]
    header_size = int.from_bytes(header[5:7], "little")
    result = {
        "plausible": False,
        "error": "",
        "format": "rar",
        "detected_ext": ".rar",
        "version": 4,
        "first_header_offset": first_header_offset,
        "first_header_size": header_size,
        "first_header_type": header_type,
        "confidence": "none",
        "evidence": ["rar4:signature"],
    }
    if header_type not in RAR4_KNOWN_BLOCK_TYPES:
        result["error"] = "rar4_unknown_first_header_type"
        return result
    if header_size < 7 or first_header_offset + header_size > file_size:
        result["error"] = "rar4_first_header_size_out_of_range"
        return result
    result["plausible"] = True
    result["confidence"] = "strong"
    result["evidence"].append("rar4:first_header")
    return result


def _inspect_rar5(data: bytes, file_size: int) -> dict[str, Any]:
    first_header_offset = len(RAR5_SIGNATURE)
    if file_size < first_header_offset + 6 or len(data) < first_header_offset + 6:
        return _empty_result("rar5_first_header_too_small")
    parsed_size = _read_vint(data, first_header_offset + 4)
    result = {
        "plausible": False,
        "error": "",
        "format": "rar",
        "detected_ext": ".rar",
        "version": 5,
        "first_header_offset": first_header_offset,
        "first_header_size": 0,
        "first_header_type": 0,
        "confidence": "none",
        "evidence": ["rar5:signature"],
    }
    if parsed_size is None:
        result["error"] = "rar5_header_size_vint_missing"
        return result
    header_size, after_size = parsed_size
    parsed_type = _read_vint(data, after_size)
    if parsed_type is None:
        result["error"] = "rar5_header_type_vint_missing"
        return result
    header_type, _after_type = parsed_type
    result["first_header_size"] = header_size
    result["first_header_type"] = header_type
    if header_size <= 0 or first_header_offset + 4 + header_size > file_size:
        result["error"] = "rar5_first_header_size_out_of_range"
        return result
    result["plausible"] = True
    result["confidence"] = "strong"
    result["evidence"].append("rar5:first_header")
    return result


def inspect_rar_structure(path: str, magic_bytes: bytes | None = None) -> dict[str, Any]:
    try:
        file_size = os.path.getsize(path)
        with open(path, "rb") as handle:
            data = magic_bytes or b""
            if len(data) < 64:
                handle.seek(0)
                data = handle.read(64)
    except OSError as exc:
        return _empty_result(f"os_error:{exc}")

    if data.startswith(RAR5_SIGNATURE):
        return _inspect_rar5(data, file_size)
    if data.startswith(RAR4_SIGNATURE):
        return _inspect_rar4(data, file_size)
    return _empty_result("rar_signature_not_found")


@register_processor(
    "rar_structure",
    input_facts={"file.path", "file.magic_bytes"},
    output_facts={"rar.structure"},
    schemas={
        "rar.structure": {
            "type": "dict",
            "description": "Lightweight RAR4/RAR5 signature and first-header structure check.",
        },
    },
)
def process_rar_structure(context: FactProcessorContext) -> dict[str, Any]:
    facts = context.fact_bag
    return inspect_rar_structure(
        facts.get("file.path") or "",
        facts.get("file.magic_bytes") or b"",
    )
