import os
import zlib
from typing import Any

from smart_unpacker.detection.pipeline.processors.context import FactProcessorContext
from smart_unpacker.detection.pipeline.processors.registry import register_processor

try:
    from smart_unpacker_native import inspect_rar_structure as _native_inspect_rar_structure
except ImportError:  # pragma: no cover - exercised when native extension is absent
    _native_inspect_rar_structure = None


RAR4_SIGNATURE = b"Rar!\x1a\x07\x00"
RAR5_SIGNATURE = b"Rar!\x1a\x07\x01\x00"
RAR4_KNOWN_BLOCK_TYPES = {0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B}
RAR4_MAIN_HEADER_TYPE = 0x73
RAR4_LONG_BLOCK_FLAG = 0x8000
RAR5_MAIN_HEADER_TYPE = 1
RAR5_KNOWN_HEADER_TYPES = {1, 2, 3, 4, 5}
DEFAULT_MAX_FIRST_HEADER_CHECK_BYTES = 1024 * 1024


def _empty_result(error: str = "") -> dict[str, Any]:
    return {
        "plausible": False,
        "error": error,
        "magic_matched": False,
        "format": "",
        "detected_ext": "",
        "version": 0,
        "first_header_offset": 0,
        "first_header_size": 0,
        "first_header_type": 0,
        "header_crc_checked": False,
        "header_crc_ok": False,
        "second_block_checked": False,
        "second_block_ok": False,
        "second_block_type": 0,
        "second_block_size": 0,
        "block_walk_ok": False,
        "strong_accept": False,
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


def _inspect_rar4_block(data: bytes, offset: int, file_size: int) -> dict[str, Any]:
    result = {"ok": False, "type": 0, "size": 0, "error": ""}
    if offset >= file_size:
        return result
    if len(data) < offset + 7 or file_size < offset + 7:
        result["error"] = "rar4_second_block_too_small"
        return result
    header = data[offset:offset + 7]
    header_crc = int.from_bytes(header[0:2], "little")
    header_type = header[2]
    header_flags = int.from_bytes(header[3:5], "little")
    header_size = int.from_bytes(header[5:7], "little")
    result.update({"type": header_type, "size": header_size})
    if header_type not in RAR4_KNOWN_BLOCK_TYPES:
        result["error"] = "rar4_second_block_unknown_type"
        return result
    if header_size < 7 or offset + header_size > file_size or len(data) < offset + header_size:
        result["error"] = "rar4_second_block_size_out_of_range"
        return result
    full_header = data[offset:offset + header_size]
    if (zlib.crc32(full_header[2:]) & 0xFFFF) != header_crc:
        result["error"] = "rar4_second_block_crc_mismatch"
        return result
    block_size = header_size
    if header_flags & RAR4_LONG_BLOCK_FLAG:
        if header_size < 11:
            result["error"] = "rar4_second_block_add_size_missing"
            return result
        add_size = int.from_bytes(full_header[7:11], "little")
        block_size += add_size
        if offset + block_size > file_size:
            result["error"] = "rar4_second_block_payload_out_of_range"
            return result
    result.update({"ok": True, "size": block_size})
    return result


def _inspect_rar5_block(data: bytes, offset: int, file_size: int) -> dict[str, Any]:
    result = {"ok": False, "type": 0, "size": 0, "error": ""}
    if offset >= file_size:
        return result
    if len(data) < offset + 6 or file_size < offset + 6:
        result["error"] = "rar5_second_header_too_small"
        return result
    parsed_size = _read_vint(data, offset + 4)
    if parsed_size is None:
        result["error"] = "rar5_second_header_size_vint_missing"
        return result
    header_size, after_size = parsed_size
    parsed_type = _read_vint(data, after_size)
    if parsed_type is None:
        result["error"] = "rar5_second_header_type_vint_missing"
        return result
    header_type, _after_type = parsed_type
    result.update({"type": header_type, "size": header_size})
    if header_type not in RAR5_KNOWN_HEADER_TYPES:
        result["error"] = "rar5_second_header_unknown_type"
        return result
    if header_size <= 0 or offset + 4 + header_size > file_size or len(data) < offset + 4 + header_size:
        result["error"] = "rar5_second_header_size_out_of_range"
        return result
    stored_crc = int.from_bytes(data[offset:offset + 4], "little")
    header_data = data[offset + 4:offset + 4 + header_size]
    if (zlib.crc32(header_data) & 0xFFFFFFFF) != stored_crc:
        result["error"] = "rar5_second_header_crc_mismatch"
        return result
    result.update({"ok": True, "size": 4 + header_size})
    return result


def _inspect_rar4(data: bytes, file_size: int) -> dict[str, Any]:
    first_header_offset = len(RAR4_SIGNATURE)
    if file_size < first_header_offset + 7 or len(data) < first_header_offset + 7:
        return _empty_result("rar4_first_header_too_small")
    header = data[first_header_offset:first_header_offset + 7]
    header_crc = int.from_bytes(header[0:2], "little")
    header_type = header[2]
    header_size = int.from_bytes(header[5:7], "little")
    result = {
        "plausible": False,
        "error": "",
        "magic_matched": True,
        "format": "rar",
        "detected_ext": ".rar",
        "version": 4,
        "first_header_offset": first_header_offset,
        "first_header_size": header_size,
        "first_header_type": header_type,
        "header_crc_checked": False,
        "header_crc_ok": False,
        "second_block_checked": False,
        "second_block_ok": False,
        "second_block_type": 0,
        "second_block_size": 0,
        "block_walk_ok": False,
        "strong_accept": False,
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
    if len(data) >= first_header_offset + header_size:
        full_header = data[first_header_offset:first_header_offset + header_size]
        result["header_crc_checked"] = True
        result["header_crc_ok"] = (zlib.crc32(full_header[2:]) & 0xFFFF) == header_crc
        if result["header_crc_ok"]:
            result["evidence"].append("rar4:header_crc")
        elif header_type == RAR4_MAIN_HEADER_TYPE:
            result["error"] = "rar4_header_crc_mismatch"
    second_offset = first_header_offset + header_size
    if header_type == RAR4_MAIN_HEADER_TYPE and result["header_crc_ok"] and second_offset < file_size:
        second = _inspect_rar4_block(data, second_offset, file_size)
        result["second_block_checked"] = True
        result["second_block_ok"] = second["ok"]
        result["second_block_type"] = second["type"]
        result["second_block_size"] = second["size"]
        result["block_walk_ok"] = second["ok"]
        if second["ok"]:
            result["evidence"].append("rar4:second_block")
        else:
            result["error"] = second["error"]
    if header_type == RAR4_MAIN_HEADER_TYPE and result["header_crc_ok"] and (second_offset >= file_size or result["block_walk_ok"]):
        result["strong_accept"] = True
    return result


def _inspect_rar5(data: bytes, file_size: int) -> dict[str, Any]:
    first_header_offset = len(RAR5_SIGNATURE)
    if file_size < first_header_offset + 6 or len(data) < first_header_offset + 6:
        return _empty_result("rar5_first_header_too_small")
    parsed_size = _read_vint(data, first_header_offset + 4)
    result = {
        "plausible": False,
        "error": "",
        "magic_matched": True,
        "format": "rar",
        "detected_ext": ".rar",
        "version": 5,
        "first_header_offset": first_header_offset,
        "first_header_size": 0,
        "first_header_type": 0,
        "header_crc_checked": False,
        "header_crc_ok": False,
        "second_block_checked": False,
        "second_block_ok": False,
        "second_block_type": 0,
        "second_block_size": 0,
        "block_walk_ok": False,
        "strong_accept": False,
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
    if len(data) >= first_header_offset + 4 + header_size:
        stored_crc = int.from_bytes(data[first_header_offset:first_header_offset + 4], "little")
        header_data = data[first_header_offset + 4:first_header_offset + 4 + header_size]
        result["header_crc_checked"] = True
        result["header_crc_ok"] = (zlib.crc32(header_data) & 0xFFFFFFFF) == stored_crc
        if result["header_crc_ok"]:
            result["evidence"].append("rar5:header_crc")
        elif header_type == RAR5_MAIN_HEADER_TYPE:
            result["error"] = "rar5_header_crc_mismatch"
    second_offset = first_header_offset + 4 + header_size
    if header_type == RAR5_MAIN_HEADER_TYPE and result["header_crc_ok"] and second_offset < file_size:
        second = _inspect_rar5_block(data, second_offset, file_size)
        result["second_block_checked"] = True
        result["second_block_ok"] = second["ok"]
        result["second_block_type"] = second["type"]
        result["second_block_size"] = second["size"]
        result["block_walk_ok"] = second["ok"]
        if second["ok"]:
            result["evidence"].append("rar5:second_header")
        else:
            result["error"] = second["error"]
    if header_type == RAR5_MAIN_HEADER_TYPE and result["header_crc_ok"] and (second_offset >= file_size or result["block_walk_ok"]):
        result["strong_accept"] = True
    return result


def inspect_rar_structure(
    path: str,
    magic_bytes: bytes | None = None,
    max_first_header_check_bytes: int = DEFAULT_MAX_FIRST_HEADER_CHECK_BYTES,
) -> dict[str, Any]:
    if _native_inspect_rar_structure is not None:
        try:
            return dict(_native_inspect_rar_structure(path, magic_bytes or b"", max_first_header_check_bytes))
        except Exception:
            pass

    try:
        file_size = os.path.getsize(path)
        with open(path, "rb") as handle:
            data = magic_bytes or b""
            if len(data) < 64:
                handle.seek(0)
                data = handle.read(64)
            if data.startswith(RAR4_SIGNATURE) and len(data) >= len(RAR4_SIGNATURE) + 7:
                header_size = int.from_bytes(data[len(RAR4_SIGNATURE) + 5:len(RAR4_SIGNATURE) + 7], "little")
                read_size = min(file_size, len(RAR4_SIGNATURE) + header_size + 64, max_first_header_check_bytes)
                if len(data) < read_size:
                    handle.seek(0)
                    data = handle.read(read_size)
            elif data.startswith(RAR5_SIGNATURE):
                parsed_size = _read_vint(data, len(RAR5_SIGNATURE) + 4)
                if parsed_size is not None:
                    header_size, _after_size = parsed_size
                    read_size = min(file_size, len(RAR5_SIGNATURE) + 4 + header_size + 64, max_first_header_check_bytes)
                    if len(data) < read_size:
                        handle.seek(0)
                        data = handle.read(read_size)
    except OSError as exc:
        return _empty_result(f"os_error:{exc}")

    if data.startswith(RAR5_SIGNATURE):
        return _inspect_rar5(data, file_size)
    if data.startswith(RAR4_SIGNATURE):
        return _inspect_rar4(data, file_size)
    if data.startswith(b"Rar!"):
        result = _empty_result("rar_signature_incomplete_or_unknown")
        result.update({
            "magic_matched": True,
            "format": "rar",
            "detected_ext": ".rar",
            "evidence": ["rar:signature"],
        })
        return result
    return _empty_result("rar_signature_not_found")


@register_processor(
    "rar_structure",
    input_facts={"file.path", "file.magic_bytes"},
    output_facts={"rar.structure"},
    schemas={
        "rar.structure": {
            "type": "dict",
            "description": "RAR4/RAR5 signature, main-header CRC, and optional second block/header walk checks.",
        },
    },
)
def process_rar_structure(context: FactProcessorContext) -> dict[str, Any]:
    facts = context.fact_bag
    return inspect_rar_structure(
        facts.get("file.path") or "",
        facts.get("file.magic_bytes") or b"",
        int(context.fact_config.get("max_first_header_check_bytes", DEFAULT_MAX_FIRST_HEADER_CHECK_BYTES)),
    )
