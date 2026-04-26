import os
from typing import Any

from smart_unpacker.detection.pipeline.processors.context import FactProcessorContext
from smart_unpacker.detection.pipeline.processors.registry import register_processor


TAR_BLOCK_SIZE = 512


def _empty_result(error: str = "") -> dict[str, Any]:
    return {
        "plausible": False,
        "error": error,
        "format": "",
        "stored_checksum": 0,
        "computed_checksum": 0,
        "file_size": 0,
        "member_size": 0,
        "ustar_magic": False,
        "zero_block": False,
    }


def _parse_octal_field(field: bytes) -> int | None:
    text = field.rstrip(b"\x00 ").strip()
    if not text:
        return 0
    try:
        return int(text.decode("ascii"), 8)
    except (UnicodeDecodeError, ValueError):
        return None


def _checksum(header: bytes) -> int:
    return sum(header[:148]) + (32 * 8) + sum(header[156:])


def inspect_tar_header_structure(path: str) -> dict[str, Any]:
    try:
        file_size = os.path.getsize(path)
        if file_size < TAR_BLOCK_SIZE:
            return _empty_result("file_too_small")
        with open(path, "rb") as handle:
            header = handle.read(TAR_BLOCK_SIZE)
    except OSError as exc:
        return _empty_result(f"os_error:{exc}")

    result = _empty_result()
    result["file_size"] = file_size
    if len(header) < TAR_BLOCK_SIZE:
        result["error"] = "short_header"
        return result
    if header == b"\x00" * TAR_BLOCK_SIZE:
        result["error"] = "leading_zero_block"
        result["zero_block"] = True
        return result

    stored_checksum = _parse_octal_field(header[148:156])
    member_size = _parse_octal_field(header[124:136])
    computed_checksum = _checksum(header)
    result.update({
        "stored_checksum": stored_checksum or 0,
        "computed_checksum": computed_checksum,
        "member_size": member_size or 0,
        "ustar_magic": header[257:263] in {b"ustar\x00", b"ustar "},
    })

    if stored_checksum is None:
        result["error"] = "invalid_checksum_field"
        return result
    if member_size is None:
        result["error"] = "invalid_size_field"
        return result
    if stored_checksum != computed_checksum:
        result["error"] = "checksum_mismatch"
        return result

    result["plausible"] = True
    result["format"] = "ustar" if result["ustar_magic"] else "tar"
    return result


@register_processor(
    "tar_header_structure",
    input_facts={"file.path"},
    output_facts={"tar.header_structure"},
    schemas={
        "tar.header_structure": {
            "type": "dict",
            "description": "TAR header checksum and ustar marker structure check derived from the candidate file.",
        },
    },
)
def process_tar_header_structure(context: FactProcessorContext) -> dict[str, Any]:
    return inspect_tar_header_structure(context.fact_bag.get("file.path") or "")
