import os
import struct
from typing import Any

from smart_unpacker.detection.pipeline.processors.context import FactProcessorContext
from smart_unpacker.detection.pipeline.processors.registry import register_processor


EOCD_SIGNATURE = b"PK\x05\x06"
CENTRAL_DIRECTORY_SIGNATURE = b"PK\x01\x02"
EOCD_MIN_SIZE = 22
EOCD_MAX_COMMENT = 65535


def _empty_result(error: str = "") -> dict[str, Any]:
    return {
        "plausible": False,
        "error": error,
        "eocd_offset": 0,
        "central_directory_offset": 0,
        "central_directory_size": 0,
        "archive_offset": 0,
        "total_entries": 0,
        "comment_length": 0,
        "central_directory_present": False,
    }


def _find_eocd(tail: bytes, file_size: int, read_size: int) -> tuple[int, bytes] | None:
    search_end = len(tail)
    while search_end >= 0:
        index = tail.rfind(EOCD_SIGNATURE, 0, search_end)
        if index < 0:
            return None
        if len(tail) - index >= EOCD_MIN_SIZE:
            eocd = tail[index:index + EOCD_MIN_SIZE]
            comment_length = struct.unpack("<H", eocd[-2:])[0]
            eocd_offset = file_size - read_size + index
            if file_size - eocd_offset - EOCD_MIN_SIZE == comment_length:
                return eocd_offset, eocd
        search_end = index
    return None


def inspect_zip_eocd_structure(path: str) -> dict[str, Any]:
    try:
        file_size = os.path.getsize(path)
        if file_size < EOCD_MIN_SIZE:
            return _empty_result("file_too_small")

        read_size = min(file_size, EOCD_MIN_SIZE + EOCD_MAX_COMMENT)
        with open(path, "rb") as handle:
            handle.seek(file_size - read_size)
            tail = handle.read(read_size)
    except OSError as exc:
        return _empty_result(f"os_error:{exc}")

    found_eocd = _find_eocd(tail, file_size, read_size)
    if found_eocd is None:
        return _empty_result("eocd_not_found")
    eocd_offset, eocd = found_eocd

    (
        _signature,
        disk_number,
        central_directory_disk,
        disk_entries,
        total_entries,
        central_directory_size,
        central_directory_offset,
        comment_length,
    ) = struct.unpack("<4sHHHHIIH", eocd)

    expected_comment_length = file_size - eocd_offset - EOCD_MIN_SIZE
    if comment_length != expected_comment_length:
        result = _empty_result("comment_length_mismatch")
        result["eocd_offset"] = eocd_offset
        result["comment_length"] = comment_length
        return result

    if disk_number or central_directory_disk or disk_entries != total_entries:
        result = _empty_result("multi_disk_or_entry_mismatch")
        result.update({
            "eocd_offset": eocd_offset,
            "central_directory_offset": central_directory_offset,
            "central_directory_size": central_directory_size,
            "total_entries": total_entries,
            "comment_length": comment_length,
        })
        return result

    physical_central_offset = eocd_offset - central_directory_size
    archive_offset = physical_central_offset - central_directory_offset
    result = {
        "plausible": False,
        "error": "",
        "eocd_offset": eocd_offset,
        "central_directory_offset": physical_central_offset,
        "central_directory_size": central_directory_size,
        "archive_offset": archive_offset,
        "total_entries": total_entries,
        "comment_length": comment_length,
        "central_directory_present": False,
    }

    if physical_central_offset < 0 or archive_offset < 0:
        result["error"] = "central_directory_out_of_range"
        return result
    if physical_central_offset + central_directory_size != eocd_offset:
        result["error"] = "central_directory_size_mismatch"
        return result
    if total_entries == 0 and central_directory_size == 0:
        result["plausible"] = True
        return result
    if central_directory_size < 4:
        result["error"] = "central_directory_too_small"
        return result

    try:
        with open(path, "rb") as handle:
            handle.seek(physical_central_offset)
            signature = handle.read(4)
    except OSError as exc:
        result["error"] = f"os_error:{exc}"
        return result

    if signature != CENTRAL_DIRECTORY_SIGNATURE:
        result["error"] = "bad_central_directory_signature"
        return result

    result["plausible"] = True
    result["central_directory_present"] = True
    return result


@register_processor(
    "zip_eocd_structure",
    input_facts={"file.path"},
    output_facts={"zip.eocd_structure"},
    schemas={
        "zip.eocd_structure": {
            "type": "dict",
            "description": "ZIP EOCD and central directory structure check derived from the candidate file.",
        },
    },
)
def process_zip_eocd_structure(context: FactProcessorContext) -> dict[str, Any]:
    return inspect_zip_eocd_structure(context.fact_bag.get("file.path") or "")
