from __future__ import annotations

import math

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec
from smart_unpacker.repair.pipeline.modules._common import load_source_bytes, write_candidate
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult


class TarTrailingZeroBlockRepair:
    spec = RepairModuleSpec(
        name="tar_trailing_zero_block_repair",
        formats=("tar",),
        categories=("boundary_repair",),
        stage="safe_fallback",
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"missing_end_block", "probably_truncated", "boundary_unreliable"}:
            return 0.82
        if diagnosis.format == "tar" and "boundary_repair" in diagnosis.categories:
            return 0.7
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_source_bytes(job.source_input)
        payload_end = _walk_payload_end(data)
        if payload_end is None:
            return RepairResult(status="unrepairable", confidence=0.0, format="tar", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="TAR entries could not be walked safely")
        end = _canonical_tar_end(data, payload_end)
        repaired = data[:end]
        if not repaired.endswith(b"\0" * 1024):
            repaired += b"\0" * (1024 - min(1024, len(repaired) - payload_end))
        if repaired == data:
            return RepairResult(status="unrepairable", confidence=0.0, format="tar", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="TAR already has canonical zero block ending")
        path = write_candidate(repaired, workspace, "tar_trailing_zero_block_repair.tar")
        return RepairResult(
            status="repaired",
            confidence=0.84,
            format="tar",
            repaired_input={"kind": "file", "path": path, "format_hint": "tar"},
            actions=["trim_or_append_tar_zero_blocks"],
            damage_flags=list(job.damage_flags),
            workspace_paths=[path],
            module_name=self.spec.name,
            diagnosis=diagnosis.as_dict(),
        )


def _walk_payload_end(data: bytes) -> int | None:
    offset = 0
    while offset + 512 <= len(data):
        header = data[offset:offset + 512]
        if header == b"\0" * 512:
            return offset
        size = _parse_octal(header[124:136])
        if size is None:
            return None
        offset += 512 + int(math.ceil(size / 512) * 512)
    return offset if offset == len(data) else None


def _canonical_tar_end(data: bytes, payload_end: int) -> int:
    end = payload_end
    while end + 512 <= len(data) and data[end:end + 512] == b"\0" * 512:
        end += 512
        if end >= payload_end + 1024:
            break
    return end


def _parse_octal(value: bytes) -> int | None:
    text = value.strip(b"\0 ").decode("ascii", errors="ignore")
    if not text:
        return 0
    try:
        return int(text, 8)
    except ValueError:
        return None


register_repair_module(TarTrailingZeroBlockRepair())
