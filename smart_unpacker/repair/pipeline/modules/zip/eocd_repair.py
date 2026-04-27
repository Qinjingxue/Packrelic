from __future__ import annotations

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec
from smart_unpacker.repair.pipeline.modules._common import load_source_bytes, write_candidate
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult

from ._directory import find_eocd, find_valid_central_directory, rewrite_eocd, trim_to_eocd, walk_central_directory


class ZipEocdRepair:
    spec = RepairModuleSpec(
        name="zip_eocd_repair",
        formats=("zip",),
        categories=("directory_rebuild", "boundary_repair"),
        stage="targeted",
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"eocd_bad", "central_directory_bad", "directory_integrity_bad_or_unknown"}:
            return 0.9
        if "directory_rebuild" in diagnosis.categories:
            return 0.82
        if "boundary_repair" in diagnosis.categories:
            return 0.55
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_source_bytes(job.source_input)
        eocd = find_eocd(data, allow_trailing_junk=True)
        if eocd is not None:
            cd = walk_central_directory(data, eocd.cd_offset, expected_end=eocd.cd_offset + eocd.cd_size)
            if cd.valid:
                repaired = trim_to_eocd(data, eocd)
                if repaired == data:
                    return _failed(self.spec.name, diagnosis, "EOCD and central directory already look consistent")
                path = write_candidate(repaired, workspace, "zip_eocd_repair.zip")
                return _ok(self.spec.name, diagnosis, job, path, 0.9, ["trim_after_eocd"])

        cd = find_valid_central_directory(data)
        if cd is None:
            return _failed(self.spec.name, diagnosis, "no valid central directory was found for EOCD rebuild")
        path = write_candidate(rewrite_eocd(data, cd), workspace, "zip_eocd_repair.zip")
        return _ok(self.spec.name, diagnosis, job, path, 0.86, ["scan_central_directory", "rebuild_eocd"])


def _ok(module_name, diagnosis, job, path, confidence, actions):
    return RepairResult(
        status="repaired",
        confidence=confidence,
        format="zip",
        repaired_input={"kind": "file", "path": path, "format_hint": "zip"},
        actions=actions,
        damage_flags=list(job.damage_flags),
        workspace_paths=[path],
        module_name=module_name,
        diagnosis=diagnosis.as_dict(),
    )


def _failed(module_name, diagnosis, message):
    return RepairResult(
        status="unrepairable",
        confidence=0.0,
        format="zip",
        module_name=module_name,
        diagnosis=diagnosis.as_dict(),
        message=message,
    )


register_repair_module(ZipEocdRepair())
