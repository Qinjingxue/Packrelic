from __future__ import annotations

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec, RepairRoute
from smart_unpacker.repair.pipeline.modules._common import load_source_bytes, write_candidate
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult

from ._directory import find_eocd, find_valid_central_directory, rewrite_eocd


class ZipCentralDirectoryOffsetFix:
    spec = RepairModuleSpec(
        name="zip_central_directory_offset_fix",
        formats=("zip",),
        categories=("directory_rebuild",),
        stage="targeted",
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_flags=("central_directory_offset_bad", "central_directory_bad"),
                require_any_failure_kinds=("structure_recognition",),
                base_score=0.8,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"carrier_archive", "sfx", "embedded_archive", "carrier_prefix"}:
            return 0.0
        if flags & {"central_directory_offset_bad", "central_directory_bad"}:
            return 0.92
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_source_bytes(job.source_input)
        eocd = find_eocd(data, allow_trailing_junk=True)
        cd = find_valid_central_directory(data)
        if eocd is None or cd is None:
            return RepairResult(
                status="unrepairable",
                confidence=0.0,
                format="zip",
                module_name=self.spec.name,
                diagnosis=diagnosis.as_dict(),
                message="EOCD or central directory is missing",
            )
        if eocd.cd_offset == cd.offset and eocd.cd_size == cd.end - cd.offset and eocd.total_entries == cd.count:
            return RepairResult(
                status="unrepairable",
                confidence=0.0,
                format="zip",
                module_name=self.spec.name,
                diagnosis=diagnosis.as_dict(),
                message="central directory offset already matches parsed central directory",
            )
        path = write_candidate(rewrite_eocd(data, cd, comment=eocd.comment), workspace, "zip_central_directory_offset_fix.zip")
        return RepairResult(
            status="repaired",
            confidence=0.9,
            format="zip",
            repaired_input={"kind": "file", "path": path, "format_hint": "zip"},
            actions=["scan_central_directory", "rewrite_eocd_cd_offset_size_count"],
            damage_flags=list(job.damage_flags),
            workspace_paths=[path],
            module_name=self.spec.name,
            diagnosis=diagnosis.as_dict(),
        )


register_repair_module(ZipCentralDirectoryOffsetFix())
