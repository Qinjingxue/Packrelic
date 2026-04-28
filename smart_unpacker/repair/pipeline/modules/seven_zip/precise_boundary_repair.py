from __future__ import annotations

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec
from smart_unpacker.repair.pipeline.modules.archive_carrier_crop import _result_from_native
from smart_unpacker.repair.pipeline.registry import register_repair_module

from smart_unpacker_native import seven_zip_precise_boundary_repair as _native_seven_zip_precise_boundary_repair


class SevenZipPreciseBoundaryRepair:
    spec = RepairModuleSpec(
        name="seven_zip_precise_boundary_repair",
        formats=("7z", "seven_zip"),
        categories=("boundary_repair",),
        stage="deep",
        safe=True,
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"trailing_junk", "boundary_unreliable", "carrier_archive", "sfx", "embedded_archive"}:
            return 0.98
        if "boundary_repair" in diagnosis.categories:
            return 0.82
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        result = _native_seven_zip_precise_boundary_repair(
            job.source_input,
            workspace,
            float(deep.get("max_input_size_mb", 512) or 0),
            int(deep.get("max_candidates_per_module", 8) or 1),
        )
        return _result_from_native(self.spec.name, result, job, diagnosis, config)


register_repair_module(SevenZipPreciseBoundaryRepair())
