from __future__ import annotations

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec, RepairRoute
from smart_unpacker.repair.pipeline.modules._native_candidates import candidates_from_native_result
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult

from smart_unpacker_native import zip_deep_partial_recovery as _native_zip_deep_partial_recovery


class ZipDeepPartialRecovery:
    spec = RepairModuleSpec(
        name="zip_deep_partial_recovery",
        formats=("zip",),
        categories=("content_recovery", "directory_rebuild", "boundary_repair"),
        stage="deep",
        safe=True,
        partial=True,
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_categories=("content_recovery", "directory_rebuild", "boundary_repair"),
                require_any_flags=(
                    "damaged",
                    "crc_error",
                    "checksum_error",
                    "local_header_recovery",
                    "central_directory_bad",
                    "directory_integrity_bad_or_unknown",
                    "data_descriptor",
                    "corrupted_data",
                ),
                require_any_failure_stages=("item_extract", "archive_open"),
                require_any_failure_kinds=("checksum_error", "corrupted_data", "data_error", "structure_recognition"),
                base_score=0.88,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if "content_recovery" in diagnosis.categories:
            return 0.96
        if flags & {
            "damaged",
            "crc_error",
            "checksum_error",
            "local_header_recovery",
            "central_directory_bad",
            "directory_integrity_bad_or_unknown",
            "data_descriptor",
        }:
            return 0.92
        if "directory_rebuild" in diagnosis.categories:
            return 0.88
        if "boundary_repair" in diagnosis.categories:
            return 0.55
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        result = self._run_native(job, workspace, config)
        return self._result_from_native(result, job, diagnosis)

    def generate_candidates(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        result = self._run_native(job, workspace, config)
        return candidates_from_native_result(
            self.spec.name,
            result,
            job,
            diagnosis,
            native_key="native_zip_deep_recovery",
            format_hint="zip",
            partial_default=True,
            default_confidence=0.7,
            default_message="ZIP deep partial recovery produced a candidate",
        )

    def _run_native(self, job: RepairJob, workspace: str, config: dict) -> dict:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        return _native_zip_deep_partial_recovery(
            job.source_input,
            workspace,
            int(deep.get("max_candidates_per_module", 3) or 3),
            int(deep.get("max_entries", 20000) or 20000),
            float(deep.get("max_input_size_mb", 512) or 0),
            float(deep.get("max_output_size_mb", 2048) or 0),
            float(deep.get("max_entry_uncompressed_mb", 512) or 0),
            float(deep.get("max_seconds_per_module", 30.0) or 0),
            bool(deep.get("verify_candidates", True)),
        )

    def _result_from_native(self, result: dict, job: RepairJob, diagnosis: RepairDiagnosis) -> RepairResult:
        status = str(result.get("status") or "unrepairable")
        selected_path = str(result.get("selected_path") or "")
        if status not in {"repaired", "partial"} or not selected_path:
            return RepairResult(
                status="unrepairable" if status == "skipped" else status,
                confidence=float(result.get("confidence") or 0.0),
                format="zip",
                actions=list(result.get("actions") or []),
                damage_flags=list(job.damage_flags),
                warnings=list(result.get("warnings") or []),
                workspace_paths=list(result.get("workspace_paths") or []),
                partial=True,
                module_name=self.spec.name,
                diagnosis=diagnosis.as_dict(),
                message=str(result.get("message") or "ZIP deep partial recovery did not produce a candidate"),
            )

        return RepairResult(
            status="partial",
            confidence=float(result.get("confidence") or 0.7),
            format="zip",
            repaired_input={"kind": "file", "path": selected_path, "format_hint": "zip"},
            actions=list(result.get("actions") or []),
            damage_flags=list(job.damage_flags),
            warnings=list(result.get("warnings") or []),
            workspace_paths=list(result.get("workspace_paths") or []),
            partial=True,
            module_name=self.spec.name,
            diagnosis={
                **diagnosis.as_dict(),
                "native_zip_deep_recovery": {
                    "selected_candidate": result.get("selected_candidate", ""),
                    "recovered_entries": result.get("recovered_entries", 0),
                    "verified_entries": result.get("verified_entries", 0),
                    "descriptor_entries": result.get("descriptor_entries", 0),
                    "passthrough_entries": result.get("passthrough_entries", 0),
                    "skipped_entries": result.get("skipped_entries", 0),
                    "encrypted_entries": result.get("encrypted_entries", 0),
                    "unsupported_entries": result.get("unsupported_entries", 0),
                    "candidates": list(result.get("candidates") or []),
                },
            },
            message=str(result.get("message") or "ZIP deep partial recovery produced a candidate"),
        )


register_repair_module(ZipDeepPartialRecovery())
