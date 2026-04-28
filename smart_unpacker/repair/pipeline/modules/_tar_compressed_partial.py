from __future__ import annotations

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec
from smart_unpacker.repair.result import RepairResult

from smart_unpacker_native import tar_compressed_partial_recovery as _native_tar_compressed_partial_recovery


class TarCompressedPartialRecovery:
    format_name: str = ""
    aliases: tuple[str, ...] = ()
    module_name: str = ""

    @property
    def spec(self) -> RepairModuleSpec:
        return RepairModuleSpec(
            name=self.module_name,
            formats=self.aliases,
            categories=("content_recovery", "boundary_repair", "directory_rebuild"),
            stage="deep",
            safe=True,
            partial=True,
        )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        fmt = str(diagnosis.format or job.format or "").lower()
        if fmt == self.format_name and flags & _STRONG_FLAGS:
            return 0.98
        if fmt == self.format_name and "directory_rebuild" in diagnosis.categories:
            return 0.9
        if fmt in self.aliases and flags & _STREAM_FLAGS:
            return 0.86
        if fmt in self.aliases and "content_recovery" in diagnosis.categories:
            return 0.78
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        result = _native_tar_compressed_partial_recovery(
            job.source_input,
            self.format_name,
            workspace,
            float(deep.get("max_input_size_mb", 512) or 0),
            float(deep.get("max_output_size_mb", 2048) or 0),
            float(deep.get("max_seconds_per_module", 30.0) or 0),
            int(deep.get("max_entries", 20000) or 0),
        )
        status = str(result.get("status") or "unrepairable")
        selected_path = str(result.get("selected_path") or "")
        if status not in {"partial", "repaired"} or not selected_path:
            return RepairResult(
                status="unrepairable" if status in {"skipped", "unsupported"} else status,
                confidence=float(result.get("confidence") or 0.0),
                format=self.format_name,
                actions=list(result.get("actions") or []),
                damage_flags=list(job.damage_flags),
                warnings=list(result.get("warnings") or []),
                workspace_paths=list(result.get("workspace_paths") or []),
                partial=True,
                module_name=self.spec.name,
                diagnosis=diagnosis.as_dict(),
                message=str(result.get("message") or "compressed TAR partial recovery did not produce a candidate"),
            )

        return RepairResult(
            status=status,
            confidence=float(result.get("confidence") or 0.68),
            format=self.format_name,
            repaired_input={"kind": "file", "path": selected_path, "format_hint": self.format_name},
            actions=list(result.get("actions") or []),
            damage_flags=list(job.damage_flags),
            warnings=list(result.get("warnings") or []),
            workspace_paths=list(result.get("workspace_paths") or []),
            partial=status == "partial",
            module_name=self.spec.name,
            diagnosis={
                **diagnosis.as_dict(),
                "native_tar_compressed_partial_recovery": {
                    "format": result.get("format", self.format_name),
                    "outer_format": result.get("outer_format", ""),
                    "decoded_bytes": result.get("decoded_bytes", 0),
                    "tar_bytes": result.get("tar_bytes", 0),
                    "output_bytes": result.get("output_bytes", 0),
                    "members": result.get("members", 0),
                    "checksum_fixes": result.get("checksum_fixes", 0),
                    "truncated_members": result.get("truncated_members", 0),
                    "decoder_error": result.get("decoder_error", ""),
                },
            },
            message=str(result.get("message") or "compressed TAR partial recovery produced a candidate"),
        )


_STREAM_FLAGS = {
    "probably_truncated",
    "stream_truncated",
    "input_truncated",
    "truncated",
    "unexpected_end",
    "unexpected_eof",
    "data_error",
    "damaged",
}
_STRONG_FLAGS = _STREAM_FLAGS | {
    "missing_end_block",
    "tar_checksum_bad",
    "header_checksum_bad",
    "boundary_unreliable",
}
