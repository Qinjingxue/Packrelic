from smart_unpacker.analysis.pipeline.module import AnalysisModuleSpec
from smart_unpacker.analysis.pipeline.registry import register_analysis_module
from smart_unpacker.analysis.pipeline.modules._boundaries import next_archive_boundary
from smart_unpacker.analysis.result import ArchiveFormatEvidence, ArchiveSegment

try:
    from smart_unpacker_native import inspect_rar_structure as _inspect_rar_structure
except (ImportError, AttributeError):
    _inspect_rar_structure = None


class RarAnalysisModule:
    spec = AnalysisModuleSpec(name="rar", formats=("rar",), signatures=(b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00"))

    def analyze(self, view, prepass: dict, config: dict) -> ArchiveFormatEvidence:
        hits = [hit for hit in prepass.get("hits", []) if str(hit.get("name", "")).startswith("rar")]
        if not hits:
            return ArchiveFormatEvidence(format="rar", confidence=0.0, status="not_found")
        start = min(hit["offset"] for hit in hits)
        if hasattr(view, "probe_rar"):
            native = view.probe_rar(start_offset=start, max_blocks_to_walk=int(config.get("max_blocks_to_walk", 4096) or 4096))
            if native:
                return self._from_native(dict(native), start, next_archive_boundary(prepass, start, view.size))
        if _inspect_rar_structure and start == 0:
            return self._from_native(
                dict(_inspect_rar_structure(str(view.path), max_first_header_check_bytes=int(config.get("max_first_header_check_bytes", 1024 * 1024) or 1024 * 1024))),
                start,
                next_archive_boundary(prepass, start, view.size),
            )

        end = next_archive_boundary(prepass, start, view.size)
        return ArchiveFormatEvidence(
            format="rar",
            confidence=0.90,
            status="extractable",
            segments=[ArchiveSegment(start_offset=start, end_offset=end, confidence=0.90, evidence=["rar:signature", "rar:boundary_inferred"])],
            warnings=["rar segment end inferred from next archive signature or EOF"],
        )

    def _from_native(self, native: dict, start: int, boundary: int) -> ArchiveFormatEvidence:
        if not native.get("magic_matched"):
            return ArchiveFormatEvidence(format="rar", confidence=0.0, status="not_found", details=native)
        evidence = list(native.get("evidence") or ["rar:signature"])
        strong = bool(native.get("strong_accept"))
        plausible = bool(native.get("plausible"))
        segment_end = int(native.get("segment_end") or 0) or boundary
        if strong:
            status = "extractable"
            confidence = 0.97
        elif plausible:
            status = "damaged"
            confidence = 0.65
        else:
            status = "weak"
            confidence = 0.35
        damage_flags = []
        error = native.get("error") or ""
        if error:
            damage_flags.append(str(error))
        return ArchiveFormatEvidence(
            format="rar",
            confidence=confidence,
            status=status,
            segments=[ArchiveSegment(start_offset=start, end_offset=segment_end, confidence=confidence, damage_flags=damage_flags, evidence=evidence)],
            warnings=[] if native.get("segment_end") else ["rar segment end inferred from next archive signature or EOF"],
            details=native,
        )


register_analysis_module(RarAnalysisModule())
