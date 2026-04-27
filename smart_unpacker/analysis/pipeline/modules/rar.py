from smart_unpacker.analysis.pipeline.module import AnalysisModuleSpec
from smart_unpacker.analysis.pipeline.registry import register_analysis_module
from smart_unpacker.analysis.result import ArchiveFormatEvidence, ArchiveSegment


class RarAnalysisModule:
    spec = AnalysisModuleSpec(name="rar", formats=("rar",), signatures=(b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00"))

    def analyze(self, view, prepass: dict, config: dict) -> ArchiveFormatEvidence:
        hits = [hit for hit in prepass.get("hits", []) if str(hit.get("name", "")).startswith("rar")]
        if not hits:
            return ArchiveFormatEvidence(format="rar", confidence=0.0, status="not_found")
        start = min(hit["offset"] for hit in hits)
        return ArchiveFormatEvidence(
            format="rar",
            confidence=0.90,
            status="extractable",
            segments=[ArchiveSegment(start_offset=start, end_offset=None, confidence=0.90, evidence=["rar_signature"])],
        )


register_analysis_module(RarAnalysisModule())
