from smart_unpacker.analysis.pipeline.module import AnalysisModuleSpec
from smart_unpacker.analysis.pipeline.registry import register_analysis_module
from smart_unpacker.analysis.result import ArchiveFormatEvidence, ArchiveSegment


class SevenZipAnalysisModule:
    spec = AnalysisModuleSpec(name="seven_zip", formats=("7z",), signatures=(b"7z\xbc\xaf\x27\x1c",))

    def analyze(self, view, prepass: dict, config: dict) -> ArchiveFormatEvidence:
        hits = [hit for hit in prepass.get("hits", []) if hit.get("name") == "7z"]
        if not hits:
            return ArchiveFormatEvidence(format="7z", confidence=0.0, status="not_found")
        start = min(hit["offset"] for hit in hits)
        header = view.read_at(start, min(32, view.size - start))
        confidence = 0.95 if header.startswith(b"7z\xbc\xaf\x27\x1c") else 0.40
        return ArchiveFormatEvidence(
            format="7z",
            confidence=confidence,
            status="extractable" if confidence >= 0.85 else "weak",
            segments=[ArchiveSegment(start_offset=start, end_offset=None, confidence=confidence, evidence=["7z_signature"])],
        )


register_analysis_module(SevenZipAnalysisModule())
