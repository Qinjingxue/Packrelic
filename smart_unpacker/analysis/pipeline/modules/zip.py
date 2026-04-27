from smart_unpacker.analysis.pipeline.module import AnalysisModuleSpec
from smart_unpacker.analysis.pipeline.registry import register_analysis_module
from smart_unpacker.analysis.result import ArchiveFormatEvidence, ArchiveSegment


class ZipAnalysisModule:
    spec = AnalysisModuleSpec(name="zip", formats=("zip",), signatures=(b"PK\x03\x04", b"PK\x05\x06"), io_profile="tail_heavy")

    def analyze(self, view, prepass: dict, config: dict) -> ArchiveFormatEvidence:
        hits = [hit for hit in prepass.get("hits", []) if str(hit.get("name", "")).startswith("zip_")]
        if not hits:
            return ArchiveFormatEvidence(format="zip", confidence=0.0, status="not_found")

        local_hits = [hit["offset"] for hit in hits if hit.get("name") == "zip_local"]
        eocd_hits = [hit["offset"] for hit in hits if hit.get("name") == "zip_eocd"]
        start = min(local_hits or [hits[0]["offset"]])
        end = None
        evidence = []
        confidence = 0.45
        status = "weak"
        if local_hits:
            evidence.append("local_header")
            confidence += 0.25
        if eocd_hits:
            evidence.append("eocd")
            eocd = max(eocd_hits)
            end = min(view.size, eocd + 22)
            confidence += 0.25
        if local_hits and eocd_hits:
            status = "extractable"
            confidence = 0.95
        elif local_hits or eocd_hits:
            status = "damaged"

        return ArchiveFormatEvidence(
            format="zip",
            confidence=min(confidence, 1.0),
            status=status,
            segments=[ArchiveSegment(start_offset=start, end_offset=end, confidence=min(confidence, 1.0), evidence=evidence)],
        )


register_analysis_module(ZipAnalysisModule())
