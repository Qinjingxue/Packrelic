from typing import Any, Dict

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.rules import RuleEffect
from smart_unpacker.detection.pipeline.rules.base import RuleBase
from smart_unpacker.detection.pipeline.rules.registry import register_rule


DEFAULT_COMPRESSION_STREAM_SCORE = 5


@register_rule(name="compression_stream_identity", layer="scoring")
class CompressionStreamIdentityScoreRule(RuleBase):
    required_facts = {"compression.stream_structure"}
    fact_requirements = []
    produced_facts = {"file.detected_ext", "file.probe_detected_archive", "file.probe_offset"}
    config_schema = {
        "stream_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_COMPRESSION_STREAM_SCORE,
            "description": "Score for a plausible gzip, bzip2, xz, or zstd stream structure.",
        },
    }

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> RuleEffect:
        structure = facts.get("compression.stream_structure") or {}
        if not structure.get("plausible"):
            return RuleEffect.pass_()

        detected_ext = structure.get("detected_ext") or ""
        if detected_ext:
            facts.set("file.detected_ext", detected_ext)
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", 0)

        score = config.get("stream_score", DEFAULT_COMPRESSION_STREAM_SCORE)
        if not score:
            return RuleEffect.pass_()
        archive_format = structure.get("format") or detected_ext or "compression_stream"
        confidence = structure.get("confidence") or "unknown"
        return RuleEffect.add_score(
            score,
            reason=f"Compression stream structure {archive_format} ({confidence})",
        )
