from typing import Any, Dict

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.rules import RuleEffect
from smart_unpacker.detection.pipeline.rules.base import RuleBase
from smart_unpacker.detection.pipeline.rules.registry import register_rule


DEFAULT_ZIP_EOCD_SCORE = 6
DEFAULT_ZIP_EMBEDDED_EOCD_SCORE = 4
DEFAULT_ZIP_EMPTY_EOCD_SCORE = 4


@register_rule(name="zip_structure_identity", layer="scoring")
class ZipStructureIdentityScoreRule(RuleBase):
    required_facts = {"zip.eocd_structure"}
    fact_requirements = []
    produced_facts = {"file.detected_ext", "file.probe_detected_archive", "file.probe_offset"}
    config_schema = {
        "eocd_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_ZIP_EOCD_SCORE,
            "description": "Score for a plausible ZIP EOCD and central directory structure.",
        },
        "empty_eocd_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_ZIP_EMPTY_EOCD_SCORE,
            "description": "Score for a plausible empty ZIP EOCD without central directory entries.",
        },
        "embedded_eocd_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_ZIP_EMBEDDED_EOCD_SCORE,
            "description": "Score for a plausible ZIP EOCD whose archive payload starts after a leading stub.",
        },
    }

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> RuleEffect:
        structure = facts.get("zip.eocd_structure") or {}
        if not structure.get("plausible"):
            return RuleEffect.pass_()

        facts.set("file.detected_ext", ".zip")
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", int(structure.get("archive_offset") or 0))

        archive_offset = int(structure.get("archive_offset") or 0)
        if archive_offset > 0:
            score = config.get("embedded_eocd_score", DEFAULT_ZIP_EMBEDDED_EOCD_SCORE)
            reason = "ZIP structure: embedded EOCD and central directory"
        elif structure.get("central_directory_present"):
            score = config.get("eocd_score", DEFAULT_ZIP_EOCD_SCORE)
            reason = "ZIP structure: EOCD and central directory"
        else:
            score = config.get("empty_eocd_score", DEFAULT_ZIP_EMPTY_EOCD_SCORE)
            reason = "ZIP structure: empty EOCD"
        if not score:
            return RuleEffect.pass_()
        return RuleEffect.add_score(score, reason=reason)
