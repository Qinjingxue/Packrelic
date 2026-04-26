from typing import Any, Dict

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.rules import RuleEffect
from smart_unpacker.detection.pipeline.rules.base import RuleBase
from smart_unpacker.detection.pipeline.rules.registry import register_rule


DEFAULT_SEVEN_Z_STRUCTURE_SCORE = 5


@register_rule(name="seven_zip_structure_identity", layer="scoring")
class SevenZipStructureIdentityScoreRule(RuleBase):
    required_facts = {"7z.structure"}
    fact_requirements = []
    produced_facts = {"file.detected_ext", "file.magic_matched", "file.probe_detected_archive", "file.probe_offset"}
    config_schema = {
        "structure_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_SEVEN_Z_STRUCTURE_SCORE,
            "description": "Score for a plausible 7z start-header structure.",
        },
    }

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> RuleEffect:
        structure = facts.get("7z.structure") or {}
        if not structure.get("plausible"):
            return RuleEffect.pass_()
        facts.set("file.detected_ext", ".7z")
        facts.set("file.magic_matched", True)
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", 0)
        score = config.get("structure_score", DEFAULT_SEVEN_Z_STRUCTURE_SCORE)
        if not score:
            return RuleEffect.pass_()
        return RuleEffect.add_score(score, reason="7z structure: start header CRC and next header range")
