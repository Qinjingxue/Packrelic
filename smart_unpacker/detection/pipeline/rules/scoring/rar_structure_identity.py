from typing import Any, Dict

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.rules import RuleEffect
from smart_unpacker.detection.pipeline.rules.base import RuleBase
from smart_unpacker.detection.pipeline.rules.registry import register_rule


DEFAULT_RAR_STRUCTURE_SCORE = 5
DEFAULT_RAR_MAGIC_SCORE = 2


@register_rule(name="rar_structure_identity", layer="scoring")
class RarStructureIdentityScoreRule(RuleBase):
    required_facts = {"rar.structure"}
    fact_requirements = []
    produced_facts = {"file.detected_ext", "file.magic_matched", "file.probe_detected_archive", "file.probe_offset"}
    config_schema = {
        "structure_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_RAR_STRUCTURE_SCORE,
            "description": "Score for a plausible RAR4/RAR5 first-header structure.",
        },
        "magic_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_RAR_MAGIC_SCORE,
            "description": "Score for a RAR magic signature without stronger first-header structure.",
        },
    }

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> RuleEffect:
        structure = facts.get("rar.structure") or {}
        if not structure.get("plausible") and not structure.get("magic_matched"):
            return RuleEffect.pass_()
        facts.set("file.detected_ext", ".rar")
        facts.set("file.magic_matched", True)
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", 0)
        score = (
            config.get("structure_score", DEFAULT_RAR_STRUCTURE_SCORE)
            if structure.get("plausible")
            else config.get("magic_score", DEFAULT_RAR_MAGIC_SCORE)
        )
        if not score:
            return RuleEffect.pass_()
        version = structure.get("version") or ""
        reason = f"RAR structure: RAR{version} first header" if structure.get("plausible") else "RAR structure: magic signature"
        return RuleEffect.add_score(score, reason=reason)
