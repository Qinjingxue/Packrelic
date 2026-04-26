from typing import Any, Dict

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.rules import RuleEffect
from smart_unpacker.detection.pipeline.rules.base import RuleBase
from smart_unpacker.detection.pipeline.rules.registry import register_rule


@register_rule(name="zip_structure_accept", layer="precheck")
class ZipStructureAcceptRule(RuleBase):
    required_facts = {"zip.eocd_structure"}
    produced_facts = {"file.detected_ext", "file.probe_detected_archive", "file.probe_offset"}
    config_schema = {
        "accept_empty_zip": {
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Whether a structurally valid empty ZIP EOCD can be accepted before scoring.",
        },
    }

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> RuleEffect:
        structure = facts.get("zip.eocd_structure") or {}
        if not structure.get("plausible"):
            return RuleEffect.pass_()
        if int(structure.get("archive_offset") or 0) != 0:
            return RuleEffect.pass_()

        central_directory_present = bool(structure.get("central_directory_present"))
        empty_zip = (
            int(structure.get("total_entries") or 0) == 0
            and int(structure.get("central_directory_size") or 0) == 0
        )
        if not central_directory_present and not (empty_zip and config.get("accept_empty_zip", True)):
            return RuleEffect.pass_()

        facts.set("file.detected_ext", ".zip")
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", 0)
        return RuleEffect.accept("ZIP structure accept: EOCD and central directory")
