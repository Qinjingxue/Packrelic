from typing import List, Dict, Any
from dataclasses import dataclass

from smart_unpacker.detection import DetectionScheduler

@dataclass
class ScanResult:
    logical_name: str
    main_path: str
    all_parts: List[str]
    should_extract: bool
    score: int
    stop_reason: str
    matched_rules: List[str]
    detected_ext: str
    fact_bag: object
    decision: str

class ScanOrchestrator:
    def __init__(self, config: Dict[str, Any]):
        self.detector = DetectionScheduler(config)

    def scan(self, root_dir: str) -> List[ScanResult]:
        return self.scan_targets([root_dir])

    def scan_targets(self, target_paths: List[str]) -> List[ScanResult]:
        results = []
        for detection in self.detector.detect_targets(target_paths):
            bag = detection.fact_bag
            main_path = bag.get("candidate.entry_path")
            if not main_path:
                continue
            decision = detection.decision
            
            if decision.should_extract:
                results.append(ScanResult(
                    logical_name=bag.get("candidate.logical_name", ""),
                    main_path=main_path,
                    all_parts=list(bag.get("candidate.member_paths") or []),
                    should_extract=decision.should_extract,
                    score=decision.total_score,
                    stop_reason=decision.stop_reason or "",
                    matched_rules=decision.matched_rules,
                    detected_ext=bag.get("file.detected_ext", ""),
                    fact_bag=bag,
                    decision=decision.decision,
                ))
                
        return results
