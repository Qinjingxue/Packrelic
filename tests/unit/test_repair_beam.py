from smart_unpacker.coordinator.repair_beam import RepairBeamLoop, RepairBeamState
from smart_unpacker.repair.candidate import CandidateValidation, RepairCandidate, RepairCandidateBatch


def test_repair_beam_expands_candidates_and_keeps_top_states():
    scheduler = _FakeCandidateScheduler([
        _candidate("low", confidence=0.3),
        _candidate("middle", confidence=0.6),
        _candidate("high", confidence=0.75),
    ])
    loop = RepairBeamLoop(
        scheduler,
        beam_width=2,
        max_analyze_candidates=3,
        analyze=lambda candidate: {"confidence": 0.95 if candidate.module_name == "middle" else 0.1},
    )

    round_result = loop.expand_round([
        RepairBeamState(
            source_input={"kind": "file", "path": "broken.zip"},
            format="zip",
            confidence=0.7,
            damage_flags=["damaged"],
            archive_key="broken",
        )
    ], round_index=1)

    assert len(round_result.candidates) == 3
    assert len(round_result.states_out) == 2
    assert round_result.states_out[0].history[-1]["module"] == "middle"
    assert round_result.states_out[1].history[-1]["module"] == "high"


def test_repair_beam_deduplicates_equivalent_state_outputs():
    scheduler = _FakeCandidateScheduler([
        _candidate("first", confidence=0.8, path="same.zip"),
        _candidate("second", confidence=0.8, path="same.zip"),
    ])
    loop = RepairBeamLoop(scheduler, beam_width=4, max_analyze_candidates=4)

    round_result = loop.expand_round([
        RepairBeamState(source_input={"kind": "file", "path": "broken.zip"}, format="zip", archive_key="broken")
    ], round_index=1)

    assert len(round_result.states_out) == 1


class _FakeCandidateScheduler:
    def __init__(self, candidates):
        self.candidates = candidates
        self.jobs = []

    def generate_repair_candidates(self, job):
        self.jobs.append(job)
        return RepairCandidateBatch(candidates=list(self.candidates), diagnosis={"format": job.format, "confidence": job.confidence})


def _candidate(module_name, *, confidence, path=None):
    return RepairCandidate(
        module_name=module_name,
        format="zip",
        repaired_input={"kind": "file", "path": path or f"{module_name}.zip", "format_hint": "zip"},
        confidence=confidence,
        actions=[module_name],
        validations=[CandidateValidation(name="module_result", accepted=True, score=confidence)],
    )
