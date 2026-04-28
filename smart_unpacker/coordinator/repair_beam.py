from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable

from smart_unpacker.repair.candidate import CandidateSelector, RepairCandidate
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.scheduler import RepairScheduler


AnalyzeFn = Callable[[RepairCandidate], dict[str, Any]]


@dataclass(frozen=True)
class RepairBeamState:
    source_input: dict[str, Any]
    format: str
    confidence: float = 0.0
    damage_flags: list[str] = field(default_factory=list)
    archive_key: str = ""
    round_index: int = 0
    score: float = 0.0
    actions: list[str] = field(default_factory=list)
    history: list[dict[str, Any]] = field(default_factory=list)

    @property
    def digest(self) -> str:
        payload = {
            "source_input": self.source_input,
            "format": self.format,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()

    def to_job(self) -> RepairJob:
        return RepairJob(
            source_input=dict(self.source_input),
            format=self.format,
            confidence=self.confidence,
            damage_flags=list(self.damage_flags),
            archive_key=self.archive_key,
            attempts=self.round_index,
        )


@dataclass(frozen=True)
class RepairBeamCandidate:
    state: RepairBeamState
    candidate: RepairCandidate
    analyze: dict[str, Any] = field(default_factory=dict)
    score: float = 0.0


@dataclass(frozen=True)
class RepairBeamRound:
    round_index: int
    states_in: list[RepairBeamState]
    candidates: list[RepairBeamCandidate]
    states_out: list[RepairBeamState]


class RepairBeamLoop:
    def __init__(
        self,
        scheduler: RepairScheduler,
        *,
        beam_width: int = 4,
        max_candidates_per_state: int | None = None,
        max_analyze_candidates: int = 8,
        analyze: AnalyzeFn | None = None,
    ):
        self.scheduler = scheduler
        self.beam_width = max(1, int(beam_width or 1))
        self.max_candidates_per_state = max_candidates_per_state
        self.max_analyze_candidates = max(1, int(max_analyze_candidates or 1))
        self.analyze = analyze or (lambda _candidate: {})

    def expand_round(self, states: list[RepairBeamState], *, round_index: int) -> RepairBeamRound:
        raw_candidates: list[RepairBeamCandidate] = []
        for state in states:
            batch = self.scheduler.generate_repair_candidates(state.to_job())
            candidates = list(batch.candidates)
            if self.max_candidates_per_state is not None:
                candidates = candidates[: max(0, int(self.max_candidates_per_state))]
            for candidate in candidates:
                raw_candidates.append(RepairBeamCandidate(
                    state=state,
                    candidate=candidate,
                    score=_candidate_pre_score(candidate, state),
                ))

        ranked = sorted(raw_candidates, key=lambda item: item.score, reverse=True)
        analyzed = [
            _with_analyze(item, self.analyze(item.candidate))
            for item in ranked[: self.max_analyze_candidates]
        ]
        analyzed = sorted(analyzed, key=lambda item: item.score, reverse=True)
        states_out = self._states_from_candidates(analyzed, round_index=round_index)
        return RepairBeamRound(
            round_index=round_index,
            states_in=list(states),
            candidates=analyzed,
            states_out=states_out,
        )

    def _states_from_candidates(self, candidates: list[RepairBeamCandidate], *, round_index: int) -> list[RepairBeamState]:
        output: list[RepairBeamState] = []
        seen: set[str] = set()
        for item in candidates:
            repaired_input = item.candidate.repaired_input
            state = RepairBeamState(
                source_input=dict(repaired_input),
                format=item.candidate.format or item.state.format,
                confidence=max(float(item.candidate.confidence or 0.0), float(item.analyze.get("confidence", 0.0) or 0.0)),
                damage_flags=list(item.candidate.damage_flags or item.state.damage_flags),
                archive_key=f"{item.state.archive_key or 'repair'}:{round_index}:{item.candidate.module_name}",
                round_index=round_index,
                score=item.score,
                actions=[*item.state.actions, *item.candidate.actions],
                history=[
                    *item.state.history,
                    {
                        "round": round_index,
                        "module": item.candidate.module_name,
                        "status": item.candidate.status,
                        "score": item.score,
                        "analyze": dict(item.analyze),
                    },
                ],
            )
            if state.digest in seen:
                continue
            seen.add(state.digest)
            output.append(state)
            if len(output) >= self.beam_width:
                break
        return output


def _candidate_pre_score(candidate: RepairCandidate, state: RepairBeamState) -> float:
    selector_score = CandidateSelector._score(candidate)
    return selector_score + min(1.0, max(0.0, state.score)) * 0.05


def _with_analyze(item: RepairBeamCandidate, analyze: dict[str, Any]) -> RepairBeamCandidate:
    confidence = float(analyze.get("confidence", 0.0) or 0.0) if isinstance(analyze, dict) else 0.0
    status_bonus = 0.05 if str(analyze.get("status") or "") in {"damaged", "extractable", "repaired"} else 0.0
    score = item.score + min(1.0, max(0.0, confidence)) * 0.25 + status_bonus
    return RepairBeamCandidate(
        state=item.state,
        candidate=item.candidate,
        analyze=dict(analyze or {}),
        score=score,
    )
