from smart_unpacker.verification.comparison import RecoveryAttempt, compare_attempts, rank_attempts
from smart_unpacker.verification.result import (
    ASSESSMENT_COMPLETE,
    ASSESSMENT_PARTIAL,
    ArchiveCoverageSummary,
    DECISION_ACCEPT,
    DECISION_ACCEPT_PARTIAL,
    DECISION_REPAIR,
    VerificationResult,
)


def test_verification_comparator_prefers_verified_complete_over_confident_partial():
    complete = _attempt(
        "complete",
        status=ASSESSMENT_COMPLETE,
        decision=DECISION_ACCEPT,
        completeness=1.0,
        complete_files=2,
        expected_files=2,
        source_code="info.archive_output_coverage",
        patch_cost=0.2,
    )
    partial = _attempt(
        "partial",
        status=ASSESSMENT_PARTIAL,
        decision=DECISION_ACCEPT_PARTIAL,
        completeness=0.8,
        complete_files=4,
        failed_files=1,
        expected_files=5,
        source_code="info.output_progress_coverage",
    )

    ranked = rank_attempts([partial, complete])

    assert ranked[0][0].attempt_id == "complete"
    assert ranked[0][1].decision == "accept"


def test_verification_comparator_keeps_incumbent_when_patch_plan_does_not_improve():
    incumbent = _attempt(
        "original",
        status=ASSESSMENT_PARTIAL,
        decision=DECISION_ACCEPT_PARTIAL,
        completeness=0.75,
        complete_files=3,
        failed_files=1,
        expected_files=4,
    )
    repaired = _attempt(
        "patched",
        status=ASSESSMENT_PARTIAL,
        decision=DECISION_REPAIR,
        completeness=0.5,
        complete_files=2,
        failed_files=2,
        expected_files=4,
        patch_cost=0.1,
    )

    result = compare_attempts([repaired], incumbent=incumbent)

    assert result.best is incumbent
    assert result.stop_reason in {"partial_incumbent", "no_improvement"}
    assert result.ranks["original"].rank_score > result.ranks["patched"].rank_score


def _attempt(
    attempt_id: str,
    *,
    status: str,
    decision: str,
    completeness: float,
    complete_files: int,
    expected_files: int,
    failed_files: int = 0,
    source_code: str = "info.archive_output_coverage",
    patch_cost: float = 0.0,
) -> RecoveryAttempt:
    coverage = ArchiveCoverageSummary(
        completeness=completeness,
        file_coverage=completeness,
        byte_coverage=completeness,
        expected_files=expected_files,
        matched_files=max(0, expected_files - failed_files),
        complete_files=complete_files,
        failed_files=failed_files,
        confidence=0.95,
        sources=[{"code": source_code, "method": "test", "confidence": 0.95}],
    )
    return RecoveryAttempt(
        attempt_id=attempt_id,
        verification=VerificationResult(
            completeness=completeness,
            assessment_status=status,
            decision_hint=decision,
            archive_coverage=coverage,
            complete_files=complete_files,
            failed_files=failed_files,
        ),
        patch_cost=patch_cost,
    )
