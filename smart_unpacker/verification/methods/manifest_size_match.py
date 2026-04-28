from smart_unpacker.verification.evidence import VerificationEvidence
from smart_unpacker.verification.methods._archive_output_match import (
    archive_files_from_names,
    coverage_details,
    coverage_from_archive_and_output,
    output_files_from_directory,
)
from smart_unpacker.verification.methods._output_stats import output_stats_for_evidence
from smart_unpacker.verification.registry import register_verification_method
from smart_unpacker.verification.result import (
    DECISION_REPAIR,
    SOURCE_INTEGRITY_COMPLETE,
    SOURCE_INTEGRITY_DAMAGED,
    VerificationIssue,
    VerificationStepResult,
)


@register_verification_method("manifest_size_match")
class ManifestSizeMatchMethod:
    name = "manifest_size_match"

    def verify(self, evidence: VerificationEvidence, config: dict) -> VerificationStepResult:
        expected_files = _as_int(evidence.analysis.get("file_count"))
        expected_size = _as_int(evidence.analysis.get("total_unpacked_size"))
        expected_names = _expected_names(evidence)
        if expected_files <= 0 and expected_size <= 0:
            return VerificationStepResult(method=self.name, status="skipped")

        stats = output_stats_for_evidence(evidence)
        if not stats.exists or not stats.is_dir:
            return VerificationStepResult(method=self.name, status="skipped")

        issues: list[VerificationIssue] = []
        source_integrity = _source_integrity_hint(evidence)
        name_coverage = None
        if expected_names:
            name_coverage = coverage_from_archive_and_output(
                archive_files_from_names(expected_names),
                output_files_from_directory(evidence.output_dir),
                method=self.name,
            )
            if name_coverage.missing_files:
                issues.append(VerificationIssue(
                    method=self.name,
                    code="fail.manifest_named_files_missing",
                    message="Some manifest-named files were not found in extraction output",
                    path=evidence.output_dir,
                    expected=len(expected_names),
                    actual=coverage_details(name_coverage),
                ))

        if expected_files > 0:
            file_tolerance = max(
                int(config.get("file_count_abs_tolerance", 2) or 0),
                int(expected_files * float(config.get("file_count_ratio_tolerance", 0.05) or 0.0)),
            )
            lower_bound = max(0, expected_files - file_tolerance)
            upper_bound = expected_files + file_tolerance
            if stats.file_count < lower_bound:
                issues.append(VerificationIssue(
                    method=self.name,
                    code="fail.manifest_file_count_under",
                    message="Output file count is lower than archive manifest file count",
                    path=evidence.output_dir,
                    expected=expected_files,
                    actual=stats.file_count,
                ))
            elif stats.file_count > upper_bound:
                issues.append(VerificationIssue(
                    method=self.name,
                    code="warning.manifest_file_count_over",
                    message="Output file count is higher than archive manifest file count",
                    path=evidence.output_dir,
                    expected=expected_files,
                    actual=stats.file_count,
                ))

        if expected_size > 0:
            size_tolerance = max(
                int(config.get("size_abs_tolerance_bytes", 1024 * 1024) or 0),
                int(expected_size * float(config.get("size_ratio_tolerance", 0.02) or 0.0)),
            )
            lower_bound = max(0, expected_size - size_tolerance)
            upper_bound = expected_size + size_tolerance
            if stats.total_size < lower_bound:
                issues.append(VerificationIssue(
                    method=self.name,
                    code="fail.manifest_size_under",
                    message="Output total size is lower than archive manifest unpacked size",
                    path=evidence.output_dir,
                    expected=expected_size,
                    actual=stats.total_size,
                ))
            elif stats.total_size > upper_bound:
                issues.append(VerificationIssue(
                    method=self.name,
                    code="warning.manifest_size_over",
                    message="Output total size is higher than archive manifest unpacked size",
                    path=evidence.output_dir,
                    expected=expected_size,
                    actual=stats.total_size,
                ))

        if not issues:
            return VerificationStepResult(
                method=self.name,
                status="passed",
                completeness_hint=name_coverage.completeness if name_coverage is not None else 1.0,
                source_integrity_hint=source_integrity,
                file_observations=name_coverage.observations if name_coverage is not None else [],
            )
        completeness = _manifest_completeness(stats.file_count, stats.total_size, expected_files, expected_size)
        if name_coverage is not None:
            completeness = min(completeness, name_coverage.completeness)
        return VerificationStepResult(
            method=self.name,
            status="warning",
            issues=issues,
            completeness_hint=completeness,
            source_integrity_hint=source_integrity,
            recoverable_upper_bound_hint=completeness if source_integrity != SOURCE_INTEGRITY_COMPLETE else None,
            decision_hint=DECISION_REPAIR if source_integrity == SOURCE_INTEGRITY_COMPLETE else "none",
            file_observations=name_coverage.observations if name_coverage is not None else [],
        )


def _as_int(value) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _manifest_completeness(actual_files: int, actual_size: int, expected_files: int, expected_size: int) -> float:
    ratios = []
    if expected_files > 0:
        ratios.append(min(1.0, max(0.0, actual_files / expected_files)))
    if expected_size > 0:
        ratios.append(min(1.0, max(0.0, actual_size / expected_size)))
    return min(ratios) if ratios else 1.0


def _source_integrity_hint(evidence: VerificationEvidence) -> str:
    health = evidence.health or {}
    analysis = evidence.analysis or {}
    status = str(analysis.get("status") or health.get("status") or "")
    if status in {"extractable", "ok", "complete"}:
        return SOURCE_INTEGRITY_COMPLETE
    if status in {"damaged", "weak"}:
        return SOURCE_INTEGRITY_DAMAGED
    return SOURCE_INTEGRITY_COMPLETE


def _expected_names(evidence: VerificationEvidence) -> list[str]:
    names = []
    for field in ("expected_names", "manifest_names", "item_names", "file_names", "paths"):
        names.extend(_iter_names(evidence.analysis.get(field)))
    result = []
    seen = set()
    for name in names:
        if name in seen:
            continue
        seen.add(name)
        result.append(name)
    return result[:2000]


def _iter_names(value):
    if value is None:
        return
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, dict):
        for key in ("path", "name", "file", "filename"):
            if key in value:
                yield from _iter_names(value.get(key))
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _iter_names(item)
