from typing import Any

from smart_unpacker.support.sevenzip_native import (
    STATUS_BACKEND_UNAVAILABLE,
    STATUS_DAMAGED,
    STATUS_OK,
    STATUS_UNSUPPORTED,
    STATUS_WRONG_PASSWORD,
    cached_read_archive_crc_manifest,
)
from smart_unpacker.verification.evidence import VerificationEvidence
from smart_unpacker.verification.methods._archive_output_match import coverage_details, coverage_from_archive_and_output
from smart_unpacker.verification.registry import register_verification_method
from smart_unpacker.verification.result import (
    DECISION_REPAIR,
    SOURCE_INTEGRITY_COMPLETE,
    SOURCE_INTEGRITY_DAMAGED,
    SOURCE_INTEGRITY_PAYLOAD_DAMAGED,
    VerificationIssue,
    VerificationStepResult,
)

try:
    from smart_unpacker_native import compute_directory_crc_manifest as _compute_directory_crc_manifest
except Exception:  # pragma: no cover - depends on optional native build availability
    _compute_directory_crc_manifest = None


@register_verification_method("archive_test_crc")
class ArchiveTestCrcMethod:
    name = "archive_test_crc"

    def verify(self, evidence: VerificationEvidence, config: dict) -> VerificationStepResult:
        max_items = max(0, int(config.get("max_items", 200000) or 0))
        try:
            archive_manifest = cached_read_archive_crc_manifest(
                evidence.archive_path,
                password=evidence.password or "",
                part_paths=evidence.archive_parts or [evidence.archive_path],
                max_items=max_items,
            )
        except Exception as exc:
            return VerificationStepResult(
                method=self.name,
                status="skipped",
                issues=[VerificationIssue(
                    method=self.name,
                    code="warning.archive_crc_backend_unavailable",
                    message=f"Archive CRC backend is unavailable: {exc}",
                    path=evidence.archive_path,
                )],
            )

        archive_status_result = self._archive_status_result(archive_manifest, evidence)
        if archive_status_result is not None:
            return archive_status_result

        archive_files = [item for item in archive_manifest.files if isinstance(item, dict) and item.get("path")]
        if not archive_files:
            return VerificationStepResult(method=self.name, status="skipped")
        if _compute_directory_crc_manifest is None:
            return VerificationStepResult(
                method=self.name,
                status="skipped",
                issues=[VerificationIssue(
                    method=self.name,
                    code="warning.output_crc_backend_unavailable",
                    message="Rust output CRC backend is unavailable",
                    path=evidence.output_dir,
                )],
            )

        try:
            output_manifest = _compute_directory_crc_manifest(evidence.output_dir, max_items)
        except Exception as exc:
            return VerificationStepResult(
                method=self.name,
                status="skipped",
                issues=[VerificationIssue(
                    method=self.name,
                    code="warning.output_crc_backend_error",
                    message=f"Output CRC backend failed: {exc}",
                    path=evidence.output_dir,
                )],
            )

        status = str(output_manifest.get("status") or "")
        if status != "ok":
            return VerificationStepResult(method=self.name, status="skipped")

        mismatches = []
        missing = []
        issue_by_path: dict[str, list[VerificationIssue]] = {}
        for item in archive_files:
            expected_path = str(item.get("path") or "")
            output_item = _output_by_path_or_name(output_manifest.get("files") or [], expected_path)
            if output_item is None:
                missing.append(expected_path)
            elif bool(item.get("has_crc", False)) and item.get("crc32") is not None and output_item.get("crc32") is not None:
                expected_crc = _as_u32(item.get("crc32"))
                actual_crc = _as_u32(output_item.get("crc32"))
                if expected_crc != actual_crc:
                    mismatches.append({
                        "path": expected_path,
                        "expected_crc32": expected_crc,
                        "actual_crc32": actual_crc,
                    })

        issues: list[VerificationIssue] = []
        if mismatches:
            issue = VerificationIssue(
                method=self.name,
                code="fail.archive_crc_mismatch",
                message="Output file CRC does not match archive manifest CRC",
                path=evidence.output_dir,
                expected=len(archive_files),
                actual=mismatches[: int(config.get("max_reported_items", 20) or 20)],
            )
            issues.append(issue)
            for item in mismatches:
                issue_by_path.setdefault(str(item.get("path") or ""), []).append(issue)
        if missing:
            issue = VerificationIssue(
                method=self.name,
                code="fail.archive_crc_file_missing",
                message="Some archive CRC entries were not found in extraction output",
                path=evidence.output_dir,
                expected=len(archive_files),
                actual=missing[: int(config.get("max_reported_items", 20) or 20)],
            )
            issues.append(issue)
            for path in missing:
                issue_by_path.setdefault(str(path), []).append(issue)

        coverage = coverage_from_archive_and_output(
            archive_files,
            list(output_manifest.get("files") or []),
            method=self.name,
            issues_by_path=issue_by_path,
        )

        if not issues:
            return VerificationStepResult(
                method=self.name,
                status="passed",
                completeness_hint=coverage.completeness,
                source_integrity_hint=SOURCE_INTEGRITY_COMPLETE,
                file_observations=coverage.observations,
                issues=[VerificationIssue(
                    method=self.name,
                    code="info.archive_output_coverage",
                    message="Archive files were matched against extraction output",
                    path=evidence.output_dir,
                    expected=coverage.expected_files,
                    actual=coverage_details(coverage),
                )],
            )
        issues.append(VerificationIssue(
            method=self.name,
            code="info.archive_output_coverage",
            message="Archive files were matched against extraction output",
            path=evidence.output_dir,
            expected=coverage.expected_files,
            actual=coverage_details(coverage),
        ))
        return VerificationStepResult(
            method=self.name,
            status="failed",
            issues=issues,
            completeness_hint=coverage.completeness,
            source_integrity_hint=SOURCE_INTEGRITY_COMPLETE,
            decision_hint=DECISION_REPAIR,
            file_observations=coverage.observations,
        )

    def _archive_status_result(self, archive_manifest, evidence: VerificationEvidence) -> VerificationStepResult | None:
        if archive_manifest.status == STATUS_OK and archive_manifest.ok:
            return None
        if archive_manifest.status in {STATUS_BACKEND_UNAVAILABLE, STATUS_UNSUPPORTED}:
            return VerificationStepResult(
                method=self.name,
                status="skipped",
                issues=[VerificationIssue(
                    method=self.name,
                    code="warning.archive_crc_unsupported",
                    message=archive_manifest.message,
                    path=evidence.archive_path,
                )],
            )
        if archive_manifest.status == STATUS_WRONG_PASSWORD:
            return VerificationStepResult(
                method=self.name,
                status="failed",
                issues=[VerificationIssue(
                    method=self.name,
                    code="fail.archive_crc_wrong_password",
                    message=archive_manifest.message,
                    path=evidence.archive_path,
                )],
            )
        if archive_manifest.status == STATUS_DAMAGED or archive_manifest.checksum_error or archive_manifest.damaged:
            return VerificationStepResult(
                method=self.name,
                status="failed",
                completeness_hint=None,
                source_integrity_hint=SOURCE_INTEGRITY_PAYLOAD_DAMAGED if archive_manifest.checksum_error else SOURCE_INTEGRITY_DAMAGED,
                decision_hint=DECISION_REPAIR,
                issues=[VerificationIssue(
                    method=self.name,
                    code="fail.archive_crc_test_failed",
                    message=archive_manifest.message,
                    path=evidence.archive_path,
                )],
            )
        return VerificationStepResult(
            method=self.name,
            status="skipped",
            issues=[VerificationIssue(
                method=self.name,
                code="warning.archive_crc_unknown_status",
                message=archive_manifest.message,
                path=evidence.archive_path,
                actual=archive_manifest.status,
            )],
        )


def _output_by_path_or_name(files: list[dict], expected_path: str) -> dict | None:
    from smart_unpacker.support.path_names import clean_relative_archive_path, normalize_match_name, normalize_match_path
    import os

    normalized = normalize_match_path(clean_relative_archive_path(expected_path))
    basename = normalize_match_name(os.path.basename(normalized))
    name_matches = []
    for item in files:
        if not isinstance(item, dict):
            continue
        path = clean_relative_archive_path(item.get("path"))
        if normalize_match_path(path) == normalized:
            return item
        if normalize_match_name(os.path.basename(path)) == basename:
            name_matches.append(item)
    return name_matches[0] if len(name_matches) == 1 else None


def _as_u32(value: Any) -> int:
    try:
        return int(value or 0) & 0xFFFFFFFF
    except (TypeError, ValueError):
        return 0
