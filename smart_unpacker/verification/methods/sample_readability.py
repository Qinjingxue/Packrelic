from smart_unpacker.verification.evidence import VerificationEvidence
from smart_unpacker.verification.registry import register_verification_method
from smart_unpacker.verification.result import VerificationIssue, VerificationStepResult

try:
    from smart_unpacker_native import sample_directory_readability as _sample_directory_readability
except Exception:  # pragma: no cover - depends on optional native build availability
    _sample_directory_readability = None


@register_verification_method("sample_readability")
class SampleReadabilityMethod:
    name = "sample_readability"

    def verify(self, evidence: VerificationEvidence, config: dict) -> VerificationStepResult:
        if _sample_directory_readability is None:
            return VerificationStepResult(
                method=self.name,
                status="skipped",
                issues=[VerificationIssue(
                    method=self.name,
                    code="warning.sample_readability_backend_unavailable",
                    message="Rust sample readability backend is unavailable",
                    path=evidence.output_dir,
                )],
            )

        max_samples = max(1, int(config.get("max_samples", 64) or 64))
        read_bytes = max(1, int(config.get("read_bytes", 4096) or 4096))
        try:
            sample = _sample_directory_readability(evidence.output_dir, max_samples, read_bytes)
        except Exception as exc:
            return VerificationStepResult(
                method=self.name,
                status="skipped",
                issues=[VerificationIssue(
                    method=self.name,
                    code="warning.sample_readability_backend_error",
                    message=f"Rust sample readability backend failed: {exc}",
                    path=evidence.output_dir,
                )],
            )

        status = str(sample.get("status") or "")
        if status != "ok":
            return VerificationStepResult(method=self.name, status="skipped")

        total_files = int(sample.get("total_files", 0) or 0)
        sampled_files = int(sample.get("sampled_files", 0) or 0)
        readable_files = int(sample.get("readable_files", 0) or 0)
        unreadable_files = int(sample.get("unreadable_files", 0) or 0)
        empty_files = int(sample.get("empty_files", 0) or 0)
        errors = list(sample.get("errors") or [])
        if total_files <= 0 or sampled_files <= 0:
            return VerificationStepResult(method=self.name, status="skipped")

        issues: list[VerificationIssue] = []
        score_delta = 0
        hard_fail = False
        if unreadable_files:
            all_unreadable = readable_files == 0
            penalty_name = "all_unreadable_penalty" if all_unreadable else "unreadable_penalty"
            default_penalty = 100 if all_unreadable else 40
            score_delta -= abs(int(config.get(penalty_name, default_penalty) or default_penalty))
            hard_fail = bool(all_unreadable and config.get("hard_fail_on_all_unreadable", True))
            issues.append(VerificationIssue(
                method=self.name,
                code="fail.sample_unreadable",
                message="Some sampled output files could not be read",
                path=evidence.output_dir,
                expected=0,
                actual={
                    "unreadable_files": unreadable_files,
                    "sampled_files": sampled_files,
                    "errors": errors[: int(config.get("max_reported_items", 20) or 20)],
                },
            ))

        if empty_files and empty_files == sampled_files:
            penalty = int(config.get("all_empty_penalty", 20) or 20)
            score_delta -= abs(penalty)
            issues.append(VerificationIssue(
                method=self.name,
                code="warning.sample_all_empty",
                message="All sampled output files are empty",
                path=evidence.output_dir,
                expected="non-empty sample",
                actual={"empty_files": empty_files, "sampled_files": sampled_files},
            ))
        elif empty_files:
            penalty = int(config.get("empty_sample_penalty", 10) or 10)
            score_delta -= abs(penalty)
            issues.append(VerificationIssue(
                method=self.name,
                code="warning.sample_empty_files",
                message="Some sampled output files are empty",
                path=evidence.output_dir,
                expected=0,
                actual={"empty_files": empty_files, "sampled_files": sampled_files},
            ))

        if not issues:
            return VerificationStepResult(method=self.name, status="passed")
        return VerificationStepResult(
            method=self.name,
            status="failed" if hard_fail else "warning",
            score_delta=score_delta,
            issues=issues,
            hard_fail=hard_fail,
        )
