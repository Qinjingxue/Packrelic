import json

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.run_context import RunContext
from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.coordinator.extraction_batch import ExtractionBatchRunner
from smart_unpacker.extraction.result import ExtractionResult
from smart_unpacker.verification import VerificationScheduler


def test_partial_extraction_manifest_produces_accept_partial_assessment(tmp_path):
    archive = tmp_path / "broken.zip"
    archive.write_bytes(b"broken")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    good = out_dir / "good.txt"
    bad = out_dir / "bad.bin"
    good.write_text("ok", encoding="utf-8")
    bad.write_bytes(b"partial")
    manifest = _write_manifest(
        out_dir,
        archive,
        [
            {"path": str(good), "archive_path": "good.txt", "status": "complete", "bytes_written": 2, "expected_size": 2},
            {"path": str(bad), "archive_path": "bad.bin", "status": "failed", "bytes_written": 0, "expected_size": 20},
        ],
    )
    result = ExtractionResult(
        success=False,
        archive=str(archive),
        out_dir=str(out_dir),
        all_parts=[str(archive)],
        error="crc error",
        partial_outputs=True,
        progress_manifest=str(manifest),
        diagnostics={"result": {"failure_stage": "item_extract", "failure_kind": "checksum_error", "native_status": "damaged"}},
    )

    verification = VerificationScheduler({
        "verification": {
            "enabled": True,
            "methods": [{"name": "extraction_exit_signal"}],
        }
    }).verify(_task(archive), result)

    assert verification.decision_hint == "accept_partial"
    assert verification.assessment_status == "partial"
    assert verification.source_integrity == "payload_damaged"
    assert verification.completeness == 0.5
    assert verification.complete_files == 1
    assert verification.failed_files == 1


def test_output_presence_ignores_sunpack_manifest_files(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"zip")
    out_dir = tmp_path / "out"
    (out_dir / ".sunpack").mkdir(parents=True)
    (out_dir / ".sunpack" / "extraction_manifest.json").write_text("{}", encoding="utf-8")
    result = ExtractionResult(success=True, archive=str(archive), out_dir=str(out_dir), all_parts=[str(archive)])

    verification = VerificationScheduler({
        "verification": {
            "enabled": True,
            "methods": [{"name": "output_presence"}],
        }
    }).verify(_task(archive), result)

    assert verification.decision_hint == "fail"
    assert verification.issues[0].code == "fail.output_empty"


def test_main_flow_accepts_recoverable_partial_after_repair_has_no_candidate(tmp_path):
    archive = tmp_path / "broken.zip"
    archive.write_bytes(b"broken")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    good = out_dir / "good.txt"
    partial = out_dir / "partial.bin"
    failed = out_dir / "failed.bin"
    good.write_text("ok", encoding="utf-8")
    partial.write_bytes(b"half")
    failed.write_bytes(b"bad")
    manifest = _write_manifest(
        out_dir,
        archive,
        [
            {"path": str(good), "archive_path": "good.txt", "status": "complete", "bytes_written": 2, "expected_size": 2},
            {"path": str(partial), "archive_path": "partial.bin", "status": "partial", "bytes_written": 4, "expected_size": 8},
            {"path": str(failed), "archive_path": "failed.bin", "status": "failed", "bytes_written": 0, "expected_size": 10},
        ],
    )
    result = ExtractionResult(
        success=False,
        archive=str(archive),
        out_dir=str(out_dir),
        all_parts=[str(archive)],
        error="crc error",
        partial_outputs=True,
        progress_manifest=str(manifest),
        diagnostics={"result": {"failure_stage": "item_extract", "failure_kind": "checksum_error", "native_status": "damaged"}},
    )
    runner = ExtractionBatchRunner(
        RunContext(),
        _SingleResultExtractor(result),
        _FakeOutputScanPolicy(),
        config={
            "repair": {"enabled": True, "workspace": str(tmp_path / "repair"), "max_repair_rounds_per_task": 1},
            "verification": {
                "enabled": True,
                "methods": [{"name": "extraction_exit_signal"}],
                "partial_min_completeness": 0.1,
            },
        },
    )
    runner.repair_stage = _NoCandidateRepairStage()

    task = _task(archive)
    outcome = runner._extract_verify_with_retries(task, str(out_dir), runtime_scheduler=None)

    assert outcome.success is True
    assert outcome.verification is not None
    assert outcome.verification.decision_hint == "accept_partial"
    assert good.exists()
    assert not partial.exists()
    assert not failed.exists()
    assert runner.collect_result(task, outcome) == str(out_dir)
    assert runner.context.partial_success_count == 1
    recovered = runner.context.recovered_outputs[0]
    assert recovered["archive_coverage"]["expected_files"] == 3
    report = json.loads((out_dir / ".sunpack" / "recovery_report.json").read_text(encoding="utf-8"))
    assert report["success_kind"] == "partial"
    assert report["archive_coverage"]["expected_files"] == 3
    file_statuses = {item["archive_path"]: item["status"] for item in report["files"]}
    assert file_statuses["good.txt"] == "complete"
    assert file_statuses["partial.bin"] == "discarded"
    assert file_statuses["failed.bin"] == "failed"
    assert {item["user_action"] for item in report["files"]} >= {"safe_to_use", "discarded_low_quality", "not_recovered"}
    manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert manifest_payload["recovery"]["verification"]["decision_hint"] == "accept_partial"


class _SingleResultExtractor:
    password_session = None

    def __init__(self, result):
        self.result = result

    def default_output_dir_for_task(self, task):
        return self.result.out_dir

    def inspect(self, task, out_dir):
        return type("Preflight", (), {"skip_result": None})()

    def extract(self, task, out_dir, runtime_scheduler=None):
        return self.result


class _FakeOutputScanPolicy:
    def scan_roots_from_outputs(self, outputs):
        return list(outputs)


class _NoCandidateRepairStage:
    config = {
        "max_repair_rounds_per_task": 1,
        "max_repair_seconds_per_task": 120.0,
        "max_repair_generated_files_per_task": 16,
        "max_repair_generated_mb_per_task": 2048.0,
    }

    def repair_after_extraction_failure_result(self, task, result):
        return None


def _task(path):
    return ArchiveTask(
        fact_bag=FactBag(),
        score=10,
        key=path.name,
        main_path=str(path),
        all_parts=[str(path)],
        logical_name=path.stem,
        detected_ext=path.suffix.lstrip("."),
    )


def _write_manifest(out_dir, archive, files):
    summary = {"complete": 0, "partial": 0, "failed": 0, "skipped": 0, "unverified": 0, "total": len(files)}
    for item in files:
        summary[item["status"]] += 1
    manifest = out_dir / ".sunpack" / "extraction_manifest.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps({
        "version": 1,
        "archive": str(archive),
        "out_dir": str(out_dir),
        "partial_outputs": True,
        "failure_stage": "item_extract",
        "failure_kind": "checksum_error",
        "native_status": "damaged",
        "summary": summary,
        "files": files,
    }, ensure_ascii=False), encoding="utf-8")
    return manifest
