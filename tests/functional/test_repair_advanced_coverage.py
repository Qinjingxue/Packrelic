from __future__ import annotations

import io
from pathlib import Path
import shutil
import struct
import subprocess
import zipfile
import zlib

import pytest

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.run_context import RunContext
from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.coordinator.extraction_batch import ExtractionBatchRunner
from smart_unpacker.coordinator.repair_beam import RepairBeamLoop, RepairBeamState
from smart_unpacker.detection import NestedOutputScanPolicy
from smart_unpacker.extraction.result import ExtractionResult
from smart_unpacker.extraction.scheduler import ExtractionScheduler
from smart_unpacker.repair import RepairJob, RepairScheduler
from smart_unpacker.repair.candidate import RepairCandidate, RepairCandidateBatch
from smart_unpacker.verification import VerificationScheduler


def test_coordinator_real_repair_then_worker_extraction_for_prefixed_7z(tmp_path):
    _require_worker_or_skip()
    inner = _build_7z_archive(tmp_path, {"ok.txt": b"ok"})
    source = tmp_path / "prefixed.7z"
    source.write_bytes(b"SFX-PREFIX" + inner.read_bytes())
    extractor = _FailOnceThenRealExtractor(error="carrier archive prefix is damaged")
    task = _task(source, detected_ext="7z")
    task.fact_bag.set("analysis.selected_format", "7z")
    task.fact_bag.set("analysis.confidence", 0.82)
    config = {
        "repair": {
            "enabled": True,
            "workspace": str(tmp_path / "repair"),
            "max_repair_rounds_per_task": 1,
            "stages": {"deep": True},
            "deep": {"verify_candidates": False, "max_candidates_per_module": 4},
            "modules": [{"name": "archive_carrier_crop_deep_recovery", "enabled": True}],
            "beam": {"enabled": True, "max_rounds": 1},
        },
        "verification": {
            "enabled": True,
            "methods": [
                {"name": "extraction_exit_signal"},
                {"name": "output_presence"},
                {"name": "archive_test_crc"},
            ],
        },
    }
    runner = ExtractionBatchRunner(RunContext(), extractor, NestedOutputScanPolicy({}), config=config)

    try:
        outcome = runner._extract_verify_with_retries(task, str(tmp_path / "out"), runtime_scheduler=None)
    finally:
        extractor.close()

    assert outcome.success is True
    assert extractor.calls == 2
    assert outcome.repair_module == "archive_carrier_crop_deep_recovery"
    assert outcome.verification is not None
    assert outcome.verification.decision_hint == "accept"
    assert (tmp_path / "out" / "ok.txt").read_bytes() == b"ok"


def test_beam_uses_real_verification_coverage_to_pick_less_confident_better_zip(tmp_path):
    source = tmp_path / "source.zip"
    _write_zip(source, {"a.txt": b"a", "b.txt": b"b", "c.txt": b"c"})
    weak = tmp_path / "weak.zip"
    better = tmp_path / "better.zip"
    _write_zip(weak, {"a.txt": b"a"})
    _write_zip(better, {"a.txt": b"a", "b.txt": b"b"})
    task = _task(source, detected_ext="zip")
    verifier = VerificationScheduler({
        "verification": {
            "enabled": True,
            "methods": [{"name": "output_presence"}, {"name": "archive_test_crc"}],
            "partial_accept_threshold": 0.2,
        }
    })

    def assess(item):
        out_dir = tmp_path / f"assess-{item.candidate.module_name}"
        _extract_zip(Path(item.candidate.repaired_input["path"]), out_dir)
        result = ExtractionResult(
            success=True,
            archive=str(item.candidate.repaired_input["path"]),
            out_dir=str(out_dir),
            all_parts=[str(item.candidate.repaired_input["path"])],
        )
        return verifier.verify(task, result)

    run = RepairBeamLoop(
        _StaticCandidateScheduler([
            _candidate("weak_high_confidence", weak, 0.95),
            _candidate("better_low_confidence", better, 0.55),
        ]),
        beam_width=2,
        max_candidates_per_state=2,
        max_analyze_candidates=2,
        max_assess_candidates=2,
        analyze=lambda candidate: {"confidence": candidate.confidence},
        assess=assess,
    ).run([
        RepairBeamState(
            source_input={"kind": "file", "path": str(source), "format_hint": "zip"},
            format="zip",
            archive_state=task.archive_state().to_dict(),
            archive_key="beam-real-verification",
        )
    ], max_rounds=1)

    assert run.best_state is not None
    assert run.best_state.history[-1]["module"] == "better_low_confidence"
    assert run.best_state.completeness == pytest.approx(2 / 3, abs=0.02)


def test_zip_conflict_resolver_rejects_traversal_and_keeps_safe_duplicate(tmp_path):
    source = tmp_path / "adversarial.zip"
    source.write_bytes(b"".join([
        _raw_stored_local_entry("../evil.txt", b"evil"),
        _raw_stored_local_entry("dup.txt", b"bad", crc32=0),
        _raw_stored_local_entry("dup.txt", b"good"),
    ]))
    result = _run_single_module_repair(
        tmp_path,
        "zip_conflict_resolver_rebuild",
        "zip",
        source,
        ["duplicate_entries", "overlapping_entries", "local_header_conflict", "damaged"],
    )

    assert result.status == "partial"
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.namelist() == ["dup.txt"]
        assert archive.read("dup.txt") == b"good"


def test_deep_module_input_size_limit_blocks_large_nested_salvage(tmp_path):
    inner = _zip_bytes({"inner.txt": b"payload"})
    source = tmp_path / "oversize-carrier.bin"
    source.write_bytes((b"x" * 4096) + inner)
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "stages": {"deep": True},
            "deep": {"max_input_size_mb": 0.001},
            "modules": [{"name": "archive_nested_payload_salvage", "enabled": True}],
        }
    })

    result = scheduler.repair(RepairJob(
        source_input={"kind": "file", "path": str(source)},
        format="zip",
        confidence=0.82,
        damage_flags=["outer_container_bad", "nested_archive", "damaged"],
        archive_key="oversize-carrier",
    ))

    assert result.ok is False
    modules = result.diagnosis["capability_decision"]["modules"]
    nested = next(item for item in modules if item["name"] == "archive_nested_payload_salvage")
    assert "deep_input_size_blocked" in nested["reasons"]


def test_deep_candidate_cap_limits_nested_payload_salvage_outputs(tmp_path):
    first = _zip_bytes({"first.txt": b"1"})
    second = _zip_bytes({"second.txt": b"2"})
    source = tmp_path / "two-nested.bin"
    source.write_bytes(b"prefix" + first + b"middle" + second + b"tail")
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "stages": {"deep": True},
            "deep": {"max_candidates_per_module": 1, "verify_candidates": False},
            "modules": [{"name": "archive_nested_payload_salvage", "enabled": True}],
        }
    })

    batch = scheduler.generate_repair_candidates(RepairJob(
        source_input={"kind": "file", "path": str(source)},
        format="zip",
        confidence=0.82,
        damage_flags=["outer_container_bad", "nested_archive", "damaged"],
        archive_key="two-nested",
    ))

    assert len(batch.candidates) == 1
    assert batch.candidates[0].module_name == "archive_nested_payload_salvage"


class _FailOnceThenRealExtractor:
    password_session = None

    def __init__(self, *, error: str = "zip end of central directory is missing"):
        self.calls = 0
        self.error = error
        self.real = ExtractionScheduler(max_retries=1, process_config={"persistent_workers": False})
        self.password_session = self.real.password_session

    def close(self) -> None:
        self.real.close()

    def default_output_dir_for_task(self, task):
        return str(Path(task.main_path).with_suffix(""))

    def inspect(self, task, out_dir):
        return type("Preflight", (), {"skip_result": None})()

    def extract(self, task, out_dir, runtime_scheduler=None):
        self.calls += 1
        if self.calls == 1:
            return ExtractionResult(
                success=False,
                archive=task.main_path,
                out_dir=out_dir,
                all_parts=[task.main_path],
                error=self.error,
                diagnostics={
                    "failure_stage": "archive_open",
                    "failure_kind": "structure_recognition",
                    "result": {
                        "status": "failed",
                        "native_status": "damaged",
                        "failure_stage": "archive_open",
                        "failure_kind": "structure_recognition",
                    },
                },
            )
        return self.real.extract(task, out_dir, runtime_scheduler=runtime_scheduler)


class _StaticCandidateScheduler:
    def __init__(self, candidates):
        self.candidates = list(candidates)

    def generate_repair_candidates(self, job, *, lazy=False):
        return RepairCandidateBatch(candidates=list(self.candidates))


def _candidate(module_name: str, path: Path, confidence: float) -> RepairCandidate:
    return RepairCandidate(
        module_name=module_name,
        format="zip",
        repaired_input={"kind": "file", "path": str(path), "format_hint": "zip"},
        confidence=confidence,
        status="partial",
        stage="deep",
        actions=[module_name],
        workspace_paths=[str(path)],
    )


def _task(path: Path, *, detected_ext: str = "zip") -> ArchiveTask:
    bag = FactBag()
    bag.set("candidate.entry_path", str(path))
    bag.set("candidate.member_paths", [str(path)])
    bag.set("file.detected_ext", detected_ext)
    return ArchiveTask(
        fact_bag=bag,
        score=10,
        key=path.name,
        main_path=str(path),
        all_parts=[str(path)],
        logical_name=path.stem,
        detected_ext=detected_ext,
    ).ensure_archive_state()


def _run_single_module_repair(tmp_path: Path, module_name: str, fmt: str, source: Path, flags: list[str]):
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "stages": {"deep": True},
            "deep": {"verify_candidates": False, "max_candidates_per_module": 4},
            "modules": [{"name": module_name, "enabled": True}],
        }
    })
    return scheduler.repair(RepairJob(
        source_input={"kind": "file", "path": str(source)},
        format=fmt,
        confidence=0.82,
        damage_flags=flags,
        archive_key=source.name,
    ))


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


def _write_zip(path: Path, entries: dict[str, bytes]) -> None:
    path.write_bytes(_zip_bytes(entries))


def _extract_zip(path: Path, out_dir: Path) -> None:
    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True)
    with zipfile.ZipFile(path) as archive:
        archive.extractall(out_dir)


def _raw_stored_local_entry(name: str, payload: bytes, *, crc32: int | None = None) -> bytes:
    encoded = name.encode("utf-8")
    crc = zlib.crc32(payload) & 0xFFFFFFFF if crc32 is None else crc32
    return (
        struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            0,
            0,
            0,
            0,
            crc,
            len(payload),
            len(payload),
            len(encoded),
            0,
        )
        + encoded
        + payload
    )


def _build_7z_archive(tmp_path: Path, entries: dict[str, bytes]) -> Path:
    seven_zip = _require_7z_tool_or_skip()
    source_dir = tmp_path / "seven-src"
    source_dir.mkdir()
    for name, payload in entries.items():
        target = source_dir / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    output = tmp_path / "inner.7z"
    subprocess.run(
        [str(seven_zip), "a", "-t7z", str(output.resolve()), *entries.keys()],
        cwd=str(source_dir),
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return output


def _require_7z_tool_or_skip() -> Path:
    candidate = Path("tools") / "7z.exe"
    if candidate.is_file():
        return candidate.resolve()
    found = shutil.which("7z")
    if found:
        return Path(found)
    pytest.skip("7z executable is required for coordinator real worker coverage")


def _require_worker_or_skip() -> None:
    missing = [
        name
        for name in ("sevenzip_worker.exe", "7z.dll")
        if not (Path("tools") / name).is_file()
    ]
    if missing:
        pytest.skip(f"{', '.join(missing)} is required for coordinator real worker coverage")
