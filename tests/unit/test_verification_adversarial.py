from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.extraction.result import ExtractionResult
from smart_unpacker.support import sevenzip_native as native
from smart_unpacker.verification import VerificationScheduler


def _task_and_result(tmp_path, analysis=None):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"zip")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    bag = FactBag()
    bag.set("resource.analysis", analysis or {})
    task = ArchiveTask(fact_bag=bag, score=10, key="sample", main_path=str(archive), all_parts=[str(archive)])
    result = ExtractionResult(success=True, archive=str(archive), out_dir=str(out_dir), all_parts=[str(archive)])
    return task, result, out_dir


def _verify(methods, task, result, pass_threshold=70, fail_fast_threshold=40):
    return VerificationScheduler({
        "verification": {
            "enabled": True,
            "initial_score": 100,
            "pass_threshold": pass_threshold,
            "fail_fast_threshold": fail_fast_threshold,
            "methods": methods,
        }
    }).verify(task, result)


def test_pipeline_stops_before_expensive_methods_when_output_is_missing(tmp_path, monkeypatch):
    task, result, out_dir = _task_and_result(tmp_path)
    result.out_dir = str(out_dir / "missing")

    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("archive_test_crc should not run after hard fail")

    monkeypatch.setattr(
        "smart_unpacker.verification.methods.archive_test_crc.cached_read_archive_crc_manifest",
        fail_if_called,
    )

    verification = _verify([
        {"name": "output_presence"},
        {"name": "archive_test_crc"},
    ], task, result)

    assert verification.ok is False
    assert verification.status == "failed"
    assert [step.method for step in verification.steps] == ["output_presence"]


def test_multiple_small_warnings_accumulate_into_verification_failure(tmp_path, monkeypatch):
    task, result, out_dir = _task_and_result(
        tmp_path,
        {
            "expected_names": ["expected-a.txt", "expected-b.txt"],
            "file_count": 5,
            "total_unpacked_size": 10 * 1024 * 1024,
        },
    )
    (out_dir / "only.tmp").write_text("x", encoding="utf-8")
    monkeypatch.setattr(
        "smart_unpacker.verification.methods.archive_test_crc.cached_read_archive_crc_manifest",
        lambda *_args, **_kwargs: native.NativeArchiveCrcManifest(
            status=native.STATUS_UNSUPPORTED,
            is_archive=True,
            encrypted=False,
            damaged=False,
            checksum_error=False,
            item_count=0,
            file_count=0,
            files=[],
            message="unsupported",
        ),
    )
    monkeypatch.setattr(
        "smart_unpacker.verification.methods.sample_readability._sample_directory_readability",
        lambda *_args, **_kwargs: {
            "status": "ok",
            "total_files": 1,
            "sampled_files": 1,
            "readable_files": 1,
            "unreadable_files": 0,
            "empty_files": 1,
            "errors": [],
        },
    )

    verification = _verify([
        {"name": "output_presence", "hard_fail_on_only_transient": False, "only_transient_penalty": 20},
        {"name": "expected_name_presence", "all_missing_penalty": 20},
        {"name": "manifest_size_match"},
        {"name": "archive_test_crc"},
        {"name": "sample_readability"},
    ], task, result)

    assert verification.ok is False
    assert verification.status == "failed_fast"
    assert verification.score < verification.fail_fast_threshold
    assert "archive_test_crc" not in [step.method for step in verification.steps]
    assert {issue.code for issue in verification.issues} >= {
        "fail.output_only_transient_files",
        "fail.expected_names_all_missing",
        "fail.manifest_file_count_under",
        "fail.manifest_size_under",
    }


def test_duplicate_output_basenames_do_not_allow_crc_basename_guess(tmp_path, monkeypatch):
    task, result, out_dir = _task_and_result(tmp_path)
    (out_dir / "a").mkdir()
    (out_dir / "b").mkdir()
    (out_dir / "a" / "same.txt").write_text("a", encoding="utf-8")
    (out_dir / "b" / "same.txt").write_text("b", encoding="utf-8")
    monkeypatch.setattr(
        "smart_unpacker.verification.methods.archive_test_crc.cached_read_archive_crc_manifest",
        lambda *_args, **_kwargs: native.NativeArchiveCrcManifest(
            status=native.STATUS_OK,
            is_archive=True,
            encrypted=False,
            damaged=False,
            checksum_error=False,
            item_count=1,
            file_count=1,
            files=[{"path": "c/same.txt", "size": 1, "has_crc": True, "crc32": 1}],
            message="ok",
        ),
    )
    monkeypatch.setattr(
        "smart_unpacker.verification.methods.archive_test_crc._compute_directory_crc_manifest",
        lambda *_args, **_kwargs: {
            "status": "ok",
            "files": [
                {"path": "a/same.txt", "size": 1, "crc32": 1},
                {"path": "b/same.txt", "size": 1, "crc32": 1},
            ],
            "errors": [],
        },
    )

    verification = _verify([{"name": "archive_test_crc"}], task, result)

    assert verification.ok is False
    assert verification.issues[0].code == "fail.archive_crc_file_missing"


def test_crc_method_skips_when_archive_has_no_crc_entries(tmp_path, monkeypatch):
    task, result, out_dir = _task_and_result(tmp_path)
    (out_dir / "inside.txt").write_text("hello", encoding="utf-8")
    monkeypatch.setattr(
        "smart_unpacker.verification.methods.archive_test_crc.cached_read_archive_crc_manifest",
        lambda *_args, **_kwargs: native.NativeArchiveCrcManifest(
            status=native.STATUS_OK,
            is_archive=True,
            encrypted=False,
            damaged=False,
            checksum_error=False,
            item_count=1,
            file_count=1,
            files=[{"path": "inside.txt", "size": 5, "has_crc": False, "crc32": 0}],
            message="ok",
        ),
    )

    verification = _verify([{"name": "archive_test_crc"}], task, result)

    assert verification.ok is True
    assert verification.steps[0].status == "skipped"


def test_name_presence_sanitizes_nested_dicts_bytes_and_parent_paths(tmp_path):
    task, result, out_dir = _task_and_result(tmp_path)
    (out_dir / "safe").mkdir()
    (out_dir / "safe" / "Name.TXT").write_text("ok", encoding="utf-8")
    task.fact_bag.set("verification.expected_names", [
        {"path": b"../safe/name.txt"},
        {"filename": "./safe//name.txt"},
    ])

    verification = _verify([{"name": "expected_name_presence"}], task, result)

    assert verification.ok is True
    assert verification.steps[0].status == "passed"


def test_sample_readability_backend_failure_is_warning_skip(tmp_path, monkeypatch):
    task, result, out_dir = _task_and_result(tmp_path)
    (out_dir / "inside.txt").write_text("hello", encoding="utf-8")

    def backend_error(*_args, **_kwargs):
        raise RuntimeError("native crashed")

    monkeypatch.setattr(
        "smart_unpacker.verification.methods.sample_readability._sample_directory_readability",
        backend_error,
    )

    verification = _verify([{"name": "sample_readability"}], task, result)

    assert verification.ok is True
    assert verification.steps[0].status == "skipped"
    assert verification.issues[0].code == "warning.sample_readability_backend_error"
