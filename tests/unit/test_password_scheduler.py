from types import SimpleNamespace

from smart_unpacker.passwords.cache import PasswordAttemptCache
from smart_unpacker.passwords.candidates import PasswordCandidatePipeline
from smart_unpacker.passwords.job import PasswordJob
from smart_unpacker.passwords.scheduler import PasswordScheduler
from smart_unpacker.passwords.verifier import PasswordBatchVerification


class FakeVerifier:
    def __init__(self, correct_password: str):
        self.correct_password = correct_password
        self.batches: list[list[str]] = []

    def verify_batch(self, archive_path, passwords, *, part_paths=None):
        self.batches.append(list(passwords))
        if self.correct_password in passwords:
            return PasswordBatchVerification(
                ok=True,
                matched_index=passwords.index(self.correct_password),
                attempts=passwords.index(self.correct_password) + 1,
                test_result=SimpleNamespace(returncode=0),
            )
        return PasswordBatchVerification(
            ok=False,
            attempts=len(passwords),
            test_result=SimpleNamespace(returncode=2),
            error_text="wrong password",
        )


def test_password_scheduler_batches_lazy_candidates_and_stops_on_match(tmp_path):
    archive = tmp_path / "sample.7z"
    archive.write_bytes(b"archive")
    verifier = FakeVerifier("secret")
    scheduler = PasswordScheduler(verifier, default_batch_size=2)

    result = scheduler.run(PasswordJob(
        archive_path=str(archive),
        candidates=PasswordCandidatePipeline.from_values(["bad1", "bad2", "secret", "unused"]),
        batch_size=2,
    ))

    assert result.password == "secret"
    assert result.test_result.returncode == 0
    assert verifier.batches == [["bad1", "bad2"], ["secret", "unused"]]


def test_password_scheduler_skips_negative_cache_and_reuses_success(tmp_path):
    archive = tmp_path / "sample.7z"
    archive.write_bytes(b"archive")
    cache = PasswordAttemptCache()
    verifier = FakeVerifier("secret")
    scheduler = PasswordScheduler(verifier, cache=cache, default_batch_size=1)

    first = scheduler.run(PasswordJob(
        archive_path=str(archive),
        candidates=PasswordCandidatePipeline.from_values(["bad", "secret"]),
    ))
    second = scheduler.run(PasswordJob(
        archive_path=str(archive),
        candidates=PasswordCandidatePipeline.from_values(["bad", "secret"]),
    ))

    assert first.password == "secret"
    assert second.password == "secret"
    assert second.stopped_reason == "cache_hit"
    assert verifier.batches == [["bad"], ["secret"]]


def test_password_scheduler_caps_batch_to_max_attempts(tmp_path):
    archive = tmp_path / "sample.7z"
    archive.write_bytes(b"archive")
    verifier = FakeVerifier("secret")
    scheduler = PasswordScheduler(verifier, default_batch_size=10)

    result = scheduler.run(PasswordJob(
        archive_path=str(archive),
        candidates=PasswordCandidatePipeline.from_values(["bad1", "bad2", "secret"]),
        max_attempts=2,
    ))

    assert result.password is None
    assert result.attempts == 2
    assert result.stopped_reason == "max_attempts"
    assert verifier.batches == [["bad1", "bad2"]]


def test_password_scheduler_reports_progress_events(tmp_path):
    archive = tmp_path / "sample.7z"
    archive.write_bytes(b"archive")
    verifier = FakeVerifier("secret")
    scheduler = PasswordScheduler(verifier, default_batch_size=1)
    events = []

    result = scheduler.run(PasswordJob(
        archive_path=str(archive),
        candidates=PasswordCandidatePipeline.from_values(["bad", "secret"]),
        progress_callback=events.append,
    ))

    assert result.password == "secret"
    assert [event.stage for event in events] == [
        "started",
        "batch_started",
        "batch_finished",
        "batch_started",
        "batch_finished",
        "finished",
    ]
    assert events[-1].password_found is True
    assert events[-1].attempts == 2


def test_password_scheduler_honors_timeout_before_verifying_more_candidates(tmp_path):
    archive = tmp_path / "sample.7z"
    archive.write_bytes(b"archive")
    verifier = FakeVerifier("secret")
    scheduler = PasswordScheduler(verifier, default_batch_size=1)

    result = scheduler.run(PasswordJob(
        archive_path=str(archive),
        candidates=PasswordCandidatePipeline.from_values(["bad", "secret"]),
        timeout_seconds=0,
    ))

    assert result.password is None
    assert result.stopped_reason == "timeout"
    assert verifier.batches == []
