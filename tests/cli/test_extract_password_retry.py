from pathlib import Path
from types import SimpleNamespace

from smart_unpacker.app.cli_context import CliContext
from smart_unpacker.app.cli_reporter import CliReporter
from smart_unpacker.app.commands import extract


def test_wrong_password_failure_detection():
    assert extract.has_wrong_password_failure(["secret.zip [wrong password]"]) is True
    assert extract.has_wrong_password_failure(["secret.zip [密码错误]"]) is True
    assert extract.has_wrong_password_failure(["broken.zip [headers error]"]) is False


def test_extract_prompts_for_password_retry_after_wrong_password(tmp_path, monkeypatch):
    target = tmp_path / "archives"
    target.mkdir()
    attempts = []

    class FakeRunner:
        def __init__(self, config):
            attempts.append(list(config.get("user_passwords", [])))
            self.recent_passwords = []

        def run_targets(self, _target_paths):
            if len(attempts) == 1:
                return SimpleNamespace(success_count=0, failed_tasks=["secret.zip [wrong password]"], processed_keys=["secret"])
            self.recent_passwords = ["secret"]
            return SimpleNamespace(success_count=1, failed_tasks=[], processed_keys=["secret"])

    answers = iter(["y", "secret", ""])
    monkeypatch.setattr(extract, "PipelineRunner", FakeRunner)
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    args = SimpleNamespace(
        paths=[str(target)],
        password=[],
        password_file=None,
        prompt_passwords=False,
        no_builtin_passwords=True,
        recursive_extract=None,
        scheduler_profile=None,
        archive_cleanup_mode=None,
        flatten_single_directory=None,
        json=False,
        quiet=False,
        verbose=False,
    )
    ctx = CliContext(language="en", reporter=CliReporter())

    exit_code, result = extract.handle(args, ctx)

    assert exit_code == 0
    assert attempts == [[], ["secret"]]
    assert result.summary["password_retry_count"] == 1
    assert result.summary["success_count"] == 1
    assert result.errors == []
