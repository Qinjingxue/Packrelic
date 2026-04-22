import json
import os
import shutil
from functools import lru_cache
from pathlib import Path


TESTS_ROOT = Path(__file__).resolve().parent
REPO_ROOT = TESTS_ROOT.parent
CONFIG_PATH = TESTS_ROOT / "test_config.json"


@lru_cache(maxsize=1)
def load_test_config():
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def _resolve_candidate(candidate: str):
    if candidate.startswith("env:"):
        value = os.environ.get(candidate[4:])
        return Path(value).expanduser() if value else None

    if candidate.startswith("cmd:"):
        value = shutil.which(candidate[4:])
        return Path(value) if value else None

    path = Path(candidate).expanduser()
    if not path.is_absolute():
        path = REPO_ROOT / path
    return path


def resolve_first_existing(candidates):
    for candidate in candidates:
        path = _resolve_candidate(candidate)
        if path and path.is_file():
            return path
    return None


def get_reports_dir():
    raw = load_test_config()["paths"]["reports_dir"]
    path = Path(raw)
    if not path.is_absolute():
        path = REPO_ROOT / path
    return path


def get_temp_root():
    raw = load_test_config()["paths"].get("temp_root")
    if not raw:
        return None
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = REPO_ROOT / path
    return path


def make_tempdir_kwargs():
    temp_root = get_temp_root()
    if temp_root is None:
        return {}
    temp_root.mkdir(parents=True, exist_ok=True)
    return {"dir": str(temp_root)}


def get_test_tools():
    config = load_test_config()
    return {
        "seven_zip": resolve_first_existing(config["tools"]["seven_zip_candidates"]),
        "seven_zip_sfx": resolve_first_existing(config["tools"]["seven_zip_sfx_candidates"]),
        "rar_exe": resolve_first_existing(config["tools"]["rar_candidates"]),
    }
