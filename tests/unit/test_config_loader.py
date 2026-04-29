import json

from sunpack.config import loader


def test_load_config_merges_simple_config_over_advanced_config(tmp_path, monkeypatch):
    simple = tmp_path / "sunpack_config.json"
    advanced = tmp_path / "sunpack_advanced_config.json"
    advanced.write_text(json.dumps({
        "cli": {"language": "en"},
        "thresholds": {"archive_score_threshold": 6, "maybe_archive_threshold": 3},
        "recursive_extract": "*",
        "post_extract": {"archive_cleanup_mode": "r", "flatten_single_directory": True},
        "filesystem": {
            "directory_scan_mode": "*",
            "scan_filters_enabled": True,
            "scan_filters": [{"name": "size_range", "enabled": True, "range": "r >= 1 MB"}],
        },
        "performance": {
            "scheduler_profile": "auto",
            "max_extract_task_seconds": 1800,
        },
        "detection": {
            "enabled": True,
            "fact_collectors": [{"name": "file_facts", "enabled": True}],
            "processors": [],
            "rule_pipeline": {
                "precheck": [],
                "scoring": [{"name": "extension", "enabled": True}],
                "confirmation": [],
            },
        },
    }), encoding="utf-8")
    simple.write_text(json.dumps({
        "cli": {"language": "zh"},
        "filesystem": {
            "scan_filters": [{"name": "size_range", "enabled": True, "range": "r >= 2 MB"}],
        },
        "performance": {"scheduler_profile": "conservative"},
    }), encoding="utf-8")

    def candidate_paths(filename):
        return [simple if filename == loader.SIMPLE_CONFIG_FILENAME else advanced]

    monkeypatch.setattr(loader, "_candidate_config_paths", candidate_paths)

    config = loader.load_config()

    assert config["cli"]["language"] == "zh"
    assert config["filesystem"]["directory_scan_mode"] == "recursive"
    assert config["filesystem"]["scan_filters"] == [{"name": "size_range", "enabled": True, "range": "r >= 2 MB"}]
    assert config["performance"]["scheduler_profile"] == "conservative"
    assert config["performance"]["max_extract_task_seconds"] == 1800
    assert config["detection"]["enabled"] is True


def test_effective_config_payload_returns_merged_external_config(tmp_path, monkeypatch):
    simple = tmp_path / "sunpack_config.json"
    advanced = tmp_path / "sunpack_advanced_config.json"
    advanced.write_text(json.dumps({
        "thresholds": {"archive_score_threshold": 6, "maybe_archive_threshold": 3},
        "recursive_extract": "*",
        "post_extract": {"archive_cleanup_mode": "r", "flatten_single_directory": True},
        "filesystem": {"directory_scan_mode": "*", "scan_filters": []},
        "detection": {
            "enabled": True,
            "rule_pipeline": {
                "precheck": [],
                "scoring": [{"name": "extension", "enabled": True}],
                "confirmation": [],
            },
        },
    }), encoding="utf-8")
    simple.write_text(json.dumps({"recursive_extract": "2"}), encoding="utf-8")

    def candidate_paths(filename):
        return [simple if filename == loader.SIMPLE_CONFIG_FILENAME else advanced]

    monkeypatch.setattr(loader, "_candidate_config_paths", candidate_paths)

    path, payload = loader.load_effective_config_payload()

    assert path == simple
    assert payload["recursive_extract"] == "2"
    assert payload["filesystem"]["directory_scan_mode"] == "*"
