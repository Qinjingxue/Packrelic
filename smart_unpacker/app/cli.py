from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict

from smart_unpacker.core.engine import DecompressionEngine
from smart_unpacker.detection.defaults import build_default_config_payload
from smart_unpacker.support.passwords import dedupe_passwords, read_password_file
from smart_unpacker.support.resources import ResourceLocator
from smart_unpacker.support.types import CliCommandResult, CliInspectItem, CliPasswordSummary, CliScanItem


EXIT_OK = 0
EXIT_TASK_FAILED = 1
EXIT_USAGE = 2
EXIT_RUNTIME = 3

CONFIG_SET_KEYS = {
    "min_inspection_size_bytes",
    "recursive_extract",
    "scheduler_profile",
    "archive_cleanup_mode",
    "flatten_single_directory",
}
SCHEDULER_PROFILES = {"auto", "conservative", "aggressive"}
ARCHIVE_CLEANUP_MODES = {"keep", "recycle", "delete"}


def configure_stdio_fallback() -> None:
    """Avoid UnicodeEncodeError on legacy Windows consoles in CI."""
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            if getattr(stream, "errors", None) != "backslashreplace":
                reconfigure(errors="backslashreplace")
        except Exception:
            continue


class CliReporter:
    def __init__(self, json_mode: bool = False, quiet: bool = False, verbose: bool = False):
        self.json_mode = json_mode
        self.quiet = quiet
        self.verbose = verbose
        self.logs: list[str] = []

    def log(self, message: str) -> None:
        self.logs.append(message)
        if not self.json_mode and not self.quiet:
            print(message, flush=True)

    def info(self, message: str) -> None:
        if not self.json_mode and not self.quiet:
            print(message, flush=True)

    def detail(self, message: str) -> None:
        if not self.json_mode and self.verbose and not self.quiet:
            print(message, flush=True)

    def error(self, message: str) -> None:
        if not self.json_mode:
            print(message, file=sys.stderr, flush=True)

    def emit_result(self, result: CliCommandResult) -> None:
        if self.json_mode:
            print(json.dumps(asdict(result), ensure_ascii=False, indent=2), flush=True)


def resolve_common_root(paths):
    normalized_paths = [os.path.normpath(path) for path in paths if path]
    if not normalized_paths:
        return os.getcwd()
    try:
        common_root = os.path.commonpath(normalized_paths)
    except ValueError:
        first = normalized_paths[0]
        common_root = first if os.path.isdir(first) else os.path.dirname(first)
    if os.path.isfile(common_root):
        common_root = os.path.dirname(common_root)
    return common_root or os.getcwd()


def preprocess_sys_argv(argv: list[str]) -> list[str]:
    cleaned = []
    for arg in argv:
        if not isinstance(arg, str):
            cleaned.append(arg)
            continue
        merged_flags = re.match(r'^(.*)"\s+(--.+)$', arg)
        if merged_flags:
            path = merged_flags.group(1)
            if path.endswith("\\"):
                path = path[:-1]
            cleaned.append(path)
            cleaned.extend(part for part in merged_flags.group(2).split(" ") if part)
            continue
        if arg.endswith('"'):
            path = arg[:-1]
            if path.endswith("\\"):
                path = path[:-1]
            cleaned.append(path)
            continue
        cleaned.append(arg)
    return cleaned


def build_common_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--json", action="store_true", help="以 JSON 格式输出结果。")
    parser.add_argument("--quiet", action="store_true", help="减少终端输出，仅保留必要信息。")
    parser.add_argument("--verbose", action="store_true", help="输出更详细的终端信息。")
    pause_group = parser.add_mutually_exclusive_group()
    pause_group.add_argument("--no-pause", action="store_true", help="命令结束后不暂停。")
    pause_group.add_argument("--pause-on-exit", action="store_true", help="命令结束后等待按键退出。")
    return parser


def build_password_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-p", "--password", action="append", default=[], help="解压密码，可重复传入多次。")
    parser.add_argument("--password-file", help="密码列表文件路径，按每行一个密码读取。")
    parser.add_argument("--prompt-passwords", action="store_true", help="通过终端交互输入密码列表。")
    parser.add_argument("--no-builtin-passwords", action="store_true", help="禁用内置的高频密码表进行尝试。")
    return parser


def parse_non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("必须是非负整数。") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("必须是非负整数。")
    return parsed


def parse_bool_value(value: str) -> bool:
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "y", "on", "启用", "是"}:
        return True
    if normalized in {"0", "false", "no", "n", "off", "禁用", "否"}:
        return False
    raise argparse.ArgumentTypeError("必须是 true/false、yes/no、1/0。")


def parse_recursive_extract_value(value: str):
    normalized = str(value).strip()
    if normalized in {"*", "?"}:
        return normalized
    if normalized.isdigit() and int(normalized) > 0:
        return int(normalized)
    raise argparse.ArgumentTypeError('必须是正整数、"*" 或 "?"。')


def build_runtime_config_override_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--min-inspection-size-bytes", type=parse_non_negative_int, help="仅本次运行覆盖最小检测大小。")
    parser.add_argument("--recursive-extract", type=parse_recursive_extract_value, help='仅本次运行覆盖递归解压模式，取值为正整数、"*" 或 "?"。')
    parser.add_argument("--scheduler-profile", choices=sorted(SCHEDULER_PROFILES), help="仅本次运行覆盖并发调度档位。")
    parser.add_argument("--archive-cleanup-mode", choices=sorted(ARCHIVE_CLEANUP_MODES), help="仅本次运行覆盖原归档后处理方式。")
    flatten_group = parser.add_mutually_exclusive_group()
    flatten_group.add_argument("--flatten-single-directory", dest="flatten_single_directory", action="store_true", default=None, help="仅本次运行启用单子目录压平。")
    flatten_group.add_argument("--no-flatten-single-directory", dest="flatten_single_directory", action="store_false", help="仅本次运行禁用单子目录压平。")
    return parser


def build_cli_parser():
    common_parser = build_common_parser()
    password_parser = build_password_parser()
    runtime_config_parser = build_runtime_config_override_parser()

    parser = argparse.ArgumentParser(
        description="智能解压工具：命令行模式。",
        usage=(
            "SmartUnpacker [-h] <command> [command options] [paths...]\n"
        ),
        epilog=(
            "示例:\n"
            "  SmartUnpacker extract C:\\Archives\n"
            "  SmartUnpacker inspect .\\fixtures\n"
            "  SmartUnpacker passwords --prompt-passwords\n"
            "\n"
            "查看某个子命令的完整参数:\n"
            "  SmartUnpacker <command> -h"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    extract_parser = subparsers.add_parser(
        "extract",
        parents=[common_parser, password_parser, runtime_config_parser],
        help="执行预检查、扫描、解压和清理。",
        usage="SmartUnpacker extract [options] <paths...>",
    )
    extract_parser.add_argument("paths", nargs="+", help="要处理的文件或目录路径。")

    scan_parser = subparsers.add_parser(
        "scan",
        parents=[common_parser, runtime_config_parser],
        help="只扫描候选归档，不修改文件系统。",
        usage="SmartUnpacker scan [options] <paths...>",
    )
    scan_parser.add_argument("paths", nargs="+", help="要扫描的文件或目录路径。")

    inspect_parser = subparsers.add_parser(
        "inspect",
        parents=[common_parser, runtime_config_parser],
        help="输出文件检测详情，不修改文件系统。",
        usage="SmartUnpacker inspect [options] <paths...>",
    )
    inspect_parser.add_argument("paths", nargs="+", help="要检查的文件或目录路径。")

    subparsers.add_parser(
        "passwords",
        parents=[common_parser, password_parser],
        help="查看当前会参与尝试的密码列表。",
        usage="SmartUnpacker passwords [options]",
    )

    config_parser = subparsers.add_parser(
        "config",
        parents=[common_parser],
        help="查看或修改 smart_unpacker_config.json。",
        usage="SmartUnpacker config [options] <show|set|blacklist> ...",
    )
    config_subparsers = config_parser.add_subparsers(dest="config_action", required=True)
    config_subparsers.add_parser("show", help="显示当前配置文件内容。", usage="SmartUnpacker config show [options]")

    config_set_parser = config_subparsers.add_parser(
        "set",
        help="修改一个常用配置项。",
        usage="SmartUnpacker config set <key> <value>",
    )
    config_set_parser.add_argument("key", choices=sorted(CONFIG_SET_KEYS), help="要修改的配置项。")
    config_set_parser.add_argument("value", help="新的配置值。")

    blacklist_parser = config_subparsers.add_parser(
        "blacklist",
        help="添加、删除或查看黑名单规则。",
        usage="SmartUnpacker config blacklist <list|add-dir|remove-dir|add-file|remove-file> [pattern]",
    )
    blacklist_parser.add_argument("operation", choices=["list", "add-dir", "remove-dir", "add-file", "remove-file"], help="黑名单操作。")
    blacklist_parser.add_argument("pattern", nargs="?", help="要添加或删除的正则表达式。")

    return parser


def prompt_passwords_terminal(initial_passwords: list[str] | None = None) -> list[str]:
    existing = dedupe_passwords(initial_passwords or [])
    print("[CLI] 请输入密码列表，每行一个。", flush=True)
    print("[CLI] 输入空行结束。按 Ctrl+C 或 Ctrl+Z 后回车取消。", flush=True)
    if existing:
        print("[CLI] 当前已存在密码列表：", flush=True)
        for password in existing:
            print(f"  - {password}", flush=True)
        print("[CLI] 第一行直接回车可保留当前密码列表。", flush=True)

    collected: list[str] = []
    first_line = True
    while True:
        prompt = "password> " if first_line else "... "
        try:
            line = input(prompt)
        except EOFError as exc:
            raise KeyboardInterrupt("用户取消了密码输入") from exc
        except KeyboardInterrupt as exc:
            raise KeyboardInterrupt("用户取消了密码输入") from exc

        if line == "":
            if first_line and existing:
                return existing
            break
        collected.append(line)
        first_line = False

    return dedupe_passwords(collected)


def collect_cli_passwords(args):
    passwords = list(getattr(args, "password", []) or [])
    if getattr(args, "password_file", None):
        passwords.extend(read_password_file(args.password_file))
    if getattr(args, "prompt_passwords", False):
        passwords = prompt_passwords_terminal(passwords)
    return dedupe_passwords(passwords)


def _get_config_file_path(locator: ResourceLocator | None = None) -> str:
    locator = locator or ResourceLocator()
    return locator.find_existing_resource_path("smart_unpacker_config.json") or locator.get_resource_path("smart_unpacker_config.json")


def _read_config_payload() -> tuple[str, dict]:
    config_path = _get_config_file_path()
    if not os.path.exists(config_path):
        return config_path, build_default_config_payload()
    try:
        with open(config_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception:
        payload = build_default_config_payload()
    if not isinstance(payload, dict):
        payload = build_default_config_payload()
    return config_path, payload


def _write_config_payload(config_path: str, payload: dict) -> None:
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def _ensure_dict(parent: dict, key: str) -> dict:
    value = parent.get(key)
    if not isinstance(value, dict):
        value = {}
        parent[key] = value
    return value


def _ensure_list(parent: dict, key: str) -> list:
    value = parent.get(key)
    if not isinstance(value, list):
        value = []
        parent[key] = value
    return value


def _validate_config_set_value(key: str, raw_value: str):
    if key == "min_inspection_size_bytes":
        return parse_non_negative_int(raw_value)
    if key == "recursive_extract":
        return parse_recursive_extract_value(raw_value)
    if key == "scheduler_profile":
        normalized = raw_value.strip().lower()
        if normalized not in SCHEDULER_PROFILES:
            raise ValueError(f"scheduler_profile 必须是: {', '.join(sorted(SCHEDULER_PROFILES))}")
        return normalized
    if key == "archive_cleanup_mode":
        normalized = raw_value.strip().lower()
        if normalized not in ARCHIVE_CLEANUP_MODES:
            raise ValueError(f"archive_cleanup_mode 必须是: {', '.join(sorted(ARCHIVE_CLEANUP_MODES))}")
        return normalized
    if key == "flatten_single_directory":
        return parse_bool_value(raw_value)
    raise ValueError(f"不支持的配置项: {key}")


def _set_config_value(payload: dict, key: str, value) -> None:
    if key == "min_inspection_size_bytes":
        extraction_rules = _ensure_dict(payload, "extraction_rules")
        extraction_rules["min_inspection_size_bytes"] = value
    elif key == "recursive_extract":
        payload["recursive_extract"] = value
    elif key == "scheduler_profile":
        performance = _ensure_dict(payload, "performance")
        performance["scheduler_profile"] = value
    elif key == "archive_cleanup_mode":
        post_extract = _ensure_dict(payload, "post_extract")
        post_extract["archive_cleanup_mode"] = value
    elif key == "flatten_single_directory":
        post_extract = _ensure_dict(payload, "post_extract")
        post_extract["flatten_single_directory"] = value


def _blacklist_payload(payload: dict) -> dict:
    extraction_rules = _ensure_dict(payload, "extraction_rules")
    blacklist = _ensure_dict(extraction_rules, "blacklist")
    _ensure_list(blacklist, "directory_patterns")
    _ensure_list(blacklist, "filename_patterns")
    return blacklist


def _apply_blacklist_operation(payload: dict, operation: str, pattern: str | None) -> dict:
    blacklist = _blacklist_payload(payload)
    if operation == "list":
        return blacklist
    if not pattern:
        raise ValueError(f"{operation} 需要提供 pattern。")

    key = "directory_patterns" if operation.endswith("-dir") else "filename_patterns"
    patterns = _ensure_list(blacklist, key)
    if operation.startswith("add-"):
        try:
            re.compile(pattern, re.I)
        except re.error as exc:
            raise ValueError(f"非法正则表达式: {exc}") from exc
        if pattern not in patterns:
            patterns.append(pattern)
    elif operation.startswith("remove-"):
        blacklist[key] = [item for item in patterns if item != pattern]
    return blacklist


def _collect_runtime_config_overrides(args) -> dict:
    overrides = {}
    if getattr(args, "min_inspection_size_bytes", None) is not None:
        overrides["min_inspection_size_bytes"] = args.min_inspection_size_bytes
    if getattr(args, "recursive_extract", None) is not None:
        overrides["recursive_extract"] = args.recursive_extract
    if getattr(args, "scheduler_profile", None) is not None:
        overrides["scheduler_profile"] = args.scheduler_profile
    if getattr(args, "archive_cleanup_mode", None) is not None:
        overrides["archive_cleanup_mode"] = args.archive_cleanup_mode
    if getattr(args, "flatten_single_directory", None) is not None:
        overrides["flatten_single_directory"] = args.flatten_single_directory
    return overrides


def apply_runtime_config_overrides(engine: DecompressionEngine, args) -> dict:
    overrides = _collect_runtime_config_overrides(args)
    if not overrides:
        return {}

    if "min_inspection_size_bytes" in overrides:
        engine.app_config.min_inspection_size_bytes = overrides["min_inspection_size_bytes"]
        engine.MIN_SIZE = overrides["min_inspection_size_bytes"]
    if "recursive_extract" in overrides:
        engine.app_config.recursive_extract = ResourceLocator()._coerce_recursive_extract(overrides["recursive_extract"])
    if "archive_cleanup_mode" in overrides:
        engine.app_config.post_extract.archive_cleanup_mode = overrides["archive_cleanup_mode"]
    if "flatten_single_directory" in overrides:
        engine.app_config.post_extract.flatten_single_directory = overrides["flatten_single_directory"]
    if "scheduler_profile" in overrides:
        locator = ResourceLocator()
        resolved = locator._build_scheduler_profile_defaults(overrides["scheduler_profile"])
        engine.app_config.scheduler_profile = resolved["scheduler_profile"]
        engine.app_config.initial_concurrency_limit = resolved["initial_concurrency_limit"]
        engine.app_config.scheduler_poll_interval_ms = resolved["scheduler_poll_interval_ms"]
        engine.app_config.scheduler_scale_up_threshold_mb_s = resolved["scheduler_scale_up_threshold_mb_s"]
        engine.app_config.scheduler_scale_up_backlog_threshold_mb_s = resolved["scheduler_scale_up_backlog_threshold_mb_s"]
        engine.app_config.scheduler_scale_down_threshold_mb_s = resolved["scheduler_scale_down_threshold_mb_s"]
        engine.app_config.scheduler_scale_up_streak_required = resolved["scheduler_scale_up_streak_required"]
        engine.app_config.scheduler_scale_down_streak_required = resolved["scheduler_scale_down_streak_required"]
        engine.app_config.scheduler_medium_backlog_threshold = resolved["scheduler_medium_backlog_threshold"]
        engine.app_config.scheduler_high_backlog_threshold = resolved["scheduler_high_backlog_threshold"]
        engine.app_config.scheduler_medium_floor_workers = resolved["scheduler_medium_floor_workers"]
        engine.app_config.scheduler_high_floor_workers = resolved["scheduler_high_floor_workers"]
        engine.current_concurrency_limit = min(
            max(1, resolved["initial_concurrency_limit"]),
            max(1, engine.max_workers_limit),
        )
    engine.reset_scan_caches()
    return overrides


def build_password_summary(user_passwords: list[str], use_builtin_passwords: bool, recent_passwords: list[str] | None = None) -> CliPasswordSummary:
    recent = list(recent_passwords or [])
    builtin = ResourceLocator().get_builtin_passwords() if use_builtin_passwords else []
    combined = dedupe_passwords(list(user_passwords) + recent + builtin)
    return CliPasswordSummary(
        user_passwords=list(user_passwords),
        recent_passwords=recent,
        builtin_passwords=builtin,
        combined_passwords=combined,
        use_builtin_passwords=use_builtin_passwords,
    )


def resolve_target_paths(paths: list[str]) -> tuple[list[str], list[str]]:
    target_paths = []
    missing_paths = []
    for raw_path in paths:
        norm_path = os.path.normpath(raw_path)
        if os.path.exists(norm_path):
            target_paths.append(norm_path)
        else:
            missing_paths.append(raw_path)
    return target_paths, missing_paths


def collect_inspection_items(engine: DecompressionEngine, target_paths: list[str]) -> list[CliInspectItem]:
    items: list[CliInspectItem] = []
    seen_paths: set[str] = set()

    def add_file(path: str) -> None:
        norm_path = os.path.normpath(path)
        if norm_path in seen_paths or not os.path.isfile(norm_path):
            return
        seen_paths.add(norm_path)

        root = os.path.dirname(norm_path)
        filename = os.path.basename(norm_path)
        scene_context = engine._resolve_scene_context_for_path(root, engine.root_dir)
        relations = engine._build_directory_relationships(root, [filename], scan_root=engine.root_dir)
        relation = relations[filename]
        info = engine.inspect_archive_candidate(norm_path, relation=relation, scene_context=scene_context)
        items.append(
            CliInspectItem(
                path=norm_path,
                decision=info.decision,
                should_extract=info.should_extract,
                score=info.score,
                ext=info.ext,
                detected_ext=info.detected_ext,
                container_type=info.container_type,
                scene_role=info.scene_role,
                validation_ok=info.validation_ok,
                validation_skipped=info.validation_skipped,
                validation_encrypted=info.validation_encrypted,
                probe_detected_archive=info.probe_detected_archive,
                probe_offset=info.probe_offset,
                is_split_candidate=info.is_split_candidate,
                reasons=list(info.reasons),
            )
        )

    for path in target_paths:
        if os.path.isfile(path):
            add_file(path)
        else:
            for root, _, files in os.walk(path):
                for filename in files:
                    add_file(os.path.join(root, filename))

    items.sort(key=lambda item: item.path.lower())
    return items


def build_scan_items(engine: DecompressionEngine, tasks) -> list[CliScanItem]:
    items = []
    for task in tasks:
        main_info = task.group_info.main_info
        items.append(
            CliScanItem(
                key=task.key,
                main_path=task.main_path,
                all_parts=list(task.all_parts),
                decision=main_info.decision,
                score=task.group_info.group_score,
                detected_ext=main_info.detected_ext,
                validation_ok=main_info.validation_ok,
                validation_skipped=main_info.validation_skipped,
                validation_encrypted=main_info.validation_encrypted,
                scene_role=main_info.scene_role,
                reasons=list(main_info.reasons),
                group_reasons=list(task.group_info.reasons),
            )
        )
    items.sort(key=lambda item: item.main_path.lower())
    return items


def summarize_inspection(items: list[CliInspectItem]) -> dict[str, int]:
    summary = {
        "total_items": len(items),
        "archive_items": 0,
        "maybe_archive_items": 0,
        "not_archive_items": 0,
        "extractable_items": 0,
        "encrypted_items": 0,
    }
    for item in items:
        if item.decision == "archive":
            summary["archive_items"] += 1
        elif item.decision == "maybe_archive":
            summary["maybe_archive_items"] += 1
        else:
            summary["not_archive_items"] += 1
        if item.should_extract:
            summary["extractable_items"] += 1
        if item.validation_encrypted:
            summary["encrypted_items"] += 1
    return summary


def summarize_scan(items: list[CliScanItem]) -> dict[str, int]:
    return {
        "task_count": len(items),
        "encrypted_task_count": sum(1 for item in items if item.validation_encrypted),
        "split_task_count": sum(1 for item in items if len(item.all_parts) > 1),
    }


def print_scan_text(reporter: CliReporter, items: list[CliScanItem], summary: dict[str, int]) -> None:
    reporter.info(f"[CLI] 共识别到 {summary['task_count']} 个可处理任务。")
    if summary["encrypted_task_count"]:
        reporter.info(f"[CLI] 其中加密任务: {summary['encrypted_task_count']} 个。")
    for item in items:
        reporter.info(f"- {item.main_path}")
        reporter.info(f"  判定={item.decision} 分数={item.score} 部件数={len(item.all_parts)}")
        if item.validation_encrypted:
            reporter.info("  加密=是")
        elif item.validation_skipped and reporter.verbose:
            reporter.info("  完整校验=已跳过，extract 时再验证")
        if reporter.verbose:
            for reason in item.reasons[-4:]:
                reporter.info(f"  {reason}")
            for reason in item.group_reasons:
                reporter.info(f"  {reason}")


def print_inspect_text(reporter: CliReporter, items: list[CliInspectItem], summary: dict[str, int]) -> None:
    reporter.info(
        f"[CLI] 检查完成: 共 {summary['total_items']} 个文件，archive={summary['archive_items']}，"
        f"maybe={summary['maybe_archive_items']}，not_archive={summary['not_archive_items']}。"
    )
    for item in items:
        reporter.info(f"- {item.path}")
        reporter.info(
            f"  判定={item.decision} 可解压={'是' if item.should_extract else '否'} "
            f"分数={item.score} 检测扩展={item.detected_ext or '-'}"
        )
        if item.validation_encrypted:
            reporter.info("  加密=是")
        elif item.validation_skipped and reporter.verbose:
            reporter.info("  完整校验=已跳过，extract 时再验证")
        if item.probe_offset:
            reporter.info(f"  偏移={item.probe_offset}")
        if reporter.verbose:
            for reason in item.reasons[-6:]:
                reporter.info(f"  {reason}")


def print_password_text(reporter: CliReporter, password_summary: CliPasswordSummary) -> None:
    reporter.info("[CLI] 密码来源摘要:")
    reporter.info(f"  用户输入: {password_summary.user_passwords or []}")
    reporter.info(f"  最近成功: {password_summary.recent_passwords or []}")
    reporter.info(f"  内置高频: {password_summary.builtin_passwords or []}")
    reporter.info(f"  最终顺序: {password_summary.combined_passwords or []}")


def maybe_pause(args) -> None:
    if not getattr(args, "pause_on_exit", False):
        return
    print("按任意键退出...", flush=True)
    os.system("pause >nul" if os.name == "nt" else "read -n 1 -s")


def handle_extract(args, reporter: CliReporter) -> tuple[int, CliCommandResult]:
    target_paths, missing_paths = resolve_target_paths(args.paths)
    if missing_paths:
        errors = [f"目标不存在: {path}" for path in missing_paths]
        for error in errors:
            reporter.error(f"[CLI] {error}")
        return EXIT_USAGE, CliCommandResult(
            command="extract",
            inputs={"paths": list(args.paths)},
            summary={"target_count": len(target_paths)},
            errors=errors,
        )

    common_root = resolve_common_root(target_paths)
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleTitleW(f"Smart Unpacker - {common_root}")
        except Exception:
            pass

    try:
        passwords = collect_cli_passwords(args)
    except KeyboardInterrupt as exc:
        error = str(exc)
        reporter.error(f"[CLI] {error}")
        return EXIT_USAGE, CliCommandResult(
            command="extract",
            inputs={"paths": list(args.paths)},
            summary={"target_count": len(target_paths)},
            errors=[error],
        )
    except Exception as exc:
        error = f"读取密码列表失败: {exc}"
        reporter.error(f"[CLI] {error}")
        return EXIT_USAGE, CliCommandResult(
            command="extract",
            inputs={"paths": list(args.paths)},
            summary={"target_count": len(target_paths)},
            errors=[error],
        )

    password_summary = build_password_summary(passwords, use_builtin_passwords=not args.no_builtin_passwords)
    reporter.info("[CLI] 目标目录/文件:")
    for path in target_paths:
        reporter.info(f"  - {path}")
    reporter.info(f"[CLI] 工作根目录: {common_root}")
    if reporter.verbose:
        print_password_text(reporter, password_summary)

    engine = DecompressionEngine(
        common_root,
        passwords,
        reporter.log,
        None,
        selected_paths=list(target_paths),
        use_builtin_passwords=not args.no_builtin_passwords,
    )
    config_overrides = apply_runtime_config_overrides(engine, args)
    run_summary = engine.run()

    result = CliCommandResult(
        command="extract",
        inputs={
            "paths": list(target_paths),
            "common_root": common_root,
            "json": args.json,
            "quiet": args.quiet,
            "verbose": args.verbose,
            "config_overrides": config_overrides,
        },
        summary={
            "success_count": run_summary.success_count,
            "failed_count": len(run_summary.failed_tasks),
            "processed_count": len(run_summary.processed_keys),
            "use_builtin_passwords": not args.no_builtin_passwords,
        },
        errors=list(run_summary.failed_tasks),
        items=[asdict(password_summary)],
        logs=list(reporter.logs),
    )
    exit_code = EXIT_TASK_FAILED if run_summary.failed_tasks else EXIT_OK
    return exit_code, result


def handle_scan(args, reporter: CliReporter) -> tuple[int, CliCommandResult]:
    target_paths, missing_paths = resolve_target_paths(args.paths)
    if missing_paths:
        errors = [f"目标不存在: {path}" for path in missing_paths]
        for error in errors:
            reporter.error(f"[CLI] {error}")
        return EXIT_USAGE, CliCommandResult(
            command="scan",
            inputs={"paths": list(args.paths)},
            summary={"target_count": len(target_paths)},
            errors=errors,
        )

    common_root = resolve_common_root(target_paths)
    engine = DecompressionEngine(common_root, [], None, None, selected_paths=list(target_paths))
    config_overrides = apply_runtime_config_overrides(engine, args)
    tasks = engine.scan_archives_readonly()
    scan_items = build_scan_items(engine, tasks)
    summary = summarize_scan(scan_items)
    if not args.json:
        print_scan_text(reporter, scan_items, summary)

    return EXIT_OK, CliCommandResult(
        command="scan",
        inputs={"paths": list(target_paths), "common_root": common_root, "config_overrides": config_overrides},
        summary=summary,
        tasks=[asdict(item) for item in scan_items],
        logs=list(reporter.logs),
    )


def handle_inspect(args, reporter: CliReporter) -> tuple[int, CliCommandResult]:
    target_paths, missing_paths = resolve_target_paths(args.paths)
    if missing_paths:
        errors = [f"目标不存在: {path}" for path in missing_paths]
        for error in errors:
            reporter.error(f"[CLI] {error}")
        return EXIT_USAGE, CliCommandResult(
            command="inspect",
            inputs={"paths": list(args.paths)},
            summary={"target_count": len(target_paths)},
            errors=errors,
        )

    common_root = resolve_common_root(target_paths)
    engine = DecompressionEngine(common_root, [], None, None, selected_paths=list(target_paths))
    config_overrides = apply_runtime_config_overrides(engine, args)
    items = collect_inspection_items(engine, target_paths)
    summary = summarize_inspection(items)
    if not args.json:
        print_inspect_text(reporter, items, summary)

    return EXIT_OK, CliCommandResult(
        command="inspect",
        inputs={"paths": list(target_paths), "common_root": common_root, "config_overrides": config_overrides},
        summary=summary,
        items=[asdict(item) for item in items],
        logs=list(reporter.logs),
    )


def handle_passwords(args, reporter: CliReporter) -> tuple[int, CliCommandResult]:
    try:
        passwords = collect_cli_passwords(args)
    except KeyboardInterrupt as exc:
        error = str(exc)
        reporter.error(f"[CLI] {error}")
        return EXIT_USAGE, CliCommandResult(
            command="passwords",
            inputs={},
            summary={},
            errors=[error],
        )
    except Exception as exc:
        error = f"读取密码列表失败: {exc}"
        reporter.error(f"[CLI] {error}")
        return EXIT_USAGE, CliCommandResult(
            command="passwords",
            inputs={},
            summary={},
            errors=[error],
        )

    password_summary = build_password_summary(passwords, use_builtin_passwords=not args.no_builtin_passwords)
    if not args.json:
        print_password_text(reporter, password_summary)

    return EXIT_OK, CliCommandResult(
        command="passwords",
        inputs={
            "json": args.json,
            "quiet": args.quiet,
            "verbose": args.verbose,
            "use_builtin_passwords": not args.no_builtin_passwords,
        },
        summary={
            "user_password_count": len(password_summary.user_passwords),
            "recent_password_count": len(password_summary.recent_passwords),
            "builtin_password_count": len(password_summary.builtin_passwords),
            "combined_password_count": len(password_summary.combined_passwords),
        },
        items=[asdict(password_summary)],
        logs=list(reporter.logs),
    )


def handle_config(args, reporter: CliReporter) -> tuple[int, CliCommandResult]:
    try:
        config_path, payload = _read_config_payload()
        changed = False
        item = payload
        summary = {"config_path": config_path, "changed": False}

        if args.config_action == "show":
            if not args.json and not args.quiet:
                print(json.dumps(payload, ensure_ascii=False, indent=2), flush=True)
        elif args.config_action == "set":
            value = _validate_config_set_value(args.key, args.value)
            _set_config_value(payload, args.key, value)
            _write_config_payload(config_path, payload)
            changed = True
            item = {"key": args.key, "value": value}
            reporter.info(f"[CONFIG] 已修改 {args.key} = {value}")
        elif args.config_action == "blacklist":
            item = _apply_blacklist_operation(payload, args.operation, args.pattern)
            if args.operation != "list":
                _write_config_payload(config_path, payload)
                changed = True
                reporter.info(f"[CONFIG] 黑名单已更新: {args.operation} {args.pattern}")
            elif not args.json and not args.quiet:
                reporter.info("[CONFIG] 目录黑名单:")
                for pattern in item.get("directory_patterns", []):
                    reporter.info(f"  - {pattern}")
                reporter.info("[CONFIG] 文件名黑名单:")
                for pattern in item.get("filename_patterns", []):
                    reporter.info(f"  - {pattern}")
        else:
            return EXIT_USAGE, CliCommandResult(command="config", inputs={}, summary={}, errors=[f"未知配置命令: {args.config_action}"])
    except Exception as exc:
        error = str(exc)
        reporter.error(f"[CONFIG] {error}")
        return EXIT_USAGE, CliCommandResult(
            command="config",
            inputs={"action": getattr(args, "config_action", None)},
            summary={},
            errors=[error],
        )

    summary["changed"] = changed
    return EXIT_OK, CliCommandResult(
        command="config",
        inputs={
            "action": args.config_action,
            "operation": getattr(args, "operation", None),
            "key": getattr(args, "key", None),
            "pattern": getattr(args, "pattern", None),
        },
        summary=summary,
        items=[item],
        logs=list(reporter.logs),
    )


def dispatch_command(args, reporter: CliReporter) -> tuple[int, CliCommandResult]:
    if args.command == "extract":
        return handle_extract(args, reporter)
    if args.command == "scan":
        return handle_scan(args, reporter)
    if args.command == "inspect":
        return handle_inspect(args, reporter)
    if args.command == "passwords":
        return handle_passwords(args, reporter)
    if args.command == "config":
        return handle_config(args, reporter)
    return EXIT_USAGE, CliCommandResult(command="", inputs={}, summary={}, errors=[f"未知命令: {args.command}"])


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    configure_stdio_fallback()
    argv = preprocess_sys_argv(argv)
    parser = build_cli_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)

    reporter = CliReporter(json_mode=args.json, quiet=args.quiet, verbose=args.verbose)
    try:
        exit_code, result = dispatch_command(args, reporter)
    except Exception as exc:
        reporter.error(f"[CLI] 运行失败: {exc}")
        result = CliCommandResult(
            command=getattr(args, "command", ""),
            inputs={"argv": argv},
            summary={},
            errors=[str(exc)],
            logs=list(reporter.logs),
        )
        reporter.emit_result(result)
        maybe_pause(args)
        return EXIT_RUNTIME

    reporter.emit_result(result)
    maybe_pause(args)
    return exit_code
