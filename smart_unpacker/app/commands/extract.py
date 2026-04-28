from smart_unpacker.app.cli_constants import EXIT_TASK_FAILED, EXIT_USAGE
from smart_unpacker.app.cli_parsers import (
    CliHelpFormatter,
    build_common_parser,
    build_extract_config_override_parser,
    build_password_parser,
    localize_help_action,
)
from smart_unpacker.app.cli_runtime import (
    apply_runtime_config_overrides,
    build_password_summary,
    collect_cli_passwords,
    password_summary_item,
    prompt_for_passwords,
    resolve_common_root,
    resolve_target_paths,
    result_for_missing,
)
from smart_unpacker.app.cli_types import CliCommandResult
from smart_unpacker.config.loader import load_config
from smart_unpacker.coordinator.runner import PipelineRunner

COMMAND = "extract"
ORDER = 10
TEXTS = {
    "en": {
        "help": "Run precheck, scan, extraction, and cleanup.",
        "paths": "Files or directories to process.",
        "target_paths": "[CLI] Target paths:",
        "common_root": "[CLI] Common root: {root}",
        "retry_round": "[CLI] Running another extraction round with newly entered passwords.",
        "retry_no_passwords": "[CLI] No new passwords entered; stopping retry.",
    },
    "zh": {
        "help": "执行预检查、扫描、解压和清理。",
        "paths": "要处理的文件或目录。",
        "target_paths": "[CLI] 目标路径：",
        "common_root": "[CLI] 公共根目录：{root}",
        "retry_round": "[CLI] 使用新输入的密码再解压一轮。",
        "retry_no_passwords": "[CLI] 未输入新密码，停止重试。",
    },
}


def register(subparsers, ctx):
    parser = subparsers.add_parser(
        COMMAND,
        parents=[build_common_parser(ctx), build_password_parser(ctx), build_extract_config_override_parser(ctx)],
        help=ctx.t(TEXTS, "help"),
        usage="sunpack extract [options] <paths...>",
        formatter_class=CliHelpFormatter,
    )
    localize_help_action(parser, ctx)
    parser.add_argument("paths", nargs="+", help=ctx.t(TEXTS, "paths"))


def handle(args, ctx):
    reporter = ctx.reporter
    target_paths, missing_paths = resolve_target_paths(args.paths)
    if missing_paths:
        return result_for_missing(COMMAND, args, missing_paths)

    try:
        passwords = collect_cli_passwords(
            args,
            prompt_text=ctx.core_text("password_prompt"),
            input_prompt=ctx.core_text("password_input_prompt"),
        )
    except Exception as exc:
        return EXIT_USAGE, CliCommandResult(command=COMMAND, inputs={"paths": list(args.paths)}, summary={}, errors=[str(exc)])

    config = load_config()
    config_overrides = apply_runtime_config_overrides(config, args)
    common_root = resolve_common_root(target_paths)
    config.setdefault("output", {})["common_root"] = common_root

    reporter.info(ctx.t(TEXTS, "target_paths"))
    for path in target_paths:
        reporter.info(f"  - {path}")
    reporter.info(ctx.t(TEXTS, "common_root").format(root=common_root))

    attempts = []
    retry_count = 0
    while True:
        runner, summary, password_summary = _run_extract_attempt(
            config,
            passwords,
            use_builtin_passwords=not args.no_builtin_passwords,
            target_paths=target_paths,
        )
        failed_tasks = list(summary.failed_tasks)
        processed_keys = list(summary.processed_keys)
        attempts.append({
            "success_count": summary.success_count,
            "failed_count": len(failed_tasks),
            "processed_count": len(set(processed_keys)),
            "partial_success_count": getattr(summary, "partial_success_count", 0),
            "recovered_outputs": list(getattr(summary, "recovered_outputs", []) or []),
            "wrong_password_failure": has_wrong_password_failure(failed_tasks),
        })
        if not _should_retry_password_failure(args, failed_tasks):
            break
        if not _confirm_password_retry(ctx):
            break
        try:
            new_passwords = prompt_for_passwords(
                prompt_text=ctx.core_text("password_prompt"),
                input_prompt=ctx.core_text("password_input_prompt"),
            )
        except (EOFError, KeyboardInterrupt):
            break
        if not new_passwords:
            reporter.info(ctx.t(TEXTS, "retry_no_passwords"))
            break
        passwords = _dedupe([*passwords, *new_passwords])
        retry_count += 1
        reporter.info(ctx.t(TEXTS, "retry_round"))

    password_summary = build_password_summary(
        passwords,
        use_builtin_passwords=not args.no_builtin_passwords,
        recent_passwords=runner.recent_passwords,
    )

    result = CliCommandResult(
        command=COMMAND,
        inputs={
            "paths": target_paths,
            "common_root": common_root,
            "json": args.json,
            "quiet": args.quiet,
            "verbose": args.verbose,
            "config_overrides": config_overrides,
        },
        summary={
            "success_count": summary.success_count,
            "failed_count": len(failed_tasks),
            "processed_count": len(set(processed_keys)),
            "partial_success_count": getattr(summary, "partial_success_count", 0),
            "recovered_outputs": list(getattr(summary, "recovered_outputs", []) or []),
            "use_builtin_passwords": not args.no_builtin_passwords,
            "password_retry_count": retry_count,
        },
        errors=failed_tasks,
        items=[password_summary_item(password_summary)],
        tasks=attempts,
    )
    return (EXIT_TASK_FAILED if failed_tasks else 0), result


def _run_extract_attempt(config: dict, passwords: list[str], *, use_builtin_passwords: bool, target_paths: list[str]):
    password_summary = build_password_summary(passwords, use_builtin_passwords=use_builtin_passwords)
    run_config = dict(config)
    run_config["user_passwords"] = password_summary.user_passwords
    run_config["builtin_passwords"] = password_summary.builtin_passwords
    runner = PipelineRunner(run_config)
    summary = runner.run_targets(target_paths)
    password_summary = build_password_summary(
        passwords,
        use_builtin_passwords=use_builtin_passwords,
        recent_passwords=runner.recent_passwords,
    )
    return runner, summary, password_summary


def has_wrong_password_failure(failed_tasks: list[str]) -> bool:
    markers = (
        "wrong password",
        "wrong_password",
        "password error",
        "密码错误",
        "密码不正确",
    )
    return any(any(marker in str(item).lower() for marker in markers) for item in failed_tasks)


def _should_retry_password_failure(args, failed_tasks: list[str]) -> bool:
    return (
        bool(failed_tasks)
        and has_wrong_password_failure(failed_tasks)
        and not getattr(args, "json", False)
        and not getattr(args, "quiet", False)
    )


def _confirm_password_retry(ctx) -> bool:
    while True:
        try:
            answer = input(ctx.core_text("password_retry_prompt")).strip().lower()
        except EOFError:
            return False
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no", ""}:
            return False
        print("Please answer y or n.", flush=True)


def _dedupe(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
