import os
from smart_unpacker.detection.pipeline.facts.registry import register_batch_fact, register_fact
from smart_unpacker.support.path_keys import path_key

@register_fact(
    "file.path",
    type="str",
    description="Absolute or normalized path of the candidate file.",
)
def collect_file_path(base_path: str) -> str:
    return base_path

@register_fact(
    "file.size",
    type="int",
    description="File size in bytes, or -1 if unavailable.",
    context=True,
)
def collect_file_size(context) -> int:
    existing = context.fact_bag.get("file.size")
    if isinstance(existing, int):
        return existing
    scan_session = getattr(context, "scan_session", None)
    base_path = context.fact_bag.get("file.path") or context.base_path
    if scan_session is not None:
        facts = scan_session.file_head_facts_for_path(base_path, magic_size=0)
        size = facts.get("size")
        if isinstance(size, int):
            return size
    try:
        return os.path.getsize(base_path)
    except OSError:
        return -1


@register_batch_fact("file.size")
def collect_file_size_batch(context) -> None:
    paths = [
        bag.get("file.path") or ""
        for bag in context.fact_bags
        if bag.get("file.path")
    ]
    if not paths:
        return
    scan_session = getattr(context, "scan_session", None)
    facts_by_key = (
        scan_session.file_head_facts_for_paths(paths, magic_size=0)
        if scan_session is not None
        else {}
    )
    for bag in context.fact_bags:
        path = bag.get("file.path") or ""
        if not path:
            continue
        facts = facts_by_key.get(path_key(path), {})
        size = facts.get("size")
        if isinstance(size, int):
            bag.set(context.fact_name, size)
            continue
        try:
            bag.set(context.fact_name, os.path.getsize(path))
        except OSError:
            bag.set(context.fact_name, -1)
