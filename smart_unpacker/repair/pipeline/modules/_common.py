from __future__ import annotations

from pathlib import Path
from typing import Any


def load_source_bytes(source_input: dict[str, Any]) -> bytes:
    kind = str(source_input.get("kind") or "file")
    if kind == "file":
        return Path(source_input["path"]).read_bytes()
    if kind == "file_range":
        path = Path(source_input["path"])
        start = int(source_input.get("start") or 0)
        end = source_input.get("end")
        with path.open("rb") as handle:
            handle.seek(start)
            if end is None:
                return handle.read()
            return handle.read(max(0, int(end) - start))
    if kind == "concat_ranges":
        chunks = []
        for item in source_input.get("ranges") or []:
            chunks.append(load_source_bytes({"kind": "file_range", **item}))
        return b"".join(chunks)
    raise ValueError(f"unsupported repair input kind: {kind}")


def write_candidate(data: bytes, workspace: str, filename: str) -> str:
    path = Path(workspace) / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return str(path)
