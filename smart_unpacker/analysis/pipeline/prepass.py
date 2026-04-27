from dataclasses import dataclass

from smart_unpacker.analysis.view import SharedBinaryView


DEFAULT_HEAD_BYTES = 1024 * 1024
DEFAULT_TAIL_BYTES = 1024 * 1024
KNOWN_SIGNATURES = {
    "zip_local": b"PK\x03\x04",
    "zip_eocd": b"PK\x05\x06",
    "rar4": b"Rar!\x1a\x07\x00",
    "rar5": b"Rar!\x1a\x07\x01\x00",
    "7z": b"7z\xbc\xaf\x27\x1c",
    "gzip": b"\x1f\x8b\x08",
    "bzip2": b"BZh",
    "xz": b"\xfd7zXZ\x00",
    "zstd": b"\x28\xb5\x2f\xfd",
    "tar_ustar": b"ustar",
}


@dataclass(frozen=True)
class SignatureHit:
    name: str
    offset: int


def run_signature_prepass(view: SharedBinaryView, config: dict | None = None) -> dict:
    config = config or {}
    head_size = int(config.get("head_bytes", DEFAULT_HEAD_BYTES) or DEFAULT_HEAD_BYTES)
    tail_size = int(config.get("tail_bytes", DEFAULT_TAIL_BYTES) or DEFAULT_TAIL_BYTES)
    native_result = view.signature_prepass(head_bytes=head_size, tail_bytes=tail_size)
    if native_result is not None:
        return native_result

    head = view.read_at(0, min(head_size, view.size))
    tail_len = min(tail_size, view.size)
    tail_start = max(0, view.size - tail_len)
    tail = view.read_at(tail_start, tail_len)

    hits: list[SignatureHit] = []
    for name, signature in KNOWN_SIGNATURES.items():
        for offset in _find_all(head, signature):
            hits.append(SignatureHit(name=name, offset=offset))
        for offset in _find_all(tail, signature):
            absolute = tail_start + offset
            if absolute >= len(head) or tail_start > 0:
                hits.append(SignatureHit(name=name, offset=absolute))

    return {
        "hits": [{"name": hit.name, "offset": hit.offset} for hit in sorted(hits, key=lambda item: item.offset)],
        "formats": sorted(_formats_from_hits(hits)),
        "head_bytes": len(head),
        "tail_bytes": len(tail),
    }


def _find_all(data: bytes, needle: bytes):
    start = 0
    while True:
        index = data.find(needle, start)
        if index < 0:
            return
        yield index
        start = index + 1


def _formats_from_hits(hits: list[SignatureHit]) -> set[str]:
    formats = set()
    for hit in hits:
        if hit.name.startswith("zip_"):
            formats.add("zip")
        elif hit.name.startswith("rar"):
            formats.add("rar")
        elif hit.name == "7z":
            formats.add("7z")
        elif hit.name == "gzip":
            formats.add("gzip")
        elif hit.name == "bzip2":
            formats.add("bzip2")
        elif hit.name == "xz":
            formats.add("xz")
        elif hit.name == "zstd":
            formats.add("zstd")
        elif hit.name == "tar_ustar":
            formats.add("tar")
    return formats
