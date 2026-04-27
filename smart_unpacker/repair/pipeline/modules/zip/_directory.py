from __future__ import annotations

from dataclasses import dataclass
import struct

from ._rebuild import CD_SIG, EOCD_SIG, ZIP64_EOCD_SIG, ZIP64_LOCATOR_SIG


@dataclass(frozen=True)
class EocdRecord:
    offset: int
    end: int
    disk_no: int
    cd_disk_no: int
    disk_entries: int
    total_entries: int
    cd_size: int
    cd_offset: int
    comment: bytes


@dataclass(frozen=True)
class CentralDirectoryWalk:
    offset: int
    end: int
    count: int
    valid: bool


def find_eocd(data: bytes, *, allow_trailing_junk: bool = True) -> EocdRecord | None:
    pos = data.rfind(EOCD_SIG)
    while pos >= 0:
        record = _parse_eocd_at(data, pos)
        if record and (allow_trailing_junk or record.end == len(data)):
            return record
        pos = data.rfind(EOCD_SIG, 0, pos)
    return None


def find_valid_central_directory(data: bytes) -> CentralDirectoryWalk | None:
    pos = data.find(CD_SIG)
    best: CentralDirectoryWalk | None = None
    while pos >= 0:
        walk = walk_central_directory(data, pos)
        if walk.valid:
            if best is None or walk.count > best.count:
                best = walk
        pos = data.find(CD_SIG, pos + 4)
    return best


def walk_central_directory(data: bytes, offset: int, *, expected_end: int | None = None) -> CentralDirectoryWalk:
    pos = offset
    count = 0
    while pos + 46 <= len(data) and data[pos:pos + 4] == CD_SIG:
        try:
            name_len, extra_len, comment_len = struct.unpack_from("<HHH", data, pos + 28)
        except struct.error:
            break
        record_len = 46 + name_len + extra_len + comment_len
        if record_len < 46 or pos + record_len > len(data):
            break
        pos += record_len
        count += 1
        if expected_end is not None and pos >= expected_end:
            break
    valid = count > 0 and (expected_end is None or pos == expected_end)
    return CentralDirectoryWalk(offset=offset, end=pos, count=count, valid=valid)


def rewrite_eocd(data: bytes, cd: CentralDirectoryWalk, *, comment: bytes = b"") -> bytes:
    output = bytearray(data[:cd.end])
    output.extend(struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        min(cd.count, 0xFFFF),
        min(cd.count, 0xFFFF),
        cd.end - cd.offset,
        cd.offset,
        len(comment),
    ))
    output.extend(comment)
    return bytes(output)


def trim_to_eocd(data: bytes, eocd: EocdRecord) -> bytes:
    zip64_tail = _zip64_tail_start(data, eocd.offset)
    if zip64_tail is None:
        return data[:eocd.end]
    return data[:eocd.end]


def _parse_eocd_at(data: bytes, offset: int) -> EocdRecord | None:
    if offset + 22 > len(data) or data[offset:offset + 4] != EOCD_SIG:
        return None
    try:
        (
            signature,
            disk_no,
            cd_disk_no,
            disk_entries,
            total_entries,
            cd_size,
            cd_offset,
            comment_len,
        ) = struct.unpack_from("<IHHHHIIH", data, offset)
    except struct.error:
        return None
    if signature != 0x06054B50:
        return None
    end = offset + 22 + comment_len
    if end > len(data):
        return None
    return EocdRecord(
        offset=offset,
        end=end,
        disk_no=disk_no,
        cd_disk_no=cd_disk_no,
        disk_entries=disk_entries,
        total_entries=total_entries,
        cd_size=cd_size,
        cd_offset=cd_offset,
        comment=data[offset + 22:end],
    )


def _zip64_tail_start(data: bytes, eocd_offset: int) -> int | None:
    locator = data.rfind(ZIP64_LOCATOR_SIG, 0, eocd_offset)
    if locator < 0:
        return None
    record = data.rfind(ZIP64_EOCD_SIG, 0, locator)
    return record if record >= 0 else locator
