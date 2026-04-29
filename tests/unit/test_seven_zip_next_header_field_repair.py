import struct
import zlib

from smart_unpacker.repair.pipeline.modules.seven_zip.next_header_fields import _find_next_header_candidate


def test_next_header_field_repair_rejects_nonterminated_crc_collision_candidate():
    fake = bytearray(b"\x01" + bytes((index * 37) % 255 or 1 for index in range(1, 5000)))
    fake[-1] = 0x41
    stored_crc = zlib.crc32(fake) & 0xFFFFFFFF
    real_next_header = b"\x17" + b"\0" * 35
    stored_offset = len(fake) + 32
    start_header = struct.pack("<QQI", stored_offset, len(real_next_header), stored_crc)
    data = (
        b"7z\xbc\xaf\x27\x1c"
        + b"\x00\x04"
        + struct.pack("<I", zlib.crc32(start_header) & 0xFFFFFFFF)
        + start_header
        + bytes(fake)
        + (b"x" * 32)
        + real_next_header
    )

    assert _find_next_header_candidate(data, {}) is None


def test_next_header_field_repair_keeps_compact_fixture_candidate():
    gap = b"abcdefgh"
    next_header = b"\x01\x02\x03"
    start_header = struct.pack("<QQI", 0, len(next_header), zlib.crc32(next_header) & 0xFFFFFFFF)
    data = bytearray(
        b"7z\xbc\xaf\x27\x1c"
        + b"\x00\x04"
        + struct.pack("<I", zlib.crc32(start_header) & 0xFFFFFFFF)
        + start_header
        + gap
        + next_header
    )

    assert _find_next_header_candidate(bytes(data), {}) == (len(gap), len(next_header))
