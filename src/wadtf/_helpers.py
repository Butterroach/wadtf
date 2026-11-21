import struct
from ._little_classes import *
from ._errors import *

def safe_read(f: SeekableReadableBinaryIO, read_large_files: bool, num: int) -> bytes:
    start: int = f.tell()
    if num > 2**31 and not read_large_files:
        raise ReadTooHigh(f"Attempted to read {num} bytes (over 2GiB!). Malicious WAD? Corrupted headers/directory? Wrong endianness? Is it even a WAD?")
    data: bytes = f.read(num)
    if len(data) < num:
        raise EOFError(f"Expected {num} bytes but got {len(data)} bytes at {start}. Malicious WAD? Corrupted headers/directory? Wrong endianness? Is it even a WAD?")
    return data


def safe_seek(f: SeekableReadableBinaryIO, stream_length: int, num: int) -> None:
    if num < 0:
        raise NegativeSeek(
            f"Attempted to seek to {num} which should never happen so uh I'm not sure what happened please send a bug report https://github.com/Butterroach/wadtf/issues/new"
        )
    f.seek(num)
    if f.tell() > stream_length:
        raise EOFError(f"Seeked past EOF (by {f.tell() - stream_length} bytes)! Malicious WAD? Corrupted headers/directory? Wrong endianness? Is it even a WAD?")


def safe_si32_pack(big_endian: bool, num: int) -> bytes:
    if not isinstance(num, int):
        raise TypeError(f"Tried to pack non-integer number {num}. This should never happen. Something is seriously wrong.")
    if -2147483648 <= num <= 2147483647:
        return struct.pack(">i" if big_endian else "<i", num)
    raise TooLargeToSerialize(
        f"Tried to pack integer {num} which is not representable by a signed 32-bit integer as a consequence of attempting to serialize data that is too large for the WAD format."
    )
