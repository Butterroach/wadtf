import os
import re  # tragedy
import struct
from collections.abc import Buffer, Iterator
from dataclasses import dataclass
from enum import auto, Enum
from pathlib import Path
from types import TracebackType
from typing import BinaryIO, cast, overload, Protocol, Self, runtime_checkable


@runtime_checkable
class SeekableReadableBinaryIO(Protocol):
    def seek(self, offset: int, whence: int = 0, /) -> int: ...
    def read(self, n: int = -1, /) -> bytes: ...
    def tell(self) -> int: ...


@runtime_checkable
class WriteableBinaryIO(Protocol):
    def write(self, data: Buffer, /) -> int: ...


class ClosedWAD(Exception):
    """Attempted to do something on a closed WAD"""


class WADTooLarge(Exception):
    """Your data is too large to serialize as a WAD file. Sorry man. Complain to John Carmack or something."""


class InvalidLumpError(Exception):
    """Something is wrong with a lump YOU defined and it's all YOUR fault because it cannot be serialized."""


class UnserializableType(Exception):
    """Tried to serialize an unserializable type like WADType.UNKNOWN."""


class ReadTooHigh(Exception):
    """Attempted to read over 1 GiB of data. Likely malicious WAD or corrupted directory/WAD."""


class InvalidEntryError(Exception):
    """An entry is invalid."""


class InvalidHeaderError(Exception):
    """Header is invalid, or this is not a WAD file."""


class WADType(Enum):
    """WAD type enum. Not much to say."""

    IWAD = auto()
    PWAD = auto()
    UNKNOWN = auto()
    """This value is used if the wad has an invalid identification value and dont_check_magic was used to ignore it.
A WAD object with this type can NOT be saved, you must set its type first."""


class LumpType(Enum):
    """Lump type enum. Based on markers/size and NOT actual contents!

Intentionally excludes patches as its markers not actually used by engine and are unreliable."""

    NONE = auto()
    """No other defined types apply to it.
Might still be of a type that isn't autodetected, such as an unrecognized marker or a type based on file contents or other lumps' contents, like patches!"""
    MARKER = auto()
    SPRITE = auto()
    FLAT = auto()
    MAP = auto()


@dataclass
class Lump:
    """Lump data."""

    name: bytes | bytearray
    """8 bytes max pretty please"""
    lump_type: LumpType
    contents: bytes | bytearray


def safe_read(f: SeekableReadableBinaryIO, read_large_files: bool, num: int) -> bytes:
    start: int = f.tell()
    if num >= 2**31 and not read_large_files:
        raise ReadTooHigh(f"Attempted to read {num} bytes (over 2GiB!). Malicious WAD? Corrupted headers/directory? Wrong endianness? Is it even a WAD?")
    data: bytes = f.read(num)
    if len(data) < num:
        raise EOFError(f"Expected {num} bytes but got {len(data)} bytes at {start}. Malicious WAD? Corrupted headers/directory? Wrong endianness? Is it even a WAD?")
    return data


def safe_seek(f: SeekableReadableBinaryIO, stream_length: int, num: int) -> None:
    f.seek(num)
    if f.tell() > stream_length:
        raise EOFError(f"Seeked past EOF (by {f.tell() - stream_length} bytes)! Malicious WAD? Corrupted headers/directory? Wrong endianness? Is it even a WAD?")


def safe_si32_pack(big_endian: bool, num: int) -> bytes:
    if not isinstance(num, int):
        raise TypeError(f"Tried to pack non-integer number {num}. This should never happen. Something is seriously wrong.")
    if -2147483648 <= num <= 2147483647:
        return struct.pack(">i" if big_endian else "<i", num)
    raise WADTooLarge(
        f"Tried to pack integer {num} which is not representable by a signed 32-bit integer as a consequence of attempting to serialize data that is too large for the WAD format."
    )


class WAD:
    """Mutable WAD object. Holds lumps and a WAD type, and can be serialized into a WAD file.

Args:
    stream: A seekable readable binary IO object, optional. Wrap a bytes object around io.BytesIO() if you for some reason want to deserialize from bytes
    dont_check_magic: A bool that specifies whether or not to check the first 4 bytes, defaults to False
    big_endian: A bool that specifies whether to use big endian, defaults to False. Keep it False unless you know why you want this
    read_large_files: A bool that specifies whether to disable the 2GiB safety check, defaults to False. Keep it False unless you have special reasons

Returns:
    None.

Raises:
    InvalidHeaderError: If there is something wrong with the header.
    InvalidEntryError: If there is something wrong with an entry in the directory.
    ReadTooHigh: If there was an attempt to read over 1 GiB of data.
    EOFError: If EOF is unexpectedly reached."""

    lumps: list[Lump]
    """Key is index #. Starts at 0."""
    wad_type: WADType
    """Whether it's an IWAD or PWAD or unknown. Not actually checked by the engine lol lmao."""
    __closed: bool = False

    def __init__(self, stream: SeekableReadableBinaryIO | None = None, *, dont_check_magic: bool = False, big_endian: bool = False, read_large_files: bool = False) -> None:
        int_temp: str = ">i" if big_endian else "<i"
        self.lumps = []
        if stream is None:
            # lol
            self.wad_type = WADType.PWAD
            return

        stream.seek(0)

        match safe_read(stream, read_large_files, 4):
            case b"IWAD":
                self.wad_type = WADType.IWAD
            case b"PWAD":
                self.wad_type = WADType.PWAD
            case unknown_id:
                if dont_check_magic:
                    self.wad_type = WADType.UNKNOWN
                else:
                    raise InvalidHeaderError(f"Not a WAD. Expected first 4 bytes to be 'IWAD' or 'PWAD', but got {unknown_id}.")
        
        numlumps: int = cast(int, struct.unpack(int_temp, safe_read(stream, read_large_files, 4))[0])
        
        infotableofs: int = cast(int, struct.unpack(int_temp, safe_read(stream, read_large_files, 4))[0])

        stream.seek(0, os.SEEK_END)
        
        stream_length: int = stream.tell()
        
        if numlumps == 0:
            return  # yeah we're done here
        
        if infotableofs < 12:
            raise InvalidHeaderError(
                f"infotableofs is invalid ({infotableofs} is less than 16 and if naively read could start reading headers). Malicious WAD? Corrupted headers? Wrong endianness? Is it even a WAD?"
            )

        if numlumps < 0:
            raise InvalidHeaderError(
                f"numlumps is invalid ({numlumps} is negative which if naively read could start reading headers). Malicious WAD? Corrupted headers? Wrong endianness? Is it even a WAD?"
            )

        if infotableofs + (numlumps * 16) > stream_length:
            raise InvalidHeaderError(
                f"numlumps is invalid (numlumps is {numlumps} which if naively read would exceed EOF). Malicious WAD? Corrupted headers? Wrong endianness? Is it even a WAD?"
            )
        
        last_marker: bytes = b""
        
        for i in range(numlumps):
            safe_seek(stream, stream_length, infotableofs + i * 16)
            filepos: int = cast(int, struct.unpack(int_temp, safe_read(stream, read_large_files, 4))[0])
            size: int = cast(int, struct.unpack(int_temp, safe_read(stream, read_large_files, 4))[0])
            name: bytes = safe_read(stream, read_large_files, 8)
            contents: bytes = b""
            if size != 0:
                if size < 0:
                    raise InvalidEntryError(
                        f"Entry #{i} has a negative size ({size}) which if naively read would go backwards. Malicious WAD? Corrupted directory? Wrong endianness? Is it even a WAD?"
                    )
                if filepos < 12:
                    raise InvalidEntryError(
                        f"Entry #{i} has an invalid filepos ({filepos}) with a non-zero size. Malicious WAD? Corrupted directory? Wrong endianness? Is it even a WAD?"
                    )
                if filepos + size > stream_length:
                    raise InvalidEntryError(
                        f"Entry #{i} has an invalid filepos ({filepos}) or size ({size}) which if naively read would read past EOF. Malicious WAD? Corrupted directory? Wrong endianness? Is it even a WAD?"
                    )
                if filepos < infotableofs + (numlumps * 16) and filepos + size > infotableofs:
                    raise InvalidEntryError(
                        f"Entry #{i} has a filepos ({filepos}) and size ({size}) which if naively read would read into the directory. Malicious WAD? Corrupted directory? Wrong endianness? Is it even a WAD?"
                    )
                safe_seek(stream, stream_length, filepos)
                contents = safe_read(stream, read_large_files, size)
            lump_type: LumpType = LumpType.NONE
            if size == 0:
                try:
                    s_name: str = name.rstrip(b"\x00").decode(errors="strict").upper()
                    if s_name in ("F_START", "FF_START", "S_START", "SS_START", "F_END", "FF_END", "S_END", "SS_END") or re.fullmatch(r"E[0-9]M[0-9]|MAP[0-9]{2}", s_name):
                        last_marker = name
                        lump_type = LumpType.MARKER
                except UnicodeDecodeError:
                    lump_type = LumpType.NONE
            else:
                try:
                    s_name: str = name.rstrip(b"\x00").decode(errors="strict").upper()
                    s_last_marker: str = last_marker.rstrip(b'\x00').decode(errors="strict").upper()
                    if s_last_marker in ("F_START", "FF_START"):
                        lump_type = LumpType.FLAT
                    elif s_last_marker in ("S_START", "SS_START"):
                        lump_type = LumpType.SPRITE
                    elif re.fullmatch(r"E[0-9]M[0-9]|MAP[0-9]{2}", s_last_marker):
                        lump_type = LumpType.MAP
                    else:
                        lump_type = LumpType.NONE
                    if s_name == "BLOCKMAP":
                        last_marker = b""
                    if s_name == "BEHAVIOR":
                        last_marker = b""
                        lump_type = LumpType.MAP
                except UnicodeDecodeError:
                    lump_type = LumpType.NONE
            lump: Lump = Lump(name=name.rstrip(b"\x00"), lump_type=lump_type, contents=contents)
            self.lumps.append(lump)
    
    def match_name(self, name: str | bytes) -> list[int]:
        """Performs a **CASE-SENSITIVE!!!** search for lumps based on their names. Returns a list of indices (just wad.lumps[index] to access it)."""
        if self.__closed:
            raise ClosedWAD("Attempted to operate on a closed WAD")
        b_name: bytes
        if isinstance(name, str):
            b_name = name.encode()
        else:
            b_name = name
        return [i for i, lump in enumerate(self.lumps) if lump.name == b_name]

    def case_match_name(self, name: str | bytes) -> list[int]:
        """Performs a case-insensitive search for lumps based on their names. Returns a list of indices (just wad.lumps[index] to access it).
Will NOT match lumps with binary names. Use match_name() if you care about binary lumps."""
        if self.__closed:
            raise ClosedWAD("Attempted to operate on a closed WAD")
        s_name: str
        if isinstance(name, bytes):
            try:
                s_name = name.decode(errors="strict").casefold()
            except UnicodeDecodeError:
                raise  # lol
        else:
            s_name = name.casefold()
        matches = []
        for i, lump in enumerate(self.lumps):
            try:
                if lump.name.decode(errors="strict").casefold() == s_name:
                    matches.append(i)
            except UnicodeDecodeError:
                continue
        return matches

    def greedy_match_name(self, name: str | bytes) -> int | None:
        """Like match_name() but returns the first match immediately. Returns None if nothing is found."""
        if self.__closed:
            raise ClosedWAD("Attempted to operate on a closed WAD")
        b_name: bytes
        if isinstance(name, str):
            b_name = name.encode()
        else:
            b_name = name
        for i, lump in enumerate(self.lumps):
            if lump.name == b_name:
                return i

    def greedy_case_match_name(self, name: str | bytes) -> int | None:
        """Like greedy_case_match_name() but returns the first match immediately. Returns None if nothing is found."""
        if self.__closed:
            raise ClosedWAD("Attempted to operate on a closed WAD")
        s_name: str
        if isinstance(name, bytes):
            try:
                s_name = name.decode(errors="strict").casefold()
            except UnicodeDecodeError:
                raise  # lol
        else:
            s_name = name.casefold()
        for i, lump in enumerate(self.lumps):
            try:
                if lump.name.decode(errors="strict").casefold() == s_name:
                    return i
            except UnicodeDecodeError:
                continue

    def serialize(self, *, big_endian: bool = False, magic: bytes | bytearray | None = None) -> bytes:
        """Serialize the WAD object and return the data.

Args:
    big_endian: An optional bool that specifies whether to use big endian, defaults to False. Keep it False unless you know why you want this
    magic: An optional bytes or bytearray that specifies the 4-byte identification string at the start of the file and ignores the WAD type, defaults to None.

Returns:
    The serialized binary data as a bytes object.

Raises:
    UnserializableType: If the WAD type is unserializable and magic was not provided.
    ValueError: If magic is not 4 bytes.
    TypeError: If magic is not bytes or bytearray."""

        if self.__closed:
            raise ClosedWAD("Attempted to operate on a closed WAD")

        if magic is not None and not isinstance(magic, (bytes, bytearray)):
            raise TypeError(f"Expected magic to be bytes or bytearray but got '{type(magic)}'")

        if magic is not None and len(magic) != 4:
            raise ValueError("magic is not 4 bytes.")

        data: bytearray = bytearray()

        if magic is None:
            match self.wad_type:
                case WADType.IWAD:
                    data += b"IWAD"
                case WADType.PWAD:
                    data += b"PWAD"
                case unknown_type:
                    raise UnserializableType(f"Expected a serializable WAD type but got {unknown_type}.")
        else:
            data += magic

        data += safe_si32_pack(big_endian,  len(self.lumps))

        all_the_cute_lump_data: bytes = b"".join([lump.contents for lump in self.lumps])

        data += safe_si32_pack(big_endian,  len(all_the_cute_lump_data) + 12)

        data += all_the_cute_lump_data
        
        current_pos = 12

        for i, lump in enumerate(self.lumps):
            data += safe_si32_pack(big_endian,  current_pos)
            data += safe_si32_pack(big_endian,  len(lump.contents))
            if not isinstance(lump.name, (bytes, bytearray)):
                raise TypeError(f"Name of lump index {i} is not bytes nor bytearray, but rather '{type(lump.name)}'")
            if len(lump.name) > 8:
                raise InvalidLumpError(f"Name of lump index {i} is longer than 8 bytes")
            if len(lump.name) < 0:
                raise InvalidLumpError(f"Name of lump index {i} is zero")
            data += struct.pack("8s", lump.name)
            current_pos += len(lump.contents)

        return bytes(data)

    def save_to(self, file: WriteableBinaryIO | int | str | bytes | os.PathLike[str] | os.PathLike[bytes], *, big_endian: bool = False, magic: bytes | None = None) -> None:
        """Serializes and writes in one go.

Args:
    file_or_path: Either a writeable binary IO object, or an integer (file descriptor), or a string or bytes (file path), or a path-like object.
    big_endian: An optional bool that specifies whether to use big endian, defaults to False. Keep it False unless you know why you want this
    magic: An optional bytes that specifies the 4-byte identification string at the start of the file and ignores the WAD type, defaults to None.

Returns:
    None.

Raises:
    UnserializableType: If the WAD type is unserializable and magic was not provided.
    ValueError: If magic is not 4 bytes."""
        if self.__closed:
            raise ClosedWAD("Attempted to operate on a closed WAD")
        if isinstance(file, (int, str, bytes, os.PathLike[str], os.PathLike[bytes])):
            with open(file, "wb") as f:  # ty: ignore[no-matching-overload]  # ty is just stupid
                f.write(self.serialize(big_endian=big_endian, magic=magic))
        else:
            file.write(self.serialize(big_endian=big_endian, magic=magic))  # ty: ignore[possibly-missing-attribute]  # ty is just stupid

    def close(self) -> None:
        """Closes the WAD. Frees up memory. Be VERY careful not to operate on a closed WAD!"""
        if self.__closed:
            raise ClosedWAD("Attempted to operate on a closed WAD")
        self.__closed = True
        del self.lumps
        del self.wad_type

    def __eq__(self, other: object) -> bool:
        if self.__closed:
            raise ClosedWAD("Attempted to operate on a closed WAD")
        if not isinstance(other, WAD):
            return NotImplemented
        return self.lumps == other.lumps and self.wad_type == other.wad_type

    def __len__(self) -> int:
        if self.__closed:
            raise ClosedWAD("Attempted to operate on a closed WAD")
        return len(self.lumps)

    def __iter__(self) -> Iterator[Lump]:
        if self.__closed:
            raise ClosedWAD("Attempted to operate on a closed WAD")
        return iter(self.lumps)

    def __enter__(self) -> Self:
        if self.__closed:
            raise ClosedWAD("Attempted to operate on a closed WAD")
        return self  # lol

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: type[BaseException] | None, exc_tb: TracebackType | None):
        # cleanup!!! yay!!!
        if self.__closed:
            raise ClosedWAD("Attempted to operate on a closed WAD")
        self.close()
        return False


def open_wad(path: int | str | bytes | os.PathLike[str] | os.PathLike[bytes]) -> WAD:
    """Helper to open a file and deserialize it."""
    with open(path, "rb") as f:
        return WAD(f)
