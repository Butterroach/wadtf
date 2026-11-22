# Copyright(c) Butterroach 2026
# SPDX-License-Identifier: Apache-2.0

import os
import re  # tragedy
import struct
from collections.abc import Iterator
from copy import deepcopy
from types import TracebackType
from typing import Self, cast, Literal, overload, SupportsIndex, Iterable, TYPE_CHECKING
from ._errors import *
from ._little_classes import *
from ._helpers import *

if TYPE_CHECKING:
    slice_index = slice[SupportsIndex | None, SupportsIndex | None, SupportsIndex | None]
else:
    slice_index = slice

__all__ = ["ClosedWAD", "TooLargeToSerialize", "InvalidLumpError", "UnserializableType", "ReadTooHigh", "InvalidEntryError", "InvalidHeaderError", "SeekableReadableBinaryIO", "WritableBinaryIO", "WADType", "LumpType", "Lump", "WAD", "open_wad", "FileTooLarge"]


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
    ReadTooHigh: If there was an attempt to read over 2 GiB of data.
    FileTooLarge: If the stream passed is over 2GiB.
    EOFError: If EOF is unexpectedly reached."""

    lumps: list[Lump]
    """Internal directory. You can directly modify this too instead of using the instance methods!"""
    wad_type: WADType
    """Whether it's an IWAD or PWAD or unknown. Not actually checked by the engine lol lmao."""
    __closed: bool

    def __init__(self, stream: SeekableReadableBinaryIO | None = None, *, dont_check_magic: bool = False, big_endian: bool = False, read_large_files: bool = False) -> None:
        self.__closed = False
        int_format: str = ">i" if big_endian else "<i"
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
                    raise InvalidHeaderError(f"Not a WAD. Expected first 4 bytes to be 'IWAD' or 'PWAD', but got {repr(unknown_id)}.")
        
        numlumps: int = cast(int, struct.unpack(int_format, safe_read(stream, read_large_files, 4))[0])
        
        infotableofs: int = cast(int, struct.unpack(int_format, safe_read(stream, read_large_files, 4))[0])

        stream.seek(0, os.SEEK_END)
        
        stream_length: int = stream.tell()
        
        if numlumps == 0:
            return  # yeah we're done here
        
        if stream_length > 2**31 and not read_large_files:
            raise FileTooLarge(f"WAD is {stream_length} bytes (over 2GiB!). Set read_large_files to True if you want this to continue regardless.")
        
        if infotableofs < 12:
            raise InvalidHeaderError(
                f"infotableofs is invalid ({infotableofs} is less than 12 and if naively read could start reading headers). Malicious WAD? Corrupted headers? Wrong endianness? Is it even a WAD?"
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
            filepos: int = cast(int, struct.unpack(int_format, safe_read(stream, read_large_files, 4))[0])
            size: int = cast(int, struct.unpack(int_format, safe_read(stream, read_large_files, 4))[0])
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
            s_name: str
            if size == 0:
                try:
                    s_name = name.rstrip(b"\x00").decode(errors="strict").upper()
                    if s_name in ("F_START", "FF_START", "S_START", "SS_START", "F_END", "FF_END", "S_END", "SS_END", "ENDMAP") or re.fullmatch(r"E[0-9]M[0-9]|MAP[0-9]{2}", s_name):
                        last_marker = name
                        lump_type = LumpType.MARKER
                except UnicodeDecodeError:
                    lump_type = LumpType.NONE
            else:
                try:
                    s_name = name.rstrip(b"\x00").decode(errors="strict").upper()
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
            s_name = name.decode(errors="strict").casefold()
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
        return None

    def greedy_case_match_name(self, name: str | bytes) -> int | None:
        """Like greedy_case_match_name() but returns the first match immediately. Returns None if nothing is found."""
        if self.__closed:
            raise ClosedWAD("Attempted to operate on a closed WAD")
        s_name: str
        if isinstance(name, bytes):
            s_name = name.decode(errors="strict").casefold()
        else:
            s_name = name.casefold()
        for i, lump in enumerate(self.lumps):
            try:
                if lump.name.decode(errors="strict").casefold() == s_name:
                    return i
            except UnicodeDecodeError:
                continue
        return None

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

        all_lump_data: bytes = b"".join([lump.contents for lump in self.lumps])

        data += safe_si32_pack(big_endian,  len(all_lump_data) + 12)

        data += all_lump_data
        
        current_pos = 12

        for i, lump in enumerate(self.lumps):
            data += safe_si32_pack(big_endian,  current_pos)
            data += safe_si32_pack(big_endian,  len(lump.contents))
            if not isinstance(lump.name, (bytes, bytearray)):
                raise TypeError(f"Name of lump index {i} is not bytes nor bytearray, but rather '{type(lump.name)}'")
            if len(lump.name) > 8:
                raise InvalidLumpError(f"Name of lump index {i} is longer than 8 bytes")
            data += struct.pack("8s", lump.name)
            current_pos += len(lump.contents)

        return bytes(data)

    def save_to(self, file: WritableBinaryIO | str | bytes | os.PathLike[str] | os.PathLike[bytes], *, big_endian: bool = False, magic: bytes | None = None) -> None:
        """Serializes and writes in one go.

Args:
    file_or_path: Either a writeable binary IO object, or a string or bytes (file path), or a path-like object.
    big_endian: An optional bool that specifies whether to use big endian, defaults to False. Keep it False unless you know why you want this
    magic: An optional bytes that specifies the 4-byte identification string at the start of the file and ignores the WAD type, defaults to None.

Returns:
    None.

Raises:
    UnserializableType: If the WAD type is unserializable and magic was not provided.
    ValueError: If magic is not 4 bytes."""
        if self.__closed:
            raise ClosedWAD("Attempted to operate on a closed WAD")
        if isinstance(file, (str, bytes, os.PathLike)):
            with open(file, "wb") as f:  # ty: ignore[no-matching-overload]  # ty is just stupid
                f.write(self.serialize(big_endian=big_endian, magic=magic))
        else:
            file.write(self.serialize(big_endian=big_endian, magic=magic))

    def close(self) -> None:
        """Closes the WAD. Frees up memory. Be VERY careful not to operate on a closed WAD!"""
        if self.__closed:
            return
        self.__closed = True
        del self.lumps
        del self.wad_type

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, WAD):
            return NotImplemented
        if self.__closed or other.__closed:
            raise ClosedWAD("Attempted to operate on a closed WAD")
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

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> Literal[False]:
        # cleanup!!! yay!!!
        self.close()
        return False
    
    @overload
    def __getitem__(self, index: SupportsIndex) -> Lump: ...
    @overload
    def __getitem__(self, index: slice_index) -> list[Lump]: ...
    def __getitem__(self, key: SupportsIndex | slice_index) -> Lump | list[Lump]:
        if not isinstance(key, (SupportsIndex, slice_index)):
            raise TypeError(f"key of type '{type(key)}' must be a slice, or interpretable as an integer")
        if self.__closed:
            raise ClosedWAD("Attempted to operate on a closed WAD")
        return self.lumps[key]

    @overload
    def __setitem__(self, key: SupportsIndex, value: Lump) -> None: ...
    @overload
    def __setitem__(self, key: slice_index, value: Iterable[Lump]) -> None: ...
    def __setitem__(self, key: SupportsIndex | slice_index, value: Lump | Iterable[Lump]) -> None:
        if not isinstance(key, (SupportsIndex, slice_index)):
            raise TypeError(f"key of type '{type(key)}' must be a slice, or interpretable as an integer")
        if isinstance(key, SupportsIndex) and not isinstance(value, Lump):
            raise TypeError(f"expected value of type Lump, got '{type(value)}'")
        if isinstance(key, slice_index) and not isinstance(value, Iterable[Lump]):
            raise TypeError(f"expected value of type Iterable[Lump] (due to slice key), got '{type(value)}'")
        if self.__closed:
            raise ClosedWAD("Attempted to operate on a closed WAD")
        self.lumps[key] = value  # ty: ignore[invalid-assignment]

    def __delitem__(self, key: SupportsIndex | slice_index) -> None:
        if not isinstance(key, (SupportsIndex, slice_index)):
            raise TypeError(f"key of type '{type(key)}' must be a slice, or interpretable as an integer")
        if self.__closed:
            raise ClosedWAD("Attempted to operate on a closed WAD")
        del self.lumps[key]

    def __add__(self, other: "WAD") -> Self:
        if not isinstance(other, WAD):
            return NotImplemented
        if self.__closed or other.__closed:
            raise ClosedWAD("Attempted to operate on a closed WAD")
        instance: WAD = type(self)()
        if self.wad_type == WADType.UNKNOWN:
            if other.wad_type != WADType.UNKNOWN:
                instance.wad_type = other.wad_type
        else:
            instance.wad_type = self.wad_type
        instance.lumps = deepcopy(self.lumps + other.lumps)
        return instance

    def __iadd__(self, other: "WAD") -> Self:
        if not isinstance(other, WAD):
            return NotImplemented
        if self.__closed or other.__closed:
            raise ClosedWAD("Attempted to operate on a closed WAD")
        if self.wad_type == WADType.UNKNOWN:
            if other.wad_type != WADType.UNKNOWN:
                self.wad_type = other.wad_type
        self.lumps += deepcopy(other.lumps)
        return self

    def __contains__(self, item: Lump) -> bool:
        if not isinstance(item, Lump):
            return False
        if self.__closed:
            raise ClosedWAD("Attempted to operate on a closed WAD")
        return item in self.lumps

    def append(self, object: Lump) -> None:
        """Append a lump to the end of the WAD"""
        if not isinstance(object, Lump):
            raise TypeError(f"Expected Lump, got {type(object)}")
        if self.__closed:
            raise ClosedWAD("Attempted to operate on a closed WAD")
        self.lumps.append(object)
    
    def clear(self) -> None:
        """Clear the WAD of all lumps"""
        if self.__closed:
            raise ClosedWAD("Attempted to operate on a closed WAD")
        self.lumps.clear()

    def copy(self) -> "WAD":
        """Return a new copy of the WAD"""
        if self.__closed:
            raise ClosedWAD("Attempted to operate on a closed WAD")
        instance: WAD = WAD()
        instance.wad_type = self.wad_type
        instance.lumps = deepcopy(self.lumps)
        return instance

    def extend(self, iterable: "WAD") -> None:
        """Extend self with the lumps of another WAD"""
        if not isinstance(iterable, WAD):
            raise TypeError(f"Expected WAD, got {type(iterable)}")
        if self.__closed or iterable.__closed:
            raise ClosedWAD("Attempted to operate on a closed WAD")
        self.lumps.extend(iterable.lumps)

    def insert(self, index: SupportsIndex, object: Lump) -> None:
        """Insert lump before index"""
        if not isinstance(index, SupportsIndex):
            raise TypeError(f"Expected index to be interpretable as an integer, got {type(index)}")
        if not isinstance(object, Lump):
            raise TypeError(f"Expected object to be Lump, got {type(object)}")
        if self.__closed:
            raise ClosedWAD("Attempted to operate on a closed WAD")
        self.lumps.insert(index, object)

    def pop(self, index: SupportsIndex = -1) -> Lump:
        """Remove and return lump at index (default last), raising IndexError if index is out of range or the WAD is empty"""
        if not isinstance(index, SupportsIndex):
            raise TypeError(f"Expected index to be interpretable as an integer, got {type(index)}")
        if self.__closed:
            raise ClosedWAD("Attempted to operate on a closed WAD")
        return self.lumps.pop(index)

    def is_closed(self) -> bool:
        """Check whether this WAD is closed. Returns True if closed."""
        return self.__closed

def open_wad(
    path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
    *,
    dont_check_magic: bool = False,
    big_endian: bool = False,
    read_large_files: bool = False,
) -> WAD:
    """Helper to open a file and deserialize it. See WAD for the keyword args."""
    with open(path, "rb") as f:
        return WAD(f, dont_check_magic=dont_check_magic, big_endian=big_endian, read_large_files=read_large_files)
