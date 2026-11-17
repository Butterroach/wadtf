# TODO: implement error handling for read() and seek() ending up beyond EOF
# TODO: implement serialization
# TODO: implement helpers for opening and saving to a WAD file

import os
import re  # tragedy
import struct
from collections.abc import Buffer
from dataclasses import dataclass
from enum import auto, Enum
from typing import BinaryIO, cast, overload, Protocol, Self


class SeekableReadableBinaryIO(Protocol):
    def seek(self, offset: int, whence: int = 0, /) -> int: ...
    def read(self, n: int = -1, /) -> bytes: ...
    def tell(self) -> int: ...


class WriteableBinaryIO(Protocol):
    def write(self, data: Buffer, /) -> int: ...


class InvalidLumpError(Exception):
    """Something is wrong with a lump YOU defined and it's all YOUR fault because it cannot be serialized."""


class UnserializableType(Exception):
    """Tried to serialize an unserializable type like WADType.UNKNOWN."""


class ReadTooHigh(Exception):
    """Attempted to read over 1 GiB of data. Likely malicious WAD or corrupted directory/WAD."""


class InvalidEntryError(Exception):
    """An entry is invalid."""


class UnseekableContents(Exception):
    """You passed an unseekable binary IO object. Please don't do that"""


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
    name: bytes
    """8 bytes max pretty please"""
    lump_type: LumpType
    contents: bytes


def safe_read(f: SeekableReadableBinaryIO, num: int) -> bytes:
    start: int = f.tell()
    if num >= 2**30:
        raise ReadTooHigh(f"Attempted to read {num} bytes (over 1GiB!). Malicious WAD? Corrupted headers? Wrong endianness? Is it even a WAD?")
    data: bytes = f.read(num)
    if len(data) < num:
        raise EOFError(f"Expected {num} bytes but got {len(data)} bytes at {start}. Malicious WAD? Corrupted headers? Wrong endianness? Is it even a WAD?")
    return data


class WAD:
    """Mutable WAD object. Holds lumps and a WAD type, and can be serialized into a WAD file.

Args:
    stream: A seekable readable binary IO object, required. Wrap a bytes object around io.BytesIO() if you for some reason want to deserialize from bytes
    dont_check_magic: A bool that specifies whether or not to check the first 4 bytes, defaults to False
    big_endian: A bool that specifies whether to use big endian, defaults to False. Keep it False unless you know why you want this

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

    def __init__(self, stream: SeekableReadableBinaryIO | None, *, dont_check_magic: bool = False, big_endian: bool = False) -> None:
        int_temp: str = ">i" if big_endian else "<i"
        self.lumps = []
        if stream is None:
            # lol
            self.wad_type = WADType.PWAD
            return

        stream.seek(0)

        match safe_read(stream, 4):
            case b"IWAD":
                self.wad_type = WADType.IWAD
            case b"PWAD":
                self.wad_type = WADType.PWAD
            case unknown_id:
                if dont_check_magic:
                    self.wad_type = WADType.UNKNOWN
                else:
                    raise InvalidHeaderError(f"Not a WAD. Expected first 4 bytes to be 'IWAD' or 'PWAD', but got {unknown_id}.")
        
        numlumps: int = cast(int, struct.unpack(int_temp, safe_read(stream, 4))[0])
        
        infotableofs: int = cast(int, struct.unpack(int_temp, safe_read(stream, 4))[0])

        stream.seek(0, os.SEEK_END)
        
        stream_length: int = stream.tell()
        
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
            stream.seek(infotableofs + i * 16)
            filepos: int = cast(int, struct.unpack(int_temp, safe_read(stream, 4))[0])
            size: int = cast(int, struct.unpack(int_temp, safe_read(stream, 4))[0])
            name: bytes = safe_read(stream, 8)
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
                stream.seek(filepos)
                contents = safe_read(stream, size)
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
                    s_last_marker: str = last_marker.rstrip(b'\x00').decode(errors="strict").upper()
                    if s_last_marker in ("F_START", "FF_START"):
                        lump_type = LumpType.FLAT
                    elif s_last_marker in ("S_START", "SS_START"):
                        lump_type = LumpType.SPRITE
                    elif re.fullmatch(r"E[0-9]M[0-9]|MAP[0-9]{2}", s_last_marker):
                        lump_type = LumpType.MAP
                    else:
                        lump_type = LumpType.NONE
                except UnicodeDecodeError:
                    lump_type = LumpType.NONE
            lump: Lump = Lump(name=name.rstrip(b"\x00"), lump_type=lump_type, contents=contents)
            self.lumps.append(lump)
    
    def match_name(self, name: str | bytes) -> list[int]:
        """Performs a **CASE-SENSITIVE!!!** search for lumps based on their names. Returns a list of indices (just wad.lumps[index] to access it)."""
        b_name: bytes
        if isinstance(name, str):
            b_name = name.encode()
        else:
            b_name = name
        return [i for i, lump in enumerate(self.lumps) if lump.name == b_name]

    def case_match_name(self, name: str | bytes) -> list[int]:
        """Performs a case-insensitive search for lumps based on their names. Returns a list of indices (just wad.lumps[index] to access it).
Will NOT match lumps with binary names. Use match_name() if you care about binary lumps."""
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
    
    @overload
    def serialize(self, stream: WriteableBinaryIO, *, big_endian: bool = False, magic: bytes | None = None) -> None: ...
    @overload
    def serialize(self, *, big_endian: bool = False, magic: bytes | None = None) -> bytes: ...
    def serialize(self, stream: WriteableBinaryIO | None = None, *, big_endian: bool = False, magic: bytes | None = None) -> bytes | None:
        """Serialize the WAD object and either return a bytes or write to an IO object.

Args:
    stream: An optional writeable binary IO object. If provided, the serialized data will be written to it.
    big_endian: An optional bool that specifies whether to use big endian, defaults to False. Keep it False unless you know why you want this
    magic: An optional bytes that specifies the 4-byte identification string at the start of the file and ignores the WAD type, defaults to None.

Returns:
    A bytes object if no stream was given, or None if a stream was given.

Raises:
    UnserializableType: If the WAD type is unserializable and magic was not provided.
    ValueError: If magic is not 4 bytes."""
        int_temp: str = ">i" if big_endian else "<i"

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

        data += struct.pack(int_temp, len(self.lumps))

        all_the_cute_lump_data: bytes = b"".join([lump.contents for lump in self.lumps])

        data += struct.pack(int_temp, len(all_the_cute_lump_data) + 12)

        data += all_the_cute_lump_data
        
        current_pos = 12

        for i, lump in enumerate(self.lumps):
            data += struct.pack(int_temp, current_pos)
            data += struct.pack(int_temp, len(lump.contents))
            if len(lump.name) > 8:
                raise InvalidLumpError(f"Name of lump index {i} is longer than 8 bytes")
            data += struct.pack("8s", lump.name)
            current_pos += len(lump.contents)
        
        if stream is not None:
            stream.write(data)
            return None

        return bytes(data)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, WAD):
            return NotImplemented
        return self.lumps == other.lumps and self.wad_type == other.wad_type
