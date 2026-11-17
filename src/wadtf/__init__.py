# TODO: implement error handling for read() and seek() ending up beyond EOF
# TODO: implement serialization
# TODO: implement helpers for opening and saving to a WAD file

import os
import re  # tragedy
import struct
from dataclasses import dataclass
from enum import auto, Enum
from typing import BinaryIO, cast, Self


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
    """No other defined types apply to it"""
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


class WAD:
    """Mutable WAD object. Holds lumps and a WAD type, and can be serialized into a WAD file.

Init args:

- stream: a seekable binary IO object, required
- dont_check_magic: bool that specifies whether or not to check the first 4 bytes, defaults to False
- big_endian: bool that specifies whether to use big endian, defaults to False. keep it False unless you know why you want this"""
    lumps: list[Lump]
    """Key is index #. Starts at 0."""
    wad_type: WADType
    """Whether it's an IWAD or PWAD or unknown. Not actually checked by the engine lol lmao."""

    def __init__(self, stream: BinaryIO | None, *, dont_check_magic: bool = False, big_endian: bool = False) -> None:
        int_temp: str = ">i" if big_endian else "<i"
        self.lumps = []
        if stream is None:
            # lol
            self.wad_type = WADType.PWAD
            return

        if not stream.seekable():
            raise UnseekableContents("stream is unseekable")

        stream.seek(0)

        match stream.read(4):
            case b"IWAD":
                self.wad_type = WADType.IWAD
            case b"PWAD":
                self.wad_type = WADType.PWAD
            case unknown_id:
                if dont_check_magic:
                    self.wad_type = WADType.UNKNOWN
                else:
                    raise InvalidHeaderError(f"Not a WAD. Expected first 4 bytes to be 'IWAD' or 'PWAD', but got {unknown_id}.")
        
        numlumps: int = cast(int, struct.unpack(int_temp, stream.read(4))[0])
        
        infotableofs: int = cast(int, struct.unpack(int_temp, stream.read(4))[0])

        stream.seek(0, os.SEEK_END)
        
        stream_length: int = stream.tell()
        
        if infotableofs < 12:
            raise InvalidHeaderError(f"infotableofs is invalid ({infotableofs} is less than 16 and if naively read could start reading headers). Malicious WAD?")

        if numlumps < 0:
            raise InvalidHeaderError(f"numlumps is invalid ({numlumps} is negative which if naively read could start reading headers). Malicious WAD?")

        if infotableofs + (numlumps * 16) > stream_length:
            raise InvalidHeaderError(f"numlumps is invalid (numlumps is {numlumps} which if naively read would exceed EOF). Malicious WAD?")
        
        last_marker: bytes = b""
        
        for i in range(numlumps):
            stream.seek(infotableofs + i * 16)
            filepos: int = cast(int, struct.unpack(int_temp, stream.read(4))[0])
            size: int = cast(int, struct.unpack(int_temp, stream.read(4))[0])
            name: bytes = stream.read(8)
            contents: bytes = b""
            if size != 0:
                if size < 0:
                    raise InvalidEntryError(f"Entry #{i} has a negative size ({size}) which if naively read would go backwards. Malicious WAD?")
                if filepos < 12:
                    raise InvalidEntryError(f"Entry #{i} has an invalid filepos ({filepos}) with a non-zero size. Malicious WAD?")
                if filepos + size > stream_length:
                    raise InvalidEntryError(
                        f"Entry #{i} has an invalid filepos ({filepos}) or size ({size}) which if naively read would read past EOF. Malicious WAD?"
                    )
                if filepos < infotableofs + (numlumps * 16) and filepos + size > infotableofs:
                    raise InvalidEntryError(
                        f"Entry #{i} has a filepos ({filepos}) and size ({size}) which if naively read would read into the directory. Malicious WAD?"
                    )
                stream.seek(filepos)
                contents = stream.read(size)
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

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, WAD):
            return NotImplemented
        return self.lumps == other.lumps and self.wad_type == other.wad_type
