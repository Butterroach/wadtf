from collections.abc import Buffer
from dataclasses import dataclass
from enum import Enum, auto
from typing import Protocol, runtime_checkable


@runtime_checkable
class SeekableReadableBinaryIO(Protocol):
    def seek(self, offset: int, whence: int = 0, /) -> int: ...
    def read(self, n: int = -1, /) -> bytes: ...
    def tell(self) -> int: ...


@runtime_checkable
class WriteableBinaryIO(Protocol):
    def write(self, data: Buffer, /) -> int: ...


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
