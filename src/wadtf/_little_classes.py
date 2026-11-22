# Copyright(c) Butterroach 2026
# SPDX-License-Identifier: Apache-2.0

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
class WritableBinaryIO(Protocol):
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


@dataclass(kw_only=True)
class Lump:
    """Lump data."""

    name: bytes | bytearray
    """8 bytes max pretty please"""
    lump_type: LumpType = LumpType.NONE
    """This isn't needed when serializing and is really only helpful when reading a WAD. You can just keep this as the default if you're creating lumps."""
    contents: bytes | bytearray

    def __lt__(self, other: "Lump") -> bool:
        if not isinstance(other, Lump):
            return NotImplemented
        return self.name < other.name

    def __le__(self, other: "Lump") -> bool:
        if not isinstance(other, Lump):
            return NotImplemented
        return self.name <= other.name

    def __gt__(self, other: "Lump") -> bool:
        if not isinstance(other, Lump):
            return NotImplemented
        return self.name > other.name

    def __ge__(self, other: "Lump") -> bool:
        if not isinstance(other, Lump):
            return NotImplemented
        return self.name >= other.name
