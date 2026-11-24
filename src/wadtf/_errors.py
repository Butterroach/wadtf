# Copyright(c) Butterroach 2026
# SPDX-License-Identifier: Apache-2.0


class ClosedWAD(ValueError):
    """Attempted to do something on a closed WAD"""


class TooLargeToSerialize(ValueError):
    """Your data is too large to serialize as a WAD file. Sorry man. Complain to John Carmack or something."""


class InvalidLumpError(ValueError):
    """Something is wrong with a lump YOU defined and it's all YOUR fault because it cannot be serialized."""


class UnserializableType(ValueError):
    """Tried to serialize an unserializable type like WADType.UNKNOWN."""


class ReadTooHigh(ValueError):
    """Attempted to read over 2GiB of data. Likely malicious WAD or corrupted directory/WAD."""


class InvalidWADError(ValueError):
    """WAD is invalid in some way."""


class InvalidEntryError(InvalidWADError):
    """An entry is invalid."""


class InvalidHeaderError(InvalidWADError):
    """Header is invalid, or this is not a WAD file."""


class FileTooLarge(ValueError):
    """Attempted to deserialize a file that is over 2GiB large."""


class NegativeSeek(ValueError):
    """Somehow seeked to a negative number. That shouldn't happen. You might want to run memtest"""


class UnseekableStreamError(ValueError):
    """You passed an unseekable stream and that's not nice."""
