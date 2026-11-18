class ClosedWAD(Exception):
    """Attempted to do something on a closed WAD"""


class WADTooLarge(Exception):
    """Your data is too large to serialize as a WAD file. Sorry man. Complain to John Carmack or something."""


class InvalidLumpError(Exception):
    """Something is wrong with a lump YOU defined and it's all YOUR fault because it cannot be serialized."""


class UnserializableType(Exception):
    """Tried to serialize an unserializable type like WADType.UNKNOWN."""


class ReadTooHigh(Exception):
    """Attempted to read over 2GiB of data. Likely malicious WAD or corrupted directory/WAD."""


class InvalidEntryError(Exception):
    """An entry is invalid."""


class InvalidHeaderError(Exception):
    """Header is invalid, or this is not a WAD file."""
