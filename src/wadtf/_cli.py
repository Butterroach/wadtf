# Copyright(c) Butterroach 2026
# SPDX-License-Identifier: Apache-2.0

import argparse
import base64
import binascii
import json
import re  # tragedy
import sys
from pathlib import Path
from typing import cast

import wadtf

UNITS: tuple[str, ...] = ("B", "KiB", "MiB", "GiB")


def existing_file(value: str) -> Path:
    path: Path = Path(value)
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"file not found: {value}")
    return path


def valid_file(value: str) -> Path:
    path: Path = Path(value)
    if path.exists() and not path.is_file():
        raise argparse.ArgumentTypeError(f"path exists but is not a file: {value}")
    return path


def valid_dir(value: str) -> Path:
    path: Path = Path(value)
    try:
        path = path.resolve(strict=False)
        if path.exists() and not path.is_dir():
            raise argparse.ArgumentTypeError(
                f"path exists but is not a directory: {value}"
            )
        for parent in path.parents:
            if not parent.is_dir():
                raise argparse.ArgumentTypeError(
                    f"parent {parent} of path {value} does not exist"
                )
    except (OSError, ValueError) as e:
        raise argparse.ArgumentTypeError(f"{value} is not a valid path: {e!s}")
    return path


def bytes_pattern(value: str) -> re.Pattern[bytes]:
    try:
        return re.compile(value.encode(), re.DOTALL)
    except re.error as e:
        raise argparse.ArgumentTypeError(f"regex pattern invalid: {e!s}")


def human_unit(bytes_n: int) -> str:
    val: float = bytes_n
    unit_index: int = 0
    while abs(val) >= 1024 and unit_index < len(UNITS) - 1:
        val /= 1024
        unit_index += 1
    return f"{val:.2f} {UNITS[unit_index]}"


DESCRIPTION: str = "Program to print info about a WAD, extract a WAD, output a single lump, search for lumps by name, and convert a WAD to JSON and vice-versa, powered by the wadtf library."

parser: argparse.ArgumentParser

if sys.version_info >= (3, 14):
    parser = argparse.ArgumentParser(
        description=DESCRIPTION,
        suggest_on_error=True,
        color=True,
    )
else:
    parser = argparse.ArgumentParser(description=DESCRIPTION)


def handle_info(args: argparse.Namespace) -> None:
    path: Path = cast(Path, args.path)
    try:
        with wadtf.open_wad(
            path,
            dont_check_magic=args.dont_check_magic,
            big_endian=args.big_endian,
            read_large_files=args.read_large_files,
        ) as w:
            print("file name:      ", path.name)
            print("type:           ", w.wad_type.name)
            print("file size:      ", human_unit(path.stat().st_size))
            print()
            print("lumps:          ", len(w))
            if len(w) > 0:
                print("first lump name:", w[0].name.decode(errors="ignore"))
                print("last lump name: ", w[-1].name.decode(errors="ignore"))
                small_lump: wadtf.Lump = min(w, key=lambda x: len(x.contents))
                large_lump: wadtf.Lump = max(w, key=lambda x: len(x.contents))
                small_lump_len: int = len(small_lump.contents)
                large_lump_len: int = len(large_lump.contents)
                print(
                    "smallest lump:  ",
                    f"{small_lump.name.decode(errors='ignore'): <8} / {small_lump_len: <{len(str(large_lump_len))}} / {small_lump.lump_type.name}",
                )
                print(
                    "largest lump:   ",
                    f"{large_lump.name.decode(errors='ignore'): <8} / {large_lump_len: <{len(str(large_lump_len))}} / {large_lump.lump_type.name}",
                )
    except (
        wadtf.InvalidWADError,
        wadtf.ReadTooHigh,
        wadtf.FileTooLarge,
        EOFError,
    ) as e:
        sys.exit(f"WAD is invalid: {e!s}")
    except PermissionError:
        sys.exit("can't open file, no permissions")
    except wadtf.UnseekableStreamError:
        sys.exit("file is unseekable")


def handle_json(args: argparse.Namespace) -> None:
    path: Path = cast(Path, args.path)
    output: Path | None = None if args.output is None else cast(Path, args.output)
    out: bytes
    if args.reverse:
        try:
            with open(path, "r") as f:
                try:
                    data: dict[str, object] = cast(dict[str, object], json.load(f))
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    sys.exit(f"json is invalid: {e!s}")
        except OSError as e:
            sys.exit(f"can't read file: {e!s}")
        if not isinstance(data, dict):
            sys.exit(f"data is of invalid type '{type(data)}'")
        w: wadtf.WAD = wadtf.WAD()
        try:
            w.wad_type = wadtf.WADType(data["type"])
        except (ValueError, TypeError):
            sys.exit(
                f"'type' value {data['type']!r} is not a valid wad type (which would be integer 1 or 2)"
            )
        except KeyError:
            sys.exit("'type' is missing from json")
        if w.wad_type == wadtf.WADType.UNKNOWN:
            sys.exit("'type' is not a valid wad type (which would be integer 1 or 2)")
        lumps: list[dict[str, str]] | None = cast(
            list[dict[str, str]] | None, data.get("lumps")
        )
        if "lumps" not in data:
            sys.exit("'lumps' is missing")
        if not isinstance(lumps, list):
            sys.exit(f"'lumps' is of invalid type '{type(lumps)}'")
        lumps = cast(list[dict[str, str]], lumps)
        for i, entry in enumerate(lumps):
            if not isinstance(entry, dict):
                sys.exit(f"entry #{i} is of invalid type '{type(entry)}'")
            if "name" not in entry:
                sys.exit(f"entry #{i} is missing 'name'")
            if "contents" not in entry:
                sys.exit(f"entry #{i} is missing 'contents'")
            lump_name: str | None = entry.get("name")
            lump_contents: str | None = entry.get("contents")
            if not isinstance(lump_name, str):
                sys.exit(f"'name' of entry #{i} is of invalid type '{type(lump_name)}'")
            if not isinstance(lump_contents, str):
                sys.exit(
                    f"'contents' of entry #{i} is of invalid type '{type(lump_contents)}'"
                )
            lump_name, lump_contents = cast(str, lump_name), cast(str, lump_contents)
            try:
                name: bytes = base64.a85decode(lump_name)
            except (ValueError, binascii.Error):
                sys.exit(f"'name' of entry #{i} is invalid")
            try:
                contents: bytes = base64.a85decode(lump_contents)
            except (ValueError, binascii.Error):
                sys.exit(f"'contents' of entry #{i} is invalid")
            w.append(wadtf.Lump(name=name, contents=contents))
        try:
            out = w.serialize(big_endian=args.big_endian)
        except wadtf.TooLargeToSerialize:
            print("data is too large for WAD format", file=sys.stderr)
            sys.exit(1)
        except wadtf.InvalidLumpError as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)
    else:
        data: dict = {}
        try:
            with wadtf.open_wad(
                path,
                dont_check_magic=args.dont_check_magic,
                big_endian=args.big_endian,
                read_large_files=args.read_large_files,
            ) as w:
                data["type"] = w.wad_type.value
                data["lumps"] = []
                for lump in w:
                    data["lumps"].append(
                        {
                            "name": base64.a85encode(lump.name).decode(),
                            "contents": base64.a85encode(lump.contents).decode(),
                        }
                    )
        except (
            wadtf.InvalidWADError,
            wadtf.ReadTooHigh,
            wadtf.FileTooLarge,
            EOFError,
        ) as e:
            sys.exit(f"WAD is invalid: {e!s}")
        except PermissionError:
            sys.exit("can't open file, no permissions")
        except wadtf.UnseekableStreamError:
            sys.exit("file is unseekable")
        out = json.dumps(data).encode()
    if output is None:
        sys.stdout.buffer.write(out)
        sys.stdout.buffer.flush()
    else:
        try:
            with open(output, "wb") as f:
                f.write(out)
        except OSError as e:
            sys.exit(f"can't write to file: {e!s}")


def handle_extract(args: argparse.Namespace) -> None:
    path: Path = cast(Path, args.wad)
    directory_path: Path = cast(Path, args.dir)
    pattern: re.Pattern[bytes] = cast(re.Pattern[bytes], args.pattern)
    try:
        directory_path.mkdir(exist_ok=True, parents=False)  # intentional
    except PermissionError:
        sys.exit("can't create directory, no permissions")
    except OSError as e:
        sys.exit(f"can't create directory: {e!s}")
    try:
        with wadtf.open_wad(
            path,
            dont_check_magic=args.dont_check_magic,
            big_endian=args.big_endian,
            read_large_files=args.read_large_files,
        ) as w:
            if len(w) != 0:
                for i, lump in enumerate(w):
                    print(
                        f"{'█' * int(i / len(w) * 50):<50} | {i / len(w) * 100:.2f}%",
                        end="\r",
                        flush=True,
                    )  # intentional yes yes
                    if pattern.fullmatch(lump.name) is not None:
                        try:
                            with open(
                                directory_path
                                / (
                                    base64.urlsafe_b64encode(lump.name).decode()
                                    + "."
                                    + str(i)
                                    + ".lump"
                                ),
                                "wb",
                            ) as f:
                                f.write(lump.contents)
                        except OSError as e:
                            sys.exit(f"can't write to file: {e!s}")
    except (
        wadtf.InvalidWADError,
        wadtf.ReadTooHigh,
        wadtf.FileTooLarge,
        EOFError,
    ) as e:
        sys.exit(f"WAD is invalid: {e!s}")
    except PermissionError:
        sys.exit("can't open file, no permissions")
    except wadtf.UnseekableStreamError:
        sys.exit("file is unseekable")
    print(f"{'█' * 50} | 100.00%", flush=True)


def handle_lump(args: argparse.Namespace) -> None:
    path: Path = cast(Path, args.path)
    index: int = cast(int, args.index)
    output: Path | None = None if args.output is None else cast(Path, args.output)
    try:
        with wadtf.open_wad(
            path,
            dont_check_magic=args.dont_check_magic,
            big_endian=args.big_endian,
            read_large_files=args.read_large_files,
        ) as w:
            try:
                lump_contents: bytes | bytearray = w[index].contents
            except IndexError:
                sys.exit(f"lump #{index} does not exist in WAD")
            if output is None:
                sys.stdout.buffer.write(lump_contents)
                sys.stdout.buffer.flush()
            else:
                try:
                    with open(output, "wb") as f:
                        f.write(lump_contents)
                except OSError as e:
                    sys.exit(f"can't write to file: {e!s}")
    except (
        wadtf.InvalidWADError,
        wadtf.ReadTooHigh,
        wadtf.FileTooLarge,
        EOFError,
    ) as e:
        sys.exit(f"WAD is invalid: {e!s}")
    except PermissionError:
        sys.exit("can't open file, no permissions")
    except wadtf.UnseekableStreamError:
        sys.exit("file is unseekable")


def handle_search(args: argparse.Namespace) -> None:
    path: Path = cast(Path, args.path)
    pattern: re.Pattern[bytes] = cast(re.Pattern[bytes], args.pattern)
    try:
        with wadtf.open_wad(
            path,
            dont_check_magic=args.dont_check_magic,
            big_endian=args.big_endian,
            read_large_files=args.read_large_files,
        ) as w:
            for i, lump in enumerate(w):
                if pattern.fullmatch(lump.name) is not None:
                    print(i)
    except (
        wadtf.InvalidWADError,
        wadtf.ReadTooHigh,
        wadtf.FileTooLarge,
        EOFError,
    ) as e:
        sys.exit(f"WAD is invalid: {e!s}")
    except PermissionError:
        sys.exit("can't open file, no permissions")
    except wadtf.UnseekableStreamError:
        sys.exit("file is unseekable")


def handle_equal(args: argparse.Namespace) -> None:
    path1: Path = cast(Path, args.path1)
    path2: Path = cast(Path, args.path2)
    try:
        with wadtf.open_wad(
            path1,
            dont_check_magic=args.dont_check_magic,
            big_endian=args.big_endian,
            read_large_files=args.read_large_files,
        ) as w1:
            try:
                with wadtf.open_wad(
                    path2,
                    dont_check_magic=args.dont_check_magic,
                    big_endian=args.big_endian,
                    read_large_files=args.read_large_files,
                ) as w2:
                    if w1 != w2:
                        sys.exit(1)
            except (
                wadtf.InvalidWADError,
                wadtf.ReadTooHigh,
                wadtf.FileTooLarge,
                EOFError,
            ) as e:
                sys.exit(f"second WAD is invalid: {e!s}")
            except PermissionError:
                sys.exit("can't open second file, no permissions")
            except wadtf.UnseekableStreamError:
                sys.exit("second file is unseekable")
    except (
        wadtf.InvalidWADError,
        wadtf.ReadTooHigh,
        wadtf.FileTooLarge,
        EOFError,
    ) as e:
        sys.exit(f"first WAD is invalid: {e!s}")
    except PermissionError:
        sys.exit("can't open first file, no permissions")
    except wadtf.UnseekableStreamError:
        sys.exit("first file is unseekable")


subparsers = parser.add_subparsers(
    dest="command", required=True, help="Available commands"
)

info_parser = subparsers.add_parser("info", help="Print info about a WAD")
info_parser.add_argument("path", help="Path to WAD file", type=existing_file)
info_parser.add_argument(
    "-b",
    "--big-endian",
    action="store_true",
    help="Use big endian instead of little endian",
)
info_parser.add_argument(
    "-d",
    "--dont-check-magic",
    action="store_true",
    help="Don't check the magic string of the file",
)
info_parser.add_argument(
    "--read-large-files",
    action="store_true",
    help="Don't do the safety check for large reads (don't use unless you know why you want this)",
)
info_parser.set_defaults(func=handle_info)

json_parser = subparsers.add_parser("json", help="Convert WAD from and to JSON")
json_parser.add_argument("path", help="Path to file", type=existing_file)
json_parser.add_argument(
    "-r",
    "--reverse",
    action="store_true",
    help="Convert from JSON to WAD instead of from WAD to JSON",
)
json_parser.add_argument(
    "-b",
    "--big-endian",
    action="store_true",
    help="Use big endian instead of little endian",
)
json_parser.add_argument(
    "-d",
    "--dont-check-magic",
    action="store_true",
    help="Don't check the magic string of the file if reading a WAD file",
)
json_parser.add_argument(
    "--read-large-files",
    action="store_true",
    help="Don't do the safety check for large reads if reading a WAD file (don't use unless you know why you want this)",
)
json_parser.add_argument(
    "-o",
    "--output",
    help="Path to output file, if omitted will output to stdout",
    type=valid_file,
    default=None,
)
json_parser.set_defaults(func=handle_json)

extract_parser = subparsers.add_parser(
    "extract", help="Extract a WAD's lumps to a directory"
)
extract_parser.add_argument("wad", help="Path to WAD file", type=existing_file)
extract_parser.add_argument("dir", help="Path to directory", type=valid_dir)
extract_parser.add_argument(
    "-p",
    "--pattern",
    help="Optional Python regex pattern to match on lump names, use `.*` to match everything (default)",
    type=bytes_pattern,
    default=bytes_pattern(".*"),
)
extract_parser.add_argument(
    "-b",
    "--big-endian",
    action="store_true",
    help="Use big endian instead of little endian",
)
extract_parser.add_argument(
    "-d",
    "--dont-check-magic",
    action="store_true",
    help="Don't check the magic string of the file",
)
extract_parser.add_argument(
    "--read-large-files",
    action="store_true",
    help="Don't do the safety check for large reads (don't use unless you know why you want this)",
)
extract_parser.set_defaults(func=handle_extract)

lump_parser = subparsers.add_parser("lump", help="Output a single lump's contents")
lump_parser.add_argument("path", help="Path to WAD file", type=existing_file)
lump_parser.add_argument("index", help="Lump index", type=int)
lump_parser.add_argument(
    "-b",
    "--big-endian",
    action="store_true",
    help="Use big endian instead of little endian",
)
lump_parser.add_argument(
    "-d",
    "--dont-check-magic",
    action="store_true",
    help="Don't check the magic string of the file",
)
lump_parser.add_argument(
    "--read-large-files",
    action="store_true",
    help="Don't do the safety check for large reads (don't use unless you know why you want this)",
)
lump_parser.add_argument(
    "-o",
    "--output",
    help="Path to output file, if omitted will output to stdout",
    type=valid_file,
    default=None,
)
lump_parser.set_defaults(func=handle_lump)

search_parser = subparsers.add_parser(
    "search",
    help="Search for lumps by matching their names with regex and output their indices",
)
search_parser.add_argument("path", help="Path to WAD file", type=existing_file)
search_parser.add_argument("pattern", help="Python regex pattern", type=bytes_pattern)
search_parser.add_argument(
    "-b",
    "--big-endian",
    action="store_true",
    help="Use big endian instead of little endian",
)
search_parser.add_argument(
    "-d",
    "--dont-check-magic",
    action="store_true",
    help="Don't check the magic string of the file",
)
search_parser.add_argument(
    "--read-large-files",
    action="store_true",
    help="Don't do the safety check for large reads (don't use unless you know why you want this)",
)
search_parser.set_defaults(func=handle_search)

equal_parser = subparsers.add_parser("equal", help="Check if two WADs are equal. Exit with 0 if equal, otherwise 1.")
equal_parser.add_argument("path1", help="Path to first WAD file", type=existing_file)
equal_parser.add_argument("path2", help="Path to second WAD file", type=existing_file)
equal_parser.add_argument(
    "-b",
    "--big-endian",
    action="store_true",
    help="Use big endian instead of little endian",
)
equal_parser.add_argument(
    "-d",
    "--dont-check-magic",
    action="store_true",
    help="Don't check the magic string of the file",
)
equal_parser.add_argument(
    "--read-large-files",
    action="store_true",
    help="Don't do the safety check for large reads (don't use unless you know why you want this)",
)
equal_parser.set_defaults(func=handle_equal)


def main() -> None:
    args = parser.parse_args()
    args.func(args)


# packaging entry point calls main()
