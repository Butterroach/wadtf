import argparse
import base64
import json
import re  # tragedy
import sys
import wadtf
from pathlib import Path
from typing import cast, TextIO

UNITS: list[str] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB", "RiB", "QiB"]


def human_unit(bytes: int) -> str:
    val: float = bytes
    unit_index: int = 0
    while abs(val) >= 1024 and unit_index < len(UNITS) - 1:
        val /= 1024
        unit_index += 1
    return f"{val:.2f} {UNITS[unit_index]}"


DESCRIPTION: str = \
    "Program to print info about a WAD, extract a WAD, output a single lump, search for lumps by name, and convert a WAD to JSON and vice-versa, powered by the wadtf library."

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
    with wadtf.open_wad(path, dont_check_magic=args.dont_check_magic, big_endian=args.big_endian, read_large_files=args.read_large_files) as w:
        print("file name:      ", path.name)
        print("type:           ", w.wad_type.name)
        print("file size:      ", human_unit(path.stat().st_size))
        print()
        print("lumps:          ", len(w))
        if len(w) > 0:
            print("first lump name:", w[0].name.decode(errors="ignore"))
            print("last lump name: ", w[-1].name.decode(errors="ignore"))
            small_lump: wadtf.Lump = min(w.lumps, key=lambda x: len(x.contents))
            large_lump: wadtf.Lump = max(w.lumps, key=lambda x: len(x.contents))
            small_lump_len: int = len(small_lump.contents)
            large_lump_len: int = len(large_lump.contents)
            print(
                "smallest lump:  ",
                f"{small_lump.name.decode(errors="ignore"): <8} / {small_lump_len: <{len(str(large_lump_len))}} / {small_lump.lump_type.name}"
            )
            print(
                "largest lump:   ",
                f"{large_lump.name.decode(errors="ignore"): <8} / {large_lump_len: <{len(str(large_lump_len))}} / {large_lump.lump_type.name}"
            )


def handle_json(args: argparse.Namespace) -> None:
    path: Path = cast(Path, args.path)
    output: Path | None = None if args.output is None else cast(Path, args.output)
    out: bytes
    if args.reverse:
        data: dict
        with open(path, "r") as f:
            data = json.load(f)
        w: wadtf.WAD = wadtf.WAD()
        w.wad_type = wadtf.WADType(data["type"])
        for entry in data["lumps"]:
            w.append(wadtf.Lump(name=base64.a85decode(entry["name"]), contents=base64.a85decode(entry["contents"])))
        out = w.serialize(big_endian=args.big_endian)
    else:
        data: dict = {}
        with wadtf.open_wad(path, dont_check_magic=args.dont_check_magic, big_endian=args.big_endian, read_large_files=args.read_large_files) as w:
            data["type"] = w.wad_type.value
            data["lumps"] = []
            for lump in w:
                data["lumps"].append({"name": base64.a85encode(lump.name).decode(), "contents": base64.a85encode(lump.contents).decode()})
        out = json.dumps(data).encode()
    if output is None:
        sys.stdout.buffer.write(out)
        sys.stdout.buffer.flush()
    else:
        with open(output, "wb") as f:
            f.write(out)


def handle_extract(args: argparse.Namespace) -> None:
    path: Path = cast(Path, args.wad)
    directory_path: Path = cast(Path, args.dir)
    pattern: re.Pattern[bytes] = re.compile(cast(str, args.pattern).encode(), re.DOTALL)
    directory_path.mkdir(exist_ok=True)
    with wadtf.open_wad(path, dont_check_magic=args.dont_check_magic, big_endian=args.big_endian, read_large_files=args.read_large_files) as w:
        if len(w) == 0:
            return  # lol
        for i, lump in enumerate(w):
            print(f"{"█" * int(i / len(w) * 50):<50} | {i / len(w) * 100:.2f}%", end="\r", flush=True)
            if pattern.fullmatch(lump.name) is not None:
                with open(directory_path / (base64.urlsafe_b64encode(lump.name).decode() + "." + str(i) + ".lump"), "wb") as f:
                    f.write(lump.contents)
    print(f"{"█" * 50} | 100.00%", flush=True)


def handle_lump(args: argparse.Namespace) -> None:
    path: Path = cast(Path, args.path)
    index: int = cast(int, args.index)
    output: Path | None = None if args.output is None else cast(Path, args.output)
    with wadtf.open_wad(path, dont_check_magic=args.dont_check_magic, big_endian=args.big_endian, read_large_files=args.read_large_files) as w:
        if output is None:
            sys.stdout.buffer.write(w[index].contents)
            sys.stdout.buffer.flush()
        else:
            with open(output, "wb") as f:
                f.write(w[index].contents)


def handle_search(args: argparse.Namespace) -> None:
    path: Path = cast(Path, args.path)
    pattern: re.Pattern[bytes] = re.compile(cast(str, args.pattern).encode(), re.DOTALL)
    with wadtf.open_wad(path, dont_check_magic=args.dont_check_magic, big_endian=args.big_endian, read_large_files=args.read_large_files) as w:
        for i, lump in enumerate(w):
            if pattern.fullmatch(lump.name) is not None:
                print(i)


subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

info_parser = subparsers.add_parser("info", help="Print info about a WAD")
info_parser.add_argument("path", help="Path to WAD file", type=Path)
info_parser.add_argument("-b", "--big-endian", action="store_true", help="Use big endian instead of little endian")
info_parser.add_argument("-d", "--dont-check-magic", action="store_true", help="Don't check the magic string of the file")
info_parser.add_argument(
    "--read-large-files",
    action="store_true",
    help="Don't do the safety check for large reads (don't use unless you know why you want this)"
)
info_parser.set_defaults(func=handle_info)

json_parser = subparsers.add_parser("json", help="Convert WAD from and to JSON")
json_parser.add_argument("path", help="Path to file", type=Path)
json_parser.add_argument("-r", "--reverse", action="store_true", help="Convert from JSON to WAD instead of from WAD to JSON")
json_parser.add_argument("-b", "--big-endian", action="store_true", help="Use big endian instead of little endian")
json_parser.add_argument("-d", "--dont-check-magic", action="store_true", help="Don't check the magic string of the file if reading a WAD file")
json_parser.add_argument(
    "--read-large-files",
    action="store_true",
    help="Don't do the safety check for large reads if reading a WAD file (don't use unless you know why you want this)"
)
json_parser.add_argument("-o", "--output", help="Path to output file, if omitted will output to stdout", type=Path, default=None)
json_parser.set_defaults(func=handle_json)

extract_parser = subparsers.add_parser("extract", help="Extract a WAD's lumps to a directory")
extract_parser.add_argument("wad", help="Path to WAD file", type=Path)
extract_parser.add_argument("dir", help="Path to directory", type=Path)
extract_parser.add_argument(
    "-p", "--pattern", help="Optional Python regex pattern to match on lump names, use `.*` to match everything (default)", type=str, default=".*"
)
extract_parser.add_argument("-b", "--big-endian", action="store_true", help="Use big endian instead of little endian")
extract_parser.add_argument("-d", "--dont-check-magic", action="store_true", help="Don't check the magic string of the file")
extract_parser.add_argument(
    "--read-large-files",
    action="store_true",
    help="Don't do the safety check for large reads (don't use unless you know why you want this)"
)
extract_parser.set_defaults(func=handle_extract)

lump_parser = subparsers.add_parser("lump", help="Output a single lump's contents")
lump_parser.add_argument("path", help="Path to WAD file", type=Path)
lump_parser.add_argument("index", help="Lump index", type=int)
lump_parser.add_argument("-b", "--big-endian", action="store_true", help="Use big endian instead of little endian")
lump_parser.add_argument("-d", "--dont-check-magic", action="store_true", help="Don't check the magic string of the file")
lump_parser.add_argument(
    "--read-large-files",
    action="store_true",
    help="Don't do the safety check for large reads (don't use unless you know why you want this)"
)
lump_parser.add_argument("-o", "--output", help="Path to output file, if omitted will output to stdout", type=Path, default=None)
lump_parser.set_defaults(func=handle_lump)

search_parser = subparsers.add_parser("search", help="Search for lumps by matching their names with regex and output their indices")
search_parser.add_argument("path", help="Path to WAD file", type=Path)
search_parser.add_argument("pattern", help="Python regex pattern", type=str)
search_parser.add_argument("-b", "--big-endian", action="store_true", help="Use big endian instead of little endian")
search_parser.add_argument("-d", "--dont-check-magic", action="store_true", help="Don't check the magic string of the file")
search_parser.add_argument(
    "--read-large-files",
    action="store_true",
    help="Don't do the safety check for large reads (don't use unless you know why you want this)"
)
search_parser.set_defaults(func=handle_search)


def main() -> None:
    args = parser.parse_args()
    args.func(args)
