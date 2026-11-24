# `wadtf`

## What?

`wadtf` is an easy-to-use OOP-based Python library to safely read, create, modify, and write WAD files:

- Python 3.12 or later
- No dependencies
- Fully typed (passes mypy strict mode)
- Validates WAD files
- Does not deserialize huge files without an explicit flag
- Support for little endian *and* big endian
- 100% human-written
- Probably maintained as of right now
- **Not** bloated with map/image/sound parsing (use another library along with this if you want that)

## What can this do?

- Read WAD data
- Deserialize it into a clean `WAD` object
- Let you use and manipulate the `WAD` object almost exactly like a Python list
- Serialize a `WAD` object into a valid WAD file compatible with the original DOOM, Heretic, and Hexen engines (along with almost every source port)
- Preserve lump names and data during deserialization

## What can't this do?

- Parse maps, images, and sounds (not planned and likely will never be implemented)
- Parse WAD2 and WAD3 (not planned, might consider it)
- Compress/optimize WADs (considering it)
- Attempt to recover data from corrupted files (soon)

## What's a WAD file?

Google it.

### Caveman terms

is 1993. guy need store data for game. guy make format. format has data. format has lump. lump is data and name. guy name format WAD

## How do I use this?

Install:

- `pip install wadtf`
- `uv add wadtf` / `uv pip install wadtf`

Basic example:

```python
import wadtf

with wadtf.open_wad("doom.wad") as w:  # w is wadtf.WAD
    # wadtf.open_wad() can also take pathlike and bytes
    # for its path
    match w.wad_type:
        case wadtf.WADType.IWAD:
            print("type: IWAD")
        case wadtf.WADType.PWAD:
            print("type: PWAD")
        case wadtf.WADType.UNKNOWN:
            print("type: (unknown)")  # this case will never be reached
            # unless you pass dont_check_magic=True
            # to wadtf.open_wad()
    print(f"lumps: {len(w)}")
    for i, lump in enumerate(w):
        print(f"--lump #{i}--")
        print(
            f"name: {lump.name.decode(errors='ignore')}"  # lump.name is bytes or bytearray
        )
        print(
            f"lump size: {len(lump.contents)}"  # lump.contents is bytes or bytearray
        )
        match lump.lump_type:
            case wadtf.LumpType.NONE:
                print("lump type: normal")
            case wadtf.LumpType.MARKER:
                print("lump type: marker")
            case wadtf.LumpType.SPRITE:
                print("lump type: sprite")
            case wadtf.LumpType.FLAT:
                print("lump type: flat")
            case wadtf.LumpType.MAP:
                # patches are not included because they do not use markers and are
                # therefore undetectable without parsing which goes against
                # wadtf's design philosophy
                print("lump type: map")
    w.append(
        wadtf.Lump(name=b"WADTF", contents=b"wadtf demo!")
    )  # make sure your lumps' names
    # aren't larger than 8 bytes!
    w.save_to("wadtf_demo.wad")
```

Another example (generating a PWAD file):

```python
import wadtf

my_wad = wadtf.WAD()  # its type is PWAD by default
# if you want to make it an IWAD,
# do `my_wad.wad_type = wadtf.WADType.IWAD` afterwards
my_wad.append(wadtf.Lump(name=b"WADTF", contents=b"this WAD was generated using wadtf"))
my_wad.append(wadtf.Lump(name=b"WAR", contents=b"love"))
print(len(my_wad))  # 2
my_wad.save_to("wadtf_second_demo.wad")

with wadtf.open_wad("wadtf_second_demo.wad") as w:
    assert w == my_wad  # passes! yay!
```

Most functions also have useful docstrings, and you can check out `src/wadtf/_cli.py` for more examples and error handling.

## CLI

`wadtf` comes with a basic CLI meant as a demo for wadtf's capabilities while also hopefully being useful.

Install `wadtf` then just run `wadtf --help`. Should be self-explanatory enough.

## Why is this Python 3.12+ only?

I hate Python 3.11 so much

## When did you finish v1.0.0?

7 days (started on 2026-11-17, finished on 2026-11-24).

## License

Copyright (c) 2026 Butterroach

`wadtf` is licensed under the Apache license, version 2.0.

See the `LICENSE` file to read version 2.0 of the Apache license, or visit: <https://www.apache.org/licenses/LICENSE-2.0>
