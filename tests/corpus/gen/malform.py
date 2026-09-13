#!/usr/bin/env python3
"""
Generates the malformed / byte-patched Mach-O fixtures for the machre corpus.

Notes:
------
Every fixture is derived from an already-built corpus file (hello-c, hello-fat,
legacy-bind) by locating the relevant structure with a tiny Mach-O parser and
overwriting a handful of bytes. Outputs are written into <corpus>/malformed/
(plus the structurally valid fake-upx fixture at the corpus root) and a
manifest, malformed/MANIFEST.txt, describing each patch. All multi-byte values
are little-endian except the fat header, which is big-endian.
"""
from __future__ import annotations

import os
import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_DYLD_INFO_ONLY = 0x80000022


def read(path) -> bytearray:
    """
    Reads and returns the whole file as a mutable bytearray.

    Parameters:
    -----------
    path : str
        Filesystem path of the file to read.
    """
    with open(path, "rb") as f:
        return bytearray(f.read())


def write(path, data, manifest, note) -> None:
    """
    Writes a fixture to disk and appends a one-line description to the manifest.

    Parameters:
    -----------
    path : str
        Destination path of the fixture.
    data : bytes | bytearray
        Fixture contents.
    manifest : list[str]
        Accumulated manifest lines; one entry is appended.
    note : str
        Human-readable description of what was patched and why.

    Notes:
    ------
    Overwrites any existing file at path.
    """
    with open(path, "wb") as f:
        f.write(data)
    manifest.append("%-34s %6d bytes  %s" % (os.path.basename(path), len(data), note))


def load_commands(data) -> list[tuple[int, int, int]]:
    """
    Parses a thin 64-bit Mach-O header and returns [(cmd, cmdsize, offset)].

    Parameters:
    -----------
    data : bytes | bytearray
        Complete thin Mach-O image.

    Raises:
    -------
    AssertionError
        If the magic is not MH_MAGIC_64.
    """
    magic, _cpu, _sub, _ft, ncmds, _sizeofcmds, _flags, _res = struct.unpack_from("<8I", data, 0)
    assert magic == MH_MAGIC_64, "expected MH_MAGIC_64"
    out, off = [], 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, off)
        out.append((cmd, size, off))
        off += size
    return out


def find_segment(data, name) -> int:
    """
    Returns the file offset of the LC_SEGMENT_64 load command named name.

    Parameters:
    -----------
    data : bytes | bytearray
        Complete thin Mach-O image.
    name : str
        Segment name to locate, e.g. "__TEXT".

    Raises:
    -------
    KeyError
        If no segment with that name exists.
    """
    for cmd, _size, off in load_commands(data):
        if cmd == LC_SEGMENT_64 and data[off + 8:off + 24].rstrip(b"\0") == name.encode():
            return off
    raise KeyError(name)


def find_cmd(data, wanted) -> int:
    """
    Returns the file offset of the first load command whose cmd equals wanted.

    Parameters:
    -----------
    data : bytes | bytearray
        Complete thin Mach-O image.
    wanted : int
        LC_* constant to search for.

    Raises:
    -------
    KeyError
        If the load command is not present.
    """
    for cmd, _size, off in load_commands(data):
        if cmd == wanted:
            return off
    raise KeyError(hex(wanted))


def main(corpus) -> None:
    """
    Builds every malformed fixture into <corpus>/malformed and writes the manifest.

    Parameters:
    -----------
    corpus : str
        Path of the tests/corpus directory containing the healthy fixtures.

    Raises:
    -------
    FileNotFoundError
        If hello-c, hello-fat or legacy-bind have not been built yet.

    Notes:
    ------
    Also writes <corpus>/fake-upx, which is a *structurally valid* Mach-O whose
    __DATA_CONST segment (and its sections) is renamed to UPX_DATA; only its
    code signature is invalidated, so it is a packer-name heuristic fixture
    rather than a robustness fixture.
    """
    out = os.path.join(corpus, "malformed")
    os.makedirs(out, exist_ok=True)
    manifest: list[str] = []
    hello = read(os.path.join(corpus, "hello-c"))
    fat = read(os.path.join(corpus, "hello-fat"))
    legacy = read(os.path.join(corpus, "legacy-bind"))

    # 1. truncated header: only the first 20 bytes (cuts inside mach_header_64)
    write(os.path.join(out, "truncated-header.bin"), hello[:20], manifest,
          "first 20 bytes of hello-c: mach_header_64 cut after ncmds")

    # 2. ncmds = 0xFFFFFFFF
    d = bytearray(hello); struct.pack_into("<I", d, 16, 0xFFFFFFFF)
    write(os.path.join(out, "bogus-ncmds.bin"), d, manifest, "mach_header_64.ncmds = 0xFFFFFFFF")

    # 3. first load command cmdsize = 0 (infinite loop / zero-advance trap)
    d = bytearray(hello); struct.pack_into("<I", d, 32 + 4, 0)
    write(os.path.join(out, "cmdsize-zero.bin"), d, manifest, "load_command[0].cmdsize = 0")

    # 4. first load command cmdsize huge (walks past sizeofcmds and EOF)
    d = bytearray(hello); struct.pack_into("<I", d, 32 + 4, 0xFFFFFFF0)
    write(os.path.join(out, "cmdsize-huge.bin"), d, manifest, "load_command[0].cmdsize = 0xFFFFFFF0")

    # 5. fat header claiming 1000 architectures (big-endian)
    d = bytearray(fat); assert struct.unpack_from(">I", d, 0)[0] == FAT_MAGIC
    struct.pack_into(">I", d, 4, 1000)
    write(os.path.join(out, "fat-1000-arches.bin"), d, manifest, "fat_header.nfat_arch = 1000 (only 2 real)")

    # 6. fat arch[0] offset past EOF
    d = bytearray(fat); struct.pack_into(">I", d, 8 + 8, 0x7FFFFFF0)
    write(os.path.join(out, "fat-arch-offset-past-eof.bin"), d, manifest, "fat_arch[0].offset = 0x7FFFFFF0")

    # 7. sizeofcmds larger than the file
    d = bytearray(hello); struct.pack_into("<I", d, 20, 0xFFFFFFF0)
    write(os.path.join(out, "sizeofcmds-too-big.bin"), d, manifest, "mach_header_64.sizeofcmds = 0xFFFFFFF0")

    # 8. section offset past EOF: __TEXT,__text section_64.offset
    d = bytearray(hello); seg = find_segment(d, "__TEXT")
    sect = seg + 72                                  # first section_64 follows the 72-byte segment_command_64
    assert d[sect:sect + 16].rstrip(b"\0") == b"__text"
    struct.pack_into("<I", d, sect + 48, 0x7FFFFFF0)  # section_64.offset is at +48
    write(os.path.join(out, "section-offset-past-eof.bin"), d, manifest, "__TEXT,__text section_64.offset = 0x7FFFFFF0")

    # 9. segment nsects absurd
    d = bytearray(hello); seg = find_segment(d, "__TEXT")
    struct.pack_into("<I", d, seg + 64, 0xFFFFFFFF)  # segment_command_64.nsects at +64
    write(os.path.join(out, "nsects-huge.bin"), d, manifest, "__TEXT segment_command_64.nsects = 0xFFFFFFFF")

    # 10. symtab stroff past EOF (and strsize huge)
    d = bytearray(hello); st = find_cmd(d, LC_SYMTAB)
    struct.pack_into("<II", d, st + 16, 0x7FFFFFF0, 0x7FFFFFF0)  # stroff at +16, strsize at +20
    write(os.path.join(out, "symtab-stroff-past-eof.bin"), d, manifest, "LC_SYMTAB stroff = strsize = 0x7FFFFFF0")

    # 11. symtab nsyms absurd
    d = bytearray(hello); st = find_cmd(d, LC_SYMTAB)
    struct.pack_into("<I", d, st + 12, 0x0FFFFFFF)   # nsyms at +12
    write(os.path.join(out, "symtab-nsyms-huge.bin"), d, manifest, "LC_SYMTAB nsyms = 0x0FFFFFFF")

    # 12. chained fixups header with absurd counts
    d = bytearray(hello); cf = find_cmd(d, LC_DYLD_CHAINED_FIXUPS)
    dataoff, datasize = struct.unpack_from("<II", d, cf + 8)
    # dyld_chained_fixups_header: fixups_version, starts_offset, imports_offset, symbols_offset, imports_count, imports_format, symbols_format
    struct.pack_into("<IIIIII", d, dataoff, 0, 0x7FFFFFF0, 0x7FFFFFF0, 0x7FFFFFF0, 0xFFFFFFFF, 1)
    write(os.path.join(out, "chained-fixups-absurd.bin"), d, manifest,
          "dyld_chained_fixups_header offsets = 0x7FFFFFF0, imports_count = 0xFFFFFFFF")

    # 13. chained starts: seg_count absurd (header intact so parser reaches starts_in_image)
    d = bytearray(hello); cf = find_cmd(d, LC_DYLD_CHAINED_FIXUPS)
    dataoff = struct.unpack_from("<I", d, cf + 8)[0]
    starts_off = struct.unpack_from("<I", d, dataoff + 4)[0]
    struct.pack_into("<I", d, dataoff + starts_off, 0xFFFFFFFF)  # dyld_chained_starts_in_image.seg_count
    write(os.path.join(out, "chained-starts-segcount-huge.bin"), d, manifest,
          "dyld_chained_starts_in_image.seg_count = 0xFFFFFFFF")

    # 14. dyld_info bind_off past EOF (legacy opcode stream)
    d = bytearray(legacy); di = find_cmd(d, LC_DYLD_INFO_ONLY)
    # dyld_info_command: rebase_off/size at +8/+12, bind_off/size at +16/+20
    struct.pack_into("<II", d, di + 16, 0x7FFFFFF0, 0x7FFFFFF0)
    write(os.path.join(out, "dyldinfo-bind-past-eof.bin"), d, manifest, "LC_DYLD_INFO_ONLY bind_off = bind_size = 0x7FFFFFF0")

    # 15. garbage magic
    d = bytearray(hello); d[0:4] = b"\xde\xad\xbe\xef"
    write(os.path.join(out, "bad-magic.bin"), d, manifest, "magic = de ad be ef (neither Mach-O nor fat)")

    # 16. zero-byte file
    write(os.path.join(out, "empty.bin"), b"", manifest, "0-byte file")

    # 17. fake-upx: rename __DATA_CONST -> UPX_DATA (segment + its sections); signature now invalid
    d = bytearray(hello); seg = find_segment(d, "__DATA_CONST")
    nsects = struct.unpack_from("<I", d, seg + 64)[0]
    d[seg + 8:seg + 24] = b"UPX_DATA".ljust(16, b"\0")
    for i in range(nsects):
        s = seg + 72 + 80 * i
        d[s + 16:s + 32] = b"UPX_DATA".ljust(16, b"\0")   # section_64.segname at +16
    write(os.path.join(corpus, "fake-upx"), d, manifest,
          "(corpus root) hello-c with __DATA_CONST renamed UPX_DATA; valid structure, broken signature")
    os.chmod(os.path.join(corpus, "fake-upx"), 0o755)

    with open(os.path.join(out, "MANIFEST.txt"), "w") as f:
        f.write("machre malformed fixtures (generated by gen/malform.py)\n\n")
        f.write("\n".join(manifest) + "\n")
    print("\n".join(manifest))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), ".."))
