#!/usr/bin/env python3
"""
Emits truth/summary.json: machine-comparable key facts for every healthy corpus fixture.

Notes:
------
Structural facts (header, load commands, segments, sections, symbol counts, code
signature superblob / CodeDirectory, entitlements) come from an independent
pure-Python Mach-O parser in this file. Facts that need Apple's semantics
(exports, imports, objc classes, spctl assessment, codesign identity) are
scraped from dyld_info / nm / codesign / spctl / xattr output. Where both
sources cover a value (ncmds, cdhash, identifier) they are cross-checked and a
mismatch aborts, so the JSON is trustworthy as a test oracle.
"""
from __future__ import annotations

import hashlib
import json
import os
import plistlib
import re
import struct
import subprocess
import sys

MH_MAGIC_64, MH_CIGAM_64 = 0xFEEDFACF, 0xCFFAEDFE
MH_MAGIC, MH_CIGAM = 0xFEEDFACE, 0xCEFAEDFE
FAT_MAGIC, FAT_MAGIC_64 = 0xCAFEBABE, 0xCAFEBABF
LC_REQ_DYLD = 0x80000000
LC_NAMES = {
    0x1: "LC_SEGMENT", 0x2: "LC_SYMTAB", 0x4: "LC_THREAD", 0x5: "LC_UNIXTHREAD",
    0xB: "LC_DYSYMTAB", 0xC: "LC_LOAD_DYLIB", 0xD: "LC_ID_DYLIB", 0xE: "LC_LOAD_DYLINKER",
    0xF: "LC_ID_DYLINKER", 0x11: "LC_ROUTINES", 0x12: "LC_SUB_FRAMEWORK", 0x14: "LC_SUB_CLIENT",
    0x15: "LC_SUB_LIBRARY", 0x16: "LC_TWOLEVEL_HINTS", 0x19: "LC_SEGMENT_64", 0x1A: "LC_ROUTINES_64",
    0x1B: "LC_UUID", 0x1C | LC_REQ_DYLD: "LC_RPATH", 0x1D: "LC_CODE_SIGNATURE",
    0x1E: "LC_SEGMENT_SPLIT_INFO", 0x1F | LC_REQ_DYLD: "LC_REEXPORT_DYLIB", 0x20: "LC_LAZY_LOAD_DYLIB",
    0x21: "LC_ENCRYPTION_INFO", 0x22: "LC_DYLD_INFO", 0x22 | LC_REQ_DYLD: "LC_DYLD_INFO_ONLY",
    0x23 | LC_REQ_DYLD: "LC_LOAD_UPWARD_DYLIB", 0x24: "LC_VERSION_MIN_MACOSX", 0x25: "LC_VERSION_MIN_IPHONEOS",
    0x26: "LC_FUNCTION_STARTS", 0x27: "LC_DYLD_ENVIRONMENT", 0x28 | LC_REQ_DYLD: "LC_MAIN",
    0x29: "LC_DATA_IN_CODE", 0x2A: "LC_SOURCE_VERSION", 0x2B: "LC_DYLIB_CODE_SIGN_DRS",
    0x2C: "LC_ENCRYPTION_INFO_64", 0x2D: "LC_LINKER_OPTION", 0x2E: "LC_LINKER_OPTIMIZATION_HINT",
    0x2F: "LC_VERSION_MIN_TVOS", 0x30: "LC_VERSION_MIN_WATCHOS", 0x31: "LC_NOTE", 0x32: "LC_BUILD_VERSION",
    0x33 | LC_REQ_DYLD: "LC_DYLD_EXPORTS_TRIE", 0x34 | LC_REQ_DYLD: "LC_DYLD_CHAINED_FIXUPS",
    0x35 | LC_REQ_DYLD: "LC_FILESET_ENTRY", 0x36: "LC_ATOM_INFO", 0x37: "LC_FUNCTION_VARIANTS",
    0x38: "LC_FUNCTION_VARIANT_FIXUPS", 0x39: "LC_TARGET_TRIPLE",
}
CPU_NAMES = {0x01000007: "x86_64", 0x0100000C: "arm64", 0x0000000C: "arm", 0x00000007: "i386"}
FILETYPES = {1: "MH_OBJECT", 2: "MH_EXECUTE", 3: "MH_FVMLIB", 4: "MH_CORE", 5: "MH_PRELOAD",
             6: "MH_DYLIB", 7: "MH_DYLINKER", 8: "MH_BUNDLE", 9: "MH_DYLIB_STUB", 10: "MH_DSYM",
             11: "MH_KEXT_BUNDLE", 12: "MH_FILESET"}
MH_FLAGS = {0x1: "MH_NOUNDEFS", 0x2: "MH_INCRLINK", 0x4: "MH_DYLDLINK", 0x8: "MH_BINDATLOAD", 0x10: "MH_PREBOUND",
            0x20: "MH_SPLIT_SEGS", 0x40: "MH_LAZY_INIT", 0x80: "MH_TWOLEVEL", 0x100: "MH_FORCE_FLAT",
            0x200: "MH_NOMULTIDEFS", 0x400: "MH_NOFIXPREBINDING", 0x800: "MH_PREBINDABLE", 0x1000: "MH_ALLMODSBOUND",
            0x2000: "MH_SUBSECTIONS_VIA_SYMBOLS", 0x4000: "MH_CANONICAL", 0x8000: "MH_WEAK_DEFINES",
            0x10000: "MH_BINDS_TO_WEAK", 0x20000: "MH_ALLOW_STACK_EXECUTION", 0x40000: "MH_ROOT_SAFE",
            0x80000: "MH_SETUID_SAFE", 0x100000: "MH_NO_REEXPORTED_DYLIBS", 0x200000: "MH_PIE",
            0x400000: "MH_DEAD_STRIPPABLE_DYLIB", 0x800000: "MH_HAS_TLV_DESCRIPTORS", 0x1000000: "MH_NO_HEAP_EXECUTION",
            0x2000000: "MH_APP_EXTENSION_SAFE", 0x4000000: "MH_NLIST_OUTOFSYNC_WITH_DYLDINFO", 0x8000000: "MH_SIM_SUPPORT",
            0x10000000: "MH_IMPLICIT_PAGEZERO", 0x80000000: "MH_DYLIB_IN_CACHE"}  # values verified against SDK mach-o/loader.h
PLATFORMS = {1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 5: "bridgeOS", 6: "macCatalyst",
             7: "iOSSimulator", 8: "tvOSSimulator", 9: "watchOSSimulator", 10: "DriverKit", 11: "visionOS", 12: "visionOSSimulator"}
TOOLS = {1: "clang", 2: "swift", 3: "ld", 4: "lld", 5: "zig(5: not in SDK loader.h)"}
CS_FLAGS = {0x1: "CS_VALID", 0x2: "CS_ADHOC", 0x4: "CS_GET_TASK_ALLOW", 0x8: "CS_INSTALLER",
            0x10: "CS_FORCED_LV", 0x20: "CS_INVALID_ALLOWED", 0x100: "CS_HARD", 0x200: "CS_KILL",
            0x400: "CS_CHECK_EXPIRATION", 0x800: "CS_RESTRICT", 0x1000: "CS_ENFORCEMENT",
            0x2000: "CS_REQUIRE_LV", 0x4000: "CS_ENTITLEMENTS_VALIDATED", 0x8000: "CS_NVRAM_UNRESTRICTED",
            0x10000: "CS_RUNTIME", 0x20000: "CS_LINKER_SIGNED"}
CS_SLOTS = {0: "CSSLOT_CODEDIRECTORY", 1: "CSSLOT_INFOSLOT", 2: "CSSLOT_REQUIREMENTS", 3: "CSSLOT_RESOURCEDIR",
            4: "CSSLOT_APPLICATION", 5: "CSSLOT_ENTITLEMENTS", 6: "CSSLOT_REP_SPECIFIC",
            7: "CSSLOT_ENTITLEMENTS_DER", 8: "CSSLOT_LAUNCH_CONSTRAINT_SELF", 9: "CSSLOT_LAUNCH_CONSTRAINT_PARENT",
            10: "CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE", 11: "CSSLOT_LIBRARY_CONSTRAINT",
            0x1000: "CSSLOT_ALTERNATE_CODEDIRECTORIES", 0x10000: "CSSLOT_SIGNATURESLOT",
            0x10001: "CSSLOT_IDENTIFICATIONSLOT", 0x10002: "CSSLOT_TICKETSLOT"}
CS_MAGICS = {0xFADE0C00: "CSMAGIC_REQUIREMENT", 0xFADE0C01: "CSMAGIC_REQUIREMENTS", 0xFADE0C02: "CSMAGIC_CODEDIRECTORY",
             0xFADE0CC0: "CSMAGIC_EMBEDDED_SIGNATURE", 0xFADE0CC1: "CSMAGIC_DETACHED_SIGNATURE",
             0xFADE0B01: "CSMAGIC_BLOBWRAPPER", 0xFADE7171: "CSMAGIC_EMBEDDED_ENTITLEMENTS",
             0xFADE7172: "CSMAGIC_EMBEDDED_DER_ENTITLEMENTS", 0xFADE8181: "CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT"}
HASH_TYPES = {1: "sha1", 2: "sha256", 3: "sha256_truncated", 4: "sha384", 5: "sha512"}
N_STAB, N_TYPE, N_EXT, N_UNDF, N_SECT = 0xE0, 0x0E, 0x01, 0x0, 0xE


def sh(*args) -> str:
    """
    Runs a command and returns its combined stdout+stderr as text, never raising.

    Parameters:
    -----------
    *args : str
        Command and arguments.
    """
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
    return p.stdout


def sh_rc(*args) -> tuple[int, str]:
    """
    Runs a command and returns (exit code, combined output).

    Parameters:
    -----------
    *args : str
        Command and arguments.
    """
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
    return p.returncode, p.stdout


def cstr(b) -> str:
    """
    Returns the bytes up to the first NUL decoded as UTF-8 (lossy).

    Parameters:
    -----------
    b : bytes
        Fixed-width, NUL-padded name field.
    """
    return b.split(b"\0", 1)[0].decode("utf-8", "replace")


def ver(v) -> str:
    """
    Returns a packed X.Y.Z version (16.8.8 bits) as "X.Y.Z".

    Parameters:
    -----------
    v : int
        Packed version value from a load command.
    """
    return "%d.%d.%d" % (v >> 16, (v >> 8) & 0xFF, v & 0xFF)


def ver2(v) -> str:
    """
    Returns a packed X.Y.Z version the way otool/vtool print minos/sdk (Z omitted if 0).

    Parameters:
    -----------
    v : int
        Packed version value from LC_BUILD_VERSION / LC_VERSION_MIN_*.
    """
    x, y, z = v >> 16, (v >> 8) & 0xFF, v & 0xFF
    return "%d.%d" % (x, y) if z == 0 else "%d.%d.%d" % (x, y, z)


def parse_code_signature(blob) -> dict:
    """
    Parses an embedded code-signature SuperBlob and returns its key facts.

    Parameters:
    -----------
    blob : bytes
        The LC_CODE_SIGNATURE payload (big-endian CS blobs).

    Notes:
    ------
    Computes the cdhash exactly as codesign does for hashType 2: SHA-256 over the
    whole CodeDirectory blob, truncated to 20 bytes. Entitlement keys are read from
    the XML blob (CSMAGIC_EMBEDDED_ENTITLEMENTS); the DER blob is only measured.
    """
    out = {"superblob": None, "code_directory": None, "entitlements_keys": None,
           "has_der_entitlements": False, "der_entitlements_length": None,
           "cms_signature_length": None, "requirements_length": None}
    if len(blob) < 12:
        return out
    magic, length, count = struct.unpack_from(">III", blob, 0)
    slots = []
    for i in range(count):
        t, off = struct.unpack_from(">II", blob, 12 + 8 * i)
        m, l = struct.unpack_from(">II", blob, off)
        slots.append({"type": t, "type_name": CS_SLOTS.get(t, "?"), "offset": off,
                      "magic": "0x%08x" % m, "magic_name": CS_MAGICS.get(m, "?"), "length": l})
        sub = blob[off:off + l]
        if m == 0xFADE0C02 and out["code_directory"] is None:
            (v, flags, hash_off, ident_off, nspecial, ncode, code_limit,
             hash_size, hash_type, platform, page_size, _spare2) = struct.unpack_from(">IIIIIIIBBBBI", sub, 8)
            cd = {"version": "0x%x" % v, "flags": flags, "flags_hex": "0x%x" % flags,
                  "flags_names": [n for b, n in CS_FLAGS.items() if flags & b],
                  "hash_type": HASH_TYPES.get(hash_type, hash_type), "hash_size": hash_size,
                  "page_size": 1 << page_size if page_size else 0, "platform": platform,
                  "n_code_slots": ncode, "n_special_slots": nspecial, "code_limit": code_limit,
                  "identifier": cstr(sub[ident_off:]), "team_id": None}
            if v >= 0x20200:
                team_off = struct.unpack_from(">I", sub, 48)[0]
                cd["team_id"] = cstr(sub[team_off:]) if team_off else None
            if v >= 0x20400:
                base, limit, eflags = struct.unpack_from(">QQQ", sub, 64)
                cd["exec_seg_base"], cd["exec_seg_limit"], cd["exec_seg_flags"] = base, limit, "0x%x" % eflags
            full = hashlib.sha256(sub).hexdigest()
            cd["cdhash"] = full[:40]
            cd["cdhash_full"] = full
            out["code_directory"] = cd
        elif m == 0xFADE7171:
            try:
                out["entitlements_keys"] = sorted(plistlib.loads(sub[8:]).keys())
            except Exception as e:  # noqa: BLE001
                out["entitlements_keys"] = ["<unparseable: %s>" % e]
        elif m == 0xFADE7172:
            out["has_der_entitlements"] = True
            out["der_entitlements_length"] = l
        elif m == 0xFADE0B01:
            out["cms_signature_length"] = l
        elif m == 0xFADE0C01:
            out["requirements_length"] = l
    out["superblob"] = {"magic": "0x%08x" % magic, "magic_name": CS_MAGICS.get(magic, "?"),
                        "length": length, "count": count, "slots": slots}
    return out


def parse_slice(data, base, size) -> dict:
    """
    Parses one thin 64-bit Mach-O image and returns its structural facts.

    Parameters:
    -----------
    data : bytes
        Whole file contents.
    base : int
        File offset of the slice's mach_header_64.
    size : int
        Length of the slice in bytes.

    Raises:
    -------
    ValueError
        If the magic is not a little-endian 64-bit Mach-O header.
    """
    d = data[base:base + size]
    magic = struct.unpack_from("<I", d, 0)[0]
    if magic != MH_MAGIC_64:
        raise ValueError("unsupported magic 0x%08x" % magic)
    _, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, _res = struct.unpack_from("<IiiIIIII", d, 0)
    s = {"offset_in_file": base, "size": size, "magic": "0x%08x" % magic,
         "cputype": cputype, "cputype_hex": "0x%x" % cputype, "cputype_name": CPU_NAMES.get(cputype, "?"),
         "cpusubtype": cpusubtype, "cpusubtype_hex": "0x%x" % (cpusubtype & 0xFFFFFFFF),
         "cpusubtype_caps": "0x%x" % ((cpusubtype >> 24) & 0xFF), "cpusubtype_low": cpusubtype & 0xFFFFFF,
         "filetype": filetype, "filetype_name": FILETYPES.get(filetype, "?"),
         "ncmds": ncmds, "sizeofcmds": sizeofcmds, "flags": "0x%x" % flags,
         "flags_names": [n for b, n in MH_FLAGS.items() if flags & b],
         "load_commands": [], "segments": [], "dylibs": [], "id_dylib": None, "rpaths": [],
         "dylinker": None, "uuid": None, "build_version": None, "version_min": None,
         "source_version": None, "entry_point": None, "symtab": None, "dysymtab": None,
         "dyld_info": None, "chained_fixups": None, "exports_trie": None, "function_starts": None,
         "data_in_code": None, "code_signature": {"present": False}}
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", d, off)
        name = LC_NAMES.get(cmd, "0x%x" % cmd)
        s["load_commands"].append(name)
        if cmd == 0x19:
            segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, sflags = struct.unpack_from("<16sQQQQiiII", d, off + 8)
            seg = {"name": cstr(segname), "vmaddr": "0x%x" % vmaddr, "vmsize": "0x%x" % vmsize,
                   "fileoff": fileoff, "filesize": filesize, "maxprot": maxprot, "initprot": initprot,
                   "nsects": nsects, "flags": "0x%x" % sflags, "sections": []}
            for i in range(nsects):
                so = off + 72 + 80 * i
                sectname, sseg, addr, ssize, soff, align, reloff, nreloc, secflags = struct.unpack_from("<16s16sQQIIIII", d, so)
                seg["sections"].append({"name": cstr(sectname), "segname": cstr(sseg), "addr": "0x%x" % addr,
                                        "size": ssize, "offset": soff, "align": align,
                                        "flags": "0x%08x" % secflags, "type": secflags & 0xFF})
            s["segments"].append(seg)
        elif cmd in (0xC, 0xD, 0x1F | LC_REQ_DYLD, 0x20, 0x23 | LC_REQ_DYLD):
            noff, ts, cur, compat = struct.unpack_from("<IIII", d, off + 8)
            ent = {"cmd": name, "path": cstr(d[off + noff:off + cmdsize]), "timestamp": ts,
                   "current_version": ver(cur), "compatibility_version": ver(compat)}
            if cmd == 0xD:
                s["id_dylib"] = ent
            else:
                s["dylibs"].append(ent)
        elif cmd == 0x1C | LC_REQ_DYLD:
            noff = struct.unpack_from("<I", d, off + 8)[0]
            s["rpaths"].append(cstr(d[off + noff:off + cmdsize]))
        elif cmd == 0xE:
            noff = struct.unpack_from("<I", d, off + 8)[0]
            s["dylinker"] = cstr(d[off + noff:off + cmdsize])
        elif cmd == 0x1B:
            u = d[off + 8:off + 24].hex().upper()
            s["uuid"] = "%s-%s-%s-%s-%s" % (u[:8], u[8:12], u[12:16], u[16:20], u[20:])
        elif cmd == 0x32:
            platform, minos, sdk, ntools = struct.unpack_from("<IIII", d, off + 8)
            tools = [{"tool": TOOLS.get(t, t), "version": ver(v)}
                     for t, v in struct.iter_unpack("<II", d[off + 24:off + 24 + 8 * ntools])]
            s["build_version"] = {"platform": platform, "platform_name": PLATFORMS.get(platform, "?"),
                                  "minos": ver2(minos), "sdk": ver2(sdk), "tools": tools}
        elif cmd in (0x24, 0x25, 0x2F, 0x30):
            v, sdk = struct.unpack_from("<II", d, off + 8)
            s["version_min"] = {"cmd": name, "version": ver2(v), "sdk": ver2(sdk)}
        elif cmd == 0x2A:
            v = struct.unpack_from("<Q", d, off + 8)[0]
            s["source_version"] = "%d.%d.%d.%d.%d" % (v >> 40, (v >> 30) & 0x3FF, (v >> 20) & 0x3FF, (v >> 10) & 0x3FF, v & 0x3FF)
        elif cmd == 0x28 | LC_REQ_DYLD:
            entryoff, stacksize = struct.unpack_from("<QQ", d, off + 8)
            s["entry_point"] = {"entryoff": entryoff, "entryoff_hex": "0x%x" % entryoff, "stacksize": stacksize}
        elif cmd == 0x2:
            symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", d, off + 8)
            s["symtab"] = {"symoff": symoff, "nsyms": nsyms, "stroff": stroff, "strsize": strsize}
        elif cmd == 0xB:
            f = struct.unpack_from("<18I", d, off + 8)
            keys = ["ilocalsym", "nlocalsym", "iextdefsym", "nextdefsym", "iundefsym", "nundefsym", "tocoff", "ntoc",
                    "modtaboff", "nmodtab", "extrefsymoff", "nextrefsyms", "indirectsymoff", "nindirectsyms",
                    "extreloff", "nextrel", "locreloff", "nlocrel"]
            s["dysymtab"] = dict(zip(keys, f))
        elif cmd in (0x22, 0x22 | LC_REQ_DYLD):
            f = struct.unpack_from("<10I", d, off + 8)
            keys = ["rebase_off", "rebase_size", "bind_off", "bind_size", "weak_bind_off", "weak_bind_size",
                    "lazy_bind_off", "lazy_bind_size", "export_off", "export_size"]
            s["dyld_info"] = dict(zip(keys, f))
        elif cmd in (0x1D, 0x26, 0x29, 0x33 | LC_REQ_DYLD, 0x34 | LC_REQ_DYLD):
            dataoff, datasize = struct.unpack_from("<II", d, off + 8)
            le = {"dataoff": dataoff, "datasize": datasize}
            if cmd == 0x1D:
                cs = {"present": True, **le}
                cs.update(parse_code_signature(d[dataoff:dataoff + datasize]))
                s["code_signature"] = cs
            elif cmd == 0x26:
                s["function_starts"] = le
            elif cmd == 0x29:
                s["data_in_code"] = le
            elif cmd == 0x33 | LC_REQ_DYLD:
                s["exports_trie"] = le
            else:
                hdr = struct.unpack_from("<7I", d, dataoff)
                keys = ["fixups_version", "starts_offset", "imports_offset", "symbols_offset", "imports_count",
                        "imports_format", "symbols_format"]
                le.update(dict(zip(keys, hdr)))
                seg_count = struct.unpack_from("<I", d, dataoff + hdr[1])[0]
                seg_info_offsets = list(struct.unpack_from("<%dI" % seg_count, d, dataoff + hdr[1] + 4))
                starts = []
                for si, sio in enumerate(seg_info_offsets):
                    if sio == 0:
                        continue
                    so = dataoff + hdr[1] + sio
                    ssz, page_size, pointer_format, segment_offset, max_valid_pointer, page_count = struct.unpack_from("<IHHQIH", d, so)
                    starts.append({"seg_index": si, "page_size": page_size, "pointer_format": pointer_format,
                                   "segment_offset": segment_offset, "page_count": page_count})
                le["seg_count"] = seg_count
                le["starts"] = starts
                s["chained_fixups"] = le
        off += cmdsize
    s["has_chained_fixups"] = s["chained_fixups"] is not None
    s["has_dyld_info"] = s["dyld_info"] is not None
    s["has_exports_trie"] = s["exports_trie"] is not None
    # nlist_64 scan for symbol counts
    if s["symtab"]:
        st = s["symtab"]
        counts = {"total": st["nsyms"], "defined": 0, "undefined": 0, "stabs": 0, "external": 0, "local": 0}
        objc_classes, objc_categories, objc_protocols, defined_names, undefined_names = [], [], [], [], []
        for i in range(st["nsyms"]):
            n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from("<IBBHQ", d, st["symoff"] + 16 * i)
            nm = cstr(d[st["stroff"] + n_strx:st["stroff"] + st["strsize"]])
            if n_type & N_STAB:
                counts["stabs"] += 1
                continue
            if (n_type & N_TYPE) == N_UNDF:
                counts["undefined"] += 1
                undefined_names.append(nm)
            else:
                counts["defined"] += 1
                defined_names.append(nm)
                if nm.startswith("_OBJC_CLASS_$_"):
                    objc_classes.append(nm[len("_OBJC_CLASS_$_"):])
                elif nm.startswith("__OBJC_$_CATEGORY_") and not re.match(
                        r"__OBJC_\$_CATEGORY_(INSTANCE_METHODS|CLASS_METHODS|PROP_LIST|PROTOCOLS)_", nm):
                    objc_categories.append(nm[len("__OBJC_$_CATEGORY_"):].replace("_$_", "(") + ")")
                elif nm.startswith("__OBJC_PROTOCOL_$_"):
                    objc_protocols.append(nm[len("__OBJC_PROTOCOL_$_"):])
            counts["external" if n_type & N_EXT else "local"] += 1
        s["symbols"] = counts
        s["defined_symbols_first20"] = sorted(defined_names)[:20]
        s["undefined_symbols_first20"] = sorted(undefined_names)[:20]
        s["objc_classes"] = sorted(objc_classes)
        s["objc_categories"] = sorted(objc_categories)
        s["objc_protocols"] = sorted(objc_protocols)
    # segment entropy (Shannon, bits/byte) for the packer heuristic
    import math
    from collections import Counter
    for seg in s["segments"]:
        seg["entropy"], seg["file_fraction"] = None, 0.0
        if seg["filesize"]:
            chunk = d[seg["fileoff"]:seg["fileoff"] + seg["filesize"]]
            c = Counter(chunk)
            n = len(chunk)
            seg["entropy"] = round(-sum(v / n * math.log2(v / n) for v in c.values()), 3)
            seg["file_fraction"] = round(n / len(d), 3)
    return s


def parse_file(path) -> dict:
    """
    Parses a thin or fat Mach-O file and returns {container, fat_arches, slices}.

    Parameters:
    -----------
    path : str
        Path of the Mach-O file.
    """
    data = open(path, "rb").read()
    magic = struct.unpack_from(">I", data, 0)[0]
    out = {"container": "thin", "fat_arches": [], "slices": []}
    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        out["container"] = "fat"
        out["fat_magic"] = "0x%08x" % magic
        nfat = struct.unpack_from(">I", data, 4)[0]
        for i in range(nfat):
            if magic == FAT_MAGIC:
                cputype, cpusub, off, sz, align = struct.unpack_from(">iiIII", data, 8 + 20 * i)
            else:
                cputype, cpusub, off, sz, align, _ = struct.unpack_from(">iiQQII", data, 8 + 32 * i)
            out["fat_arches"].append({"cputype": cputype, "cputype_name": CPU_NAMES.get(cputype, "?"),
                                      "cpusubtype": "0x%x" % (cpusub & 0xFFFFFFFF), "offset": off, "size": sz,
                                      "align": align, "align_bytes": 1 << align})
            out["slices"].append(parse_slice(data, off, sz))
    else:
        out["slices"].append(parse_slice(data, 0, len(data)))
    out["file_entropy"] = None
    return out


def dyld_info_lists(path, arch) -> dict:
    """
    Returns {exports, imports, objc_classes} scraped from dyld_info for one arch.

    Parameters:
    -----------
    path : str
        Mach-O path.
    arch : str
        Architecture name accepted by dyld_info -arch (arm64, arm64e, x86_64).
    """
    exports, imports, classes = [], [], []
    for line in sh("/usr/bin/dyld_info", "-arch", arch, "-exports", path).splitlines():
        m = re.match(r"\s+0x[0-9A-Fa-f]+\s+(\S+)", line)
        if m:
            exports.append(m.group(1))
    for line in sh("/usr/bin/dyld_info", "-arch", arch, "-imports", path).splitlines():
        m = re.match(r"\s+(?:0x[0-9A-Fa-f]+\s+)?(\S+)\s+\(from (\S+)\)", line)
        if m:
            imports.append({"symbol": m.group(1), "dylib": m.group(2)})
    for line in sh("/usr/bin/dyld_info", "-arch", arch, "-objc", path).splitlines():
        m = re.match(r"\s+@interface (\S+) : (\S*)", line)
        if m:
            classes.append({"name": m.group(1), "superclass": m.group(2)})
    nm_imports = []
    for line in sh("/usr/bin/nm", "-m", "-arch", arch, path).splitlines():
        m = re.match(r"\s+\(undefined\) (?:\S+ )?(\S+) \(from (\S+)\)", line)
        if m:
            nm_imports.append({"symbol": m.group(1), "dylib": m.group(2)})
    return {"nm_undefined_first20": nm_imports[:20], "nm_undefined_count": len(nm_imports),
            "exports_first20": exports[:20], "exports_count": len(exports),
            "imports_first20": imports[:20], "imports_count": len(imports),
            "objc_classes_dyld_info": classes}


def codesign_facts(target) -> dict:
    """
    Returns the identity facts codesign reports for a file or bundle.

    Parameters:
    -----------
    target : str
        Mach-O path or .app bundle path.
    """
    rc, out = sh_rc("/usr/bin/codesign", "-dvvv", target)
    facts = {"exit": rc, "signed": rc == 0, "identifier": None, "team_id": None, "cdhash": None,
             "flags": None, "signature": None, "format": None, "authority": [], "hash_type": None,
             "runtime_version": None, "timestamp": None, "info_plist": None, "sealed_resources": None}
    if "not signed at all" in out:
        facts["signature"] = "unsigned"
    for line in out.splitlines():
        k, _, v = line.partition("=")
        if k == "Identifier": facts["identifier"] = v
        elif k == "TeamIdentifier": facts["team_id"] = None if v == "not set" else v
        elif k == "CDHash": facts["cdhash"] = v
        elif k.startswith("CodeDirectory"):
            m = re.search(r"flags=(0x[0-9a-f]+)\(([^)]*)\)", v)
            facts["flags"] = {"hex": m.group(1), "names": m.group(2)} if m else v
            facts["code_directory_line"] = v
        elif k.startswith("Signature"): facts["signature"] = v if k == "Signature" else line
        elif k == "Format": facts["format"] = v
        elif k == "Authority": facts["authority"].append(v)
        elif k == "Hash type": facts["hash_type"] = v
        elif k == "Runtime Version": facts["runtime_version"] = v
        elif k == "Timestamp": facts["timestamp"] = v
        elif k.startswith("Info.plist"): facts["info_plist"] = line
        elif k.startswith("Sealed Resources"): facts["sealed_resources"] = line
    rc2, out2 = sh_rc("/usr/bin/codesign", "--verify", "--strict", "--verbose=2", target)
    facts["verify_exit"] = rc2
    facts["verify_output"] = [l.strip() for l in out2.strip().splitlines() if l.strip()]
    rc3, out3 = sh_rc("/usr/bin/codesign", "-d", "--entitlements", "-", "--xml", target)
    ents = None
    if rc3 == 0 and "<?xml" in out3:
        try:
            ents = sorted(plistlib.loads(out3[out3.index("<?xml"):].encode()).keys())
        except Exception:  # noqa: BLE001
            ents = ["<unparseable>"]
    facts["entitlements_keys"] = ents
    return facts


def spctl_facts(target) -> dict:
    """
    Returns the Gatekeeper assessment spctl gives for a file or bundle.

    Parameters:
    -----------
    target : str
        Mach-O path or .app bundle path.
    """
    rc, out = sh_rc("/usr/sbin/spctl", "-a", "-vv", "-t", "exec", target)
    verdict = "accepted" if rc == 0 else "rejected"
    source = None
    m = re.search(r"source=(.*)", out)
    if m:
        source = m.group(1).strip()
    return {"exit": rc, "assessment": verdict, "source": source, "raw": out.strip().splitlines()}


def fixture(corpus, name, macho, bundle=None) -> dict:
    """
    Assembles and returns the full fact record for one fixture.

    Parameters:
    -----------
    corpus : str
        tests/corpus directory (cwd for relative paths).
    name : str
        Fixture key used in summary.json.
    macho : str
        Path of the Mach-O to parse (relative to corpus, or absolute).
    bundle : str | None
        Bundle directory for codesign/spctl when the fixture is an app.

    Raises:
    -------
    AssertionError
        If the Python parser disagrees with otool/codesign on ncmds, identifier or cdhash.
    """
    path = macho if os.path.isabs(macho) else os.path.join(corpus, macho)
    data = open(path, "rb").read()
    rec = {"name": name, "path": macho, "bundle": bundle, "size": len(data),
           "sha256": hashlib.sha256(data).hexdigest(), "file": sh("/usr/bin/file", "-b", path).strip()}
    rec.update(parse_file(path))
    import math
    from collections import Counter
    c = Counter(data)
    rec["file_entropy"] = round(-sum(v / len(data) * math.log2(v / len(data)) for v in c.values()), 3)
    # cross-check with otool -h (ncmds / sizeofcmds per slice)
    for sl in rec["slices"]:
        arch = sl["cputype_name"]
        if arch == "arm64" and sl["cpusubtype_low"] == 2:
            arch = "arm64e"
            sl["cputype_name"] = "arm64e"
        hv = sh("/usr/bin/otool", "-arch", arch, "-h", path).splitlines()[-1].split()
        assert int(hv[5]) == sl["ncmds"] and int(hv[6]) == sl["sizeofcmds"], (name, arch, hv, sl["ncmds"])
        sl.update(dyld_info_lists(path, arch))
    target = os.path.join(corpus, bundle) if bundle else path
    rec["codesign"] = codesign_facts(target)
    rec["spctl"] = spctl_facts(target)
    # cross-check codesign vs parser on the first slice that has a signature
    for sl in rec["slices"]:
        cs = sl["code_signature"]
        if cs.get("present") and cs.get("code_directory") and rec["codesign"]["signed"] and rec["container"] == "thin":
            cd, csf = cs["code_directory"], rec["codesign"]
            assert cd["identifier"] == csf["identifier"], (name, cd["identifier"], csf["identifier"])
            assert cd["cdhash"] == csf["cdhash"], (name, cd["cdhash"], csf["cdhash"])
            assert isinstance(csf["flags"], dict) and cd["flags_hex"] == csf["flags"]["hex"], (name, cd["flags_hex"], csf["flags"])
            rec["cross_check"] = "identifier, cdhash and CS flags agree between python parser and codesign"
            break
    q = sh_rc("/usr/bin/xattr", "-p", "com.apple.quarantine", path)
    rec["quarantine"] = q[1].strip() if q[0] == 0 else None
    rec["xattrs"] = [l.strip() for l in sh("/usr/bin/xattr", path).splitlines() if l.strip()]
    if bundle:
        plist_path = os.path.join(corpus, bundle, "Contents", "Info.plist")
        with open(plist_path, "rb") as f:
            rec["info_plist"] = plistlib.load(f)
        rec["info_plist_format"] = sh("/usr/bin/file", "-b", plist_path).strip()
        rec["bundle_files"] = sorted(
            os.path.relpath(os.path.join(dp, fn), os.path.join(corpus, bundle))
            for dp, _, fns in os.walk(os.path.join(corpus, bundle)) for fn in fns)
    return rec


FIXTURES = [
    ("hello-c", "hello-c"), ("hello-x86_64", "hello-x86_64"), ("hello-fat", "hello-fat"),
    ("hello-objc", "hello-objc"), ("libhello.dylib", "libhello.dylib"), ("hello-usedylib", "hello-usedylib"),
    ("hello-adhoc", "hello-adhoc"), ("hello-entitled", "hello-entitled"), ("hello-unsigned", "hello-unsigned"),
    ("high-entropy", "high-entropy"), ("fake-packed", "fake-packed"), ("fake-upx", "fake-upx"),
    ("hello-zig", "hello-zig"), ("legacy-bind", "legacy-bind"), ("hello-quarantined", "hello-quarantined"),
    ("Hello.app", "Hello.app/Contents/MacOS/Hello", "Hello.app"), ("bin-ls", "/bin/ls"),
]


def main(corpus) -> None:
    """
    Prints summary.json for every fixture in FIXTURES to stdout.

    Parameters:
    -----------
    corpus : str
        tests/corpus directory.
    """
    recs = {}
    for entry in FIXTURES:
        recs[entry[0]] = fixture(corpus, *entry)
    doc = {"_generated_by": "tests/corpus/gen/summary.py",
           "_host": sh("/usr/bin/sw_vers", "-productVersion").strip() + " " + sh("/usr/bin/sw_vers", "-buildVersion").strip(),
           "_note": "Structural facts from an independent Python parser, cross-checked against otool/codesign; "
                    "exports/imports/objc from dyld_info; assessment from spctl. Hex strings are lowercase 0x-prefixed; "
                    "byte offsets/sizes are decimal integers.",
           "fixtures": recs}
    json.dump(doc, sys.stdout, indent=1, sort_keys=False, default=str)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main(os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..")))
