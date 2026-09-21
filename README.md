# machre — Mach-O reverse-engineering and triage tool

A robustness-first static analysis tool for macOS Mach-O files (thin, fat/universal, bundles), written in
Zig `0.17.0-dev.2257`. Every byte is read through a bounds-checked reader, every count is clamped, every
structural problem becomes a diagnostic instead of a crash, and the shipped build is ReleaseSafe. The
design is in `docs/DESIGN.md`; the JSON contract in `docs/json-schema.md`.

## Build

```sh
zig build                                   # Debug binary in zig-out/bin/machre
zig build --release                         # shipped mode: ReleaseSafe (-Doptimize=ReleaseSafe also works)
zig build -Dcapstone=false                  # no libcapstone (default: auto-detect /opt/homebrew/opt/capstone)
zig build -Dcapstone=true                   # force libcapstone (static; -Dcapstone-static=false for the dylib)
zig build -Dsecurity=false                  # no Security/CoreFoundation frameworks (pure Zig; links only libSystem)
zig build -Dsecurity=false -Dcapstone=false # smallest configuration
zig build run -- info /bin/ls               # build and run
```

Build options: `-Dcapstone=<bool>`, `-Dcapstone-prefix=<dir>`, `-Dcapstone-static=<bool>`, `-Dsecurity=<bool>`,
`-Dupdate-golden=true` (rewrite `tests/golden/*.txt`), `-Dtest-filter=<substring>`, `-Doptimize=<mode>`.

## Test

```sh
zig build test --summary all        # everything: unit, cli, corpus facts, golden, robustness, deps
zig build test --release            # the same suite in ReleaseSafe (proves no trap is reachable)
zig build test-unit -Dtest-filter=reader
zig build test-corpus               # tests/facts/*.zig against tests/corpus/truth/summary.json
zig build test-golden               # tests/golden/*.rows.zig: otool/nm/dyld_info/codesign diffs + JSON key inventory
zig build test-robustness           # malformed x command matrix, 256-mutant sweep per fixture, budget tests, fuzzers
zig build test-robustness --fuzz    # loop the std.testing.fuzz Smith fuzzers
zig build test-deps                 # import-graph policy (DESIGN.md §4)
```

The corpus lives in `tests/corpus` (fixtures, `malformed/`, `truth/` with Apple-tool output and
`summary.json`); `tests/helpers.zig` locates it through the `corpus_manifest` build option.

## Usage

```
machre <command> [global flags] [command flags] <path>
machre help [command]          machre version
```

| command | purpose | mirrors |
|---|---|---|
| `info` | one-screen summary: container, header, platform, entry, dyld data, dylibs, segments, symbols, signature, security, quarantine | `otool -hv`, `dyld_info`, `vtool -show` |
| `header` | Mach header (`--fat`: fat table first) | `otool -hv` |
| `loadcmds` (alias `headers`) | every load command decoded (`--raw`: hexdump) | `otool -h -l` |
| `segments` | segments + sections with prot, flags, type, class (`--entropy`) | `otool -l`, `size -m` |
| `symbols` (alias `nm`) | nlist table, stabs, library ordinals, indirect table | `nm`, `nm -m`, `nm -a` |
| `dyld` (alias `fixups`) | chained fixups / legacy opcode streams, function starts, data-in-code | `dyld_info -fixups` |
| `imports` / `exports` | imported symbols with dylib attribution; export trie | `dyld_info -imports/-exports` |
| `codesign` / `entitlements` | embedded signature, page hashes, requirements, CMS chain, Security.framework verdict | `codesign -dvvv`, `-d -r-` |
| `objc`, `strings`, `entropy` | ObjC metadata, sectioned strings, per-segment entropy + packer tells | `dyld_info -objc`, `strings` |
| `plist`, `bundle`, `quarantine` | plist files, bundle layout/CodeResources, xattrs | `plutil -p`, `xattr -l` |
| `disasm`, `functions`, `xrefs` | disassembly with symbolization, function discovery, cross references | `otool -tV` |
| `triage` | scored anomaly report (KnockKnock style; never a single tell) | — |
| `dump` | hexdump of a section (`--section=__TEXT,__cstring`) or range (`--addr`, `--offset`) | `otool -s` |
| `report` (alias `all`) | every payload in one document | — |
| `version` | tool/zig version, capstone/security availability | — |

Global flags: `--json` / `--json-compact`, `--arch <name>`, `--all-archs` (JSON default; text shows the
host-preferred slice and says `N architectures, showing X`), `-v`/`--verbose` (repeatable), `-q`/`--quiet`,
`--limit <n>`, `--no-security`, `--no-network`, `--strict` (exit 4 on error diagnostics), `--paranoid`
(tiny parser limits), `--max-file-size <bytes>`, `--max-arena-bytes <bytes>` (analysis memory budget),
`--otool-compat` (text byte-compatible with the mirrored Apple tool: the text diffs empty against
`otool -hv`, `otool -h -l`, `otool -tV`, `nm -m`, `nm -a`, `dyld_info -fixups/-fixup_chains/-exports/-imports/
-function_starts`, `codesign -dvvv --entitlements -`, `codesign -d -r -`, `plutil -p` and `strings -n` -- those
diffs are the golden tests), `--color=auto|always|never`.

Exit codes: 0 ok · 1 usage · 2 I/O · 3 not a Mach-O (or `--arch` absent) · 4 `--strict` diagnostics ·
5 limits (`--max-file-size`) · 6 feature unavailable · 20 triage threshold · 70 internal (OOM past the arena
budget — reported, never a trap).

## Layout

```
build.zig, build.zig.zon    build graph (DESIGN.md §11); one build_options module shared by every compilation
src/main.zig, src/root.zig  entry point; library root that references every declaration at comptime
src/core/                   kernel (std only): reader, limits + budget allocator, diagnostics, arch, sanitize,
                            fmt, version tables, macho_extra, load-command walker, segments, fat, file, image
src/macho/                  symbols, chained fixups, export trie, legacy dyld info, function starts, fixups, imports
src/codesign/               ASN.1, SuperBlob/CodeDirectory, hashes, requirements, entitlements, CMS
src/darwin/                 Security.framework verdict, xattrs/quarantine, dylib resolution (macOS only)
src/objc/ src/strings/ src/plist/ src/bundle/ src/disasm/ src/analysis/   ObjC, strings, plists, bundles,
                            disassembly, entropy, the memoising Analysis facade, triage
src/output/                 Sink, JSON conventions (envelope, hex/sanitised strings), text tables
src/cli/                    flag parser, Context/Command/ExitCode leaf, dispatcher + framing
src/cmd/<name>.zig          one file per subcommand (text + JSON rendering)
tests/                      helpers, truth-section comparators, corpus facts, golden rows, robustness, deps policy
docs/                       DESIGN.md, json-schema.md, research notes
```

Work-package status (DESIGN.md §12): every work package (WP0-WP9) is implemented and integrated. Three
DESIGN claims described a different corpus than the shipped one and were corrected against it at integration
(each carries a note in `docs/DESIGN.md`): §5.4/§5.5's `fake-upx` numbers (1 bad page hash at page 0, max
segment entropy 5.16 `__LINKEDIT`), and §4.16's `@rpath/libhello.dylib`, which resolves to `on_disk` for the
bare `hello-usedylib` because `tests/corpus/libhello.dylib` sits next to it and the fixture's first `LC_RPATH`
is `@executable_path`. DESIGN §12/WP1's claim that the `/bin/ls` x86_64 slice carries `LC_VERSION_MIN_MACOSX`
is also false on this machine (both slices use `LC_BUILD_VERSION`, x86_64 minos 10.14 as §10.3 says);
`tests/golden/core.rows.zig` covers the `LC_VERSION_MIN_MACOSX` renderer with a synthetic 48-byte Mach-O
diffed against `otool -h -l` on the same bytes instead.

WP0 decisions not spelled out in DESIGN.md §4: `cmd/*.zig` may import other `cmd/*.zig` renderers (shared
header/segment JSON), `cli/cli.zig` imports `bundle/bundle.zig` (`mainExecutable`) and `darwin/xattr.zig`
(the envelope's `file.xattrs`/`file.quarantine`/`file.translocated`, §6.1), `plist/plist.zig` imports
`plist/bplist.zig` and `plist/xml.zig` (§4.20 puts `parseAny` there, so it must dispatch), the
`--max-arena-bytes` global flag exists for budget tests, and the top-level `bundle` key is written only by the
commands that analyse a bundle (`json.endArches` closes the `arches` array before top-level payloads).
