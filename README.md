# machre — Mach-O reverse-engineering and triage tool

A robustness-first static analysis tool for macOS Mach-O files (thin, fat/universal, bundles), written in
Zig. Every byte is read through a bounds-checked reader, every count is clamped, every structural problem
becomes a diagnostic instead of a crash, and the shipped build is ReleaseSafe.

```
$ machre triage tests/corpus/fake-upx
machre triage: tests/corpus/fake-upx [arm64]
LEVEL: SUSPICIOUS (score 60, 2 categories)            trust: INVALID SIGNATURE
Signing     [HIGH]   sig.invalid       embedded CodeDirectory does not match the file: 1/13 page hashes mismatch (first page 0 @ 0x0); Security: errSecCSSignatureFailed (-67061)
Packing     [MEDIUM] pack.names        segment named UPX_DATA (UPX marker) at LC index 2
Signing     [LOW]    sig.adhoc         ad hoc, linker-signed; no certificate chain, not notarized
Corroboration: packing tell (UPX_DATA) is corroborated by a broken signature -> file was modified after linking.
```

## Requirements

- macOS (arm64 or x86_64) with the Xcode command-line tools. The Security.framework verdicts,
  notarization check and quarantine xattrs are macOS-only; `-Dsecurity=false` builds a pure-Zig binary.
- Zig nightly, `0.17.0-dev.2257` or newer (tested with `0.17.0-dev.2307`). The std API still changes
  between nightlies, so a much newer build may need small fixes.
- Optional: Capstone (`brew install capstone`) for full x86_64 disassembly. Without it machre uses its
  built-in arm64 decoder and an x86_64 length decoder.

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
zig build test-deps                 # import-graph policy between modules
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

## Documentation and examples

- [`docs/TUTORIAL.md`](docs/TUTORIAL.md): a hands-on tour, from the first look at a file to a worked
  investigation, what to look for, common traps and scripting.
- [`examples/`](examples/): real transcripts of every major command against the test corpus, including
  hostile inputs, `--json` output with `jq`, and CI gating with `--fail-on`.
- [`docs/json-schema.md`](docs/json-schema.md): every key in the `--json` output, the triage rule ids and
  the exit codes.
- `machre help <command>`: flags for one command.

## Layout

```
build.zig, build.zig.zon    build graph; one build_options module shared by every compilation
src/main.zig, src/root.zig  entry point; library root that references every declaration at comptime
src/core/                   kernel (std only): reader, limits + budget allocator, diagnostics, arch, sanitize,
                            fmt, version tables, load-command walker, segments, fat, file, image
src/macho/                  symbols, chained fixups, export trie, legacy dyld info, function starts, imports
src/codesign/               ASN.1, SuperBlob/CodeDirectory, hashes, requirements, entitlements, CMS
src/darwin/                 Security.framework verdict, xattrs/quarantine, dylib resolution (macOS only)
src/objc/ src/strings/ src/plist/ src/bundle/ src/disasm/ src/analysis/   ObjC, strings, plists, bundles,
                            disassembly, entropy, the memoising Analysis facade, triage
src/output/                 Sink, JSON conventions (envelope, hex/sanitised strings), text tables
src/cli/                    flag parser, Context/Command/ExitCode, dispatcher
src/cmd/<name>.zig          one file per subcommand (text + JSON rendering)
tests/                      corpus facts, golden diffs against Apple tools, robustness/fuzz, deps policy
tests/corpus/               fixtures built from source by tests/corpus/gen/, malformed/ inputs, truth/ from Apple tools
examples/                   command transcripts (examples/gen.sh regenerates them)
docs/                       tutorial and JSON schema
```

## License

MIT; see [LICENSE](LICENSE).
