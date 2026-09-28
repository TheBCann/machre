# machre internals

Contributor reference: the design machre was built from and the research it was verified against. You
do not need any of this to use machre; see `docs/TUTORIAL.md` and `examples/` for that. Source comments
cite these files by name and section, e.g. `DESIGN.md §4` or `format-notes 4.1`.

| file | contents |
|---|---|
| [DESIGN.md](DESIGN.md) | The binding design: module layout and import rules (§4), CLI and exit codes (§5), JSON conventions (§6), parser limits (§7), Security.framework layer (§8), disassembly (§9), testing (§10), build graph (§11), work packages (§12). |
| [format-notes.md](format-notes.md) | Mach-O, dyld fixups and export tries, code signing blobs, ObjC metadata, plists and xattrs, each checked against Apple's tools. |
| [disasm-notes.md](disasm-notes.md) | Capstone linkage, the built-in arm64 decoder and x86_64 length decoder, stub symbolization. |
| [corpus-notes.md](corpus-notes.md) | How `tests/corpus/` is generated and what each fixture exercises. |
| [zig-api-notes.md](zig-api-notes.md) | The Zig nightly std APIs machre relies on, as verified at the time. |

These notes were written during development (September 2026, Zig `0.17.0-dev.1154` to `dev.2257`, macOS
26.3). The source is authoritative where they disagree. Where DESIGN.md lists `skeleton-reference/` or
`docs/design-candidates/`, those were build-time scaffolding and are not part of the repository.
