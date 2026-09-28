# machre tutorial

A hands-on tour of `machre`, a Mach-O reverse-engineering and triage tool.
Every example is real output from the built binary.

## 1. Build

```
cd machre && zig build --release
./zig-out/bin/machre version
```

`version` reports whether `capstone` and `security` are linked. Capstone gives
full x86-64 disassembly; Security.framework gives signature *verdicts* and the
notarization check. Without them machre still runs and says what it could not
check, rather than staying silent.

## 2. The first look

`machre info <path>` is the one-screen summary: container, header, platform,
entry, dylibs, segments, symbol counts, signature, quarantine.

Read it bottom-up when triaging:
- `pages 18/18 ok` — machre recomputed every code-page hash against the file.
- `trust: platform` — top of the ladder (Apple, anchor apple).
- `notarized: no` on an Apple binary is correct; on third-party software it is not.

`machre triage --explain <path>` gives the scored verdict plus the rationale for
each rule that fired. The `Not flagged:` line is as important as the findings —
it states what was checked and came back clean.

## 3. Commands, by question asked

| command | answers | mirrors |
|---|---|---|
| `info` | Everything at once. Start here. | — |
| `triage` | Is this suspicious, and on what evidence? | — |
| `report` | info + codesign + imports + triage together | — |
| `header` | Mach header and fat table | `otool -hv` |
| `loadcmds` | Every load command decoded | `otool -h -l` |
| `segments` | Segments/sections: prot, flags, type, entropy | cf. `otool -l`, `size -m` |
| `symbols` | Symbol table, stabs, ordinals, indirect table | `nm -m` |
| `imports` | Imported symbols attributed to their dylib | `dyld_info -imports` |
| `exports` | Export trie / defined external symbols | `dyld_info -exports` |
| `dyld` | Chained fixups, opcodes, function starts, data-in-code | `dyld_info` |
| `codesign` | Signature parsed in Zig + Security.framework verdict | `codesign -dvvv` |
| `entitlements` | XML and DER entitlements, dangerous keys annotated | `codesign -d --ent` |
| `bundle` | Bundle layout, nested code, CodeResources seal, ticket | cf. `codesign --verify` |
| `quarantine` | xattrs, parsed com.apple.quarantine, translocation | `xattr -l` |
| `objc` | Classes, methods, ivars, protocols, selectors | cf. `dyld_info -objc` |
| `strings` | Strings by kind and analyst classification | `strings` |
| `entropy` | Per-segment/section entropy and packer tells | — |
| `disasm` | Disassembly with symbolization | `otool -tV` |
| `functions` | Discovered functions with source and size | `dyld_info -function_starts` |
| `xrefs` | Cross-references to/from an address or symbol | — |
| `dump` | Hexdump of a section or vm/file range | cf. `xxd`, `otool -s` |
| `plist` | A .plist, `__TEXT,__info_plist`, or Contents/Info.plist | `plutil -p` |
| `version` | Tool version and linked optional features | — |

Only these 13 diff empty against their Apple tool under `--otool-compat`: `header`, `loadcmds`,
`symbols`, `dyld`, `imports`, `exports`, `functions`, `codesign`, `entitlements`, `strings`,
`quarantine`, `plist`, `disasm`. Rows marked `cf.` name the tool that answers the same question;
`--otool-compat` is a no-op for those.

### Per-command flags worth knowing

- `triage --explain` — reasoning for each rule.
- `triage --fail-on=notable|suspicious|likely_malicious` — exit 20 at/above that level.
- `imports --by-dylib` — capability view; `--resolve` checks each dependency exists.
- `strings --class=url|shell|persistence|keychain|crypto_wallet|anti_analysis|launch_agent|...`
- `strings --kind=cstring|cfstring|objc_methname|...`, `--bare` to diff against `strings(1)`.
- `entropy --sections` — a small packed section hides inside a large normal segment.
- `disasm --func=<name>` / `--addr=0x...`, `--backend=auto|capstone|builtin`, `--att`/`--intel`.
- `xrefs --to=<sym>` / `--from=<sym>`, `--strings` to tie strings to their user.
- `codesign --hashes --cms --der` for signature internals.
- `bundle --nested --files` to audit helper apps and frameworks.
- `functions --sort=addr|name|size`; `symbols --mode=nm|nm-m|nm-a|machre --sort=addr|name|index`.
- `plist --format=auto|bplist|xml --key=<k>`; `report --only=<command>`.

## 4. Global flags that change results (not just formatting)

**Fat binaries.** Text output analyses ONE slice and says so on line 1.
`--json` defaults to ALL slices. A text/JSON or machre/`nm` comparison can look
wrong when both are right. Pin it with `--arch arm64e` whenever comparing.

**Truncation.** Most long tables cap at 500 rows in text (`--limit`; JSON defaults to 0 =
unlimited). It tells you, but a count taken from truncated output is wrong. Not universal:
`symbols` in its default nm-m mode, `loadcmds` and `dump` are uncapped. Pass `--limit 0`
before counting.

Others: `--all-archs`, `--no-security` (never call Security.framework — recorded
as `sig.not_evaluated`, never silent), `--no-network`, `--paranoid` (tiny parser
limits for hostile input), `--strict` (exit 4 on error diagnostics),
`--otool-compat` (byte-compatible with the mirrored Apple tool, for the 13 commands that have one;
a no-op for `segments`, `dump`, `objc`, `bundle`, `info`, `entropy`, `xrefs`, `triage`), `-v`, `-q`.

## 5. A worked investigation

1. **Identity and integrity** — `machre info`. Record the SHA-256. If
   `pages n/n ok` and trust is `platform` or `Developer ID, notarized`
   (`developer_id_notarized` in JSON), most files are done.
2. **Score it** — `machre triage --explain`.
3. **Who signed it** — `machre codesign`. Ad hoc proves only that the file has
   not changed since signing; it names nobody. A revoked cert or page-hash
   mismatch means modification after signing — stop and treat as hostile.
4. **Capabilities** — `machre entitlements` (dangerous keys annotated inline),
   then `machre imports --by-dylib` for what it actually links against. The
   difference between permitted and used.
5. **Packing** — `machre entropy --sections`. Near 8.0 bits/byte is compressed
   or encrypted.
6. **Behaviour** — `machre strings --class=<class>` instead of reading 50,000
   strings.
7. **Follow the code** — `machre xrefs --strings` ties a suspicious string to
   the function using it, then `machre disasm --func=<name>`.
8. **Bundles** — `machre bundle` recomputes each nested cdhash and compares it
   to the parent CodeResources seal. Healthy apps read `verify ok ... 0 mismatched`.

## 6. What to look for

53 rules across 11 categories, following Wardle's "no single tell" rule.

- score = sum(fired weights) − credits, floored at 0
- credits: Apple platform −20, notarized Developer ID −15, App Store −15, hardened runtime −3
- every weight is < 50, asserted at compile time
- `suspicious` and `likely_malicious` need >= 2 categories; a 100+ score from a single category
  is capped at `suspicious` rather than demoted further

| level | score | also requires |
|---|---|---|
| clean | 0–19 | — |
| notable | 20–49 | — |
| suspicious | 50–99 | >= 2 categories (else notable) |
| likely_malicious | 100+ | >= 2 categories (else suspicious) |

Heaviest rules: `sig.revoked` 45, `sig.invalid` 35, `hdr.rwx_segment` 30, then
at 25: `sig.unsigned`, `pack.entropy`, `pack.names`, `pack.no_imports_no_symbols`,
`bundle.resource_mismatch`. Four rules score 0 and are context, never evidence:
`sig.not_evaluated`, `sym.stripped`, `quarantine.present`, `quarantine.translocated`.
Run `machre triage --explain` for the full list with rationale, or see the web
version linked above for the complete weighted table.

### Combinations that matter

Single findings are usually boring; pairs are actionable, and machre prints a
`Corroboration:` line when it sees one.

- packer name + broken signature -> modified after linking
- high entropy + no imports/symbols -> unpacking stub, payload compressed
- persistence strings + LSUIElement -> wants to run invisibly and survive reboot
- disable-library-validation + get-task-allow -> built for injection
- RWX segment + allow-unsigned-memory -> generates code at runtime

Context that is NOT evidence on its own: ad hoc signatures (normal for locally
built and open-source binaries), high entropy (normal with compressed assets),
a quarantine xattr (just means downloaded).

## 7. Traps

Each of these produced a wrong conclusion during the tool's own verification.

- **Fat-slice default** — text one slice, JSON all slices. Use `--arch`.
- **Row truncation** — most long tables cap at 500 rows in text (`strings`, `exports`, `functions`,
  `xrefs`, `disasm`, `symbols --mode=machre`) and say so; `symbols` in its default nm-m mode,
  `loadcmds` and `dump` are uncapped. Use `--limit 0` before counting.
- **Exit code through a pipe** — `$?` after `| head` is head's status. Redirect.
- **Counting extracted strings** — `strings` prints words *found in* the target,
  so grepping its output for "panic" finds the target's text, not a crash.
- **`--no-security` means unverified** — trust comes only from the embedded
  chain; revocation is unknown. Read `sig.not_evaluated`.
- **Dylib install name** — `otool -L` prints a dylib's own install name first;
  `imports` lists only real dependencies. Counts differ by one, correctly.
- **Stale seals are real** — a nested cdhash mismatch is not always tampering;
  some vendors re-sign components after the outer signature.

## 8. Scripting

```sh
machre triage --fail-on=suspicious --json app >/dev/null 2>&1; echo "rc=$?"   # 20

for f in /Applications/*.app; do
  machre triage --fail-on=suspicious -q "$f" >/dev/null 2>&1 || echo "REVIEW: $f"
done
```

Exit codes: `0` ok, `1` usage, `2` io, `3` not Mach-O, `4` `--strict`
diagnostics, `5` limits, `6` feature unavailable, `20` triage threshold,
`70` internal.

Every JSON response opens with a `machre` object carrying `version`, `schema`,
`command`, and whether `capstone`/`security` were available, so a consumer can
tell a real negative from an unlinked feature. Fat binaries produce an `arches`
array — index into it rather than assuming one slice.
