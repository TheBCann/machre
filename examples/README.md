# machre examples

Real transcripts from the release binary, run against the fixtures in `tests/corpus/`. Each file starts
with the command line and ends with the exit code. Regenerate them all with `examples/gen.sh` after
`zig build --release`.

| file | question it answers | command |
|---|---|---|
| [01-info.txt](01-info.txt) | What is this file, at a glance? | `machre info tests/corpus/hello-c` |
| [02-triage-suspicious.txt](02-triage-suspicious.txt) | Should I worry about it? (tampered, UPX-marked binary) | `machre triage tests/corpus/fake-upx` |
| [03-triage-explain.txt](03-triage-explain.txt) | Why did each rule fire? | `machre triage --explain tests/corpus/fake-upx` |
| [04-triage-clean.txt](04-triage-clean.txt) | What does a clean result look like? | `machre triage tests/corpus/hello-c` |
| [05-codesign.txt](05-codesign.txt) | Who signed it, and does the signature still match? | `machre codesign tests/corpus/hello-adhoc` |
| [06-entitlements.txt](06-entitlements.txt) | Which entitlements does it claim? | `machre entitlements tests/corpus/hello-entitled` |
| [07-imports.txt](07-imports.txt) | What does it call, and from which dylib? | `machre imports tests/corpus/hello-usedylib` |
| [08-bundle.txt](08-bundle.txt) | Is this app bundle intact? | `machre bundle tests/corpus/Hello.app` |
| [09-entropy.txt](09-entropy.txt) | Is anything packed or encrypted? | `machre entropy tests/corpus/high-entropy` |
| [10-disasm.txt](10-disasm.txt) | What does the code do? | `machre disasm --limit 40 tests/corpus/hello-c` |
| [11-malformed.txt](11-malformed.txt) | What happens with a hostile header? (`ncmds = 0xffffffff`) | `machre info tests/corpus/malformed/bogus-ncmds.bin` |
| [12-not-macho.txt](12-not-macho.txt) | And with a file too short to be Mach-O? | `machre info tests/corpus/malformed/truncated-header.bin` |
| [13-triage.json](13-triage.json) | The same triage, machine-readable | `machre triage --json tests/corpus/fake-upx` |
| [14-scripting.txt](14-scripting.txt) | Pull the verdict and findings out with `jq` | `machre triage --json … \| jq …` |
| [15-fail-on.txt](15-fail-on.txt) | Gate a script or CI job on the verdict (exit 20) | `machre triage --fail-on=suspicious -q …` |
| [16-otool-compat.txt](16-otool-compat.txt) | Is the text really compatible with Apple's tools? | `diff <(machre loadcmds --otool-compat …) <(otool -h -l …)` |

For a guided tour with commentary see `docs/TUTORIAL.md`; `docs/json-schema.md` documents every key in
the `--json` output. The `mtime` fields in `13-triage.json` come from the checkout, so they will differ on
your machine.
