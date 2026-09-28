#!/bin/bash
# Regenerate every example transcript in examples/ from the test corpus.
# Run from the repository root after `zig build --release`:
#   examples/gen.sh
# Paths stay relative so the transcripts carry no machine-specific directories.
set -u

cd "$(dirname "$0")/.." || exit 1
MACHRE=${MACHRE:-zig-out/bin/machre}
C=tests/corpus
OUT=examples

[ -x "$MACHRE" ] || { echo "build first: zig build --release" >&2; exit 1; }

# run <output file> <machre args...>: writes "$ machre <args>", the output and the exit code.
run() {
    file=$1; shift
    {
        echo "\$ machre $*"
        "$MACHRE" "$@" 2>&1
        echo "[exit $?]"
    } > "$OUT/$file"
}

# shell <output file> <command line>: same, for pipelines (machre stands for $MACHRE).
shell() {
    file=$1; shift
    {
        echo "\$ $1"
        machre() { "$MACHRE" "$@"; }
        eval "$1" 2>&1
        echo "[exit $?]"
    } > "$OUT/$file"
}

run 01-info.txt                  info $C/hello-c
run 02-triage-suspicious.txt     triage $C/fake-upx
run 03-triage-explain.txt        triage --explain $C/fake-upx
run 04-triage-clean.txt          triage $C/hello-c
run 05-codesign.txt              codesign $C/hello-adhoc
run 06-entitlements.txt          entitlements $C/hello-entitled
run 07-imports.txt               imports $C/hello-usedylib
run 08-bundle.txt                bundle $C/Hello.app
run 09-entropy.txt               entropy $C/high-entropy
run 10-disasm.txt                disasm --limit 40 $C/hello-c
run 11-malformed.txt             info $C/malformed/bogus-ncmds.bin
run 12-not-macho.txt             info $C/malformed/truncated-header.bin
run 13-triage.json               triage --json $C/fake-upx
shell 14-scripting.txt           "machre triage --json $C/fake-upx | jq -r '.arches[].triage | .level, (.findings[] | \"\\(.severity)\\t\\(.id)\")'"
shell 15-fail-on.txt             "machre triage --fail-on=suspicious -q $C/fake-upx > /dev/null; echo \"exit code: \$?\""
shell 16-otool-compat.txt        "diff <(machre loadcmds --otool-compat $C/hello-c) <(otool -h -l $C/hello-c) && echo identical"
