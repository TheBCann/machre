#!/bin/bash
# truth.sh -- capture Apple-tool ground truth for every healthy fixture, Hello.app's main executable
# and /bin/ls into tests/corpus/truth/<name>.txt, then build truth/summary.json via gen/summary.py.
# Idempotent; re-run after build.sh.
#
# Captures are not kept "for reference": a section nothing reads is dead weight. Every `run` line below
# is diffed by a test (tests/golden/*.rows.zig and tests/facts/*.zig; tests/truth.zig splits the file
# into sections) EXCEPT these five, which are provenance only -- a record of what the fixture was when
# the corpus was generated: `file`, `stat -f`, `shasum -a 256`, `spctl -a` and `plutil -lint`.
# If you add a `run` line, add its reader too, or say here why it is provenance only.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORPUS="$(cd "$HERE/.." && pwd)"
T="$CORPUS/truth"
mkdir -p "$T"
cd "$CORPUS"

OTOOL=/usr/bin/otool; NM=/usr/bin/nm; DI=/usr/bin/dyld_info; CS=/usr/bin/codesign; VT=/usr/bin/vtool
STRINGS=/usr/bin/strings; FILE=/usr/bin/file; PLUTIL=/usr/bin/plutil; XATTR=/usr/bin/xattr; SPCTL=/usr/sbin/spctl
OBJDUMP="$(/usr/bin/xcrun -f objdump)"

section() { printf '\n===== %s =====\n' "$*"; }
run() { section "$*"; "$@" 2>&1; printf -- '--- exit=%s\n' "$?"; }

# capture <name> <macho path> [bundle path]
capture() {
    local name="$1" bin="$2" bundle="${3:-}" out="$T/$1.txt"
    {
        echo "# machre corpus ground truth for $name"
        echo "# generated $(date -u +%Y-%m-%dT%H:%M:%SZ) on $(sw_vers -productVersion) ($(sw_vers -buildVersion)) by gen/truth.sh"
        echo "# macho=$bin bundle=${bundle:-none}"
        run $FILE "$bin"
        run /usr/bin/stat -f 'size=%z mode=%Mp%Lp' "$bin"
        run /usr/bin/shasum -a 256 "$bin"
        run $OTOOL -hv "$bin"
        run $OTOOL -h -l "$bin"
        run $OTOOL -L "$bin"                # facts/tool_oracles.zig (id dylib + imports)
        # The disassembly and indirect-symbol ground truth: `machre disasm --otool-compat` is diffed
        # against -tV (facts/disasm.zig), and the stub/pointer tables machre rebuilds from the section
        # headers + indirect symbol table are diffed against -Iv (facts/tool_oracles.zig).
        run $OTOOL -tV "$bin"
        run $OTOOL -Iv "$bin"
        run $NM -m "$bin"
        run $NM -a "$bin"
        run $DI -platform -uuid -segments -linked_dylibs -load_commands "$bin"  # -platform: facts/tool_oracles.zig
        run $DI -fixup_chains "$bin"
        run $DI -fixups "$bin"
        run $DI -exports "$bin"
        run $DI -imports "$bin"
        run $DI -objc "$bin"
        # -inits is empty for every fixture in the corpus; facts/tool_oracles.zig asserts that machre
        # agrees no image has an initializer, and fails loudly if a future fixture adds one.
        run $DI -inits "$bin"
        run $DI -function_starts "$bin"
        # Clean for every fixture. NOT equivalent to `machre --strict` (fake-upx validates for dyld
        # but machre reports its renamed UPX_DATA segment): facts/tool_oracles.zig asserts the
        # structural claim instead -- dyld read the image, so machre parsed every load command.
        run $DI -validate_only "$bin"
        run $VT -show "$bin"                # facts/tool_oracles.zig vs the `info` platform line
        run $CS -dvvv --entitlements - "${bundle:-$bin}"
        run $CS -d --entitlements - --xml "${bundle:-$bin}"
        run $CS -d -r - "${bundle:-$bin}"
        run $CS --verify --verbose=4 --strict "${bundle:-$bin}"
        run $SPCTL -a -vv -t exec "${bundle:-$bin}"
        run $XATTR -l "$bin"
        if [ -n "$bundle" ]; then
            run $PLUTIL -p "$bundle/Contents/Info.plist"
            run $PLUTIL -lint "$bundle/Contents/Info.plist"
            run $FILE "$bundle/Contents/Info.plist"
            run /usr/bin/find "$bundle" -type f
            run $CS -dvvv "$bundle/Contents/Frameworks/libhello.dylib"
        fi
        if $OTOOL -l "$bin" | /usr/bin/grep -q '__objc_classlist'; then
            # PARTIAL oracle only: objdump mis-resolves RELATIVE method lists and prints
            # "extends past end of file" for 220 name/types/imp rows that are plainly inside the image
            # (e.g. -[MachreAnimal sound] at 0x100001064, which `machre objc` resolves correctly).
            # facts/tool_oracles.zig asserts the parts objdump gets right and proves the flagged
            # addresses really are file-backed instead of trusting the tool.
            run "$OBJDUMP" --macho --objc-meta-data "$bin"
        fi
        section "$STRINGS -n 6 | head -200"
        $STRINGS -n 6 "$bin" 2>&1 | /usr/bin/head -200
        # Every section must be closed by an "--- exit=" line or tests/truth.zig cannot see it.
        printf -- '--- exit=%s\n' "${PIPESTATUS[0]}"
    } > "$out"
    printf '[truth] %-18s -> %s (%s lines)\n' "$name" "$out" "$(wc -l < "$out" | tr -d ' ')"
}

capture hello-c            hello-c
capture hello-x86_64       hello-x86_64
capture hello-fat          hello-fat
capture hello-objc         hello-objc
capture libhello.dylib     libhello.dylib
capture hello-usedylib     hello-usedylib
capture hello-adhoc        hello-adhoc
capture hello-entitled     hello-entitled
capture hello-unsigned     hello-unsigned
capture high-entropy       high-entropy
capture fake-packed        fake-packed
capture fake-upx           fake-upx
capture hello-zig          hello-zig
capture legacy-bind        legacy-bind
capture hello-quarantined  hello-quarantined
capture Hello.app          Hello.app/Contents/MacOS/Hello Hello.app
capture bin-ls             /bin/ls

# Apple-tool reactions to the malformed fixtures (robustness expectations)
{
    echo "# How Apple's tools react to each malformed fixture (generated by gen/truth.sh)"
    for f in malformed/*.bin; do
        section "$f"
        echo "-- otool -h:"; $OTOOL -h "$f" 2>&1 | /usr/bin/tail -3; echo "   exit=$?"
        echo "-- otool -l (first 3 lines):"; $OTOOL -l "$f" 2>&1 | /usr/bin/head -3
        echo "-- dyld_info -validate_only:"; $DI -validate_only "$f" 2>&1 | /usr/bin/head -3; echo "   exit=${PIPESTATUS[0]}"
        echo "-- file:"; $FILE "$f" 2>&1
        echo "-- codesign -dv:"; $CS -dv "$f" 2>&1 | /usr/bin/head -2
    done
} > "$T/malformed-tool-reactions.txt"
echo "[truth] malformed-tool-reactions.txt"

# Toolchain versions used to build the corpus
{
    echo "# Toolchain that produced this corpus (gen/truth.sh)"
    sw_vers; echo
    /usr/bin/clang --version; echo
    /usr/bin/ld -v 2>&1 | /usr/bin/head -2; echo
    /usr/bin/xcrun --show-sdk-version; /usr/bin/xcrun --show-sdk-path; echo
    /usr/bin/xcodebuild -version 2>/dev/null; echo
    "${ZIG:-/Users/bcann/.zig-versions/nightly/zig}" version
    python3 --version
} > "$T/TOOLS.txt"
echo "[truth] TOOLS.txt"

python3 "$HERE/summary.py" "$CORPUS" > "$T/summary.json" && echo "[truth] summary.json ($(wc -c < "$T/summary.json" | tr -d ' ') bytes)"
