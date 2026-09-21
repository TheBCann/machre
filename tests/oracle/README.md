# lldb oracle — validating machre against the live process

`otool`, `nm` and `dyld_info` are the ground truth for what a Mach-O *file* says.
They cannot tell you what dyld and the Objective-C runtime *do* with it. This
oracle launches each corpus fixture under lldb, stops at `main` (every fixup has
been applied, every class registered), and checks machre's static predictions
against real process memory.

```bash
tests/oracle/lldb_oracle.py                 # all runnable arm64 fixtures
ORACLE_ONLY=hello-zig tests/oracle/lldb_oracle.py
ORACLE_DEBUG=1 ORACLE_ONLY=hello-c tests/oracle/lldb_oracle.py
```

It is not wired into `zig build test`: it needs lldb, spawns processes, and takes
about a minute. Run it after touching `src/dyld/`, `src/objc/`, or `src/disasm/functions.zig`.

## What is judged, and how

| machre output | oracle | pass rule |
|---|---|---|
| `dyld` binds (chained, `LC_DYLD_INFO`, lazy) | raw slot value → `image lookup -a`, `image lookup -n` | same symbol, **or** same address under another name, **or** a documented rewrite (below) |
| `dyld` rebases | raw slot value | equals the decoded target (chained) or the file word (legacy); slide is 0 under lldb |
| `functions` starts | `image lookup -v -a` | an lldb symbol range begins exactly there |
| `objc` classes and methods | `objc_getClass`, `method_getImplementation` via `expr` | class exists; the runtime IMP equals machre's decoded `imp` (this exercises relative/small method lists) |
| `objc` selector refs | C string at the runtime pointer | names the same selector machre decoded |

## Differences that are correct, and why

The file and the running process legitimately disagree in six ways. Each is
verified by address or content, never assumed:

- **alias** — `wait4` and `__wait4_nocancel` are one address; lldb prefers one name.
- **reexport** — `memcpy`, `strcmp`, `strlen` in libsystem_c are forwarding stubs
  with no address of their own; dyld lands on `_platform_*` in libsystem_platform.
- **tlv-rewrite** — every thread-local descriptor binds `__tlv_bootstrap` in the
  file; dyld overwrites the thunk with `_tlv_get_addr` at load.
- **objc-class** — `_OBJC_CLASS_$_NSString` is the object the runtime labels `NSString`.
- **bind-authoritative** — a legacy `__la_symbol_ptr` slot carries both a rebase
  (to the stub helper) and a lazy bind; dyld4 binds eagerly and the bind wins.
- **selref-uniqued** — `__objc_selrefs` entries are rebased to the image's own
  `__objc_methname` string; the runtime repoints them at the uniqued copy in the
  shared cache. The oracle reads both strings and requires them to match.

machre reports what the file says in all six cases, which is the right thing for
a static tool.

## Caveats

- `image lookup -n` on a **data** symbol such as `__stack_chk_guard` makes both
  Apple's and Homebrew's lldb exit(1) silently, killing the rest of the batch.
  The oracle therefore issues name lookups only for binds that did not already
  match by address, and reports any lookup lldb aborted on as `lldb-aborted`,
  never as a machre failure.
- lldb stops on the first failing batch command unless
  `interpreter.stop-command-source-on-error` is off; the oracle turns it off.
- Disassembly *text* is not judged here: lldb uses the same LLVM disassembler as
  `otool`, so that comparison lives in `tests/facts/disasm.zig` against `otool -tV`.
- Fixtures that the kernel refuses to launch (an unsigned arm64 binary, for
  instance) are reported as `SKIP`, not as failures.
- SIP does not matter for the corpus: these are ad-hoc-signed non-platform
  binaries. SIP only matters if you point the oracle at `/bin/*` or another
  platform binary.
