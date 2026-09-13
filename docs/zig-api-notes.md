# Zig API notes for machre (verified on this machine)

- Zig: `0.17.0-dev.1154+ba5420896` at `/Users/bcann/.zig-versions/nightly/zig`; std at `/Users/bcann/.zig-versions/nightly/lib/std`.
- Host: macOS 26.3 arm64, SDK 26.5 (`xcrun --show-sdk-path`).
- Everything below was verified by reading the std source at the paths cited and by building and running the probe project:
  - `/private/tmp/claude-501/-Users-bcann-programming-mac-security/9135d7a5-d466-4310-b16a-780257c75456/scratchpad/probe-zig-api/` (`build.zig`, `src/main.zig`)
  - `zig build run -- /bin/ls`, `zig build test` (6/6 pass), `zig build -Doptimize=ReleaseSafe`, `zig build -Doptimize=ReleaseFast -Dcapstone=true run` all succeed.
  - Output cross-checked against `shasum -a 256`, `shasum`, `codesign -dv --verbose=2`, `otool -l`, `xattr -p`: sha256/sha1 of `/bin/ls` match exactly, identifier `com.apple.ls`, platform 26, 20 load commands, Discord team id `53Q6R32WPB`, ad-hoc binary flags `0x20002`.

Signatures are copied verbatim from std source. Line numbers refer to files under `lib/std/`.

---

## 0. Gotchas / compile errors hit (read this first)

| # | Symptom | Fix |
|---|---------|-----|
| 1 | `error: invalid builtin function: '@cImport'` | **`@cImport` no longer exists in this nightly.** Use `b.addTranslateC(.{ .root_source_file, .target, .optimize, .link_libc })` in build.zig, then `exe_mod.addImport("name", tc.createModule())` and `@import("name")` in Zig. Verified with capstone. |
| 2 | translate-c of `Security/Security.h`, `Security/SecCode.h`, `Security/SecStaticCode.h` fails: `xpc/xpc.h:992: nullability specifier cannot be applied to non-pointer type 'uuid_t'` (3 sites) | translate-c (aro frontend) claims `__has_feature(nullability_on_arrays)` and then rejects it; `defineCMacro("XPC_NONNULL_ARRAY","")` does NOT help (base.h redefines it). **Verdict: do not translate Security/CoreFoundation headers. Hand-write `extern fn` / `extern const` declarations** (working set in section 10). |
| 3 | `std.mem.indexOf`, `indexOfScalar`, `indexOfPos`, `lastIndexOf`, `indexOfAny` do not exist | Renamed to `std.mem.find`, `findScalar`, `findPos`, `findLast`, `findAny`, `findNone`, `findScalarPos`, `findScalarLast`, `findLastAny`, `findDiff` (mem.zig:852-1547). `std.ascii.indexOfIgnoreCase` -> `std.ascii.findIgnoreCase`. |
| 4 | `std.fs.cwd()`, `std.fs.File`, `std.fs.openFileAbsolute` gone | `std.fs` (fs.zig, 729 bytes) only re-exports `path`, `max_path_bytes`, `max_name_bytes` as deprecated aliases. Use `std.Io.Dir.cwd()`, `std.Io.File`, `std.Io.Dir.openFileAbsolute(io, path, .{})`. |
| 5 | `std.time.timestamp()` / `milliTimestamp()` / `nanoTimestamp()` gone | `time.zig` has only `ns_per_*`/`s_per_*` constants and `epoch`. Use `std.Io.Clock.real.now(io)` -> `Io.Timestamp` with `.toSeconds()` / `.toNanoseconds()`. |
| 6 | `std.process.argsAlloc` / `args()` gone | `init.minimal.args.toSlice(arena)` -> `[]const [:0]const u8`, or `init.minimal.args.iterate()` -> `Iterator` with `.next() ?[:0]const u8`. |
| 7 | `std.io` (lowercase) gone; `std.ArrayList(T).writer()` gone; `std.fmt.fmtSliceHexLower` gone | `std.Io` is the namespace. Use `std.Io.Writer.Allocating.init(gpa)` (fields `.writer`, methods `written()`, `toOwnedSlice()`, `deinit()`) or `Writer.fromArrayList(*ArrayList(u8))`. Print hex with `{x}` / `{X}` on a `[]const u8`/array. |
| 8 | `std.ArrayList(T)` is unmanaged (`std.ArrayListUnmanaged` is an alias of it) | Every mutating call takes `gpa` first: `.empty`, `append(gpa, x)`, `appendSlice(gpa, s)`, `deinit(gpa)`, `toOwnedSlice(gpa)`. The managed type is `std.array_list.Managed(T)`. |
| 9 | Storing `segment_command_64.segName()` results in a map | `segName()`/`sectName()` slice into the struct you called it on. `LoadCommand.cast()` returns a *copy* by value, so the slice dangles once the copy goes out of scope. `arena.dupe(u8, seg.segName())` before storing (done in probe). |
| 10 | `{t}` on a non-exhaustive enum with an unknown value | `{t}` uses `@tagName` (traps on unnamed values). For `std.macho.LC` (non-exhaustive, `_`) use `{}`/`{any}`, which goes through `printEnumNonexhaustive` and prints `@enumFromInt(N)` for unknown tags. |
| 11 | Printing an optional or slice without a specifier is a compile error | `{?s}`, `{?d}`, `{?x}` for optionals; `{s}`/`{x}`/`{any}` for slices; `{any}` for structs. Error unions need `{!s}`/`{any}`. |
| 12 | `readInt` wants `*const [N]u8`, not `[]const u8` | Slice with comptime-known bounds: `std.mem.readInt(u32, bytes[off..][0..4], .little)`. |
| 13 | `Io.File.Writer` has no `writer()`; the writable thing is a field | `var fw: Io.File.Writer = .init(.stdout(), io, &buf); const w = &fw.interface;` and **`try w.flush()` before exit** (defer it). |
| 14 | A test needs an `Io` | `std.testing.io` (an `Io.Threaded` instance), `std.testing.allocator`. `Io.Dir.cwd().readFileAlloc(std.testing.io, "/bin/ls", std.testing.allocator, .unlimited)` works in tests. |
| 15 | `std.log` output appears only when level allows | Default level is `.debug` in Debug and `.info` in Release builds. Override with `pub const std_options: std.Options = .{ .log_level = .info };` in the root file. Output goes to stderr. |
| 16 | Fat headers are big-endian | `std.mem.readInt(u32, ..., .big)`, or read the struct with `bytesToValue` and `std.mem.byteSwapAllFields(macho.fat_arch, &fa)`. Mach-O 64 headers on arm64/x86_64 are little-endian. |
| 17 | `extern "c" fn` for framework symbols | Plain `extern fn Foo(...)` (no lib name) works for Security/CoreFoundation symbols when the module has `linkFramework`. `extern const kSecCodeInfoIdentifier: CFStringRef;` works for CF global keys. |
| 18 | `getxattr` is not in `std.c` | Only the `XATTR` flag bit exists (c.zig:8466). Declare `extern "c" fn getxattr(path: [*:0]const u8, name: [*:0]const u8, value: ?[*]u8, size: usize, position: u32, options: c_int) isize;` (matches `sys/xattr.h:65`). `ENOATTR` = `std.posix.E.NOATTR` (93). |

---

## 1. Program entry: `main(init: std.process.Init)` (process.zig:31)

```zig
pub const Init = struct {
    minimal: Minimal,                    // .args: Args, .environ: Environ
    arena: *std.heap.ArenaAllocator,     // process-lifetime arena, freed at exit
    gpa: Allocator,                      // leak-checked in Debug; c_allocator when link_libc in Release
    io: Io,                              // Io.Threaded-backed
    environ_map: *Environ.Map,
    preopens: Preopens,
    pub const Minimal = struct { environ: Environ, args: Args };
};
```

- Accepted `main` shapes (start.zig:749-815): `fn main() T`, `fn main(init: std.process.Init.Minimal) T`, `fn main(init: std.process.Init) T` where `T` is `void`, `u8`, `noreturn`, or an error union of those. An error return is logged via `std.log.err("{t}", .{err})` and exits 1.
- Args (process/Args.zig):
  - `pub fn toSlice(a: Args, arena: Allocator) ToSliceError![]const [:0]const u8` (line 479) -- elements are NUL-terminated, directly usable as C strings.
  - `pub fn iterate(a: Args) Iterator` (line 456); `Iterator.next(it) ?[:0]const u8`, `skip() bool`.
- `std.process.exit(status: u8) noreturn`, `std.process.fatal(comptime fmt, args) noreturn` (process.zig:696), `std.process.cleanExit(io)`.
- `std.process.currentPathAlloc(io, allocator) ![:0]u8`, `std.process.executablePathAlloc(io, allocator)`.

Probe snippet:
```zig
pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    const path: [:0]const u8 = if (args.len > 1) args[1] else "/bin/ls";
```

---

## 2. Io: files, directories, readers, writers

### 2.1 `std.Io.File` (Io/File.zig)
```zig
handle: Handle, flags: Flags,
pub fn stdout() File; pub fn stderr() File; pub fn stdin() File;          // :91-128
pub fn stat(file: File, io: Io) StatError!Stat;                            // :141
pub fn close(file: File, io: Io) void;                                      // :212
pub fn length(file: File, io: Io) LengthError!u64;                          // :286
pub fn reader(file: File, io: Io, buffer: []u8) Reader;                     // :563 positional, falls back to streaming
pub fn readerStreaming(file: File, io: Io, buffer: []u8) Reader;            // :589
pub fn writer(file: File, io: Io, buffer: []u8) Writer;                     // :597
pub fn readPositionalAll(file: File, io: Io, buffer: []u8, offset: u64) ReadPositionalError!usize; // :573
pub fn createMemoryMap(file: File, io: Io, options: MemoryMap.CreateOptions) MemoryMap.CreateError!MemoryMap; // :745
pub const Stat = struct { inode, nlink, size: u64, permissions, kind: Kind, atime: ?Io.Timestamp, mtime: Io.Timestamp, ctime: Io.Timestamp, block_size: u32 };
pub const Kind = enum { block_device, character_device, directory, named_pipe, sym_link, file, unix_domain_socket, whiteout, door, event_port, unknown };
```
`MemoryMap.CreateOptions = struct { len: usize, protection: std.process.MemoryProtection = .{.read=true,.write=true}, undefined_contents: bool = false, populate: bool = true, offset: u64 = 0 }`; `MemoryMap` has `memory: []align(page_size_min) u8`, `destroy(mm, io)`. (Declared; not exercised by the probe.)

### 2.2 `std.Io.File.Writer` / `Reader` (Io/File/Writer.zig, Reader.zig)
```zig
// Writer
pub fn init(file: File, io: Io, buffer: []u8) Writer;          // positional; stdout/pipes fall back to streaming
pub fn initStreaming(file: File, io: Io, buffer: []u8) Writer;
interface: Io.Writer,                                          // <-- the *Io.Writer you print with
pub fn flush(w: *Writer) Error!void;
pub fn seekTo(w: *Writer, offset: u64) (SeekError || Io.Writer.Error)!void;
// Reader
pub fn init(file: File, io: Io, buffer: []u8) Reader;
interface: Io.Reader,
pub fn getSize(r: *Reader) SizeError!u64;                       // :115
pub fn seekBy(r: *Reader, offset: i64) SeekError!void;           // :134
pub fn seekTo(r: *Reader, offset: u64) SeekError!void;           // :164
```
Buffered stdout (probe):
```zig
var stdout_buffer: [8192]u8 = undefined;
var stdout_fw: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
const out = &stdout_fw.interface;
defer out.flush() catch {};
try out.print("path={s} size={d}\n", .{ path, data.len });
```

### 2.3 `std.Io.Dir` (Io/Dir.zig)
```zig
pub fn cwd() Dir;                                                                             // :88
pub fn openFile(dir: Dir, io: Io, sub_path: []const u8, options: OpenFileOptions) File.OpenError!File;   // :580
pub fn openFileAbsolute(io: Io, absolute_path: []const u8, options: OpenFileOptions) File.OpenError!File; // :584 (asserts absolute)
pub fn openDir(dir: Dir, io: Io, sub_path: []const u8, options: OpenOptions) OpenError!Dir;   // :484
pub fn close(dir: Dir, io: Io) void;                                                          // :493
pub fn stat(dir: Dir, io: Io) StatError!Stat;                                                 // :880
pub fn statFile(dir: Dir, io: Io, sub_path: []const u8, options: StatFileOptions) StatFileError!Stat; // :902
pub fn readFile(dir: Dir, io: Io, file_path: []const u8, buffer: []u8) ReadFileError![]u8;    // :756
pub fn readFileAlloc(dir: Dir, io: Io, sub_path: []const u8, gpa: Allocator, limit: Io.Limit) ReadFileAllocError![]u8; // :1330
pub fn readFileAllocOptions(dir, io, sub_path, gpa, limit: Io.Limit, comptime alignment: std.mem.Alignment, comptime sentinel: ?u8) ...; // :1350
pub fn iterate(dir: Dir) Iterator;   // Iterator.next(it: *Iterator, io: Io) Error!?Entry     // :211
pub fn walk(dir: Dir, allocator: Allocator) Allocator.Error!Walker; // Walker.next(self, io) !?Walker.Entry {dir, basename:[:0]const u8, path:[:0]const u8, kind}; deinit()
pub fn realPathFileAlloc(dir: Dir, io: Io, sub_path: []const u8, allocator: Allocator) RealPathFileAllocError![:0]u8; // :947
pub fn access(dir: Dir, io: Io, sub_path: []const u8, options: AccessOptions) AccessError!void; // :441
pub const Entry = struct { name: []const u8, kind: File.Kind, inode: File.INode };
pub const OpenOptions = struct { access_sub_paths: bool = true, iterate: bool = false, follow_symlinks: bool = true };
pub const OpenFileOptions = struct { mode: Mode = .read_only, allow_directory: bool = true, path_only: bool = false, lock: File.Lock = .none, lock_nonblocking: bool = false, allow_ctty: bool = false, follow_symlinks: bool = true, resolve_beneath: bool = false; pub const Mode = enum { read_only, write_only, read_write }; };
pub const path = std.fs.path;   // std.fs.path.dirname/basename/join still exist
```
`Io.Limit` (Io.zig:636): `enum(usize) { unlimited = maxInt(usize), _ }` with `.limited(n)`, `.limited64(n)`, `.toInt()`.

Whole-file read + streaming read + dir iteration (probe):
```zig
const data = try Io.Dir.cwd().readFileAlloc(io, path, gpa, .unlimited);   // absolute or relative path OK
defer gpa.free(data);

var file = try Io.Dir.cwd().openFile(io, path, .{});
defer file.close(io);
const st = try file.stat(io);
var rbuf: [4096]u8 = undefined;
var fr = file.reader(io, &rbuf);
const first_u32_be = try fr.interface.takeInt(u32, .big);

var dir = try Io.Dir.cwd().openDir(io, dirname, .{ .iterate = true });   // .iterate REQUIRED
defer dir.close(io);
var dit = dir.iterate();
while (try dit.next(io)) |entry| { _ = entry.name; _ = entry.kind; }
```

### 2.4 `std.Io.Writer` (Io/Writer.zig) -- the universal sink
```zig
pub fn print(w: *Writer, comptime fmt: []const u8, args: anytype) Error!void;     // :617
pub fn writeAll(w: *Writer, bytes: []const u8) Error!void;                          // :550
pub fn writeByte(w: *Writer, byte: u8) Error!void;                                  // :748
pub fn splatByteAll(w: *Writer, byte: u8, n: usize) Error!void;                     // :781
pub fn flush(w: *Writer) Error!void;                                                // :312
pub fn fixed(buffer: []u8) Writer;                                                  // :125
pub fn buffered(w: *const Writer) []u8;                                             // :155
pub inline fn writeInt(w: *Writer, comptime T: type, value: T, endian: std.builtin.Endian) Error!void; // :877
pub inline fn writeStruct(w: *Writer, value: anytype, endian: std.builtin.Endian) Error!void;          // :885
pub fn printHex(w: *Writer, bytes: []const u8, case: std.fmt.Case) Error!void;      // :1848
pub fn printByteSize(w, value, units: ByteSizeUnits, options) Error!void;           // :1781  ({B} / {Bi})
pub inline fn printInt(w, value, base: u8, case: Case, options: std.fmt.Options) Error!void; // :1519
pub fn printAscii(w: *Writer, bytes: []const u8, options: std.fmt.Options) Error!void; // :1611
pub fn writeUleb128 / writeSleb128 / writeLeb128(w, value) Error!void;             // :1868-1892
pub fn fromArrayList(array_list: *ArrayList(u8)) Writer;  pub fn toArrayList(w: *Writer) ArrayList(u8); // :2388-2401
pub const Error = error{WriteFailed};
pub const Allocating = struct { allocator, writer: Writer, ...
    pub fn init(allocator: Allocator) Allocating; pub fn deinit(a: *Allocating) void;
    pub fn written(a: *Allocating) []u8; pub fn toOwnedSlice(a: *Allocating) Allocator.Error![]u8;
    pub fn clearRetainingCapacity(a: *Allocating) void; };
```

### 2.5 `std.Io.Reader` (Io/Reader.zig) -- useful for parsing byte streams
```zig
pub fn fixed(buffer: []const u8) Reader;                                            // :152  in-memory reader
pub fn take(r: *Reader, n: usize) Error![]u8;                                       // :562
pub fn takeArray(r: *Reader, comptime n: usize) Error!*[n]u8;                       // :579
pub fn peek(r: *Reader, n: usize) Error![]u8;                                       // :514
pub fn discardAll(r: *Reader, n: usize) Error!void;                                 // :610
pub inline fn takeInt(r: *Reader, comptime T: type, endian: std.builtin.Endian) Error!T;   // :1173
pub inline fn peekInt(...)                                                          // :1179
pub inline fn takeStruct(r: *Reader, comptime T: type, endian: std.builtin.Endian) Error!T; // :1224 (extern struct; byte-swaps)
pub inline fn peekStruct(...)                                                       // :1250
pub fn takeStructPointer(r: *Reader, comptime T: type) Error!*align(1) T;           // :1198
pub fn takeEnum(r: *Reader, comptime Enum: type, endian) TakeEnumError!Enum;        // :1274
pub fn takeLeb128(r: *Reader, comptime T: type) TakeLeb128Error!T;                  // :1296  (ULEB/SLEB by signedness of T)
pub fn takeSentinel(r: *Reader, comptime sentinel: u8) DelimiterError![:sentinel]u8; // :773
pub fn allocRemaining(r: *Reader, gpa: Allocator, limit: Limit) LimitedAllocError![]u8; // :296
pub fn readAlloc(r: *Reader, allocator: Allocator, len: usize) ReadAllocError![]u8; // :743
pub fn readSliceAll(r: *Reader, buffer: []u8) Error!void;                           // :664
pub const Error = error{ ReadFailed, EndOfStream };
```
`std.leb128` has only writers; use `Reader.takeLeb128` for bind/rebase opcode and export-trie decoding.

---

## 3. Formatting (`std.fmt`, Io/Writer.zig `printValue` :1091)

Placeholder grammar (fmt.zig:75-149): `{[argname|index]specifier:[fill]<alignment>[width][.precision]}`; fill is any byte, alignment one of `<` `^` `>`; a leading `0` in width without explicit alignment means fill `'0'`. `{{`/`}}` escape braces. Max 32 args.

| Specifier | Accepts | Notes |
|---|---|---|
| `{}` / `{any}` | ints, floats, bools, enums, structs, unions, optionals, slices | `{any}` on struct prints `.{ .a = 1, ... }` (depth `std.options.fmt_max_depth` = 3) |
| `{d}` | int/float/enum(int value) | decimal; `{d:0>6}` zero-pads |
| `{x}` `{X}` | ints, enums, **`[]const u8`/`[N]u8`/`[*:0]u8` (hex dump, no width)**, floats | struct with `formatNumber` method also accepted |
| `{b}` `{o}` | ints/enums | binary/octal |
| `{s}` | `[]const u8`, `[N]u8`, `[*:0]const u8` | width/alignment apply |
| `{q}` | strings | Zig-escaped quoted string |
| `{c}` | u8 | ASCII char |
| `{u}` | u21 | UTF-8 code point |
| `{t}` | enum, tagged union, error set | `@tagName` / `@errorName` (traps on unnamed non-exhaustive value) |
| `{f}` | any type with `pub fn format(self, w: *std.Io.Writer) std.Io.Writer.Error!void` | **the only way custom formatters are invoked** |
| `{*}` | pointers | address |
| `{B}` `{Bi}` | ints | byte size `1.536kB` / `1.5KiB` |
| `{b64}` | bytes | base64 |
| `{e}` `{E}` | floats | scientific |
| `{?x}` `{?s}` `{?d}` | optionals | prints `null` when null |
| `{!s}` | error unions | prints `error.Name` on error |

Verified probe line and output:
```zig
try out.print("[{s:>8}] [{s:<8}] [{s:^8}] [{d:0>6}] [{x:0>8}] [{X}] [{b}] [{o}] [{c}] [{t}] [{any}] [{?d}] [{B}] [{Bi}]\n", .{ "right", "left", "mid", @as(u32, 42), @as(u32, 0xbeef), @as(u8, 255), @as(u8, 5), @as(u8, 8), @as(u8, 'Z'), macho.LC.SEGMENT_64, [_]u8{ 1, 2 }, @as(?u32, null), @as(u64, 1536), @as(u64, 1536) });
// [   right] [left    ] [  mid   ] [000042] [0000beef] [FF] [101] [10] [Z] [SEGMENT_64] [{ 1, 2 }] [null] [1.536kB] [1.5KiB]
```

Custom format method (probe, verified with `std.testing.expectFmt`):
```zig
const Magic = struct {
    value: u32,
    pub fn format(self: Magic, w: *Io.Writer) Io.Writer.Error!void {
        try w.print("0x{x:0>8} ({s})", .{ self.value, name });
    }
};
try out.print("{f}\n", .{Magic{ .value = hdr.magic }});   // 0xfeedfacf (MH_MAGIC_64)
```
Alternative without a method: `std.fmt.alt(ctx, .funcName)` / `std.fmt.Alt(Data, formatFn)` (fmt.zig:272-300) produce a `{f}`-able wrapper. A struct with `pub fn formatNumber(self, w: *Writer, n: std.fmt.Number) Error!void` responds to `{d}/{x}/{X}/{b}/{o}` (this is how `Io.Timestamp` prints).

Helpers (fmt.zig): `allocPrint(gpa, fmt, args) Allocator.Error![]u8` (:625), `bufPrint(buf, fmt, args) BufPrintError![]u8` (:600), `comptimePrint`, `parseInt(T, buf, base) ParseIntError!T` (:322; base 0 = auto-detect prefix), `parseUnsigned`, `parseIntSizeSuffix`, `bytesToHex(input, case) [input.len*2]u8` (:1142, comptime-length input), `hexToBytes(out, input) ![]u8` (:1158), `hex(x: unsigned int)` (:1335, little-endian nibbles), `std.fmt.Case = enum{lower,upper}`, `std.fmt.Options{precision,width,alignment,fill}`.

---

## 4. Containers

### `std.ArrayList(T)` = `std.array_list.Aligned(T, null)` -- unmanaged (array_list.zig:567)
```zig
pub const empty: Self;
pub fn initCapacity(gpa: Allocator, num: usize) Allocator.Error!Self;
pub fn initBuffer(buffer: Slice) Self;                       // fixed backing, use *Bounded methods
pub fn deinit(self: *Self, gpa: Allocator) void;
pub fn append(self: *Self, gpa: Allocator, item: T) Allocator.Error!void;
pub fn appendSlice(self: *Self, gpa: Allocator, items: []const T) Allocator.Error!void;
pub fn appendUnalignedSlice(self: *Self, gpa: Allocator, items: []align(1) const T) Allocator.Error!void;
pub fn addOne(self: *Self, gpa: Allocator) Allocator.Error!*T;
pub fn addManyAsSlice(self: *Self, gpa: Allocator, n: usize) Allocator.Error![]T;
pub fn insert(self: *Self, gpa: Allocator, i: usize, item: T) Allocator.Error!void;
pub fn orderedRemove(self: *Self, i: usize) T;  pub fn swapRemove(self: *Self, i: usize) T;
pub fn pop(self: *Self) ?T;  pub fn getLast(self: Self) ?T;
pub fn toOwnedSlice(self: *Self, gpa: Allocator) Allocator.Error!Slice;
pub fn ensureTotalCapacity / ensureUnusedCapacity(self: *Self, gpa: Allocator, n: usize) Allocator.Error!void;
pub fn clearRetainingCapacity(self: *Self) void;  pub fn clearAndFree(self: *Self, gpa: Allocator) void;
pub fn print(self: *Self, gpa: Allocator, comptime fmt: []const u8, args: anytype) error{OutOfMemory}!void;
// fields: items: Slice, capacity: usize
```
Managed variant: `std.array_list.Managed(T).init(gpa)` (`append(item)`, `deinit()`).

### Hash maps (hash_map.zig)
- `std.StringHashMapUnmanaged(V)` / `std.AutoHashMapUnmanaged(K, V)`: `.empty`, `put(gpa, k, v)`, `getOrPut(gpa, k) !GetOrPutResult{key_ptr,value_ptr,found_existing}`, `get(k) ?V`, `getPtr(k) ?*V`, `contains(k)`, `remove(k) bool`, `count() u32`, `iterator()` (entries have `key_ptr`, `value_ptr`), `keyIterator()`, `valueIterator()`, `deinit(gpa)`.
- `std.StringHashMap(V).init(gpa)` / `std.AutoHashMap(K,V).init(gpa)` managed variants still exist: same methods without the allocator argument, `deinit()`.
- `std.StringHashMap` does NOT copy keys; the key slice must outlive the map (use arena/dupe).
- Also available: `std.StringArrayHashMapUnmanaged`, `std.AutoArrayHashMapUnmanaged` (array_hash_map.zig) for insertion order.

Probe:
```zig
var seg_sizes: std.StringHashMapUnmanaged(u64) = .empty;  defer seg_sizes.deinit(gpa);
try seg_sizes.put(gpa, name, seg.filesize);
var lc_counts: std.AutoHashMapUnmanaged(u32, u32) = .empty;
const gop = try lc_counts.getOrPut(gpa, @intFromEnum(lc.hdr.cmd));
if (!gop.found_existing) gop.value_ptr.* = 0;
gop.value_ptr.* += 1;
var it = seg_sizes.iterator();
while (it.next()) |e| try out.print("{s} {d}\n", .{ e.key_ptr.*, e.value_ptr.* });
```

### Allocators (heap.zig)
`std.heap.page_allocator`, `std.heap.c_allocator` (needs link_libc), `std.heap.smp_allocator`, `std.heap.ArenaAllocator.init(child)` -> `.allocator()`, `.deinit()`, `.reset(mode)`; `std.heap.DebugAllocator(config)`, `std.heap.FixedBufferAllocator`. In `main`, prefer `init.gpa` and `init.arena.allocator()`.

---

## 5. Byte parsing (`std.mem`) -- alignment-safe Mach-O reads

```zig
pub fn readInt(comptime T: type, buffer: *const [@divExact(@typeInfo(T).int.bits, 8)]u8, endian: Endian) T;
pub fn readVarInt(comptime ReturnType: type, bytes: []const u8, endian: Endian) ReturnType;      // :1781 (runtime length)
pub fn bytesAsValue(comptime T: type, bytes: anytype) BytesAsValueReturnType(T, @TypeOf(bytes)); // :4436  == @ptrCast, keeps bytes' alignment (align(1) for u8 ptr)
pub fn bytesToValue(comptime T: type, bytes: anytype) T;                                        // :4496  copy out via *align(1) -> alignment-safe
pub fn bytesAsSlice(comptime T: type, bytes: anytype) BytesAsSliceReturnType(T, @TypeOf(bytes)); // :4516  -> []align(1) const T
pub fn asBytes(ptr: anytype) AsBytesReturnType(@TypeOf(ptr));                                   // :4349
pub fn toBytes(value: anytype) [@sizeOf(@TypeOf(value))]u8;                                     // :4412
pub fn sliceTo(ptr: anytype, comptime end) SliceTo(...);                                        // :963  (NUL-terminated names)
pub fn byteSwapAllFields(comptime S: type, ptr: *S) void;                                       // :2220
pub fn bigToNative(comptime T: type, x: T) T; littleToNative; nativeTo(T, x, endian); nativeToBig/Little; // :4215-4255
pub fn alignForward(comptime T: type, addr: T, alignment: T) T;                                 // :4763
pub fn isAligned(addr: usize, alignment: usize) bool;                                           // :4929
pub fn eql(comptime T: type, a: []const T, b: []const T) bool; startsWith; endsWith; cutPrefix; cutSuffix; cut; cutScalar;
pub fn find(comptime T, haystack, needle) ?usize; findScalar; findPos; findLast; findAny; findNone; findScalarPos;
pub fn tokenizeScalar / tokenizeAny / tokenizeSequence; splitScalar / splitAny / splitSequence; trim / trimStart / trimEnd;
pub fn sort(comptime T: type, items: []T, context: anytype, comptime lessThanFn: fn (@TypeOf(context), lhs: T, rhs: T) bool) void; // :631 (std.sort.asc(T)/desc(T) for context=void)
pub fn zeroes(comptime T: type) T; span(ptr); join(alloc, sep, slices); concat(alloc, T, slices);
```
`std.mem.Alignment` (mem.zig:24): `pub inline fn of(comptime T: type) Alignment`, `.toByteUnits()`, `.fromByteUnits(n)`. `std.builtin.Endian = enum { big, little }`.

Verified alignment-safe pattern (probe; a copy of `/bin/ls` at an odd heap address parses identically, and the unit test `bytesToValue from odd-aligned buffer` passes):
```zig
fn readStructAt(comptime T: type, bytes: []const u8, offset: usize) ?T {
    if (offset > bytes.len or bytes.len - offset < @sizeOf(T)) return null;
    return std.mem.bytesToValue(T, bytes[offset..][0..@sizeOf(T)]);
}
const magic_le = std.mem.readInt(u32, view[0..4], .little);
const fh = readStructAt(macho.fat_header, view, 0).?;          // big-endian on disk
const nfat = std.mem.bigToNative(u32, fh.nfat_arch);
var fa = readStructAt(macho.fat_arch, view, 8 + i * 20).?;
std.mem.byteSwapAllFields(macho.fat_arch, &fa);               // whole struct big -> native
```
Stream style: `var r: Io.Reader = .fixed(bytes); const h = try r.takeStruct(macho.mach_header_64, .little);`

---

## 6. `std.macho` inventory (macho.zig) -- reuse these, do not redeclare

**Structs (all `extern struct`)**: `mach_header` (:26), `mach_header_64` (:36, fields have defaults; `magic: u32 = MH_MAGIC_64`), `fat_header` (:47), `fat_arch` (:52, field `@"align"`), `load_command{cmd: LC, cmdsize}` (:60), `uuid_command` (:67), `version_min_command` (:80), `source_version_command` (:96), `build_version_command` (:110) + `build_tool_version` (:131), `entry_point_command` (:170), `symtab_command` (:187), `dysymtab_command` (:244), `linkedit_data_command{cmd, cmdsize, dataoff, datasize}` (:384), `dyld_info_command` (:404), `dylinker_command` (:525), `dylib_command{cmd, cmdsize, dylib}` (:546) + `dylib{name: u32 offset, timestamp, current_version, compatibility_version}` (:564), `rpath_command{cmd, cmdsize, path: u32}` (:580), `segment_command` (:601), `segment_command_64` (:638; `segName()`, `isWriteable()`; `maxprot/initprot: vm_prot_t` packed struct(u32) with `.read/.write/.execute` bools), `section` (:723), `section_64` (:758; `sectName()`, `segName()`, `@"type"() u8`, `attrs() u32`, `isCode()`, `isZerofill()`, `isSymbolStubs()`, `isDebug()`, `isDontDeadStrip()`, `isDontDeadStripIfReferencesLive()`), `nlist` (:844), `nlist_64` (:852; **`n_type` is a `packed union(u8) { bits: packed struct{ext: bool, type: enum(u3){undf=0,abs=1,sect=7,pbud=6,indr=5,_}, pext: bool, is_stab: u3}, stab: enum(u8){...} }`**, `n_desc: i16`), `relocation_info` (packed, :932), `CodeDirectory` (:1809), `BlobIndex` (:1875), `SuperBlob` (:1885), `GenericBlob` (:1896), `data_in_code_entry` (:1907), compact-unwind structs (:1990-2136).

**Enums**: `LC = enum(u32)` non-exhaustive (:961): `NONE, SEGMENT, SYMTAB, SYMSEG, THREAD, UNIXTHREAD, LOADFVMLIB, IDFVMLIB, IDENT, FVMFILE, PREPAGE, DYSYMTAB, LOAD_DYLIB, ID_DYLIB, LOAD_DYLINKER, ID_DYLINKER, PREBOUND_DYLIB, ROUTINES, SUB_FRAMEWORK, SUB_UMBRELLA, SUB_CLIENT, SUB_LIBRARY, TWOLEVEL_HINTS, PREBIND_CKSUM, LOAD_WEAK_DYLIB, SEGMENT_64, ROUTINES_64, UUID, RPATH, CODE_SIGNATURE, SEGMENT_SPLIT_INFO, REEXPORT_DYLIB, LAZY_LOAD_DYLIB, ENCRYPTION_INFO, DYLD_INFO, DYLD_INFO_ONLY, LOAD_UPWARD_DYLIB, VERSION_MIN_MACOSX, VERSION_MIN_IPHONEOS, FUNCTION_STARTS, DYLD_ENVIRONMENT, MAIN, DATA_IN_CODE, SOURCE_VERSION, DYLIB_CODE_SIGN_DRS, ENCRYPTION_INFO_64, LINKER_OPTION, LINKER_OPTIMIZATION_HINT, VERSION_MIN_TVOS, VERSION_MIN_WATCHOS, NOTE, BUILD_VERSION, DYLD_EXPORTS_TRIE, DYLD_CHAINED_FIXUPS, _` (values with `LC_REQ_DYLD = 0x80000000` OR'd in where applicable). `PLATFORM = enum(u32)` (:139), `TOOL` (:157), `reloc_type_x86_64`, `reloc_type_arm64`, `UNWIND_*` enums.

**Constants**: `MH_MAGIC/CIGAM(_64)`, `MH_OBJECT..MH_KEXT_BUNDLE` (file types), `MH_NOUNDEFS..MH_DYLIB_IN_CACHE` (flags incl. `MH_PIE`, `MH_TWOLEVEL`, `MH_ALLOW_STACK_EXECUTION`, `MH_NO_HEAP_EXECUTION`), `FAT_MAGIC/CIGAM(_64)`, `SG_HIGHVM/FVMLIB/NORELOC/PROTECTED_VERSION_1/READ_ONLY`, `SECTION_TYPE/ATTRIBUTES`, `S_REGULAR..S_INIT_FUNC_OFFSETS` (0x0-0x16), `S_ATTR_*`, `N_STAB/PEXT/TYPE/EXT/UNDF/ABS/SECT/PBUD/INDR` + all `N_*` stab kinds, `N_WEAK_REF/WEAK_DEF/NO_DEAD_STRIP/SYMBOL_RESOLVER`, `REFERENCE_FLAG_*`, `REFERENCED_DYNAMICALLY`, `CPU_TYPE_X86_64/ARM64`, `CPU_SUBTYPE_X86_64_ALL/ARM_ALL`, `REBASE_*` and `BIND_*` opcodes/types/flags, `EXPORT_SYMBOL_FLAGS_*`, `INDIRECT_SYMBOL_LOCAL/ABS`, `CSMAGIC_*` (REQUIREMENT, REQUIREMENTS, CODEDIRECTORY, EMBEDDED_SIGNATURE, EMBEDDED_SIGNATURE_OLD, EMBEDDED_ENTITLEMENTS, EMBEDDED_DER_ENTITLEMENTS, DETACHED_SIGNATURE, BLOBWRAPPER), `CS_SUPPORTS*`, `CSSLOT_*`, `CS_HASHTYPE_*`, `CS_SHA1_LEN/SHA256_LEN/CDHASH_LEN/HASH_MAX_SIZE`, `CS_ADHOC = 0x2`, `CS_LINKER_SIGNED = 0x20000`, `CS_EXECSEG_MAIN_BINARY`, `CS_SIGNER_TYPE_*`, `LC_REQ_DYLD`.

**NOT present (implementers must declare)**: anything from `mach-o/fixup-chains.h` (`dyld_chained_fixups_header`, `dyld_chained_starts_in_image`, `dyld_chained_starts_in_segment`, `dyld_chained_ptr_64_*`, `DYLD_CHAINED_PTR_*`, `DYLD_CHAINED_IMPORT*`); `encryption_info_command(_64)`; `thread_command`/`arm_thread_state`; `CPU_TYPE_ARM64E`/subtype masks like `CPU_SUBTYPE_MASK`/`CPU_SUBTYPE_LIB64`/`CPU_SUBTYPE_ARM64E`; `CS_HARDENED_RUNTIME (CS_RUNTIME = 0x10000)`, `CS_VALID`, `CS_KILL`, `CS_RESTRICT` etc.; `MH_FILESET`; `S_ATTR_*` beyond those listed; `PLATFORM` values newer than those in the enum (check before use). Only `LC.DYLD_CHAINED_FIXUPS` and `LC.DYLD_EXPORTS_TRIE` tags exist for chained fixups.

**`LoadCommandIterator`** (:1916) -- verified on `/bin/ls` arm64 slice (20 commands, matches `otool -l`):
```zig
pub fn init(hdr: *const mach_header_64, cmds_buf_overlong: []const u8) error{InvalidMachO}!LoadCommandIterator;
pub fn next(it: *LoadCommandIterator) error{InvalidMachO}!?LoadCommand;   // LoadCommand{ hdr: load_command, data: []const u8 }
LoadCommand.cast(lc, comptime Cmd: type) ?Cmd;                              // copies out, byte-swaps on BE hosts
LoadCommand.getSections(lc) []align(1) const section_64;                    // asserts SEGMENT_64
LoadCommand.getDylibPathName(lc) []const u8;  getRpathPathName(lc);  getBuildVersionTools(lc);
```
```zig
const hdr = readStructAt(macho.mach_header_64, slice, 0) orelse return error.Truncated;
var it = try macho.LoadCommandIterator.init(&hdr, slice[@sizeOf(macho.mach_header_64)..]);
while (try it.next()) |lc| switch (lc.hdr.cmd) {
    .SEGMENT_64 => { const seg = lc.cast(macho.segment_command_64).?; for (lc.getSections()) |sect| { ... sect.sectName() ... } },
    .LOAD_DYLIB, .LOAD_WEAK_DYLIB, .REEXPORT_DYLIB => try out.print("{}: {s}\n", .{ lc.hdr.cmd, lc.getDylibPathName() }),
    .CODE_SIGNATURE, .DYLD_CHAINED_FIXUPS => { const led = lc.cast(macho.linkedit_data_command).?; ... },
    .UUID => { const u = lc.cast(macho.uuid_command).?; try out.print("{X}\n", .{u.uuid}); },
    else => {},
};
```
Note: `init` requires `cmds_buf_overlong.len >= hdr.sizeofcmds`; for a non-Mach-O file (a PDF) it returns `error.InvalidMachO` -- check magic first.

---

## 7. Crypto

```zig
const Sha256 = std.crypto.hash.sha2.Sha256;    // also Sha224, Sha384, Sha512, Sha512_256
pub const digest_length = 32; pub const block_length = 64;
pub fn hash(b: []const u8, out: *[digest_length]u8, options: Options) void;   // one-shot; options = .{}
pub fn init(options: Options) Self; pub fn update(d: *Self, b: []const u8) void;
pub fn final(d: *Self, out: *[digest_length]u8) void; pub fn finalResult(d: *Self) [digest_length]u8;
const Sha1 = std.crypto.hash.Sha1;              // digest_length = 20, same API (crypto/Sha1.zig)
```
Probe (matches `shasum`): `Sha256.hash(data, &digest, .{}); try out.print("sha256={x}\n", .{digest});` and `const hex_owned = try std.fmt.allocPrint(arena, "{x}", .{digest});`. Also `std.crypto.hash.Md5`, `Blake3`, `sha3`.

---

## 8. JSON (`std.json`, json/Stringify.zig)

```zig
pub fn Stringify.value(v: anytype, options: Options, writer: *Io.Writer) Error!void;          // :573
pub fn Stringify.valueAlloc(gpa: Allocator, v: anytype, options: Options) error{OutOfMemory}![]u8; // :618
pub fn std.json.fmt(value: anytype, options: Stringify.Options) Formatter(@TypeOf(value));   // use with {f}
pub const Options = struct { whitespace: enum{minified, indent_1, indent_2, indent_3, indent_4, indent_8, indent_tab} = .minified, emit_null_optional_fields: bool = true, emit_strings_as_arrays: bool = false, escape_unicode: bool = false, emit_nonportable_numbers_as_strings: bool = false };
// streaming
var js: std.json.Stringify = .{ .writer = out, .options = .{} };
try js.beginObject(); try js.objectField("k"); try js.write(v); try js.beginArray(); ... try js.endArray(); try js.endObject();
// custom: pub fn jsonStringify(self: @This(), jw: anytype) !void   (jw is *Stringify)
// parse
pub fn parseFromSlice(comptime T: type, allocator, slice: []const u8, options: ParseOptions) ParseError!Parsed(T); // .value, .deinit()
pub const Value = union(enum){ null, bool, integer, float, number_string, string, array, object: ObjectMap };
```
Serialization rules (verified): `[]const u8` -> JSON string, `?T` null -> `null`, structs -> objects with field names, `[]const []const u8` -> array of strings, `u32` -> number, enums -> tag-name strings. `Stringify.value(report, .{ .whitespace = .indent_2 }, out)` produced the pretty report in the probe; `out.print("{f}\n", .{std.json.fmt(report, .{})})` produced the minified one.

---

## 9. Time / timestamps

- `std.Io.Clock = enum { real, awake, boot, cpu_process, cpu_thread }` (Io.zig:738; `.awake` = CLOCK_UPTIME_RAW on macOS); `Clock.now(clock, io) Io.Timestamp` (:795) and `Io.Timestamp.now(io, clock)` (:926).
- `Io.Timestamp = struct { nanoseconds: i96 }` with `toSeconds() i64`, `toMilliseconds()`, `toNanoseconds() i96`, `durationTo(to) Duration`, `addDuration`, `untilNow(io, clock)`, `formatNumber` (so `{d}` works on it).
- `Io.Duration = struct { nanoseconds: i96 }` with `toSeconds()`, `toNanoseconds()`.
- `File.Stat.mtime/ctime: Io.Timestamp`, `atime: ?Io.Timestamp` (nanoseconds since Unix epoch).
- `std.time.ns_per_s`, `ns_per_ms`, `s_per_day`, ...; `std.time.epoch.{Year, Month, isLeapYear, getDaysInYear, secs_per_day}` for civil-date math (no `EpochSeconds` struct in this version).

Probe: `const now = Io.Clock.real.now(io); st.mtime.durationTo(now).toSeconds()`.

---

## 10. C interop on macOS (Security.framework, CoreFoundation, xattr)

### Working: hand-written extern declarations (probe `src/main.zig`)
```zig
const CFTypeRef = ?*const anyopaque;  const CFAllocatorRef = ?*const anyopaque;
const CFStringRef = ?*const anyopaque; const CFURLRef = ?*const anyopaque;
const CFDictionaryRef = ?*const anyopaque; const CFNumberRef = ?*const anyopaque;
const SecStaticCodeRef = ?*const anyopaque; const SecRequirementRef = ?*const anyopaque;
const CFIndex = c_long; const CFTypeID = c_ulong; const Boolean = u8;
const OSStatus = i32; const SecCSFlags = u32; const CFStringEncoding = u32; const CFNumberType = CFIndex;

const kCFStringEncodingUTF8: CFStringEncoding = 0x08000100;   // CFString.h:113
const kCFNumberSInt32Type: CFNumberType = 3;  const kCFNumberSInt64Type: CFNumberType = 4;  // CFNumber.h
// CSCommon.h:237-241
const kSecCSDefaultFlags: SecCSFlags = 0;
const kSecCSConsiderExpiration: SecCSFlags = 1 << 31;
const kSecCSEnforceRevocationChecks: SecCSFlags = 1 << 30;
const kSecCSNoNetworkAccess: SecCSFlags = 1 << 29;
// SecStaticCode.h:176-181 (SecStaticCodeCheckValidity flags)
const kSecCSCheckAllArchitectures: SecCSFlags = 1 << 0;
const kSecCSDoNotValidateExecutable: SecCSFlags = 1 << 1;
const kSecCSDoNotValidateResources: SecCSFlags = 1 << 2;
const kSecCSCheckNestedCode: SecCSFlags = 1 << 3;
const kSecCSStrictValidate: SecCSFlags = 1 << 4;
// SecCode.h:468-472 (SecCodeCopySigningInformation flags)
const kSecCSInternalInformation: SecCSFlags = 1 << 0;
const kSecCSSigningInformation: SecCSFlags = 1 << 1;
const kSecCSRequirementInformation: SecCSFlags = 1 << 2;
const kSecCSDynamicInformation: SecCSFlags = 1 << 3;
const kSecCSContentInformation: SecCSFlags = 1 << 4;
// CSCommon.h
const errSecSuccess: OSStatus = 0;
const errSecCSUnsigned: OSStatus = -67062;           // :74
const errSecCSSignatureFailed: OSStatus = -67061;    // :75
const errSecCSBadResource: OSStatus = -67054;        // :82
const errSecCSReqFailed: OSStatus = -67050;          // :86
const errSecCSSignatureInvalid: OSStatus = -67045;   // :91
const errSecCSUnsignedNestedCode: OSStatus = -67022; // :116
const errSecCSRevokedNotarization: OSStatus = -66992;// :146

extern fn CFURLCreateFromFileSystemRepresentation(allocator: CFAllocatorRef, buffer: [*]const u8, bufLen: CFIndex, isDirectory: Boolean) CFURLRef;
extern fn CFRelease(cf: CFTypeRef) void;
extern fn CFGetTypeID(cf: CFTypeRef) CFTypeID;
extern fn CFStringGetTypeID() CFTypeID;
extern fn CFNumberGetTypeID() CFTypeID;
extern fn CFStringGetLength(theString: CFStringRef) CFIndex;
extern fn CFStringGetMaximumSizeForEncoding(length: CFIndex, encoding: CFStringEncoding) CFIndex;
extern fn CFStringGetCString(theString: CFStringRef, buffer: [*]u8, bufferSize: CFIndex, encoding: CFStringEncoding) Boolean;
extern fn CFDictionaryGetValue(theDict: CFDictionaryRef, key: ?*const anyopaque) ?*const anyopaque;
extern fn CFNumberGetValue(number: CFNumberRef, theType: CFNumberType, valuePtr: *anyopaque) Boolean;
extern fn SecStaticCodeCreateWithPath(path: CFURLRef, flags: SecCSFlags, staticCode: *SecStaticCodeRef) OSStatus;
extern fn SecStaticCodeCheckValidity(staticCode: SecStaticCodeRef, flags: SecCSFlags, requirement: SecRequirementRef) OSStatus;
extern fn SecCodeCopySigningInformation(code: SecStaticCodeRef, flags: SecCSFlags, information: *CFDictionaryRef) OSStatus;
extern const kSecCodeInfoIdentifier: CFStringRef;
extern const kSecCodeInfoTeamIdentifier: CFStringRef;
extern const kSecCodeInfoFlags: CFStringRef;
extern const kSecCodeInfoPlatformIdentifier: CFStringRef;
// other keys available in SecCode.h:477-504: kSecCodeInfoCertificates, kSecCodeInfoEntitlements, kSecCodeInfoEntitlementsDict,
// kSecCodeInfoDesignatedRequirement, kSecCodeInfoCdHashes, kSecCodeInfoDigestAlgorithm(s), kSecCodeInfoFormat, kSecCodeInfoMainExecutable,
// kSecCodeInfoRuntimeVersion, kSecCodeInfoStapledNotarizationTicket, kSecCodeInfoTime, kSecCodeInfoTimestamp, kSecCodeInfoUnique, kSecCodeInfoTrust
// Additional protos (SDK): SecStaticCodeCheckValidityWithErrors(code, flags, req, errors: *CFErrorRef) OSStatus;
//                          SecRequirementCreateWithString(text: CFStringRef, flags, req: *SecRequirementRef) OSStatus;

extern "c" fn getxattr(path: [*:0]const u8, name: [*:0]const u8, value: ?[*]u8, size: usize, position: u32, options: c_int) isize;
// sys/xattr.h: XATTR_NOFOLLOW = 0x0001, XATTR_SHOWCOMPRESSION = 0x0020, XATTR_NOFOLLOW_ANY = 0x0040
```
```zig
fn cfStringToUtf8(alloc: std.mem.Allocator, s: CFStringRef) ![]u8 {
    const len = CFStringGetLength(s);
    const max = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
    const buf = try alloc.alloc(u8, @intCast(max));
    if (CFStringGetCString(s, buf.ptr, max, kCFStringEncodingUTF8) == 0) return error.CFStringConversionFailed;
    return std.mem.sliceTo(buf, 0);
}
fn checkSignature(alloc: std.mem.Allocator, path: [:0]const u8) !SigningInfo {
    const url = CFURLCreateFromFileSystemRepresentation(null, path.ptr, @intCast(path.len), 0) orelse return error.CFURLCreateFailed;
    defer CFRelease(url);
    var code: SecStaticCodeRef = null;
    const rc = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
    if (rc != errSecSuccess) return .{ .status = rc };
    defer CFRelease(code);
    const validity = SecStaticCodeCheckValidity(code, kSecCSCheckAllArchitectures | kSecCSEnforceRevocationChecks, null);
    var info: SigningInfo = .{ .status = validity };
    if (validity == errSecCSUnsigned) return info;
    var dict: CFDictionaryRef = null;
    if (SecCodeCopySigningInformation(code, kSecCSSigningInformation | kSecCSRequirementInformation, &dict) != errSecSuccess) return info;
    defer CFRelease(dict);
    info.identifier = try dictString(alloc, dict, kSecCodeInfoIdentifier);   // CFGetTypeID(v) == CFStringGetTypeID()
    info.team_id = try dictString(alloc, dict, kSecCodeInfoTeamIdentifier);
    info.flags = dictU32(dict, kSecCodeInfoFlags);                            // CFNumberGetValue(v, kCFNumberSInt64Type, &i64)
    return info;
}
fn readQuarantine(alloc: std.mem.Allocator, path: [:0]const u8) !?[]u8 {
    const n = getxattr(path.ptr, "com.apple.quarantine", null, 0, 0, 0);
    if (n < 0) return switch (std.posix.errno(n)) { .NOATTR => null, else => null };
    const buf = try alloc.alloc(u8, @intCast(n));
    const got = getxattr(path.ptr, "com.apple.quarantine", buf.ptr, buf.len, 0, 0);
    if (got < 0) return error.XattrReadFailed;
    return buf[0..@intCast(got)];
}
```
Verified results: `/bin/ls` -> status 0, `com.apple.ls`, team null, flags 0x0, platform 26; `Discord` -> `com.hnc.Discord`, team `53Q6R32WPB`, flags 0x10000 (hardened runtime); `Alacritty` -> `org.alacritty`, flags 0x2 (ad hoc) with quarantine `01c1;69aa7f48;Firefox;...`; local `enumerateProcess` -> flags 0x20002 (adhoc|linker-signed); a PDF -> status -67062 (errSecCSUnsigned), quarantine `0081;6a8dca47;Firefox;...`. All agree with `codesign -dv --verbose=2` and `xattr -p`.

`std.posix.errno(rc) E` reads thread-local errno when `rc == -1`; darwin `E` enum (c/darwin.zig:1286) has `.NOATTR = 93`, `.NOENT`, `.ACCES`, etc.

### Not working: translate-c of Security headers (see gotcha #2). Capstone's header translates fine (`cs_version` called successfully).

---

## 11. build.zig (verified; probe `build.zig`)

```zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // -Dcapstone=true links libcapstone (optional dependency).
    const use_capstone = b.option(bool, "capstone", "Link libcapstone for disassembly") orelse false;
    const capstone_prefix = b.option([]const u8, "capstone-prefix", "Capstone install prefix") orelse "/opt/homebrew/opt/capstone";

    const opts = b.addOptions();
    opts.addOption(bool, "have_capstone", use_capstone);

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    exe_mod.addOptions("build_options", opts);          // @import("build_options").have_capstone
    exe_mod.linkFramework("Security", .{});
    exe_mod.linkFramework("CoreFoundation", .{});
    if (use_capstone) {
        // @cImport was removed from the language; C headers are translated by a
        // build step and imported as a named module instead.
        const tc = b.addTranslateC(.{
            .root_source_file = .{ .cwd_relative = b.fmt("{s}/include/capstone/capstone.h", .{capstone_prefix}) },
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        tc.addIncludePath(.{ .cwd_relative = b.fmt("{s}/include", .{capstone_prefix}) });
        exe_mod.addImport("capstone", tc.createModule());   // const cs = @import("capstone"); cs.cs_version(&maj, &min)
        exe_mod.addLibraryPath(.{ .cwd_relative = b.fmt("{s}/lib", .{capstone_prefix}) });
        exe_mod.linkSystemLibrary("capstone", .{});
    }

    const exe = b.addExecutable(.{ .name = "probe", .root_module = exe_mod });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();                          // `zig build run -- args`
    b.step("run", "Run the probe").dependOn(&run_cmd.step);

    const exe_tests = b.addTest(.{ .root_module = exe_mod });   // tests in main.zig + files it imports
    const run_exe_tests = b.addRunArtifact(exe_tests);
    b.step("test", "Run tests").dependOn(&run_exe_tests.step);
}
```
Signatures (Build.zig / Build/Module.zig / Build/Step/*.zig):
- `pub fn option(b: *Build, comptime T: type, name_raw: []const u8, description_raw: []const u8) ?T` (:1100) -- T may be `bool`, `[]const u8`, ints, enums, `[]const []const u8`.
- `pub fn addOptions(b: *Build) *Step.Options` (:687); `Options.addOption(options, comptime T, name, value: T)`; `Options.addOptionPath`; `Module.addOptions(m, module_name, options)` (Module.zig:314).
- `pub fn createModule(b: *Build, options: Module.CreateOptions) *Module` (:851); `addModule(b, name, options)` (:830, public/exported). `CreateOptions` fields: `root_source_file: ?LazyPath, imports: []const Import, target, optimize, link_libc: ?bool, link_libcpp, single_threaded, strip, unwind_tables, dwarf_format, code_model, stack_protector, stack_check, sanitize_c, sanitize_thread, fuzz, valgrind, pic, red_zone, omit_frame_pointer, error_tracing, no_builtin`.
- `Module.linkFramework(m, name, LinkFrameworkOptions{needed: bool = false, weak: bool = false})` (:367); `linkSystemLibrary(m, name, LinkSystemLibraryOptions{needed, weak, use_pkg_config = .yes, preferred_link_mode = .dynamic, search_strategy = .paths_first})` (:337; names matching libc like "c"/"m" just set `link_libc`); `addIncludePath(m, LazyPath)`, `addSystemIncludePath`, `addLibraryPath(m, LazyPath)`, `addFrameworkPath`, `addSystemFrameworkPath`, `addRPath`, `addCMacro(m, name, value)`, `addCSourceFile(m, .{ .file, .flags })`, `addCSourceFiles`, `addImport(m, name, *Module)`, `linkLibrary(m, *Step.Compile)`.
- `LazyPath` variants: `.src_path`, `.generated`, `.cwd_relative: []const u8` (absolute paths), `.dependency`, `.relative`; `b.path("rel")` for build-root-relative.
- `pub fn addExecutable(b, ExecutableOptions{ name, root_module: *Module, version, linkage, max_rss, use_llvm, use_lld, zig_lib_dir, win32_manifest }) *Step.Compile` (:708).
- `pub fn addTest(b, TestOptions{ name = "test", root_module: *Module, max_rss, filters: []const []const u8, test_runner, use_llvm, use_lld, zig_lib_dir, emit_object }) *Step.Compile` (:802).
- `pub fn addRunArtifact(b, exe: *Step.Compile) *Step.Run` (:891); `Run.addArg/addArgs/addFileArg/addPassthruArgs/setCwd/expectExitCode`.
- `pub fn installArtifact(b, artifact: *Step.Compile) void` (:1611); `b.getInstallStep()`; `b.step(name, desc) *Step`; `b.fmt(fmt, args) []u8`; `b.addSystemCommand(argv)`; `b.dependency(name, args)` / `b.lazyDependency`.
- `pub fn addTranslateC(b, Step.TranslateC.Options{ root_source_file: LazyPath, target, optimize, link_libc: bool = true }) *Step.TranslateC` (:1083); `TranslateC.createModule()`, `.addModule(name)`, `.addIncludePath`, `.addSystemIncludePath`, `.addFrameworkPath`, `.addSystemFrameworkPath`, `.defineCMacro(name, ?value)`, `.linkSystemLibrary`, `.getOutput() LazyPath`.
- Build outputs: `zig-out/bin/<name>`; cache `.zig-cache/`. `zig build -Doptimize=ReleaseSafe|ReleaseFast|ReleaseSmall`, `-Dtarget=aarch64-macos`.

---

## 12. Testing (testing.zig)

- `std.testing.allocator` (leak-checking `SafeAllocator`), `std.testing.io` (an `Io.Threaded`), `std.testing.expect(ok) !void`, `expectEqual(expected, actual)` (inline; coerces via `@TypeOf(expected, actual)` -- cast literals with `@as`), `expectEqualSlices(T, a, b)`, `expectEqualStrings(a, b)`, `expectStringStartsWith/EndsWith`, `expectError(err, result)`, `expectFmt(expected, template, args)`, `expectEqualDeep`, `tmpDir(opts)`, `refAllDecls(T)`.
- `test "name" { ... }` blocks in the root module and any file it imports run under `zig build test`; `test { _ = @import("other.zig"); }` pulls in tests from modules that would otherwise not be referenced.
- Six probe tests (readInt endianness, odd-aligned bytesToValue, `{f}` custom format, reading `/bin/ls` with `std.testing.io`, unmanaged ArrayList/StringHashMap, JSON round trip) pass in Debug.

---

## 13. Logging and diagnostics

- `std.log.info/warn/err/debug(comptime fmt, args)`; scoped: `const log = std.log.scoped(.macho); log.warn(...)`.
- Configure in root: `pub const std_options: std.Options = .{ .log_level = .info, .log_scope_levels = &.{ .{ .scope = .macho, .level = .debug } }, .logFn = myLog };` (std.zig:121; `logFn` signature `fn (comptime level: std.log.Level, comptime scope: @EnumLiteral(), comptime format: []const u8, args: anytype) void`; forward to `std.log.defaultLog`).
- `std.debug.print(fmt, args)` writes to stderr, unbuffered-ish (64-byte buffer, flushed), locks stderr; `std.debug.assert`.
- Colors: `std.Io.Terminal{ writer: *Io.Writer, mode }` with `setColor(t, Color)`; `std.debug.lockStderr(&buf).terminal()`. `File.isTty(file, io)`, `File.supportsAnsiEscapeCodes(file, io)`.
- Other useful: `std.ascii.isPrint/isAscii/isControl/toLower/eqlIgnoreCase/findIgnoreCase`, `std.unicode.utf8ValidateSlice(s) bool`, `std.fmt.parseInt`, `std.SemanticVersion`, `std.base64`, `std.Uri`.

---

## 14. Probe outputs (abridged, `zig build run -- /bin/ls`)
```
path=/bin/ls size=154624 (stat 154624) mtime=1770268403s kind=file
first u32 (BE via Reader.takeInt) = 0xcafebabe (FAT_MAGIC)
sha256=0056d8fd617b4af3e6f8ec08a08530747962b7392ccd767b275677e8387dac51
sha1=5E963AA9FA68B1D165BA4481025E11B449B0979A
magic LE=0xbebafeca (FAT_CIGAM) BE=0xcafebabe (FAT_MAGIC)
fat: nfat_arch=2
  arch[0] cputype=0x1000007 subtype=0x3 offset=16384 size=48112 align=2^14
  arch[1] cputype=0x100000c subtype=0x2 offset=65536 size=89088 align=2^14
mach_header_64: magic=0xfeedfacf (MH_MAGIC_64) cputype=0x100000c filetype=2 ncmds=20 sizeofcmds=1712 flags=0x200085
    sect __TEXT,__text addr=0x100000700 size=15276 off=1792 flags=0x80000400
  .DYLD_CHAINED_FIXUPS: dataoff=65536 datasize=1424
  .LOAD_DYLIB: /usr/lib/libSystem.B.dylib
  .CODE_SIGNATURE: dataoff=70240 datasize=18848
codesign: status=0 identifier=com.apple.ls team=null flags=0x0 platform=26
quarantine: null
{"path":"/bin/ls","size":154624,...,"segments":["__PAGEZERO","__TEXT","__DATA_CONST","__DATA","__LINKEDIT"]}
```

---

## 15. Completeness-critic additions (verified 2026-09-11 19:45, probe `scratchpad/critic/`)

Everything below was compiled and run on this machine with the same nightly. Probe project:
`/private/tmp/claude-501/-Users-bcann-programming-mac-security/9135d7a5-d466-4310-b16a-780257c75456/scratchpad/critic/`
(`build.zig`, `src/main.zig`, `src/sec.zig`, `walk.zig`); captured output in `run.txt`, `run-extra.txt`.

### 15.1 CORRECTION to section 9: `std.time.epoch.EpochSeconds` exists
`time/epoch.zig:169`: `pub const EpochSeconds = struct { secs: u64, getEpochDay() EpochDay, getDaySeconds() DaySeconds }`;
`EpochDay.calculateYearDay() YearAndDay{ year, day }`; `YearAndDay.calculateMonthDay() MonthAndDay{ month: Month, day_index: u5 /*0-based*/ }`;
`Month.numeric() u4`; `DaySeconds.getHoursIntoDay()/getMinutesIntoHour()/getSecondsIntoMinute()`.
Verified: `0x68c3a1b2` -> `2025-09-12T04:29:38Z` (the corpus quarantine timestamp). `secs` is `u64` (no pre-1970 dates).
```zig
const es = std.time.epoch.EpochSeconds{ .secs = secs };
const yd = es.getEpochDay().calculateYearDay();
const md = yd.calculateMonthDay();
const ds = es.getDaySeconds();
try w.print("{d}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{ yd.year, md.month.numeric(), @as(u32, md.day_index) + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute() });
```

### 15.2 `std.macho.LoadCommandIterator` on malformed input: what it does NOT check (macho.zig:1916-1980)
- `init` fails (`error.InvalidMachO`) only if `cmds_buf.len < sizeofcmds` or (`ncmds > 0 and sizeofcmds < 8`).
- `next` = `peekStruct(load_command)` + `take(cmdsize)`; `EndOfStream` -> `error.InvalidMachO`. **No `cmdsize >= 8` / `cmdsize % 8 == 0` check.** With `cmdsize == 0` it returns the same zero-length command `ncmds` times and ends normally; with a `cmdsize` that is not a multiple of 8 the following header is read from a misaligned offset (verified: patched copies of hello-c with LC[0].cmdsize = 4 and = 12 each yield one garbage command and then `error.InvalidMachO`).
- `getSections()` slices `nsects` entries with **no bounds check** (`sects_ptr[0..nsects]`); iterating it on `nsects-huge.bin` reads out of bounds. Check `72 + 80 * nsects <= cmdsize` first.
- `cast(T)` returns `null` when `data.len < @sizeOf(T)` (safe). Nothing checks the magic.

| fixture | observed |
|---|---|
| `truncated-header.bin` (20 B), `empty.bin` | header read fails -> reject before `init` |
| `bogus-ncmds.bin` (ncmds 0xFFFFFFFF) | 18 commands, then `error.InvalidMachO` |
| `cmdsize-zero.bin` | 18 x cmdsize-0 commands, ends with `null` -- **no error** |
| `cmdsize-huge.bin` | 0 commands, `error.InvalidMachO` |
| `sizeofcmds-too-big.bin` | `init` -> `error.InvalidMachO` |
| `nsects-huge.bin` | 18 commands; `getSections().len == 4294967295` (needs 343597383672 B, cmdsize 392) |
| `section-offset-past-eof.bin`, `symtab-nsyms-huge.bin`, `bad-magic.bin` | iterate normally -- offsets, counts and magic are the caller's job |

Required caller checks per slice: magic in {MH_MAGIC_64, MH_CIGAM_64, MH_MAGIC, MH_CIGAM}; `32 + sizeofcmds <= slice.len`; per command `cmdsize >= 8 and cmdsize % 8 == 0` (4 for 32-bit) and it ends inside `sizeofcmds`; `72 + 80*nsects <= cmdsize`; every `fileoff/offset/dataoff (+size)`, `symoff + 16*nsyms`, `stroff + strsize`, `indirectsymoff + 4*n` inside the slice; `n_strx < strsize`; cap loops by remaining bytes.

### 15.3 `nlist_64` field types (macho.zig:852-900)
`n_desc` is a **`packed struct(u16)`** (the 32-bit `nlist` has `n_desc: i16`): `{ _pad0: u3, arm_thumb_def, referenced_dynamically, discarded_or_no_dead_strip, weak_ref, weak_def_or_ref_to_weak, symbol_resolver, alt_entry: bool, _pad2: u6 }`. The library ordinal lives in the padding bits, so:
```zig
const desc_raw: u16 = @bitCast(sym.n_desc);          // packed struct(u16) -> u16
const lib_ordinal = (desc_raw >> 8) & 0xff;           // GET_LIBRARY_ORDINAL
const raw_n_type: u8 = @intFromEnum(sym.n_type.stab); // whole byte; the enum is non-exhaustive so this works for non-stabs too
if (sym.n_type.bits.is_stab != 0) { /* stab */ } else switch (sym.n_type.bits.type) { .undf => {}, .sect => {}, else => {} }
```
Verified on `/bin/ls` arm64e: `__DefaultRuneLocale n_type=0x01 n_desc=0x0300 lib_ordinal=3 (libSystem) ext=true`. `@sizeOf(nlist_64)=16`.
`std.mem.bytesAsSlice(macho.nlist_64, slice[symoff..][0 .. nsyms * 16])` -> `[]align(1) const nlist_64`; iterate by value.

### 15.4 `sectName()` / `segName()` on 16-character names
`parseName` (macho.zig:839) = `findScalar(u8, name, 0) orelse name.len`, so a name with no NUL returns all 16 bytes. Verified on hello-objc: `__objc_classname`, `__objc_classlist`, `__objc_protolist`, `__objc_imageinfo`, `__objc_superrefs`, `__objc_arraydata` all have len 16.

### 15.5 `std.json.Stringify` pitfalls for binary-derived data (json/Stringify.zig:504-516)
- A `[]const u8` is emitted as a JSON **string only if `std.unicode.utf8ValidateSlice` passes; otherwise it silently becomes an array of numbers** (`"name":[98,97,100,255,...]`). Symbol names, section names, `__cstring` contents and xattr values can hold arbitrary bytes, so the output schema would change per input. Sanitize before stringifying (replace invalid bytes with U+FFFD or emit hex).
- `[N]u8` (UUID, cdhash, digests) -> array of N numbers, never a string; pre-format with `std.fmt.allocPrint(gpa, "{x}", .{digest})`.
- `u64` > 2^53 (raw chained-fixup pointers such as `0x8010000000000000`) are emitted as plain numbers -> JS/jq consumers lose precision. Emit hex strings for addresses/raw pointers, or set `.emit_nonportable_numbers_as_strings = true` (then `"raw":"9227875636482146304"` while `4294967296` stays numeric).
- Control bytes in valid strings are escaped as `` etc.; `.escape_unicode = true` escapes non-ASCII.
Verified output: `{"name":[98,97,100,255,117,116,102,56,1,99,116,108],"uuid":[50,44,177,72,...],"raw":9227875636482146304,"small":4294967296,"opt":null,"bytes_slice":""}`.

### 15.6 Running external tools: `std.process.run` / `spawn` (process.zig:369-540, process/Child.zig)
```zig
pub fn run(gpa: Allocator, io: Io, options: RunOptions) RunError!RunResult;   // spawn + wait + collect both pipes
pub const RunOptions = struct { argv: []const []const u8, stderr_limit: Io.Limit = .unlimited, stdout_limit: Io.Limit = .unlimited, reserve_amount: usize = 64,
    cwd: Child.Cwd = .inherit, environ_map: ?*const Environ.Map = null, expand_arg0: ArgExpansion = .no_expand, progress_node, create_no_window, disable_aslr: bool = false, timeout: Io.Timeout = .none };
pub const RunResult = struct { term: Child.Term, stdout: []u8, stderr: []u8 };   // caller frees stdout/stderr
pub fn spawn(io: Io, options: SpawnOptions) SpawnError!Child;                  // SpawnOptions{ argv, cwd, environ_map, stdin/stdout/stderr: StdIo = .inherit | .ignore | .pipe, ... }
// Child fields: id, stdin/stdout/stderr: ?File; pub fn wait(child: *Child, io: Io) WaitError!Term; pub fn kill(child: *Child, io: Io) void
// Child.Term = union(enum) { exited: u8, signal, stopped, unknown }; has format() so print with {f}; Term.success()
```
`std.process.Child` has no `init`/`spawn`/`collectOutput` methods any more and `std.ChildProcess` does not exist. Verified:
- `std.process.run(gpa, io, .{ .argv = &.{ "/usr/sbin/spctl", "-a", "-vv", "-t", "exec", "/Applications/Discord.app" } })` -> `term=exited with code 0`, stdout empty, **stderr** = `...: accepted` / `source=Notarized Developer ID` / `origin=Developer ID Application: Discord, Inc. (53Q6R32WPB)`; corpus `Hello.app` -> exit 3, stderr `...: rejected`.
- `/usr/bin/xcrun stapler validate <path>` -> exit 0 when a ticket is stapled (Discord.app), **exit 65** when not (Alacritty.app, `/bin/ls`); message on stdout.

### 15.7 `Io.Dir.walk` for bundles (Io/Dir.zig:342-400)
`var walker = try dir.walk(gpa); defer walker.deinit(); while (try walker.next(io)) |e| { e.kind, e.path, e.basename, e.dir }` -- `path` is relative to the walked dir, directory order (unsorted). Symlinks are reported as `.sym_link` and **not descended** (Squirrel.framework: 11 entries = `find -mindepth 1`, no duplication through `Versions/Current -> A`). `dir.statFile(io, "Versions/Current", .{})` follows (kind `directory`); `.{ .follow_symlinks = false }` -> `sym_link`. `dir.readLink(io, sub_path, buffer) ReadLinkError!usize` returns the target **length** (target = `buffer[0..len]`, here "A"). `Io.Dir.openDirAbsolute(io, path, .{ .iterate = true })` exists.

### 15.8 zlib (chained-fixups `symbols_format == 1`), base64 (CodeResources `<data>`), UTF-16 (bplist)
```zig
var r: Io.Reader = .fixed(compressed);
var window: [std.compress.flate.max_window_len]u8 = undefined;      // Decompress asserts this size when a buffer is given
var d: std.compress.flate.Decompress = .init(&r, .zlib, &window);   // Container = enum { raw, gzip, zlib }
const plain = try d.reader.allocRemaining(gpa, .unlimited);          // verified: 43 B zlib -> 37 B
const dec = std.base64.standard.decoderWithIgnore(" \n\t\r");       // plist <data> is wrapped/indented
const n = try dec.decode(&buf, text);                                 // verified -> 41b85e203bb8c224afbb5cc02bb4a5d28049b754 (Hello.app nested cdhash)
// bplist 0x6n strings are UTF-16BE: byte-swap into []u16, then
const s = try std.unicode.utf16LeToUtf8Alloc(gpa, units);            // takes native-endian u16; verified "h\xc3\xa9llo" -> "héllo"
```
`std.compress` has `flate`, `zstd`, `xz`, `lzma`, `lzma2`; there is no `std.compress.zlib` -- use `flate` with the `.zlib` container.

### 15.9 No XML parser in std
`zfn -l | grep -i xml` -> nothing. XML plists (`Info.plist`, `_CodeSignature/CodeResources`, `__TEXT,__info_plist`, `codesign -d --entitlements :-`) need a hand-written reader: elements `plist dict key string integer real true false date data array`, entities `&amp; &lt; &gt; &quot; &apos; &#N; &#xN;`, base64 `<data>` with whitespace (15.8), `<?xml ...?>` / `<!DOCTYPE ...>` prologue. `python3 -c "import plistlib"` / `plutil -p` are the oracles; `truth/summary.json` stores the parsed `Hello.app` Info.plist.

### 15.10 dyld shared cache residency and xattr enumeration
```zig
extern "c" fn _dyld_shared_cache_contains_path(path: [*:0]const u8) bool;   // <mach-o/dyld.h>:128, macOS 11+
extern "c" fn listxattr(path: [*:0]const u8, namebuf: ?[*]u8, size: usize, options: c_int) isize;  // sys/xattr.h; names NUL-separated
```
Verified: `/usr/lib/libSystem.B.dylib`, `/usr/lib/libutil.dylib`, `/usr/lib/libncurses.5.4.dylib`, `.../Foundation.framework/Versions/C/Foundation` -> true; `/opt/homebrew/opt/capstone/lib/libcapstone.5.dylib`, `/usr/lib/libnope.dylib` -> false. Consult this before flagging an absolute `LC_LOAD_DYLIB` path as missing -- no system dylib exists as a file. `listxattr(path, null, 0, 0)` = 21 on `hello-quarantined` -> `[com.apple.quarantine]`. xattr option bits: `XATTR_NOFOLLOW 1`, `XATTR_SHOWCOMPRESSION 0x20`, `XATTR_NOFOLLOW_ANY 0x40`, `XATTR_RESOLVE_BENEATH 0x80`.

### 15.11 Security.framework: trust ladder, notarization, signing information (probe `src/sec.zig`)
**`SecStaticCodeCheckValidity(code, kSecCSCheckAllArchitectures, null) == 0` does not mean trusted** -- every ad-hoc object (hello-adhoc, hello-entitled, Hello.app, Alacritty.app) returns 0. Trust needs requirements:
```zig
extern fn SecRequirementCreateWithString(text: CFStringRef, flags: SecCSFlags, requirement: *SecRequirementRef) OSStatus;   // SecRequirement.h:87
extern fn SecRequirementCopyString(requirement: SecRequirementRef, flags: SecCSFlags, text: *CFStringRef) OSStatus;
extern fn SecStaticCodeCheckValidityWithErrors(code: SecStaticCodeRef, flags: SecCSFlags, req: SecRequirementRef, errors: *CFErrorRef) OSStatus;
extern fn CFStringCreateWithCString(alloc: CFAllocatorRef, cStr: [*:0]const u8, encoding: CFStringEncoding) CFStringRef;
extern fn CFErrorCopyDescription(err: CFErrorRef) CFStringRef;   extern fn CFErrorGetCode(err: CFErrorRef) CFIndex;
```
`SecStaticCodeCheckValidity(code, kSecCSCheckAllArchitectures, req)` results (0 = satisfied; -67050 `errSecCSReqFailed`; -67062 `errSecCSUnsigned`; -67061 `errSecCSSignatureFailed`):

| target | no req | `anchor apple` | `anchor apple generic` | Developer ID `...generic and certificate leaf[field.1.2.840.113635.100.6.1.13]` | App Store `...generic and certificate leaf[field.1.2.840.113635.100.6.1.9]` | `notarized` |
|---|---|---|---|---|---|---|
| /bin/ls (platform) | 0 | **0** | 0 | -67050 | -67050 | **-67050** |
| Discord.app (Developer ID, stapled) | 0 | -67050 | 0 | **0** | -67050 | **0** |
| Discord.app/Contents/MacOS/Discord | 0 | -67050 | 0 | 0 | -67050 | 0 |
| Sketch.app (Mac App Store) | 0 | -67050 | 0 | -67050 | **0** | **-67050** |
| Alacritty.app, Hello.app, hello-adhoc, hello-entitled (ad hoc) | 0 | -67050 | -67050 | -67050 | -67050 | -67050 |
| hello-fat (arm64 signed, x86_64 unsigned) | -67062 | -67050 | -67050 | -67050 | -67050 | -67050 |
| hello-x86_64, hello-unsigned | -67062 | -67062 | -67062 | -67062 | -67062 | -67062 |
| fake-upx (modified) | -67061 | -67061 | -67061 | -67061 | -67061 | -67061 |

Ladder: platform (`anchor apple`; also CD `platform != 0`) -> Mac App Store (6.1.9) -> Developer ID (6.1.13) **and** `notarized` -> Developer ID without ticket -> other certificate (apple-generic fails) -> ad hoc (`CS_ADHOC`, no certificates) -> unsigned. Platform binaries and App Store apps are **not** `notarized` in requirement terms -- do not penalise them for it. `codesign --verify -R='notarized' <path>` gives the same verdict (exit 0/3). Timing: each requirement check <= 2 ms on already-validated code (77 ms for Sketch.app with 786 sealed files); `kSecCSEnforceRevocationChecks` added <= 271 ms here with network available -- offline behaviour was not tested; `kSecCSNoNetworkAccess` (1<<29) cancels it. Other flags (CSCommon.h:236-250, SecStaticCode.h:176-191): `kSecCSConsiderExpiration 1<<31`, `kSecCSCheckTrustedAnchors 1<<27`, `kSecCSStripDisallowedXattrs 1<<24`, `kSecCSCheckGatekeeperArchitectures (1<<6)|kSecCSCheckAllArchitectures`, `kSecCSRestrictSymlinks 1<<7`, `kSecCSRestrictToAppLike 1<<8`, `kSecCSRestrictSidebandData 1<<9`, `kSecCSValidatePEH 1<<11`, `kSecCSSingleThreaded 1<<12`, `kSecCSAllowNetworkAccess 1<<16`.
`SecStaticCodeCheckValidityWithErrors` adds nothing useful: `CFErrorGetCode` = the status and the description is "The operation couldn't be completed. (OSStatus error -67062.)" -- map codes with the table below.

**`SecCodeCopySigningInformation` value types** (flags `kSecCSSigningInformation | kSecCSRequirementInformation | kSecCSContentInformation`; checked with `CFGetTypeID`):

| key | CF type | verified values |
|---|---|---|
| kSecCodeInfoIdentifier | CFString | `com.hnc.Discord`; bare linker-signed file -> file name (`hello-objc`, `libcapstone.5`) |
| kSecCodeInfoTeamIdentifier | CFString / absent | `53Q6R32WPB`; absent for platform and ad hoc |
| kSecCodeInfoFlags | CFNumber | CD flags (0x10000 runtime, 0x2 adhoc, 0x20002 linker-signed) |
| kSecCodeInfoFormat | CFString | `Mach-O thin (arm64)`, `Mach-O universal (x86_64 arm64e)`, `app bundle with Mach-O universal (x86_64 arm64)`, `bundle with Mach-O universal (x86_64 arm64)` (framework) |
| kSecCodeInfoPlatformIdentifier | CFNumber / absent | 26 for /bin/ls only |
| kSecCodeInfoRuntimeVersion | CFNumber / absent | 0x1a0200 = 26.2.0 (nibble-encoded like minos) |
| kSecCodeInfoDigestAlgorithms | CFArray of CFNumber | `[2]` = sha256 |
| kSecCodeInfoUnique | CFData 20 B | the cdhash `codesign` prints as `CDHash=` (the SHA-256 one for dual-CD apps) |
| kSecCodeInfoCdHashes | CFArray of CFData | Sketch: `[3e77... (sha1), 417d... (sha256)]` -- one per CodeDirectory |
| kSecCodeInfoTime | CFDate / absent | signing time (Discord 2026-08-31); absent for ad hoc and App Store here |
| kSecCodeInfoTimestamp | CFDate / absent | secure timestamp (Developer ID) |
| kSecCodeInfoCertificates | CFArray of SecCertificateRef (needs kSecCSSigningInformation) | leaf first: `Developer ID Application: Discord, Inc. (53Q6R32WPB)`, `Developer ID Certification Authority`, `Apple Root CA`; /bin/ls: `Software Signing`, `Apple Code Signing Certification Authority`, `Apple Root CA`; Sketch: `Apple Mac OS Application Signing`, `Apple Worldwide Developer Relations Certification Authority`, `Apple Root CA`; absent for ad hoc |
| kSecCodeInfoStapledNotarizationTicket | CFData, **only with kSecCSContentInformation** | Discord 2304 B beginning `73 38 63 68` ("s8ch"); absent otherwise |
| kSecCodeInfoDesignatedRequirement | SecRequirementRef | `SecRequirementCopyString` -> the `codesign -d -r-` text (ad hoc: `cdhash H"..."`; universal ad hoc: `cdhash H"a" or cdhash H"b"`) |
| kSecCodeInfoMainExecutable | CFURL | `CFURLGetFileSystemRepresentation(url, 1, buf, len)` -> `/Applications/Discord.app/Contents/MacOS/Discord` |
| kSecCodeInfoEntitlementsDict | CFDictionary | CFString keys; CFBoolean / CFString / CFArray values (hello-entitled: 5 keys) |

Helpers verified as plain `extern fn`: `CFDateGetAbsoluteTime(d) f64` (+ `978307200.0` = Unix seconds), `SecCertificateCopySubjectSummary(cert) CFStringRef` (SecCertificate.h:101; gives the CN used in codesign's `Authority=` lines), `SecCertificateGetTypeID()`, `CFArrayGetCount/CFArrayGetValueAtIndex`, `CFDictionaryGetCount/CFDictionaryGetKeysAndValues(d, keys, values)`, `CFDataGetLength/CFDataGetBytePtr`, `CFBooleanGetValue`, `CFURLGetFileSystemRepresentation(url, resolveAgainstBase: Boolean, buffer: [*]u8, maxBufLen: CFIndex) Boolean`, `CFDateGetTypeID/CFDataGetTypeID/CFArrayGetTypeID/CFDictionaryGetTypeID/CFBooleanGetTypeID`. **Guard array elements with `CFGetTypeID(e) == SecCertificateGetTypeID()`** before `SecCertificateCopySubjectSummary` -- calling it on the CFData elements of `CdHashes` segfaults inside Security.framework (the probe crashed until the guard was added). With `kSecCSDefaultFlags` only the generic keys come back (no certificates, no ticket).

**Bundle promotion:** `SecStaticCodeCreateWithPath` on a bundle's main executable (`Discord.app/Contents/MacOS/Discord`, `Discord Helper (GPU).app/Contents/MacOS/...`, `X.framework/Versions/A/X`, corpus `Hello.app/Contents/MacOS/Hello`) yields the **bundle's** identity (Format `app bundle with ...`, Identifier = `CFBundleIdentifier`, ticket visible, `MainExecutable` = that path). The byte-identical bare file `hello-objc` yields `Mach-O thin (arm64)` / identifier `hello-objc`. Pass `isDirectory = 1` to `CFURLCreateFromFileSystemRepresentation` for `.app`/`.framework` directories.

**`errSecCS*` codes (CSCommon.h, complete list of 83, generated from the header):**
```
-67072 errSecCSUnimplemented -- unimplemented code signing feature
-67071 errSecCSInvalidObjectRef -- invalid API object reference
-67070 errSecCSInvalidFlags -- invalid or inappropriate API flag(s) specified
-67069 errSecCSObjectRequired -- a required pointer argument was NULL
-67068 errSecCSStaticCodeNotFound -- cannot find code object on disk
-67067 errSecCSUnsupportedGuestAttributes -- cannot locate guests using this attribute set
-67066 errSecCSInvalidAttributeValues -- given attribute values are invalid
-67065 errSecCSNoSuchCode -- host has no guest with the requested attributes
-67064 errSecCSMultipleGuests -- ambiguous guest specification (host has multiple guests with these attribute values)
-67063 errSecCSGuestInvalid -- code identity has been invalidated
-67062 errSecCSUnsigned -- code object is not signed at all
-67061 errSecCSSignatureFailed -- invalid signature (code or signature have been modified)
-67060 errSecCSSignatureNotVerifiable -- the code cannot be read by the verifier (file system permissions etc.)
-67059 errSecCSSignatureUnsupported -- unsupported type or version of signature
-67058 errSecCSBadDictionaryFormat -- a required plist file or resource is malformed
-67057 errSecCSResourcesNotSealed -- resources are present but not sealed by signature
-67056 errSecCSResourcesNotFound -- code has no resources but signature indicates they must be present
-67055 errSecCSResourcesInvalid -- the sealed resource directory is invalid
-67054 errSecCSBadResource -- a sealed resource is missing or invalid
-67053 errSecCSResourceRulesInvalid -- invalid resource specification rule(s)
-67052 errSecCSReqInvalid -- invalid or corrupted code requirement(s)
-67051 errSecCSReqUnsupported -- unsupported type or version of code requirement(s)
-67050 errSecCSReqFailed -- code failed to satisfy specified code requirement(s)
-67049 errSecCSBadObjectFormat -- object file format unrecognized, invalid, or unsuitable
-67048 errSecCSInternalError -- internal error in Code Signing subsystem
-67047 errSecCSHostReject -- code rejected its host
-67046 errSecCSNotAHost -- attempt to specify guest of code that is not a host
-67045 errSecCSSignatureInvalid -- invalid or unsupported format for signature
-67044 errSecCSHostProtocolRelativePath -- host protocol violation - absolute guest path required
-67043 errSecCSHostProtocolContradiction -- host protocol violation - contradictory hosting modes
-67042 errSecCSHostProtocolDedicationError -- host protocol violation - operation not allowed with/for a dedicated guest
-67041 errSecCSHostProtocolNotProxy -- host protocol violation - proxy hosting not engaged
-67040 errSecCSHostProtocolStateError -- host protocol violation - invalid guest state change request
-67039 errSecCSHostProtocolUnrelated -- host protocol violation - the given guest is not a guest of the given host
-67037 errSecCSNotSupported -- operation inapplicable or not supported for this type of code
-67036 errSecCSCMSTooLarge -- signature too large to embed (size limitation of on-disk representation)
-67035 errSecCSHostProtocolInvalidHash -- host protocol violation - invalid guest hash
-67034 errSecCSStaticCodeChanged -- the code on disk does not match what is running
-67033 errSecCSDBDenied -- permission to use a database denied
-67032 errSecCSDBAccess -- cannot access a database
-67033 errSecCSSigDBDenied -- permission to use a database denied
-67032 errSecCSSigDBAccess -- cannot access a database
-67031 errSecCSHostProtocolInvalidAttribute -- host returned invalid or inconsistent guest attributes
-67030 errSecCSInfoPlistFailed -- invalid Info.plist (plist or signature have been modified)
-67029 errSecCSNoMainExecutable -- the code has no main executable file
-67028 errSecCSBadBundleFormat -- bundle format unrecognized, invalid, or unsuitable
-67027 errSecCSNoMatches -- no matches for search or update operation
-67026 errSecCSFileHardQuarantined -- File created by an AppSandbox, exec/open not allowed
-67025 errSecCSOutdated -- presented data is out of date
-67024 errSecCSDbCorrupt -- a system database or file is corrupt
-67023 errSecCSResourceDirectoryFailed -- invalid resource directory (directory or signature have been modified)
-67022 errSecCSUnsignedNestedCode -- nested code is unsigned
-67021 errSecCSBadNestedCode -- nested code is modified or invalid
-67020 errSecCSBadCallbackValue -- monitor callback returned invalid value
-67019 errSecCSHelperFailed -- the codesign_allocate helper tool cannot be found or used
-67018 errSecCSVetoed --
-67017 errSecCSBadLVArch -- library validation flag cannot be used with an i386 binary
-67016 errSecCSResourceNotSupported -- unsupported resource found (something not a directory, file or symlink)
-67015 errSecCSRegularFile -- the main executable or Info.plist must be a regular file (no symlinks, etc.)
-67014 errSecCSUnsealedAppRoot -- unsealed contents present in the bundle root
-67013 errSecCSWeakResourceRules -- resource envelope is obsolete (custom omit rules)
-67012 errSecCSDSStoreSymlink -- .DS_Store files cannot be a symlink
-67011 errSecCSAmbiguousBundleFormat -- bundle format is ambiguous (could be app or framework)
-67010 errSecCSBadMainExecutable -- main executable failed strict validation
-67009 errSecCSBadFrameworkVersion -- embedded framework contains modified or invalid version
-67008 errSecCSUnsealedFrameworkRoot -- unsealed contents present in the root directory of an embedded framework
-67007 errSecCSWeakResourceEnvelope -- resource envelope is obsolete (version 1 signature)
-67006 errSecCSCancelled -- operation was terminated by explicit cancelation
-67005 errSecCSInvalidPlatform -- invalid platform identifier or platform mismatch
-67004 errSecCSTooBig -- code is too big for current signing format
-67003 errSecCSInvalidSymlink -- invalid destination for symbolic link in bundle
-67002 errSecCSNotAppLike -- the code is valid but does not seem to be an app
-67001 errSecCSBadDiskImageFormat -- disk image format unrecognized, invalid, or unsuitable
-67000 errSecCSUnsupportedDigestAlgorithm -- a requested signature digest algorithm is not supported
-66999 errSecCSInvalidAssociatedFileData -- resource fork, Finder information, or similar detritus not allowed
-66998 errSecCSInvalidTeamIdentifier -- a Team Identifier string is invalid
-66997 errSecCSBadTeamIdentifier -- a Team Identifier is wrong or inappropriate
-66996 errSecCSSignatureUntrusted -- signature is valid but signer is not trusted
-66994 errSecCSInvalidEntitlements -- invalid entitlement plist
-66993 errSecCSInvalidRuntimeVersion -- an invalid runtime version was explicitly set
-66992 errSecCSRevokedNotarization -- notarization indicates this code has been revoked
-66991 errSecCSCMSConstructionFailed -- CMS construction failed, see logs for deeper error
-66990 errSecCSRemoteSignerFailed -- remote signing block did not return a signature
```
Also: `errSecCertificateRevoked = -67820` (SecBase.h:629) and `CSSMERR_TP_CERT_REVOKED = -2147409652` (cssmerr.h:427) for revoked signing certificates; `-67062` / `-67061` / `-67050` / `-66992` are the codes a triage tool meets first.

### 15.12 Probe-project status (rebuilt 2026-09-11 19:50)
- `probe-zig-api`: `zig build` and `zig build test` pass. `probe-capstone`: `zig build -Dcapstone=true run` prints capstone 5.0 and the `/bin/ls` listing. `disasm-notes/a64probe.zig`: `zig test` 2/2 pass.
- `probe-security-tc`: still fails with "translate-c 4 errors" -- this is the documented negative result of gotcha #2 (Security headers cannot be translated), not a regression.
- `critic`: `zig build`, `zig-out/bin/critic`, `zig-out/bin/critic extra`, `zig run walk.zig` all run to completion.
