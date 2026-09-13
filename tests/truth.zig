//! tests/truth.zig — extracts "===== cmd =====" ... "--- exit=N" sections from truth/<name>.txt. Owned by WP0.
const std = @import("std");
const helpers = @import("helpers.zig");

pub const Section = struct { cmd: []const u8, body: []const u8, exit: u8 };
/// Set to false by tests that exercise the failure paths so they do not print expected diffs.
pub var print_diffs: bool = true;

/// Loads truth/<name>.txt and splits it into sections (arena-owned).
pub fn load(arena: std.mem.Allocator, io: std.Io, name: []const u8) ![]Section {
    const path = try std.fmt.allocPrint(arena, "{s}/{s}.txt", .{ helpers.truthDir(), name });
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(1 << 26));
    var out: std.ArrayList(Section) = .empty;
    var it = std.mem.splitScalar(u8, bytes, '\n');
    var cur_cmd: ?[]const u8 = null;
    var body_start: usize = 0;
    var pos: usize = 0;
    while (it.next()) |line| {
        const line_start = pos;
        pos += line.len + 1;
        if (std.mem.startsWith(u8, line, "===== ") and std.mem.endsWith(u8, line, " =====")) {
            cur_cmd = line[6 .. line.len - 6];
            body_start = pos;
            continue;
        }
        if (cur_cmd != null and std.mem.startsWith(u8, line, "--- exit=")) {
            const code = std.fmt.parseInt(u8, std.mem.trim(u8, line[9..], " \r"), 10) catch 255;
            const body_end = if (line_start > body_start) line_start else body_start;
            try out.append(arena, .{ .cmd = cur_cmd.?, .body = bytes[body_start..body_end], .exit = code });
            cur_cmd = null;
        }
    }
    return out.toOwnedSlice(arena);
}
/// First section whose command line starts with `cmd_prefix` (e.g. "/usr/bin/nm -m").
pub fn find(sections: []const Section, cmd_prefix: []const u8) ?Section {
    for (sections) |s| if (std.mem.startsWith(u8, s.cmd, cmd_prefix)) return s;
    return null;
}

/// Trailing whitespace trimmed; "<path>:", "<path> (architecture x):" (otool) and "<path> [arch]:"
/// (dyld_info) banners reduced to the basename, so a test may pass an absolute fixture path.
fn normalize(buf: []u8, line: []const u8) []const u8 {
    const t = std.mem.trimEnd(u8, line, " \t\r");
    if (t.len == 0 or t[t.len - 1] != ':') return t;
    const head = t[0 .. t.len - 1];
    var path = head;
    var rest: []const u8 = "";
    if (std.mem.find(u8, head, " (architecture ")) |p| {
        path = head[0..p];
        rest = head[p..];
    } else if (head.len > 2 and head[head.len - 1] == ']') {
        if (std.mem.findLast(u8, head, " [")) |p| {
            path = head[0..p];
            rest = head[p..];
        }
    }
    if (std.mem.findScalar(u8, path, ' ') != null or std.mem.findScalar(u8, path, '/') == null) return t;
    return std.fmt.bufPrint(buf, "{s}{s}:", .{ std.fs.path.basename(path), rest }) catch t;
}
/// Lines whose value is machine, locale or timezone dependent and can never diff byte-exact:
/// codesign's `Executable=<abs path>` and its locale-formatted `Signed Time=`/`Timestamp=`.
fn skipLine(l: []const u8) bool {
    return std.mem.startsWith(u8, l, "Executable=") or
        std.mem.startsWith(u8, l, "Signed Time=") or
        std.mem.startsWith(u8, l, "Timestamp=");
}

/// Line-by-line compare after trimming trailing whitespace, dropping "Executable=" lines and normalising
/// the tool's "<path>:" banner to the basename; prints the first differing line on failure.
pub fn expectSameLines(expected: []const u8, actual: []const u8) !void {
    var ei = std.mem.splitScalar(u8, expected, '\n');
    var ai = std.mem.splitScalar(u8, actual, '\n');
    var n: usize = 0;
    var eb: [512]u8 = undefined;
    var ab: [512]u8 = undefined;
    while (true) {
        var e: ?[]const u8 = ei.next();
        while (e != null and skipLine(e.?)) e = ei.next();
        var a: ?[]const u8 = ai.next();
        while (a != null and skipLine(a.?)) a = ai.next();
        // tolerate a missing final newline on either side
        if (e != null and e.?.len == 0 and ei.peek() == null) e = ei.next();
        if (a != null and a.?.len == 0 and ai.peek() == null) a = ai.next();
        if (e == null and a == null) return;
        n += 1;
        const en = if (e) |x| normalize(&eb, x) else "<EOF>";
        const an = if (a) |x| normalize(&ab, x) else "<EOF>";
        if (!std.mem.eql(u8, en, an)) {
            if (print_diffs) std.debug.print("\nline {d} differs:\n  expected: {s}\n  actual:   {s}\n", .{ n, en, an });
            return error.LinesDiffer;
        }
    }
}
/// Set-equality of non-empty trimmed lines (order-insensitive comparators for -fixups/-imports/...).
pub fn expectSameLineSet(gpa: std.mem.Allocator, expected: []const u8, actual: []const u8) !void {
    var counts: std.StringHashMapUnmanaged(i32) = .empty;
    defer counts.deinit(gpa);
    // `normalize` rewrites a banner into a stack buffer, so the map cannot borrow it: keys are duped
    // into a scratch arena that outlives the map.
    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();
    const keys = scratch.allocator();
    var eb: [512]u8 = undefined;
    var ab: [512]u8 = undefined;
    var ei = std.mem.splitScalar(u8, expected, '\n');
    while (ei.next()) |l| {
        const t = normalize(&eb, std.mem.trim(u8, l, " \t\r"));
        if (t.len == 0 or skipLine(t)) continue;
        const g = try counts.getOrPut(gpa, try keys.dupe(u8, t));
        if (!g.found_existing) g.value_ptr.* = 0;
        g.value_ptr.* += 1;
    }
    var ai = std.mem.splitScalar(u8, actual, '\n');
    while (ai.next()) |l| {
        const t = normalize(&ab, std.mem.trim(u8, l, " \t\r"));
        if (t.len == 0 or skipLine(t)) continue;
        const g = try counts.getOrPut(gpa, try keys.dupe(u8, t));
        if (!g.found_existing) g.value_ptr.* = 0;
        g.value_ptr.* -= 1;
    }
    var it = counts.iterator();
    var bad = false;
    while (it.next()) |e| if (e.value_ptr.* != 0) {
        if (print_diffs) std.debug.print("\nline set differs ({s}): {s}\n", .{ if (e.value_ptr.* > 0) "missing from actual" else "unexpected in actual", e.key_ptr.* });
        bad = true;
    };
    if (bad) return error.LineSetsDiffer;
}

test "truth: section extraction and comparators" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const secs = try load(arena.allocator(), std.testing.io, "hello-c");
    try std.testing.expect(secs.len > 10);
    const h = find(secs, "/usr/bin/otool -hv").?;
    try std.testing.expectEqual(@as(u8, 0), h.exit);
    try std.testing.expect(std.mem.startsWith(u8, h.body, "hello-c:\nMach header\n"));
    try expectSameLines("/x/y/hello-c:\nA  \nExecutable=z\nB", "hello-c:\nA\nB\n");
    // dyld_info spells the per-slice banner "<path> [arch]:", otool "<path> (architecture x):".
    try expectSameLines("hello-c [arm64]:\nA", "/x/y/hello-c [arm64]:\nA");
    try expectSameLines("x (architecture arm64e):", "/a/b/x (architecture arm64e):");
    // Locale/timezone-dependent codesign lines are dropped like Executable=.
    try expectSameLines("A\nSigned Time=Jan 16, 2026 at 8:39:18 AM\nB", "A\nB");
    try expectSameLines("A\nTimestamp=whenever\nB", "A\nB");
    print_diffs = false;
    defer print_diffs = true;
    try std.testing.expectError(error.LinesDiffer, expectSameLines("A\nB", "A\nC"));
    try expectSameLineSet(std.testing.allocator, "b\na\n", "a\nb");
    // The set comparator normalises banners too (the -fixups/-exports/-imports rows carry one).
    try expectSameLineSet(std.testing.allocator, "hello-c [arm64]:\nx", "/a/b/hello-c [arm64]:\nx");
    try std.testing.expectError(error.LineSetsDiffer, expectSameLineSet(std.testing.allocator, "a\n", "a\nb"));
}
