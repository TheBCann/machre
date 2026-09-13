//! cmd/disasm.zig — disassembly with symbolization (otool -tV compatible with --otool-compat).
//! Owned by WP8 (DESIGN.md §12). Imports: cli/context, output/*, analysis/analysis, disasm/*, core/*.
//!
//! Selection: `--func`, `--addr`, `--section`, `--all`, or (default) every function of `__TEXT,__text`,
//! which is exactly the scope `otool -t` prints. Line shape is otool's: address TAB mnemonic TAB operands,
//! then ` ; comment` (arm64) or the operand column padded to 32 plus `## comment` (x86_64, LLVM's column).
const std = @import("std");
const Io = std.Io;
const context = @import("../cli/context.zig");
const Context = context.Context;
const Command = context.Command;
const ExitCode = context.ExitCode;
const json = @import("../output/json.zig");
const text = @import("../output/text.zig");
const Image = @import("../core/image.zig").Image;
const Section = @import("../core/image.zig").Section;
const Analysis = @import("../analysis/analysis.zig").Analysis;
const insn_mod = @import("../disasm/insn.zig");
const Listing = insn_mod.Listing;
const engine_mod = @import("../disasm/engine.zig");
const symbolize = @import("../disasm/symbolize.zig");
const functions_mod = @import("../disasm/functions.zig");

pub const command: Command = .{
    .name = "disasm",
    .summary = "disassembly with symbolization (otool -tV compatible with --otool-compat)",
    .run = run,
    .flags = &.{ "--func=", "--addr=", "--section=", "--all", "--backend=", "--att", "--intel", "--no-annotate", "--bytes", "--count=" },
    .aliases = &.{},
    .needs_macho = true,
};

/// Renders the command for every selected arch through ctx.sink; returns the exit code.
pub fn run(ctx: *Context) anyerror!u8 {
    if (ctx.sink.isJson()) return runJson(ctx);
    return runText(ctx);
}

fn analysisFor(ctx: *Context, img: *const Image) anyerror!Analysis {
    return Analysis.init(ctx.gpa, ctx.arena, ctx.io, ctx.file.?, img, ctx.limits, ctx.diags, .{
        .security = !ctx.no_security,
        .network = !ctx.no_network,
    });
}

/// AnnotateCtx without the (expensive, unused here) strings pass.
fn annotateCtx(an: *Analysis, otool_compat: bool) anyerror!symbolize.AnnotateCtx {
    return .{
        .img = an.img,
        .syms = try an.symbols(),
        .index = try an.addressIndex(),
        .fix = try an.fixups(),
        .stubs = try an.stubs(),
        .funcs = try an.functions(),
        .objc = try an.objc(),
        .strings = null,
        .otool_compat = otool_compat,
    };
}

/// `--otool-compat` is a TEXT diff contract (DESIGN.md §5.2, §5.6): it makes machre's *rendered lines*
/// match an Apple tool's. Nothing in it is about the machine-readable channel, and there is no Apple
/// tool for a JSON consumer to diff against — which is why it changes nothing in the JSON payload of
/// any of the other twenty-two commands.
///
/// `disasm` was the exception: the flag reached `Engine.init` (engine.zig:60, which forces the built-in
/// arm64 text backend) and `AnnotateCtx.otool_compat` (which makes the annotator REPRODUCE otool's
/// answers rather than machre's), so `disasm --json --otool-compat` returned different `mnemonic`,
/// `operands`, `kind`, `comment` and `comment_kind` values from `disasm --json` — including otool's
/// deliberately wrong `Objc class ref: bad class ref` in place of the resolved class name. Degrading a
/// machine-readable answer to match a text-parity goal that JSON cannot even have is a defect, so the
/// flag is now dropped at the JSON boundary. Backend choice in JSON is `--backend`'s job alone, and the
/// payload still reports which backend ran in `backend` / `text_backend`.
fn otoolCompatFor(ctx: *Context) bool {
    return ctx.otool_compat and !ctx.sink.isJson();
}

fn engineOptions(ctx: *Context, arch: @import("../core/arch.zig").ArchName) !engine_mod.Options {
    var o: engine_mod.Options = .{
        .syntax = if (ctx.args.flag("--intel")) .intel else .att,
        .annotate = !ctx.args.flag("--no-annotate"),
        .otool_compat = otoolCompatFor(ctx),
        .show_bytes = ctx.args.flag("--bytes"),
    };
    if (try ctx.args.valueInt(u32, "--count")) |n| o.max_insns = n;
    const b = ctx.args.value("--backend") orelse "auto";
    if (std.mem.eql(u8, b, "capstone")) {
        o.backend = .capstone;
    } else if (std.mem.eql(u8, b, "builtin")) {
        o.backend = insn_mod.builtinBackendFor(arch) orelse return error.UnsupportedArch;
    } else if (!std.mem.eql(u8, b, "auto")) {
        return error.InvalidValue;
    }
    return o;
}

const Range = struct { start: u64, len: u64 };
const Selection = union(enum) {
    func: []const u8,
    range: Range,
    section: struct { seg: []const u8, sect: []const u8 },
    all_sections,
    text_section,
};

fn selectionOf(ctx: *Context) !Selection {
    if (ctx.args.value("--func")) |f| return .{ .func = f };
    if (ctx.args.value("--addr")) |a| return .{ .range = try parseRange(a) };
    if (ctx.args.value("--section")) |s| {
        const comma = std.mem.findScalar(u8, s, ',') orelse return error.InvalidValue;
        return .{ .section = .{ .seg = s[0..comma], .sect = s[comma + 1 ..] } };
    }
    if (ctx.args.flag("--all")) return .all_sections;
    return .text_section;
}

/// "0x100000524", "0x100000524-0x100000600", "0x100000524+0x40".
fn parseRange(s: []const u8) !Range {
    if (std.mem.findScalar(u8, s, '+')) |p| {
        const start = std.fmt.parseInt(u64, s[0..p], 0) catch return error.InvalidValue;
        const len = std.fmt.parseInt(u64, s[p + 1 ..], 0) catch return error.InvalidValue;
        return .{ .start = start, .len = len };
    }
    // A '-' after the first character separates start and end (leading '-' would be a negative number).
    if (s.len > 1) if (std.mem.findScalarPos(u8, s, 1, '-')) |p| {
        const start = std.fmt.parseInt(u64, s[0..p], 0) catch return error.InvalidValue;
        const end = std.fmt.parseInt(u64, s[p + 1 ..], 0) catch return error.InvalidValue;
        return .{ .start = start, .len = if (end > start) end - start else 0 };
    };
    const start = std.fmt.parseInt(u64, s, 0) catch return error.InvalidValue;
    return .{ .start = start, .len = 0 };
}

const Group = struct { section: ?*const Section, listings: []const Listing };

/// Total instruction budget for one command: without it `--all` on a large image would decode far past
/// `limits.max_instructions` (which caps each function, not the run).
fn budgetFor(ctx: *Context, e: *const engine_mod.Engine) u32 {
    if (e.opts.max_insns != 0) return @min(e.opts.max_insns, ctx.limits.max_instructions);
    return ctx.limits.max_instructions;
}

/// Builds the listings the selection asks for, grouped by the section they live in.
fn build(ctx: *Context, an: *Analysis, e: *engine_mod.Engine, img: *const Image, sel: Selection) anyerror![]const Group {
    const actx = try annotateCtx(an, otoolCompatFor(ctx));
    var groups: std.ArrayList(Group) = .empty;
    switch (sel) {
        .func => |name| {
            const funcs = try an.functions();
            var f: ?*const functions_mod.Function = funcs.byName(name);
            if (f == null) {
                if (std.fmt.parseInt(u64, name, 0)) |addr| {
                    f = funcs.byStart(addr) orelse funcs.containing(addr);
                } else |_| {}
            }
            if (f == null) {
                ctx.diags.warn(.disasm, .not_available, null, "no function named '{s}' in this slice", .{name});
                return groups.items;
            }
            const one = try ctx.arena.alloc(Listing, 1);
            one[0] = try engine_mod.disassembleFunction(ctx.arena, e, img, f.?, actx, ctx.limits, ctx.diags);
            try groups.append(ctx.arena, .{ .section = sectionOfIndex(img, f.?.section), .listings = one });
        },
        .range => |r| {
            var len = r.len;
            if (len == 0) {
                const funcs = try an.functions();
                if (funcs.containing(r.start)) |f| len = f.end - r.start else len = 64;
            }
            const one = try ctx.arena.alloc(Listing, 1);
            one[0] = try engine_mod.disassembleRange(ctx.arena, e, img, r.start, len, actx, ctx.limits, ctx.diags);
            try groups.append(ctx.arena, .{ .section = img.sectionForVm(r.start), .listings = one });
        },
        .section => |s| {
            const sect = img.sectionByName(s.seg, s.sect) orelse {
                ctx.diags.warn(.disasm, .not_available, null, "no section {s},{s} in this slice", .{ s.seg, s.sect });
                return groups.items;
            };
            const funcs = try an.functions();
            try groups.append(ctx.arena, .{ .section = sect, .listings = try engine_mod.disassembleSection(ctx.arena, e, img, sect, funcs, actx, ctx.limits, ctx.diags) });
        },
        .all_sections => {
            const funcs = try an.functions();
            var budget = budgetFor(ctx, e);
            for (img.sections) |*sect| {
                if (!sect.isCode() or sect.isZerofill() or sect.size == 0) continue;
                if (budget == 0) break;
                e.opts.max_insns = budget;
                const ls = try engine_mod.disassembleSection(ctx.arena, e, img, sect, funcs, actx, ctx.limits, ctx.diags);
                for (ls) |l| budget -|= @intCast(@min(l.insns.len, std.math.maxInt(u32)));
                try groups.append(ctx.arena, .{ .section = sect, .listings = ls });
            }
        },
        .text_section => {
            const sect = img.sectionByName("__TEXT", "__text") orelse img.sectionByClass(.text) orelse {
                ctx.diags.info(.disasm, .not_available, null, "no __TEXT,__text section in this slice", .{});
                return groups.items;
            };
            const funcs = try an.functions();
            try groups.append(ctx.arena, .{ .section = sect, .listings = try engine_mod.disassembleSection(ctx.arena, e, img, sect, funcs, actx, ctx.limits, ctx.diags) });
        },
    }
    return groups.items;
}

fn sectionOfIndex(img: *const Image, index: ?u16) ?*const Section {
    const i = index orelse return null;
    if (i == 0 or i > img.sections.len) return null;
    return &img.sections[i - 1];
}

// ---------------------------------------------------------------------------------------------
// text
// ---------------------------------------------------------------------------------------------

/// otool's line: address TAB mnemonic [TAB operands] [comment].
fn printInsn(out: *Io.Writer, i: *const insn_mod.Insn, comment: ?[]const u8, arm: bool, show_bytes: bool) Io.Writer.Error!void {
    try out.print("{x:0>16}\t", .{i.addr});
    if (show_bytes) {
        for (i.raw()) |b| try out.print("{x:0>2} ", .{b});
        try out.writeByte('\t');
    }
    try out.writeAll(i.mnemonic);
    if (i.operands.len != 0) {
        try out.writeByte('\t');
        try out.writeAll(i.operands);
    }
    if (comment) |c| {
        if (arm) {
            try out.print(" ; {s}", .{c});
        } else {
            // LLVM/otool put x86 comments in a fixed column after the operand field.
            const width: usize = 32;
            const pad = if (i.operands.len < width) width - i.operands.len else 1;
            try out.splatByteAll(' ', pad);
            try out.print("## {s}", .{c});
        }
    }
    try out.writeByte('\n');
}

fn runText(ctx: *Context) anyerror!u8 {
    const out = ctx.sink.out;
    const multi = ctx.images.len > 1;
    const limit: u32 = if (ctx.otool_compat) 0 else ctx.sink.opts.limit;
    for (ctx.images) |*img| {
        var an = try analysisFor(ctx, img);
        defer an.deinit();
        const opts = engineOptions(ctx, img.arch.name) catch |e| return flagError(ctx, e);
        var e = engine_mod.Engine.init(img.arch.name, opts) catch |err| return engineError(ctx, err, img);
        defer e.deinit();
        var nb: [32]u8 = undefined;
        if (multi) try text.archBanner(out, ctx.display_path, img.arch.displayName(&nb), true) else try out.print("{s}:\n", .{ctx.display_path});

        const sel = selectionOf(ctx) catch |err| return flagError(ctx, err);
        const groups = try build(ctx, &an, &e, img, sel);
        var shown: u32 = 0;
        var total: u32 = 0;
        for (groups) |g| {
            if (g.section) |s| {
                if (e.isPartial())
                    try out.print("({s},{s}) section [{s}: mnemonics limited]\n", .{ try ctx.sink.safe(s.segname), try ctx.sink.safe(s.sectname), e.backendName() })
                else
                    try out.print("({s},{s}) section\n", .{ try ctx.sink.safe(s.segname), try ctx.sink.safe(s.sectname) });
            }
            for (g.listings) |l| {
                for (l.insns, 0..) |*i, idx| {
                    total += 1;
                    if (limit != 0 and shown >= limit) continue;
                    // Labels and comments interpolate symbol/cstring/selector names straight out of the
                    // file (disasm/symbolize.zig), so they are escaped here like every other file string.
                    if (idx < l.labels.len) if (l.labels[idx]) |lab| try out.print("{s}:\n", .{try ctx.sink.safe(lab)});
                    const c: ?[]const u8 = if (idx < l.comments.len) (if (l.comments[idx]) |cm| try ctx.sink.safe(cm) else null) else null;
                    try printInsn(out, i, c, isArm(img), opts.show_bytes);
                    shown += 1;
                }
            }
        }
        if (limit != 0 and total > shown) try out.print("({d} more instructions, use --limit 0)\n", .{total - shown});
        if (e.disagreements != 0)
            try out.print("({d} instruction(s) where capstone and the built-in decoder disagreed on the length; built-in boundaries kept)\n", .{e.disagreements});
    }
    return 0;
}

fn isArm(img: *const Image) bool {
    return switch (img.arch.name) {
        .arm64, .arm64e, .arm64v8, .arm64_32, .armv7, .armv7s, .armv7k, .armv8 => true,
        else => false,
    };
}

fn flagError(ctx: *Context, e: anyerror) anyerror!u8 {
    ctx.diags.err(.cli, .unknown_value, null, "disasm: bad flag value ({t})", .{e});
    ctx.exit_code = .usage;
    return @intFromEnum(ExitCode.usage);
}

/// `--backend=capstone` on a build without Capstone is exit 6; an arch with no decoder is reported and skipped.
fn engineError(ctx: *Context, e: anyerror, img: *const Image) anyerror!u8 {
    switch (e) {
        error.CapstoneUnavailable, error.CapstoneOpen => {
            ctx.diags.err(.disasm, .not_available, null, "capstone backend requested but this build has no Capstone (-Dcapstone=false)", .{});
            ctx.exit_code = .feature_unavailable;
            return @intFromEnum(ExitCode.feature_unavailable);
        },
        error.UnsupportedArch => {
            var nb: [32]u8 = undefined;
            ctx.diags.warn(.disasm, .not_available, null, "no disassembler for {s}", .{img.arch.displayName(&nb)});
            return 0;
        },
        else => return e,
    }
}

// ---------------------------------------------------------------------------------------------
// json
// ---------------------------------------------------------------------------------------------

fn runJson(ctx: *Context) anyerror!u8 {
    const js = &ctx.sink.json;
    var code: u8 = 0;
    for (ctx.images) |*img| {
        var an = try analysisFor(ctx, img);
        defer an.deinit();
        try json.beginArch(js, img);
        const opts = engineOptions(ctx, img.arch.name) catch {
            try json.unavailable(js, command.name, "bad flag value");
            try json.endArch(js);
            ctx.exit_code = .usage;
            code = @intFromEnum(ExitCode.usage);
            continue;
        };
        var e = engine_mod.Engine.init(img.arch.name, opts) catch |err| switch (err) {
            error.CapstoneUnavailable, error.CapstoneOpen => {
                try json.unavailable(js, command.name, "built without Capstone (-Dcapstone=false)");
                try json.endArch(js);
                ctx.exit_code = .feature_unavailable;
                code = @intFromEnum(ExitCode.feature_unavailable);
                continue;
            },
            error.UnsupportedArch => {
                try json.unavailable(js, command.name, "no disassembler for this architecture");
                try json.endArch(js);
                continue;
            },
            else => return err,
        };
        defer e.deinit();
        const sel = selectionOf(ctx) catch {
            try json.unavailable(js, command.name, "bad flag value");
            try json.endArch(js);
            ctx.exit_code = .usage;
            code = @intFromEnum(ExitCode.usage);
            continue;
        };
        const groups = try build(ctx, &an, &e, img, sel);
        const funcs = try an.functions();

        try js.objectField("disasm");
        try js.beginObject();
        try js.objectField("backend");
        try js.write(e.backendName());
        try js.objectField("text_backend");
        try js.write(@tagName(e.text_backend));
        try js.objectField("syntax");
        try js.write(@tagName(opts.syntax));
        try json.boolean(js, "partial", e.isPartial());
        var truncated = false;
        try js.objectField("functions");
        try js.beginArray();
        var shown: usize = 0;
        for (groups) |g| for (g.listings) |l| {
            try js.beginObject();
            const f = funcs.byStart(l.start);
            try json.strOpt(js, ctx.arena, "name", if (f) |x| x.name else null);
            try json.hex(js, "start", l.start);
            try json.hex(js, "end", l.end);
            try js.objectField("source");
            if (f) |x| try js.write(@tagName(x.source)) else try js.write(null);
            try js.objectField("instructions");
            try js.beginArray();
            for (l.insns, 0..) |*i, idx| {
                if (ctx.sink.opts.limit != 0 and shown >= ctx.sink.opts.limit) {
                    truncated = true;
                    break;
                }
                shown += 1;
                try js.beginObject();
                try json.hex(js, "address", i.addr);
                try json.int(js, "size", i.size);
                try json.bytesHex(js, "bytes", i.raw());
                try json.str(js, ctx.arena, "mnemonic", i.mnemonic);
                try json.str(js, ctx.arena, "operands", i.operands);
                try js.objectField("kind");
                try js.write(insn_mod.kindName(i.kind));
                try json.hexOpt(js, "target", i.target);
                const c: ?[]const u8 = if (idx < l.comments.len) l.comments[idx] else null;
                try json.strOpt(js, ctx.arena, "comment", c);
                try js.objectField("comment_kind");
                if (c) |t| try js.write(@tagName(symbolize.commentKind(t))) else try js.write(null);
                try json.strOpt(js, ctx.arena, "label", if (idx < l.labels.len) l.labels[idx] else null);
                try json.boolean(js, "valid", i.valid);
                try js.endObject();
            }
            try js.endArray();
            try js.endObject();
        };
        try js.endArray();
        try json.int(js, "disagreements", e.disagreements);
        try json.boolean(js, "truncated", truncated);
        try js.endObject();
        try json.endArch(js);
    }
    return code;
}
