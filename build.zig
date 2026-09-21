const std = @import("std");

const capstone_prefix_default = "/opt/homebrew/opt/capstone";

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // Shipped mode is ReleaseSafe: `zig build --release` (or -Drelease=true). Debug when omitted.
    // `-Doptimize=<mode>` is ALSO accepted (it is registered before the preferred-mode option so
    // scripts written either way work); when given it wins.
    const optimize: std.builtin.OptimizeMode = b.option(std.builtin.OptimizeMode, "optimize", "Explicit optimize mode (overrides --release)") orelse
        b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });

    // ---- feature detection ----
    const capstone_prefix = b.option([]const u8, "capstone-prefix", "Capstone install prefix (default /opt/homebrew/opt/capstone)") orelse capstone_prefix_default;
    const have_capstone: bool = b.option(bool, "capstone", "Link libcapstone (default: auto-detect header on native builds)") orelse blk: {
        if (!target.query.isNative()) break :blk false;
        const hdr = b.fmt("{s}/include/capstone/capstone.h", .{capstone_prefix});
        std.Io.Dir.accessAbsolute(b.graph.io, hdr, .{}) catch break :blk false;
        break :blk true;
    };
    const capstone_static = b.option(bool, "capstone-static", "Link libcapstone.a instead of the dylib (default true)") orelse true;
    const is_macos = target.result.os.tag == .macos;
    const have_security = b.option(bool, "security", "Link Security/CoreFoundation (default: true on macOS)") orelse is_macos;
    const update_golden = b.option(bool, "update-golden", "Rewrite tests/golden/*.txt from current output") orelse false;

    // `b.root` is the build root as a `Cache.Path`; `joinString` resolves a sub-path against it.
    // (`b.build_root` was removed in this window, and `b.graph.path(.build_root, ..)` asserts.)
    const rootJoin = struct {
        fn f(bb: *std.Build, sub_path: []const u8) []const u8 {
            return bb.root.joinString(bb.allocator, sub_path) catch @panic("OOM");
        }
    }.f;

    // ---- build_options: ONE module, imported by every compilation. `Module.addOptions` calls
    //      `createModule()` per call and two modules over one options.zig fail with
    //      "file exists in modules 'build_options' and 'build_options0'". ----
    const opts = b.addOptions();
    opts.addOption(bool, "have_capstone", have_capstone);
    opts.addOption(bool, "have_security", have_security);
    opts.addOption(bool, "update_golden", update_golden);
    opts.addOption([]const u8, "version", "0.1.0");
    // Absolute paths for the test harness, joined against the build root here rather than derived
    // in tests/helpers.zig. Zig 0.17.0-dev.2257 changed `addOptionPath` (and its new siblings
    // `addOptionPathDirectory`/`addOptionPathUntracked`) to emit a build-root-RELATIVE sub_path --
    // std.Build/Serialize.zig:41 serializes a `.src_path` LazyPath as `sp.sub_path` alone. It used
    // to resolve to an absolute path, and tests/helpers.zig feeds these straight to
    // `Io.Dir.openDirAbsolute` (which asserts `isAbsolute`) and into machre's own argv, so a
    // relative value trips an assert in every filesystem-touching suite.
    opts.addOption([]const u8, "corpus_dir", rootJoin(b, "tests/corpus"));
    opts.addOption([]const u8, "truth_dir", rootJoin(b, "tests/corpus/truth"));
    opts.addOption([]const u8, "golden_dir", rootJoin(b, "tests/golden"));
    opts.addOption([]const u8, "src_dir", rootJoin(b, "src"));
    opts.addOption([]const u8, "corpus_manifest", rootJoin(b, "tests/corpus/truth/summary.json"));
    // Declared only for its dependency edge; the emitted (relative) value is unused. Regenerating
    // the corpus rewrites summary.json, which must re-run the tests rather than report them cached.
    opts.addOptionPath("corpus_manifest_dep", b.path("tests/corpus/truth/summary.json"));
    const options_mod = opts.createModule();

    // ---- library module (everything under src/ except main.zig) ----
    const lib_mod = b.addModule("machre", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = is_macos or have_capstone,
    });
    lib_mod.addImport("build_options", options_mod);
    if (have_security) {
        lib_mod.linkFramework("Security", .{});
        lib_mod.linkFramework("CoreFoundation", .{});
    }
    if (have_capstone) {
        lib_mod.addLibraryPath(.{ .cwd_relative = b.fmt("{s}/lib", .{capstone_prefix}) });
        lib_mod.linkSystemLibrary("capstone", .{
            .use_pkg_config = .no,
            .preferred_link_mode = if (capstone_static) .static else .dynamic,
        });
    }

    // ---- executable ----
    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "machre", .module = lib_mod }},
    });
    exe_mod.addImport("build_options", options_mod);
    const exe = b.addExecutable(.{ .name = "machre", .root_module = exe_mod });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    b.step("run", "Run machre (zig build run -- <command> <path>)").dependOn(&run_cmd.step);

    // ---- tests ----
    const filters = b.option([]const []const u8, "test-filter", "Only run tests whose name contains this string") orelse &.{};

    const unit_tests = b.addTest(.{ .name = "unit", .root_module = lib_mod, .filters = filters });
    const run_unit = b.addRunArtifact(unit_tests);
    const cli_tests = b.addTest(.{ .name = "cli", .root_module = exe_mod, .filters = filters });
    const run_cli = b.addRunArtifact(cli_tests);

    const TestRoot = struct { name: []const u8, path: []const u8, desc: []const u8 };
    const roots = [_]TestRoot{
        .{ .name = "corpus", .path = "tests/corpus_tests.zig", .desc = "Corpus fact tests against tests/corpus/truth/summary.json" },
        .{ .name = "golden", .path = "tests/golden_tests.zig", .desc = "Golden text/JSON output tests (-Dupdate-golden=true to regenerate)" },
        .{ .name = "robustness", .path = "tests/robustness_tests.zig", .desc = "Malformed matrix + mutation sweep + Smith fuzzers (add --fuzz)" },
        .{ .name = "deps", .path = "tests/deps_tests.zig", .desc = "Import-graph policy check over src/**/*.zig" },
        .{ .name = "sanitize", .path = "tests/sanitize_tests.zig", .desc = "Output-inertness: no control bytes or invalid UTF-8 from hostile input" },
    };
    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_unit.step);
    test_step.dependOn(&run_cli.step);
    b.step("test-unit", "Unit tests inside src/ (-Dtest-filter=<module>)").dependOn(&run_unit.step);
    for (roots) |r| {
        const mod = b.createModule(.{
            .root_source_file = b.path(r.path),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "machre", .module = lib_mod }},
        });
        mod.addImport("build_options", options_mod);
        const t = b.addTest(.{ .name = r.name, .root_module = mod, .filters = filters });
        const run_t = b.addRunArtifact(t);
        b.step(b.fmt("test-{s}", .{r.name}), r.desc).dependOn(&run_t.step);
        test_step.dependOn(&run_t.step);
    }
}
