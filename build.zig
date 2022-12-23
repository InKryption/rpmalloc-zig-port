const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    const link_libc = b.option(bool, "link-c", "Force generated executables to link to C") orelse false;
    const options = .{
        .strip = b.option(bool, "strip", "Strip generated executables"),
        .sanitize_thread = b.option(bool, "sanitize-thread", "Enable thread sanitizer") orelse false,
        .disable_sanitize_c = b.option(bool, "no-sanitize-c", "Disable C UBSAN") orelse false,
        .valgrind_support = b.option(bool, "valgrind-support", "Force valgrind support on or off."),
    };
    const setOptions = struct {
        fn setOptions(leo: *std.build.LibExeObjStep, opts: @TypeOf(options)) void {
            inline for (@typeInfo(@TypeOf(opts)).Struct.fields) |field| {
                @field(leo, field.name) = @field(opts, field.name);
            }
        }
    }.setOptions;

    const unit_tests_leo = b.addTest("src/rpmalloc.zig");
    unit_tests_leo.setTarget(target);
    unit_tests_leo.setBuildMode(mode);
    setOptions(unit_tests_leo, options);
    if (link_libc) unit_tests_leo.linkLibC();

    const unit_tests_tls = b.step("unit-tests", "Run the unit tests");
    unit_tests_tls.dependOn(&unit_tests_leo.step);

    const bench_exe_leo = b.addExecutable("bench", "benchmark/main.zig");
    bench_exe_leo.setTarget(target);
    bench_exe_leo.setBuildMode(mode);
    setOptions(bench_exe_leo, options);
    bench_exe_leo.addPackagePath("rpmalloc", "src/rpmalloc.zig");
    if (link_libc) bench_exe_leo.linkLibC();
    bench_exe_leo.install();

    const bench_exe_options = b.addOptions();
    bench_exe_leo.addOptions("build-options", bench_exe_options);
    bench_exe_options.addOption(?comptime_int, "cmd_args_buffer_size", null);

    const BenchImpl = enum {
        @"rp-zig",
        @"rp-c",
        gpa,
    };
    const BenchPrng = enum {
        Xoshiro256,
        Xoroshiro128,
        Pcg,
        RomuTrio,
        Sfc64,
        Isaac64,
    };

    const bench_impl = b.option(BenchImpl, "bench", "Which allocator to benchmark") orelse .@"rp-zig";
    const bench_prng = b.option(BenchPrng, "bench-prng", "Name of PRNG to use") orelse comptime blk: {
        for (std.enums.values(BenchPrng)) |tag| {
            const T = @field(std.rand, @tagName(tag));
            if (T == std.rand.DefaultPrng) break :blk tag;
        }
        unreachable;
    };

    bench_exe_options.contents.writer().print(
        \\pub const impl = .{s};
        \\pub const prng = .{s};
        \\
    , .{
        std.zig.fmtId(@tagName(bench_impl)),
        @tagName(bench_prng),
    }) catch unreachable;

    const bench_exe_run = bench_exe_leo.run();
    if (b.args) |args| {
        bench_exe_run.addArgs(args);
    }
    bench_exe_run.step.dependOn(b.getInstallStep());

    const bench_exe_run_tls = b.step("bench", "Run the benchmark");
    bench_exe_run_tls.dependOn(&bench_exe_run.step);
}
