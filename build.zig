const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    const BenchImplementation = enum {
        original,
        port,
    };
    const bench_implementation = b.option(BenchImplementation, "impl", "Which impl of the benchmark to run") orelse .port;

    // Some general compiler options
    const link_libc = b.option(bool, "link-c", "Unconditionally link libc.") orelse false;
    const strip = b.option(bool, "strip", "Strip executable");
    const want_lto = b.option(bool, "want-lto", "Enable wanting LTO");
    const single_threaded = b.option(bool, "single-threaded", "Disable threading");
    const emit_asm: std.build.LibExeObjStep.EmitOption = if (b.option(bool, "emit-asm", "Emit assembly")) |cond| (if (cond) .emit else .no_emit) else .default;

    // More specific options for zig
    const port_safety = b.option(bool, "port-safety", "Use GPA as the backing allocator to check for leaks") orelse false;
    const zig_malloc = b.option(bool, "zig-malloc", "Back the zig allocator using the C allocator; useful for testing with valgrind") orelse false;

    const zig_bench_impl_leo = b.addStaticLibrary("benchmark-impl-zig", "benchmark/benchmark-impl.zig");
    zig_bench_impl_leo.setBuildMode(mode);
    zig_bench_impl_leo.setTarget(target);
    zig_bench_impl_leo.strip = strip;
    zig_bench_impl_leo.want_lto = want_lto;
    zig_bench_impl_leo.single_threaded = single_threaded;
    zig_bench_impl_leo.emit_asm = emit_asm;
    if (link_libc or zig_malloc) zig_bench_impl_leo.linkLibC();
    zig_bench_impl_leo.addPackagePath("rpmalloc", "src/rpmalloc.zig");

    {
        const zig_bench_impl_options = b.addOptions();
        zig_bench_impl_leo.addOptions("build_options", zig_bench_impl_options);
        zig_bench_impl_options.addOption(bool, "port_safety", port_safety);
        zig_bench_impl_options.addOption(bool, "zig_malloc", zig_malloc);
        zig_bench_impl_options.contents.writer().print(
            \\pub const impl = .{s};
            \\
        , .{@tagName(bench_implementation)}) catch unreachable;
    }

    const c_bench_impl_leo = b.addStaticLibrary("benchmark-impl-c", "benchmark/rpmalloc-benchmark/benchmark/rpmalloc/benchmark.c");
    c_bench_impl_leo.setBuildMode(mode);
    c_bench_impl_leo.setTarget(target);
    c_bench_impl_leo.strip = strip;
    c_bench_impl_leo.want_lto = want_lto;
    c_bench_impl_leo.single_threaded = single_threaded;
    c_bench_impl_leo.emit_asm = emit_asm;
    c_bench_impl_leo.linkLibC();
    c_bench_impl_leo.addIncludePath("benchmark/rpmalloc-benchmark/benchmark");
    c_bench_impl_leo.addIncludePath("benchmark/rpmalloc-benchmark/test");
    c_bench_impl_leo.addCSourceFiles(&.{
        "benchmark/rpmalloc-benchmark/benchmark/rpmalloc/rpmalloc.c",
    }, &.{"-O3"});

    const bench_leo = b.addExecutable(switch (bench_implementation) {
        inline else => |tag| "benchmark-" ++ @tagName(tag),
    }, "benchmark/rpmalloc-benchmark/benchmark/main.c");
    bench_leo.setBuildMode(mode);
    bench_leo.setTarget(target);
    bench_leo.strip = strip;
    bench_leo.want_lto = want_lto;
    bench_leo.single_threaded = single_threaded;

    bench_leo.linkLibC();
    bench_leo.addIncludePath("benchmark/rpmalloc-benchmark/benchmark");
    bench_leo.addIncludePath("benchmark/rpmalloc-benchmark/test");
    bench_leo.addCSourceFiles(&.{
        "benchmark/rpmalloc-benchmark/test/thread.c",
        "benchmark/rpmalloc-benchmark/test/timer.c",
    }, &.{"-O3"});

    switch (bench_implementation) {
        .original => bench_leo.linkLibrary(c_bench_impl_leo),
        .port => bench_leo.linkLibrary(zig_bench_impl_leo),
    }
    bench_leo.install();

    const bench_run = bench_leo.run();
    bench_run.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        bench_run.addArgs(args);
    }
    bench_run.expected_exit_code = null;

    const bench_run_step = b.step("bench", "Run the benchmark");
    bench_run_step.dependOn(&bench_run.step);
}
