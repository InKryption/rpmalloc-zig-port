const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    const bench_implementation = b.option(enum { zig, c }, "impl", "Which impl of the benchmark to run") orelse .zig;
    const strip = b.option(bool, "strip", "Strip executable");
    const want_lto = b.option(bool, "want-lto", "Enable wanting LTO");
    const single_threaded = b.option(bool, "single-threaded", "Disable threading");

    const zig_bench_impl_leo = b.addSharedLibrary("benchmark-impl-zig", "src/benchmark.zig", .unversioned);
    zig_bench_impl_leo.setBuildMode(mode);
    zig_bench_impl_leo.setTarget(target);
    zig_bench_impl_leo.strip = strip;
    zig_bench_impl_leo.want_lto = want_lto;
    zig_bench_impl_leo.single_threaded = single_threaded;

    const c_bench_impl_leo = b.addSharedLibrary("benchmark-impl-c", null, .unversioned);
    c_bench_impl_leo.setBuildMode(mode);
    c_bench_impl_leo.setTarget(target);
    c_bench_impl_leo.strip = strip;
    c_bench_impl_leo.want_lto = want_lto;
    c_bench_impl_leo.single_threaded = single_threaded;
    c_bench_impl_leo.addIncludePath("rpmalloc-benchmark/benchmark");
    c_bench_impl_leo.addIncludePath("rpmalloc-benchmark/test");
    c_bench_impl_leo.addCSourceFiles(&.{
        "rpmalloc-benchmark/benchmark/rpmalloc/benchmark.c",
        "rpmalloc-benchmark/benchmark/rpmalloc/rpmalloc.c",
    }, &.{"-O3"});
    c_bench_impl_leo.linkLibC();

    const bench_leo = b.addExecutable(switch (bench_implementation) {
        inline else => |tag| "benchmark-" ++ @tagName(tag),
    }, "rpmalloc-benchmark/benchmark/main.c");
    bench_leo.setBuildMode(mode);
    bench_leo.setTarget(target);
    bench_leo.strip = strip;
    bench_leo.want_lto = want_lto;
    bench_leo.single_threaded = single_threaded;

    bench_leo.linkLibC();
    bench_leo.addIncludePath("rpmalloc-benchmark/benchmark");
    bench_leo.addIncludePath("rpmalloc-benchmark/test");
    bench_leo.addCSourceFiles(&.{
        "rpmalloc-benchmark/test/thread.c",
        "rpmalloc-benchmark/test/timer.c",
    }, &.{"-O3"});

    switch (bench_implementation) {
        .zig => bench_leo.linkLibrary(zig_bench_impl_leo),
        .c => bench_leo.linkLibrary(c_bench_impl_leo),
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
