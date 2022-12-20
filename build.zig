const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const mode = b.standardReleaseOptions();
    _ = mode;
    const target = b.standardTargetOptions(.{});
    _ = target;

    const BenchImplementation = enum { original, port };
    const bench_implementation = b.option(BenchImplementation, "impl", "Which impl of the benchmark to run") orelse .port;
    _ = bench_implementation;
}
