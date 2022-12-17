const std = @import("std");
const build_options = @import("build_options");
const rpmalloc = @import("rpmalloc");

var rpmalloc_gpa = if (!build_options.port_safety) @compileError("don't reference") else std.heap.GeneralPurposeAllocator(.{
    .stack_trace_frames = 64,
    .retain_metadata = true,
    .never_unmap = true,
    .safety = true,
    .thread_safe = false, // rpmalloc should already be thread safe
}){ .backing_allocator = if (build_options.zig_malloc) std.heap.c_allocator else std.heap.page_allocator };
const Rp = rpmalloc.RPMalloc(.{
    .backing_allocator = blk: {
        if (build_options.port_safety) break :blk &rpmalloc_gpa.allocator();
        if (build_options.zig_malloc) break :blk &std.heap.c_allocator;
        break :blk &std.heap.page_allocator;
    },
});

var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{
    .backing_allocator = if (build_options.zig_malloc) std.heap.c_allocator else std.heap.page_allocator,
};

const allocator = switch (build_options.impl) {
    else => unreachable,
    .port => Rp.allocator(),
    .gpa => gpa.allocator(),
};

export fn benchmark_initialize() c_int {
    switch (build_options.impl) {
        else => unreachable,
        .port => {
            if (build_options.port_safety) {
                rpmalloc_gpa = .{};
            }
            Rp.init(null, .{}) catch return -1;
            return 0;
        },
        .gpa => gpa = .{},
    }
    return 0;
}

export fn benchmark_finalize() c_int {
    switch (build_options.impl) {
        else => unreachable,
        .port => {
            Rp.deinit();
            if (build_options.port_safety) {
                if (rpmalloc_gpa.deinit()) return -1;
            }
        },
        .gpa => if (gpa.deinit()) return -1,
    }
    return 0;
}

export fn benchmark_thread_initialize() c_int {
    switch (build_options.impl) {
        else => unreachable,
        .port => {
            Rp.initThread() catch return -1;
        },
        .gpa => {},
    }
    return 0;
}

export fn benchmark_thread_finalize() c_int {
    switch (build_options.impl) {
        else => unreachable,
        .port => {
            Rp.deinitThread(true);
        },
        .gpa => {},
    }
    return 0;
}

export fn benchmark_thread_collect() void {
    // rpmalloc_thread_collect();
}

export fn benchmark_malloc(alignment: usize, size: usize) ?*anyopaque {
    return allocator.rawAlloc(size, if (alignment != 0) std.math.log2_int(usize, alignment) else 1, 0);
}

export fn benchmark_free(ptr: ?*anyopaque) void {
    allocator.free(@ptrCast([*]u8, ptr orelse return)[0..1]);
}

export fn benchmark_name() [*:0]const u8 {
    return @tagName(build_options.impl);
}
