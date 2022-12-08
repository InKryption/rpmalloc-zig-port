const std = @import("std");
const rpmalloc = @import("rpmalloc.zig");
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const Rp = rpmalloc.RPMalloc(.{
    // .enable_global_cache = true,
});
const allocator = Rp.allocator();

export fn benchmark_initialize() c_int {
    Rp.init(null, .{}) catch return -1;
    return 0;
}

export fn benchmark_finalize() c_int {
    Rp.deinit();
    return 0;
}

export fn benchmark_thread_initialize() c_int {
    Rp.initThread() catch return -1;
    return 0;
}

export fn benchmark_thread_finalize() c_int {
    Rp.deinitThread(true);
    return 0;
}

export fn benchmark_thread_collect() void {
    // rpmalloc_thread_collect();
}

export fn benchmark_malloc(alignment: usize, size: usize) ?*anyopaque {
    //return rpmemalign(alignment, size);
    return allocator.rawAlloc(size, if (alignment != 0) std.math.log2_int(usize, alignment) else 1, 0);
}

export fn benchmark_free(ptr: ?*anyopaque) void {
    allocator.free(@ptrCast([*]u8, ptr orelse return)[0..1]);
}

export fn benchmark_name() [*:0]const u8 {
    return "zig-rpmalloc";
}
