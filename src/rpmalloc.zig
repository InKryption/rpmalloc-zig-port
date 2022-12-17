const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub const RPMallocOptions = struct {
    /// Enable configuring sizes at runtime. Will introduce a very small
    /// overhead due to some size calculations not being compile time constants
    configurable_sizes: bool = false,
    /// Enable per-thread cache
    enable_thread_cache: bool = true,
    /// Enable global cache shared between all threads, requires thread cache
    enable_global_cache: bool = true,
    /// Enable some slightly more expensive safety checks.
    enable_asserts: bool = std.debug.runtime_safety,
    /// Disable unmapping memory pages (also enables unlimited cache)
    disable_unmap: bool = false,
    /// Enable unlimited global cache (no unmapping until finalization)
    enable_unlimited_cache: bool = false,
    /// Default number of spans to map in call to map more virtual memory (default values yield 4MiB here)
    default_span_map_count: usize = 64,
    /// Size of heap hashmap
    heap_array_size: usize = 47,
    /// Multiplier for global cache
    global_cache_multiplier: usize = 8,
    /// Either a pointer to a comptime-known pointer to an allocator interface, or null to indicate
    /// that the backing allocator will be supplied during initialisation.
    backing_allocator: ?*const Allocator = &std.heap.page_allocator,
};
pub fn RPMalloc(comptime options: RPMallocOptions) type {
    const configurable_sizes = options.configurable_sizes;

    const heap_array_size = options.heap_array_size;
    const enable_thread_cache = options.enable_thread_cache;
    const enable_global_cache = options.enable_global_cache;
    const disable_unmap = options.disable_unmap;
    const enable_unlimited_cache = options.enable_unlimited_cache;
    const default_span_map_count = options.default_span_map_count;
    const global_cache_multiplier = options.global_cache_multiplier;

    if (disable_unmap and !enable_global_cache) {
        @compileError("Must use global cache if unmap is disabled");
    }

    if (disable_unmap and !enable_unlimited_cache) {
        var new_options: RPMallocOptions = options;
        new_options.enable_unlimited_cache = true;
        return RPMalloc(new_options);
    }

    if (!enable_global_cache and enable_unlimited_cache) {
        var new_options = options;
        new_options.enable_unlimited_cache = false;
        return RPMalloc(new_options);
    }

    const known_allocator = options.backing_allocator != null;
    const is_windows_and_not_dynamic = builtin.os.tag == .windows and builtin.link_mode != .Dynamic;

    return struct {
        pub inline fn allocator() Allocator {
            comptime return Allocator{
                .ptr = undefined,
                .vtable = &Allocator.VTable{
                    .alloc = alloc,
                    .resize = resize,
                    .free = free,
                },
            };
        }

        /// Initialize the allocator and setup global data.
        pub fn init(
            ally: if (known_allocator) ?noreturn else Allocator,
            config: InitConfig,
        ) error{OutOfMemory}!void {
            @setCold(true);
            assert(!initialized);
            initialized = true;
            if (!known_allocator) {
                backing_allocator_mut = ally;
            }

            const min_span_size: usize = 256;
            const max_page_size: usize = if (std.math.maxInt(usize) > 0xFFFF_FFFF)
                (4096 * 1024 * 1024)
            else
                (4 * 1024 * 1024);
            // _memory_page_size = std.math.clamp(_memory_page_size, min_span_size, max_page_size);
            comptime assert(page_size >= min_span_size and page_size <= max_page_size);

            if (config.span_size != .default) {
                comptime assert(configurable_sizes);
                span_size_mut = @enumToInt(config.span_size);
                span_size_shift_mut = std.math.log2_int(usize, span_size.*);
                span_mask_mut = calculateSpanMask(span_size.*);
            } // otherwise, they're either not confiburable, or they're already set to default values.

            span_map_count = if (config.span_map_count != 0)
                config.span_map_count
            else
                default_span_map_count;
            if ((span_size.* * span_map_count) < page_size) {
                span_map_count = (page_size / span_size.*);
            }
            if ((page_size >= span_size.*) and ((span_map_count * span_size.*) % page_size) != 0) {
                span_map_count = (page_size / span_size.*);
            }
            heap_reserve_count = if (span_map_count > default_span_map_count) default_span_map_count else span_map_count;

            // TODO: evaluate if this is worth doing.
            if (is_windows_and_not_dynamic) {
                fls_key = FlsAlloc(&struct {
                    fn threadDestructor(value: ?*anyopaque) callconv(.Stdcall) void {
                        if (value != null) threadFinalize(true);
                    }
                }.threadDestructor);
            }

            // Setup all small and medium size classes
            if (configurable_sizes) {
                globalSmallSizeClassesInit(&global_size_classes, span_size);
            } else if (comptime builtin.mode == .Debug) {
                var expected: [SIZE_CLASS_COUNT]SizeClass = std.mem.zeroes([SIZE_CLASS_COUNT]SizeClass);
                globalSmallSizeClassesInit(&expected, span_size);
                for (global_size_classes[0..SMALL_CLASS_COUNT]) |sz_class, i| {
                    assert(std.meta.eql(sz_class, expected[i]));
                }
            }

            if (configurable_sizes) {
                // At least two blocks per span, then fall back to large allocations
                medium_size_limit_runtime.* = calculateMediumSizeLimitRuntime(span_size.*);
            }
            var iclass: usize = 0;
            while (iclass < MEDIUM_CLASS_COUNT) : (iclass += 1) {
                const size: usize = SMALL_SIZE_LIMIT + ((iclass + 1) * MEDIUM_GRANULARITY);
                if (size > medium_size_limit_runtime.*) break;
                global_size_classes[SMALL_CLASS_COUNT + iclass].block_size = @intCast(u32, size);
                adjustSizeClass(SMALL_CLASS_COUNT + iclass, &global_size_classes, span_size);
            }

            try threadInitialize(@returnAddress()); // initialise this thread after everything else is set up.
        }
        pub inline fn initThread() error{OutOfMemory}!void {
            comptime if (builtin.single_threaded) return;
            assert(getThreadId() != main_thread_id);
            assert(!isThreadInitialized());
            try threadInitialize(@returnAddress());
        }

        /// Finalize the allocator
        pub fn deinit() void {
            assert(initialized);
            threadFinalize(true, @returnAddress());

            if (global_reserve != null) {
                _ = @atomicRmw(u32, &global_reserve_master.?.remaining_spans, .Sub, @intCast(u32, global_reserve_count), .Monotonic);
                global_reserve_master = null;
                global_reserve_count = 0;
                global_reserve = null;
            }
            releaseLock(&global_lock); // this is just to set the lock back to its initial state

            { // Free all thread caches and fully free spans
                var list_idx: usize = 0;
                while (list_idx < heap_array_size) : (list_idx += 1) {
                    var maybe_heap: ?*Heap = all_heaps[list_idx];
                    while (maybe_heap != null) {
                        const next_heap: ?*Heap = maybe_heap.?.next_heap;
                        maybe_heap.?.finalize = 1;
                        heapGlobalFinalize(maybe_heap.?, @returnAddress());
                        maybe_heap = next_heap;
                    }
                }
            }

            if (enable_global_cache) {
                // Free global caches
                var iclass: usize = 0;
                while (iclass < LARGE_CLASS_COUNT) : (iclass += 1) {
                    globalCacheFinalize(&global_span_cache[iclass], @returnAddress());
                }
            }

            // TODO: evaluate if this is worth doing
            if (is_windows_and_not_dynamic) {
                FlsFree(fls_key);
                fls_key = 0;
            }

            initialized = false;
        }
        pub inline fn deinitThread(release_caches: bool) void {
            comptime if (builtin.single_threaded) return;
            assert(getThreadId() != main_thread_id);
            assert(isThreadInitialized());
            threadFinalize(release_caches, @returnAddress());
        }

        fn alloc(state_ptr: *anyopaque, len: usize, ptr_align_log2: u8, ret_addr: usize) ?[*]u8 {
            _ = state_ptr;

            const result_ptr = alignedAllocate(
                thread_heap.?,
                @as(u64, 1) << @intCast(u6, ptr_align_log2),
                len,
                ret_addr,
            ) orelse return null;

            if (options.enable_asserts) {
                const usable_size = usableSize(result_ptr);
                assert(len <= usable_size);
            }
            return @ptrCast([*]u8, result_ptr);
        }
        fn resize(state_ptr: *anyopaque, buf: []u8, buf_align: u8, new_len: usize, ret_addr: usize) bool {
            _ = state_ptr;
            _ = ret_addr;

            const usable_size = usableSize(buf.ptr);
            assert(buf.len <= usable_size);
            if (options.enable_asserts) {
                assert(std.mem.isAligned(@ptrToInt(buf.ptr), std.math.shl(usize, 1, buf_align)));
            }

            return usable_size >= new_len;
        }
        fn free(state_ptr: *anyopaque, buf: []u8, buf_align: u8, ret_addr: usize) void {
            _ = state_ptr;
            if (options.enable_asserts) {
                const usable_size = usableSize(buf.ptr);
                assert(buf.len <= usable_size);
                assert(std.mem.isAligned(@ptrToInt(buf.ptr), std.math.shl(usize, 1, buf_align)));
            }
            const span: *Span = getSpanPtr(buf.ptr).?;
            if (span.size_class < SIZE_CLASS_COUNT) {
                @setCold(false);
                deallocateSmallOrMedium(span, @alignCast(SMALL_GRANULARITY, buf.ptr), ret_addr);
            } else if (span.size_class == SIZE_CLASS_LARGE) {
                deallocateLarge(span, ret_addr);
            } else {
                deallocateHuge(span, ret_addr);
            }
        }

        var fls_key: std.os.windows.DWORD = if (is_windows_and_not_dynamic) 0 else @compileError("can't reference");

        /// Maximum allocation size to avoid integer overflow
        inline fn maxAllocSize() @TypeOf(span_size.*) {
            return std.math.maxInt(usize) - span_size.*;
        }

        /// A span can either represent a single span of memory pages with size declared by span_map_count configuration variable,
        /// or a set of spans in a continuous region, a super span. Any reference to the term "span" usually refers to both a single
        /// span or a super span. A super span can further be divided into multiple spans (or this, super spans), where the first
        /// (super)span is the master and subsequent (super)spans are subspans. The master span keeps track of how many subspans
        /// that are still alive and mapped in virtual memory, and once all subspans and master have been unmapped the entire
        /// superspan region is released and unmapped (on Windows for example, the entire superspan range has to be released
        /// in the same call to release the virtual memory range, but individual subranges can be decommitted individually
        /// to reduce physical memory use).
        const Span = extern struct {
            /// Free list
            free_list: ?*align(SMALL_GRANULARITY) anyopaque align(SMALL_GRANULARITY),
            /// Total block count of size class
            block_count: u32,
            /// Size class
            size_class: u32,
            /// Index of last block initialized in free list
            free_list_limit: u32,
            /// Number of used blocks remaining when in partial state
            used_count: u32,
            /// Deferred free list
            free_list_deferred: ?*align(SMALL_GRANULARITY) anyopaque, // atomic
            /// Size of deferred free list, or list of spans when part of a cache list
            list_size: u32,
            /// Size of a block
            block_size: u32,
            /// Flags and counters
            flags: SpanFlags,
            /// Number of spans
            span_count: u32,
            /// Total span counter for master spans
            total_spans: u32,
            /// Offset from master span for subspans
            offset_from_master: u32,
            /// Remaining span counter, for master spans
            remaining_spans: u32, // atomic
            /// Alignment offset
            align_offset: u32,
            /// Owning heap
            heap: *Heap,
            /// Next span
            next: ?*Span,
            /// Previous span
            prev: ?*Span,
        };

        comptime {
            if (@sizeOf(Span) > SPAN_HEADER_SIZE) @compileError("span size mismatch");
        }

        const SpanCache = extern struct {
            count: usize,
            span: [MAX_THREAD_SPAN_CACHE]*Span,
        };

        const SpanLargeCache = extern struct {
            count: usize,
            span: [MAX_THREAD_SPAN_LARGE_CACHE]*Span,
        };

        const HeapSizeClass = extern struct {
            /// Free list of active span
            free_list: ?*align(SMALL_GRANULARITY) anyopaque,
            /// Double linked list of partially used spans with free blocks.
            /// Previous span pointer in head points to tail span of list.
            partial_span: ?*Span,
            /// Early level cache of fully free spans
            cache: ?*Span,
        };

        /// Control structure for a heap, either a thread heap or a first class heap if enabled
        const Heap = extern struct {
            /// Owning thread ID
            owner_thread: if (builtin.single_threaded) [0]u8 else ThreadId,
            /// Free lists for each size class
            size_class: [SIZE_CLASS_COUNT]HeapSizeClass,
            /// Arrays of fully freed spans, single span
            span_cache: if (enable_thread_cache) SpanCache else [0]u8,
            /// List of deferred free spans (single linked list)
            span_free_deferred: ?*Span, // atomic
            /// Number of full spans
            full_span_count: usize,
            /// Mapped but unused spans
            span_reserve: ?*Span,
            /// Master span for mapped but unused spans
            span_reserve_master: ?*Span,
            /// Number of mapped but unused spans
            spans_reserved: u32,
            /// Child count
            child_count: u32, // atomic
            /// Next heap in id list
            next_heap: ?*Heap,
            /// Next heap in orphan list
            next_orphan: ?*Heap,
            /// Heap ID
            id: u32,
            /// Finalization state flag
            finalize: i8,
            /// Master heap owning the memory pages
            master_heap: ?*Heap,

            /// Arrays of fully freed spans, large spans with > 1 span count
            span_large_cache: if (enable_thread_cache) ([LARGE_CLASS_COUNT - 1]SpanLargeCache) else [0]u8,
        };

        /// Size class for defining a block size bucket
        const SizeClass = extern struct {
            /// Size of blocks in this class
            block_size: u32,
            /// Number of blocks in each chunk
            block_count: u16,
            /// Class index this class is merged with
            class_idx: u16,
        };

        comptime {
            if (@sizeOf(SizeClass) != 8) @compileError("Size class size mismatch");
        }

        const GlobalCache = extern struct {
            /// Cache lock
            lock: u32, // atomic
            /// Cache count
            count: u32,
            /// Cached spans
            span: [global_cache_multiplier * MAX_THREAD_SPAN_CACHE]*Span,
            /// Unlimited cache overflow
            overflow: ?*Span,
        };

        /// Default span size (64KiB)
        const default_span_size = 64 * 1024;
        const default_span_size_shift = std.math.log2(default_span_size);
        inline fn calculateSpanMask(input_span_size: anytype) @TypeOf(input_span_size) {
            assert(@popCount(@as(std.math.IntFittingRange(0, input_span_size), input_span_size)) == 1);
            return ~@as(usize, input_span_size - 1);
        }

        // Global data

        /// Pointer to backing allocator. If one is specified at comptime,
        /// this is a pointer to a comptime-known read-only interface.
        /// Otherwise, this is actually a mutable pointer.
        const backing_allocator: *const Allocator = options.backing_allocator orelse &backing_allocator_mut;
        var backing_allocator_mut: std.mem.Allocator = if (known_allocator) @compileError("Don't reference") else undefined;

        var initialized: bool = false;
        var main_thread_id: ThreadId = 0;
        const page_size: usize = std.mem.page_size;
        /// Shift to divide by page size
        const page_size_shift: std.math.Log2Int(usize) = std.math.log2_int(usize, page_size);
        /// Granularity at which memory pages are mapped by OS
        const map_granularity: usize = page_size;

        /// Returns `*const Int` if `configurable_sizes`. Otherwise returns `*const comptime_int`.
        fn ConfigurableIntPtr(comptime Int: type) type {
            if (configurable_sizes) return *const Int;
            return *const comptime_int;
        }

        /// Size of a span of memory pages
        const span_size: ConfigurableIntPtr(usize) = if (!configurable_sizes) &default_span_size else &span_size_mut;
        var span_size_mut: usize = if (configurable_sizes) default_span_size else @compileError("Don't reference");

        /// Shift to divide by span size
        const span_size_shift: ConfigurableIntPtr(std.math.Log2Int(usize)) = if (!configurable_sizes) &default_span_size_shift else &span_size_shift_mut;
        var span_size_shift_mut: std.math.Log2Int(usize) = if (configurable_sizes) default_span_size_shift else @compileError("Don't reference");

        /// Mask to get to start of a memory span
        const span_mask: ConfigurableIntPtr(usize) = if (!configurable_sizes) &calculateSpanMask(span_size.*) else &span_mask_mut;
        var span_mask_mut: usize = if (configurable_sizes) calculateSpanMask(default_span_size) else @compileError("Don't reference");

        /// Number of spans to map in each map call
        var span_map_count: usize = 0;
        /// Number of spans to keep reserved in each heap
        var heap_reserve_count: usize = 0;
        var global_size_classes: [SIZE_CLASS_COUNT]SizeClass = blk: {
            var global_size_classes_init = [_]SizeClass{.{ .block_size = 0, .block_count = 0, .class_idx = 0 }} ** SIZE_CLASS_COUNT;
            if (!configurable_sizes) {
                globalSmallSizeClassesInit(&global_size_classes_init, span_size);
            }
            break :blk global_size_classes_init;
        };

        /// Run-time size limit of medium blocks
        const medium_size_limit_runtime: ConfigurableIntPtr(usize) = if (!configurable_sizes) &calculateMediumSizeLimitRuntime(span_size.*) else &medium_size_limit_runtime_mut;
        var medium_size_limit_runtime_mut: usize = if (configurable_sizes) undefined else @compileError("Don't reference");

        var heap_id_counter: u32 = 0; // atomic

        var global_span_cache = if (enable_global_cache) ([_]GlobalCache{.{
            .lock = 0,
            .count = 0,
            .span = undefined,
            .overflow = null,
        }} ** LARGE_CLASS_COUNT) else @compileError("");

        var global_reserve: ?*Span = null;
        var global_reserve_count: usize = 0;
        var global_reserve_master: ?*Span = null;
        var all_heaps: [heap_array_size]?*Heap = .{null} ** heap_array_size;
        // TODO: Is this comment accurate? If so, does that mean that
        // this isn't needed if we're not supporting huge pages?
        /// Used to restrict access to mapping memory for huge pages
        var global_lock: u32 = 0; // atomic
        /// Orphaned heaps
        var orphan_heaps: ?*Heap = null;

        /// Thread local heap and ID
        threadlocal var thread_heap: ?*Heap = null;

        /// Fast thread ID
        const ThreadId = if (builtin.single_threaded) u0 else std.Thread.Id;
        inline fn getThreadId() ThreadId {
            comptime if (builtin.single_threaded) return 0;
            return std.Thread.getCurrentId();
        }

        /// Set the current thread heap
        inline fn setThreadHeap(heap: ?*Heap) void {
            thread_heap = heap;
            if (!builtin.single_threaded) {
                if (heap != null) {
                    heap.?.owner_thread = getThreadId();
                }
            }
        }

        // Low level memory map/unmap

        /// Map more virtual memory
        /// size is number of bytes to map
        /// offset receives the offset in bytes from start of mapped region
        /// returns address to start of mapped region to use
        inline fn memoryMap(size: usize, offset: *usize, ret_addr: usize) ?*align(page_size) anyopaque {
            assert(size != 0); // invalid mmap size
            assert(size % page_size == 0); // invalid mmap size
            // Either size is a heap (a single page) or a (multiple) span - we only need to align spans, and only if larger than map granularity
            const padding: usize = if (size >= span_size.* and span_size.* > map_granularity) span_size.* else 0;
            var ptr: *align(page_size) anyopaque = blk: {
                const ptr = backing_allocator.rawAlloc(
                    size + padding,
                    comptime std.math.log2_int(usize, page_size),
                    ret_addr,
                ) orelse return null;
                break :blk @alignCast(page_size, ptr);
            };
            if (padding != 0) {
                const final_padding: usize = padding - (@ptrToInt(ptr) & ~@as(usize, span_mask.*));
                assert(final_padding <= span_size.*);
                assert(final_padding % 8 == 0);
                ptr = @alignCast(page_size, @ptrCast([*]u8, ptr) + final_padding);
                offset.* = final_padding >> 3;
            }
            assert(size < span_size.* or (@ptrToInt(ptr) & ~@as(usize, span_mask.*)) == 0);
            return ptr;
        }

        /// Unmap virtual memory
        /// address is the memory address to unmap, as returned from _memory_map
        /// size is the number of bytes to unmap, which might be less than full region for a partial unmap
        /// offset is the offset in bytes to the actual mapped region, as set by _memory_map
        /// release is set to 0 for partial unmap, or size of entire range for a full unmap
        inline fn memoryUnmap(address_init: ?*anyopaque, offset: usize, release_init: usize, ret_addr: usize) void {
            var address: *anyopaque = address_init orelse return;
            var release = release_init;

            // I don't think we want to/can do partial unmappings, and it
            // seems like the zig stdlib discourages it as well.
            assert(release != 0);
            assert(offset != 0);
            assert(release >= page_size); // Invalid unmap size
            assert(release % page_size == 0); // Invalid unmap size

            address = @ptrCast([*]u8, address) - (offset << 3);
            if ((release >= span_size.*) and (span_size.* > map_granularity)) {
                // Padding is always one span size
                release += span_size.*;
            }

            if (!disable_unmap) {
                backing_allocator.rawFree(@ptrCast([*]u8, address)[0..release], page_size_shift, ret_addr);
            }
        }

        /// Declare the span to be a subspan and store distance from master span and span count
        inline fn spanMarkAsSubspanUnlessMaster(master: *Span, subspan: *Span, span_count: usize) void {
            assert(subspan != master or subspan.flags.master); // Span master pointer and/or flag mismatch
            if (subspan != master) {
                subspan.flags = .{ .subspan = true };
                assert(@ptrToInt(subspan) > @ptrToInt(master));
                subspan.offset_from_master = @intCast(u32, (@ptrToInt(subspan) - @ptrToInt(master)) >> span_size_shift.*);
                subspan.align_offset = 0;
            }
            subspan.span_count = @intCast(u32, span_count);
        }

        /// Use global reserved spans to fulfill a memory map request (reserve size must be checked by caller)
        inline fn globalGetReservedSpans(span_count: usize) ?*Span {
            const span: *Span = global_reserve.?;
            spanMarkAsSubspanUnlessMaster(global_reserve_master.?, span, span_count);
            global_reserve_count -= span_count;
            if (global_reserve_count != 0) {
                global_reserve = ptrAndAlignCast(*Span, @ptrCast([*]u8, span) + (span_count << span_size_shift.*));
            } else {
                global_reserve = null;
            }
            return span;
        }

        /// Store the given spans as global reserve (must only be called from within new heap allocation, not thread safe)
        inline fn globalSetReservedSpans(master: *Span, reserve: *Span, reserve_span_count: usize) void {
            global_reserve_master = master;
            global_reserve_count = reserve_span_count;
            global_reserve = reserve;
        }

        // Span linked list management

        /// Add a span to double linked list at the head
        inline fn spanDoubleLinkListAdd(head: *?*Span, span: *Span) void {
            if (head.* != null) {
                head.*.?.prev = span;
            }
            span.next = head.*;
            head.* = span;
        }

        /// Pop head span from double linked list
        inline fn spanDoubleLinkListPopHead(head: *?*Span, span: *Span) void {
            assert(head.* == span); // Linked list corrupted
            const old_head: *Span = head.*.?;
            head.* = old_head.next;
        }

        /// Remove a span from double linked list
        inline fn spanDoubleLinkListRemove(maybe_head: *?*Span, span: *Span) void {
            assert(maybe_head.* != null); // Linked list corrupted
            const head = maybe_head;
            if (head.* == span) {
                head.* = span.next;
                return;
            }

            const maybe_next_span: ?*Span = span.next;
            const prev_span: *Span = span.prev.?;
            prev_span.next = maybe_next_span;
            if (maybe_next_span != null) {
                @setCold(false);
                maybe_next_span.?.prev = prev_span;
            }
        }

        // Span control

        inline fn getSpanPtr(ptr: *anyopaque) ?*Span {
            const span_addr = @ptrToInt(ptr) & span_mask.*;
            return @intToPtr(?*Span, span_addr);
        }

        /// Use reserved spans to fulfill a memory map request (reserve size must be checked by caller)
        inline fn spanMapFromReserve(heap: *Heap, span_count: usize) ?*Span {
            //Update the heap span reserve
            const span: ?*Span = heap.span_reserve;
            heap.span_reserve = ptrAndAlignCast(?*Span, @ptrCast([*]u8, span) + (span_count * span_size.*));
            heap.spans_reserved -= @intCast(u32, span_count);
            spanMarkAsSubspanUnlessMaster(heap.span_reserve_master.?, span.?, span_count);
            return span;
        }

        /// Get the aligned number of spans to map in based on wanted count, configured mapping granularity and the page size
        inline fn spanAlignCount(span_count: usize) usize {
            var request_count: usize = if (span_count > span_map_count) span_count else span_map_count;
            if ((page_size > span_size.*) and ((request_count * span_size.*) % page_size) != 0) {
                request_count += span_map_count - (request_count % span_map_count);
            }
            return request_count;
        }

        /// Setup a newly mapped span
        inline fn spanInitialize(span: *Span, total_span_count: usize, span_count: usize, align_offset: usize) void {
            span.total_spans = @intCast(u32, total_span_count);
            span.span_count = @intCast(u32, span_count);
            span.align_offset = @intCast(u32, align_offset);
            span.flags = .{ .master = true };
            assert(@bitCast(u32, span.flags) == 1);
            // TODO: Is there a reason for this to be atomic?
            // Intuitively it seems like there wouldn't be, since the span in question has presumably
            // just been mapped, and thus wouldn't be accessible by any other thread at present.
            @atomicStore(u32, &span.remaining_spans, @intCast(u32, total_span_count), .Monotonic);
        }

        /// Map an aligned set of spans, taking configured mapping granularity and the page size into account
        fn spanMapAlignedCount(heap: *Heap, span_count: usize, ret_addr: usize) ?*Span {
            // If we already have some, but not enough, reserved spans, release those to heap cache and map a new
            // full set of spans. Otherwise we would waste memory if page size > span size (huge pages)
            const aligned_span_count: usize = spanAlignCount(span_count);
            var align_offset: usize = 0;
            const span: *Span = @ptrCast(?*Span, memoryMap(aligned_span_count * span_size.*, &align_offset, ret_addr)) orelse return null;
            spanInitialize(span, aligned_span_count, span_count, align_offset);
            if (aligned_span_count > span_count) {
                const reserved_spans: *Span = ptrAndAlignCast(*Span, @ptrCast([*]u8, span) + (span_count * span_size.*));
                var reserved_count: usize = aligned_span_count - span_count;
                if (heap.spans_reserved != 0) {
                    spanMarkAsSubspanUnlessMaster(heap.span_reserve_master.?, heap.span_reserve.?, heap.spans_reserved);
                    heapCacheInsert(heap, heap.span_reserve.?, ret_addr);
                }
                // TODO: Is this ever true? Empirically it seems like no, and if the comment on global_lock is true,
                // then the assumed precondition of this branch would indicate that it is never allowed to happen anyways.
                if (reserved_count > heap_reserve_count) {
                    // If huge pages or eager spam map count, the global reserve spin lock is held by caller, spanMap
                    if (options.enable_asserts) {
                        assert(@atomicLoad(u32, &global_lock, .Monotonic) == 1); // Global spin lock not held as expected
                    }
                    const remain_count: usize = reserved_count - heap_reserve_count;
                    reserved_count = heap_reserve_count;
                    const remain_span: *Span = ptrAndAlignCast(*Span, @ptrCast([*]u8, reserved_spans) + (reserved_count * span_size.*));

                    if (global_reserve != null) {
                        spanMarkAsSubspanUnlessMaster(global_reserve_master.?, global_reserve.?, global_reserve_count);
                        spanUnmap(global_reserve.?, ret_addr);
                    }
                    globalSetReservedSpans(span, remain_span, remain_count);
                }
                heapSetReservedSpans(heap, span, reserved_spans, @intCast(u32, reserved_count));
            }
            return span;
        }

        /// Map in memory pages for the given number of spans (or use previously reserved pages)
        inline fn spanMap(heap: *Heap, span_count: usize, ret_addr: usize) ?*Span {
            @setCold(true);
            if (span_count <= heap.spans_reserved)
                return spanMapFromReserve(heap, span_count);
            var span: ?*Span = null;
            const use_global_reserve: bool = (page_size > span_size.*) or (span_map_count > heap_reserve_count);
            if (use_global_reserve) {
                // If huge pages, make sure only one thread maps more memory to avoid bloat
                acquireLock(&global_lock);
                if (global_reserve_count >= span_count) {
                    var reserve_count: usize = if (heap.spans_reserved == 0) heap_reserve_count else span_count;
                    reserve_count = @min(reserve_count, global_reserve_count);
                    span = globalGetReservedSpans(reserve_count);
                    if (span != null) {
                        if (reserve_count > span_count) {
                            const reserved_span: *Span = ptrAndAlignCast(*Span, @ptrCast([*]u8, span) + (span_count << span_size_shift.*));
                            heapSetReservedSpans(heap, global_reserve_master, reserved_span, @intCast(u32, reserve_count - span_count));
                        }
                        // Already marked as subspan in globalGetReservedSpans
                        span.?.span_count = @intCast(u32, span_count);
                    }
                }
            }
            defer if (use_global_reserve) releaseLock(&global_lock);

            if (span == null) {
                span = spanMapAlignedCount(heap, span_count, ret_addr);
            }
            return span;
        }

        /// Unmap memory pages for the given number of spans (or mark as unused if no partial unmappings)
        fn spanUnmap(span: *Span, ret_addr: usize) void {
            assert(span.flags.master or span.flags.subspan); // Span flag corrupted
            assert(!span.flags.master or !span.flags.subspan); // Span flag corrupted

            const is_master = span.flags.master;
            const master: *Span = if (!is_master)
                ptrAndAlignCast(*Span, @ptrCast([*]u8, span) - (span.offset_from_master * span_size.*))
            else
                span;
            assert(is_master or span.flags.subspan); // Span flag corrupted
            assert(master.flags.master); // Span flag corrupted

            if (!is_master) {
                assert(span.align_offset == 0); // Span align offset corrupted
                // TODO: partial unmapping doesn't really work with a generic backing allocator,
                // and it seems like the zig stdlib discourages it as well.

                if (false) {
                    // Directly unmap subspans (unless huge pages, in which case we defer and unmap entire page range with master)
                    if (span_size.* >= page_size) {
                        memoryUnmap(span, 0, 0);
                    }
                }
            } else {
                // Special double flag to denote an unmapped master
                // It must be kept in memory since span header must be used
                @ptrCast(*SpanFlags.BackingInt, &span.flags).* |= comptime @bitCast(SpanFlags.BackingInt, SpanFlags{
                    .aligned_blocks = false,
                    .master = true,
                    .subspan = true,
                    .unmapped_master = true,
                });
            }

            std.debug.assert(span.span_count != 0);
            const prev_remaining_spans: i64 = @atomicRmw(u32, &master.remaining_spans, .Sub, span.span_count, .Monotonic);
            if (prev_remaining_spans - span.span_count <= 0) {
                // Everything unmapped, unmap the master span with release flag to unmap the entire range of the super span
                assert(master.flags.master and master.flags.subspan); // Span flag corrupted
                memoryUnmap(master, master.align_offset, @as(usize, master.total_spans) * span_size.*, ret_addr);
            }
        }

        /// Move the span (used for small or medium allocations) to the heap thread cache
        inline fn spanReleaseToCache(heap: *Heap, span: *Span, ret_addr: usize) void {
            assert(heap == span.heap); // Span heap pointer corrupted
            assert(span.size_class < SIZE_CLASS_COUNT); // Invalid span size class
            assert(span.span_count == 1); // Invalid span count
            if (heap.finalize == 0) {
                if (heap.size_class[span.size_class].cache != null) {
                    heapCacheInsert(heap, heap.size_class[span.size_class].cache.?, ret_addr);
                }
                heap.size_class[span.size_class].cache = span;
            } else {
                spanUnmap(span, ret_addr);
            }
        }

        /// Initialize a (partial) free list up to next system memory page, while reserving the first block
        /// as allocated, returning number of blocks in list
        fn freeListPartialInit(list: *?*anyopaque, first_block: *?*anyopaque, page_start: *anyopaque, block_start: *anyopaque, block_count_init: u32, block_size: u32) u32 {
            var block_count = block_count_init;
            assert(block_count != 0); // Internal failure
            first_block.* = block_start;
            if (block_count > 1) {
                var free_block = ptrAndAlignCast(*align(SMALL_GRANULARITY) anyopaque, @ptrCast([*]u8, block_start) + block_size);
                var block_end = ptrAndAlignCast(*align(SMALL_GRANULARITY) anyopaque, @ptrCast([*]u8, block_start) + (@as(usize, block_size) * block_count));
                // If block size is less than half a memory page, bound init to next memory page boundary
                if (block_size < (page_size >> 1)) {
                    const page_end = ptrAndAlignCast(*align(SMALL_GRANULARITY) anyopaque, @ptrCast([*]u8, page_start) + page_size);
                    if (@ptrToInt(page_end) < @ptrToInt(block_end)) {
                        block_end = page_end;
                    }
                }
                list.* = free_block;
                block_count = 2;
                var next_block = ptrAndAlignCast(*align(SMALL_GRANULARITY) anyopaque, @ptrCast([*]u8, free_block) + block_size);
                while (@ptrToInt(next_block) < @ptrToInt(block_end)) {
                    ptrAndAlignCast(*?*anyopaque, free_block).* = next_block;
                    free_block = next_block;
                    block_count += 1;
                    next_block = @alignCast(SMALL_GRANULARITY, @ptrCast([*]u8, next_block) + block_size);
                }
                ptrAndAlignCast(*?*anyopaque, free_block).* = null;
            } else {
                list.* = null;
            }
            return block_count;
        }

        /// Initialize an unused span (from cache or mapped) to be new active span, putting the initial free list in heap class free list
        fn spanInitializeNew(heap: *Heap, heap_size_class: *HeapSizeClass, span: *Span, class_idx: u32) ?*align(SMALL_GRANULARITY) anyopaque {
            assert(span.span_count == 1); // Internal failure
            const size_class: *SizeClass = &global_size_classes[class_idx];
            span.size_class = class_idx;
            span.heap = heap;
            // span.flags &= ~SPAN_FLAG_ALIGNED_BLOCKS;
            @ptrCast(*SpanFlags.BackingInt, &span.flags).* &= comptime @bitCast(u32, SpanFlags{
                .master = true,
                .subspan = true,
                .aligned_blocks = false,
                .unmapped_master = true,
            });
            span.block_size = size_class.block_size;
            span.block_count = size_class.block_count;
            span.free_list = null;
            span.list_size = 0;
            atomicStorePtrRelease(&span.free_list_deferred, null);

            //Setup free list. Only initialize one system page worth of free blocks in list
            var block: ?*align(SMALL_GRANULARITY) anyopaque = undefined;
            span.free_list_limit = freeListPartialInit(
                &heap_size_class.free_list,
                &block,
                span,
                @ptrCast([*]align(SMALL_GRANULARITY) u8, span) + SPAN_HEADER_SIZE,
                size_class.block_count,
                size_class.block_size,
            );
            // Link span as partial if there remains blocks to be initialized as free list, or full if fully initialized
            if (span.free_list_limit < span.block_count) {
                spanDoubleLinkListAdd(&heap_size_class.partial_span, span);
                span.used_count = span.free_list_limit;
            } else {
                heap.full_span_count += 1;
                span.used_count = span.block_count;
            }
            return block;
        }

        fn spanExtractFreeListDeferred(span: *Span) void {
            // We need acquire semantics on the CAS operation since we are interested in the list size
            // Refer to deallocateDeferSmallOrMedium for further comments on this dependency

            // TODO: is this OK? According to Protty `@atomicRmw` is already a loop like the one below
            span.free_list = atomicExchangePtrAcquire(&span.free_list_deferred, INVALID_POINTER);
            if (false) while (true) {
                span.free_list = atomicExchangePtrAcquire(&span.free_list_deferred, INVALID_POINTER);
                if (span.free_list != INVALID_POINTER) break;
            };
            span.used_count -= span.list_size;
            span.list_size = 0;
            atomicStorePtrRelease(&span.free_list_deferred, null);
        }

        inline fn spanIsFullyUtilized(span: *Span) bool {
            assert(span.free_list_limit <= span.block_count); // Span free list corrupted
            return span.free_list == null and (span.free_list_limit == span.block_count);
        }

        fn spanFinalize(heap: *Heap, iclass: usize, span: *Span, list_head: ?*?*Span, ret_addr: usize) bool {
            const free_list = heap.size_class[iclass].free_list.?;
            const class_span: ?*Span = getSpanPtr(free_list);
            if (span == class_span) {
                // Adopt the heap class free list back into the span free list
                var block: ?*align(SMALL_GRANULARITY) anyopaque = span.free_list;
                var last_block: @TypeOf(block) = null;
                while (block != null) {
                    last_block = block;
                    block = @ptrCast(*@TypeOf(block), block).*;
                }
                var free_count: u32 = 0;
                block = free_list;
                while (block != null) {
                    free_count += 1;
                    block = @ptrCast(*@TypeOf(block), block).*;
                }
                if (last_block != null) {
                    @ptrCast(*@TypeOf(last_block), last_block).* = free_list;
                } else {
                    span.free_list = free_list;
                }
                heap.size_class[iclass].free_list = null;
                span.used_count -= free_count;
            }
            // TODO: should this leak check be kept? And should it be an assertion?
            if (false) {
                assert(span.list_size == span.used_count); // If this assert triggers you have memory leaks
            }
            if (span.list_size == span.used_count) {
                // This function only used for spans in double linked lists
                if (list_head != null) {
                    spanDoubleLinkListRemove(list_head.?, span);
                }
                spanUnmap(span, ret_addr);
                return true;
            }
            return false;
        }

        // Global cache

        /// Finalize a global cache
        fn globalCacheFinalize(cache: *GlobalCache, ret_addr: usize) void {
            comptime assert(enable_global_cache);

            acquireLock(&cache.lock);
            defer releaseLock(&cache.lock);

            for (@as([*]*Span, &cache.span)[0..cache.count]) |span| {
                spanUnmap(span, ret_addr);
            }
            cache.count = 0;

            while (cache.overflow != null) {
                cache.overflow = cache.overflow.?.next;
                spanUnmap(cache.overflow.?, ret_addr);
            }
        }

        fn globalCacheInsertSpans(span: [*]*Span, span_count: usize, count: usize, ret_addr: usize) void {
            comptime assert(enable_global_cache);

            const cache_limit: usize = if (span_count == 1)
                global_cache_multiplier * MAX_THREAD_SPAN_CACHE
            else
                global_cache_multiplier * (MAX_THREAD_SPAN_LARGE_CACHE - (span_count >> 1));

            const cache: *GlobalCache = &global_span_cache[span_count - 1];

            var insert_count: usize = count;
            {
                acquireLock(&cache.lock);
                defer releaseLock(&cache.lock);

                if ((cache.count + insert_count) > cache_limit)
                    insert_count = cache_limit - cache.count;

                // memcpy(cache->span + cache->count, span, sizeof(Span*) * insert_count);
                for ((@as([*]*Span, &cache.span) + cache.count)[0..insert_count]) |*dst, i| {
                    dst.* = span[i];
                }
                cache.count += @intCast(u32, insert_count);

                while ( // zig fmt: off
                    if (comptime enable_unlimited_cache)
                        (insert_count < count)
                    else
                        // Enable unlimited cache if huge pages, or we will leak since it is unlikely that an entire huge page
                        // will be unmapped, and we're unable to partially decommit a huge page
                        ((page_size > span_size.*) and (insert_count < count))
                    // zig fmt: on
                ) {
                    const current_span: *Span = span[insert_count];
                    insert_count += 1;
                    current_span.next = cache.overflow;
                    cache.overflow = current_span;
                }
            }

            var keep: ?*Span = null;
            for (span[insert_count..count]) |current_span| {
                // Keep master spans that has remaining subspans to avoid dangling them
                if (current_span.flags.master and (@atomicLoad(u32, &current_span.remaining_spans, .Monotonic) > current_span.span_count)) {
                    current_span.next = keep;
                    keep = current_span;
                } else {
                    spanUnmap(current_span, ret_addr);
                }
            }

            if (keep != null) {
                acquireLock(&cache.lock);
                defer releaseLock(&cache.lock);

                var islot: usize = 0;
                while (keep != null) {
                    while (islot < cache.count) : (islot += 1) {
                        const current_span: *Span = cache.span[islot];
                        if (!current_span.flags.master or
                            (current_span.flags.master and (@atomicLoad(u32, &current_span.remaining_spans, .Monotonic) <= current_span.span_count)))
                        {
                            spanUnmap(current_span, ret_addr);
                            cache.span[islot] = keep.?;
                            break;
                        }
                    }
                    if (islot == cache.count) break;
                    keep = keep.?.next;
                }

                if (keep != null) {
                    var tail: *Span = keep.?;
                    while (tail.next != null) {
                        tail = tail.next.?;
                    }
                    tail.next = cache.overflow;
                    cache.overflow = keep;
                }
            }
        }

        fn globalCacheExtractSpans(span: [*]*Span, span_count: usize, count: usize) usize {
            comptime assert(enable_global_cache);

            const cache: *GlobalCache = &global_span_cache[span_count - 1];

            var extract_count: usize = 0;
            acquireLock(&cache.lock);
            defer releaseLock(&cache.lock);

            const want = @intCast(u32, @min(count - extract_count, cache.count));

            // memcpy(span + extract_count, cache->span + (cache->count - want), sizeof(span_t*) * want);
            for (@as([*]*Span, &cache.span)[cache.count - want .. want][0..want]) |src, i| {
                (span + extract_count)[i] = src;
            }

            cache.count -= want;
            extract_count += want;

            while (extract_count < count) {
                const current_span: *Span = cache.overflow orelse break;
                span[extract_count] = current_span;
                extract_count += 1;
                cache.overflow = current_span.next;
            }

            if (options.enable_asserts) {
                for (span[0..extract_count]) |span_elem| {
                    assert(span_elem.span_count == span_count);
                }
            }

            return extract_count;
        }

        // Heap control

        /// Store the given spans as reserve in the given heap
        inline fn heapSetReservedSpans(heap: *Heap, master: ?*Span, reserve: ?*Span, reserve_span_count: u32) void {
            heap.span_reserve_master = master;
            heap.span_reserve = reserve;
            heap.spans_reserved = reserve_span_count;
        }

        /// Adopt the deferred span cache list, optionally extracting the first single span for immediate re-use
        fn heapCacheAdoptDeferred(heap: *Heap, single_span: ?*?*Span, ret_addr: usize) void {
            var maybe_span: ?*Span = atomicExchangePtrAcquire(&heap.span_free_deferred, null);
            while (maybe_span != null) {
                const next_span: ?*Span = @ptrCast(?*Span, maybe_span.?.free_list);
                assert(maybe_span.?.heap == heap); // Span heap pointer corrupted

                if (maybe_span.?.size_class < SIZE_CLASS_COUNT) {
                    @setCold(false);
                    assert(heap.full_span_count != 0); // Heap span counter corrupted
                    heap.full_span_count -= 1;
                    if (single_span != null and single_span.?.* == null) {
                        @ptrCast(*?*Span, single_span).* = maybe_span.?;
                    } else {
                        heapCacheInsert(heap, maybe_span.?, ret_addr);
                    }
                } else {
                    if (maybe_span.?.size_class == SIZE_CLASS_HUGE) {
                        deallocateHuge(maybe_span.?, ret_addr);
                    } else {
                        assert(maybe_span.?.size_class == SIZE_CLASS_LARGE); // Span size class invalid
                        assert(heap.full_span_count != 0); // Heap span counter corrupted
                        heap.full_span_count -= 1;
                        const idx: u32 = maybe_span.?.span_count - 1;
                        if (idx == 0 and single_span != null and single_span.?.* == null) {
                            single_span.?.* = maybe_span.?;
                        } else {
                            heapCacheInsert(heap, maybe_span.?, ret_addr);
                        }
                    }
                }

                maybe_span = next_span;
            }
        }

        fn heapUnmap(heap: *Heap, ret_addr: usize) void {
            const master_heap = heap.master_heap orelse {
                if (heap.finalize > 1 and @atomicLoad(u32, &heap.child_count, .Monotonic) == 0) {
                    const span: *Span = getSpanPtr(heap).?;
                    spanUnmap(span, ret_addr);
                }
                return;
            };
            if (@atomicRmw(u32, &master_heap.child_count, .Sub, 1, .Monotonic) - 1 == 0) {
                return @call(.always_tail, heapUnmap, .{ master_heap, ret_addr });
            }
        }

        inline fn heapGlobalFinalize(heap: *Heap, ret_addr: usize) void {
            if (heap.finalize > 1) return;
            heap.finalize += 1;

            heapFinalize(heap, ret_addr);

            if (enable_thread_cache) {
                const helper = struct {
                    inline fn unmapCache(span_cache: *SpanCache, _ret_addr: usize) void {
                        for (@as([*]*Span, &span_cache.span)[0..span_cache.count]) |cached_span| {
                            spanUnmap(cached_span, _ret_addr);
                        }
                        span_cache.count = 0;
                    }
                };

                helper.unmapCache(&heap.span_cache, ret_addr);
                for (heap.span_large_cache) |*span_large_cache| {
                    helper.unmapCache(@ptrCast(*SpanCache, span_large_cache), ret_addr);
                }
            }

            if (heap.full_span_count != 0) {
                heap.finalize -= 1;
                return;
            }

            for (&heap.size_class) |size_class| {
                if (size_class.free_list != null or size_class.partial_span != null) {
                    heap.finalize -= 1;
                    return;
                }
            }

            // Heap is now completely free, unmap and remove from heap list
            const list_idx: usize = @intCast(usize, heap.id) % heap_array_size;
            var list_heap: ?*Heap = all_heaps[list_idx].?;
            if (list_heap == heap) {
                all_heaps[list_idx] = heap.next_heap;
            } else {
                while (list_heap.?.next_heap != heap) {
                    list_heap = list_heap.?.next_heap;
                }
                list_heap.?.next_heap = heap.next_heap;
            }

            heapUnmap(heap, ret_addr);
        }

        /// Insert a single span into thread heap cache, releasing to global cache if overflow
        fn heapCacheInsert(heap: *Heap, span: *Span, ret_addr: usize) void {
            if (heap.finalize != 0) {
                spanUnmap(span, ret_addr);
                heapGlobalFinalize(heap, ret_addr);
                return;
            } else {
                @setCold(false);
            }
            if (enable_thread_cache) {
                const span_count: usize = span.span_count;
                if (span_count == 1) {
                    const span_cache: *SpanCache = &heap.span_cache;
                    span_cache.span[span_cache.count] = span;
                    span_cache.count += 1;

                    if (span_cache.count == MAX_THREAD_SPAN_CACHE) {
                        const remain_count: usize = MAX_THREAD_SPAN_CACHE - THREAD_SPAN_CACHE_TRANSFER;
                        if (enable_global_cache) {
                            globalCacheInsertSpans(@as([*]*Span, &span_cache.span) + remain_count, span_count, THREAD_SPAN_CACHE_TRANSFER, ret_addr);
                        } else {
                            var ispan: usize = 0;
                            while (ispan < THREAD_SPAN_CACHE_TRANSFER) : (ispan += 1) {
                                spanUnmap(span_cache.span[remain_count + ispan]);
                            }
                        }
                        span_cache.count = remain_count;
                    }
                } else {
                    const cache_idx: usize = span_count - 2;
                    const span_cache: *SpanLargeCache = &heap.span_large_cache[cache_idx];
                    span_cache.span[span_cache.count] = span;
                    span_cache.count += 1;

                    const cache_limit: usize = (MAX_THREAD_SPAN_LARGE_CACHE - (span_count >> 1));
                    if (span_cache.count == cache_limit) {
                        const transfer_limit: usize = 2 + (cache_limit >> 2);
                        const transfer_count: usize = if (THREAD_SPAN_LARGE_CACHE_TRANSFER <= transfer_limit) THREAD_SPAN_LARGE_CACHE_TRANSFER else transfer_limit;
                        const remain_count: usize = cache_limit - transfer_count;
                        if (enable_global_cache) {
                            globalCacheInsertSpans(@as([*]*Span, &span_cache.span) + remain_count, span_count, transfer_count, ret_addr);
                        } else {
                            var ispan: usize = 0;
                            while (ispan < transfer_count) : (ispan += 1) {
                                spanUnmap(span_cache.span[remain_count + ispan]);
                            }
                        }
                        span_cache.count = remain_count;
                    }
                }
            } else {
                spanUnmap(span, ret_addr);
            }
        }

        /// Extract the given number of spans from the different cache levels
        inline fn heapThreadCacheExtract(heap: *Heap, span_count: usize) ?*Span {
            if (enable_thread_cache) {
                assert(span_count != 0);
                const span_cache: *SpanCache = if (span_count == 1)
                    &heap.span_cache
                else
                    @ptrCast(*SpanCache, &heap.span_large_cache[span_count - 2]);

                if (span_cache.count != 0) {
                    span_cache.count -= 1;
                    return span_cache.span[span_cache.count];
                }
            }
            return null;
        }

        inline fn heapThreadCacheDeferredExtract(heap: *Heap, span_count: usize, ret_addr: usize) ?*Span {
            var span: ?*Span = null;
            if (span_count == 1) {
                heapCacheAdoptDeferred(heap, &span, ret_addr);
            } else {
                heapCacheAdoptDeferred(heap, null, ret_addr);
                span = heapThreadCacheExtract(heap, span_count);
            }
            return span;
        }

        inline fn heapReservedExtract(heap: *Heap, span_count: usize) ?*Span {
            if (heap.spans_reserved >= span_count) {
                return spanMapFromReserve(heap, span_count);
            }
            return null;
        }

        /// Extract a span from the global cache
        inline fn heapGlobalCacheExtract(heap: *Heap, span_count: usize) ?*Span {
            if (enable_global_cache) {
                assert(span_count != 0);
                if (enable_thread_cache) {
                    var span_cache: *SpanCache = undefined;
                    var wanted_count: usize = undefined;
                    if (span_count == 1) {
                        span_cache = &heap.span_cache;
                        wanted_count = THREAD_SPAN_CACHE_TRANSFER;
                    } else {
                        span_cache = @ptrCast(*SpanCache, &heap.span_large_cache[span_count - 2]);
                        wanted_count = THREAD_SPAN_LARGE_CACHE_TRANSFER;
                    }
                    span_cache.count = globalCacheExtractSpans(&span_cache.span, span_count, wanted_count);
                    if (span_cache.count != 0) {
                        span_cache.count -= 1;
                        return span_cache.span[span_cache.count];
                    }
                } else {
                    var span: *Span = undefined;
                    const count: usize = globalCacheExtractSpans(@ptrCast(*[1]*Span, &span), span_count, 1);
                    if (count != 0) {
                        return span;
                    }
                }
            }
            return null;
        }

        /// Get a span from one of the cache levels (thread cache, reserved, global cache) or fallback to mapping more memory
        inline fn heapExtractNewSpan(heap: *Heap, maybe_heap_size_class: ?*HeapSizeClass, span_count_init: usize, ret_addr: usize) ?*Span {
            if (enable_thread_cache) cached_blk: {
                const heap_size_class: *HeapSizeClass = maybe_heap_size_class orelse break :cached_blk;
                const span: *Span = heap_size_class.cache orelse break :cached_blk;
                heap_size_class.cache = null;
                if (heap.span_cache.count != 0) {
                    heap.span_cache.count -= 1;
                    heap_size_class.cache = heap.span_cache.span[heap.span_cache.count];
                }
                return span;
            }

            var span_count = span_count_init;

            // Allow 50% overhead to increase cache hits
            const base_span_count: usize = span_count;
            var limit_span_count: usize = if (span_count > 2) (span_count + (span_count >> 1)) else span_count;
            if (limit_span_count > LARGE_CLASS_COUNT) {
                limit_span_count = LARGE_CLASS_COUNT;
            }
            while (true) {
                if (heapThreadCacheExtract(heap, span_count)) |span| {
                    @setCold(false);
                    return span;
                }
                if (heapThreadCacheDeferredExtract(heap, span_count, ret_addr)) |span| {
                    @setCold(false);
                    return span;
                }
                if (heapReservedExtract(heap, span_count)) |span| {
                    @setCold(false);
                    return span;
                }
                if (heapGlobalCacheExtract(heap, span_count)) |span| {
                    @setCold(false);
                    return span;
                }
                span_count += 1;
                if (span_count > limit_span_count) break;
            }
            // Final fallback, map in more virtual memory
            return spanMap(heap, base_span_count, ret_addr);
        }

        inline fn heapInitialize(heap: *Heap) void {
            heap.* = comptime Heap{
                .owner_thread = if (builtin.single_threaded) undefined else 0,
                .size_class = [_]HeapSizeClass{.{ .free_list = null, .partial_span = null, .cache = null }} ** SIZE_CLASS_COUNT,
                .span_cache = if (enable_thread_cache) SpanCache{ .count = 0, .span = undefined } else .{},
                .span_free_deferred = null,
                .full_span_count = 0,
                .span_reserve = null,
                .span_reserve_master = null,
                .spans_reserved = 0,
                .child_count = 0,
                .next_heap = null,
                .next_orphan = null,
                .id = 0,
                .finalize = 0,
                .master_heap = null,
                .span_large_cache = if (enable_thread_cache) [_]SpanLargeCache{.{ .count = 0, .span = undefined }} ** (LARGE_CLASS_COUNT - 1) else .{},
            };
            // TODO: In the original code this used a function which returned the old value of heap_id_counter plus 1,
            // and then also added one, which caused the first id to ever be assigned to be '2', instead of '0' like it is here.
            // Need to investigate whether this is in any way significant.
            heap.id = @atomicRmw(u32, &heap_id_counter, .Add, 1, .Monotonic);

            //Link in heap in heap ID map
            const list_idx: usize = @intCast(usize, heap.id) % heap_array_size;
            heap.next_heap = all_heaps[list_idx];
            all_heaps[list_idx] = heap;
        }

        inline fn heapOrphan(heap: *Heap) void {
            if (!builtin.single_threaded) {
                heap.owner_thread = std.math.maxInt(usize);
            }
            const heap_list: *?*Heap = &orphan_heaps;
            heap.next_orphan = heap_list.*;
            heap_list.* = heap;
        }

        /// Allocate a new heap from newly mapped memory pages
        inline fn heapAllocateNew(ret_addr: usize) ?*Heap {
            // Map in pages for a 16 heaps. If page size is greater than required size for this, map a page and
            // use first part for heaps and remaining part for spans for allocations. Adds a lot of complexity,
            // but saves a lot of memory on systems where page size > 64 spans (4MiB)
            const aligned_heap_size: usize = 16 * ((@sizeOf(Heap) + 15) / 16);
            var request_heap_count: usize = 16;
            var heap_span_count: usize = ((aligned_heap_size * request_heap_count) + @sizeOf(Span) + span_size.* - 1) / span_size.*;

            var span_count: usize = heap_span_count;
            const span: *Span = span_init: {
                // If there are global reserved spans, use these first
                if (global_reserve_count >= heap_span_count) {
                    break :span_init globalGetReservedSpans(heap_span_count).?;
                }

                var block_size: usize = span_size.* * heap_span_count;
                if (page_size > block_size) {
                    span_count = page_size / span_size.*;
                    block_size = page_size;
                    // If using huge pages, make sure to grab enough heaps to avoid reallocating a huge page just to serve new heaps
                    const possible_heap_count: usize = (block_size - @sizeOf(Span)) / aligned_heap_size;
                    if (possible_heap_count >= (request_heap_count * 16)) {
                        request_heap_count *= 16;
                    } else if (possible_heap_count < request_heap_count) {
                        request_heap_count = possible_heap_count;
                    }
                    heap_span_count = ((aligned_heap_size * request_heap_count) + @sizeOf(Span) + span_size.* - 1) / span_size.*;
                }

                var align_offset: usize = 0;
                const span: *Span = @ptrCast(*Span, memoryMap(block_size, &align_offset, ret_addr) orelse return null);

                // Master span will contain the heaps
                spanInitialize(span, span_count, heap_span_count, align_offset);

                break :span_init span;
            };

            const remain_size: usize = span_size.* - @sizeOf(Span);
            const heap: *Heap = @ptrCast(*Heap, @ptrCast([*]Span, span) + 1);
            heapInitialize(heap);

            // Put extra heaps as orphans
            var num_heaps: usize = @max(remain_size / aligned_heap_size, request_heap_count);
            @atomicStore(u32, &heap.child_count, @intCast(u32, num_heaps - 1), .Monotonic);
            var extra_heap: *Heap = @ptrCast(*Heap, @ptrCast([*]align(@alignOf(Heap)) u8, heap) + aligned_heap_size);
            while (num_heaps > 1) {
                heapInitialize(extra_heap);
                extra_heap.master_heap = heap;
                heapOrphan(extra_heap);
                extra_heap = @ptrCast(*Heap, @ptrCast([*]align(@alignOf(Heap)) u8, extra_heap) + aligned_heap_size);
                num_heaps -= 1;
            }

            if (span_count > heap_span_count) {
                // Cap reserved spans
                const remain_count: usize = span_count - heap_span_count;
                var reserve_count: usize = if (remain_count > heap_reserve_count) heap_reserve_count else remain_count;
                var remain_span: *Span = ptrAndAlignCast(*Span, @ptrCast([*]u8, span) + (heap_span_count * span_size.*));
                heapSetReservedSpans(heap, span, remain_span, @intCast(u32, reserve_count));

                if (remain_count > reserve_count) {
                    // Set to global reserved spans
                    remain_span = ptrAndAlignCast(*Span, @ptrCast([*]u8, remain_span) + (reserve_count * span_size.*));
                    reserve_count = remain_count - reserve_count;
                    globalSetReservedSpans(span, remain_span, @intCast(u32, reserve_count));
                }
            }

            return heap;
        }

        inline fn heapExtractOrphan(heap_list: *?*Heap) ?*Heap {
            const heap: ?*Heap = heap_list.*;
            heap_list.* = if (heap != null) heap.?.next_orphan else null;
            return heap;
        }

        /// Allocate a new heap, potentially reusing a previously orphaned heap
        inline fn heapAllocate(ret_addr: usize) ?*Heap {
            acquireLock(&global_lock);
            defer releaseLock(&global_lock);
            const maybe_heap = heapExtractOrphan(&orphan_heaps) orelse heapAllocateNew(ret_addr);
            if (maybe_heap != null) heapCacheAdoptDeferred(maybe_heap.?, null, ret_addr);
            return maybe_heap;
        }

        inline fn heapRelease(heap: *Heap, release_cache: bool, ret_addr: usize) void {
            // Release thread cache spans back to global cache
            heapCacheAdoptDeferred(heap, null, ret_addr);
            if (enable_thread_cache) {
                if (release_cache or heap.finalize != 0) {
                    const helper = struct {
                        inline fn releaseSpan(p_heap: *Heap, span_cache: *SpanCache, iclass: usize, _ret_addr: usize) void {
                            if (span_cache.count == 0) return;
                            if (enable_global_cache) {
                                if (p_heap.finalize != 0) {
                                    var ispan: usize = 0;
                                    while (ispan < span_cache.count) : (ispan += 1) {
                                        spanUnmap(span_cache.span[ispan], _ret_addr);
                                    }
                                } else {
                                    globalCacheInsertSpans(&span_cache.span, iclass + 1, span_cache.count, _ret_addr);
                                }
                            } else {
                                var ispan: usize = 0;
                                while (ispan < span_cache.count) : (ispan += 1) {
                                    spanUnmap(span_cache.span[ispan], _ret_addr);
                                }
                            }
                            span_cache.count = 0;
                        }
                    };

                    helper.releaseSpan(heap, &heap.span_cache, 0, ret_addr);
                    for (heap.span_large_cache) |*span_large_cache, @"iclass-1"| {
                        helper.releaseSpan(heap, @ptrCast(*SpanCache, span_large_cache), @"iclass-1" + 1, ret_addr);
                    }
                }
            }

            if (thread_heap == heap) {
                setThreadHeap(null);
            }

            // If we are forcibly terminating with _exit the state of the
            // lock atomic is unknown and it's best to just go ahead and exit
            if (getThreadId() != main_thread_id) {
                acquireLock(&global_lock);
            }
            heapOrphan(heap);
            // TODO: the original source does this unconditionally, despite
            // the lock being acquired conditionally, but I don't understand
            // why or whether it's a good idea to do this.
            releaseLock(&global_lock);
        }

        inline fn heapFinalize(heap: *Heap, ret_addr: usize) void {
            if (heap.spans_reserved != 0) {
                const span: *Span = spanMapFromReserve(heap, heap.spans_reserved).?;
                spanUnmap(span, ret_addr);
                assert(heap.spans_reserved == 0);
            }

            heapCacheAdoptDeferred(heap, null, ret_addr);

            {
                var iclass: usize = 0;
                while (iclass < SIZE_CLASS_COUNT) : (iclass += 1) {
                    if (heap.size_class[iclass].cache != null) {
                        spanUnmap(heap.size_class[iclass].cache.?, ret_addr);
                    }
                    heap.size_class[iclass].cache = null;
                    var maybe_span: ?*Span = heap.size_class[iclass].partial_span;
                    while (maybe_span != null) {
                        const next: ?*Span = maybe_span.?.next;
                        _ = spanFinalize(heap, iclass, maybe_span.?, &heap.size_class[iclass].partial_span, ret_addr);
                        maybe_span = next;
                    }
                    // If class still has a free list it must be a full span
                    if (heap.size_class[iclass].free_list != null) {
                        const class_span: *Span = getSpanPtr(heap.size_class[iclass].free_list.?).?;

                        heap.full_span_count -= 1;
                        if (!spanFinalize(heap, iclass, class_span, null, ret_addr)) {
                            spanDoubleLinkListAdd(&heap.size_class[iclass].partial_span, class_span);
                        }
                    }
                }
            }

            if (enable_thread_cache) {
                var iclass: usize = 0;
                while (iclass < LARGE_CLASS_COUNT) : (iclass += 1) {
                    const span_cache: *SpanCache = if (iclass == 0) &heap.span_cache else @ptrCast(*SpanCache, &heap.span_large_cache[iclass - 1]);
                    var ispan: usize = 0;
                    while (ispan < span_cache.count) : (ispan += 1) {
                        spanUnmap(span_cache.span[ispan], ret_addr);
                    }
                    span_cache.count = 0;
                }
            }
            if (options.enable_asserts) {
                assert(@atomicLoad(?*Span, &heap.span_free_deferred, .Monotonic) == null); // Heaps still active during finalization
            }
        }

        // Allocation entry points

        /// Pop first block from a free list
        inline fn freeListPop(list: *?*align(SMALL_GRANULARITY) anyopaque) ?*align(SMALL_GRANULARITY) anyopaque {
            const block = list.*;
            list.* = @ptrCast(*?*align(SMALL_GRANULARITY) anyopaque, block).*;
            return block;
        }

        /// Allocate a small/medium sized memory block from the given heap
        inline fn allocateFromHeapFallback(heap: *Heap, heap_size_class: *HeapSizeClass, class_idx: u32, ret_addr: usize) ?*align(SMALL_GRANULARITY) anyopaque {
            var span = heap_size_class.partial_span;
            if (span != null) {
                @setCold(false);
                assert(span.?.block_count == global_size_classes[span.?.size_class].block_count); // Span block count corrupted
                assert(!spanIsFullyUtilized(span.?)); // Internal failure
                var block: *align(SMALL_GRANULARITY) anyopaque = undefined;
                if (span.?.free_list != null) {
                    // Span local free list is not empty, swap to size class free list
                    block = freeListPop(&span.?.free_list).?;
                    heap_size_class.free_list = span.?.free_list;
                    span.?.free_list = null;
                } else {
                    // If the span did not fully initialize free list, link up another page worth of blocks
                    const block_start = @ptrCast([*]u8, span) + (SPAN_HEADER_SIZE + (span.?.free_list_limit * span.?.block_size));
                    span.?.free_list_limit += freeListPartialInit(
                        &heap_size_class.free_list,
                        @ptrCast(*?*anyopaque, &block),
                        @intToPtr(*anyopaque, @ptrToInt(block_start) & ~(page_size - 1)),
                        block_start,
                        span.?.block_count - span.?.free_list_limit,
                        span.?.block_size,
                    );
                }
                assert(span.?.free_list_limit <= span.?.block_count); // Span block count corrupted
                span.?.used_count = span.?.free_list_limit;

                // Swap in deferred free list if present
                if (@atomicLoad(?*align(SMALL_GRANULARITY) anyopaque, &span.?.free_list_deferred, .Monotonic) != null) {
                    spanExtractFreeListDeferred(span.?);
                }

                // If span is still not fully utilized keep it in partial list and early return block
                if (!spanIsFullyUtilized(span.?)) return block;

                // The span is fully utilized, unlink from partial list and add to fully utilized list
                spanDoubleLinkListPopHead(&heap_size_class.partial_span, span.?);
                heap.full_span_count += 1;
                return block;
            }

            //Find a span in one of the cache levels
            span = heapExtractNewSpan(heap, heap_size_class, 1, ret_addr);
            if (span != null) {
                @setCold(false);
                //Mark span as owned by this heap and set base data, return first block
                return spanInitializeNew(heap, heap_size_class, span.?, class_idx);
            }

            return null;
        }

        /// Allocate a small sized memory block from the given heap
        inline fn allocateSmall(heap: *Heap, size: usize, ret_addr: usize) ?*align(SMALL_GRANULARITY) anyopaque {
            // Small sizes have unique size classes
            const class_idx: u32 = @intCast(u32, (size + (SMALL_GRANULARITY - 1)) >> SMALL_GRANULARITY_SHIFT);
            const heap_size_class: *HeapSizeClass = &heap.size_class[class_idx];
            if (heap_size_class.free_list != null) {
                @setCold(false);
                return freeListPop(&heap_size_class.free_list);
            }
            return allocateFromHeapFallback(heap, heap_size_class, class_idx, ret_addr);
        }

        /// Allocate a medium sized memory block from the given heap
        inline fn allocateMedium(heap: *Heap, size: usize, ret_addr: usize) ?*align(SMALL_GRANULARITY) anyopaque {
            // Calculate the size class index and do a dependent lookup of the final class index (in case of merged classes)
            const base_idx: u32 = @intCast(u32, SMALL_CLASS_COUNT + ((size - (SMALL_SIZE_LIMIT + 1)) >> MEDIUM_GRANULARITY_SHIFT));
            const class_idx: u32 = global_size_classes[base_idx].class_idx;
            const heap_size_class: *HeapSizeClass = &heap.size_class[class_idx];
            if (heap_size_class.free_list != null) {
                @setCold(false);
                return freeListPop(&heap_size_class.free_list);
            }
            return allocateFromHeapFallback(heap, heap_size_class, class_idx, ret_addr);
        }

        /// Allocate a large sized memory block from the given heap
        inline fn allocateLarge(heap: *Heap, size_init: usize, ret_addr: usize) ?*align(SMALL_GRANULARITY) anyopaque {
            var size = size_init;

            // Calculate number of needed max sized spans (including header)
            // Since this function is never called if size > calculateLargeSizeLimit(span_size.*)
            // the span_count is guaranteed to be <= LARGE_CLASS_COUNT
            size += SPAN_HEADER_SIZE;
            var span_count: usize = size >> span_size_shift.*;
            if (size & (span_size.* - 1) != 0) {
                span_count += 1;
            }

            // Find a span in one of the cache levels
            const span: *Span = heapExtractNewSpan(heap, null, span_count, ret_addr) orelse return null;

            // Mark span as owned by this heap and set base data
            assert(span.span_count >= span_count); // Internal failure
            span.size_class = SIZE_CLASS_LARGE;
            span.heap = heap;
            heap.full_span_count += 1;

            return @ptrCast([*]align(SMALL_GRANULARITY) u8, span) + SPAN_HEADER_SIZE;
        }

        /// Allocate a huge block by mapping memory pages directly
        inline fn allocateHuge(heap: *Heap, size_init: usize, ret_addr: usize) ?*align(SMALL_GRANULARITY) anyopaque {
            var size = size_init;

            heapCacheAdoptDeferred(heap, null, ret_addr);
            size += SPAN_HEADER_SIZE;
            var num_pages: usize = size >> page_size_shift;
            if (size & (page_size - 1) != 0) {
                num_pages += 1;
            }
            var align_offset: usize = 0;
            const span: *Span = @ptrCast(*Span, memoryMap(num_pages * page_size, &align_offset, ret_addr) orelse return null);

            // Store page count in span_count
            span.size_class = SIZE_CLASS_HUGE;
            span.span_count = @intCast(u32, num_pages);
            span.align_offset = @intCast(u32, align_offset);
            span.heap = heap;
            heap.full_span_count += 1;

            return @ptrCast([*]align(SMALL_GRANULARITY) u8, span) + SPAN_HEADER_SIZE;
        }

        /// Allocate a block of the given size
        inline fn allocate(heap: *Heap, size: usize, ret_addr: usize) ?*align(SMALL_GRANULARITY) anyopaque {
            if (size <= SMALL_SIZE_LIMIT) {
                @setCold(false);
                return allocateSmall(heap, size, ret_addr);
            }
            if (size <= medium_size_limit_runtime.*) return allocateMedium(heap, size, ret_addr);
            if (size <= calculateLargeSizeLimit(span_size.*)) return allocateLarge(heap, size, ret_addr);
            return allocateHuge(heap, size, ret_addr);
        }

        inline fn alignedAllocate(heap: *Heap, alignment: usize, size: usize, ret_addr: usize) ?*align(SMALL_GRANULARITY) anyopaque {
            if (alignment <= SMALL_GRANULARITY) {
                // if (size >= maxAllocSize()) return null;
                assert(size < maxAllocSize());
                return allocate(heap, size, ret_addr);
            }

            if ((alignment <= SPAN_HEADER_SIZE) and (size < medium_size_limit_runtime.*)) {
                // If alignment is less or equal to span header size (which is power of two),
                // and size aligned to span header size multiples is less than size + alignment,
                // then use natural alignment of blocks to provide alignment
                const multiple_size: usize = if (size != 0) (size + (SPAN_HEADER_SIZE - 1)) & ~@as(usize, SPAN_HEADER_SIZE - 1) else SPAN_HEADER_SIZE;
                if (options.enable_asserts) {
                    assert(multiple_size % SPAN_HEADER_SIZE == 0); // Failed alignment calculation
                }
                if (multiple_size <= (size + alignment)) {
                    return allocate(heap, multiple_size, ret_addr);
                }
            }

            const align_mask: usize = alignment - 1;
            assert(alignment <= page_size); // this is imposed by the stdlib, so may as well take advantage here.
            if (true or alignment <= page_size) {
                var ptr = allocate(heap, size + alignment, ret_addr);
                if (@ptrToInt(ptr) & align_mask != 0) {
                    ptr = @intToPtr(*align(SMALL_GRANULARITY) anyopaque, (@ptrToInt(ptr) & ~@as(usize, align_mask)) + alignment);
                    // Mark as having aligned blocks
                    const span: *Span = getSpanPtr(ptr.?).?;
                    span.flags.aligned_blocks = true;
                }
                return ptr;
            }

            // Fallback to mapping new pages for this request. Since pointers passed
            // to rpfree must be able to reach the start of the span by bitmasking of
            // the address with the span size, the returned aligned pointer from this
            // function must be with a span size of the start of the mapped area.
            // In worst case this requires us to loop and map pages until we get a
            // suitable memory address. It also means we can never align to span size
            // or greater, since the span header will push alignment more than one
            // span size away from span start (thus causing pointer mask to give us
            // an invalid span start on free)
            if (options.enable_asserts) {
                assert(alignment & align_mask == 0);
                assert(alignment < span_size.*);
            }

            const extra_pages: usize = alignment / page_size;

            // Since each span has a header, we will at least need one extra memory page
            var num_pages: usize = 1 + (size / page_size) +
                @boolToInt(size & (page_size - 1) != 0);
            if (num_pages < extra_pages) {
                num_pages = 1 + extra_pages;
            }

            const original_pages: usize = num_pages;
            // var limit_pages: usize = (span_size.* / page_size) * 2;
            // if (limit_pages < (original_pages * 2)) {
            //     limit_pages = original_pages * 2;
            // }
            const limit_pages: usize = 2 * @max(span_size.* / page_size, original_pages);

            var ptr: *align(SMALL_GRANULARITY) anyopaque = undefined;
            var mapped_size: usize = undefined;
            var align_offset: usize = undefined;
            var span: *Span = undefined;

            retry: while (true) {
                align_offset = 0;
                mapped_size = num_pages * page_size;

                span = @ptrCast(*Span, memoryMap(mapped_size, &align_offset) orelse return null);
                ptr = @ptrCast([*]align(SMALL_GRANULARITY) u8, span) + SPAN_HEADER_SIZE;

                if (@ptrToInt(ptr) & align_mask != 0) {
                    ptr = @intToPtr(*align(SMALL_GRANULARITY) anyopaque, (@ptrToInt(ptr) & ~@as(usize, align_mask)) + alignment);
                }

                if ((@ptrToInt(ptr) - @ptrToInt(span)) >= span_size.* or
                    (@ptrToInt(ptr) + size) > (@ptrToInt(span) + mapped_size) or
                    ((@ptrToInt(ptr) & span_mask.*) != @ptrToInt(span)))
                {
                    memoryUnmap(span, align_offset, mapped_size);
                    num_pages += 1;
                    if (num_pages > limit_pages) return null;
                    continue :retry;
                }

                break;
            }

            // Store page count in span_count
            span.size_class = SIZE_CLASS_HUGE;
            span.span_count = @intCast(u32, num_pages);
            span.align_offset = @intCast(u32, align_offset);
            span.heap = heap;
            heap.full_span_count += 1;

            return ptr;
        }

        // Deallocation entry points

        /// Deallocate the given small/medium memory block in the current thread local heap
        inline fn deallocateDirectSmallOrMedium(span: *Span, block: *align(SMALL_GRANULARITY) anyopaque, ret_addr: usize) void {
            const heap: *Heap = span.heap;
            if (!builtin.single_threaded and options.enable_asserts) {
                assert(heap.finalize != 0 or heap.owner_thread == 0 or heap.owner_thread == getThreadId()); // Internal failure
            }
            // Add block to free list
            if (spanIsFullyUtilized(span)) {
                span.used_count = span.block_count;
                spanDoubleLinkListAdd(&heap.size_class[span.size_class].partial_span, span);
                heap.full_span_count -= 1;
            } else {
                @setCold(false);
            }
            @ptrCast(*?*anyopaque, block).* = span.free_list;
            span.used_count -= 1;
            span.free_list = block;
            if (span.used_count == span.list_size) {
                spanDoubleLinkListRemove(&heap.size_class[span.size_class].partial_span, span);
                spanReleaseToCache(heap, span, ret_addr);
            } else {
                @setCold(false);
            }
        }

        inline fn deallocateDeferFreeSpan(heap: *Heap, span: *Span) void {
            // This list does not need ABA protection, no mutable side state
            while (true) {
                span.free_list = @ptrCast(?*anyopaque, @atomicLoad(?*Span, &heap.span_free_deferred, .Monotonic));
                if (atomicCasPtr(&heap.span_free_deferred, span, @ptrCast(?*Span, span.free_list))) break;
            }
        }

        /// Put the block in the deferred free list of the owning span
        inline fn deallocateDeferSmallOrMedium(span: *Span, block: *align(SMALL_GRANULARITY) anyopaque) void {
            const free_list = blk: {
                // TODO: is this OK? According to Protty `@atomicRmw` is already a loop like the one below
                if (true) break :blk atomicExchangePtrAcquire(&span.free_list_deferred, INVALID_POINTER);

                // The memory ordering here is a bit tricky, to avoid having to ABA protect
                // the deferred free list to avoid desynchronization of list and list size
                // we need to have acquire semantics on successful CAS of the pointer to
                // guarantee the list_size variable validity + release semantics on pointer store
                var free_list: ?*anyopaque = undefined;
                while (true) {
                    free_list = atomicExchangePtrAcquire(&span.free_list_deferred, INVALID_POINTER);
                    if (free_list != INVALID_POINTER) break;
                }
            };
            @ptrCast(*?*anyopaque, block).* = free_list;

            span.list_size += 1;
            const free_count: u32 = span.list_size;

            const all_deferred_free = free_count == span.block_count;
            atomicStorePtrRelease(&span.free_list_deferred, block);
            if (all_deferred_free) {
                // Span was completely freed by this block. Due to the INVALID_POINTER spin lock
                // no other thread can reach this state simultaneously on this span.
                // Safe to move to owner heap deferred cache
                deallocateDeferFreeSpan(span.heap, span);
            }
        }

        inline fn deallocateSmallOrMedium(span: *Span, p_init: *align(SMALL_GRANULARITY) anyopaque, ret_addr: usize) void {
            var p = p_init;
            if (span.flags.aligned_blocks) {
                // Realign pointer to block start
                const blocks_start: *align(SMALL_GRANULARITY) anyopaque = @ptrCast([*]align(SMALL_GRANULARITY) u8, span) + SPAN_HEADER_SIZE;
                const block_offset = @ptrToInt(p) - @ptrToInt(blocks_start);
                const offset_mod_size = @intCast(u32, block_offset % span.block_size);
                assert(offset_mod_size == 0); // TODO: this seems to be empirically true
                p = ptrAndAlignCast(*align(SMALL_GRANULARITY) anyopaque, @ptrCast([*]u8, p) - offset_mod_size);
            }

            // Check if block belongs to this heap or if deallocation should be deferred
            const defer_dealloc: bool = span.heap.finalize == 0 and (if (builtin.single_threaded) false else span.heap.owner_thread != getThreadId());
            if (!defer_dealloc) {
                deallocateDirectSmallOrMedium(span, p, ret_addr);
            } else {
                deallocateDeferSmallOrMedium(span, p);
            }
        }

        /// Deallocate the given large memory block to the current heap
        inline fn deallocateLarge(span: *Span, ret_addr: usize) void {
            @setCold(true);
            assert(span.size_class == SIZE_CLASS_LARGE); // Bad span size class
            assert(!span.flags.master or !span.flags.subspan); // Span flag corrupted
            assert(span.flags.master or span.flags.subspan); // Span flag corrupted
            //We must always defer (unless finalizing) if from another heap since we cannot touch the list or counters of another heap
            const defer_dealloc: bool = span.heap.finalize == 0 and (if (builtin.single_threaded) false else span.heap.owner_thread != getThreadId());

            if (defer_dealloc) {
                deallocateDeferFreeSpan(span.heap, span);
                return;
            }
            assert(span.heap.full_span_count != 0); // Heap span counter corrupted
            span.heap.full_span_count -= 1;

            const heap: *Heap = span.heap;

            const set_as_reserved = if (enable_thread_cache)
                ((span.span_count > 1) and (heap.span_cache.count == 0) and heap.finalize == 0 and heap.spans_reserved == 0)
            else
                ((span.span_count > 1) and heap.finalize == 0 and heap.spans_reserved == 0);

            if (set_as_reserved) {
                heap.span_reserve = span;
                heap.spans_reserved = span.span_count;
                if (span.flags.master) {
                    heap.span_reserve_master = span;
                } else { //SPAN_FLAG_SUBSPAN
                    const master = ptrAndAlignCast(*Span, @ptrCast([*]u8, span) - (span.offset_from_master * span_size.*));
                    heap.span_reserve_master = master;
                    if (options.enable_asserts) {
                        assert(master.flags.master); // Span flag corrupted
                        assert(@atomicLoad(u32, &master.remaining_spans, .Monotonic) >= span.span_count); // Master span count corrupted
                    }
                }
            } else {
                // Insert into cache list
                heapCacheInsert(heap, span, ret_addr);
            }
        }

        /// Deallocate the given huge span
        inline fn deallocateHuge(span: *Span, ret_addr: usize) void {
            @setCold(true);
            const defer_dealloc: bool = span.heap.finalize == 0 and (if (builtin.single_threaded) false else span.heap.owner_thread != getThreadId());
            if (defer_dealloc) {
                deallocateDeferFreeSpan(span.heap, span);
                return;
            }
            assert(span.heap.full_span_count != 0); // Heap span counter corrupted
            span.heap.full_span_count -= 1;

            // Oversized allocation, page count is stored in span_count
            const num_pages: usize = span.span_count;
            memoryUnmap(span, span.align_offset, num_pages * page_size, ret_addr);
        }

        /// Deallocate the given block
        inline fn deallocate(p_unaligned: *anyopaque, ret_addr: usize) void {
            const p = @alignCast(SMALL_GRANULARITY, p_unaligned);
            // Grab the span (always at start of span, using span alignment)
            const span: *Span = getSpanPtr(p).?;
            if (span.size_class < SIZE_CLASS_COUNT) {
                @setCold(false);
                deallocateSmallOrMedium(span, p, ret_addr);
            } else if (span.size_class == SIZE_CLASS_LARGE) {
                deallocateLarge(span, ret_addr);
            } else {
                deallocateHuge(span, ret_addr);
            }
        }

        // Initialization, finalization and utility

        /// Get the usable size of the given block
        inline fn usableSize(p: *anyopaque) usize {
            // Grab the span using guaranteed span alignment
            const span: *Span = getSpanPtr(p).?;
            if (span.size_class < SIZE_CLASS_COUNT) {
                // Small/medium block
                const blocks_start: *anyopaque = @ptrCast([*]align(@alignOf(Span)) u8, span) + SPAN_HEADER_SIZE;
                return span.block_size - ((@ptrToInt(p) - @ptrToInt(blocks_start)) % span.block_size);
            }
            if (span.size_class == SIZE_CLASS_LARGE) {
                // Large block
                const current_spans: usize = span.span_count;
                return (current_spans * span_size.*) - (@ptrToInt(p) - @ptrToInt(span));
            }
            // Oversized block, page count is stored in span_count
            const current_pages: usize = span.span_count;
            return (current_pages * page_size) - (@ptrToInt(p) - @ptrToInt(span));
        }

        /// Adjust and optimize the size class properties for the given class
        inline fn adjustSizeClass(
            iclass: usize,
            comptime size_classes: *[SIZE_CLASS_COUNT]SizeClass,
            comptime input_span_size: *const @TypeOf(span_size.*),
        ) void {
            comptime assert(input_span_size == span_size);

            const block_size: usize = size_classes[iclass].block_size;
            const block_count: usize = (input_span_size.* - SPAN_HEADER_SIZE) / block_size;

            size_classes[iclass].block_count = @intCast(u16, block_count);
            size_classes[iclass].class_idx = @intCast(u16, iclass);

            //Check if previous size classes can be merged
            if (iclass >= SMALL_CLASS_COUNT) {
                var prevclass: usize = iclass;
                while (prevclass > 0) {
                    prevclass -= 1;
                    //A class can be merged if number of pages and number of blocks are equal
                    if (size_classes[prevclass].block_count == size_classes[iclass].block_count) {
                        size_classes[prevclass] = size_classes[iclass];
                    } else {
                        break;
                    }
                }
            }
        }
        /// Initializes the small size classes of the given array.
        inline fn globalSmallSizeClassesInit(
            comptime p_size_classes: *[SIZE_CLASS_COUNT]SizeClass,
            comptime input_span_size: *const @TypeOf(span_size.*),
        ) void {
            comptime assert(input_span_size == span_size);
            p_size_classes[0].block_size = SMALL_GRANULARITY;
            adjustSizeClass(0, p_size_classes, input_span_size);
            var iclass: usize = 1;
            while (iclass < SMALL_CLASS_COUNT) : (iclass += 1) {
                const size: usize = iclass * SMALL_GRANULARITY;
                p_size_classes[iclass].block_size = @intCast(u32, size);
                adjustSizeClass(iclass, p_size_classes, input_span_size);
            }
        }

        /// Initialize thread, assign heap
        inline fn threadInitialize(ret_addr: usize) error{OutOfMemory}!void {
            const heap = heapAllocate(ret_addr) orelse return error.OutOfMemory;
            setThreadHeap(heap);
            if (is_windows_and_not_dynamic) {
                FlsSetValue(fls_key, heap);
            }
        }

        /// Finalize thread, orphan heap
        inline fn threadFinalize(release_caches: bool, ret_addr: usize) void {
            if (thread_heap != null) {
                heapRelease(thread_heap.?, release_caches, ret_addr);
                setThreadHeap(null);
            }
            if (is_windows_and_not_dynamic) {
                FlsSetValue(fls_key, 0);
            }
        }

        inline fn isThreadInitialized() bool {
            return thread_heap != null;
        }

        pub const InitConfig = struct {
            /// Size of a span of memory blocks. MUST be a power of two, and in [4096,262144]
            /// range (unless 0 - set to 0 to use the default span size). Used if RPMALLOC_CONFIGURABLE
            /// is defined to 1.
            span_size: if (configurable_sizes) SpanSize else enum { default } = .default,
            /// Number of spans to map at each request to map new virtual memory blocks. This can
            /// be used to minimize the system call overhead at the cost of virtual memory address
            /// space. The extra mapped pages will not be written until actually used, so physical
            /// committed memory should not be affected in the default implementation. Will be
            /// aligned to a multiple of spans that match memory page size in case of huge pages.
            span_map_count: usize = 0,

            pub const SpanSize = enum(usize) {
                default = 0,
                pow12 = 1 << 12,
                pow13 = 1 << 13,
                pow14 = 1 << 14,
                pow15 = 1 << 15,
                pow16 = 1 << 16,
                pow17 = 1 << 17,
                pow18 = 1 << 18,
            };
        };
    };
}

const FlsAlloc = @compileError("windows stub");
const FlsFree = @compileError("windows stub");
const FlsSetValue = @compileError("windows stub");

inline fn atomicStorePtrRelease(dst: anytype, val: @TypeOf(dst.*)) void {
    @atomicStore(@TypeOf(dst.*), dst, val, .Release);
}
inline fn atomicExchangePtrAcquire(dst: anytype, val: @TypeOf(dst.*)) @TypeOf(dst.*) {
    return @atomicRmw(@TypeOf(dst.*), dst, .Xchg, val, .Acquire);
}
inline fn atomicCasPtr(dst: anytype, val: @TypeOf(dst.*), ref: @TypeOf(dst.*)) bool {
    return @cmpxchgWeak(@TypeOf(dst.*), dst, ref, val, .Monotonic, .Monotonic) == null;
}

inline fn acquireLock(lock: *u32) void {
    while (@cmpxchgWeak(u32, lock, 0, 1, .Acquire, .Monotonic) != null) {
        std.atomic.spinLoopHint();
    }
}
inline fn releaseLock(lock: *u32) void {
    @atomicStore(u32, lock, 0, .Release);
}

const INVALID_POINTER = @intToPtr(*align(SMALL_GRANULARITY) anyopaque, std.mem.alignBackward(std.math.maxInt(usize), SMALL_GRANULARITY));
const SIZE_CLASS_LARGE = SIZE_CLASS_COUNT;
const SIZE_CLASS_HUGE = std.math.maxInt(u32);

// Preconfigured limits and sizes

/// Granularity of a small allocation block (must be power of two)
const SMALL_GRANULARITY = 16;
/// Small granularity shift count
const SMALL_GRANULARITY_SHIFT = 4;
/// Number of small block size classes
const SMALL_CLASS_COUNT = 65;
/// Maximum size of a small block
const SMALL_SIZE_LIMIT = (SMALL_GRANULARITY * (SMALL_CLASS_COUNT - 1));
/// Granularity of a medium allocation block
const MEDIUM_GRANULARITY = 512;
/// Medium granularity shift count
const MEDIUM_GRANULARITY_SHIFT = 9;
/// Number of medium block size classes
const MEDIUM_CLASS_COUNT = 61;
/// Total number of small + medium size classes
const SIZE_CLASS_COUNT = (SMALL_CLASS_COUNT + MEDIUM_CLASS_COUNT);
/// Number of large block size classes
const LARGE_CLASS_COUNT = 63;
/// Maximum size of a medium block
const MEDIUM_SIZE_LIMIT = (SMALL_SIZE_LIMIT + (MEDIUM_GRANULARITY * MEDIUM_CLASS_COUNT));
inline fn calculateMediumSizeLimitRuntime(input_span_size: anytype) @TypeOf(input_span_size) {
    return @min(MEDIUM_SIZE_LIMIT, (input_span_size - SPAN_HEADER_SIZE) >> 1);
}
/// Maximum size of a large block
inline fn calculateLargeSizeLimit(span_size: anytype) @TypeOf(span_size) {
    return ((LARGE_CLASS_COUNT * span_size) - SPAN_HEADER_SIZE);
}
/// Size of a span header (must be a multiple of SMALL_GRANULARITY and a power of two)
const SPAN_HEADER_SIZE = 128;
/// Number of spans in thread cache
const MAX_THREAD_SPAN_CACHE = 400;
/// Number of spans to transfer between thread and global cache
const THREAD_SPAN_CACHE_TRANSFER = 64;
/// Number of spans in thread cache for large spans (must be greater than LARGE_CLASS_COUNT / 2)
const MAX_THREAD_SPAN_LARGE_CACHE = 100;
/// Number of spans to transfer between thread and global cache for large spans
const THREAD_SPAN_LARGE_CACHE_TRANSFER = 6;

comptime {
    if ((SMALL_GRANULARITY & (SMALL_GRANULARITY - 1)) != 0) @compileError("Small granularity must be power of two");
    if ((SPAN_HEADER_SIZE & (SPAN_HEADER_SIZE - 1)) != 0) @compileError("Span header size must be power of two");
    assert(SPAN_HEADER_SIZE % SMALL_GRANULARITY == 0);
}

const SpanFlags = packed struct(u32) {
    const BackingInt = @typeInfo(SpanFlags).Struct.backing_integer.?;
    /// Flag indicating span is the first (master) span of a split superspan
    master: bool = false,
    /// Flag indicating span is a secondary (sub) span of a split superspan
    subspan: bool = false,
    /// Flag indicating span has blocks with increased alignment
    aligned_blocks: bool = false,
    /// Flag indicating an unmapped master span
    unmapped_master: bool = false,

    _pad: enum(u28) { unset } = .unset,
};

inline fn ptrAndAlignCast(comptime T: type, ptr: anytype) T {
    const alignment = comptime switch (@typeInfo(T)) {
        .Pointer => |pointer| pointer.alignment,
        .Optional => |optional| @typeInfo(optional.child).Pointer.alignment,
        else => unreachable,
    };
    return @ptrCast(T, @alignCast(alignment, ptr));
}
