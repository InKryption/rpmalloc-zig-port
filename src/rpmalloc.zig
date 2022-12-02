const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub const RPMallocOptions = struct {
    /// Enable configuring sizes at runtime. Will introduce a very small
    /// overhead due to some size calculations not being compile time constants
    configurable_sizes: bool = false,
    /// Size of heap hashmap
    heap_array_size: usize = 47,
    /// Enable per-thread cache
    enable_thread_cache: bool = true,
    /// Enable global cache shared between all threads, requires thread cache
    enable_global_cache: bool = true,
    /// Enable asserts
    enable_asserts: bool = false,
    /// Disable unmapping memory pages (also enables unlimited cache)
    disable_unmap: bool = false,
    /// Enable unlimited global cache (no unmapping until finalization)
    enable_unlimited_cache: bool = false,
    /// Default number of spans to map in call to map more virtual memory (default values yield 4MiB here)
    default_span_map_count: usize = 64,
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
        pub fn allocator() Allocator {
            return Allocator{
                .ptr = undefined,
                .vtable = &Allocator.VTable{
                    .alloc = alloc,
                    .resize = resize,
                    .free = free,
                },
            };
        }

        /// Initialize the allocator and setup global data.
        pub fn init(config: InitConfig) error{}!void {
            // TODO: Should we instead just expose `threadInitialize` as a separate function?
            if (initialized and getThreadId() != main_thread_id) {
                return threadInitialize();
            } else @setCold(true);
            assert(!initialized);
            defer threadInitialize(); // initialise this thread after everything else is set up.

            initialized = true;
            mapFailCallback = config.mapFailCallback;

            if (config.backing_allocator) |ally| {
                dangerousCastAwayConst(backing_allocator).* = ally;
            } else if (!known_allocator) {
                @panic("Must specify backing allocator with runtime allocator");
            }

            const min_span_size: usize = 256;
            const max_page_size: usize = if (std.math.maxInt(uptr_t) > 0xFFFF_FFFF)
                (4096 * 1024 * 1024)
            else
                (4 * 1024 * 1024);
            // _memory_page_size = std.math.clamp(_memory_page_size, min_span_size, max_page_size);
            comptime assert(page_size >= min_span_size and page_size <= max_page_size);

            if (config.span_size != .default) {
                // this is safe because this field is only ever not equal to `.default` if
                // sizes are configurable, meaning these pointers are to mutable memory.
                comptime assert(configurable_sizes);
                dangerousCastAwayConst(span_size).* = @enumToInt(config.span_size);
                dangerousCastAwayConst(span_size_shift).* = std.math.log2_int(usize, span_size.*);
                dangerousCastAwayConst(span_mask).* = calculateSpanMask(span_size.*);
            }

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
            var iclass: usize = 0;
            global_size_classes[iclass].block_size = SMALL_GRANULARITY;
            adjustSizeClass(iclass);
            iclass = 1;
            while (iclass < SMALL_CLASS_COUNT) : (iclass += 1) {
                const size: usize = iclass * SMALL_GRANULARITY;
                global_size_classes[iclass].block_size = @intCast(u32, size);
                adjustSizeClass(iclass);
            }

            // At least two blocks per span, then fall back to large allocations
            medium_size_limit = @min(MEDIUM_SIZE_LIMIT, (span_size.* - SPAN_HEADER_SIZE) >> 1);
            iclass = 0;
            while (iclass < MEDIUM_CLASS_COUNT) : (iclass += 1) {
                const size: usize = SMALL_SIZE_LIMIT + ((iclass + 1) * MEDIUM_GRANULARITY);
                if (size > medium_size_limit) break;
                global_size_classes[SMALL_CLASS_COUNT + iclass].block_size = @intCast(u32, size);
                adjustSizeClass(SMALL_CLASS_COUNT + iclass);
            }

            orphan_heaps = null;
            all_heaps = .{null} ** all_heaps.len;
            releaseLock(&global_lock);
        }

        /// Finalize the allocator
        pub fn deinit() void {
            assert(initialized);
            threadFinalize(true);

            if (global_reserve != null) {
                _ = atomicAdd32(&global_reserve_master.?.remaining_spans, -@intCast(i32, global_reserve_count));
                global_reserve_master = null;
                global_reserve_count = 0;
                global_reserve = null;
            }
            releaseLock(&global_lock);

            { // Free all thread caches and fully free spans
                var list_idx: usize = 0;
                while (list_idx < heap_array_size) : (list_idx += 1) {
                    var maybe_heap: ?*Heap = all_heaps[list_idx];
                    while (maybe_heap) |heap| {
                        const next_heap: ?*Heap = heap.next_heap;
                        heap.finalize = 1;
                        heapGlobalFinalize(heap);
                        maybe_heap = next_heap;
                    }
                }
            }

            if (enable_global_cache) {
                // Free global caches
                var iclass: usize = 0;
                while (iclass < LARGE_CLASS_COUNT) : (iclass += 1) {
                    globalCacheFinalize(&global_span_cache[iclass]);
                }
            }

            // TODO: evaluate if this is worth doing
            if (is_windows_and_not_dynamic) {
                FlsFree(fls_key);
                fls_key = 0;
            }

            initialized = false;
        }

        fn alloc(state_ptr: *anyopaque, len: usize, ptr_align: u8, ret_addr: usize) ?[*]u8 {
            _ = state_ptr;
            _ = ret_addr;

            const heap: *Heap = getThreadHeap();
            const result_ptr = alignedAllocate(heap, std.math.shl(usize, 1, ptr_align), len) orelse return null;

            const usable_size = usableSize(result_ptr);
            assert(len <= usable_size);
            const result: []u8 = @ptrCast([*]u8, result_ptr)[0..len];
            @memset(result.ptr, undefined, result.len);
            return result.ptr;
        }
        fn resize(state_ptr: *anyopaque, buf: []u8, buf_align: u8, new_len: usize, ret_addr: usize) bool {
            _ = state_ptr;
            _ = ret_addr;

            const usable_size = usableSize(buf.ptr);
            assert(buf.len <= usable_size);
            assert(std.mem.isAligned(@ptrToInt(buf.ptr), std.math.shl(usize, 1, buf_align)));

            return usable_size >= new_len;
        }
        fn free(state_ptr: *anyopaque, buf: []u8, buf_align: u8, ret_addr: usize) void {
            _ = state_ptr;
            _ = buf_align;
            _ = ret_addr;
            deallocate(buf.ptr);
        }

        var fls_key: std.os.windows.DWORD = if (is_windows_and_not_dynamic) 0 else @compileError("can't reference");

        inline fn rpAssert(truth: bool, comptime message: []const u8) void {
            if (options.enable_asserts and !truth) @panic(message);
            assert(truth);
        }

        /// Maximum allocation size to avoid integer overflow
        inline fn maxAllocSize() @TypeOf(span_size.*) {
            return std.math.maxInt(usize) - span_size.*;
        }

        inline fn pointerOffset(ptr: ?*anyopaque, ofs: anytype) ?*anyopaque {
            const byte_ptr: [*]allowzero u8 = @ptrCast(?[*]u8, ptr);
            return if (ofs < 0)
                byte_ptr - std.math.absCast(ofs)
            else
                byte_ptr + std.math.absCast(ofs);
        }
        inline fn pointerDiff(first: anytype, second: anytype) iptr_t {
            const first_int = @ptrToInt(first);
            const second_int = @ptrToInt(second);
            return @bitCast(iptr_t, first_int -% second_int);
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
            free_list: ?*align(@alignOf(*anyopaque)) anyopaque,
            /// Total block count of size class
            block_count: u32,
            /// Size class
            size_class: u32,
            /// Index of last block initialized in free list
            free_list_limit: u32,
            /// Number of used blocks remaining when in partial state
            used_count: u32,
            /// Deferred free list
            free_list_deferred: ?*align(@alignOf(*anyopaque)) anyopaque, // atomic
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
            remaining_spans: i32, // atomic
            /// Alignment offset
            align_offset: u32,
            /// Owning heap
            heap: ?*Heap,
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
            free_list: ?*align(@alignOf(*anyopaque)) anyopaque,
            /// Double linked list of partially used spans with free blocks.
            /// Previous span pointer in head points to tail span of list.
            partial_span: ?*Span,
            /// Early level cache of fully free spans
            cache: ?*Span,
        };

        /// Control structure for a heap, either a thread heap or a first class heap if enabled
        const Heap = extern struct {
            /// Owning thread ID
            owner_thread: std.Thread.Id,
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
            child_count: i32, // atomic
            /// Next heap in id list
            next_heap: ?*Heap,
            /// Next heap in orphan list
            next_orphan: ?*Heap,
            /// Heap ID
            id: i32,
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
            lock: i32, // atomic
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
        inline fn calculateSpanMask(input_span_size: anytype) uptr_t {
            comptime if (@TypeOf(input_span_size) == comptime_int) {
                return calculateSpanMask(@as(std.math.IntFittingRange(0, input_span_size), input_span_size));
            };
            assert(@popCount(input_span_size) == 1);
            return ~@as(uptr_t, input_span_size - 1);
        }

        // Global data

        /// Pointer to backing allocator. If one is specified at comptime,
        /// this is a pointer to a comptime-known read-only interface.
        /// Otherwise, this is actually a mutable pointer.
        const backing_allocator: *const Allocator = options.backing_allocator orelse &struct {
            var val: Allocator = undefined;
        }.val;

        var initialized: bool = false;
        var main_thread_id: std.Thread.Id = 0;
        var mapFailCallback: *const fn (size: usize) bool = undefined;
        const page_size: usize = std.mem.page_size;
        /// Shift to divide by page size
        const page_size_shift: std.math.Log2Int(usize) = std.math.log2_int(usize, page_size);
        /// Granularity at which memory pages are mapped by OS
        const map_granularity: usize = page_size;

        /// Size of a span of memory pages
        const span_size: *const usize = if (!configurable_sizes) &@as(usize, default_span_size) else &struct {
            var val: usize = default_span_size;
        }.val;
        /// Shift to divide by span size
        const span_size_shift: *const usize = if (!configurable_sizes) &@as(usize, default_span_size_shift) else &struct {
            var val: usize = default_span_size_shift;
        }.val;
        /// Mask to get to start of a memory span
        const span_mask: *const uptr_t = if (!configurable_sizes) &calculateSpanMask(span_size.*) else &struct {
            var val: uptr_t = calculateSpanMask(default_span_size);
        }.val;

        /// Number of spans to map in each map call
        var span_map_count: usize = 0;
        /// Number of spans to keep reserved in each heap
        var heap_reserve_count: usize = 0;
        var global_size_classes: [SIZE_CLASS_COUNT]SizeClass = std.mem.zeroes([SIZE_CLASS_COUNT]SizeClass);
        /// Run-time size limit of medium blocks
        var medium_size_limit: usize = 0;
        var heap_id_counter: i32 = 0; // atomic

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
        var global_lock: atomic32_t = 0; // atomic
        /// Orphaned heaps
        var orphan_heaps: ?*Heap = null;

        /// Thread local heap and ID
        threadlocal var thread_heap: ?*Heap = null;

        inline fn getThreadHeapRaw() ?*Heap {
            return thread_heap;
        }

        /// Get the current thread heap
        inline fn getThreadHeap() *Heap {
            return getThreadHeapRaw().?;
        }

        /// Fast thread ID
        inline fn getThreadId() if (builtin.single_threaded) u0 else std.Thread.Id {
            if (builtin.single_threaded) return 0;
            return std.Thread.getCurrentId();
        }

        /// Set the current thread heap
        inline fn setThreadHeap(heap: ?*Heap) void {
            thread_heap = heap;
            if (heap) |h| {
                h.owner_thread = getThreadId();
            }
        }

        // Low level memory map/unmap

        /// Map more virtual memory
        /// size is number of bytes to map
        /// offset receives the offset in bytes from start of mapped region
        /// returns address to start of mapped region to use
        fn memoryMap(size: usize, offset: *usize) ?*anyopaque {
            assert(size != 0); // invalid mmap size
            assert(size % page_size == 0); // invalid mmap size
            // Either size is a heap (a single page) or a (multiple) span - we only need to align spans, and only if larger than map granularity
            const padding: usize = if (size >= span_size.* and span_size.* > map_granularity) span_size.* else 0;
            var ptr: ?*anyopaque = while (true) {
                const ptr = backing_allocator.rawAlloc(size + padding, page_size_shift, @returnAddress()) orelse {
                    // TODO: Should this be done, or should this just fail immediately?
                    if (mapFailCallback(size)) continue;
                    return null;
                };
                break ptr;
            };
            if (padding != 0) {
                const final_padding: usize = padding - (@ptrToInt(ptr) & ~span_mask.*);
                assert(final_padding <= span_size.*);
                assert(final_padding <= padding);
                assert(final_padding % 8 == 0);
                ptr = pointerOffset(ptr, final_padding);
                offset.* = final_padding >> 3;
            }
            assert(size < span_size.* or (@ptrToInt(ptr) & ~span_mask.*) == 0);
            return ptr;
        }

        /// Unmap virtual memory
        /// address is the memory address to unmap, as returned from _memory_map
        /// size is the number of bytes to unmap, which might be less than full region for a partial unmap
        /// offset is the offset in bytes to the actual mapped region, as set by _memory_map
        /// release is set to 0 for partial unmap, or size of entire range for a full unmap
        fn memoryUnmap(address_init: ?*anyopaque, size: usize, offset_init: usize, release_init: usize) void {
            var address: *anyopaque = address_init orelse return;
            var offset = offset_init;
            var release = release_init;

            // I don't think we want to/can do partial unmappings, and it
            // seems like the zig stdlib discourages it as well.
            assert(release != 0);
            assert(release == 0 or (release >= size)); // Invalid unmap size
            assert(release == 0 or (release >= page_size)); // Invalid unmap size
            assert(release % page_size == 0); // Invalid unmap size
            assert(release != 0 or (offset == 0)); // Invalid unmap size
            assert(size >= page_size); // Invalid unmap size

            if (release != 0 and offset != 0) {
                offset <<= 3;
                address = pointerOffset(address, -@intCast(isize, offset)).?;
                if ((release >= span_size.*) and (span_size.* > map_granularity)) {
                    // Padding is always one span size
                    release += span_size.*;
                }
            }
            if (!disable_unmap) {
                backing_allocator.rawFree(@ptrCast([*]u8, address)[0..release], page_size_shift, @returnAddress());
            }
        }

        /// Declare the span to be a subspan and store distance from master span and span count
        fn spanMarkAsSubspanUnlessMaster(master: *Span, subspan: *Span, span_count: usize) void {
            assert(subspan != master or subspan.flags.master); // Span master pointer and/or flag mismatch
            if (subspan != master) {
                subspan.flags = .{ .subspan = true };
                subspan.offset_from_master = @intCast(u32, std.math.shr(uptr_t, @bitCast(uptr_t, pointerDiff(subspan, master)), span_size_shift.*));
                subspan.align_offset = 0;
            }
            subspan.span_count = @intCast(u32, span_count);
        }

        /// Use global reserved spans to fulfill a memory map request (reserve size must be checked by caller)
        fn globalGetReservedSpans(span_count: usize) ?*Span {
            const span: ?*Span = global_reserve;
            spanMarkAsSubspanUnlessMaster(global_reserve_master.?, span.?, span_count);
            global_reserve_count -= span_count;
            if (global_reserve_count != 0) {
                global_reserve = ptrAndAlignCast(?*Span, pointerOffset(span, @intCast(isize, std.math.shl(usize, span_count, span_size_shift.*))));
            } else {
                global_reserve = null;
            }
            return span;
        }

        /// Store the given spans as global reserve (must only be called from within new heap allocation, not thread safe)
        fn globalSetReservedSpans(master: *Span, reserve: *Span, reserve_span_count: usize) void {
            global_reserve_master = master;
            global_reserve_count = reserve_span_count;
            global_reserve = reserve;
        }

        // Span linked list management

        /// Add a span to double linked list at the head
        fn spanDoubleLinkListAdd(head: *?*Span, span: *Span) void {
            if (head.*) |h| {
                h.prev = span;
            }
            span.next = head.*;
            head.* = span;
        }

        /// Pop head span from double linked list
        fn spanDoubleLinkListPopHead(head: **Span, span: *Span) void {
            assert(head.* == span); // Linked list corrupted
            const old_head: *Span = head.*;
            head.* = old_head.next.?;
        }

        /// Remove a span from double linked list
        fn spanDoubleLinkListRemove(maybe_head: *?*Span, span: *Span) void {
            assert(maybe_head.* != null); // Linked list corrupted
            const head = maybe_head;
            if (head.* == span) {
                head.* = span.next;
                return;
            }

            const maybe_next_span: ?*Span = span.next;
            const prev_span: *Span = span.prev.?;
            prev_span.next = maybe_next_span;
            if (maybe_next_span) |next_span| {
                @setCold(false);
                next_span.prev = prev_span;
            }
        }

        // Span control

        /// Use reserved spans to fulfill a memory map request (reserve size must be checked by caller)
        fn spanMapFromReserve(heap: *Heap, span_count: usize) ?*Span {
            //Update the heap span reserve
            const span: ?*Span = heap.span_reserve;
            heap.span_reserve = ptrAndAlignCast(?*Span, pointerOffset(span, span_count * span_size.*));
            heap.spans_reserved -= @intCast(u32, span_count);
            spanMarkAsSubspanUnlessMaster(heap.span_reserve_master.?, span.?, span_count);
            return span;
        }

        /// Get the aligned number of spans to map in based on wanted count, configured mapping granularity and the page size
        fn spanAlignCount(span_count: usize) usize {
            var request_count: usize = if (span_count > span_map_count) span_count else span_map_count;
            if ((page_size > span_size.*) and ((request_count * span_size.*) % page_size) != 0) {
                request_count += span_map_count - (request_count % span_map_count);
            }
            return request_count;
        }

        /// Setup a newly mapped span
        fn spanInitialize(span: *Span, total_span_count: usize, span_count: usize, align_offset: usize) void {
            span.total_spans = @intCast(u32, total_span_count);
            span.span_count = @intCast(u32, span_count);
            span.align_offset = @intCast(u32, align_offset);
            span.flags = .{ .master = true };
            assert(@bitCast(u32, span.flags) == 1);
            atomicStore32(&span.remaining_spans, @intCast(i32, total_span_count));
        }

        /// Map an aligned set of spans, taking configured mapping granularity and the page size into account
        fn spanMapAlignedCount(heap: *Heap, span_count: usize) ?*Span {
            // If we already have some, but not enough, reserved spans, release those to heap cache and map a new
            // full set of spans. Otherwise we would waste memory if page size > span size (huge pages)
            const aligned_span_count: usize = spanAlignCount(span_count);
            var align_offset: usize = 0;
            const span: *Span = ptrAndAlignCast(?*Span, memoryMap(aligned_span_count * span_size.*, &align_offset)) orelse return null;
            spanInitialize(span, aligned_span_count, span_count, align_offset);
            if (aligned_span_count > span_count) {
                const reserved_spans: *Span = ptrAndAlignCast(*Span, pointerOffset(span, span_count * span_size.*).?);
                var reserved_count: usize = aligned_span_count - span_count;
                if (heap.spans_reserved != 0) {
                    spanMarkAsSubspanUnlessMaster(heap.span_reserve_master.?, heap.span_reserve.?, heap.spans_reserved);
                    heapCacheInsert(heap, heap.span_reserve.?);
                }
                if (reserved_count > heap_reserve_count) {
                    // If huge pages or eager spam map count, the global reserve spin lock is held by caller, spanMap
                    assert(atomicLoad32(&global_lock) == 1); // Global spin lock not held as expected
                    const remain_count: usize = reserved_count - heap_reserve_count;
                    reserved_count = heap_reserve_count;
                    const remain_span: *Span = ptrAndAlignCast(*Span, pointerOffset(reserved_spans, reserved_count * span_size.*).?);
                    if (global_reserve != null) {
                        spanMarkAsSubspanUnlessMaster(global_reserve_master.?, global_reserve.?, global_reserve_count);
                        spanUnmap(global_reserve.?);
                    }
                    globalSetReservedSpans(span, remain_span, remain_count);
                }
                heapSetReservedSpans(heap, span, reserved_spans, reserved_count);
            }
            return span;
        }

        /// Map in memory pages for the given number of spans (or use previously reserved pages)
        fn spanMap(heap: *Heap, span_count: usize) ?*Span {
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
                            const reserved_span: *Span = ptrAndAlignCast(*Span, pointerOffset(span, std.math.shl(usize, span_count, span_size_shift.*)).?);
                            heapSetReservedSpans(heap, global_reserve_master, reserved_span, reserve_count - span_count);
                        }
                        // Already marked as subspan in globalGetReservedSpans
                        span.?.span_count = @intCast(u32, span_count);
                    }
                }
            }
            defer if (use_global_reserve) {
                releaseLock(&global_lock);
            };
            if (span == null) {
                span = spanMapAlignedCount(heap, span_count);
            }
            return span;
        }

        /// Unmap memory pages for the given number of spans (or mark as unused if no partial unmappings)
        fn spanUnmap(span: *Span) void {
            assert(span.flags.master or span.flags.subspan); // Span flag corrupted
            assert(!span.flags.master or !span.flags.subspan); // Span flag corrupted

            const is_master = span.flags.master;
            const master: *Span = if (!is_master)
                ptrAndAlignCast(*Span, pointerOffset(span, -@intCast(iptr_t, @as(uptr_t, span.offset_from_master) * span_size.*)).?)
            else
                span;
            assert(is_master or span.flags.subspan); // Span flag corrupted
            assert(master.flags.master); // Span flag corrupted

            const span_count: usize = span.span_count;
            if (!is_master) {
                assert(span.align_offset == 0); // Span align offset corrupted

                // TODO: partial unmapping doesn't really work with a generic backing allocator,
                // and it seems like the zig stdlib discourages it as well.
                if (false) {
                    // Directly unmap subspans (unless huge pages, in which case we defer and unmap entire page range with master)
                    if (span_size.* >= page_size) {
                        memoryUnmap(span, span_count * span_size.*, span.align_offset, 0);
                    }
                }
            } else {
                // Special double flag to denote an unmapped master
                // It must be kept in memory since span header must be used
                span.flags.master = true;
                span.flags.subspan = true;
                span.flags.unmapped_master = true;
            }

            if (atomicAdd32(&master.remaining_spans, -@intCast(i32, span_count)) <= 0) {
                // Everything unmapped, unmap the master span with release flag to unmap the entire range of the super span
                assert(master.flags.master and master.flags.subspan); // Span flag corrupted
                var unmap_count: usize = master.span_count;
                if (span_size.* < page_size) {
                    unmap_count = master.total_spans;
                }
                memoryUnmap(master, unmap_count * span_size.*, master.align_offset, @as(usize, master.total_spans) * span_size.*);
            }
        }

        /// Initialize a (partial) free list up to next system memory page, while reserving the first block
        /// as allocated, returning number of blocks in list
        fn freeListPartialInit(list: *?*anyopaque, first_block: *?*anyopaque, page_start: *anyopaque, block_start: *anyopaque, block_count_init: u32, block_size: u32) u32 {
            var block_count = block_count_init;
            assert(block_count != 0); // Internal failure
            first_block.* = block_start;
            if (block_count > 1) {
                var free_block: ?*anyopaque = pointerOffset(block_start, block_size);
                var block_end: ?*anyopaque = pointerOffset(block_start, @as(usize, block_size) * block_count);
                //If block size is less than half a memory page, bound init to next memory page boundary
                if (block_size < (page_size >> 1)) {
                    const page_end: ?*anyopaque = pointerOffset(page_start, page_size);
                    if (@ptrToInt(page_end) < @ptrToInt(block_end)) {
                        block_end = page_end;
                    }
                }
                list.* = free_block;
                block_count = 2;
                var next_block: ?*anyopaque = pointerOffset(free_block, block_size);
                while (@ptrToInt(next_block) < @ptrToInt(block_end)) {
                    ptrAndAlignCast(*?*anyopaque, free_block).* = next_block;
                    free_block = next_block;
                    block_count += 1;
                    next_block = pointerOffset(next_block, block_size);
                }
                ptrAndAlignCast(*?*anyopaque, free_block).* = null;
            } else {
                list.* = null;
            }
            return block_count;
        }

        /// Initialize an unused span (from cache or mapped) to be new active span, putting the initial free list in heap class free list
        fn spanInitializeNew(heap: *Heap, heap_size_class: *HeapSizeClass, span: *Span, class_idx: u32) ?*anyopaque {
            assert(span.span_count == 1); // Internal failure
            const size_class: *SizeClass = &global_size_classes[class_idx];
            span.size_class = class_idx;
            span.heap = heap;
            // span.flags &= ~SPAN_FLAG_ALIGNED_BLOCKS;
            span.flags = SpanFlags{
                .master = span.flags.master,
                .subspan = span.flags.subspan,
                .aligned_blocks = false,
                .unmapped_master = span.flags.unmapped_master,
            };
            span.block_size = size_class.block_size;
            span.block_count = size_class.block_count;
            span.free_list = null;
            span.list_size = 0;
            atomicStorePtrRelease(&span.free_list_deferred, null);

            //Setup free list. Only initialize one system page worth of free blocks in list
            var block: ?*anyopaque = undefined;
            span.free_list_limit = freeListPartialInit(&heap_size_class.free_list, &block, span, pointerOffset(span, SPAN_HEADER_SIZE).?, size_class.block_count, size_class.block_size);
            //Link span as partial if there remains blocks to be initialized as free list, or full if fully initialized
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
            while (true) {
                span.free_list = atomicExchangePtrAcquire(&span.free_list_deferred, INVALID_POINTER);
                if (span.free_list != INVALID_POINTER) break;
            }
            span.used_count -= span.list_size;
            span.list_size = 0;
            atomicStorePtrRelease(&span.free_list_deferred, null);
        }

        fn spanIsFullyUtilized(span: *Span) bool {
            assert(span.free_list_limit <= span.block_count); // Span free list corrupted
            return span.free_list == null and (span.free_list_limit >= span.block_count);
        }

        fn spanFinalize(heap: *Heap, iclass: usize, span: *Span, list_head: ?*?*Span) bool {
            const free_list = heap.size_class[iclass].free_list;
            const class_span: ?*Span = @intToPtr(?*Span, @ptrToInt(free_list) & span_mask.*);
            if (span == class_span) {
                // Adopt the heap class free list back into the span free list
                var block: ?*anyopaque = span.free_list;
                var last_block: ?*anyopaque = null;
                while (block != null) {
                    last_block = block;
                    block = ptrAndAlignCast(*?*anyopaque, block).*;
                }
                var free_count: u32 = 0;
                block = free_list;
                while (block != null) {
                    free_count += 1;
                    block = ptrAndAlignCast(*?*anyopaque, block).*;
                }
                if (last_block != null) {
                    ptrAndAlignCast(*?*anyopaque, last_block).* = free_list;
                } else {
                    span.free_list = free_list;
                }
                heap.size_class[iclass].free_list = null;
                span.used_count -= free_count;
            }
            // TODO: should this leak check be kept? And should it be an assertion?
            // If this assert triggers you have memory leaks
            rpAssert(span.list_size == span.used_count, "Memory leak detected");
            if (span.list_size == span.used_count) {
                // This function only used for spans in double linked lists
                if (list_head != null) {
                    spanDoubleLinkListRemove(list_head.?, span);
                }
                spanUnmap(span);
                return true;
            }
            return false;
        }

        // Global cache

        /// Finalize a global cache
        fn globalCacheFinalize(cache: *GlobalCache) void {
            comptime assert(enable_global_cache);

            acquireLock(&cache.lock);
            defer releaseLock(&cache.lock);

            {
                var ispan: usize = 0;
                while (ispan < cache.count) : (ispan += 1) {
                    spanUnmap(cache.span[ispan]);
                }
            }
            cache.count = 0;

            while (cache.overflow) |span| {
                cache.overflow = span.next;
                spanUnmap(span);
            }
        }

        fn globalCacheInsertSpans(span: [*]*Span, span_count: usize, count: usize) void {
            comptime assert(enable_global_cache);

            const cache_limit: usize = if (span_count == 1)
                global_cache_multiplier * MAX_THREAD_SPAN_CACHE
            else
                global_cache_multiplier * (MAX_THREAD_SPAN_LARGE_CACHE - (span_count >> 1));

            const cache: *GlobalCache = &global_span_cache[span_count - 1];

            var insert_count: usize = count;
            acquireLock(&cache.lock);

            if ((cache.count + insert_count) > cache_limit)
                insert_count = cache_limit - cache.count;

            // memcpy(cache->span + cache->count, span, sizeof(Span*) * insert_count);
            std.mem.copy(
                *Span,
                // zig fmt: off
                cache.span[cache.count..][0..insert_count],
                span                     [0..insert_count],
                // zig fmt: on
            );
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
                const current_span: *Span = span[copyThenIncrement(&insert_count)];
                current_span.next = cache.overflow;
                cache.overflow = current_span;
            }
            releaseLock(&cache.lock);

            var keep: ?*Span = null;
            {
                var ispan: usize = insert_count;
                while (ispan < count) : (ispan += 1) {
                    const current_span: *Span = span[ispan];
                    // Keep master spans that has remaining subspans to avoid dangling them
                    if (current_span.flags.master and (atomicLoad32(&current_span.remaining_spans) > current_span.span_count)) {
                        current_span.next = keep;
                        keep = current_span;
                    } else {
                        spanUnmap(current_span);
                    }
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
                            (current_span.flags.master and (atomicLoad32(&current_span.remaining_spans) <= current_span.span_count)))
                        {
                            spanUnmap(current_span);
                            cache.span[islot] = keep.?;
                            break;
                        }
                    }
                    if (islot == cache.count) break;
                    keep = keep.?.next;
                }

                if (keep) |keep_unwrapped| {
                    var tail: *Span = keep_unwrapped;
                    while (tail.next) |next| {
                        tail = next;
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

            const want: usize = @min(count - extract_count, cache.count);

            // memcpy(span + extract_count, cache->span + (cache->count - want), sizeof(span_t*) * want);
            std.mem.copy(
                *Span,
                // zig fmt: off
                (span + extract_count)               [0..want],
                cache.span[cache.count - want ..].ptr[0..want],
                // zig fmt: on
            );

            cache.count -= @intCast(u32, want);
            extract_count += want;

            while (extract_count < count) {
                const current_span: *Span = cache.overflow orelse break;
                span[copyThenIncrement(&extract_count)] = current_span;
                cache.overflow = current_span.next;
            }

            if (std.debug.runtime_safety) {
                var ispan: usize = 0;
                while (ispan < extract_count) : (ispan += 1) {
                    assert(span[ispan].span_count == span_count);
                }
            }

            return extract_count;
        }

        // Heap control

        /// Store the given spans as reserve in the given heap
        fn heapSetReservedSpans(heap: *Heap, master: ?*Span, reserve: ?*Span, reserve_span_count: usize) void {
            heap.span_reserve_master = master;
            heap.span_reserve = reserve;
            heap.spans_reserved = @intCast(u32, reserve_span_count);
        }

        /// Adopt the deferred span cache list, optionally extracting the first single span for immediate re-use
        fn heapCacheAdoptDeferred(heap: *Heap, single_span: ?*?*Span) void {
            var maybe_span: ?*Span = atomicExchangePtrAcquire(&heap.span_free_deferred, null);
            while (maybe_span) |span| {
                const next_span: ?*Span = ptrAndAlignCast(?*Span, span.free_list);
                assert(span.heap == heap); // Span heap pointer corrupted

                if (span.size_class < SIZE_CLASS_COUNT) {
                    @setCold(false);
                    assert(heap.full_span_count != 0); // Heap span counter corrupted
                    heap.full_span_count -= 1;
                    if (single_span != null and single_span.?.* == null) {
                        @ptrCast(*?*Span, single_span).* = span;
                    } else {
                        heapCacheInsert(heap, span);
                    }
                } else {
                    if (span.size_class == SIZE_CLASS_HUGE) {
                        deallocateHuge(span);
                    } else {
                        assert(span.size_class == SIZE_CLASS_LARGE); // Span size class invalid
                        assert(heap.full_span_count != 0); // Heap span counter corrupted
                        heap.full_span_count -= 1;
                        const idx: u32 = span.span_count - 1;
                        if (idx == 0 and single_span != null and single_span.?.* == null) {
                            single_span.?.* = span;
                        } else {
                            heapCacheInsert(heap, span);
                        }
                    }
                }

                maybe_span = next_span;
            }
        }

        fn heapUnmap(heap: *Heap) void {
            if (heap.master_heap == null) {
                if ((heap.finalize > 1) and atomicLoad32(&heap.child_count) == 0) {
                    const span: *Span = @intToPtr(*Span, @ptrToInt(heap) & span_mask.*);
                    spanUnmap(span);
                }
            } else {
                if (atomicDecr32(&heap.master_heap.?.child_count) == 0) {
                    heapUnmap(heap.master_heap.?);
                }
            }
        }

        fn heapGlobalFinalize(heap: *Heap) void {
            if (heap.finalize > 1) return;
            heap.finalize += 1;

            heapFinalize(heap);

            if (enable_thread_cache) {
                var iclass: usize = 0;
                while (iclass < LARGE_CLASS_COUNT) : (iclass += 1) {
                    const span_cache: *SpanCache = if (iclass == 0)
                        &heap.span_cache
                    else
                        @ptrCast(*SpanCache, &heap.span_large_cache[iclass - 1]);

                    var ispan: usize = 0;
                    while (ispan < span_cache.count) : (ispan += 1) {
                        spanUnmap(span_cache.span[ispan]);
                    }
                    span_cache.count = 0;
                }
            }

            if (heap.full_span_count != 0) {
                heap.finalize -= 1;
                return;
            }

            {
                var iclass: usize = 0;
                while (iclass < SIZE_CLASS_COUNT) : (iclass += 1) {
                    if (heap.size_class[iclass].free_list != null or heap.size_class[iclass].partial_span != null) {
                        heap.finalize -= 1;
                        return;
                    }
                }
            }

            //Heap is now completely free, unmap and remove from heap list
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

            heapUnmap(heap);
        }

        /// Insert a single span into thread heap cache, releasing to global cache if overflow
        fn heapCacheInsert(heap: *Heap, span: *Span) void {
            if (heap.finalize != 0) {
                spanUnmap(span);
                heapGlobalFinalize(heap);
                return;
            } else {
                @setCold(false);
            }
            if (enable_thread_cache) {
                const span_count: usize = span.span_count;
                if (span_count == 1) {
                    const span_cache: *SpanCache = &heap.span_cache;
                    span_cache.span[copyThenIncrement(&span_cache.count)] = span;

                    if (span_cache.count == MAX_THREAD_SPAN_CACHE) {
                        const remain_count: usize = MAX_THREAD_SPAN_CACHE - THREAD_SPAN_CACHE_TRANSFER;
                        if (enable_global_cache) {
                            globalCacheInsertSpans(span_cache.span[remain_count..], span_count, THREAD_SPAN_CACHE_TRANSFER);
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
                    span_cache.span[copyThenIncrement(&span_cache.count)] = span;

                    const cache_limit: usize = (MAX_THREAD_SPAN_LARGE_CACHE - (span_count >> 1));
                    if (span_cache.count == cache_limit) {
                        const transfer_limit: usize = 2 + (cache_limit >> 2);
                        const transfer_count: usize = if (THREAD_SPAN_LARGE_CACHE_TRANSFER <= transfer_limit) THREAD_SPAN_LARGE_CACHE_TRANSFER else transfer_limit;
                        const remain_count: usize = cache_limit - transfer_count;
                        if (enable_global_cache) {
                            globalCacheInsertSpans(span_cache.span[remain_count..].ptr, span_count, transfer_count);
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
                spanUnmap(span);
            }
        }

        /// Extract the given number of spans from the different cache levels
        fn heapThreadCacheExtract(heap: *Heap, span_count: usize) ?*Span {
            var span: ?*Span = null;
            if (enable_thread_cache) {
                var span_cache: *SpanCache = undefined;
                if (span_count == 1) {
                    span_cache = &heap.span_cache;
                } else {
                    span_cache = @ptrCast(*SpanCache, &heap.span_large_cache[span_count - 2]);
                }

                if (span_cache.count != 0) {
                    return span_cache.span[decrementAndCopy(&span_cache.count)];
                }
            }
            return span;
        }

        fn heapThreadCacheDeferredExtract(heap: *Heap, span_count: usize) ?*Span {
            var span: ?*Span = null;
            if (span_count == 1) {
                heapCacheAdoptDeferred(heap, &span);
            } else {
                heapCacheAdoptDeferred(heap, null);
                span = heapThreadCacheExtract(heap, span_count);
            }
            return span;
        }

        fn heapReservedExtract(heap: *Heap, span_count: usize) ?*Span {
            if (heap.spans_reserved >= span_count) {
                return spanMap(heap, span_count);
            }
            return null;
        }

        /// Extract a span from the global cache
        fn heapGlobalCacheExtract(heap: *Heap, span_count: usize) ?*Span {
            if (enable_global_cache) {
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
                    span_cache.count = globalCacheExtractSpans(span_cache.span[0..], span_count, wanted_count);
                    if (span_cache.count != 0) {
                        return span_cache.span[decrementAndCopy(&span_cache.count)];
                    }
                } else {
                    var span: ?*Span = null;
                    const count: usize = globalCacheExtractSpans(@ptrCast(*[1]*Span, &span), span_count, 1);
                    if (count != 0) {
                        return span;
                    }
                }
            }
            return null;
        }

        /// Get a span from one of the cache levels (thread cache, reserved, global cache) or fallback to mapping more memory
        fn heapExtractNewSpan(heap: *Heap, maybe_heap_size_class: ?*HeapSizeClass, span_count_init: usize, class_idx: u32) ?*Span {
            var span_count = span_count_init;
            _ = class_idx;
            if (enable_thread_cache) cached_blk: {
                const heap_size_class: *HeapSizeClass = maybe_heap_size_class orelse break :cached_blk;
                const span: *Span = heap_size_class.cache orelse break :cached_blk;
                heap_size_class.cache = null;
                if (heap.span_cache.count != 0) {
                    heap_size_class.cache = heap.span_cache.span[decrementAndCopy(&heap.span_cache.count)];
                }
                return span;
            }

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
                if (heapThreadCacheDeferredExtract(heap, span_count)) |span| {
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
            return spanMap(heap, base_span_count);
        }

        fn heapInitialize(heap: *Heap) void {
            heap.* = comptime Heap{
                .owner_thread = 0,
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
            // TODO: `atomicIncr32` here returns the value of 'heap_id_counter' after it's incremented,
            // which means adding 1 here makes the first id be '2'. Need to investigate if this is
            // intentional, or if it is even a significant detail.
            heap.id = 1 + atomicIncr32(&heap_id_counter);

            //Link in heap in heap ID map
            const list_idx: usize = @intCast(usize, heap.id) % heap_array_size;
            heap.next_heap = all_heaps[list_idx];
            all_heaps[list_idx] = heap;
        }

        fn heapOrphan(heap: *Heap) void {
            heap.owner_thread = std.math.maxInt(uptr_t);
            const heap_list: *?*Heap = &orphan_heaps;
            heap.next_orphan = heap_list.*;
            heap_list.* = heap;
        }

        /// Allocate a new heap from newly mapped memory pages
        fn heapAllocateNew() ?*Heap {
            // Map in pages for a 16 heaps. If page size is greater than required size for this, map a page and
            // use first part for heaps and remaining part for spans for allocations. Adds a lot of complexity,
            // but saves a lot of memory on systems where page size > 64 spans (4MiB)
            const heap_size: usize = @sizeOf(Heap);
            const aligned_heap_size: usize = 16 * ((heap_size + 15) / 16);
            var request_heap_count: usize = 16;
            var heap_span_count: usize = ((aligned_heap_size * request_heap_count) + @sizeOf(Span) + span_size.* - 1) / span_size.*;

            var span_count: usize = heap_span_count;
            const span: *Span = span_init: {
                var span: ?*Span = null;

                var block_size: usize = span_size.* * heap_span_count;
                // If there are global reserved spans, use these first
                if (global_reserve_count >= heap_span_count) {
                    span = globalGetReservedSpans(heap_span_count);
                }
                if (span == null) {
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
                    span = ptrAndAlignCast(*Span, memoryMap(block_size, &align_offset) orelse return null);

                    // Master span will contain the heaps
                    spanInitialize(span.?, span_count, heap_span_count, align_offset);
                }

                break :span_init span.?;
            };

            var remain_size: usize = span_size.* - @sizeOf(Span);
            const heap: *Heap = ptrAndAlignCast(*Heap, pointerOffset(span, @sizeOf(Span)));
            heapInitialize(heap);

            // Put extra heaps as orphans
            var num_heaps: usize = remain_size / aligned_heap_size;
            if (num_heaps < request_heap_count) {
                num_heaps = request_heap_count;
            }
            atomicStore32(&heap.child_count, @intCast(i32, num_heaps - 1));
            var extra_heap: *Heap = ptrAndAlignCast(*Heap, pointerOffset(heap, aligned_heap_size).?);
            while (num_heaps > 1) {
                heapInitialize(extra_heap);
                extra_heap.master_heap = heap;
                heapOrphan(extra_heap);
                extra_heap = ptrAndAlignCast(*Heap, pointerOffset(extra_heap, aligned_heap_size).?);
                num_heaps -= 1;
            }

            if (span_count > heap_span_count) {
                // Cap reserved spans
                const remain_count: usize = span_count - heap_span_count;
                var reserve_count: usize = if (remain_count > heap_reserve_count) heap_reserve_count else remain_count;
                var remain_span: *Span = ptrAndAlignCast(*Span, pointerOffset(span, @intCast(isize, heap_span_count * span_size.*)).?);
                heapSetReservedSpans(heap, span, remain_span, reserve_count);

                if (remain_count > reserve_count) {
                    // Set to global reserved spans
                    remain_span = ptrAndAlignCast(*Span, pointerOffset(remain_span, reserve_count * span_size.*).?);
                    reserve_count = remain_count - reserve_count;
                    globalSetReservedSpans(span, remain_span, reserve_count);
                }
            }

            return heap;
        }

        fn heapExtractOrphan(heap_list: *?*Heap) ?*Heap {
            const heap: ?*Heap = heap_list.*;
            heap_list.* = if (heap) |heap_unwrapped| heap_unwrapped.next_orphan else null;
            return heap;
        }

        /// Allocate a new heap, potentially reusing a previously orphaned heap
        fn heapAllocate() ?*Heap {
            acquireLock(&global_lock);
            defer releaseLock(&global_lock);
            const heap: *Heap =
                heapExtractOrphan(&orphan_heaps) orelse
                heapAllocateNew() orelse
                return null;
            heapCacheAdoptDeferred(heap, null);
            return heap;
        }

        fn heapRelease(heap: *Heap, release_cache: bool) void {
            // Release thread cache spans back to global cache
            heapCacheAdoptDeferred(heap, null);
            if (enable_thread_cache) {
                if (release_cache or heap.finalize != 0) {
                    var iclass: usize = 0;
                    while (iclass < LARGE_CLASS_COUNT) : (iclass += 1) {
                        const span_cache: *SpanCache = if (iclass == 0) &heap.span_cache else @ptrCast(*SpanCache, &heap.span_large_cache[iclass - 1]);

                        if (span_cache.count == 0) continue;
                        if (enable_global_cache) {
                            if (heap.finalize != 0) {
                                var ispan: usize = 0;
                                while (ispan < span_cache.count) : (ispan += 1) {
                                    spanUnmap(span_cache.span[ispan]);
                                }
                            } else {
                                globalCacheInsertSpans(span_cache.span[0..], iclass + 1, span_cache.count);
                            }
                        } else {
                            var ispan: usize = 0;
                            while (ispan < span_cache.count) : (ispan += 1) {
                                spanUnmap(span_cache.span[ispan]);
                            }
                        }
                        span_cache.count = 0;
                    }
                }
            }

            if (getThreadHeapRaw() == heap) {
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

        fn heapFinalize(heap: *Heap) void {
            if (heap.spans_reserved != 0) {
                const span: *Span = spanMapFromReserve(heap, heap.spans_reserved).?;
                spanUnmap(span);
                assert(heap.spans_reserved == 0);
            }

            heapCacheAdoptDeferred(heap, null);

            {
                var iclass: usize = 0;
                while (iclass < SIZE_CLASS_COUNT) : (iclass += 1) {
                    if (heap.size_class[iclass].cache) |cache| {
                        spanUnmap(cache);
                    }
                    heap.size_class[iclass].cache = null;
                    var maybe_span: ?*Span = heap.size_class[iclass].partial_span;
                    while (maybe_span) |span| {
                        const next: ?*Span = span.next;
                        _ = spanFinalize(heap, iclass, span, &heap.size_class[iclass].partial_span);
                        maybe_span = next;
                    }
                    // If class still has a free list it must be a full span
                    if (heap.size_class[iclass].free_list) |free_list| {
                        const class_span: *Span = @intToPtr(*Span, @ptrToInt(free_list) & span_mask.*);
                        const list: ?*?*Span = null;

                        heap.full_span_count -= 1;
                        if (!spanFinalize(heap, iclass, class_span, list)) {
                            if (list) |list_unwrapped| {
                                spanDoubleLinkListRemove(list_unwrapped, class_span);
                            }
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
                        spanUnmap(span_cache.span[ispan]);
                    }
                    span_cache.count = 0;
                }
            }
            assert(atomicLoadPtr(&heap.span_free_deferred) == null); // Heaps still active during finalization
        }

        // Allocation entry points

        /// Pop first block from a free list
        fn freeListPop(list: *?*align(@alignOf(*anyopaque)) anyopaque) ?*anyopaque {
            const block = list.*;
            list.* = @ptrCast(*?*align(@alignOf(*anyopaque)) anyopaque, block).*;
            return block;
        }

        /// Allocate a small/medium sized memory block from the given heap
        fn allocateFromHeapFallback(heap: *Heap, heap_size_class: *HeapSizeClass, class_idx: u32) ?*anyopaque {
            if (heap_size_class.partial_span) |span| {
                @setCold(false);
                assert(span.block_count == global_size_classes[span.size_class].block_count); // Span block count corrupted
                assert(!spanIsFullyUtilized(span)); // Internal failure
                const block: *anyopaque = block: {
                    var block: ?*anyopaque = null;
                    if (span.free_list != null) {
                        //Span local free list is not empty, swap to size class free list
                        block = freeListPop(&span.free_list);
                        heap_size_class.free_list = span.free_list;
                        span.free_list = null;
                    } else {
                        //If the span did not fully initialize free list, link up another page worth of blocks
                        const block_start: *anyopaque = pointerOffset(span, SPAN_HEADER_SIZE + (@as(usize, span.free_list_limit) * span.block_size)).?;
                        span.free_list_limit += freeListPartialInit(&heap_size_class.free_list, &block, @intToPtr(*anyopaque, @ptrToInt(block_start) & ~(page_size - 1)), block_start, span.block_count - span.free_list_limit, span.block_size);
                    }
                    break :block block.?;
                };
                assert(span.free_list_limit <= span.block_count); // Span block count corrupted
                span.used_count = span.free_list_limit;

                // Swap in deferred free list if present
                if (atomicLoadPtr(&span.free_list_deferred) != null) {
                    spanExtractFreeListDeferred(span);
                }

                // If span is still not fully utilized keep it in partial list and early return block
                if (!spanIsFullyUtilized(span)) {
                    return block;
                }
                // The span is fully utilized, unlink from partial list and add to fully utilized list
                spanDoubleLinkListPopHead(@ptrCast(**Span, &heap_size_class.partial_span), span);
                heap.full_span_count += 1;
                return block;
            }

            // Find a span in one of the cache levels
            if (heapExtractNewSpan(heap, heap_size_class, 1, class_idx)) |span| {
                @setCold(false);
                return spanInitializeNew(heap, heap_size_class, span, class_idx);
            }

            return null;
        }

        /// Allocate a small sized memory block from the given heap
        fn allocateSmall(heap: *Heap, size: usize) ?*anyopaque {
            // Small sizes have unique size classes
            const class_idx: u32 = @intCast(u32, (size + (SMALL_GRANULARITY - 1)) >> SMALL_GRANULARITY_SHIFT);
            const heap_size_class: *HeapSizeClass = &heap.size_class[class_idx];
            if (heap_size_class.free_list != null) {
                @setCold(false);
                return freeListPop(&heap_size_class.free_list);
            }
            return allocateFromHeapFallback(heap, heap_size_class, class_idx);
        }

        /// Allocate a medium sized memory block from the given heap
        fn allocateMedium(heap: *Heap, size: usize) ?*anyopaque {
            // Calculate the size class index and do a dependent lookup of the final class index (in case of merged classes)
            const base_idx: u32 = @intCast(u32, SMALL_CLASS_COUNT + ((size - (SMALL_SIZE_LIMIT + 1)) >> MEDIUM_GRANULARITY_SHIFT));
            const class_idx: u32 = global_size_classes[base_idx].class_idx;
            const heap_size_class: *HeapSizeClass = &heap.size_class[class_idx];
            if (heap_size_class.free_list != null) {
                @setCold(false);
                return freeListPop(&heap_size_class.free_list);
            }
            return allocateFromHeapFallback(heap, heap_size_class, class_idx);
        }

        /// Allocate a large sized memory block from the given heap
        fn allocateLarge(heap: *Heap, size_init: usize) ?*anyopaque {
            var size = size_init;

            // Calculate number of needed max sized spans (including header)
            // Since this function is never called if size > LARGE_SIZE_LIMIT
            // the span_count is guaranteed to be <= LARGE_CLASS_COUNT
            size += SPAN_HEADER_SIZE;
            var span_count: usize = std.math.shr(usize, size, span_size_shift.*);
            if (size & (span_size.* - 1) != 0) {
                span_count += 1;
            }

            // Find a span in one of the cache levels
            const span: *Span = heapExtractNewSpan(heap, null, span_count, SIZE_CLASS_LARGE) orelse return null;

            // Mark span as owned by this heap and set base data
            assert(span.span_count >= span_count); // Internal failure
            span.size_class = SIZE_CLASS_LARGE;
            span.heap = heap;
            heap.full_span_count += 1;

            return pointerOffset(span, SPAN_HEADER_SIZE);
        }

        /// Allocate a huge block by mapping memory pages directly
        fn allocateHuge(heap: *Heap, size_init: usize) ?*anyopaque {
            var size = size_init;

            heapCacheAdoptDeferred(heap, null);
            size += SPAN_HEADER_SIZE;
            var num_pages: usize = size >> page_size_shift;
            if (size & (page_size - 1) != 0) {
                num_pages += 1;
            }
            var align_offset: usize = 0;
            const span: *Span = ptrAndAlignCast(*Span, memoryMap(num_pages * page_size, &align_offset) orelse return null);

            // Store page count in span_count
            span.size_class = SIZE_CLASS_HUGE;
            span.span_count = @intCast(u32, num_pages);
            span.align_offset = @intCast(u32, align_offset);
            span.heap = heap;
            heap.full_span_count += 1;

            return pointerOffset(span, SPAN_HEADER_SIZE);
        }

        /// Allocate a block of the given size
        fn allocate(heap: *Heap, size: usize) ?*anyopaque {
            if (size <= SMALL_SIZE_LIMIT) {
                @setCold(false);
                return allocateSmall(heap, size);
            }
            if (size <= medium_size_limit) return allocateMedium(heap, size);
            if (size <= LARGE_SIZE_LIMIT(span_size.*)) return allocateLarge(heap, size);
            return allocateHuge(heap, size);
        }

        fn alignedAllocate(heap: *Heap, alignment: usize, size: usize) ?*anyopaque {
            if (alignment <= SMALL_GRANULARITY) {
                if (size >= maxAllocSize()) return null;
                return allocate(heap, size);
            }

            if ((size +% alignment) < size) {
                return null;
            }
            if (alignment & (alignment - 1) != 0) {
                return null;
            }

            if ((alignment <= SPAN_HEADER_SIZE) and (size < medium_size_limit)) {
                // If alignment is less or equal to span header size (which is power of two),
                // and size aligned to span header size multiples is less than size + alignment,
                // then use natural alignment of blocks to provide alignment
                const multiple_size: usize = if (size != 0) (size + (SPAN_HEADER_SIZE - 1)) & ~@as(uptr_t, SPAN_HEADER_SIZE - 1) else SPAN_HEADER_SIZE;
                assert(multiple_size % SPAN_HEADER_SIZE == 0); // Failed alignment calculation
                if (multiple_size <= (size + alignment)) {
                    return allocate(heap, multiple_size);
                }
            }

            const align_mask: usize = alignment - 1;
            if (alignment <= page_size) {
                var ptr = allocate(heap, size + alignment);
                if (@ptrToInt(ptr) & align_mask != 0) {
                    ptr = @intToPtr(*anyopaque, (@ptrToInt(ptr) & ~@as(uptr_t, align_mask)) + alignment);
                    //Mark as having aligned blocks
                    const span: *Span = @intToPtr(*Span, @ptrToInt(ptr) & span_mask.*);
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
            if (alignment & align_mask != 0) {
                if (true) unreachable;
                return null;
            }
            if (alignment >= span_size.*) {
                if (true) unreachable;
                return null;
            }

            const extra_pages: usize = alignment / page_size;

            // Since each span has a header, we will at least need one extra memory page
            var num_pages: usize = 1 + (size / page_size);
            if (size & (page_size - 1) != 0) {
                num_pages += 1;
            }

            if (extra_pages > num_pages) {
                num_pages = 1 + extra_pages;
            }

            const original_pages: usize = num_pages;
            var limit_pages: usize = (span_size.* / page_size) * 2;
            if (limit_pages < (original_pages * 2)) {
                limit_pages = original_pages * 2;
            }

            var ptr: ?*anyopaque = null;
            var mapped_size: usize = undefined;
            var align_offset: usize = undefined;
            var span: *Span = undefined;

            retry: while (true) {
                align_offset = 0;
                mapped_size = num_pages * page_size;

                span = ptrAndAlignCast(*Span, memoryMap(mapped_size, &align_offset) orelse return null);
                ptr = pointerOffset(span, SPAN_HEADER_SIZE);

                if (@ptrToInt(ptr) & align_mask != 0) {
                    ptr = @intToPtr(*anyopaque, (@ptrToInt(ptr) & ~@as(uptr_t, align_mask)) + alignment);
                }

                if ((@intCast(usize, pointerDiff(ptr, span)) >= span_size.*) or
                    (@ptrToInt(pointerOffset(ptr, size)) > @ptrToInt(pointerOffset(span, mapped_size))) or
                    ((@ptrToInt(ptr) & span_mask.*) != @ptrToInt(span)))
                {
                    memoryUnmap(span, mapped_size, align_offset, mapped_size);
                    num_pages += 1;
                    if (num_pages > limit_pages) {
                        if (true) unreachable;
                        return null;
                    }
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
        fn deallocateDirectSmallOrMedium(span: *Span, block: *align(@alignOf(*anyopaque)) anyopaque) void {
            const heap: *Heap = span.heap.?;
            assert(heap.owner_thread == getThreadId() or heap.owner_thread == 0 or heap.finalize != 0); // Internal failure
            // Add block to free list
            if (spanIsFullyUtilized(span)) {
                span.used_count = span.block_count;
                spanDoubleLinkListAdd(&heap.size_class[span.size_class].partial_span, span);
                heap.full_span_count -= 1;
            } else {
                @setCold(false);
            }
            ptrAndAlignCast(*?*anyopaque, block).* = span.free_list;
            span.used_count -= 1;
            span.free_list = block;
            if (span.used_count == span.list_size) {
                // If there are no used blocks it is guaranteed that no other external thread is accessing the span
                if (span.used_count != 0) {
                    // Make sure we have synchronized the deferred list and list size by using acquire semantics
                    // and guarantee that no external thread is accessing span concurrently
                    var free_list: ?*align(@alignOf(*anyopaque)) anyopaque = undefined;
                    while (true) {
                        free_list = atomicExchangePtrAcquire(&span.free_list_deferred, INVALID_POINTER);
                        if (free_list != INVALID_POINTER) break;
                    }
                    atomicStorePtrRelease(&span.free_list_deferred, free_list);
                }
                spanDoubleLinkListRemove(&heap.size_class[span.size_class].partial_span, span);
                assert(span.size_class < SIZE_CLASS_COUNT); // Invalid span size class
                assert(span.span_count == 1); // Invalid span count
                if (heap.finalize == 0) {
                    if (heap.size_class[span.size_class].cache) |cache| {
                        heapCacheInsert(heap, cache);
                    }
                    heap.size_class[span.size_class].cache = span;
                } else {
                    spanUnmap(span);
                }
            } else {
                @setCold(false);
            }
        }

        fn deallocateDeferFreeSpan(heap: *Heap, span: *Span) void {
            //This list does not need ABA protection, no mutable side state
            while (true) {
                span.free_list = @ptrCast(?*anyopaque, atomicLoadPtr(&heap.span_free_deferred));
                if (atomicCasPtr(&heap.span_free_deferred, span, ptrAndAlignCast(?*Span, span.free_list))) break;
            }
        }

        /// Put the block in the deferred free list of the owning span
        fn deallocateDeferSmallOrMedium(span: *Span, block: *align(@alignOf(*anyopaque)) anyopaque) void {
            // The memory ordering here is a bit tricky, to avoid having to ABA protect
            // the deferred free list to avoid desynchronization of list and list size
            // we need to have acquire semantics on successful CAS of the pointer to
            // guarantee the list_size variable validity + release semantics on pointer store
            var free_list: ?*anyopaque = undefined;
            while (true) {
                free_list = atomicExchangePtrAcquire(&span.free_list_deferred, INVALID_POINTER);
                if (free_list != INVALID_POINTER) break;
            }
            ptrAndAlignCast(*?*anyopaque, block).* = free_list;

            span.list_size += 1;
            const free_count: u32 = span.list_size;

            const all_deferred_free = free_count == span.block_count;
            atomicStorePtrRelease(&span.free_list_deferred, block);
            if (all_deferred_free) {
                // Span was completely freed by this block. Due to the INVALID_POINTER spin lock
                // no other thread can reach this state simultaneously on this span.
                // Safe to move to owner heap deferred cache
                deallocateDeferFreeSpan(span.heap.?, span);
            }
        }

        fn deallocateSmallOrMedium(span: *Span, p_init: *align(@alignOf(*anyopaque)) anyopaque) void {
            var p = p_init;
            if (span.flags.aligned_blocks) {
                //Realign pointer to block start
                const blocks_start: *anyopaque = pointerOffset(span, SPAN_HEADER_SIZE).?;
                const block_offset: u32 = @intCast(u32, pointerDiff(p, blocks_start));
                p = @alignCast(@alignOf(*anyopaque), pointerOffset(p, -@intCast(i32, block_offset % span.block_size)).?);
            }

            //Check if block belongs to this heap or if deallocation should be deferred
            const defer_dealloc: bool = (span.heap.?.owner_thread != getThreadId()) and span.heap.?.finalize == 0;
            if (!defer_dealloc) {
                deallocateDirectSmallOrMedium(span, p);
            } else {
                deallocateDeferSmallOrMedium(span, p);
            }
        }

        /// Deallocate the given large memory block to the current heap
        fn deallocateLarge(span: *Span) void {
            assert(span.size_class == SIZE_CLASS_LARGE); // Bad span size class
            assert(!span.flags.master or !span.flags.subspan); // Span flag corrupted
            assert(span.flags.master or span.flags.subspan); // Span flag corrupted
            //We must always defer (unless finalizing) if from another heap since we cannot touch the list or counters of another heap
            const defer_dealloc: bool = (span.heap.?.owner_thread != getThreadId()) and span.heap.?.finalize == 0;

            if (defer_dealloc) {
                deallocateDeferFreeSpan(span.heap.?, span);
                return;
            }
            assert(span.heap.?.full_span_count != 0); // Heap span counter corrupted
            span.heap.?.full_span_count -= 1;

            const heap: *Heap = span.heap.?;

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
                    const master: *Span = ptrAndAlignCast(*Span, pointerOffset(span, -@intCast(iptr_t, @as(usize, span.offset_from_master) * span_size.*)).?);
                    heap.span_reserve_master = master;
                    assert(master.flags.master); // Span flag corrupted
                    assert(atomicLoad32(&master.remaining_spans) >= span.span_count); // Master span count corrupted
                }
            } else {
                //Insert into cache list
                heapCacheInsert(heap, span);
            }
        }

        /// Deallocate the given huge span
        fn deallocateHuge(span: *Span) void {
            const defer_dealloc: bool = (span.heap.?.owner_thread != getThreadId()) and span.heap.?.finalize == 0;
            if (defer_dealloc) {
                deallocateDeferFreeSpan(span.heap.?, span);
                return;
            }
            assert(span.heap.?.full_span_count != 0); // Heap span counter corrupted
            span.heap.?.full_span_count -= 1;

            // Oversized allocation, page count is stored in span_count
            const num_pages: usize = span.span_count;
            memoryUnmap(span, num_pages * page_size, span.align_offset, num_pages * page_size);
        }

        /// Deallocate the given block
        fn deallocate(p_unaligned: *anyopaque) void {
            const p = @alignCast(@alignOf(*anyopaque), p_unaligned);
            //Grab the span (always at start of span, using span alignment)
            const span: *Span = if (@intToPtr(?*Span, @ptrToInt(p) & span_mask.*)) |span| span: {
                @setCold(false);
                break :span span;
            } else return;
            if (span.size_class < SIZE_CLASS_COUNT) {
                @setCold(false);
                deallocateSmallOrMedium(span, p);
            } else if (span.size_class == SIZE_CLASS_LARGE) {
                deallocateLarge(span);
            } else {
                deallocateHuge(span);
            }
        }

        // Initialization, finalization and utility

        /// Get the usable size of the given block
        fn usableSize(p: *anyopaque) usize {
            // Grab the span using guaranteed span alignment
            const span: *Span = @intToPtr(*Span, @ptrToInt(p) & span_mask.*);
            if (span.size_class < SIZE_CLASS_COUNT) {
                // Small/medium block
                const blocks_start: *anyopaque = pointerOffset(span, SPAN_HEADER_SIZE).?;
                return span.block_size - @intCast(usize, pointerDiff(p, blocks_start)) % span.block_size;
            }
            if (span.size_class == SIZE_CLASS_LARGE) {
                // Large block
                const current_spans: usize = span.span_count;
                return (current_spans * span_size.*) - @intCast(usize, pointerDiff(p, span));
            }
            // Oversized block, page count is stored in span_count
            const current_pages: usize = span.span_count;
            return (current_pages * page_size) - @intCast(usize, pointerDiff(p, span));
        }

        /// Adjust and optimize the size class properties for the given class
        fn adjustSizeClass(iclass: usize) void {
            const block_size: usize = global_size_classes[iclass].block_size;
            const block_count: usize = (span_size.* - SPAN_HEADER_SIZE) / block_size;

            global_size_classes[iclass].block_count = @intCast(u16, block_count);
            global_size_classes[iclass].class_idx = @intCast(u16, iclass);

            //Check if previous size classes can be merged
            if (iclass >= SMALL_CLASS_COUNT) {
                var prevclass: usize = iclass;
                while (prevclass > 0) {
                    prevclass -= 1;
                    //A class can be merged if number of pages and number of blocks are equal
                    if (global_size_classes[prevclass].block_count == global_size_classes[iclass].block_count) {
                        global_size_classes[prevclass] = global_size_classes[iclass];
                    } else {
                        break;
                    }
                }
            }
        }

        /// Initialize thread, assign heap
        fn threadInitialize() void {
            assert(!isThreadInitialized());
            const heap = heapAllocate() orelse return;
            setThreadHeap(heap);
            if (is_windows_and_not_dynamic) {
                FlsSetValue(fls_key, heap);
            }
        }

        /// Finalize thread, orphan heap
        fn threadFinalize(release_caches: bool) void {
            assert(isThreadInitialized());
            if (getThreadHeapRaw()) |heap| {
                heapRelease(heap, release_caches);
                setThreadHeap(null);
            }
            if (is_windows_and_not_dynamic) {
                FlsSetValue(fls_key, 0);
            }
        }

        inline fn isThreadInitialized() bool {
            return getThreadHeapRaw() != null;
        }

        pub const InitConfig = struct {
            backing_allocator: ?if (known_allocator) noreturn else Allocator = null,
            /// Called when a call to map memory pages fails (out of memory). If this callback is
            /// not set or returns zero the library will return a null pointer in the allocation
            /// call. If this callback returns non-zero the map call will be retried. The argument
            /// passed is the number of bytes that was requested in the map call. Only used if
            /// the default system memory map function is used (memory_map callback is not set).
            mapFailCallback: *const fn (size: usize) bool = struct {
                fn callback(_: usize) bool {
                    @setCold(true);
                    return false;
                }
            }.callback,
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

const uptr_t = std.meta.Int(.unsigned, @bitSizeOf(*anyopaque));
const iptr_t = std.meta.Int(.signed, @bitSizeOf(*anyopaque));
comptime {
    assert(std.meta.eql(@typeInfo(uptr_t).Int, @typeInfo(usize).Int));
    assert(std.meta.eql(@typeInfo(iptr_t).Int, @typeInfo(isize).Int));
}

/// `same as --x` in C.
inline fn decrementAndCopy(x: anytype) @TypeOf(x.*) {
    x.* -= 1;
    return x.*;
}
/// same as `x++` in C.
inline fn copyThenIncrement(x: anytype) @TypeOf(x.*) {
    const result = x.*;
    x.* += 1;
    return result;
}

const FlsAlloc = @compileError("windows stub");
const FlsFree = @compileError("windows stub");
const FlsSetValue = @compileError("windows stub");

// TODO: in the original source the typedef is 'volatile _Atomic(<int32_t|int64_t|void*>)',
// but I'm not sure if it should be. Why do these atomics also need to be volatile?
const atomic32_t = i32;
const atomic64_t = i64;

inline fn atomicLoad32(src: *const atomic32_t) i32 {
    return @atomicLoad(atomic32_t, src, .Monotonic);
}
inline fn atomicStore32(dst: *atomic32_t, val: i32) void {
    @atomicStore(atomic32_t, dst, val, .Monotonic);
}
inline fn atomicIncr32(val: *atomic32_t) i32 {
    return @atomicRmw(atomic32_t, val, .Add, 1, .Monotonic) + 1; // TODO: should this use wrapping semantics
}
inline fn atomicDecr32(val: *atomic32_t) i32 {
    return @atomicRmw(atomic32_t, val, .Sub, 1, .Monotonic) - 1; // TODO: should this use wrapping sematnics
}
inline fn atomicAdd32(val: *atomic32_t, add: i32) i32 {
    return @atomicRmw(atomic32_t, val, .Add, add, .Monotonic) + add; // TODO: should this use wrapping semantics
}
inline fn atomicLoadPtr(src: anytype) @TypeOf(src.*) {
    return @atomicLoad(@TypeOf(src.*), src, .Monotonic);
}
inline fn atomicStorePtr(dst: anytype, val: @TypeOf(dst.*)) void {
    @atomicStore(@TypeOf(dst.*), dst, val, .Monotonic);
}
inline fn atomicStorePtrRelease(dst: anytype, val: @TypeOf(dst.*)) void {
    @atomicStore(@TypeOf(dst.*), dst, val, .Release);
}
inline fn atomicExchangePtrAcquire(dst: anytype, val: @TypeOf(dst.*)) @TypeOf(dst.*) {
    return @atomicRmw(@TypeOf(dst.*), dst, .Xchg, val, .Acquire);
}
inline fn atomicCasPtr(dst: anytype, val: @TypeOf(dst.*), ref: @TypeOf(dst.*)) bool {
    return @cmpxchgWeak(@TypeOf(dst.*), dst, ref, val, .Monotonic, .Monotonic) == null;
}

inline fn acquireLock(lock: *i32) void {
    while (@cmpxchgWeak(i32, lock, 0, 1, .Acquire, .Monotonic) != null) {
        std.atomic.spinLoopHint();
    }
}
inline fn releaseLock(lock: *i32) void {
    @atomicStore(atomic32_t, lock, 0, .Release);
}

const INVALID_POINTER = @intToPtr(*align(@alignOf(*anyopaque)) anyopaque, std.mem.alignBackward(std.math.maxInt(uptr_t), @alignOf(*anyopaque)));
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
/// Maximum size of a large block
inline fn LARGE_SIZE_LIMIT(span_size: anytype) @TypeOf(span_size) {
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
}

const SpanFlags = packed struct(u32) {
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

fn DangerousCastAwayConst(comptime Original: type) type {
    var new = @typeInfo(Original).Pointer;
    new.is_const = false;
    return @Type(.{ .Pointer = new });
}
inline fn dangerousCastAwayConst(ptr: anytype) DangerousCastAwayConst(@TypeOf(ptr)) {
    const ConstPtr = @TypeOf(ptr);
    const Reinterp = extern union {
        with_const: ConstPtr,
        without_const: DangerousCastAwayConst(ConstPtr),
    };
    const reinterp = Reinterp{ .with_const = ptr };
    return reinterp.without_const;
}

// TODO: This is mainly just used in places where it makes things look neater,
// but a lot of those are instances where the input type should probably already be aligned,
// and the alignCast should happen further down the call stack.
inline fn ptrAndAlignCast(comptime T: type, ptr: anytype) T {
    const alignment = comptime switch (@typeInfo(T)) {
        .Pointer => |pointer| pointer.alignment,
        .Optional => |optional| @typeInfo(optional.child).Pointer.alignment,
        else => unreachable,
    };
    return @ptrCast(T, @alignCast(alignment, ptr));
}
