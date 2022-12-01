const std = @import("std");
const builtin = @import("builtin");

pub const RPMemoryAllocatorConfig = struct {
    /// Define RPMALLOC_CONFIGURABLE to enable configuring sizes. Will introduce
    /// a very small overhead due to some size calculations not being compile time constants
    configurable: bool = false,
    /// Size of heap hashmap
    heap_array_size: usize = 47,
    /// Enable per-thread cache
    enable_thread_cache: bool = true,
    /// Enable global cache shared between all threads, requires thread cache
    enable_global_cache: bool = true,
    /// Disable unmapping memory pages (also enables unlimited cache)
    disable_unmap: bool = false,
    /// Enable unlimited global cache (no unmapping until finalization)
    enable_unlimited_cache: bool = false,
    /// Default number of spans to map in call to map more virtual memory (default values yield 4MiB here)
    default_span_map_count: usize = 64,
    /// Multiplier for global cache
    global_cache_multiplier: usize = 8,
    /// Either a pointer to a comptime-known pointer to an allocator interface, or tag to indicate
    /// that the backing allocator will be supplied during initialisation.
    backing_allocator: BackingAllocator = .{ .specific = &std.heap.page_allocator },

    pub const BackingAllocator = union(enum) {
        specific: *const std.mem.Allocator,
        runtime,
    };
};
pub fn RPMemoryAllocator(comptime cfg: RPMemoryAllocatorConfig) type {
    const RPMALLOC_CONFIGURABLE = cfg.configurable;

    const HEAP_ARRAY_SIZE = cfg.heap_array_size;
    const ENABLE_THREAD_CACHE = cfg.enable_thread_cache;
    const ENABLE_GLOBAL_CACHE = cfg.enable_global_cache;
    const DISABLE_UNMAP = cfg.disable_unmap;
    const ENABLE_UNLIMITED_CACHE = cfg.enable_unlimited_cache;
    const DEFAULT_SPAN_MAP_COUNT = cfg.default_span_map_count;
    const GLOBAL_CACHE_MULTIPLIER = cfg.global_cache_multiplier;

    if (DISABLE_UNMAP and !ENABLE_GLOBAL_CACHE) {
        @compileError("Must use global cache if unmap is disabled");
    }

    if (DISABLE_UNMAP and !ENABLE_UNLIMITED_CACHE) {
        var new_cfg: RPMemoryAllocatorConfig = cfg;
        new_cfg.enable_unlimited_cache = true;
        return RPMemoryAllocator(new_cfg);
    }

    if (!ENABLE_GLOBAL_CACHE and ENABLE_UNLIMITED_CACHE) {
        var new_cfg = cfg;
        new_cfg.enable_unlimited_cache = false;
        return RPMemoryAllocator(new_cfg);
    }

    const is_windows_and_not_dynamic = builtin.os.tag == .windows and builtin.link_mode != .Dynamic;
    return struct {
        pub fn allocator() std.mem.Allocator {
            return std.mem.Allocator{
                .ptr = undefined,
                .vtable = &std.mem.Allocator.VTable{
                    .alloc = alloc,
                    .resize = resize,
                    .free = free,
                },
            };
        }
        fn alloc(state_ptr: *anyopaque, len: usize, ptr_align: u8, ret_addr: usize) ?[*]u8 {
            _ = state_ptr;
            _ = ret_addr;

            const heap: *heap_t = get_thread_heap();
            const result_ptr = _rpmalloc_aligned_allocate(heap, std.math.shl(usize, 1, ptr_align), len) orelse return null;

            const usable_size = _rpmalloc_usable_size(result_ptr);
            std.debug.assert(len <= usable_size);
            const result: []u8 = @ptrCast([*]u8, result_ptr)[0..len];
            @memset(result.ptr, undefined, result.len);
            return result.ptr;
        }
        fn resize(state_ptr: *anyopaque, buf: []u8, buf_align: u8, new_len: usize, ret_addr: usize) bool {
            _ = state_ptr;
            _ = ret_addr;

            const usable_size = _rpmalloc_usable_size(buf.ptr);
            std.debug.assert(buf.len <= usable_size);
            std.debug.assert(std.mem.isAligned(@ptrToInt(buf.ptr), std.math.shl(usize, 1, buf_align)));

            return usable_size >= new_len;
        }
        fn free(state_ptr: *anyopaque, buf: []u8, buf_align: u8, ret_addr: usize) void {
            _ = state_ptr;
            _ = buf_align;
            _ = ret_addr;
            rpfree(buf.ptr);
        }

        var fls_key = if (is_windows_and_not_dynamic) @as(std.os.windows.DWORD, 0) else {};
        comptime {
            if ((SMALL_GRANULARITY & (SMALL_GRANULARITY - 1)) != 0) @compileError("Small granularity must be power of two");
            if ((SPAN_HEADER_SIZE & (SPAN_HEADER_SIZE - 1)) != 0) @compileError("Span header size must be power of two");
        }

        /// Maximum allocation size to avoid integer overflow
        inline fn MAX_ALLOC_SIZE() @TypeOf(_memory_span_size.*) {
            return std.math.maxInt(usize) - _memory_span_size.*;
        }

        inline fn pointer_offset(ptr: ?*anyopaque, ofs: anytype) ?*anyopaque {
            const byte_ptr: [*]allowzero u8 = @ptrCast(?[*]u8, ptr);
            return if (ofs < 0)
                byte_ptr - std.math.absCast(ofs)
            else
                byte_ptr + std.math.absCast(ofs);
        }
        inline fn pointer_diff(first: anytype, second: anytype) isize {
            // _ = @TypeOf(first, second);
            const first_int = @bitCast(isize, @ptrToInt(first));
            const second_int = @bitCast(isize, @ptrToInt(second));
            return first_int - second_int;
        }

        /// A span can either represent a single span of memory pages with size declared by span_map_count configuration variable,
        /// or a set of spans in a continuous region, a super span. Any reference to the term "span" usually refers to both a single
        /// span or a super span. A super span can further be divided into multiple spans (or this, super spans), where the first
        /// (super)span is the master and subsequent (super)spans are subspans. The master span keeps track of how many subspans
        /// that are still alive and mapped in virtual memory, and once all subspans and master have been unmapped the entire
        /// superspan region is released and unmapped (on Windows for example, the entire superspan range has to be released
        /// in the same call to release the virtual memory range, but individual subranges can be decommitted individually
        /// to reduce physical memory use).
        const span_t = extern struct {
            /// Free list
            free_list: ?*anyopaque,
            /// Total block count of size class
            block_count: u32,
            /// Size class
            size_class: u32,
            /// Index of last block initialized in free list
            free_list_limit: u32,
            /// Number of used blocks remaining when in partial state
            used_count: u32,
            /// Deferred free list
            free_list_deferred: ?*anyopaque, // atomic
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
            heap: ?*heap_t,
            /// Next span
            next: ?*span_t,
            /// Previous span
            prev: ?*span_t,
        };

        comptime {
            if (@sizeOf(span_t) > SPAN_HEADER_SIZE) @compileError("span size mismatch");
        }

        const span_cache_t = extern struct {
            count: usize,
            span: [MAX_THREAD_SPAN_CACHE]*span_t,
        };

        const span_large_cache_t = extern struct {
            count: usize,
            span: [MAX_THREAD_SPAN_LARGE_CACHE]*span_t,
        };

        const heap_size_class_t = extern struct {
            /// Free list of active span
            free_list: ?*anyopaque,
            /// Double linked list of partially used spans with free blocks.
            /// Previous span pointer in head points to tail span of list.
            partial_span: ?*span_t,
            /// Early level cache of fully free spans
            cache: ?*span_t,
        };

        /// Control structure for a heap, either a thread heap or a first class heap if enabled
        const heap_t = extern struct {
            /// Owning thread ID
            owner_thread: std.Thread.Id,
            /// Free lists for each size class
            size_class: [SIZE_CLASS_COUNT]heap_size_class_t,

            /// Arrays of fully freed spans, single span
            span_cache: if (ENABLE_THREAD_CACHE) span_cache_t else [0]u8,

            /// List of deferred free spans (single linked list)
            span_free_deferred: ?*span_t, // atomic
            /// Number of full spans
            full_span_count: usize,
            /// Mapped but unused spans
            span_reserve: ?*span_t,
            /// Master span for mapped but unused spans
            span_reserve_master: ?*span_t,
            /// Number of mapped but unused spans
            spans_reserved: u32,
            /// Child count
            child_count: i32, // atomic
            /// Next heap in id list
            next_heap: ?*heap_t,
            /// Next heap in orphan list
            next_orphan: ?*heap_t,
            /// Heap ID
            id: i32,
            /// Finalization state flag
            finalize: i8,
            /// Master heap owning the memory pages
            master_heap: ?*heap_t,

            /// Arrays of fully freed spans, large spans with > 1 span count
            span_large_cache: if (ENABLE_THREAD_CACHE) ([LARGE_CLASS_COUNT - 1]span_large_cache_t) else [0]u8,
        };

        /// Size class for defining a block size bucket
        const size_class_t = extern struct {
            /// Size of blocks in this class
            block_size: u32,
            /// Number of blocks in each chunk
            block_count: u16,
            /// Class index this class is merged with
            class_idx: u16,
        };

        comptime {
            if (@sizeOf(size_class_t) != 8) @compileError("Size class size mismatch");
        }

        const global_cache_t = extern struct {
            /// Cache lock
            lock: i32, // atomic
            /// Cache count
            count: u32,
            /// Cached spans
            span: [GLOBAL_CACHE_MULTIPLIER * MAX_THREAD_SPAN_CACHE]*span_t,
            /// Unlimited cache overflow
            overflow: ?*span_t,
        };

        /// Default span size (64KiB)
        const _memory_default_span_size = (64 * 1024);
        const _memory_default_span_size_shift = 16;
        inline fn _memory_default_span_mask() uptr_t {
            return ~@as(uptr_t, _memory_span_size.* - 1);
        }

        // Global data

        const backing_allocator: *const std.mem.Allocator = backing_allocator_mut;
        /// Possibly mutable pointer to backing allocator interface
        const backing_allocator_mut = switch (cfg.backing_allocator) {
            .specific => |specific| specific,
            .runtime => &struct {
                var val: std.mem.Allocator = undefined;
            }.val,
        };

        /// Initialized flag
        var _rpmalloc_initialized: bool = false;
        /// Main thread ID
        var _rpmalloc_main_thread_id: std.Thread.Id = 0;
        /// Configuration
        var _memory_config: rpmalloc_config_t = .{
            .map_fail_callback = null,
            .page_size = 0,
            .span_size = 0,
            .span_map_count = 0,
            .enable_huge_pages = false,
            .page_name = null,
            .huge_page_name = null,
        };
        /// Memory page size
        var _memory_page_size: usize = 0;
        /// Shift to divide by page size
        var _memory_page_size_shift: std.math.Log2Int(usize) = 0;
        /// Granularity at which memory pages are mapped by OS
        var _memory_map_granularity: usize = 0;

        /// Size of a span of memory pages
        const _memory_span_size: if (!RPMALLOC_CONFIGURABLE) *const usize else *usize = if (!RPMALLOC_CONFIGURABLE) &@as(usize, _memory_default_span_size) else &struct {
            var val: usize = 0;
        }.val;
        /// Shift to divide by span size
        const _memory_span_size_shift: if (!RPMALLOC_CONFIGURABLE) *const usize else *usize = if (!RPMALLOC_CONFIGURABLE) &@as(usize, _memory_default_span_size_shift) else &struct {
            var val: usize = 0;
        }.val;
        /// Mask to get to start of a memory span
        const _memory_span_mask: if (!RPMALLOC_CONFIGURABLE) *const uptr_t else *uptr_t = if (!RPMALLOC_CONFIGURABLE) &_memory_default_span_mask() else &struct {
            var val: uptr_t = 0;
        }.val;

        /// Number of spans to map in each map call
        var _memory_span_map_count: usize = 0;
        /// Number of spans to keep reserved in each heap
        var _memory_heap_reserve_count: usize = 0;
        /// Global size classes
        var _memory_size_class: [SIZE_CLASS_COUNT]size_class_t = std.mem.zeroes([SIZE_CLASS_COUNT]size_class_t);
        /// Run-time size limit of medium blocks
        var _memory_medium_size_limit: usize = 0;
        /// Heap ID counter
        var _memory_heap_id: i32 = 0; // atomic
        /// Huge page support
        var _memory_huge_pages: bool = false;

        /// Global span cache
        var _memory_span_cache = if (ENABLE_GLOBAL_CACHE) ([_]global_cache_t{.{
            .lock = 0,
            .count = 0,
            .span = undefined,
            .overflow = null,
        }} ** LARGE_CLASS_COUNT) else @compileError("");

        /// Global reserved spans
        var _memory_global_reserve: ?*span_t = null;
        /// Global reserved count
        var _memory_global_reserve_count: usize = 0;
        /// Global reserved master
        var _memory_global_reserve_master: ?*span_t = null;
        /// All heaps
        var _memory_heaps: [HEAP_ARRAY_SIZE]?*heap_t = .{null} ** HEAP_ARRAY_SIZE;
        /// Used to restrict access to mapping memory for huge pages
        var _memory_global_lock: i32 = 0; // atomic
        /// Orphaned heaps
        var _memory_orphan_heaps: ?*heap_t = null;

        /// Thread local heap and ID
        threadlocal var _memory_thread_heap: ?*heap_t = null;

        inline fn get_thread_heap_raw() ?*heap_t {
            return _memory_thread_heap;
        }

        /// Get the current thread heap
        inline fn get_thread_heap() *heap_t {
            return get_thread_heap_raw().?;
        }

        /// Fast thread ID
        inline fn get_thread_id() std.Thread.Id {
            return std.Thread.getCurrentId();
        }

        /// Set the current thread heap
        inline fn set_thread_heap(heap: ?*heap_t) void {
            _memory_thread_heap = heap;
            if (heap) |h| {
                h.owner_thread = get_thread_id();
            }
        }

        /// Set main thread ID
        fn rpmalloc_set_main_thread() void {
            _rpmalloc_main_thread_id = get_thread_id();
        }

        fn _rpmalloc_thread_destructor(value: ?*anyopaque) callconv(.Stdcall) void {
            comptime std.debug.assert(is_windows_and_not_dynamic);
            if (value != null) {
                rpmalloc_thread_finalize(1);
            }
        }

        // Low level memory map/unmap

        fn _rpmalloc_set_name(address: ?*anyopaque, size: usize) void {
            // if (builtin.os == .linux or builtin.target.isAndroid()) {
            //     const name = if (_memory_huge_pages) _memory_config.huge_page_name else _memory_config.page_name;
            //     if (address == MAP_FAILED or name != null) return;
            //     // If the kernel does not support CONFIG_ANON_VMA_NAME or if the call fails
            //     // (e.g. invalid name) it is a no-op basically.
            //     (void)prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, (uptr_t)address, size, (uptr_t)name);
            // } else {
            _ = size;
            _ = address;
            // }
        }

        /// Map more virtual memory
        /// size is number of bytes to map
        /// offset receives the offset in bytes from start of mapped region
        /// returns address to start of mapped region to use
        fn _rpmalloc_mmap(size: usize, offset: *usize) ?*anyopaque {
            rpmalloc_assert(size % _memory_page_size == 0, "Invalid mmap size");
            rpmalloc_assert(size >= _memory_page_size, "Invalid mmap size");
            return _rpmalloc_mmap_os(size, offset) orelse return null;
        }

        /// Unmap virtual memory
        /// address is the memory address to unmap, as returned from _memory_map
        /// size is the number of bytes to unmap, which might be less than full region for a partial unmap
        /// offset is the offset in bytes to the actual mapped region, as set by _memory_map
        /// release is set to 0 for partial unmap, or size of entire range for a full unmap
        fn _rpmalloc_unmap(address: ?*anyopaque, size: usize, offset: usize, release: usize) void {
            rpmalloc_assert(release == 0 or (release >= size), "Invalid unmap size");
            rpmalloc_assert(release == 0 or (release >= _memory_page_size), "Invalid unmap size");
            rpmalloc_assert(release % _memory_page_size == 0, "Invalid unmap size");
            return _rpmalloc_unmap_os(address, size, offset, release);
        }

        /// Default implementation to map new pages to virtual memory
        fn _rpmalloc_mmap_os(size: usize, offset: *usize) ?*anyopaque {
            //Either size is a heap (a single page) or a (multiple) span - we only need to align spans, and only if larger than map granularity
            const padding: usize = if ((size >= _memory_span_size.*) and (_memory_span_size.* > _memory_map_granularity)) _memory_span_size.* else 0;
            rpmalloc_assert(size >= _memory_page_size, "Invalid mmap size");
            var ptr: ?*anyopaque = while (true) {
                const ptr = backing_allocator.rawAlloc(size + padding, _memory_page_size_shift, @returnAddress()) orelse {
                    if (_memory_config.map_fail_callback) |callback| {
                        if (callback(size)) continue;
                    }
                    break null;
                };
                break ptr;
            };
            if (padding != 0) {
                const final_padding: usize = padding - (@ptrToInt(ptr) & ~_memory_span_mask.*);
                rpmalloc_assert(final_padding <= _memory_span_size.*, "Internal failure in padding");
                rpmalloc_assert(final_padding <= padding, "Internal failure in padding");
                rpmalloc_assert(final_padding % 8 == 0, "Internal failure in padding");
                ptr = pointer_offset(ptr, final_padding).?;
                offset.* = final_padding >> 3;
            }
            rpmalloc_assert(
                size < _memory_span_size.* or (@ptrToInt(ptr) & ~_memory_span_mask.*) == 0,
                "Internal failure in padding",
            );
            return ptr;
        }

        /// Default implementation to unmap pages from virtual memory
        fn _rpmalloc_unmap_os(address_init: ?*anyopaque, size: usize, offset_init: usize, release_init: usize) void {
            var address: *anyopaque = address_init orelse return;
            var offset = offset_init;
            var release = release_init;
            // std.debug.assert(release != 0);
            rpmalloc_assert(release != 0 or (offset == 0), "Invalid unmap size");
            rpmalloc_assert(release == 0 or (release >= _memory_page_size), "Invalid unmap size");
            rpmalloc_assert(size >= _memory_page_size, "Invalid unmap size");
            if (release != 0 and offset != 0) {
                offset <<= 3;
                address = pointer_offset(address, -@intCast(isize, offset)).?;
                if ((release >= _memory_span_size.*) and (_memory_span_size.* > _memory_map_granularity)) {
                    // Padding is always one span size
                    release += _memory_span_size.*;
                }
            }
            if (!DISABLE_UNMAP) {
                // if (builtin.os.tag == .windows) {
                //     if (std.os.windows.kernel32.VirtualFree(address, if (release != 0) 0 else size, if (release != 0) std.os.windows.MEM_RELEASE else std.os.windows.MEM_DECOMMIT) != 0) {
                //         rpmalloc_assert(false, "Failed to unmap virtual memory block");
                //     }
                // } else if (release != 0) {
                //     rpmalloc_assert(std.os.linux.munmap(@ptrCast([*]const u8, address), release) == 0, "Failed to unmap virtual memory block");
                // }
                backing_allocator.rawFree(@ptrCast([*]u8, address)[0..release], _memory_page_size_shift, @returnAddress());
            }
        }

        /// Declare the span to be a subspan and store distance from master span and span count
        fn _rpmalloc_span_mark_as_subspan_unless_master(master: *span_t, subspan: *span_t, span_count: usize) void {
            rpmalloc_assert(subspan != master or subspan.flags.master, "Span master pointer and/or flag mismatch");
            if (subspan != master) {
                subspan.flags = .{ .subspan = true };
                subspan.offset_from_master = @intCast(u32, @bitCast(uptr_t, pointer_diff(subspan, master)) >> _memory_span_size_shift.*);
                subspan.align_offset = 0;
            }
            subspan.span_count = @intCast(u32, span_count);
        }

        /// Use global reserved spans to fulfill a memory map request (reserve size must be checked by caller)
        fn _rpmalloc_global_get_reserved_spans(span_count: usize) ?*span_t {
            const span: ?*span_t = _memory_global_reserve;
            _rpmalloc_span_mark_as_subspan_unless_master(_memory_global_reserve_master.?, span.?, span_count);
            _memory_global_reserve_count -= span_count;
            if (_memory_global_reserve_count != 0) {
                _memory_global_reserve = @ptrCast(?*span_t, @alignCast(@alignOf(span_t), pointer_offset(span, @intCast(isize, span_count << _memory_span_size_shift.*))));
            } else {
                _memory_global_reserve = null;
            }
            return span;
        }

        /// Store the given spans as global reserve (must only be called from within new heap allocation, not thread safe)
        fn _rpmalloc_global_set_reserved_spans(master: *span_t, reserve: *span_t, reserve_span_count: usize) void {
            _memory_global_reserve_master = master;
            _memory_global_reserve_count = reserve_span_count;
            _memory_global_reserve = reserve;
        }

        // Span linked list management

        /// Add a span to double linked list at the head
        fn _rpmalloc_span_double_link_list_add(head: *?*span_t, span: *span_t) void {
            if (head.*) |h| {
                h.prev = span;
            }
            span.next = head.*;
            head.* = span;
        }

        /// Pop head span from double linked list
        fn _rpmalloc_span_double_link_list_pop_head(head: **span_t, span: *span_t) void {
            rpmalloc_assert(head.* == span, "Linked list corrupted");
            const old_head: *span_t = head.*;
            head.* = old_head.next.?;
        }

        /// Remove a span from double linked list
        fn _rpmalloc_span_double_link_list_remove(maybe_head: *?*span_t, span: *span_t) void {
            rpmalloc_assert(maybe_head.* != null, "Linked list corrupted");
            const head = maybe_head;
            if (head.* == span) {
                head.* = span.next;
                return;
            }

            const maybe_next_span: ?*span_t = span.next;
            const prev_span: *span_t = span.prev.?;
            prev_span.next = maybe_next_span;
            if (EXPECTED(maybe_next_span)) |next_span| {
                next_span.prev = prev_span;
            }
        }

        // Span control

        /// Use reserved spans to fulfill a memory map request (reserve size must be checked by caller)
        fn _rpmalloc_span_map_from_reserve(heap: *heap_t, span_count: usize) ?*span_t {
            //Update the heap span reserve
            const span: ?*span_t = heap.span_reserve;
            heap.span_reserve = @ptrCast(?*span_t, @alignCast(@alignOf(span_t), pointer_offset(span, span_count * _memory_span_size.*)));
            heap.spans_reserved -= @intCast(u32, span_count);
            _rpmalloc_span_mark_as_subspan_unless_master(heap.span_reserve_master.?, span.?, span_count);
            return span;
        }

        /// Get the aligned number of spans to map in based on wanted count, configured mapping granularity and the page size
        fn _rpmalloc_span_align_count(span_count: usize) usize {
            var request_count: usize = if (span_count > _memory_span_map_count) span_count else _memory_span_map_count;
            if ((_memory_page_size > _memory_span_size.*) and ((request_count * _memory_span_size.*) % _memory_page_size) != 0) {
                request_count += _memory_span_map_count - (request_count % _memory_span_map_count);
            }
            return request_count;
        }

        /// Setup a newly mapped span
        fn _rpmalloc_span_initialize(span: *span_t, total_span_count: usize, span_count: usize, align_offset: usize) void {
            // span.* = std.mem.zeroes(span_t);
            span.total_spans = @intCast(u32, total_span_count);
            span.span_count = @intCast(u32, span_count);
            span.align_offset = @intCast(u32, align_offset);
            span.flags = .{ .master = true };
            std.debug.assert(@bitCast(u32, span.flags) == 1);
            atomic_store32(&span.remaining_spans, @intCast(i32, total_span_count));
        }

        /// Map an aligned set of spans, taking configured mapping granularity and the page size into account
        fn _rpmalloc_span_map_aligned_count(heap: *heap_t, span_count: usize) ?*span_t {
            // If we already have some, but not enough, reserved spans, release those to heap cache and map a new
            // full set of spans. Otherwise we would waste memory if page size > span size (huge pages)
            const aligned_span_count: usize = _rpmalloc_span_align_count(span_count);
            var align_offset: usize = 0;
            const span: *span_t = @ptrCast(?*span_t, @alignCast(@alignOf(span_t), _rpmalloc_mmap(aligned_span_count * _memory_span_size.*, &align_offset))) orelse return null;
            _rpmalloc_span_initialize(span, aligned_span_count, span_count, align_offset);
            if (aligned_span_count > span_count) {
                const reserved_spans: *span_t = @ptrCast(*span_t, @alignCast(@alignOf(span_t), pointer_offset(span, span_count * _memory_span_size.*).?));
                var reserved_count: usize = aligned_span_count - span_count;
                if (heap.spans_reserved != 0) {
                    _rpmalloc_span_mark_as_subspan_unless_master(heap.span_reserve_master.?, heap.span_reserve.?, heap.spans_reserved);
                    _rpmalloc_heap_cache_insert(heap, heap.span_reserve.?);
                }
                if (reserved_count > _memory_heap_reserve_count) {
                    // If huge pages or eager spam map count, the global reserve spin lock is held by caller, _rpmalloc_span_map
                    rpmalloc_assert(atomic_load32(&_memory_global_lock) == 1, "Global spin lock not held as expected");
                    const remain_count: usize = reserved_count - _memory_heap_reserve_count;
                    reserved_count = _memory_heap_reserve_count;
                    const remain_span: *span_t = @ptrCast(*span_t, @alignCast(@alignOf(span_t), pointer_offset(reserved_spans, reserved_count * _memory_span_size.*).?));
                    if (_memory_global_reserve != null) {
                        _rpmalloc_span_mark_as_subspan_unless_master(_memory_global_reserve_master.?, _memory_global_reserve.?, _memory_global_reserve_count);
                        _rpmalloc_span_unmap(_memory_global_reserve.?);
                    }
                    _rpmalloc_global_set_reserved_spans(span, remain_span, remain_count);
                }
                _rpmalloc_heap_set_reserved_spans(heap, span, reserved_spans, reserved_count);
            }
            return span;
        }

        /// Map in memory pages for the given number of spans (or use previously reserved pages)
        fn _rpmalloc_span_map(heap: *heap_t, span_count: usize) ?*span_t {
            if (span_count <= heap.spans_reserved)
                return _rpmalloc_span_map_from_reserve(heap, span_count);
            var span: ?*span_t = null;
            const use_global_reserve: bool = (_memory_page_size > _memory_span_size.*) or (_memory_span_map_count > _memory_heap_reserve_count);
            if (use_global_reserve) {
                // If huge pages, make sure only one thread maps more memory to avoid bloat
                acquireLock(&_memory_global_lock);
                if (_memory_global_reserve_count >= span_count) {
                    var reserve_count: usize = if (heap.spans_reserved == 0) _memory_heap_reserve_count else span_count;
                    reserve_count = @min(reserve_count, _memory_global_reserve_count);
                    span = _rpmalloc_global_get_reserved_spans(reserve_count);
                    if (span != null) {
                        if (reserve_count > span_count) {
                            const reserved_span: *span_t = @ptrCast(*span_t, @alignCast(@alignOf(span_t), pointer_offset(span, span_count << _memory_span_size_shift.*).?));
                            _rpmalloc_heap_set_reserved_spans(heap, _memory_global_reserve_master, reserved_span, reserve_count - span_count);
                        }
                        // Already marked as subspan in _rpmalloc_global_get_reserved_spans
                        span.?.span_count = @intCast(u32, span_count);
                    }
                }
            }
            defer if (use_global_reserve) {
                releaseLock(&_memory_global_lock);
            };
            if (span == null) {
                span = _rpmalloc_span_map_aligned_count(heap, span_count);
            }
            return span;
        }

        /// Unmap memory pages for the given number of spans (or mark as unused if no partial unmappings)
        fn _rpmalloc_span_unmap(span: *span_t) void {
            rpmalloc_assert(span.flags.master or span.flags.subspan, "Span flag corrupted");
            rpmalloc_assert(!span.flags.master or !span.flags.subspan, "Span flag corrupted");

            const is_master = span.flags.master;
            const master: *span_t = if (!is_master)
                @ptrCast(*span_t, @alignCast(@alignOf(span_t), pointer_offset(span, -@intCast(iptr_t, @as(uptr_t, span.offset_from_master) * _memory_span_size.*)).?))
            else
                span;
            rpmalloc_assert(is_master or span.flags.subspan, "Span flag corrupted");
            rpmalloc_assert(master.flags.master, "Span flag corrupted");

            const span_count: usize = span.span_count;
            if (!is_master) {
                // Directly unmap subspans (unless huge pages, in which case we defer and unmap entire page range with master)
                rpmalloc_assert(span.align_offset == 0, "Span align offset corrupted");
                // if (_memory_span_size.* >= _memory_page_size) {
                // _rpmalloc_unmap(span, span_count * _memory_span_size.*, span.align_offset, 0);
                // }
            } else {
                // Special double flag to denote an unmapped master
                // It must be kept in memory since span header must be used
                span.flags.master = true;
                span.flags.subspan = true;
                span.flags.unmapped_master = true;
            }

            if (atomic_add32(&master.remaining_spans, -@intCast(i32, span_count)) <= 0) {
                // Everything unmapped, unmap the master span with release flag to unmap the entire range of the super span
                rpmalloc_assert(master.flags.master and master.flags.subspan, "Span flag corrupted");
                var unmap_count: usize = master.span_count;
                if (_memory_span_size.* < _memory_page_size) {
                    unmap_count = master.total_spans;
                }
                _rpmalloc_unmap(master, unmap_count * _memory_span_size.*, master.align_offset, @as(usize, master.total_spans) * _memory_span_size.*);
            }
        }

        /// Move the span (used for small or medium allocations) to the heap thread cache
        fn _rpmalloc_span_release_to_cache(heap: *heap_t, span: *span_t) void {
            rpmalloc_assert(heap == span.heap, "Span heap pointer corrupted");
            rpmalloc_assert(span.size_class < SIZE_CLASS_COUNT, "Invalid span size class");
            rpmalloc_assert(span.span_count == 1, "Invalid span count");
            if (heap.finalize == 0) {
                if (heap.size_class[span.size_class].cache) {
                    _rpmalloc_heap_cache_insert(heap, heap.size_class[span.size_class].cache);
                }
                heap.size_class[span.size_class].cache = span;
            } else {
                _rpmalloc_span_unmap(span);
            }
        }

        /// Initialize a (partial) free list up to next system memory page, while reserving the first block
        /// as allocated, returning number of blocks in list
        fn free_list_partial_init(list: *?*anyopaque, first_block: *?*anyopaque, page_start: *anyopaque, block_start: *anyopaque, block_count_init: u32, block_size: u32) u32 {
            var block_count = block_count_init;
            rpmalloc_assert(block_count != 0, "Internal failure");
            first_block.* = block_start;
            if (block_count > 1) {
                var free_block: ?*anyopaque = pointer_offset(block_start, block_size);
                var block_end: ?*anyopaque = pointer_offset(block_start, @as(usize, block_size) * block_count);
                //If block size is less than half a memory page, bound init to next memory page boundary
                if (block_size < (_memory_page_size >> 1)) {
                    const page_end: ?*anyopaque = pointer_offset(page_start, _memory_page_size);
                    if (@ptrToInt(page_end) < @ptrToInt(block_end)) {
                        block_end = page_end;
                    }
                }
                list.* = free_block;
                block_count = 2;
                var next_block: ?*anyopaque = pointer_offset(free_block, block_size);
                while (@ptrToInt(next_block) < @ptrToInt(block_end)) {
                    @ptrCast(*?*anyopaque, @alignCast(@alignOf(?*anyopaque), free_block)).* = next_block;
                    free_block = next_block;
                    block_count += 1;
                    next_block = pointer_offset(next_block, block_size);
                }
                @ptrCast(*?*anyopaque, @alignCast(@alignOf(?*anyopaque), free_block)).* = null;
            } else {
                list.* = null;
            }
            return block_count;
        }

        /// Initialize an unused span (from cache or mapped) to be new active span, putting the initial free list in heap class free list
        fn _rpmalloc_span_initialize_new(heap: *heap_t, heap_size_class: *heap_size_class_t, span: *span_t, class_idx: u32) ?*anyopaque {
            rpmalloc_assert(span.span_count == 1, "Internal failure");
            const size_class: *size_class_t = &_memory_size_class[class_idx];
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
            atomic_store_ptr_release(&span.free_list_deferred, null);

            //Setup free list. Only initialize one system page worth of free blocks in list
            var block: ?*anyopaque = undefined;
            span.free_list_limit = free_list_partial_init(&heap_size_class.free_list, &block, span, pointer_offset(span, SPAN_HEADER_SIZE).?, size_class.block_count, size_class.block_size);
            //Link span as partial if there remains blocks to be initialized as free list, or full if fully initialized
            if (span.free_list_limit < span.block_count) {
                _rpmalloc_span_double_link_list_add(&heap_size_class.partial_span, span);
                span.used_count = span.free_list_limit;
            } else {
                heap.full_span_count += 1;
                span.used_count = span.block_count;
            }
            return block;
        }

        fn _rpmalloc_span_extract_free_list_deferred(span: *span_t) void {
            // We need acquire semantics on the CAS operation since we are interested in the list size
            // Refer to _rpmalloc_deallocate_defer_small_or_medium for further comments on this dependency
            while (true) {
                span.free_list = atomic_exchange_ptr_acquire(&span.free_list_deferred, INVALID_POINTER);
                if (span.free_list != INVALID_POINTER) break;
            }
            span.used_count -= span.list_size;
            span.list_size = 0;
            atomic_store_ptr_release(&span.free_list_deferred, null);
        }

        fn _rpmalloc_span_is_fully_utilized(span: *span_t) bool {
            rpmalloc_assert(span.free_list_limit <= span.block_count, "Span free list corrupted");
            return span.free_list == null and (span.free_list_limit >= span.block_count);
        }

        fn _rpmalloc_span_finalize(heap: *heap_t, iclass: usize, span: *span_t, list_head: ?*?*span_t) bool {
            const free_list: ?*anyopaque = heap.size_class[iclass].free_list;
            const class_span: ?*span_t = @intToPtr(?*span_t, @ptrToInt(free_list) & _memory_span_mask.*);
            if (span == class_span) {
                // Adopt the heap class free list back into the span free list
                var block: ?*anyopaque = span.free_list;
                var last_block: ?*anyopaque = null;
                while (block != null) {
                    last_block = block;
                    block = @ptrCast(*?*anyopaque, @alignCast(@alignOf(?*anyopaque), block)).*;
                }
                var free_count: u32 = 0;
                block = free_list;
                while (block != null) {
                    free_count += 1;
                    block = @ptrCast(*?*anyopaque, @alignCast(@alignOf(?*anyopaque), block)).*;
                }
                if (last_block != null) {
                    @ptrCast(*?*anyopaque, @alignCast(@alignOf(?*anyopaque), last_block)).* = free_list;
                } else {
                    span.free_list = free_list;
                }
                heap.size_class[iclass].free_list = null;
                span.used_count -= free_count;
            }
            //If this assert triggers you have memory leaks
            rpmalloc_assert(span.list_size == span.used_count, "Memory leak detected");
            if (span.list_size == span.used_count) {
                // This function only used for spans in double linked lists
                if (list_head != null) {
                    _rpmalloc_span_double_link_list_remove(list_head.?, span);
                }
                _rpmalloc_span_unmap(span);
                return true;
            }
            return false;
        }

        // Global cache

        /// Finalize a global cache
        fn _rpmalloc_global_cache_finalize(cache: *global_cache_t) void {
            comptime std.debug.assert(ENABLE_GLOBAL_CACHE);

            acquireLock(&cache.lock);
            defer releaseLock(&cache.lock);

            {
                var ispan: usize = 0;
                while (ispan < cache.count) : (ispan += 1) {
                    _rpmalloc_span_unmap(cache.span[ispan]);
                }
            }
            cache.count = 0;

            while (cache.overflow) |span| {
                cache.overflow = span.next;
                _rpmalloc_span_unmap(span);
            }
        }

        fn _rpmalloc_global_cache_insert_spans(span: [*]*span_t, span_count: usize, count: usize) void {
            comptime std.debug.assert(ENABLE_GLOBAL_CACHE);

            const cache_limit: usize = if (span_count == 1)
                GLOBAL_CACHE_MULTIPLIER * MAX_THREAD_SPAN_CACHE
            else
                GLOBAL_CACHE_MULTIPLIER * (MAX_THREAD_SPAN_LARGE_CACHE - (span_count >> 1));

            const cache: *global_cache_t = &_memory_span_cache[span_count - 1];

            var insert_count: usize = count;
            acquireLock(&cache.lock);

            if ((cache.count + insert_count) > cache_limit)
                insert_count = cache_limit - cache.count;

            // memcpy(cache->span + cache->count, span, sizeof(span_t*) * insert_count);
            memcpy(cache.span[cache.count..].ptr, span, @sizeOf(*span_t) * insert_count);
            cache.count += @intCast(u32, insert_count);

            while ( // zig fmt: off
                if (comptime ENABLE_UNLIMITED_CACHE)
                    (insert_count < count)
                else
                    // Enable unlimited cache if huge pages, or we will leak since it is unlikely that an entire huge page
                    // will be unmapped, and we're unable to partially decommit a huge page
                    ((_memory_page_size > _memory_span_size.*) and (insert_count < count))
                // zig fmt: on
            ) {
                const current_span: *span_t = span[copyThenIncrement(&insert_count)];
                current_span.next = cache.overflow;
                cache.overflow = current_span;
            }
            releaseLock(&cache.lock);

            var keep: ?*span_t = null;
            {
                var ispan: usize = insert_count;
                while (ispan < count) : (ispan += 1) {
                    const current_span: *span_t = span[ispan];
                    // Keep master spans that has remaining subspans to avoid dangling them
                    if (current_span.flags.master and (atomic_load32(&current_span.remaining_spans) > current_span.span_count)) {
                        current_span.next = keep;
                        keep = current_span;
                    } else {
                        _rpmalloc_span_unmap(current_span);
                    }
                }
            }

            if (keep != null) {
                acquireLock(&cache.lock);
                defer releaseLock(&cache.lock);

                var islot: usize = 0;
                while (keep != null) {
                    while (islot < cache.count) : (islot += 1) {
                        const current_span: *span_t = cache.span[islot];
                        if (!current_span.flags.master or
                            (current_span.flags.master and (atomic_load32(&current_span.remaining_spans) <= current_span.span_count)))
                        {
                            _rpmalloc_span_unmap(current_span);
                            cache.span[islot] = keep.?;
                            break;
                        }
                    }
                    if (islot == cache.count) break;
                    keep = keep.?.next;
                }

                if (keep) |keep_unwrapped| {
                    var tail: *span_t = keep_unwrapped;
                    while (tail.next) |next| {
                        tail = next;
                    }
                    tail.next = cache.overflow;
                    cache.overflow = keep;
                }
            }
        }

        fn _rpmalloc_global_cache_extract_spans(span: [*]?*span_t, span_count: usize, count: usize) usize {
            comptime std.debug.assert(ENABLE_GLOBAL_CACHE);

            const cache: *global_cache_t = &_memory_span_cache[span_count - 1];

            var extract_count: usize = 0;
            acquireLock(&cache.lock);
            defer releaseLock(&cache.lock);

            var want: usize = count - extract_count;
            if (want > cache.count) {
                want = cache.count;
            }

            // memcpy(span + extract_count, cache->span + (cache->count - want), sizeof(span_t*) * want);
            memcpy(span + extract_count, cache.span[cache.count - want ..].ptr, @sizeOf(*span_t) * want);

            cache.count -= @intCast(u32, want);
            extract_count += want;

            while (extract_count < count) {
                const current_span: *span_t = cache.overflow orelse break;
                span[copyThenIncrement(&extract_count)] = current_span;
                cache.overflow = current_span.next;
            }

            if (std.debug.runtime_safety) {
                var ispan: usize = 0;
                while (ispan < extract_count) : (ispan += 1) {
                    std.debug.assert(span[ispan].?.span_count == span_count);
                }
            }

            return extract_count;
        }

        // Heap control

        /// Store the given spans as reserve in the given heap
        fn _rpmalloc_heap_set_reserved_spans(heap: *heap_t, master: ?*span_t, reserve: ?*span_t, reserve_span_count: usize) void {
            heap.span_reserve_master = master;
            heap.span_reserve = reserve;
            heap.spans_reserved = @intCast(u32, reserve_span_count);
        }

        /// Adopt the deferred span cache list, optionally extracting the first single span for immediate re-use
        fn _rpmalloc_heap_cache_adopt_deferred(heap: *heap_t, single_span: ?*?*span_t) void {
            var maybe_span: ?*span_t = atomic_exchange_ptr_acquire(&heap.span_free_deferred, null);
            while (maybe_span) |span| {
                const next_span: ?*span_t = @ptrCast(?*span_t, @alignCast(@alignOf(span_t), span.free_list));
                rpmalloc_assert(span.heap == heap, "Span heap pointer corrupted");

                if (EXPECTED(span.size_class < SIZE_CLASS_COUNT)) {
                    rpmalloc_assert(heap.full_span_count != 0, "Heap span counter corrupted");
                    heap.full_span_count -= 1;
                    if (single_span != null and single_span.?.* == null) {
                        @ptrCast(*?*span_t, single_span).* = span;
                    } else {
                        _rpmalloc_heap_cache_insert(heap, span);
                    }
                } else {
                    if (span.size_class == SIZE_CLASS_HUGE) {
                        _rpmalloc_deallocate_huge(span);
                    } else {
                        rpmalloc_assert(span.size_class == SIZE_CLASS_LARGE, "Span size class invalid");
                        rpmalloc_assert(heap.full_span_count != 0, "Heap span counter corrupted");
                        heap.full_span_count -= 1;
                        const idx: u32 = span.span_count - 1;
                        if (idx == 0 and single_span != null and single_span.?.* == null) {
                            single_span.?.* = span;
                        } else {
                            _rpmalloc_heap_cache_insert(heap, span);
                        }
                    }
                }

                maybe_span = next_span;
            }
        }

        fn _rpmalloc_heap_unmap(heap: *heap_t) void {
            if (heap.master_heap == null) {
                if ((heap.finalize > 1) and atomic_load32(&heap.child_count) == 0) {
                    const span: *span_t = @intToPtr(*span_t, @ptrToInt(heap) & _memory_span_mask.*);
                    _rpmalloc_span_unmap(span);
                }
            } else {
                if (atomic_decr32(&heap.master_heap.?.child_count) == 0) {
                    _rpmalloc_heap_unmap(heap.master_heap.?);
                }
            }
        }

        fn _rpmalloc_heap_global_finalize(heap: *heap_t) void {
            if (copyThenIncrement(&heap.finalize) > 1) {
                heap.finalize -= 1;
                return;
            }

            _rpmalloc_heap_finalize(heap);

            if (ENABLE_THREAD_CACHE) {
                var iclass: usize = 0;
                while (iclass < LARGE_CLASS_COUNT) : (iclass += 1) {
                    const span_cache: *span_cache_t = if (iclass == 0)
                        &heap.span_cache
                    else
                        @ptrCast(*span_cache_t, &heap.span_large_cache[iclass - 1]);

                    var ispan: usize = 0;
                    while (ispan < span_cache.count) : (ispan += 1) {
                        _rpmalloc_span_unmap(span_cache.span[ispan]);
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
            const list_idx: usize = @intCast(usize, heap.id) % HEAP_ARRAY_SIZE;
            var list_heap: ?*heap_t = _memory_heaps[list_idx].?;
            if (list_heap == heap) {
                _memory_heaps[list_idx] = heap.next_heap;
            } else {
                while (list_heap.?.next_heap != heap) {
                    list_heap = list_heap.?.next_heap;
                }
                list_heap.?.next_heap = heap.next_heap;
            }

            _rpmalloc_heap_unmap(heap);
        }

        /// Insert a single span into thread heap cache, releasing to global cache if overflow
        fn _rpmalloc_heap_cache_insert(heap: *heap_t, span: *span_t) void {
            if (UNEXPECTED(heap.finalize != 0)) {
                _rpmalloc_span_unmap(span);
                _rpmalloc_heap_global_finalize(heap);
                return;
            }
            if (ENABLE_THREAD_CACHE) {
                const span_count: usize = span.span_count;
                if (span_count == 1) {
                    const span_cache: *span_cache_t = &heap.span_cache;
                    span_cache.span[copyThenIncrement(&span_cache.count)] = span;

                    if (span_cache.count == MAX_THREAD_SPAN_CACHE) {
                        const remain_count: usize = MAX_THREAD_SPAN_CACHE - THREAD_SPAN_CACHE_TRANSFER;
                        if (ENABLE_GLOBAL_CACHE) {
                            _rpmalloc_global_cache_insert_spans(span_cache.span[remain_count..], span_count, THREAD_SPAN_CACHE_TRANSFER);
                        } else {
                            var ispan: usize = 0;
                            while (ispan < THREAD_SPAN_CACHE_TRANSFER) : (ispan += 1) {
                                _rpmalloc_span_unmap(span_cache.span[remain_count + ispan]);
                            }
                        }
                        span_cache.count = remain_count;
                    }
                } else {
                    const cache_idx: usize = span_count - 2;
                    const span_cache: *span_large_cache_t = &heap.span_large_cache[cache_idx];
                    span_cache.span[copyThenIncrement(&span_cache.count)] = span;

                    const cache_limit: usize = (MAX_THREAD_SPAN_LARGE_CACHE - (span_count >> 1));
                    if (span_cache.count == cache_limit) {
                        const transfer_limit: usize = 2 + (cache_limit >> 2);
                        const transfer_count: usize = if (THREAD_SPAN_LARGE_CACHE_TRANSFER <= transfer_limit) THREAD_SPAN_LARGE_CACHE_TRANSFER else transfer_limit;
                        const remain_count: usize = cache_limit - transfer_count;
                        if (ENABLE_GLOBAL_CACHE) {
                            _rpmalloc_global_cache_insert_spans(span_cache.span[remain_count..].ptr, span_count, transfer_count);
                        } else {
                            var ispan: usize = 0;
                            while (ispan < transfer_count) : (ispan += 1) {
                                _rpmalloc_span_unmap(span_cache.span[remain_count + ispan]);
                            }
                        }
                        span_cache.count = remain_count;
                    }
                }
            } else {
                _rpmalloc_span_unmap(span);
            }
        }

        /// Extract the given number of spans from the different cache levels
        fn _rpmalloc_heap_thread_cache_extract(heap: *heap_t, span_count: usize) ?*span_t {
            var span: ?*span_t = null;
            if (ENABLE_THREAD_CACHE) {
                var span_cache: *span_cache_t = undefined;
                if (span_count == 1) {
                    span_cache = &heap.span_cache;
                } else {
                    span_cache = @ptrCast(*span_cache_t, &heap.span_large_cache[span_count - 2]);
                }

                if (span_cache.count != 0) {
                    return span_cache.span[decrementAndCopy(&span_cache.count)];
                }
            }
            return span;
        }

        fn _rpmalloc_heap_thread_cache_deferred_extract(heap: *heap_t, span_count: usize) ?*span_t {
            var span: ?*span_t = null;
            if (span_count == 1) {
                _rpmalloc_heap_cache_adopt_deferred(heap, &span);
            } else {
                _rpmalloc_heap_cache_adopt_deferred(heap, null);
                span = _rpmalloc_heap_thread_cache_extract(heap, span_count);
            }
            return span;
        }

        fn _rpmalloc_heap_reserved_extract(heap: *heap_t, span_count: usize) ?*span_t {
            if (heap.spans_reserved >= span_count) {
                return _rpmalloc_span_map(heap, span_count);
            }
            return null;
        }

        /// Extract a span from the global cache
        fn _rpmalloc_heap_global_cache_extract(heap: *heap_t, span_count: usize) ?*span_t {
            if (ENABLE_GLOBAL_CACHE) {
                if (ENABLE_THREAD_CACHE) {
                    var span_cache: *span_cache_t = undefined;
                    var wanted_count: usize = undefined;
                    if (span_count == 1) {
                        span_cache = &heap.span_cache;
                        wanted_count = THREAD_SPAN_CACHE_TRANSFER;
                    } else {
                        span_cache = @ptrCast(*span_cache_t, &heap.span_large_cache[span_count - 2]);
                        wanted_count = THREAD_SPAN_LARGE_CACHE_TRANSFER;
                    }
                    span_cache.count = _rpmalloc_global_cache_extract_spans(@ptrCast([*]?*span_t, span_cache.span[0..]), span_count, wanted_count);
                    if (span_cache.count != 0) {
                        return span_cache.span[decrementAndCopy(&span_cache.count)];
                    }
                } else {
                    var span: ?*span_t = null;
                    const count: usize = _rpmalloc_global_cache_extract_spans(@ptrCast(*[1]?*span_t, &span), span_count, 1);
                    if (count != 0) {
                        return span;
                    }
                }
            }
            return null;
        }

        /// Get a span from one of the cache levels (thread cache, reserved, global cache) or fallback to mapping more memory
        fn _rpmalloc_heap_extract_new_span(heap: *heap_t, maybe_heap_size_class: ?*heap_size_class_t, span_count_init: usize, class_idx: u32) ?*span_t {
            var span_count = span_count_init;
            _ = class_idx;
            if (ENABLE_THREAD_CACHE) cached_blk: {
                const heap_size_class: *heap_size_class_t = maybe_heap_size_class orelse break :cached_blk;
                const span: *span_t = heap_size_class.cache orelse break :cached_blk;
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
                // zig fmt: off
                if (EXPECTED(_rpmalloc_heap_thread_cache_extract(         heap, span_count))) |span| return span;
                if (EXPECTED(_rpmalloc_heap_thread_cache_deferred_extract(heap, span_count))) |span| return span;
                if (EXPECTED(_rpmalloc_heap_reserved_extract(             heap, span_count))) |span| return span;
                if (EXPECTED(_rpmalloc_heap_global_cache_extract(         heap, span_count))) |span| return span;
                // zig fmt: on
                span_count += 1;
                if (span_count > limit_span_count) break;
            }
            // Final fallback, map in more virtual memory
            return _rpmalloc_span_map(heap, base_span_count);
        }

        fn _rpmalloc_heap_initialize(heap: *heap_t) void {
            heap.* = comptime heap_t{
                .owner_thread = 0,
                .size_class = [_]heap_size_class_t{.{ .free_list = null, .partial_span = null, .cache = null }} ** SIZE_CLASS_COUNT,
                .span_cache = if (ENABLE_THREAD_CACHE) span_cache_t{ .count = 0, .span = undefined } else .{},
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
                .span_large_cache = if (ENABLE_THREAD_CACHE) [_]span_large_cache_t{.{ .count = 0, .span = undefined }} ** (LARGE_CLASS_COUNT - 1) else .{},
            };
            //Get a new heap ID
            heap.id = atomic_incr32(&_memory_heap_id);

            //Link in heap in heap ID map
            const list_idx: usize = @intCast(usize, heap.id) % HEAP_ARRAY_SIZE;
            heap.next_heap = _memory_heaps[list_idx];
            _memory_heaps[list_idx] = heap;
        }

        fn _rpmalloc_heap_orphan(heap: *heap_t, first_class: bool) void {
            _ = first_class;
            heap.owner_thread = std.math.maxInt(uptr_t);
            const heap_list: *?*heap_t = &_memory_orphan_heaps;
            heap.next_orphan = heap_list.*;
            heap_list.* = heap;
        }

        /// Allocate a new heap from newly mapped memory pages
        fn _rpmalloc_heap_allocate_new() ?*heap_t {
            // Map in pages for a 16 heaps. If page size is greater than required size for this, map a page and
            // use first part for heaps and remaining part for spans for allocations. Adds a lot of complexity,
            // but saves a lot of memory on systems where page size > 64 spans (4MiB)
            const heap_size: usize = @sizeOf(heap_t);
            const aligned_heap_size: usize = 16 * ((heap_size + 15) / 16);
            var request_heap_count: usize = 16;
            var heap_span_count: usize = ((aligned_heap_size * request_heap_count) + @sizeOf(span_t) + _memory_span_size.* - 1) / _memory_span_size.*;

            var span_count: usize = heap_span_count;
            const span: *span_t = span_init: {
                var span: ?*span_t = null;

                var block_size: usize = _memory_span_size.* * heap_span_count;
                // If there are global reserved spans, use these first
                if (_memory_global_reserve_count >= heap_span_count) {
                    span = _rpmalloc_global_get_reserved_spans(heap_span_count);
                }
                if (span == null) {
                    if (_memory_page_size > block_size) {
                        span_count = _memory_page_size / _memory_span_size.*;
                        block_size = _memory_page_size;
                        // If using huge pages, make sure to grab enough heaps to avoid reallocating a huge page just to serve new heaps
                        const possible_heap_count: usize = (block_size - @sizeOf(span_t)) / aligned_heap_size;
                        if (possible_heap_count >= (request_heap_count * 16)) {
                            request_heap_count *= 16;
                        } else if (possible_heap_count < request_heap_count) {
                            request_heap_count = possible_heap_count;
                        }
                        heap_span_count = ((aligned_heap_size * request_heap_count) + @sizeOf(span_t) + _memory_span_size.* - 1) / _memory_span_size.*;
                    }

                    var align_offset: usize = 0;
                    span = @ptrCast(*span_t, @alignCast(@alignOf(span_t), _rpmalloc_mmap(block_size, &align_offset) orelse return null));

                    // Master span will contain the heaps
                    _rpmalloc_span_initialize(span.?, span_count, heap_span_count, align_offset);
                }

                break :span_init span.?;
            };

            var remain_size: usize = _memory_span_size.* - @sizeOf(span_t);
            const heap: *heap_t = @ptrCast(*heap_t, @alignCast(@alignOf(heap_t), pointer_offset(span, @sizeOf(span_t)).?));
            _rpmalloc_heap_initialize(heap);

            // Put extra heaps as orphans
            var num_heaps: usize = remain_size / aligned_heap_size;
            if (num_heaps < request_heap_count) {
                num_heaps = request_heap_count;
            }
            atomic_store32(&heap.child_count, @intCast(i32, num_heaps - 1));
            var extra_heap: *heap_t = @ptrCast(*heap_t, @alignCast(@alignOf(heap_t), pointer_offset(heap, aligned_heap_size).?));
            while (num_heaps > 1) {
                _rpmalloc_heap_initialize(extra_heap);
                extra_heap.master_heap = heap;
                _rpmalloc_heap_orphan(extra_heap, true);
                extra_heap = @ptrCast(*heap_t, @alignCast(@alignOf(heap_t), pointer_offset(extra_heap, aligned_heap_size).?));
                num_heaps -= 1;
            }

            if (span_count > heap_span_count) {
                // Cap reserved spans
                const remain_count: usize = span_count - heap_span_count;
                var reserve_count: usize = if (remain_count > _memory_heap_reserve_count) _memory_heap_reserve_count else remain_count;
                var remain_span: *span_t = @ptrCast(*span_t, @alignCast(@alignOf(span_t), pointer_offset(span, @intCast(isize, heap_span_count * _memory_span_size.*)).?));
                _rpmalloc_heap_set_reserved_spans(heap, span, remain_span, reserve_count);

                if (remain_count > reserve_count) {
                    // Set to global reserved spans
                    remain_span = @ptrCast(*span_t, @alignCast(@alignOf(span_t), pointer_offset(remain_span, reserve_count * _memory_span_size.*).?));
                    reserve_count = remain_count - reserve_count;
                    _rpmalloc_global_set_reserved_spans(span, remain_span, reserve_count);
                }
            }

            return heap;
        }

        fn _rpmalloc_heap_extract_orphan(heap_list: *?*heap_t) ?*heap_t {
            const heap: ?*heap_t = heap_list.*;
            heap_list.* = if (heap) |heap_unwrapped| heap_unwrapped.next_orphan else null;
            return heap;
        }

        /// Allocate a new heap, potentially reusing a previously orphaned heap
        fn _rpmalloc_heap_allocate() ?*heap_t {
            acquireLock(&_memory_global_lock);
            defer releaseLock(&_memory_global_lock);
            const heap: *heap_t =
                _rpmalloc_heap_extract_orphan(&_memory_orphan_heaps) orelse
                _rpmalloc_heap_allocate_new() orelse
                return null;
            _rpmalloc_heap_cache_adopt_deferred(heap, null);
            return heap;
        }

        fn _rpmalloc_heap_release(heapptr: ?*anyopaque, first_class: bool, release_cache: bool) void {
            const heap: *heap_t = @ptrCast(*heap_t, @alignCast(@alignOf(heap_t), heapptr orelse return));

            // Release thread cache spans back to global cache
            _rpmalloc_heap_cache_adopt_deferred(heap, null);
            if (ENABLE_THREAD_CACHE) {
                if (release_cache or heap.finalize != 0) {
                    var iclass: usize = 0;
                    while (iclass < LARGE_CLASS_COUNT) : (iclass += 1) {
                        const span_cache: *span_cache_t = if (iclass == 0) &heap.span_cache else @ptrCast(*span_cache_t, &heap.span_large_cache[iclass - 1]);

                        if (span_cache.count == 0) continue;
                        if (ENABLE_GLOBAL_CACHE) {
                            if (heap.finalize != 0) {
                                var ispan: usize = 0;
                                while (ispan < span_cache.count) : (ispan += 1) {
                                    _rpmalloc_span_unmap(span_cache.span[ispan]);
                                }
                            } else {
                                _rpmalloc_global_cache_insert_spans(span_cache.span[0..], iclass + 1, span_cache.count);
                            }
                        } else {
                            var ispan: usize = 0;
                            while (ispan < span_cache.count) : (ispan += 1) {
                                _rpmalloc_span_unmap(span_cache.span[ispan]);
                            }
                        }
                        span_cache.count = 0;
                    }
                }
            }

            if (get_thread_heap_raw() == heap) {
                set_thread_heap(null);
            }

            // If we are forcibly terminating with _exit the state of the
            // lock atomic is unknown and it's best to just go ahead and exit
            if (get_thread_id() != _rpmalloc_main_thread_id) {
                acquireLock(&_memory_global_lock);
            }
            _rpmalloc_heap_orphan(heap, first_class);
            if (get_thread_id() != _rpmalloc_main_thread_id) {
                releaseLock(&_memory_global_lock);
            }
        }

        fn _rpmalloc_heap_release_raw(heapptr: ?*anyopaque, release_cache: bool) void {
            _rpmalloc_heap_release(heapptr, false, release_cache);
        }

        fn _rpmalloc_heap_release_raw_fc(heapptr: ?*anyopaque) void {
            _rpmalloc_heap_release_raw(heapptr, true);
        }

        fn _rpmalloc_heap_finalize(heap: *heap_t) void {
            if (heap.spans_reserved != 0) {
                const span: *span_t = _rpmalloc_span_map_from_reserve(heap, heap.spans_reserved).?;
                _rpmalloc_span_unmap(span);
                std.debug.assert(heap.spans_reserved == 0);
            }

            _rpmalloc_heap_cache_adopt_deferred(heap, null);

            {
                var iclass: usize = 0;
                while (iclass < SIZE_CLASS_COUNT) : (iclass += 1) {
                    if (heap.size_class[iclass].cache) |cache| {
                        _rpmalloc_span_unmap(cache);
                    }
                    heap.size_class[iclass].cache = null;
                    var maybe_span: ?*span_t = heap.size_class[iclass].partial_span;
                    while (maybe_span) |span| {
                        const next: ?*span_t = span.next;
                        _ = _rpmalloc_span_finalize(heap, iclass, span, &heap.size_class[iclass].partial_span);
                        maybe_span = next;
                    }
                    // If class still has a free list it must be a full span
                    if (heap.size_class[iclass].free_list) |free_list| {
                        const class_span: *span_t = @intToPtr(*span_t, @ptrToInt(free_list) & _memory_span_mask.*);
                        const list: ?*?*span_t = null;

                        heap.full_span_count -= 1;
                        if (!_rpmalloc_span_finalize(heap, iclass, class_span, list)) {
                            if (list) |list_unwrapped| {
                                _rpmalloc_span_double_link_list_remove(list_unwrapped, class_span);
                            }
                            _rpmalloc_span_double_link_list_add(&heap.size_class[iclass].partial_span, class_span);
                        }
                    }
                }
            }

            if (ENABLE_THREAD_CACHE) {
                var iclass: usize = 0;
                while (iclass < LARGE_CLASS_COUNT) : (iclass += 1) {
                    const span_cache: *span_cache_t = if (iclass == 0) &heap.span_cache else @ptrCast(*span_cache_t, &heap.span_large_cache[iclass - 1]);
                    var ispan: usize = 0;
                    while (ispan < span_cache.count) : (ispan += 1) {
                        _rpmalloc_span_unmap(span_cache.span[ispan]);
                    }
                    span_cache.count = 0;
                }
            }
            rpmalloc_assert(atomic_load_ptr(&heap.span_free_deferred) == null, "Heaps still active during finalization");
        }

        // Allocation entry points

        /// Pop first block from a free list
        fn free_list_pop(list: *?*anyopaque) ?*anyopaque {
            const block = list.*;
            list.* = @ptrCast(*?*anyopaque, @alignCast(@alignOf(?*anyopaque), block)).*;
            return block;
        }

        /// Allocate a small/medium sized memory block from the given heap
        fn _rpmalloc_allocate_from_heap_fallback(heap: *heap_t, heap_size_class: *heap_size_class_t, class_idx: u32) ?*anyopaque {
            if (heap_size_class.partial_span) |span| {
                @setCold(false);
                rpmalloc_assert(span.block_count == _memory_size_class[span.size_class].block_count, "Span block count corrupted");
                rpmalloc_assert(!_rpmalloc_span_is_fully_utilized(span), "Internal failure");
                const block: *anyopaque = block: {
                    var block: ?*anyopaque = null;
                    if (span.free_list != null) {
                        //Span local free list is not empty, swap to size class free list
                        block = free_list_pop(&span.free_list);
                        heap_size_class.free_list = span.free_list;
                        span.free_list = null;
                    } else {
                        //If the span did not fully initialize free list, link up another page worth of blocks
                        const block_start: *anyopaque = pointer_offset(span, SPAN_HEADER_SIZE + (@as(usize, span.free_list_limit) * span.block_size)).?;
                        span.free_list_limit += free_list_partial_init(&heap_size_class.free_list, &block, @intToPtr(*anyopaque, @ptrToInt(block_start) & ~(_memory_page_size - 1)), block_start, span.block_count - span.free_list_limit, span.block_size);
                    }
                    break :block block.?;
                };
                rpmalloc_assert(span.free_list_limit <= span.block_count, "Span block count corrupted");
                span.used_count = span.free_list_limit;

                // Swap in deferred free list if present
                if (atomic_load_ptr(&span.free_list_deferred) != null) {
                    // We need acquire semantics on the CAS operation since we are interested in the list size
                    // Refer to _rpmalloc_deallocate_defer_small_or_medium for further comments on this dependency
                    while (true) {
                        span.free_list = atomic_exchange_ptr_acquire(&span.free_list_deferred, INVALID_POINTER);
                        if (span.free_list != INVALID_POINTER) break;
                    }
                    span.used_count -= span.list_size;
                    span.list_size = 0;
                    atomic_store_ptr_release(&span.free_list_deferred, null);
                }

                // If span is still not fully utilized keep it in partial list and early return block
                if (!_rpmalloc_span_is_fully_utilized(span)) {
                    return block;
                }
                // The span is fully utilized, unlink from partial list and add to fully utilized list
                _rpmalloc_span_double_link_list_pop_head(@ptrCast(**span_t, &heap_size_class.partial_span), span);
                heap.full_span_count += 1;
                return block;
            }

            // Find a span in one of the cache levels
            if (_rpmalloc_heap_extract_new_span(heap, heap_size_class, 1, class_idx)) |span| {
                @setCold(false);
                return _rpmalloc_span_initialize_new(heap, heap_size_class, span, class_idx);
            }

            return null;
        }

        /// Allocate a small sized memory block from the given heap
        fn _rpmalloc_allocate_small(heap: *heap_t, size: usize) ?*anyopaque {
            // Small sizes have unique size classes
            const class_idx: u32 = @intCast(u32, (size + (SMALL_GRANULARITY - 1)) >> SMALL_GRANULARITY_SHIFT);
            const heap_size_class: *heap_size_class_t = &heap.size_class[class_idx];
            if (EXPECTED(heap_size_class.free_list != null)) {
                return free_list_pop(&heap_size_class.free_list);
            }
            return _rpmalloc_allocate_from_heap_fallback(heap, heap_size_class, class_idx);
        }

        /// Allocate a medium sized memory block from the given heap
        fn _rpmalloc_allocate_medium(heap: *heap_t, size: usize) ?*anyopaque {
            // Calculate the size class index and do a dependent lookup of the final class index (in case of merged classes)
            const base_idx: u32 = @intCast(u32, SMALL_CLASS_COUNT + ((size - (SMALL_SIZE_LIMIT + 1)) >> MEDIUM_GRANULARITY_SHIFT));
            const class_idx: u32 = _memory_size_class[base_idx].class_idx;
            const heap_size_class: *heap_size_class_t = &heap.size_class[class_idx];
            if (EXPECTED(heap_size_class.free_list != null)) {
                return free_list_pop(&heap_size_class.free_list);
            }
            return _rpmalloc_allocate_from_heap_fallback(heap, heap_size_class, class_idx);
        }

        /// Allocate a large sized memory block from the given heap
        fn _rpmalloc_allocate_large(heap: *heap_t, size_init: usize) ?*anyopaque {
            var size = size_init;

            // Calculate number of needed max sized spans (including header)
            // Since this function is never called if size > LARGE_SIZE_LIMIT
            // the span_count is guaranteed to be <= LARGE_CLASS_COUNT
            size += SPAN_HEADER_SIZE;
            var span_count: usize = size >> _memory_span_size_shift.*;
            if (size & (_memory_span_size.* - 1) != 0) {
                span_count += 1;
            }

            // Find a span in one of the cache levels
            const span: *span_t = _rpmalloc_heap_extract_new_span(heap, null, span_count, SIZE_CLASS_LARGE) orelse return null;

            // Mark span as owned by this heap and set base data
            rpmalloc_assert(span.span_count >= span_count, "Internal failure");
            span.size_class = SIZE_CLASS_LARGE;
            span.heap = heap;
            heap.full_span_count += 1;

            return pointer_offset(span, SPAN_HEADER_SIZE);
        }

        /// Allocate a huge block by mapping memory pages directly
        fn _rpmalloc_allocate_huge(heap: *heap_t, size_init: usize) ?*anyopaque {
            var size = size_init;

            _rpmalloc_heap_cache_adopt_deferred(heap, null);
            size += SPAN_HEADER_SIZE;
            var num_pages: usize = size >> _memory_page_size_shift;
            if (size & (_memory_page_size - 1) != 0) {
                num_pages += 1;
            }
            var align_offset: usize = 0;
            const span: *span_t = @ptrCast(*span_t, @alignCast(@alignOf(span_t), _rpmalloc_mmap(num_pages * _memory_page_size, &align_offset) orelse return null));

            // Store page count in span_count
            span.size_class = SIZE_CLASS_HUGE;
            span.span_count = @intCast(u32, num_pages);
            span.align_offset = @intCast(u32, align_offset);
            span.heap = heap;
            heap.full_span_count += 1;

            return pointer_offset(span, SPAN_HEADER_SIZE);
        }

        /// Allocate a block of the given size
        fn _rpmalloc_allocate(heap: *heap_t, size: usize) ?*anyopaque {
            if (EXPECTED(size <= SMALL_SIZE_LIMIT)) return _rpmalloc_allocate_small(heap, size);
            if (size <= _memory_medium_size_limit) return _rpmalloc_allocate_medium(heap, size);
            if (size <= LARGE_SIZE_LIMIT(_memory_span_size.*)) return _rpmalloc_allocate_large(heap, size);
            return _rpmalloc_allocate_huge(heap, size);
        }

        fn _rpmalloc_aligned_allocate(heap: *heap_t, alignment: usize, size: usize) ?*anyopaque {
            if (alignment <= SMALL_GRANULARITY) {
                return _rpmalloc_allocate(heap, size);
            }

            if ((size +% alignment) < size) {
                return null;
            }
            if (alignment & (alignment - 1) != 0) {
                return null;
            }

            if ((alignment <= SPAN_HEADER_SIZE) and (size < _memory_medium_size_limit)) {
                // If alignment is less or equal to span header size (which is power of two),
                // and size aligned to span header size multiples is less than size + alignment,
                // then use natural alignment of blocks to provide alignment
                const multiple_size: usize = if (size != 0) (size + (SPAN_HEADER_SIZE - 1)) & ~@as(uptr_t, SPAN_HEADER_SIZE - 1) else SPAN_HEADER_SIZE;
                rpmalloc_assert(multiple_size % SPAN_HEADER_SIZE == 0, "Failed alignment calculation");
                if (multiple_size <= (size + alignment)) {
                    return _rpmalloc_allocate(heap, multiple_size);
                }
            }

            const align_mask: usize = alignment - 1;
            if (alignment <= _memory_page_size) {
                var ptr = _rpmalloc_allocate(heap, size + alignment);
                if (@ptrToInt(ptr) & align_mask != 0) {
                    ptr = @intToPtr(*anyopaque, (@ptrToInt(ptr) & ~@as(uptr_t, align_mask)) + alignment);
                    //Mark as having aligned blocks
                    const span: *span_t = @intToPtr(*span_t, @ptrToInt(ptr) & _memory_span_mask.*);
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
            if (alignment >= _memory_span_size.*) {
                if (true) unreachable;
                return null;
            }

            const extra_pages: usize = alignment / _memory_page_size;

            // Since each span has a header, we will at least need one extra memory page
            var num_pages: usize = 1 + (size / _memory_page_size);
            if (size & (_memory_page_size - 1) != 0) {
                num_pages += 1;
            }

            if (extra_pages > num_pages) {
                num_pages = 1 + extra_pages;
            }

            const original_pages: usize = num_pages;
            var limit_pages: usize = (_memory_span_size.* / _memory_page_size) * 2;
            if (limit_pages < (original_pages * 2)) {
                limit_pages = original_pages * 2;
            }

            var ptr: ?*anyopaque = null;
            var mapped_size: usize = undefined;
            var align_offset: usize = undefined;
            var span: *span_t = undefined;

            retry: while (true) {
                align_offset = 0;
                mapped_size = num_pages * _memory_page_size;

                span = @ptrCast(*span_t, @alignCast(@alignOf(span_t), _rpmalloc_mmap(mapped_size, &align_offset) orelse return null));
                ptr = pointer_offset(span, SPAN_HEADER_SIZE);

                if (@ptrToInt(ptr) & align_mask != 0) {
                    ptr = @intToPtr(*anyopaque, (@ptrToInt(ptr) & ~@as(uptr_t, align_mask)) + alignment);
                }

                if ((@intCast(usize, pointer_diff(ptr, span)) >= _memory_span_size.*) or
                    (@ptrToInt(pointer_offset(ptr, size)) > @ptrToInt(pointer_offset(span, mapped_size))) or
                    ((@ptrToInt(ptr) & _memory_span_mask.*) != @ptrToInt(span)))
                {
                    _rpmalloc_unmap(span, mapped_size, align_offset, mapped_size);
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
        fn _rpmalloc_deallocate_direct_small_or_medium(span: *span_t, block: *anyopaque) void {
            const heap: *heap_t = span.heap.?;
            rpmalloc_assert(heap.owner_thread == get_thread_id() or heap.owner_thread == 0 or heap.finalize != 0, "Internal failure");
            //Add block to free list
            if (UNEXPECTED(_rpmalloc_span_is_fully_utilized(span))) {
                span.used_count = span.block_count;
                _rpmalloc_span_double_link_list_add(&heap.size_class[span.size_class].partial_span, span);
                heap.full_span_count -= 1;
            }
            @ptrCast(*?*anyopaque, @alignCast(@alignOf(?*anyopaque), block)).* = span.free_list;
            span.used_count -= 1;
            span.free_list = block;
            if (UNEXPECTED(span.used_count == span.list_size)) {
                // If there are no used blocks it is guaranteed that no other external thread is accessing the span
                if (span.used_count != 0) {
                    // Make sure we have synchronized the deferred list and list size by using acquire semantics
                    // and guarantee that no external thread is accessing span concurrently
                    var free_list: ?*anyopaque = undefined;
                    while (true) {
                        free_list = atomic_exchange_ptr_acquire(&span.free_list_deferred, INVALID_POINTER);
                        if (free_list != INVALID_POINTER) break;
                    }
                    atomic_store_ptr_release(&span.free_list_deferred, free_list);
                }
                _rpmalloc_span_double_link_list_remove(&heap.size_class[span.size_class].partial_span, span);
                rpmalloc_assert(heap == span.heap, "Span heap pointer corrupted");
                rpmalloc_assert(span.size_class < SIZE_CLASS_COUNT, "Invalid span size class");
                rpmalloc_assert(span.span_count == 1, "Invalid span count");
                if (heap.finalize == 0) {
                    if (heap.size_class[span.size_class].cache) |cache| {
                        _rpmalloc_heap_cache_insert(heap, cache);
                    }
                    heap.size_class[span.size_class].cache = span;
                } else {
                    _rpmalloc_span_unmap(span);
                }
            }
        }

        fn _rpmalloc_deallocate_defer_free_span(heap: *heap_t, span: *span_t) void {
            //This list does not need ABA protection, no mutable side state
            while (true) {
                span.free_list = @ptrCast(?*anyopaque, atomic_load_ptr(&heap.span_free_deferred));
                if (atomic_cas_ptr(&heap.span_free_deferred, span, @ptrCast(?*span_t, @alignCast(@alignOf(span_t), span.free_list)))) break;
            }
        }

        /// Put the block in the deferred free list of the owning span
        fn _rpmalloc_deallocate_defer_small_or_medium(span: *span_t, block: *anyopaque) void {
            // The memory ordering here is a bit tricky, to avoid having to ABA protect
            // the deferred free list to avoid desynchronization of list and list size
            // we need to have acquire semantics on successful CAS of the pointer to
            // guarantee the list_size variable validity + release semantics on pointer store
            var free_list: ?*anyopaque = undefined;
            while (true) {
                free_list = atomic_exchange_ptr_acquire(&span.free_list_deferred, INVALID_POINTER);
                if (free_list != INVALID_POINTER) break;
            }
            @ptrCast(*?*anyopaque, @alignCast(@alignOf(?*anyopaque), block)).* = free_list;
            const free_count: u32 = incrementAndCopy(&span.list_size);
            const all_deferred_free = free_count == span.block_count;
            atomic_store_ptr_release(&span.free_list_deferred, block);
            if (all_deferred_free) {
                // Span was completely freed by this block. Due to the INVALID_POINTER spin lock
                // no other thread can reach this state simultaneously on this span.
                // Safe to move to owner heap deferred cache
                _rpmalloc_deallocate_defer_free_span(span.heap.?, span);
            }
        }

        fn _rpmalloc_deallocate_small_or_medium(span: *span_t, p_init: *anyopaque) void {
            var p = p_init;
            if (span.flags.aligned_blocks) {
                //Realign pointer to block start
                const blocks_start: *anyopaque = pointer_offset(span, SPAN_HEADER_SIZE).?;
                const block_offset: u32 = @intCast(u32, pointer_diff(p, blocks_start));
                p = pointer_offset(p, -@intCast(i32, block_offset % span.block_size)).?;
            }

            //Check if block belongs to this heap or if deallocation should be deferred
            const defer_dealloc: bool = (span.heap.?.owner_thread != get_thread_id()) and span.heap.?.finalize == 0;
            if (!defer_dealloc) {
                _rpmalloc_deallocate_direct_small_or_medium(span, p);
            } else {
                _rpmalloc_deallocate_defer_small_or_medium(span, p);
            }
        }

        /// Deallocate the given large memory block to the current heap
        fn _rpmalloc_deallocate_large(span: *span_t) void {
            rpmalloc_assert(span.size_class == SIZE_CLASS_LARGE, "Bad span size class");
            rpmalloc_assert(!span.flags.master or !span.flags.subspan, "Span flag corrupted");
            rpmalloc_assert(span.flags.master or span.flags.subspan, "Span flag corrupted");
            //We must always defer (unless finalizing) if from another heap since we cannot touch the list or counters of another heap
            const defer_dealloc: bool = (span.heap.?.owner_thread != get_thread_id()) and span.heap.?.finalize == 0;

            if (defer_dealloc) {
                _rpmalloc_deallocate_defer_free_span(span.heap.?, span);
                return;
            }
            rpmalloc_assert(span.heap.?.full_span_count != 0, "Heap span counter corrupted");
            span.heap.?.full_span_count -= 1;

            const heap: *heap_t = span.heap.?;

            const set_as_reserved = if (ENABLE_THREAD_CACHE)
                ((span.span_count > 1) and (heap.span_cache.count == 0) and heap.finalize == 0 and heap.spans_reserved == 0)
            else
                ((span.span_count > 1) and heap.finalize == 0 and heap.spans_reserved == 0);
            if (set_as_reserved) {
                heap.span_reserve = span;
                heap.spans_reserved = span.span_count;
                if (span.flags.master) {
                    heap.span_reserve_master = span;
                } else { //SPAN_FLAG_SUBSPAN
                    const master: *span_t = @ptrCast(*span_t, @alignCast(@alignOf(span_t), pointer_offset(span, -@intCast(iptr_t, @as(usize, span.offset_from_master) * _memory_span_size.*)).?));
                    heap.span_reserve_master = master;
                    rpmalloc_assert(master.flags.master, "Span flag corrupted");
                    rpmalloc_assert(atomic_load32(&master.remaining_spans) >= span.span_count, "Master span count corrupted");
                }
            } else {
                //Insert into cache list
                _rpmalloc_heap_cache_insert(heap, span);
            }
        }

        /// Deallocate the given huge span
        fn _rpmalloc_deallocate_huge(span: *span_t) void {
            const defer_dealloc: bool = (span.heap.?.owner_thread != get_thread_id()) and span.heap.?.finalize == 0;
            if (defer_dealloc) {
                _rpmalloc_deallocate_defer_free_span(span.heap.?, span);
                return;
            }
            rpmalloc_assert(span.heap.?.full_span_count != 0, "Heap span counter corrupted");
            span.heap.?.full_span_count -= 1;

            //Oversized allocation, page count is stored in span_count
            const num_pages: usize = span.span_count;
            _rpmalloc_unmap(span, num_pages * _memory_page_size, span.align_offset, num_pages * _memory_page_size);
        }

        /// Deallocate the given block
        fn _rpmalloc_deallocate(p: *anyopaque) void {
            //Grab the span (always at start of span, using span alignment)
            const span: *span_t = EXPECTED(@intToPtr(?*span_t, @ptrToInt(p) & _memory_span_mask.*)) orelse return;
            if (EXPECTED(span.size_class < SIZE_CLASS_COUNT)) {
                _rpmalloc_deallocate_small_or_medium(span, p);
            } else if (span.size_class == SIZE_CLASS_LARGE) {
                _rpmalloc_deallocate_large(span);
            } else {
                _rpmalloc_deallocate_huge(span);
            }
        }

        // Reallocation entry points

        /// Flag to rpaligned_realloc to not preserve content in reallocation
        const RPMALLOC_NO_PRESERVE = 1;
        /// Flag to rpaligned_realloc to fail and return null pointer if grow cannot be done in-place,
        /// in which case the original pointer is still valid (just like a call to realloc which failes to allocate
        /// a new block).
        const RPMALLOC_GROW_OR_FAIL = 2;

        /// Reallocate the given block to the given size
        fn _rpmalloc_reallocate(heap: *heap_t, p: *anyopaque, size: usize, oldsize_init: usize, flags: c_uint) ?*anyopaque {
            _ = heap;
            _ = flags;

            var oldsize = oldsize_init;
            //Grab the span using guaranteed span alignment
            const span: *span_t = @intToPtr(*span_t, @ptrToInt(p) & _memory_span_mask.*);
            if (EXPECTED(span.size_class < SIZE_CLASS_COUNT)) {
                // Small/medium sized block
                rpmalloc_assert(span.span_count == 1, "Span counter corrupted");
                const blocks_start: *anyopaque = pointer_offset(span, SPAN_HEADER_SIZE).?;
                const block_offset: u32 = @intCast(u32, pointer_diff(p, blocks_start));
                const block_idx: u32 = block_offset / span.block_size;
                const block: *anyopaque = pointer_offset(blocks_start, @intCast(usize, block_idx) * span.block_size).?;
                if (oldsize == 0) {
                    oldsize = @intCast(usize, @intCast(isize, span.block_size) - pointer_diff(p, block));
                }
                if (@intCast(usize, span.block_size) >= size) {
                    //Still fits in block, never mind trying to save memory, but preserve data if alignment changed
                    if ((p != block)) memmove(block, p, oldsize);
                    return block;
                }
            } else if (span.size_class == SIZE_CLASS_LARGE) {
                //Large block
                const total_size: usize = size + SPAN_HEADER_SIZE;
                var num_spans: usize = total_size >> _memory_span_size_shift.*;
                if (total_size & (_memory_span_mask.* - 1) != 0) {
                    num_spans += 1;
                }
                const current_spans: usize = span.span_count;
                const block: *anyopaque = pointer_offset(span, SPAN_HEADER_SIZE).?;
                if (oldsize == 0) {
                    oldsize = (current_spans * _memory_span_size.*) - @intCast(usize, pointer_diff(p, block)) - SPAN_HEADER_SIZE;
                }
                if ((current_spans >= num_spans) and (total_size >= (oldsize / 2))) {
                    //Still fits in block, never mind trying to save memory, but preserve data if alignment changed
                    if (p != block) memmove(block, p, oldsize);
                    return block;
                }
            } else {
                // Oversized block
                const total_size: usize = size + SPAN_HEADER_SIZE;
                var num_pages: usize = total_size >> _memory_page_size_shift;
                if (total_size & (_memory_page_size - 1) != 0) {
                    num_pages += 1;
                }
                // Page count is stored in span_count
                const current_pages: usize = span.span_count;
                const block: *anyopaque = pointer_offset(span, SPAN_HEADER_SIZE).?;
                if (oldsize == 0) {
                    oldsize = (current_pages * _memory_page_size) - @intCast(usize, pointer_diff(p, block)) - SPAN_HEADER_SIZE;
                }
                if ((current_pages >= num_pages) and (num_pages >= (current_pages / 2))) {
                    //Still fits in block, never mind trying to save memory, but preserve data if alignment changed
                    if (p != block)
                        memmove(block, p, oldsize);
                    return block;
                }
            }

            return null;
        }

        fn _rpmalloc_aligned_reallocate(heap: *heap_t, ptr: *anyopaque, alignment: usize, size: usize, oldsize: usize, flags: c_uint) ?*anyopaque {
            if (alignment <= SMALL_GRANULARITY) {
                return _rpmalloc_reallocate(heap, ptr, size, oldsize, flags);
            }

            const usablesize: usize = _rpmalloc_usable_size(ptr);
            if ((usablesize >= size) and (@ptrToInt(ptr) & (alignment - 1)) == 0) {
                return ptr;
            }

            return null;
        }

        // Initialization, finalization and utility

        /// Get the usable size of the given block
        fn _rpmalloc_usable_size(p: *anyopaque) usize {
            // Grab the span using guaranteed span alignment
            const span: *span_t = @intToPtr(*span_t, @ptrToInt(p) & _memory_span_mask.*);
            if (span.size_class < SIZE_CLASS_COUNT) {
                // Small/medium block
                const blocks_start: *anyopaque = pointer_offset(span, SPAN_HEADER_SIZE).?;
                return span.block_size - @intCast(usize, pointer_diff(p, blocks_start)) % span.block_size;
            }
            if (span.size_class == SIZE_CLASS_LARGE) {
                // Large block
                const current_spans: usize = span.span_count;
                return (current_spans * _memory_span_size.*) - @intCast(usize, pointer_diff(p, span));
            }
            // Oversized block, page count is stored in span_count
            const current_pages: usize = span.span_count;
            return (current_pages * _memory_page_size) - @intCast(usize, pointer_diff(p, span));
        }

        /// Adjust and optimize the size class properties for the given class
        fn _rpmalloc_adjust_size_class(iclass: usize) void {
            const block_size: usize = _memory_size_class[iclass].block_size;
            const block_count: usize = (_memory_span_size.* - SPAN_HEADER_SIZE) / block_size;

            _memory_size_class[iclass].block_count = @intCast(u16, block_count);
            _memory_size_class[iclass].class_idx = @intCast(u16, iclass);

            //Check if previous size classes can be merged
            if (iclass >= SMALL_CLASS_COUNT) {
                var prevclass: usize = iclass;
                while (prevclass > 0) {
                    prevclass -= 1;
                    //A class can be merged if number of pages and number of blocks are equal
                    if (_memory_size_class[prevclass].block_count == _memory_size_class[iclass].block_count) {
                        _memory_size_class[prevclass] = _memory_size_class[iclass];
                    } else {
                        break;
                    }
                }
            }
        }

        /// Initialize the allocator and setup global data
        pub inline fn init() !void {
            if (_rpmalloc_initialized) {
                rpmalloc_thread_initialize();
                return;
            }
            return initConfig(null);
        }

        pub fn initConfig(maybe_config: ?rpmalloc_config_t) !void {
            if (_rpmalloc_initialized) {
                rpmalloc_thread_initialize();
                return;
            }
            _rpmalloc_initialized = true;

            if (maybe_config) |config| {
                _memory_config = config;
            } // otherwise it should already be initialised to all 0 values
            if (cfg.backing_allocator == .runtime) success: {
                fail: {
                    const config = maybe_config orelse break :fail;
                    backing_allocator_mut.* = config.backing_allocator orelse break :fail;
                    break :success;
                }
                @panic("Must specify backing allocator with runtime allocator");
            }

            const windows_system_info = blk: {
                if (builtin.os.tag != .windows) break :blk;
                if (!builtin.os.version_range.windows.isAtLeast(.win2k)) break :blk;

                var windows_system_info: std.os.windows.SYSTEM_INFO = std.mem.zeroInit(std.os.windows.SYSTEM_INFO, .{});
                std.os.windows.kernel32.GetSystemInfo(&windows_system_info);
                break :blk windows_system_info;
            };

            if (builtin.os.tag == .windows) {
                _memory_map_granularity = @intCast(usize, windows_system_info.dwAllocationGranularity);
            } else {
                _memory_map_granularity = std.mem.page_size; // TODO: should we query system info here?
            }

            if (RPMALLOC_CONFIGURABLE) {
                _memory_page_size = _memory_config.page_size;
            } else {
                _memory_page_size = 0;
            }

            _memory_huge_pages = false;
            if (_memory_page_size == 0) {
                if (builtin.os.tag == .windows) {
                    _memory_page_size = windows_system_info.dwPageSize;
                } else {
                    _memory_page_size = _memory_map_granularity;
                    if (_memory_config.enable_huge_pages) {
                        if (builtin.os.tag == .linux) {
                            const huge_page_size: usize = huge_pg_sz: {
                                var line_buf: [128]u8 = undefined;
                                const line: []const u8 = line: {
                                    const meminfo_unbuffered = std.fs.openFileAbsolute("/proc/meminfo", std.fs.File.OpenFlags{}) catch break :huge_pg_sz 0;
                                    defer meminfo_unbuffered.close();

                                    var meminfo_buffered_state = std.io.bufferedReader(meminfo_unbuffered.reader());
                                    const meminfo = meminfo_buffered_state.reader();

                                    while (true) {
                                        const is_expected = meminfo.isBytes("Hugepagesize:") catch break :huge_pg_sz 0;
                                        if (is_expected) break;
                                    } else break :huge_pg_sz 0;

                                    break :line meminfo.readUntilDelimiter(line_buf[0..], '\n') catch break :huge_pg_sz 0;
                                };
                                // that would be sus
                                if (!std.mem.endsWith(u8, line, " kB\n")) break :huge_pg_sz 0;

                                const digits: []const u8 = "0123456789";
                                const num_start = std.mem.indexOfAny(u8, line, digits) orelse break :huge_pg_sz 0;
                                const num_end = num_start + std.mem.lastIndexOfAny(u8, line[num_start..], digits).? + 1;
                                const val = 1024 * (std.fmt.parseUnsigned(usize, line[num_start..num_end], 10) catch break :huge_pg_sz 0);
                                // non-power of 2 would be sus
                                if (@popCount(val) != 1) break :huge_pg_sz 0;
                                break :huge_pg_sz val;
                            };

                            if (huge_page_size != 0) {
                                _memory_huge_pages = true;
                                _memory_page_size = huge_page_size;
                                _memory_map_granularity = huge_page_size;
                            }
                        } else if (builtin.os.tag == .freebsd) {
                            var rc: c_int = undefined;
                            var sz: usize = @sizeOf(@TypeOf(rc));

                            if (std.os.freebsd.sysctlbyname("vm.pmap.pg_ps_enabled", &rc, &sz, null, 0) == 0 and rc == 1) {
                                _memory_huge_pages = 1;
                                _memory_page_size = 2 * 1024 * 1024;
                                _memory_map_granularity = _memory_page_size;
                            }
                        } else if (builtin.os.tag.isDarwin() or builtin.os.tag == .netbsd) {
                            _memory_huge_pages = true;
                            _memory_page_size = 2 * 1024 * 1024;
                            _memory_map_granularity = _memory_page_size;
                        }
                    }
                }
            } else {
                if (_memory_config.enable_huge_pages) {
                    _memory_huge_pages = true;
                }
            }

            if (builtin.os.tag == .windows) {
                if (_memory_config.enable_huge_pages) {
                    var token: ?std.os.windows.HANDLE = null;
                    defer if (token) |tok| std.os.windows.CloseHandle(tok);

                    var large_page_minimum: usize = GetLargePageMinimum();
                    if (large_page_minimum != 0) {
                        OpenProcessToken(std.os.windows.kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token);
                    }
                    if (token != null) {
                        var luid: LUID = undefined;
                        if (LookupPrivilegeValue(0, SE_LOCK_MEMORY_NAME, &luid)) {
                            var token_privileges: TOKEN_PRIVILEGES = std.mem.zeroInit(TOKEN_PRIVILEGES, .{});
                            token_privileges.PrivilegeCount = 1;
                            token_privileges.Privileges[0].Luid = luid;
                            token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                            if (AdjustTokenPrivileges(token, std.os.windows.FALSE, &token_privileges, 0, 0, 0)) {
                                if (std.os.windows.user32.GetLastError() == .SUCCESS) {
                                    _memory_huge_pages = true;
                                }
                            }
                        }
                    }
                    if (_memory_huge_pages) {
                        if (large_page_minimum > _memory_page_size) {
                            _memory_page_size = large_page_minimum;
                        }
                        if (large_page_minimum > _memory_map_granularity) {
                            _memory_map_granularity = large_page_minimum;
                        }
                    }
                }
            }

            const min_span_size: usize = 256;
            const max_page_size: usize = if (std.math.maxInt(uptr_t) > 0xFFFF_FFFF)
                (4096 * 1024 * 1024)
            else
                (4 * 1024 * 1024);
            _memory_page_size = std.math.clamp(_memory_page_size, min_span_size, max_page_size);
            _memory_page_size_shift = 0;
            var page_size_bit: usize = _memory_page_size;
            while (page_size_bit != 1) {
                _memory_page_size_shift += 1;
                page_size_bit >>= 1;
            }
            _memory_page_size = @as(usize, 1) << _memory_page_size_shift;

            if (RPMALLOC_CONFIGURABLE) {
                if (_memory_config.span_size == 0) {
                    _memory_span_size.* = _memory_default_span_size;
                    _memory_span_size_shift.* = _memory_default_span_size_shift;
                    _memory_span_mask.* = _memory_default_span_mask();
                } else {
                    var span_size: usize = _memory_config.span_size;
                    if (span_size > (256 * 1024)) {
                        span_size = (256 * 1024);
                    }
                    _memory_span_size.* = 4096;
                    _memory_span_size_shift.* = 12;
                    while (_memory_span_size.* < span_size) {
                        _memory_span_size.* <<= 1;
                        _memory_span_size_shift.* += 1;
                    }
                    _memory_span_mask.* = ~@as(uptr_t, _memory_span_size.* - 1);
                }
            }

            _memory_span_map_count = if (_memory_config.span_map_count != 0) _memory_config.span_map_count else DEFAULT_SPAN_MAP_COUNT;
            if ((_memory_span_size.* * _memory_span_map_count) < _memory_page_size) {
                _memory_span_map_count = (_memory_page_size / _memory_span_size.*);
            }
            if ((_memory_page_size >= _memory_span_size.*) and ((_memory_span_map_count * _memory_span_size.*) % _memory_page_size) != 0) {
                _memory_span_map_count = (_memory_page_size / _memory_span_size.*);
            }
            _memory_heap_reserve_count = if (_memory_span_map_count > DEFAULT_SPAN_MAP_COUNT) DEFAULT_SPAN_MAP_COUNT else _memory_span_map_count;

            _memory_config.page_size = _memory_page_size;
            _memory_config.span_size = _memory_span_size.*;
            _memory_config.span_map_count = _memory_span_map_count;
            _memory_config.enable_huge_pages = _memory_huge_pages;

            if (builtin.os.tag == .windows and (builtin.link_mode != .Dynamic)) {
                fls_key = FlsAlloc(&_rpmalloc_thread_destructor);
            }

            // Setup all small and medium size classes
            var iclass: usize = 0;
            _memory_size_class[iclass].block_size = SMALL_GRANULARITY;
            _rpmalloc_adjust_size_class(iclass);
            iclass = 1;
            while (iclass < SMALL_CLASS_COUNT) : (iclass += 1) {
                const size: usize = iclass * SMALL_GRANULARITY;
                _memory_size_class[iclass].block_size = @intCast(u32, size);
                _rpmalloc_adjust_size_class(iclass);
            }

            //At least two blocks per span, then fall back to large allocations
            _memory_medium_size_limit = (_memory_span_size.* - SPAN_HEADER_SIZE) >> 1;
            if (_memory_medium_size_limit > MEDIUM_SIZE_LIMIT) {
                _memory_medium_size_limit = MEDIUM_SIZE_LIMIT;
            }
            iclass = 0;
            while (iclass < MEDIUM_CLASS_COUNT) : (iclass += 1) {
                const size: usize = SMALL_SIZE_LIMIT + ((iclass + 1) * MEDIUM_GRANULARITY);
                if (size > _memory_medium_size_limit) break;
                _memory_size_class[SMALL_CLASS_COUNT + iclass].block_size = @intCast(u32, size);
                _rpmalloc_adjust_size_class(SMALL_CLASS_COUNT + iclass);
            }

            _memory_orphan_heaps = null;
            _memory_heaps = .{null} ** _memory_heaps.len;
            releaseLock(&_memory_global_lock);

            //Initialize this thread
            rpmalloc_thread_initialize();
            return;
        }

        /// Finalize the allocator
        pub fn deinit() void {
            rpmalloc_thread_finalize(true);
            //rpmalloc_dump_statistics(stdout);

            if (_memory_global_reserve != null) {
                _ = atomic_add32(&_memory_global_reserve_master.?.remaining_spans, -@intCast(i32, _memory_global_reserve_count));
                _memory_global_reserve_master = null;
                _memory_global_reserve_count = 0;
                _memory_global_reserve = null;
            }
            releaseLock(&_memory_global_lock);

            // Free all thread caches and fully free spans
            {
                var list_idx: usize = 0;
                while (list_idx < HEAP_ARRAY_SIZE) : (list_idx += 1) {
                    var maybe_heap: ?*heap_t = _memory_heaps[list_idx];
                    while (maybe_heap) |heap| {
                        const next_heap: ?*heap_t = heap.next_heap;
                        heap.finalize = 1;
                        _rpmalloc_heap_global_finalize(heap);
                        maybe_heap = next_heap;
                    }
                }
            }

            if (ENABLE_GLOBAL_CACHE) {
                //Free global caches
                var iclass: usize = 0;
                while (iclass < LARGE_CLASS_COUNT) : (iclass += 1) {
                    _rpmalloc_global_cache_finalize(&_memory_span_cache[iclass]);
                }
            }

            if (is_windows_and_not_dynamic) {
                FlsFree(fls_key);
                fls_key = 0;
            }

            _rpmalloc_initialized = false;
        }

        /// Initialize thread, assign heap
        pub fn rpmalloc_thread_initialize() void {
            if (get_thread_heap_raw() == null) {
                if (_rpmalloc_heap_allocate()) |heap| {
                    set_thread_heap(heap);
                    if (is_windows_and_not_dynamic) {
                        FlsSetValue(fls_key, heap);
                    }
                }
            }
        }

        /// Finalize thread, orphan heap
        pub fn rpmalloc_thread_finalize(release_caches: bool) void {
            if (get_thread_heap_raw()) |heap| {
                _rpmalloc_heap_release_raw(heap, release_caches);
            }
            set_thread_heap(null);
            if (is_windows_and_not_dynamic) {
                FlsSetValue(fls_key, 0);
            }
        }

        pub fn rpmalloc_is_thread_initialized() bool {
            return get_thread_heap_raw() != null;
        }

        pub inline fn rpmalloc_config() *const rpmalloc_config_t {
            return &_memory_config;
        }

        pub inline fn rpmalloc(size: usize) ?*anyopaque {
            if (size >= MAX_ALLOC_SIZE()) return null;
            const heap: *heap_t = get_thread_heap();
            return _rpmalloc_allocate(heap, size);
        }

        pub inline fn rpfree(ptr: *anyopaque) void {
            _rpmalloc_deallocate(ptr);
        }

        pub inline fn rprealloc(ptr: *anyopaque, size: usize) ?*anyopaque {
            if (size >= MAX_ALLOC_SIZE()) return ptr;
            const heap: *heap_t = get_thread_heap();
            return _rpmalloc_reallocate(heap, ptr, size, 0, 0);
        }

        pub fn rpaligned_realloc(ptr: *anyopaque, alignment: usize, size: usize, oldsize: usize, flags: c_uint) ?*anyopaque {
            if ((size +% alignment < size) or (alignment > _memory_page_size)) {
                return null;
            }
            const heap: *heap_t = get_thread_heap();
            return _rpmalloc_aligned_reallocate(heap, ptr, alignment, size, oldsize, flags);
        }

        pub inline fn rpaligned_alloc(alignment: usize, size: usize) ?*anyopaque {
            const heap: *heap_t = get_thread_heap();
            return _rpmalloc_aligned_allocate(heap, alignment, size);
        }
        pub const rpmalloc_config_t = struct {
            backing_allocator: if (cfg.backing_allocator == .runtime) ?std.mem.Allocator else ?noreturn = null,
            /// Called when a call to map memory pages fails (out of memory). If this callback is
            /// not set or returns zero the library will return a null pointer in the allocation
            /// call. If this callback returns non-zero the map call will be retried. The argument
            /// passed is the number of bytes that was requested in the map call. Only used if
            /// the default system memory map function is used (memory_map callback is not set).
            // int (*map_fail_callback)(size_t size);
            map_fail_callback: ?*const fn (size: usize) bool = null,
            /// Size of memory pages. The page size MUST be a power of two. All memory mapping
            /// requests to memory_map will be made with size set to a multiple of the page size.
            /// Used if RPMALLOC_CONFIGURABLE is defined to 1, otherwise system page size is used.
            page_size: usize = 0,
            /// Size of a span of memory blocks. MUST be a power of two, and in [4096,262144]
            /// range (unless 0 - set to 0 to use the default span size). Used if RPMALLOC_CONFIGURABLE
            /// is defined to 1.
            span_size: usize = 0,
            /// Number of spans to map at each request to map new virtual memory blocks. This can
            /// be used to minimize the system call overhead at the cost of virtual memory address
            /// space. The extra mapped pages will not be written until actually used, so physical
            /// committed memory should not be affected in the default implementation. Will be
            /// aligned to a multiple of spans that match memory page size in case of huge pages.
            span_map_count: usize = 0,
            /// Enable use of large/huge pages. If this flag is set to non-zero and page size is
            /// zero, the allocator will try to enable huge pages and auto detect the configuration.
            /// If this is set to non-zero and page_size is also non-zero, the allocator will
            /// assume huge pages have been configured and enabled prior to initializing the
            /// allocator.
            /// For Windows, see https://docs.microsoft.com/en-us/windows/desktop/memory/large-page-support
            /// For Linux, see https://www.kernel.org/doc/Documentation/vm/hugetlbpage.txt
            enable_huge_pages: bool = false,
            /// Allocated pages names for systems
            /// supporting it to be able to distinguish among anonymous regions.
            // const char *page_name;
            page_name: ?[*:0]const u8 = null,
            /// Huge allocated pages names for systems
            /// supporting it to be able to distinguish among anonymous regions.
            // const char *huge_page_name;
            huge_page_name: ?[*:0]const u8 = null,
        };
    };
}

const uptr_t = std.meta.Int(.unsigned, @bitSizeOf(*anyopaque));
const iptr_t = std.meta.Int(.signed, @bitSizeOf(*anyopaque));
comptime {
    std.debug.assert(std.meta.eql(@typeInfo(uptr_t).Int, @typeInfo(usize).Int));
    std.debug.assert(std.meta.eql(@typeInfo(iptr_t).Int, @typeInfo(isize).Int));
}

/// `same as --x` in C.
inline fn decrementAndCopy(x: anytype) @TypeOf(x.*) {
    x.* -= 1;
    return x.*;
}
/// same as `x--` in C.
inline fn copyThenDecrement(x: anytype) @TypeOf(x.*) {
    const result = x.*;
    x.* -= 1;
    return result;
}
/// same as `++x` in C.
inline fn incrementAndCopy(x: anytype) @TypeOf(x.*) {
    x.* += 1;
    return x.*;
}
/// same as `x++` in C.
inline fn copyThenIncrement(x: anytype) @TypeOf(x.*) {
    const result = x.*;
    x.* += 1;
    return result;
}

inline fn memcpy(noalias dst: anytype, noalias src: anytype, size: usize) void {
    @memcpy(@ptrCast([*]u8, dst), @ptrCast([*]const u8, src), size);
}
inline fn memmove(p_dst: anytype, p_src: anytype, size: usize) void {
    const dst = @ptrCast([*]u8, p_dst)[0..size];
    const src = @ptrCast([*]u8, p_src)[0..size];
    switch (std.math.order(@ptrToInt(dst.ptr), @ptrToInt(src.ptr))) {
        .eq => {},
        .lt => std.mem.copy(u8, dst, src),
        .gt => std.mem.copyBackwards(u8, dst, src),
    }
}

const FlsAlloc = @compileError("windows stub");
const FlsFree = @compileError("windows stub");
const FlsSetValue = @compileError("windows stub");
const GetLargePageMinimum = @compileError("windows stub");
const OpenProcessToken = @compileError("windows stub");
const LookupPrivilegeValue = @compileError("windows stub");
const TOKEN_ADJUST_PRIVILEGES = @compileError("windows stub");
const TOKEN_QUERY = @compileError("windows stub");
const LUID = @compileError("windows stub");
const SE_LOCK_MEMORY_NAME = @compileError("windows stub");
const TOKEN_PRIVILEGES = @compileError("windows stub");
const SE_PRIVILEGE_ENABLED = @compileError("windows stub");
const AdjustTokenPrivileges = @compileError("windows stub");

inline fn rpmalloc_assert(truth: bool, message: []const u8) void {
    if (!truth) @panic(message);
}

// typedef volatile _Atomic(int32_t) atomic32_t;
const atomic32_t = i32;
// typedef volatile _Atomic(int64_t) atomic64_t;
const atomic64_t = i64;
// typedef volatile _Atomic(void*) atomicptr_t;

// static FORCEINLINE int32_t atomic_load32(atomic32_t* src) { return atomic_load_explicit(src, memory_order_relaxed); }
inline fn atomic_load32(src: *const atomic32_t) atomic32_t {
    return @atomicLoad(atomic32_t, src, .Monotonic);
}

// static FORCEINLINE void    atomic_store32(atomic32_t* dst, int32_t val) { atomic_store_explicit(dst, val, memory_order_relaxed); }
inline fn atomic_store32(dst: *atomic32_t, val: atomic32_t) void {
    @atomicStore(atomic32_t, dst, val, .Monotonic);
}

// static FORCEINLINE int32_t atomic_incr32(atomic32_t* val) { return atomic_fetch_add_explicit(val, 1, memory_order_relaxed) + 1; }
inline fn atomic_incr32(val: *atomic32_t) atomic32_t {
    return @atomicRmw(atomic32_t, val, .Add, 1, .Monotonic) + 1;
}

// static FORCEINLINE int32_t atomic_decr32(atomic32_t* val) { return atomic_fetch_add_explicit(val, -1, memory_order_relaxed) - 1; }
inline fn atomic_decr32(val: *atomic32_t) atomic32_t {
    return @atomicRmw(atomic32_t, val, .Sub, 1, .Monotonic) - 1;
}

// static FORCEINLINE int32_t atomic_add32(atomic32_t* val, int32_t add) { return atomic_fetch_add_explicit(val, add, memory_order_relaxed) + add; }
inline fn atomic_add32(val: *atomic32_t, add: atomic32_t) atomic32_t {
    return @atomicRmw(atomic32_t, val, .Add, add, .Monotonic) + add;
}

// static FORCEINLINE int     atomic_cas32_acquire(atomic32_t* dst, int32_t val, int32_t ref) { return atomic_compare_exchange_weak_explicit(dst, &ref, val, memory_order_acquire, memory_order_relaxed); }
inline fn atomic_cas32_acquire(dst: *atomic32_t, val: atomic32_t, ref: atomic32_t) bool {
    return @cmpxchgWeak(atomic32_t, dst, ref, val, .Acquire, .Monotonic) == null;
}

// static FORCEINLINE void    atomic_store32_release(atomic32_t* dst, int32_t val) { atomic_store_explicit(dst, val, memory_order_release); }
inline fn atomic_store32_release(dst: *atomic32_t, val: atomic32_t) void {
    @atomicStore(atomic32_t, dst, val, .Release);
}

// static FORCEINLINE int64_t atomic_load64(atomic64_t* val) { return atomic_load_explicit(val, memory_order_relaxed); }
inline fn atomic_load64(val: *const atomic64_t) atomic64_t {
    return @atomicLoad(atomic64_t, val, .Monotonic);
}

// static FORCEINLINE int64_t atomic_add64(atomic64_t* val, int64_t add) { return atomic_fetch_add_explicit(val, add, memory_order_relaxed) + add; }
inline fn atomic_add64(val: *atomic64_t, add: atomic64_t) atomic64_t {
    return @atomicRmw(atomic64_t, val, .Add, add, .Monotonic) + add;
}

// static FORCEINLINE void*   atomic_load_ptr(atomicptr_t* src) { return atomic_load_explicit(src, memory_order_relaxed); }
inline fn atomic_load_ptr(src: anytype) @TypeOf(src.*) {
    return @atomicLoad(@TypeOf(src.*), src, .Monotonic);
}

// static FORCEINLINE void    atomic_store_ptr(atomicptr_t* dst, void* val) { atomic_store_explicit(dst, val, memory_order_relaxed); }
inline fn atomic_store_ptr(dst: anytype, val: @TypeOf(dst.*)) void {
    @atomicStore(@TypeOf(dst.*), dst, val, .Monotonic);
}

// static FORCEINLINE void    atomic_store_ptr_release(atomicptr_t* dst, void* val) { atomic_store_explicit(dst, val, memory_order_release); }
inline fn atomic_store_ptr_release(dst: anytype, val: @TypeOf(dst.*)) void {
    @atomicStore(@TypeOf(dst.*), dst, val, .Release);
}

// static FORCEINLINE void*   atomic_exchange_ptr_acquire(atomicptr_t* dst, void* val) { return atomic_exchange_explicit(dst, val, memory_order_acquire); }
inline fn atomic_exchange_ptr_acquire(dst: anytype, val: @TypeOf(dst.*)) @TypeOf(dst.*) {
    return @atomicRmw(@TypeOf(dst.*), dst, .Xchg, val, .Acquire);
}

// static FORCEINLINE int     atomic_cas_ptr(atomicptr_t* dst, void* val, void* ref) { return atomic_compare_exchange_weak_explicit(dst, &ref, val, memory_order_relaxed, memory_order_relaxed); }
inline fn atomic_cas_ptr(dst: anytype, val: @TypeOf(dst.*), ref: @TypeOf(dst.*)) bool {
    return @cmpxchgWeak(@TypeOf(dst.*), dst, ref, val, .Monotonic, .Monotonic) == null;
}

inline fn EXPECTED(x: anytype) @TypeOf(x) {
    return x;
}

inline fn UNEXPECTED(x: anytype) @TypeOf(x) {
    return x;
}

inline fn acquireLock(lock: *i32) void {
    while (@cmpxchgWeak(i32, lock, 0, 1, .Acquire, .Monotonic) != null) {
        std.atomic.spinLoopHint();
    }
}
inline fn releaseLock(lock: *i32) void {
    atomic_store32_release(lock, 0);
}

const INVALID_POINTER = @intToPtr(*anyopaque, std.math.maxInt(uptr_t));
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
inline fn LARGE_SIZE_LIMIT(_memory_span_size: anytype) @TypeOf(_memory_span_size) {
    return ((LARGE_CLASS_COUNT * _memory_span_size) - SPAN_HEADER_SIZE);
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

const SpanFlags = packed struct(u32) {
    /// Flag indicating span is the first (master) span of a split superspan
    // C Name: SPAN_FLAG_MASTER
    master: bool = false,
    /// Flag indicating span is a secondary (sub) span of a split superspan
    // C Name: SPAN_FLAG_SUBSPAN
    subspan: bool = false,
    /// Flag indicating span has blocks with increased alignment
    // C Name: SPAN_FLAG_ALIGNED_BLOCKS
    aligned_blocks: bool = false,
    /// Flag indicating an unmapped master span
    // C Name: SPAN_FLAG_UNMAPPED_MASTER
    unmapped_master: bool = false,

    _pad: enum(u28) { unset } = .unset,

    inline fn value(flags: SpanFlags) u32 {
        return @bitCast(u32, flags);
    }

    inline fn from(val: u32) SpanFlags {
        return SpanFlags.from(val);
    }
};
