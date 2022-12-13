# rpmalloc zig port

This project is an attempt to make a fast general-purpose allocator for zig. It is mostly derived from [rpmalloc](https://github.com/mjansson/rpmalloc), using the same general structure and mostly retaining the essential strategies that make it fast, though with many options and facets stripped down or modified to suit Zig.

Included as a git sumbodule at present is [rpmalloc-benchmark](https://github.com/mjansson/rpmalloc-benchmark), which can be compiled and run using either the Zig port, or the original C implementation, by executing the build.zig file:
```zig
zig build bench -D=[c|zig]
```
