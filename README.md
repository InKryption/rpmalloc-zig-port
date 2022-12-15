# rpmalloc zig port
This project is an attempt to make a fast general-purpose allocator for zig. It is mostly derived from [rpmalloc](https://github.com/mjansson/rpmalloc), using the same general structure and mostly retaining the essential strategies that make it fast, though with many options and facets stripped down or modified to suit Zig.

Included as a git sumbodule at present is [rpmalloc-benchmark](https://github.com/mjansson/rpmalloc-benchmark), which can be compiled and run using either the Zig port, or the original C implementation, by executing the build.zig file:
```
zig build bench -D=[port|original|...]
```

## WIP
At present this leaks memory.
This project is under development, does not guarantee a stable API and lacks documentation and tests.
Contributions, in the form of PRs and relevant resources, are greatly appreciated.

## Usage
It's quite trivial to use, just add some code along the lines of
```zig
exe.addPackagePath("rpmalloc", "path/to/rpmalloc/src/rpmalloc.zig");
```
to your build.zig, and then import it and use like so:
```zig
const rpmalloc = @import("rpmalloc");
const Rp = rpmalloc.RPMalloc(.{});

pub fn main() !void {
    try Rp.init(null, .{});
    defer Rp.deinit();

    const allocator = Rp.allocator();
    // -- snip --
}
```
Although it should be clear from the example, I'll note that this allocator is indeed a singleton, much like in the original C source, with an important distinction being that you can concurrently have different permutations based on the configuration.

## Notes
* There are a good few TODO comments in the code, comprised mostly of uncertanties on as to the benefits or semantics of certain parts of the code.
* At the time of writing, the port runs marginally slower than the original C source in the benchmark when linked statically, and notably slower when linked dynamically.
* I've opted to remove most code related to partial unmapping, as it's not a pattern that is well-suited to Zig (or at least that I couldn't figure out how to map to Zig's prototypical allocator patterns).
