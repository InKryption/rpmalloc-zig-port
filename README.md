# rpmalloc zig port
This project is an attempt to make a fast general-purpose allocator for zig. It is mostly derived from [rpmalloc](https://github.com/mjansson/rpmalloc), using the same general structure and mostly retaining the essential strategies that make it fast, though with many options and facets stripped down or modified to suit Zig.

## WIP
This project is under development, does not guarantee a stable API and lacks documentation and tests.
Contributions, in the form of PRs and relevant resources, are greatly appreciated.

## Usage
If you cloned the repository, or vendor it as a git submodule or similar, you can just add the main source file as a module like so:
```zig
exe.addAnonymousModule("rpmalloc", .{ .source_file = .{ .path = "<path to repo>/src/rpmalloc.zig" } });
```
However, if you want to use the zig package manager, the recommended process (at the time of writing) is as follows:
1. Get the SHA of the commit you want to depend on.
2. Make sure you have something akin to the following in your build.zig.zon file:
```zig
    .dependencies = .{
        // -- snip --
        .@"rpmalloc-zig-port" = .{
            .url = "https://github.com/InKryption/rpmalloc-zig-port/archive/<commit SHA>.tar.gz",
            .hash = <hash>, // you can get the expected value by running `zig build` while omitting this field.
        },
    },
```
3. Add something akin to the following to your build.zig file:
```zig
    const rpmalloc_dep = b.dependency("rpmalloc-zig-port", .{});
    const rpmalloc_module = rpmalloc_dep.module("rpmalloc");
    exe.addModule("rpmalloc", rpmalloc_module);
```

and then import and use it:
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
It should be noted that this allocator is indeed a singleton, much like in the original C source, with an important distinction being that you can concurrently have different permutations based on the configuration.

## Notes
* There are a good few TODO comments in the code, comprised mostly of uncertanties on as to the benefits or semantics of certain parts of the code.
* At the time of writing, the port runs marginally slower than the original C source in the benchmark when linked statically, and notably slower when linked dynamically.
* I've opted to remove most code related to partial unmapping, as it's not a pattern that is well-suited to Zig (or at least that I couldn't figure out how to map to Zig's prototypical allocator patterns).
