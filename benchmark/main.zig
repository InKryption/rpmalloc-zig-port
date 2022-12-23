const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const build_options = @import("build-options");
const compile_err = struct {
    const unknown_impl: noreturn = @compileError("unknown allocator implementation '" ++ @tagName(build_options.impl) ++ "'.\n");
    const dont_reference: noreturn = @compileError("don't reference.\n");
    const todo: noreturn = @compileError("TODO: implement for '" ++ @tagName(build_options.impl) ++ "'.\n");
};

const rp = if (build_options.impl == .@"rp-zig") @import("rpmalloc") else compile_err.dont_reference;
const Rp = rp.RPMalloc(.{});

var gpa: std.heap.GeneralPurposeAllocator(.{}) = if (build_options.impl == .gpa) undefined else compile_err.dont_reference;

pub fn main() !void {
    const CmdArgs = struct {
        seed: u64,
    };
    const cmd_args: CmdArgs = try struct {
        var buf: [@max(1, build_options.cmd_args_buffer_size orelse 4096)]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&buf);
        inline fn cmdArgs() !CmdArgs {
            var buffered_stderr = std.io.bufferedWriter(std.io.getStdErr().writer());
            defer buffered_stderr.flush() catch {};
            const stderr = buffered_stderr.writer();

            var args_iter = try std.process.argsWithAllocator(fba.allocator());
            defer args_iter.deinit();

            var results: struct {
                seed: ?union(enum) { auto, value: u64 } = null,
            } = .{};
            comptime for (@typeInfo(@TypeOf(results)).Struct.fields) |field| {
                if (std.mem.indexOfScalar(u8, field.name, '=') != null)
                    @compileError("Argument names shouldn't have equal signs, but found one in '" ++ field.name ++ "'.\n");
            };
            const ArgNameTok = std.meta.FieldEnum(@TypeOf(results));

            if (!args_iter.skip()) @panic("command line arguments don't contain executable path\n");

            while (args_iter.next()) |whole_str| {
                if (!std.mem.startsWith(u8, whole_str, "--") or
                    whole_str["--".len..].len == 0 or
                    whole_str["--".len] == '=')
                {
                    stderr.print("Expected `--[name]=[value]`, instead found `{s}`.\n", .{whole_str}) catch {};
                    return error.InvalidPositional;
                }
                const kv_str = whole_str["--".len..];

                const maybe_eql_idx = std.mem.indexOfScalar(u8, kv_str, '=');
                const name_str: []const u8 = kv_str[0 .. maybe_eql_idx orelse kv_str.len];
                const maybe_value_str: ?[]const u8 = if (maybe_eql_idx) |idx| kv_str[idx + 1 ..] else null;

                assert(name_str.len != 0);
                const name: ArgNameTok = std.meta.stringToEnum(ArgNameTok, name_str) orelse {
                    stderr.print("Unrecognized argument '{s}'.\n", .{name_str}) catch {};
                    return error.UnrecognizedArgument;
                };

                switch (name) {
                    .seed => {
                        if (maybe_value_str) |value_str| {
                            if (value_str.len == 0) {
                                stderr.print("Expected value after '--{s}='.\n", .{@tagName(name)}) catch {};
                                return error.MissingArgumentValue;
                            }
                        } else {
                            stderr.print("Expected '=' followed by value after '--{s}'.\n", .{@tagName(name)}) catch {};
                            return error.MissingArgumentValue;
                        }
                    },
                }

                switch (name) {
                    .seed => {
                        const value_str = maybe_value_str.?;
                        results.seed = if (std.mem.eql(u8, value_str, "auto"))
                            .auto
                        else .{ .value = std.fmt.parseUnsigned(u64, value_str, 0) catch {
                            stderr.print("Failed to parse '{s}' as 64 bit unsigned integer.\n", .{value_str}) catch {};
                            return error.InvalidArgumentValue;
                        } };
                    },
                }

                inline for (comptime std.enums.values(ArgNameTok)) |field| {
                    // if any field is null (meaning it hasn't been set), break the for loop to
                    // avoid hitting its else branch, which would break the outer while loop.
                    if (@field(results, @tagName(field)) == null) break;
                } else break;
            }
            if (args_iter.skip()) return error.TooManyArguments;

            return CmdArgs{
                .seed = switch (results.seed orelse .auto) {
                    .auto => std.crypto.random.int(u64),
                    .value => |value| value,
                },
            };
        }
    }.cmdArgs();
    std.log.debug("command line arguments: {}\n", .{cmd_args});

    const PrngImpl = @field(std.rand, @tagName(build_options.prng));
    var prng = PrngImpl.init(cmd_args.seed);
    const random: std.rand.Random = prng.random();
    _ = random;

    switch (build_options.impl) {
        .@"rp-zig" => try Rp.init(null, .{}),
        .@"rp-c" => compile_err.todo,
        .gpa => gpa = .{},
        else => compile_err.unknown_impl,
    }
    defer switch (build_options.impl) {
        .@"rp-zig" => Rp.deinit(),
        .@"rp-c" => @compileError("todo"),
        .gpa => _ = gpa.deinit(),
        else => compile_err.unknown_impl,
    };
    const allocator: Allocator = switch (build_options.impl) {
        .@"rp-zig" => Rp.allocator(),
        .@"rp-c" => compile_err.todo,
        .gpa => gpa.allocator(),
        else => compile_err.unknown_impl,
    };
    _ = allocator;

    @panic("TODO: Do benchmarking");
}
