const std = @import("std");
const assert = std.debug.assert;

const build_options = @import("build-options");
const compile_err = struct {
    const unknown_impl: noreturn = @compileError("unknown allocator implementation '" ++ @tagName(build_options.impl) ++ "'.\n");
    const dont_reference: noreturn = @compileError("don't reference.\n");
    const todo: noreturn = @compileError("TODO: implement for '" ++ @tagName(build_options.impl) ++ "'.\n");
};

pub const log_level = build_options.log_level;

const rp = if (build_options.impl == .@"rp-zig") @import("rpmalloc") else compile_err.dont_reference;
const Rp = rp.RPMalloc(.{});

var gpa: std.heap.GeneralPurposeAllocator(.{}) = if (build_options.impl == .gpa) (.{}) else compile_err.dont_reference;

pub fn main() !void {
    const CmdArgs = struct {
        seed: u64,
        loop_count: u64,
        min_size: u64,
        max_size: u64,
    };
    const cmd_args: CmdArgs = struct {
        var buf: [@max(1, build_options.cmd_args_buffer_size orelse 4096)]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&buf);
        inline fn cmdArgs() !CmdArgs {
            const ArgResults = std.enums.EnumFieldStruct(std.meta.FieldEnum(CmdArgs), ?u64, @as(?u64, null));
            const ArgName = comptime ArgName: {
                const old_fields = @typeInfo(std.meta.FieldEnum(CmdArgs)).Enum.fields;
                var fields: [old_fields.len]std.builtin.Type.EnumField = old_fields[0..].*;
                for (&fields) |*field| field.name = replaceScalarComptime(field.name, '_', '-');
                break :ArgName @Type(.{ .Enum = std.builtin.Type.Enum{
                    .tag_type = std.math.IntFittingRange(0, fields.len - 1),
                    .fields = &fields,
                    .decls = &.{},
                    .is_exhaustive = true,
                } });
            };

            var results: ArgResults = .{};

            var args_iter = try std.process.argsWithAllocator(fba.allocator());
            defer args_iter.deinit();

            if (!args_iter.skip()) @panic("command line arguments don't contain executable path\n");

            while (args_iter.next()) |whole_str| {
                if (whole_str.len == 0) {
                    std.log.warn("Empty command line argument token", .{});
                    continue;
                }
                if (!std.mem.startsWith(u8, whole_str, "--")) {
                    if (whole_str[0] == '-') {
                        std.log.err("Argument name must be preceded by two dashes, but there's only one in `{s}`.\n", .{whole_str});
                    } else {
                        std.log.err("Expected `--[name]=[value]`, got `{s}`.\n", .{whole_str});
                    }
                    return error.InvalidPositional;
                }
                const kv_string = whole_str["--".len..];
                if (kv_string.len == 0 or kv_string[0] == '=') {
                    std.log.err("Expeced `--[name]=[value]`, got `{s}`.\n", .{whole_str});
                    return error.MissingArgumentName;
                }
                const name_str: []const u8 = kv_string[0 .. std.mem.indexOfScalar(u8, kv_string, '=') orelse kv_string.len];
                const value_str: ?[]const u8 = if (name_str.len == kv_string.len) null else kv_string[name_str.len + 1 ..];

                const name: ArgName = std.meta.stringToEnum(ArgName, name_str) orelse {
                    std.log.err("Unrecognized argument name '{s}'.\n", .{name_str});
                    return error.UnrecognizedArgumentName;
                };
                switch (name) {
                    inline else => |iname| {
                        const iname_str = @tagName(iname);
                        const field_name = replaceScalarComptime(iname_str, '-', '_');
                        if (@field(results, field_name) != null) {
                            std.log.err("Specified argument '{s}' twice.\n", .{iname_str});
                            return error.DuplicateArgument;
                        }

                        const val_str = value_str orelse {
                            std.log.err("Missing value for argument '{s}'.\n", .{iname_str});
                            return error.MissingArgumentValue;
                        };
                        if (val_str.len == 0) {
                            std.log.err("Missing value for argument '{s}'.\n", .{iname_str});
                            return error.MissingArgumentValue;
                        }
                        @field(results, field_name) = std.fmt.parseUnsigned(u64, val_str, 0) catch |err| {
                            std.log.err("({s}) Couldn't parse '{s}' as value for '{s}', of type {s}.\n", .{
                                @errorName(err),
                                val_str,
                                iname_str,
                                @typeName(@TypeOf(@field(@as(CmdArgs, undefined), field_name))),
                            });
                            return error.InvalidArgumentValue;
                        };
                    },
                }
            }

            var cmd_args = CmdArgs{
                .seed = results.seed orelse int: {
                    var int: u64 = 0;
                    try std.os.getrandom(std.mem.asBytes(&int));
                    break :int int;
                },
                .loop_count = results.loop_count orelse 1000,
                .min_size = results.min_size orelse 8,
                .max_size = results.max_size orelse 4096,
            };

            if (cmd_args.loop_count == 0) {
                const default_loop_count = 1000;
                std.log.warn("Loop count must be greater than 0. Defaulting to {d}\n", .{default_loop_count});
                cmd_args.loop_count = default_loop_count;
            }
            if (cmd_args.min_size > cmd_args.max_size) {
                std.log.err("Minimum size must be less than or equal to maximum size.\n", .{});
                return error.IncompatibleArgumentValues;
            }

            return cmd_args;
        }
    }.cmdArgs() catch return;

    std.log.debug("Command line arguments:", .{});
    inline for (@typeInfo(CmdArgs).Struct.fields) |field| {
        std.log.debug("  {s} = {any}", .{ field.name, @field(cmd_args, field.name) });
    }

    const PrngImpl = if (build_options.prng) |prng| @field(std.rand, @tagName(prng)) else struct {
        inline fn init(s: u64) @This() {
            _ = s;
            return .{};
        }

        inline fn random(this: *@This()) std.rand.Random {
            return std.rand.Random{
                .ptr = this,
                .fillFn = noopFill,
            };
        }

        fn noopFill(ptr: *anyopaque, bytes: []u8) void {
            _ = ptr;
            _ = bytes;
            unreachable;
        }
    };
    var prng = PrngImpl.init(cmd_args.seed);
    const random: std.rand.Random = prng.random();
    _ = random;

    // initialise
    switch (build_options.impl) {
        .@"rp-zig" => try Rp.init(null, .{}),
        .@"rp-c" => compile_err.todo,
        .gpa => gpa = .{},
        else => compile_err.unknown_impl,
    }
    // deinitialise
    defer switch (build_options.impl) {
        .@"rp-zig" => Rp.deinit(),
        .@"rp-c" => @compileError("todo"),
        .gpa => _ = gpa.deinit(),
        else => compile_err.unknown_impl,
    };

    const allocator: std.mem.Allocator = switch (build_options.impl) {
        .@"rp-zig" => Rp.allocator(),
        .@"rp-c" => compile_err.todo,
        .gpa => gpa.allocator(),
        else => compile_err.unknown_impl,
    };
    _ = allocator;

    @panic("TODO: Do benchmarking");
}

inline fn replaceScalarComptime(comptime input: []const u8, comptime needle: u8, comptime replacement: u8) *const [input.len]u8 {
    comptime {
        var result: [input.len]u8 = input[0..].*;
        for (&result) |*c| {
            if (c.* == needle) c.* = replacement;
        }
        return &result;
    }
}
