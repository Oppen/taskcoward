pub fn main() !void {
    try @import("taskcoward.zig").cli_disable_user();
}
