const std = @import("std");
const eql = std.mem.eql;
const fd_t = std.posix.fd_t;

pub fn api_get_child_version() void {
    api_call(GetChildVersionReq);
}
pub fn api_snapshot() void {
    api_call(SnapshotReq);
}
pub fn api_add_version() void {
    api_call(AddVersionReq);
}
pub fn api_add_snapshot() void {
    api_call(AddSnapshotReq);
}
pub fn cli_compact_db() !void {
    const root_dir_path = std.posix.getenv("TC_ROOT_DIR").?;
    var args = std.process.args();
    _ = args.next().?;
    const uuid_str = args.next().?;
    const n_versions_to_keep = try std.fmt.parseInt(u32, args.next().?, 10);
    const uuid = UUIDv8.parse(std.mem.sliceTo(uuid_str, 0)) catch std.process.exit(1);
    var buffer: [std.posix.PATH_MAX:0]u8 = undefined;
    const user_dir_path = try std.fmt.bufPrintZ(buffer[0..], "{s}/{}", .{ root_dir_path, uuid });
    const user_dir = try std.posix.openZ(user_dir_path, .{ .DIRECTORY = true, .SYNC = true }, 0);
    defer std.posix.close(user_dir);
    const rw_lock, const index_fd, const blobs_fd, const index_start, const blobs_start = try opendb_rw(user_dir);
    defer closedb(&[_]fd_t{ blobs_fd, index_fd, rw_lock });
    const snapshot_uuid = try snapshot_version(user_dir, false);
    const oldest_version_to_keep = snapshot_uuid.seqnumber -| n_versions_to_keep;
    if (index_start >= oldest_version_to_keep) {
        return;
    }
    const new_index_start = oldest_version_to_keep - index_start;
    _ = .{ new_index_start, blobs_start };
    // TODO:
    // - Read new_index_start record to obtain new_blobs_start
    // - Create three new anonymous files for metadata, index and blobs
    // - new_meta.write(`{x:08}-{x:016}`, .{new_index_start, new_blobs_start})
    // - copy_file(blobs_fd, new_blobs_fd)
    // - copy_file(index_fd, new_index_fd)
    // - rename(new_blobs_fd, "blobs-{metadata}")
    // - rename(new_index_fd, "index-{metadata}")
    // - rename(new_metadata_fd, "metadata-{metadata}")
    // - rename("metadata-{metadata}", "metadata")
}
pub fn cli_create_user() !void {
    const root_dir_path = std.posix.getenv("TC_ROOT_DIR").?;
    const uuid_bin = std.crypto.random.int(u128) & 0xffffffffffff8fffbfffffffffffffff;
    const uuid = UUIDv8.from_binary(uuid_bin) catch unreachable;
    var buffer: [std.posix.PATH_MAX:0]u8 = undefined;
    const user_dir_path = try std.fmt.bufPrintZ(buffer[0..], "{s}/{}", .{ root_dir_path, uuid });
    const user_dir = try std.posix.openZ(user_dir_path, .{ .DIRECTORY = true, .SYNC = true }, 0);
    defer std.posix.close(user_dir);
    inline for (
        .{ "metadata", "index-00000000-0000000000000000", "blobs-00000000-0000000000000000", "snapshot", "write.lock" },
        .{ "00000000-0000000000000000", "\x00" ** 28 ++ "\x80\x70\x77\xe9", "", "\x00" ** 16 ++ "Status: 404\r\nContent-Length: 0\r\n\r\n", "" },
    ) |fname, idata| {
        const fd = try std.posix.openatZ(user_dir, "", .{ .CREAT = true, .SYNC = true, .TMPFILE = true, .ACCMODE = .RDWR }, 0o700);
        defer std.posix.close(fd);
        if (idata.len != try std.posix.write(fd, idata[0..])) {
            return error.ShortWrite;
        }
        try std.posix.renameatZ(fd, "", user_dir, fname);
    }

    // Created successfully, enable
    try std.posix.fchmod(user_dir, 0o700);
}
pub fn cli_enable_user() !void {
    try toggle_user(true);
}
pub fn cli_disable_user() !void {
    try toggle_user(false);
}
// TODO: I proabably want to make this the binary, take "enabled"
// and "disabled" as second argument and make an execline script
// for the individual commands.
inline fn toggle_user(enabled: bool) !void {
    const root_dir_path = std.posix.getenv("TC_ROOT_DIR").?;
    var args = std.process.args();
    _ = args.next().?;
    const uuid_str = args.next().?;
    const uuid = UUIDv8.parse(std.mem.sliceTo(uuid_str, 0)) catch std.process.exit(1);
    var buffer: [std.posix.PATH_MAX:0]u8 = undefined;
    const user_dir_path = try std.fmt.bufPrintZ(buffer[0..], "{s}/{}", .{ root_dir_path, uuid });
    const user_dir = try std.posix.openZ(user_dir_path, .{ .DIRECTORY = true, .SYNC = true }, 0);
    defer std.posix.close(user_dir);
    try std.posix.fchmod(user_dir, 0o700 * @as(u32, @intFromBool(enabled)));
}

inline fn api_call(comptime ReqT: type) void {
    parse_request(ReqT).do();
}
inline fn parse_request(comptime ReqT: type) ReqT {
    var request: ReqT = undefined;
    const http_x_client_id: [:0]const u8 = std.posix.getenv("HTTP_X_CLIENT_ID") orelse return send_status(500);
    const client_id = UUIDv8.parse(http_x_client_id) catch return send_status(400);
    inline for (.{ "max_days_since_snapshot", "max_versions_since_snapshot", "content_length" }, .{ "TC_SNAP_MAX_DAYS", "TC_SNAP_MAX_VERS", "CONTENT_LENGTH" }, .{ 30, 300, 0 }) |fname, ename, defval| {
        if (@hasField(ReqT, fname)) {
            @field(request, fname) = std.process.parseEnvVarInt(ename, u32, 10) catch defval;
        }
    }
    if (@hasField(ReqT, "content_length")) {
        const content_length = @field(request, "content_length");
        if (content_length == 0) {
            std.debug.print("content_length too short\n", .{});
            return send_status(400);
        }
        if (content_length > @field(ReqT, "max_expected_content")) {
            std.debug.print("content_length too long: {}\n", .{content_length});
            return send_status(400);
        }
    }
    inline for (.{ "method", "content_type", "script_name" }, .{ "REQUEST_METHOD", "CONTENT_TYPE", "SCRIPT_NAME" }) |fname, ename| {
        if (@hasDecl(ReqT, fname)) {
            const evar = std.posix.getenv(ename) orelse "";
            if (!eql(u8, @field(ReqT, fname), evar)) {
                std.debug.print("bad " ++ fname ++ ": {s} expected: " ++ @field(ReqT, "method") ++ "\n", .{evar});
                return send_status(400);
            }
        }
    }
    const path_info = std.posix.getenv("PATH_INFO") orelse "";
    if (@hasField(ReqT, "version_id")) {
        if (path_info.len != 37) {
            std.debug.print("bad path_info length\n", .{});
            return send_status(400);
        }
        if (path_info[0] != '/') {
            std.debug.print("bad path_info prefix\n", .{});
            return send_status(400);
        }
        const version_id = UUIDv8.parse(path_info[1..]) catch |e| {
            std.debug.print("bad path_info uuid: {}\n", .{e});
            return send_status(400);
        };
        if (!version_id.is_nil() and version_id.client_id != client_id.client_id) {
            return send_status(400);
        }
        @field(request, "version_id") = version_id;
    } else {
        if (path_info.len > 1 or (path_info.len == 1 and path_info[0] == '/')) {
            std.debug.print("bad path_info\n", .{});
            return send_status(400);
        }
    }
    var pathbuf: [512:0]u8 = undefined;
    const root_dir: [:0]const u8 = std.posix.getenv("TC_ROOT_DIR") orelse return send_status(500);
    const fmt = std.fmt.bufPrint(pathbuf[0..], "{s}/{}", .{ root_dir, client_id }) catch return send_status(500);
    const pathlen = fmt.len;
    pathbuf[pathlen] = 0;
    const dir_opts = comptime switch (eql(u8, @typeName(ReqT), "AddSnapshotReq")) {
        true => std.posix.O{ .ACCMODE = .RDWR, .DSYNC = true },
        false => std.posix.O{},
    };
    // NOTE: use the 0-terminated version because `toPosixPath`, called
    // by the size delimited version, seems to return `NameTooLong`
    // spuriously on debug builds on x86. I reported a bug about it.
    @field(request, "user_dir") = std.posix.openZ(&pathbuf, dir_opts, 0) catch |e|
        {
            std.debug.print("can't open user_dir: {s} ({})\n", .{ pathbuf[0..pathlen], e });
            return send_status(400);
        };
    std.debug.print("request fully processed\n", .{});
    return request;
}
fn fmt_headers(buffer: []u8, headers: anytype) usize {
    const HeadersType = @TypeOf(headers);
    const type_info = @typeInfo(HeadersType);
    if (type_info != .@"struct" or !type_info.@"struct".is_tuple) {
        @compileError("expected tuple or struct argument, found " ++ @typeName(HeadersType));
    }
    var len: usize = 0;
    inline for (type_info.@"struct".fields) |field| {
        const f_type_info = @typeInfo(field.type);
        if (f_type_info != .@"struct" or f_type_info.@"struct".fields.len != 2) {
            @compileError("expected tuple of two elements, found " ++ @typeName(field.type));
        }
        const fields = f_type_info.@"struct".fields;
        const name, const value = .{ fields[0], fields[1] };
        if (!name.is_comptime) {
            @compileError("expected comptime string");
        }
        const fmt = std.fmt.bufPrint(buffer[len..], "{s}: {any}\r\n", .{ name.name, value.name }) catch unreachable;
        len += fmt.len;
    }
    @memcpy(buffer[len .. len + 2], "\r\n");
    return len + 2;
}
// Aborts on failure.
fn send_response(status: comptime_int, headers: anytype) void {
    var buffer: [1024]u8 = undefined;
    const len = fmt_headers(buffer[0..], .{
        .{ "Status", status },
    } ++ headers);
    const stdout = std.io.getStdOut();
    stdout.writeAll(buffer[0..len]) catch std.process.abort();
}
inline fn send_status(status: comptime_int) void {
    const response = std.fmt.comptimePrint(
        "Status: {}\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n",
        .{status},
    );
    std.io.getStdOut().writeAll(std.mem.sliceTo(response, 0)) catch std.process.abort();
    std.process.exit(0);
}
// NOTE: simply abort because this is always the last step,
// failure is irrecoverable and the server will handle it.
inline fn send_blob(fd: fd_t, start: u64, length: u32) void {
    const empty_iovec = &[_]std.posix.iovec_const{};
    const stdout = std.io.getStdOut().handle;
    // Since this is a CGI script, we can assume a pipe on the other side.
    var offset: u64 = start;
    var remaining: u64 = length;
    while (remaining != 0) {
        const sent = std.posix.sendfile(stdout, fd, offset, remaining, empty_iovec, empty_iovec, 0) catch std.process.abort();
        remaining -= sent;
        offset += sent;
    }
}
// Return the error to allow proper reporting, might depend
// on the caller.
// TODO: probably just include the header processing here,
// or at least the writing. It's gona mostly the same for
// both versions and snapshots.
inline fn recv_blob(fd: fd_t, start: u64, length: u32) !void {
    const stdin = std.io.getStdIn().handle;
    try std.posix.lseek_SET(fd, start);
    var remaining = length;
    while (remaining != 0) {
        // Use the Linux version directly because we need to pass
        // a null offset for it to work with pipes.
        const rc = std.os.linux.sendfile(fd, stdin, null, remaining);
        const errno = std.posix.errno(rc);
        switch (errno) {
            .SUCCESS => {
                remaining -= rc;
            },
            else => return error.SendFileError, //FIXME: preserve some data
        }
    }
}
fn copy_file(in: fd_t, out: fd_t, start: u64) !void {
    var offset = start;
    const stat = try std.posix.fstat(in);
    var remaining = @abs(stat.size) -| start;
    while (remaining != 0) {
        const rc = std.os.linux.copy_file_range(in, &offset, out, null, remaining, 0);
        const errno = std.posix.errno(rc);
        switch (errno) {
            .SUCCESS => {
                remaining -= rc;
            },
            else => return error{errno},
        }
    }
}
fn pwriteAll(fd: fd_t, offset: u64, data: []const u8) !void {
    var remaining = data.len;
    var total: usize = 0;
    while (remaining != 0) {
        const written = try std.posix.pwrite(fd, data[total..], offset + total);
        remaining -= written;
        total += written;
    }
}

const GetChildVersionReq = struct {
    pub const script_name = "/v1/client/get-child-version";
    pub const method = "GET";
    client_id: UUIDv8,
    version_id: UUIDv8,
    user_dir: fd_t,

    pub fn do(self: *const GetChildVersionReq) void {
        const index_fd, const blobs_fd, const index_start, const blobs_start = opendb_ro(self.user_dir) catch |e| {
            std.debug.print("failed to open version database: {}\n", .{e});
            return send_status(500);
        };
        defer closedb(&[_]fd_t{ blobs_fd, index_fd });

        const seqnum = self.version_id.seqnumber;
        if (seqnum < index_start) {
            return send_status(410);
        }
        var records: [2]Record = undefined;
        const n_read = std.posix.pread(index_fd, std.mem.asBytes(&records), (seqnum - index_start) * @sizeOf(Record)) catch |e| {
            std.debug.print("failed to read version database: {}\n", .{e});
            return send_status(500);
        };
        if (n_read < @sizeOf(Record) or !records[0].valid()) {
            std.debug.print("short read or invalid record: {}\n", .{n_read});
            return send_status(500);
        }
        if (records[0].uuid != self.version_id.binary()) {
            std.debug.print("version mismatch: {x:032} {x:032}\n", .{ records[0].uuid, self.version_id.binary() });
            return send_status(400);
        }
        if (n_read < @sizeOf([2]Record) or !records[1].valid()) {
            return send_status(404);
        }
        send_blob(blobs_fd, records[1].offset - blobs_start, records[1].length);
    }
};
const AddVersionReq = struct {
    pub const script_name = "/v1/client/add-version";
    pub const method = "POST";
    pub const content_type = "application/vnd.taskchampion.history-segment";
    pub const max_expected_content = 100 << 20;
    max_days_since_snapshot: u32,
    max_versions_since_snapshot: u32,
    client_id: UUIDv8,
    version_id: UUIDv8,
    content_length: usize,
    user_dir: fd_t,

    pub fn do(self: *const AddVersionReq) void {
        const rw_lock, const index_fd, const blobs_fd, const index_start, const blobs_start = opendb_rw(self.user_dir) catch |e| {
            std.debug.print("failed to open database: {}\n", .{e});
            return send_status(500);
        };
        defer closedb(&[_]fd_t{ blobs_fd, index_fd, rw_lock });

        const stat = std.posix.fstat(index_fd) catch |e| {
            std.debug.print("failed to stat database: {}\n", .{e});
            return send_status(500);
        };
        // Read the last two in case the last one wasn't persisted properly.
        // Note that the guarantee is that we don't respond with a new version if
        // it isn't durable, so that would actually mean the previous one is the
        // last one anybody else knows, so this is correct.
        var records: [2]Record = undefined;
        const last_records_start = (((@abs(stat.size) -| 1) >> 5) <<| 5) -| @sizeOf(Record);
        const n_read = std.posix.pread(index_fd, std.mem.asBytes(&records), @bitCast(last_records_start)) catch |e| {
            std.debug.print("failed to read database: {} offset: {} bytes: {} size: {}\n", .{ e, last_records_start, std.mem.asBytes(&records).len, stat.size });
            return send_status(500);
        };
        if (n_read < @sizeOf(Record) or !records[0].valid()) {
            std.debug.print("short read: {}\n", .{n_read});
            return send_status(400);
        }
        var record = records[0];
        if (n_read == @sizeOf([2]Record) and records[1].valid()) {
            record = records[1];
        }
        if (record.uuid != self.version_id.binary()) {
            const parent = UUIDv8.from_binary(record.uuid) catch |e| {
                std.debug.print("failed to parse record: {x:016} ({})\n", .{ record.uuid, e });
                return send_status(500);
            };
            send_response(409, .{.{ "X-Parent-Version-Id", parent }});
        }
        const timestamp = std.time.timestamp();
        const new_version = UUIDv8{
            .timestamp = @truncate(@abs(timestamp)),
            .client_id = self.client_id.client_id,
            .seqnumber = self.version_id.seqnumber + 1,
        };
        var header_buffer: [1024]u8 = undefined;
        const header_len = fmt_headers(header_buffer[0..], .{
            .{ "Status", 200 },
            .{ "Content-Type", AddVersionReq.content_type },
            .{ "Content-Length", self.content_length },
            .{ "X-Version-Id", new_version },
            .{ "X-Parent-Version-Id", self.version_id },
        });

        var start = records[0].offset - blobs_start + records[0].length;
        pwriteAll(blobs_fd, start, header_buffer[0..header_len]) catch |e| {
            std.debug.print("write failed: {}\n", .{e});
            return send_status(500);
        };
        start += header_len;
        recv_blob(blobs_fd, start, self.content_length) catch |e| {
            std.debug.print("recv failed: {}\n", .{e});
            return send_status(500);
        };

        var new_record: Record = .{
            .uuid = new_version.binary(),
            .offset = records[0].offset + records[0].length,
            .length = self.content_length + header_len,
            .crc32 = undefined,
        };
        new_record.update_crc();

        start = (new_version.seqnumber - index_start) * @sizeOf(Record);
        pwriteAll(index_fd, start, std.mem.asBytes(&new_record)) catch |e| {
            std.debug.print("pwrite failed: {}\n", .{e});
            return send_status(500);
        };

        const snap_uuid = snapshot_version(self.user_dir, false) catch UUIDv8.nil();
        const low_seconds = self.max_days_since_snapshot * 24 * 60 * 60;
        const low_versions = self.max_versions_since_snapshot;
        const high_seconds = 3 * low_seconds / 2;
        const high_versions = 3 * low_versions / 2;
        if (snap_uuid.timestamp + low_seconds <= new_version.timestamp and snap_uuid.seqnumber + low_versions <= new_version.seqnumber) {
            return send_response(200, .{.{ "X-Version-Id", new_version }});
        }
        const urgency = if (snap_uuid.timestamp + high_seconds > new_version.timestamp or snap_uuid.seqnumber + high_versions > new_version.seqnumber)
            Urgency.High
        else
            Urgency.Low;
        send_response(200, .{
            .{ "X-Version-Id", new_version },
            .{ "X-Snapshot-Request", urgency },
        });
    }
};
const SnapshotReq = struct {
    pub const script_name = "/v1/client/snapshot";
    pub const method = "GET";
    client_id: UUIDv8,
    user_dir: fd_t,

    pub fn do(self: *const SnapshotReq) void {
        const snapshot = std.posix.openat(self.user_dir, "snapshot", .{}, 0) catch return send_status(404);
        const stat = std.posix.fstat(snapshot) catch return send_status(500);
        const file_length: u32 = @truncate(@abs(stat.size));
        // NOTE: skip the UUID
        send_blob(snapshot, 16, file_length -| 16);
    }
};
const AddSnapshotReq = struct {
    pub const script_name = "/v1/client/add-snapshot";
    pub const method = "POST";
    pub const content_type = "application/vnd.taskchampion.snapshot";
    pub const max_expected_content = 100 << 20;
    pub const max_versions_back = 5;
    client_id: UUIDv8,
    version_id: UUIDv8,
    content_length: usize,
    user_dir: fd_t,

    pub fn do(self: *const AddSnapshotReq) void {
        // We allow a little race here, there may be newer versions
        // at the end that make this older, but either way we check
        // the newest snapshot before moving, so no harm in a little
        // white lie.
        if (!in_newest_n(self.user_dir, AddSnapshotReq.max_versions_back, self.version_id)) {
            return send_status(400);
        }
        const current_snapshot = snapshot_version(self.user_dir, false) catch |e| {
            std.debug.print("failed to query old snapshot version: {}\n", .{e});
            return send_status(500);
        };
        if (current_snapshot.seqnumber >= self.version_id.seqnumber) {
            return send_status(200);
        }
        // NOTE: an O_TMPFILE would be desirable, but apparently replacing an existing file with it is not supported.
        // It might still be useful to ensure any collision is with a valid snapshot and not a broken one.
        // TODO: use bufPrintZ and open*Z where appropriate.
        var pathbuf: [45]u8 = undefined;
        _ = std.fmt.bufPrint(pathbuf[0..], "snapshot-{}", .{self.version_id}) catch unreachable;
        const new_snapshot = std.posix.openat(self.user_dir, pathbuf[0..], .{ .CREAT = true, .EXCL = true, .DSYNC = true, .ACCMODE = .WRONLY }, 0) catch |e| switch (e) {
            error.PathAlreadyExists => {
                return send_status(200);
            },
            else => {
                std.debug.print("failed to open snapshot file: {}\n", .{e});
                return send_status(500);
            },
        };
        defer std.posix.close(new_snapshot);
        // TODO: use send_response; need to change the interface so it receives the direction.
        // That way I can still write to the filesystem.
        var hdr: [1024]u8 = undefined;
        @memcpy(hdr[0..16], std.mem.asBytes(&self.version_id.binary()));
        const hdr_len = 16 + fmt_headers(hdr[16..], .{
            .{ "Status", 200 },
            .{ "Content-Type", AddSnapshotReq.content_type },
            .{ "Content-Length", self.content_length },
        });
        pwriteAll(new_snapshot, 0, hdr[0..hdr_len]) catch |e| {
            std.debug.print("failed to write header: {}\n", .{e});
            // FIXME: this leaks the file; I could delete it,
            // but I'm gonna move to O_TMPFILE soon
            send_status(500);
        };
        recv_blob(new_snapshot, hdr_len, self.content_length) catch |e| {
            std.debug.print("recv failed: {}\n", .{e});
            send_status(500);
        };

        const old_snapshot_version = snapshot_version(self.user_dir, true) catch UUIDv8.nil();
        if (old_snapshot_version.seqnumber >= self.version_id.seqnumber) {
            return send_status(200);
        }
        // std.posix.linkat(olddir: fd_t, oldpath: []const u8, newdir: fd_t, newpath: []const u8, flags: i32)
        std.posix.renameat(self.user_dir, pathbuf[0..], self.user_dir, "snapshot") catch |e| {
            std.debug.print("rename failed: {}\n", .{e});
            return send_status(500);
        };
    }
};

fn snapshot_version(user_dir: fd_t, lock: bool) !UUIDv8 {
    const snapshot = try std.posix.openat(user_dir, "snapshot", .{}, 0);
    // FIXME: I want to **keep** the lock!
    defer std.posix.close(snapshot);
    if (lock) {
        try std.posix.flock(snapshot, std.posix.LOCK.EX);
    }
    var value: u128 = undefined;
    if (16 != try std.posix.read(snapshot, std.mem.asBytes(&value))) {
        return error.ShortRead;
    }
    return try UUIDv8.from_binary(value);
}
// Returns (index_fd, blobs_fd, index_start, blobs_start)
fn opendb(user_dir: fd_t, options: std.posix.O, with_blobs: bool) !struct { fd_t, fd_t, u32, u64 } {
    const ro_lock = try std.posix.openat(user_dir, "metadata", .{}, 0);
    defer std.posix.close(ro_lock);
    try std.posix.flock(ro_lock, std.posix.LOCK.SH);
    var pathbuf: [31]u8 = undefined;
    if (pathbuf.len - 6 != try std.posix.read(ro_lock, pathbuf[6..])) {
        return error.ShortRead;
    }
    const index_start = try std.fmt.parseInt(u32, pathbuf[6..14], 16);
    const blobs_start = try std.fmt.parseInt(u64, pathbuf[15..31], 16);
    @memcpy(pathbuf[0..6], "index-");
    const index_fd = try std.posix.openat(user_dir, pathbuf[0..], options, 0);
    if (!with_blobs) {
        return .{ index_fd, -1, index_start, blobs_start };
    }
    errdefer std.posix.close(index_fd);
    @memcpy(pathbuf[0..6], "blobs-");
    const blobs_fd = try std.posix.openat(user_dir, pathbuf[0..], options, 0);
    return .{ index_fd, blobs_fd, index_start, blobs_start };
}
// Returns (index_fd, index_start)
fn opendb_index(user_dir: fd_t) !struct { fd_t, u32 } {
    const index_fd, const blobs_db, const index_start, _ = try opendb(user_dir, .{}, false);
    std.posix.close(blobs_db);
    return .{ index_fd, index_start };
}
// Returns (index_fd, blobs_fd, index_start, blobs_start)
fn opendb_ro(user_dir: fd_t) !struct { fd_t, fd_t, u32, u64 } {
    return opendb(user_dir, .{}, true);
}
// Returns (rw_lock_fd, index_fd, blobs_fd, index_start, blobs_start)
fn opendb_rw(user_dir: fd_t) !struct { fd_t, fd_t, fd_t, u32, u64 } {
    const rw_lock = try std.posix.openat(user_dir, "write.lock", .{}, 0);
    errdefer std.posix.close(rw_lock);
    try std.posix.flock(rw_lock, std.posix.LOCK.EX);
    const db = try opendb(user_dir, .{ .DSYNC = true, .ACCMODE = .RDWR }, true);
    return .{rw_lock} ++ db;
}
fn closedb(fds: []const fd_t) void {
    for (fds) |fd| {
        std.posix.close(fd);
    }
}
fn in_newest_n(user_dir: fd_t, max_versions_back: u32, version_id: UUIDv8) bool {
    const index_fd, const index_start = opendb_index(user_dir) catch return false;
    const stat = std.posix.fstat(index_fd) catch return false;
    if (stat.size - max_versions_back * @sizeOf(Record) > (version_id.seqnumber - index_start) * @sizeOf(Record)) {
        return false;
    }
    var record: Record = undefined;
    if (@sizeOf(Record) < std.posix.pread(index_fd, std.mem.asBytes(&record), (version_id.seqnumber - index_start) * @sizeOf(Record)) catch return false) {
        return false;
    }
    return record.valid() and record.uuid == version_id.binary();
}

const Record = packed struct(u256) {
    uuid: u128,
    offset: u64,
    length: u32,
    crc32: u32,

    fn compute_crc(self: *const Record) u32 {
        return std.hash.Crc32.hash(std.mem.asBytes(self)[0..28]);
    }
    pub fn update_crc(self: *Record) void {
        self.crc32 = self.compute_crc();
    }
    pub fn valid(self: *const Record) bool {
        return self.crc32 == self.compute_crc();
    }
};
const Urgency = enum {
    None,
    Low,
    High,
    pub fn format(
        self: Urgency,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = .{ fmt, options };
        switch (self) {
            .None => {},
            .Low => try writer.print("urgency=low", .{}),
            .High => try writer.print("urgency=high", .{}),
        }
    }
};
// TaskCoward (client) UUIDv8 layout:
// | TIMESTAMP | CLIENT_RAND1 | VER | CLIENT_RAND2 | VAR | CLIENT_RAND3 | SERVER_RAND |
//   32 bits     16 bits       0b100  13 bits       0b10   30 bits        32 bits
// TaskCoward (version) UUIDv8 layout:
// | TIMESTAMP | CLIENT_RAND1 | VER | CLIENT_RAND2 | VAR | CLIENT_RAND3 | SEQUENCE NUMBER |
//   32 bits     16 bits       0b100  13 bits       0b10   30 bits        32 bits
// For all version UUIDs, CLIENT_RAND1, CLIENT_RAND2 and CLIENT_RAND3
// MUST match the same fields in the associated client UUID.
// NB: this means the middle 64 bits need to match, given the remaining
// bits mandatorily match due to UUIDv8 requirements.
const UUIDv8 = packed struct(u128) {
    client_id: u64,
    timestamp: u32,
    seqnumber: u32,
    pub fn parse(str: []const u8) !UUIDv8 {
        if (str.len != 36) {
            return error.BadLength;
        }
        if (str[8] != '-' or str[13] != '-' or str[18] != '-' or str[23] != '-') {
            return error.BadFormat;
        }
        var buf: [32]u8 = undefined;
        if (4 != std.mem.replace(u8, str, "-", "", buf[0..])) {
            return error.BadFormat;
        }
        var uuid: UUIDv8 = undefined;
        uuid.timestamp = try std.fmt.parseInt(u32, buf[0..8], 16);
        uuid.client_id = try std.fmt.parseInt(u64, buf[8..24], 16);
        uuid.seqnumber = try std.fmt.parseInt(u32, buf[24..], 16);
        if (!uuid.is_nil() and uuid.client_id & 0x0000f000c0000000 != 0x0000800080000000) {
            return error.BadVersion;
        }
        return uuid;
    }
    pub fn format(
        self: UUIDv8,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = .{ fmt, options };
        // hex produces little-endian hex, which is the only place ever
        // I wouldn't want little-endian encoding
        var client_hex = std.fmt.hex(std.mem.nativeToBig(u64, self.client_id));
        try writer.print("{x:08}-{s}-{s}-{s}-{s}{x:08}", .{ self.timestamp, client_hex[0..4], client_hex[4..8], client_hex[8..12], client_hex[12..], self.seqnumber });
    }
    pub fn from_binary(value: u128) !UUIDv8 {
        const uuid = UUIDv8{
            .timestamp = @truncate(value >> 96),
            .client_id = @truncate(value >> 32),
            .seqnumber = @truncate(value),
        };
        if (!uuid.is_nil() and uuid.client_id & 0x0000f000c0000000 != 0x0000800080000000) {
            return error.BadVersion;
        }
        return uuid;
    }
    pub fn binary(self: UUIDv8) u128 {
        return @as(u128, self.timestamp) << 96 | @as(u128, self.client_id) << 32 | @as(u128, self.seqnumber);
    }
    pub fn nil() UUIDv8 {
        return UUIDv8{ .timestamp = 0, .seqnumber = 0, .client_id = 0 };
    }
    pub fn is_nil(self: UUIDv8) bool {
        return self.client_id == 0 and self.seqnumber == 0 and self.timestamp == 0;
    }
};
