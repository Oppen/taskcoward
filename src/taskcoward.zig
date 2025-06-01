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
    const user_dir = 5; // FIXME
    _ = try opendb_rw(user_dir);
}
pub fn cli_create_user() !void {
    const root_dir_path = std.posix.getenv("TC_ROOT_DIR").?;
    const root_dir = try std.posix.open(root_dir_path[0..], .{ .DIRECTORY = true, .SYNC = true }, 0);
    const uuid_bin = std.crypto.random.int(u128) & 0xffffffffffff8fffbfffffffffffffff;
    const uuid = UUIDv8.from_binary(uuid_bin) catch unreachable;
    var uuid_str: [36]u8 = undefined;
    uuid.fmt(uuid_str[0..]);
    const user_dir = try std.posix.openat(root_dir, uuid_str[0..], .{ .DIRECTORY = true, .CREAT = true, .SYNC = true }, 0o000);
    defer std.posix.close(user_dir);
    inline for (
        .{ "metadata", "index-00000000-0000000000000000", "blobs-00000000-0000000000000000", "snapshot", "write.lock" },
        .{ "00000000-0000000000000000", "\x00" ** 28 ++ "\x80\x70\x77\xe9", "", "\x00" ** 16 ++ "Status: 404\r\nContent-Length: 0\r\n\r\n", "" },
    ) |fname, idata| {
        const fd = try std.posix.openat(user_dir, "", .{ .CREAT = true, .SYNC = true, .TMPFILE = true, .ACCMODE = .RDWR }, 0o700);
        defer std.posix.close(fd);
        if (idata.len != try std.posix.write(fd, idata[0..])) {
            return error.ShortWrite;
        }
        try std.posix.renameat(fd, "", user_dir, fname);
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
inline fn toggle_user(enabled: bool) !void {
    try std.posix.getenv("TC_ROOT_DIR");
    try std.process.args();
    const user_dir = 5; // FIXME
    try std.posix.fchmod(user_dir, 0o700 * @intFromBool(enabled));
}

inline fn api_call(comptime ReqT: type) void {
    const status = brk: {
        const req = parse_request(ReqT, std.os.environ) catch |status| break :brk status;
        req.do() catch |status| break :brk status;
        return;
    };
    _ = send_response(status, .{}, .{ -1, 0, 0 }) catch std.process.exit(111);
}
inline fn parse_request(comptime ReqT: type, environ: [][*:0]u8) Status!ReqT {
    var request: ReqT = undefined;
    const envvars = enum(u8) {
        TC_ROOT_DIR = 0,
        TC_SNAP_MAX_DAYS = 1,
        TC_SNAP_MAX_VERS = 2,
        SCRIPT_NAME = 3,
        HTTP_X_CLIENT_ID = 4,
        PATH_INFO = 5,
        CONTENT_TYPE = 6,
        CONTENT_LENGTH = 7,
        REQUEST_METHOD = 8,
    };
    const envmap = std.static_string_map.StaticStringMap(envvars).initComptime(.{
        .{ "TC_ROOT_DIR", envvars.TC_ROOT_DIR },
        .{ "TC_SNAP_MAX_DAYS", envvars.TC_SNAP_MAX_DAYS },
        .{ "TC_SNAP_MAX_VERS", envvars.TC_SNAP_MAX_VERS },
        .{ "SCRIPT_NAME", envvars.SCRIPT_NAME },
        .{ "HTTP_X_CLIENT_ID", envvars.HTTP_X_CLIENT_ID },
        .{ "PATH_INFO", envvars.PATH_INFO },
        .{ "CONTENT_TYPE", envvars.CONTENT_TYPE },
        .{ "CONTENT_LENGTH", envvars.CONTENT_LENGTH },
        .{ "REQUEST_METHOD", envvars.REQUEST_METHOD },
    });
    var has_key: [@intFromEnum(envvars.REQUEST_METHOD) + 1]bool = undefined;
    std.debug.print("has_key.len: {} REQUEST_METHOD+1: {}\n", .{ has_key.len, @intFromEnum(envvars.REQUEST_METHOD) + 1 });
    @memset(has_key[0..], false);
    var root_dir: []const u8 = undefined;
    var user_dir: []const u8 = undefined;
    // Iterate the environment, gathering actual values and parameters
    for (environ) |envvar| {
        const envvar_ = envvar[0..std.mem.indexOfSentinel(u8, 0, envvar)];
        std.debug.print("found variable: {s}\n", .{envvar_});
        var split = std.mem.splitScalar(u8, envvar_, '=');
        const key_str = split.next() orelse {
            std.debug.print("bad env var: {s}\n", .{envvar_});
            return error.S500;
        };
        const val = split.next() orelse "";
        std.debug.print("key_str: {s}\n", .{key_str});
        const key = envmap.get(key_str) orelse continue;
        std.debug.print("key: {}\n", .{key});
        if (has_key[@intFromEnum(key)]) {
            std.debug.print("duplicate key: {}\n", .{key});
            return error.S500;
        }
        has_key[@intFromEnum(key)] = true;
        switch (key) {
            .TC_ROOT_DIR => {
                if (val.len == 0 or val[0] != '/') {
                    std.debug.print("bad root_dir: {s}\n", .{val});
                    return error.S500;
                }
                root_dir = val;
            },
            .TC_SNAP_MAX_DAYS => {
                if (@hasField(ReqT, "max_days_since_snapshot")) {
                    @field(request, "max_days_since_snapshot") = std.fmt.parseInt(u32, val, 10) catch return error.S500;
                }
            },
            .TC_SNAP_MAX_VERS => {
                if (@hasField(ReqT, "max_versions_since_snapshot")) {
                    @field(request, "max_versions_since_snapshot") = std.fmt.parseInt(u32, val, 10) catch return error.S500;
                }
            },
            .SCRIPT_NAME => {
                if (!eql(u8, @field(ReqT, "script_name"), val)) {
                    std.debug.print("bad script_name: {s}\n", .{val});
                    return error.S500;
                }
            },
            .REQUEST_METHOD => {
                if (!eql(u8, @field(ReqT, "method"), val)) {
                    std.debug.print("bad method: {s} expected: {s}\n", .{ val, @field(ReqT, "method") });
                    return error.S400;
                }
            },
            .HTTP_X_CLIENT_ID => {
                std.debug.print("found client_id: {s}\n", .{val});
                @field(request, "client_id") = UUIDv8.parse(val) catch {
                    std.debug.print("bad client_id: {s}\n", .{val});
                    return error.S400;
                };
                user_dir = val;
            },
            .PATH_INFO => {
                switch (@hasField(ReqT, "version_id")) {
                    true => {
                        if (val.len != 37) {
                            std.debug.print("bad path_info length\n", .{});
                            return error.S400;
                        }
                        if (val[0] != '/') {
                            std.debug.print("bad path_info prefix\n", .{});
                            return error.S400;
                        }
                        @field(request, "version_id") = UUIDv8.parse(val[1..]) catch |e| {
                            std.debug.print("bad path_info uuid: {}\n", .{e});
                            return error.S400;
                        };
                    },
                    false => {
                        if (val.len > 1 or (val.len == 1 and val[0] == '/')) {
                            std.debug.print("bad path_info\n", .{});
                            return error.S400;
                        }
                    },
                }
            },
            .CONTENT_TYPE => {
                if (!@hasDecl(ReqT, "content_type")) {
                    std.debug.print("unexpected content_type: {s}\n", .{val});
                    return error.S400;
                }
                if (!std.mem.eql(u8, @field(ReqT, "content_type"), val)) {
                    std.debug.print("unexpected content_type: {s}\n", .{val});
                    return error.S400;
                }
            },
            .CONTENT_LENGTH => {
                const content_length = std.fmt.parseInt(u32, val, 10) catch 0;
                switch (@hasField(ReqT, "content_length")) {
                    true => {
                        if (content_length == 0) {
                            std.debug.print("content_length too short\n", .{});
                            return error.S400;
                        }
                        if (content_length > @field(ReqT, "max_expected_content")) {
                            std.debug.print("content_length too long: {s}\n", .{val});
                            return error.S400;
                        }
                        @field(request, "content_length") = content_length;
                    },
                    false => {
                        if (content_length != 0) {
                            std.debug.print("content_length too long: {s}\n", .{val});
                            return error.S400;
                        }
                    },
                }
            },
        }
    }
    inline for (has_key, 0..9) |has_it, it| {
        const key: envvars = @enumFromInt(it);
        std.debug.print("key: {} it: {} has_it: {}\n", .{ key, it, has_it });
        switch (key) {
            .CONTENT_LENGTH => {
                if (@hasDecl(ReqT, "max_expected_content") and !has_it) {
                    std.debug.print("missing content_length\n", .{});
                    return error.S400;
                }
            },
            .CONTENT_TYPE => {
                if (@hasDecl(ReqT, "content_type") and !has_it) {
                    std.debug.print("missing content_type\n", .{});
                    return error.S400;
                }
            },
            .PATH_INFO => {
                if (@hasField(ReqT, "version_id") and !has_it) {
                    std.debug.print("missing version_id\n", .{});
                    return error.S400;
                }
            },
            .TC_SNAP_MAX_DAYS => {
                if (@hasField(ReqT, "max_days_since_snapshot") and !has_it) {
                    @field(request, "max_days_since_snapshot") = 30;
                }
            },
            .TC_SNAP_MAX_VERS => {
                if (@hasField(ReqT, "max_versions_since_snapshot") and !has_it) {
                    @field(request, "max_versions_since_snapshot") = 300;
                }
            },
            else => {
                if (!has_it) {
                    std.debug.print("missing {}\n", .{key});
                    return error.S400;
                }
            },
        }
        std.debug.print("finished iteration\n", .{});
    }
    std.debug.print("finished presence check\n", .{});
    if (@hasField(ReqT, "version_id")) {
        if (!@field(request, "version_id").is_nil() and @field(request, "version_id").client_id != @field(request, "client_id").client_id) {
            return error.S404;
        }
    }
    std.debug.print("start buffer\n", .{});
    var pathbuf: [512]u8 = undefined;
    var pathlen: usize = 0;
    @memcpy(pathbuf[0..root_dir.len], root_dir[0..]);
    pathlen = root_dir.len;
    pathbuf[pathlen] = '/';
    pathlen += 1;
    @memcpy(pathbuf[pathlen .. pathlen + user_dir.len], user_dir[0..]);
    pathlen += user_dir.len;
    std.debug.print("end buffer\n", .{});
    // NOTE: user is enabled if I can chdir to its directory.
    // chmod 0000 to disable a user, chmod 0700 to enable.
    // NOTE+TODO: the only request that actually modifies the directory is `add-snapshot`.
    // We can check for it to avoid opening with overly abarcative permissions.
    // The other user for writing is compaction and user creation, which aren't parsed by
    // this function.
    const dir_opts = comptime switch (eql(u8, @typeName(ReqT), "AddSnapshotReq")) {
        true => std.posix.O{ .ACCMODE = .RDWR, .DSYNC = true },
        false => std.posix.O{},
    };
    const to_posix = std.posix.toPosixPath(pathbuf[0..pathlen]) catch |e| blk: {
        std.debug.print("toposixpatth: {} len: {} max: {}\n", .{ e, pathbuf[0..pathlen].len, std.posix.PATH_MAX });
        break :blk undefined;
    };
    _ = std.mem.doNotOptimizeAway(to_posix);
    // std.debug.print("toposixpatth finished: {s}", .{to_posix});
    std.debug.print("call open\n", .{});
    @field(request, "user_dir") = std.posix.open(pathbuf[0..pathlen], dir_opts, 0) catch |e|
        {
            std.debug.print("can't open user_dir: {s} ({})\n", .{ pathbuf[0..pathlen], e });
            return error.S400;
        };
    std.debug.print("request fully processed\n", .{});
    return request;
}
// TODO: update callers to not use returned size.
// TODO: save prepared response for versions in the blobs file.
fn send_response(status: Status, headers: anytype, body: struct { fd_t, u64, u64 }) !void {
    var buffer: [16 << 10]u8 = undefined;
    var len: usize = 0;
    // TODO: now that we use CGI, this can simply be an fmt call.
    const status_line = switch (status) {
        error.S200 => "Status: 200\r\n",
        error.S400 => "Status: 400\r\n",
        error.S403 => "Status: 403\r\n",
        error.S404 => "Status: 404\r\n",
        error.S409 => "Status: 409\r\n",
        error.S410 => "Status: 410\r\n",
        else => "Status: 500\r\n",
    };
    @memcpy(buffer[0..status_line.len], status_line[0..]);
    len += status_line.len;
    const htype = @TypeOf(headers);
    var content_type: []const u8 = "text/plain";
    if (@hasField(htype, "content_type")) {
        content_type = @field(headers, "content_type");
    }
    {
        const fmt = try std.fmt.bufPrint(buffer[len..], "Content-Type: {s}\r\n", .{content_type});
        len += fmt.len;
    }
    var content_length: usize = 0;
    if (@hasField(htype, "content_length")) {
        content_length = @field(headers, "content_length");
    }
    {
        const fmt = try std.fmt.bufPrint(buffer[len..], "Content-Length: {d}\r\n", .{content_length});
        len += fmt.len;
    }
    if (@hasField(htype, "urgency")) {
        switch (@field(headers, "urgency")) {
            .None => {},
            .Low => {
                @memcpy(buffer[len..], "X-Snapshot-Request: urgency=low\r\n");
                len += "X-Snapshot-Request: urgency=low\r\n".len;
            },
            .High => {
                @memcpy(buffer[len..], "X-Snapshot-Request: urgency=high\r\n");
                len += "X-Snapshot-Request: urgency=high\r\n".len;
            },
        }
    }
    inline for (.{ "X-Version-Id", "X-Parent-Version-Id" }, .{ "version_id", "parent_version_id" }) |hname, hfield| {
        if (@hasField(htype, hfield)) {
            var uuid: [36]u8 = undefined;
            const field = @field(headers, hfield);
            field.fmt(uuid[0..]);
            const fmt = try std.fmt.bufPrint(buffer[len..], "{s}: {s}\r\n", .{ hname, uuid });
            len += fmt.len;
        }
    }
    @memcpy(buffer[len .. len + 2], "\r\n");
    len += 2;

    std.debug.print("sending - body: {}:{}:{} response: {s}\n", .{ body[0], body[1], body[2], buffer[0..len] });
    const stdout = std.io.getStdOut();
    try stdout.writeAll(buffer[0..len]);
    if (body[0] == -1) {
        return;
    }
    var remaining = body[2];
    var n_written: usize = 0;
    while (remaining != 0) {
        const how_many = @min(buffer.len, remaining);
        const n_read_now = std.posix.pread(body[0], buffer[0..how_many], body[1] + n_written) catch |e| {
            std.debug.print("read failed: {}\n", .{e});
            return error.S500;
        };
        try stdout.writeAll(buffer[0..n_read_now]);
        remaining -= n_read_now;
        n_written += n_read_now;
    }
}

const GetChildVersionReq = struct {
    pub const script_name = "/v1/client/get-child-version";
    pub const method = "GET";
    client_id: UUIDv8,
    version_id: UUIDv8,
    user_dir: fd_t,

    pub fn do(self: *const GetChildVersionReq) Status!void {
        const index_fd, const blobs_fd, const index_start, const blobs_start = opendb_ro(self.user_dir) catch |e| {
            std.debug.print("failed to open version database: {}\n", .{e});
            return error.S500;
        };
        defer closedb(&[_]fd_t{ blobs_fd, index_fd });

        const seqnum = self.version_id.seqnumber;
        if (seqnum < index_start) {
            return error.S410;
        }
        var records: [2]Record = undefined;
        const n_read = std.posix.pread(index_fd, std.mem.asBytes(&records), (seqnum - index_start) * @sizeOf(Record)) catch |e| {
            std.debug.print("failed to read version database: {}\n", .{e});
            return error.S500;
        };
        if (n_read < @sizeOf(Record) or !records[0].valid()) {
            std.debug.print("short read or invalid record: {}\n", .{n_read});
            return error.S500;
        }
        if (records[0].uuid != self.version_id.binary()) {
            std.debug.print("version mismatch: {x:032} {x:032}\n", .{ records[0].uuid, self.version_id.binary() });
            return error.S400;
        }
        if (n_read < @sizeOf([2]Record) or !records[1].valid()) {
            return error.S404;
        }
        _ = send_response(error.S200, .{
            .content_type = "application/vnd.taskchampion.history-segment",
            .content_length = records[1].length,
            .version_id = UUIDv8.from_binary(records[1].uuid) catch |e| {
                std.debug.print("bad record in DB: {x} ({})\n", .{ records[1].uuid, e });
                return error.S500;
            },
            .parent_version_id = self.version_id,
        }, .{ blobs_fd, records[1].offset - blobs_start, records[1].length }) catch |e|
            {
                std.debug.print("send_response failed: {}\n", .{e});
                return error.S500;
            };
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

    pub fn do(self: *const AddVersionReq) Status!void {
        const rw_lock, const index_fd, const blobs_fd, const index_start, const blobs_start = opendb_rw(self.user_dir) catch |e| {
            std.debug.print("failed to open database: {}\n", .{e});
            return error.S500;
        };
        defer closedb(&[_]fd_t{ blobs_fd, index_fd, rw_lock });

        const stat = std.posix.fstat(index_fd) catch |e| {
            std.debug.print("failed to stat database: {}\n", .{e});
            return error.S500;
        };
        // Read the last two in case the last one wasn't persisted properly.
        // Note that the guarantee is that we don't respond with a new version if
        // it isn't durable, so that would actually mean the previous one is the
        // last one anybody else knows, so this is correct.
        var records: [2]Record = undefined;
        const last_records_start = (((@abs(stat.size) -| 1) >> 5) <<| 5) -| @sizeOf(Record);
        const n_read = std.posix.pread(index_fd, std.mem.asBytes(&records), @bitCast(last_records_start)) catch |e| {
            std.debug.print("failed to read database: {} offset: {} bytes: {} size: {}\n", .{ e, last_records_start, std.mem.asBytes(&records).len, stat.size });
            return error.S500;
        };
        if (n_read < @sizeOf(Record) or !records[0].valid()) {
            std.debug.print("short read: {}\n", .{n_read});
            return error.S400;
        }
        var record = records[0];
        if (n_read == @sizeOf([2]Record) and records[1].valid()) {
            record = records[1];
        }
        if (record.uuid != self.version_id.binary()) {
            _ = send_response(Status.S409, .{ .parent_version_id = UUIDv8.from_binary(record.uuid) catch |e| {
                std.debug.print("failed to parse record: {x:016} ({})\n", .{ record.uuid, e });
                return error.S500;
            } }, .{ -1, 0, 0 }) catch |e| {
                std.debug.print("failed to send response: {}\n", .{e});
                return error.S500;
            };
            return;
        }
        const timestamp = std.time.timestamp();
        const new_version = UUIDv8{
            .timestamp = @truncate(@abs(timestamp)),
            .client_id = self.client_id.client_id,
            .seqnumber = self.version_id.seqnumber + 1,
        };
        var new_record: Record = .{
            .uuid = new_version.binary(),
            .offset = records[0].offset + records[0].length,
            .length = self.content_length,
            .crc32 = undefined,
        };
        new_record.update_crc();

        // NOTE: for blobs it's inconsequential to just overwrite data pointed by
        // an invalid record, and for the index the record itself will be overwritten
        // if invalid. Both files and the directory are assumed to be open with DSYNC,
        // so no need for explicit synchronization here. Order does matter though.
        // TODO: helper.
        std.posix.lseek_SET(blobs_fd, records[0].offset - blobs_start + records[0].length) catch |e| {
            std.debug.print("seek failed: {}\n", .{e});
            return error.S500;
        };
        var n_written: usize = 0;
        var remaining = self.content_length;
        var buffer: [16 << 10]u8 = undefined;
        const stdin = std.io.getStdIn().handle;
        while (remaining != 0) {
            const n_read_now = std.posix.read(stdin, buffer[0..]) catch |e| {
                std.debug.print("read failed: {}\n", .{e});
                return error.S500;
            };
            var n_written_now: usize = 0;
            while (n_read_now != n_written_now) {
                n_written_now += std.posix.write(blobs_fd, buffer[n_written_now..n_read_now]) catch |e| {
                    std.debug.print("write failed: {}\n", .{e});
                    return error.S500;
                };
            }
            remaining -= n_read_now;
        }
        n_written = std.posix.pwrite(index_fd, std.mem.asBytes(&new_record), (new_version.seqnumber - index_start) * @sizeOf(Record)) catch |e| {
            std.debug.print("pwrite failed: {}\n", .{e});
            return error.S500;
        };
        if (@sizeOf(Record) != n_written) {
            std.debug.print("short write: {} of {}\n", .{ n_written, @sizeOf(Record) });
            return error.S500;
        }

        const urgency = blk: {
            const snap_uuid = snapshot_version(self.user_dir, false) catch break :blk Urgency.High;
            const low_seconds = self.max_days_since_snapshot * 24 * 60 * 60;
            const low_versions = self.max_versions_since_snapshot;
            const high_seconds = 3 * low_seconds / 2;
            const high_versions = 3 * low_versions / 2;
            if (snap_uuid.timestamp + high_seconds > new_version.timestamp or snap_uuid.seqnumber + high_versions > new_version.seqnumber) {
                break :blk Urgency.High;
            }
            if (snap_uuid.timestamp + low_seconds > new_version.timestamp or snap_uuid.seqnumber + low_versions > new_version.seqnumber) {
                break :blk Urgency.Low;
            }
            break :blk Urgency.None;
        };
        _ = send_response(Status.S200, .{ .version_id = new_version, .urgency = urgency }, .{ -1, 0, 0 }) catch |e| {
            std.debug.print("send_response failed: {}\n", .{e});
            return error.S500;
        };
    }
};
const SnapshotReq = struct {
    pub const script_name = "/v1/client/snapshot";
    pub const method = "GET";
    client_id: UUIDv8,
    user_dir: fd_t,

    pub fn do(self: *const SnapshotReq) Status!void {
        const snapshot = std.posix.openat(self.user_dir, "snapshot", .{}, 0) catch return error.S404;
        const stat = std.posix.fstat(snapshot) catch return error.S500;
        // NOTE: skip the UUID
        const file_length: u64 = @bitCast(stat.size);
        if (file_length -| 16 != std.posix.sendfile(1, snapshot, 16, file_length -| 16, &[_]std.posix.iovec_const{}, &[_]std.posix.iovec_const{}, 0) catch return error.S500) {
            return error.S500;
        }
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

    pub fn do(self: *const AddSnapshotReq) Status!void {
        // We allow a little race here, there may be newer versions
        // at the end that make this older, but either way we check
        // the newest snapshot before moving, so no harm in a little
        // white lie.
        if (!in_newest_n(self.user_dir, AddSnapshotReq.max_versions_back, self.version_id)) {
            return error.S400;
        }
        const current_snapshot = snapshot_version(self.user_dir, false) catch |e| {
            std.debug.print("failed to query old snapshot version: {}\n", .{e});
            return error.S500;
        };
        if (current_snapshot.seqnumber >= self.version_id.seqnumber) {
            // TODO: older snapshot, send 200 status without saving it
            return;
        }
        // NOTE: an O_TMPFILE would be desirable, but apparently replacing an existing file with it is not supported.
        // It might still be useful to ensure any collision is with a valid snapshot and not a broken one.
        var pathbuf: [45]u8 = undefined;
        @memcpy(pathbuf[0..9], "snapshot-");
        self.version_id.fmt(pathbuf[9..]);
        const new_snapshot = std.posix.openat(self.user_dir, pathbuf[0..], .{ .CREAT = true, .EXCL = true, .DSYNC = true, .ACCMODE = .WRONLY }, 0) catch |e| switch (e) {
            error.PathAlreadyExists => {
                // TODO: snapshot exists, send 200 status without saving it
                return;
            },
            else => {
                std.debug.print("failed to open snapshot file: {}\n", .{e});
                return error.S500;
            },
        };
        defer std.posix.close(new_snapshot);
        // TODO: use send_response; need to change the interface so it receives the direction.
        // That way I can still write to the filesystem.
        var hdr: [1024]u8 = undefined;
        @memcpy(hdr[0..16], std.mem.asBytes(&self.version_id.binary()));
        const hdr_len = 16 + (std.fmt.bufPrint(hdr[16..], "Status: 200\r\nContent-Type: {s}\r\nContent-Length: {d}\r\n\r\n", .{ AddSnapshotReq.content_type, self.content_length }) catch return error.S500).len;
        const written = std.posix.sendfile(new_snapshot, 0, 0, self.content_length, &[_]std.posix.iovec_const{.{ .base = @ptrCast(&hdr), .len = hdr_len }}, &[_]std.posix.iovec_const{}, 0) catch return error.S500;
        if (written != hdr_len + self.content_length) {
            // TODO: this would be better with an O_TMPFILE
            std.debug.print("short write: {} of {}\n", .{ written, hdr_len });
            std.posix.unlinkat(self.user_dir, pathbuf[0..], 0) catch return error.S500;
            return error.S500;
        }

        const old_snapshot_version = snapshot_version(self.user_dir, true) catch UUIDv8.nil();
        if (old_snapshot_version.seqnumber > self.version_id.seqnumber) {
            std.posix.unlinkat(self.user_dir, pathbuf[0..], 0) catch return;
            // TODO: return 200, older snapshot accepted not saved
            return;
        }
        std.posix.renameat(self.user_dir, pathbuf[0..], self.user_dir, "snapshot") catch |e| {
            std.debug.print("rename failed: {}\n", .{e});
            return error.S500;
        };
    }
};

fn snapshot_version(user_dir: fd_t, lock: bool) !UUIDv8 {
    const snapshot = try std.posix.openat(user_dir, "snapshot", .{}, 0);
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
    const index_fd, _, const index_start, _ = try opendb(user_dir, .{}, false);
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
};
const Status = error{
    S200,
    S400,
    S403,
    S404,
    S409,
    S410,
    S500,
};
// TaskCoward (client) UUIDv8 layout:
//     0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           server_rand1                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          client_rand1         |  ver  |       client_rand2    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |var|                        client_rand3                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           server_rand2                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// TaskCoward (version) UUIDv8 layout:
//     0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           unix_ts_secs                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          client_rand1         |  ver  |       client_rand2    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |var|                        client_rand3                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           sequence_number                     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
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
    pub fn fmt(self: UUIDv8, buf: *[36]u8) void {
        // hex produces little-endian hex, which is the only place ever
        // I wouldn't want little-endian encoding
        var client_hex = std.fmt.hex(std.mem.nativeToBig(u64, self.client_id));
        _ = std.fmt.bufPrint(buf[0..], "{x:08}-{s}-{s}-{s}-{s}{x:08}", .{ self.timestamp, client_hex[0..4], client_hex[4..8], client_hex[8..12], client_hex[12..], self.seqnumber }) catch unreachable;
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
