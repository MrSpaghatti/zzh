// src/transport/packet.zig

const std = @import("std");
const crypto = @import("std").crypto;

/// SSH Binary Packet Protocol implementation as per RFC 4253 Section 6
pub const SSHPacket = struct {
    /// Length of the packet in bytes, not including 'mac' or packet_length field itself
    packet_length: u32,

    /// Length of padding (random bytes)
    padding_length: u8,

    /// Actual payload data
    payload: []const u8,

    /// Random padding bytes
    padding: []const u8,

    /// Message Authentication Code, if enabled
    mac: ?[]const u8,

    allocator: std.mem.Allocator,

    const Self = @This();

    /// Maximum packet length as per RFC 4253 Section 6.1
    pub const MAX_PACKET_SIZE: u32 = 35000;

    /// Minimum padding length as per RFC 4253 Section 6
    pub const MIN_PADDING_LENGTH: u8 = 4;

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .packet_length = 0,
            .padding_length = 0,
            .payload = &[_]u8{},
            .padding = &[_]u8{},
            .mac = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.payload);
        self.allocator.free(self.padding);
        if (self.mac) |mac| {
            self.allocator.free(mac);
        }
    }

    /// Creates a new SSH packet with proper padding
    pub fn create(allocator: std.mem.Allocator, payload: []const u8, block_size: u8) !Self {
        var self = Self.init(allocator);

        // Calculate padding length to make packet size multiple of block_size
        const base_length = 1 + payload.len; // padding_length + payload
        const padding_length = calculatePadding(base_length, block_size);

        // Generate random padding
        var padding = try allocator.alloc(u8, padding_length);
        try crypto.random.bytes(padding);

        // Set packet fields
        self.packet_length = @intCast(u32, 1 + payload.len + padding_length);
        self.padding_length = padding_length;
        self.payload = try allocator.dupe(u8, payload);
        self.padding = padding;

        return self;
    }

    /// Calculates required padding length as per RFC 4253 Section 6
    fn calculatePadding(base_length: usize, block_size: u8) u8 {
        const padding_mod = (base_length + 4) % block_size;
        var padding_length = MIN_PADDING_LENGTH;
        if (padding_mod != 0) {
            padding_length += block_size - @intCast(u8, padding_mod);
        }
        return padding_length;
    }

    /// Serializes the packet according to RFC 4253 Section 6
    pub fn serialize(self: Self, writer: anytype) !void {
        // Packet length
        try writer.writeIntBig(u32, self.packet_length);
        // Padding length
        try writer.writeByte(self.padding_length);
        // Payload
        try writer.writeAll(self.payload);
        // Padding
        try writer.writeAll(self.padding);
        // MAC if present
        if (self.mac) |mac| {
            try writer.writeAll(mac);
        }
    }

    /// Deserializes a packet according to RFC 4253 Section 6
    pub fn deserialize(reader: anytype, allocator: std.mem.Allocator) !Self {
        var self = Self.init(allocator);

        // Read packet length
        self.packet_length = try reader.readIntBig(u32);
        if (self.packet_length > MAX_PACKET_SIZE) {
            return error.PacketTooLarge;
        }

        // Read padding length
        self.padding_length = try reader.readByte();
        if (self.padding_length < MIN_PADDING_LENGTH) {
            return error.InvalidPaddingLength;
        }

        // Read payload
        const payload_length = self.packet_length - self.padding_length - 1;
        self.payload = try allocator.alloc(u8, payload_length);
        try reader.readNoEof(self.payload);

        // Read padding
        self.padding = try allocator.alloc(u8, self.padding_length);
        try reader.readNoEof(self.padding);

        return self;
    }
};
