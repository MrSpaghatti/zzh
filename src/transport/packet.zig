const std = @import("std");
const crypto = @import("crypto.zig");

/// SSH Packet structure as per RFC 4253
pub const SSHPacket = struct {
    packet_length: u32,
    padding_length: u8,
    payload: []const u8,
    padding: []const u8,
    mac: ?[16]u8 = null,

    /// Serialize packet according to SSH protocol
    pub fn serialize(self: SSHPacket, writer: anytype) !void {
        try writer.writeIntBig(u32, self.packet_length);
        try writer.writeByte(self.padding_length);
        try writer.writeAll(self.payload);
        try writer.writeAll(self.padding);
        
        if (self.mac) |mac| {
            try writer.writeAll(&mac);
        }
    }

    /// Deserialize packet from raw bytes
    pub fn deserialize(reader: anytype) !SSHPacket {
        const packet_length = try reader.readIntBig(u32);
        const padding_length = try reader.readByte();
        
        // Validate packet length
        if (packet_length > MAX_PACKET_LENGTH) {
            return error.PacketTooLarge;
        }

        // Read payload and padding
        const payload = try reader.readAllAlloc(std.heap.page_allocator, packet_length - padding_length - 1);
        const padding = try reader.readAllAlloc(std.heap.page_allocator, padding_length);

        return SSHPacket{
            .packet_length = packet_length,
            .padding_length = padding_length,
            .payload = payload,
            .padding = padding,
        };
    }
}

/// Maximum SSH packet length as per specification
const MAX_PACKET_LENGTH = 35000;