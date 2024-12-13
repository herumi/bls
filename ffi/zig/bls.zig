// git clone -b release https://github.com/herumi/bls-eth-go-binary
// cd bls-eth-go-binary
// copy this file into bls
// zig build-exe main.zig -I bls/include/ -L bls/lib/linux/amd64/ -l bls384_256 -l stdc++ -femit-bin=bls.exe && ./bls.exe

const std = @import("std");
const bls = @cImport({
    @cDefine("BLS_ETH", "");
    // MCLBN_COMPILED_TIME_VAR should be determined by the definition of BLS_ETH,
    // but since this is not working as intended, we explicitly provide a magic number.
    @cDefine("MCLBN_COMPILED_TIME_VAR", "246");
    @cInclude("bls/bls384_256.h");
});

pub const MSG_SIZE = 32;
pub const Message = [MSG_SIZE]u8;

pub const Error = error{
    CantInit,
    BufferTooSmall, // serialize, getStr
    BufferTooLarge, // setLittleEndianMod, setBigEndianMod
    InvalidFormat, // deserialize, setStr
    InvalidLength,
};

pub fn init() !void {
    const res = bls.blsInit(bls.MCL_BLS12_381, bls.MCLBN_COMPILED_TIME_VAR);
    if (res != 0) return Error.CantInit;
}

pub const SecretKey = struct {
    v_: bls.blsSecretKey,
    pub fn setByCSPRNG(self: *SecretKey) void {
        const ret = bls.mclBnFr_setByCSPRNG(&self.v_.v);
        if (ret != 0) @panic("mclBnFr_setByCSPRNG");
    }
    pub fn serialize(self: *const SecretKey, buf: []u8) ![]u8 {
        const len: usize = @intCast(bls.blsSecretKeySerialize(buf.ptr, buf.len, &self.v_));
        if (len == 0) return Error.BufferTooSmall;
        return buf[0..len];
    }
    pub fn deserialize(self: *SecretKey, buf: []const u8) !void {
        const len: usize = @intCast(bls.blsSecretKeyDeserialize(&self.v_, buf.ptr, buf.len));
        if (len == 0 or len != buf.len) return Error.InvalidFormat;
    }
    // set (buf[] as littleEndian) % r
    pub fn setLittleEndianMod(self: *SecretKey, buf: []const u8) !void {
        const r = bls.mclBnFr_setLittleEndianMod(&self.v_.v, buf.ptr, buf.len);
        if (r < 0) return Error.BufferTooLarge;
    }
    // set (buf[] as bigEndian) % r
    pub fn setBigEndianMod(self: *SecretKey, buf: []const u8) !void {
        const r = bls.mclBnFr_setBigEndianMod(&self.v_.v, buf.ptr, buf.len);
        if (r < 0) return Error.BufferTooLarge;
    }
    pub fn setStr(self: *SecretKey, s: []const u8, base: i32) !void {
        const r = bls.mclBnFr_setStr(&self.v_.v, s.ptr, s.len, base);
        if (r != 0) return Error.InvalidFormat;
    }
    pub fn getStr(self: *const SecretKey, s: []u8, base: i32) ![]u8 {
        const len: usize = @intCast(bls.mclBnFr_getStr(s.ptr, s.len, &self.v_.v, base));
        if (len == 0) return Error.BufferTooSmall;
        return s[0..len];
    }
    pub fn getPublicKey(self: *const SecretKey, pk: *PublicKey) void {
        bls.blsGetPublicKey(&pk.v_, &self.v_);
    }
    pub fn sign(self: *const SecretKey, sig: *Signature, msg: []const u8) void {
        bls.blsSign(&sig.v_, &self.v_, msg.ptr, msg.len);
    }
    pub fn add(self: *SecretKey, rhs: *const SecretKey) void {
        bls.blsSecretKeyAdd(&self.v_, &rhs.v_);
    }
};

pub const PublicKey = struct {
    v_: bls.blsPublicKey,
    pub fn serialize(self: *const PublicKey, buf: []u8) ![]u8 {
        const len: usize = @intCast(bls.blsPublicKeySerialize(buf.ptr, buf.len, &self.v_));
        if (len == 0) return Error.BufferTooSmall;
        return buf[0..len];
    }
    pub fn deserialize(self: *PublicKey, buf: []const u8) !void {
        const len: usize = @intCast(bls.blsPublicKeyDeserialize(&self.v_, buf.ptr, buf.len));
        if (len == 0 or len != buf.len) return Error.InvalidFormat;
    }
    pub fn verify(self: *const PublicKey, sig: *const Signature, msg: []const u8) bool {
        return bls.blsVerify(&sig.v_, &self.v_, msg.ptr, msg.len) == 1;
    }
    pub fn add(self: *PublicKey, rhs: *const PublicKey) void {
        bls.blsPublicKeyAdd(&self.v_, &rhs.v_);
    }
};

pub const Signature = struct {
    v_: bls.blsSignature,
    // Returns a zero-length slice if the function fails.
    pub fn serialize(self: *const Signature, buf: []u8) ![]u8 {
        const len: usize = @intCast(bls.blsSignatureSerialize(buf.ptr, buf.len, &self.v_));
        if (len == 0) return Error.BufferTooSmall;
        return buf[0..len];
    }
    pub fn deserialize(self: *Signature, buf: []const u8) !void {
        const len: usize = @intCast(bls.blsSignatureDeserialize(&self.v_, buf.ptr, buf.len));
        if (len == 0 or len != buf.len) return Error.InvalidFormat;
    }
    pub fn add(self: *Signature, rhs: *const Signature) void {
        bls.blsSignatureAdd(&self.v_, &rhs.v_);
    }
    pub fn fastAggregateVerify(self: *const Signature, pubVec: []const PublicKey, msg: []const u8) !bool {
        if (pubVec.len == 0) return Error.InvalidLength;
        return bls.blsFastAggregateVerify(&self.v_, &pubVec[0].v_, pubVec.len, msg.ptr, msg.len) == 1;
    }
    pub fn aggregate(self: *Signature, sigVec: []const Signature) !void {
        if (sigVec.len == 0) return Error.InvalidLength;
        bls.blsAggregateSignature(&self.v_, &sigVec[0].v_, sigVec.len);
    }
    // Assume that all msgVec are different..
    pub fn aggregateVerifyNocheck(self: *const Signature, pubVec: []const PublicKey, msgVec: []const Message) bool {
        const n = pubVec.len;
        if (n == 0 or n != msgVec.len) return Error.InvalidLength;
        return bls.blsAggregateVerifyNoCheck(&self.v_, &pubVec[0].v_, &msgVec[0][0], MSG_SIZE, n) == 1;
    }
    // Check whether all msgVec are different..
    pub fn aggregateVerify(self: *const Signature, pubVec: []const PublicKey, msgVec: []const Message) !bool {
        const n = pubVec.len;
        if (n == 0 or n != msgVec.len) return Error.InvalidLength;
        if (!try areAllMessageDifferent(msgVec)) return false;
        return bls.blsAggregateVerifyNoCheck(&self.v_, &pubVec[0].v_, &msgVec[0][0], MSG_SIZE, n) == 1;
    }
};

const MessageComp = struct {
    pub fn hash(self: @This(), key: Message) u64 {
        _ = self;
        return std.hash.Wyhash.hash(0, &key);
    }

    pub fn eql(self: @This(), lhs: Message, rhs: Message) bool {
        _ = self;
        return std.mem.eql(u8, &lhs, &rhs);
    }
};
// Returns true if all msgVec are different.
pub fn areAllMessageDifferent(msgVec: []const Message) !bool {
    if (msgVec.len <= 1) return true;
    const gpa_allocator = std.heap.page_allocator;
    var set = std.HashMap(Message, void, MessageComp, std.hash_map.default_max_load_percentage).init(gpa_allocator);

    defer set.deinit();

    for (msgVec) |msg| {
        const ret = try set.getOrPut(msg);
        if (ret.found_existing) return false;
    }
    return true;
}
