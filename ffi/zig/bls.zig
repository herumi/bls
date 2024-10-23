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

pub fn init() bool {
    const res = bls.blsInit(bls.MCL_BLS12_381, bls.MCLBN_COMPILED_TIME_VAR);
    return res == 0;
}

pub const SecretKey = struct {
    v_: bls.blsSecretKey,
    pub fn setByCSPRNG(self: *SecretKey) void {
        const ret = bls.mclBnFr_setByCSPRNG(&self.v_.v);
        if (ret != 0) @panic("mclBnFr_setByCSPRNG");
    }
    // Returns a zero-length slice if the function fails.
    pub fn serialize(self: *const SecretKey, buf: *[]u8) []u8 {
        const len: usize = @intCast(bls.blsSecretKeySerialize(buf.*.ptr, buf.*.len, &self.v_));
        return buf.*[0..len];
    }
    pub fn deserialize(self: *SecretKey, buf: []const u8) bool {
        const len: usize = @intCast(bls.blsSecretKeyDeserialize(&self.v_, buf.ptr, buf.len));
        std.debug.print("len={} buf.len={}\n", .{ len, buf.len });
        return len > 0 and len == buf.len;
    }
    // set (buf[] as littleEndian) % r
    pub fn setLittleEndianMod(self: *SecretKey, buf: []const u8) void {
        const r = bls.mclBnFr_setLittleEndianMod(&self.v_.v, buf.ptr, buf.len);
        if (r < 0) @panic("mclBnFr_setLittleEndianMod");
    }
    // set (buf[] as bigEndian) % r
    pub fn setBigEndianMod(self: *SecretKey, buf: []const u8) void {
        const r = bls.mclBnFr_setBigEndianMod(&self.v_.v, buf.ptr, buf.len);
        if (r < 0) @panic("mclBnFr_setBigEndianMod");
    }
    pub fn setStr(self: *SecretKey, s: []const u8, base: i32) bool {
        const r = bls.mclBnFr_setStr(&self.v_.v, s.ptr, s.len, base);
        return r == 0;
    }
    // Returns a zero-length slice if the function fails.
    pub fn getStr(self: *const SecretKey, s: *[]u8, base: i32) []u8 {
        const len: usize = @intCast(bls.mclBnFr_getStr(s.*.ptr, s.*.len, &self.v_.v, base));
        return s.*[0..len];
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
    // Returns a zero-length slice if the function fails.
    pub fn serialize(self: *const PublicKey, buf: *[]u8) []u8 {
        const len: usize = @intCast(bls.blsPublicKeySerialize(buf.*.ptr, buf.*.len, &self.v_));
        return buf.*[0..len];
    }
    pub fn deserialize(self: *PublicKey, buf: []const u8) bool {
        const len: usize = @intCast(bls.blsPublicKeyDeserialize(&self.v_, buf.ptr, buf.len));
        std.debug.print("len={} buf.len={}\n", .{ len, buf.len });
        return len > 0 and len == buf.len;
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
    pub fn serialize(self: *const Signature, buf: *[]u8) []u8 {
        const len: usize = @intCast(bls.blsSignatureSerialize(buf.*.ptr, buf.*.len, &self.v_));
        return buf.*[0..len];
    }
    pub fn deserialize(self: *Signature, buf: []const u8) bool {
        const len: usize = @intCast(bls.blsSignatureDeserialize(&self.v_, buf.ptr, buf.len));
        std.debug.print("len={} buf.len={}\n", .{ len, buf.len });
        return len > 0 and len == buf.len;
    }
    pub fn add(self: *Signature, rhs: *const Signature) void {
        bls.blsSignatureAdd(&self.v_, &rhs.v_);
    }
    pub fn fastAggregateVerify(self: *const Signature, pubVec: []const PublicKey, msg: []const u8) bool {
        if (pubVec.len == 0) @panic("fastAggregateVerify zero-size pubVec");
        return bls.blsFastAggregateVerify(&self.v_, &pubVec[0].v_, pubVec.len, msg.ptr, msg.len) == 1;
    }
    pub fn aggregate(self: *Signature, sigVec: []const Signature) bool {
        if (sigVec.len == 0) return false;
        bls.blsAggregateSignature(&self.v_, &sigVec[0].v_, sigVec.len);
        return true;
    }
    pub fn aggregateVerifyNocheck(self: *const Signature, pubVec: []const PublicKey, msgVec: []const [MSG_SIZE]u8) bool {
        const n = pubVec.len;
        if (n == 0 or n != msgVec.len) return false;
        return bls.blsAggregateVerifyNoCheck(&self.v_, &pubVec[0].v_, &msgVec[0][0], MSG_SIZE, n) == 1;
    }
};
