const std = @import("std");
const bls = @import("bls.zig");

test "init bls" {
    try bls.init();
}
const MSG_N: usize = 258;

test "all" {
    const msg1 = "bls zig test";
    const msg2 = "bls zig te";
    try std.testing.expect(signAndVerifyTest(msg1, msg1));
    try std.testing.expect(!signAndVerifyTest(msg1, msg2));
    try std.testing.expect(try areAllMessageDifferentTest(5));
    try std.testing.expect(try areAllMessageDifferentTest(100));
    try std.testing.expect(try areAllMessageDifferentTest(255));
    try std.testing.expect(try areAllMessageDifferentTest(256));
    try std.testing.expect(!try areAllMessageDifferentTest(257)); // contains the same msg
}

fn signAndVerifyTest(msg1: []const u8, msg2: []const u8) bool {
    var sk: bls.SecretKey = undefined;
    var pk: bls.PublicKey = undefined;
    var sig: bls.Signature = undefined;
    sk.setByCSPRNG();
    sk.getPublicKey(&pk);
    sk.sign(&sig, msg1);
    return pk.verify(&sig, msg2);
}

fn areAllMessageDifferentTest(n: usize) !bool {
    var msgVec: [MSG_N]bls.Message = undefined;
    for (0..MSG_N) |i| {
        @memset(&msgVec[i], 0);
        msgVec[i][1] = @intCast(i & 255);
    }
    return bls.areAllMessageDifferent(msgVec[0..n]);
}
