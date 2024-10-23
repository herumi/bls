const std = @import("std");
const bls = @import("bls.zig");

test "init bls" {
    try std.testing.expect(bls.init());
}

test "all" {
    try std.testing.expect(sign_and_verify());
}

fn sign_and_verify() bool {
    var sk: bls.SecretKey = undefined;
    var pk: bls.PublicKey = undefined;
    var sig: bls.Signature = undefined;
    const msg = "bls zig test";
    sk.setByCSPRNG();
    sk.getPublicKey(&pk);
    sk.sign(&sig, msg);
    const b1 = pk.verify(&sig, msg);
    const b2 = !pk.verify(&sig, "abc");
    return b1 and b2;
}
