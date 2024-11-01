const std = @import("std");
const bls = @import("bls.zig");

fn multiSig() !void {
    const N = 30;
    var skVec: [N]bls.SecretKey = undefined;
    var pkVec: [N]bls.PublicKey = undefined;
    var sigVec: [N]bls.Signature = undefined;
    var sig2Vec: [N]bls.Signature = undefined;
    var msgVec: [N]bls.Message = undefined;
    const msg = "doremifa";
    for (0..N) |i| {
        skVec[i].setByCSPRNG();
        skVec[i].getPublicKey(&pkVec[i]);
        skVec[i].sign(&sigVec[i], msg);
        if (!pkVec[i].verify(&sigVec[i], msg)) {
            std.debug.print("ERR verify i={}\n", .{i});
            return;
        }
        msgVec[i][0] = @intCast(i & 255);
        msgVec[i][1] = @intCast((i >> 8) & 255);
        @memset(msgVec[i][2..], 0);
        skVec[i].sign(&sig2Vec[i], &msgVec[i]);
    }
    var agg: bls.Signature = undefined;
    try agg.aggregate(&sigVec);
    // valid
    if (try agg.fastAggregateVerify(&pkVec, msg)) {
        std.debug.print("OK fastAggregateVerify\n", .{});
    } else {
        std.debug.print("ERR fastAggregateVerify\n", .{});
        return;
    }
    // invalid
    if (!try agg.fastAggregateVerify(pkVec[0 .. N - 1], msg)) {
        std.debug.print("OK fastAggregateVerify for invalid pk\n", .{});
    } else {
        std.debug.print("ERR fastAggregateVerify\n", .{});
        return;
    }

    try agg.aggregate(&sig2Vec);
    // valid
    if (try agg.aggregateVerify(&pkVec, &msgVec)) {
        std.debug.print("OK aggregateVerify\n", .{});
    } else {
        std.debug.print("ERR aggregateVerify\n", .{});
        return;
    }
    // invalid
    msgVec[0][0] += 1;
    if (!try agg.aggregateVerify(&pkVec, &msgVec)) {
        std.debug.print("OK aggregateVerify for invalid msg\n", .{});
    } else {
        std.debug.print("ERR aggregateVerify\n", .{});
        return;
    }
}

pub fn main() !void {
    try bls.init();
    var sk: bls.SecretKey = undefined;
    sk.setByCSPRNG();
    var buf: [128]u8 = undefined;

    const cbuf: []u8 = try sk.serialize(buf[0..]);
    std.debug.print("sk:serialize={}\n", .{std.fmt.fmtSliceHexLower(cbuf)});
    var sk2: bls.SecretKey = undefined;
    try sk2.deserialize(cbuf);
    std.debug.print("sk2:serialize={}\n", .{std.fmt.fmtSliceHexLower(try sk2.serialize(buf[0..]))});
    std.debug.print("sk:getStr(10)={s}\n", .{try sk.getStr(buf[0..], 10)});
    std.debug.print("sk:getStr(16)=0x{s}\n", .{try sk.getStr(buf[0..], 16)});
    try sk.setLittleEndianMod(@as([]const u8, &.{ 1, 2, 3, 4, 5 }));
    std.debug.print("sk={s}\n", .{try sk.getStr(buf[0..], 16)});
    try sk.setBigEndianMod(@as([]const u8, &.{ 1, 2, 3, 4, 5 }));
    std.debug.print("sk={s}\n", .{try sk.getStr(buf[0..], 16)});
    try sk.setStr("1234567890123", 10);
    std.debug.print("sk={s}\n", .{try sk.getStr(buf[0..], 10)});
    var pk: bls.PublicKey = undefined;
    sk.getPublicKey(&pk);
    std.debug.print("pk={}\n", .{std.fmt.fmtSliceHexLower(try pk.serialize(buf[0..]))});
    const msg = "abcdefg";
    var sig: bls.Signature = undefined;
    sk.sign(&sig, msg);
    std.debug.print("verify={}\n", .{pk.verify(&sig, msg)});
    std.debug.print("verify={}\n", .{pk.verify(&sig, "abc")});
    try multiSig();
}
