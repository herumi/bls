const std = @import("std");
const bls = @import("bls.zig");

fn multiSig() void {
    const N = 30;
    var skVec: [N]bls.SecretKey = undefined;
    var pkVec: [N]bls.PublicKey = undefined;
    var sigVec: [N]bls.Signature = undefined;
    var sig2Vec: [N]bls.Signature = undefined;
    var msgVec: [N][bls.MSG_SIZE]u8 = undefined;
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
    if (!agg.aggregate(&sigVec)) {
        std.debug.print("ERR aggregate\n", .{});
        return;
    }
    // valid
    if (agg.fastAggregateVerify(&pkVec, msg)) {
        std.debug.print("OK fastAggregateVerify\n", .{});
    } else {
        std.debug.print("ERR fastAggregateVerify\n", .{});
        return;
    }
    // invalid
    if (!agg.fastAggregateVerify(pkVec[0 .. N - 1], msg)) {
        std.debug.print("OK fastAggregateVerify for invalid pk\n", .{});
    } else {
        std.debug.print("ERR fastAggregateVerify\n", .{});
        return;
    }

    if (!agg.aggregate(&sig2Vec)) {
        std.debug.print("ERR aggregate2\n", .{});
        return;
    }
    // valid
    if (agg.aggregateVerifyNocheck(&pkVec, &msgVec)) {
        std.debug.print("OK aggregateVerifyNocheck\n", .{});
    } else {
        std.debug.print("ERR aggregateVerifyNocheck\n", .{});
        return;
    }
    // invalid
    msgVec[0][0] += 1;
    if (!agg.aggregateVerifyNocheck(&pkVec, &msgVec)) {
        std.debug.print("OK aggregateVerifyNocheck for invalid msg\n", .{});
    } else {
        std.debug.print("ERR aggregateVerifyNocheck\n", .{});
        return;
    }
}

pub fn main() void {
    if (!bls.init()) {
        std.debug.print("ERR bls.init()\n", .{});
        return;
    }
    var sk: bls.SecretKey = undefined;
    sk.setByCSPRNG();
    var buf128: [128]u8 = undefined;
    var buf: []u8 = &buf128;

    const cbuf: []u8 = sk.serialize(&buf);
    std.debug.print("sk:serialize={}\n", .{std.fmt.fmtSliceHexLower(cbuf)});
    var sk2: bls.SecretKey = undefined;
    if (sk2.deserialize(cbuf)) {
        std.debug.print("sk2:serialize={}\n", .{std.fmt.fmtSliceHexLower(sk2.serialize(&buf))});
    } else {
        std.debug.print("ERR sk2:serialize\n", .{});
    }
    std.debug.print("sk:getStr(10)={s}\n", .{sk.getStr(&buf, 10)});
    std.debug.print("sk:getStr(16)=0x{s}\n", .{sk.getStr(&buf, 16)});
    sk.setLittleEndianMod(@as([]const u8, &.{ 1, 2, 3, 4, 5 }));
    std.debug.print("sk={s}\n", .{sk.getStr(&buf, 16)});
    sk.setBigEndianMod(@as([]const u8, &.{ 1, 2, 3, 4, 5 }));
    std.debug.print("sk={s}\n", .{sk.getStr(&buf, 16)});
    if (sk.setStr("1234567890123", 10)) {
        std.debug.print("sk={s}\n", .{sk.getStr(&buf, 10)});
    }
    var pk: bls.PublicKey = undefined;
    sk.getPublicKey(&pk);
    std.debug.print("pk={}\n", .{std.fmt.fmtSliceHexLower(pk.serialize(&buf))});
    const msg = "abcdefg";
    var sig: bls.Signature = undefined;
    sk.sign(&sig, msg);
    std.debug.print("verify={}\n", .{pk.verify(&sig, msg)});
    std.debug.print("verify={}\n", .{pk.verify(&sig, "abc")});
    multiSig();
}
