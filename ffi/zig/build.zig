const std = @import("std");

fn setOption(comptime T: type, target: T, b: *std.Build) void {
    target.addIncludePath(b.path("../../include"));
    target.addIncludePath(b.path("../../mcl/include"));
    target.linkLibC();
    target.linkSystemLibrary("stdc++");
    target.addObjectFile(b.path("../../lib/libbls384_256.a"));
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "bls-zig",
        .root_source_file = b.path("bls.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib.linkLibC();
    lib.addLibraryPath(b.path("../../lib"));
    lib.linkSystemLibrary("stdc++");
    lib.linkSystemLibrary("bls384_256");
    b.installArtifact(lib);

    const exe = b.addExecutable(.{
        .name = "sample",
        .root_source_file = b.path("sample.zig"),
        .target = target,
        .optimize = optimize,
    });

    setOption(@TypeOf(exe), exe, b);

    // Make the executable installable
    b.installArtifact(exe);

    // Create a run step
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "Run the example");
    run_step.dependOn(&run_cmd.step);

    // Add test build and run steps
    const test_exe = b.addTest(.{
        .root_source_file = b.path("test.zig"),
        .target = target,
        .optimize = optimize,
    });
    setOption(@TypeOf(test_exe), test_exe, b);

    const test_cmd = b.addRunArtifact(test_exe);
    test_cmd.step.dependOn(&test_exe.step);
    const test_step = b.step("test", "Run the tests");
    test_step.dependOn(&test_cmd.step);
}
