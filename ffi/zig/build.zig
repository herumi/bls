const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "sample",
        .root_source_file = b.path("sample.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.addIncludePath(b.path("../../include"));
    exe.addIncludePath(b.path("../../mcl/include"));
    exe.linkLibC();
    exe.linkSystemLibrary("stdc++");
    exe.addObjectFile(b.path("../../lib/libbls384_256.a"));

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
    test_exe.addIncludePath(b.path("../../include"));
    test_exe.addIncludePath(b.path("../../mcl/include"));
    test_exe.linkLibC();
    test_exe.linkSystemLibrary("stdc++");
    test_exe.addObjectFile(b.path("../../lib/libbls384_256.a"));

    const test_cmd = b.addRunArtifact(test_exe);
    test_cmd.step.dependOn(&test_exe.step);
    const test_step = b.step("test", "Run the tests");
    test_step.dependOn(&test_cmd.step);
}
