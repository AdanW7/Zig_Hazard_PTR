//! By convention, root.zig is the root source file when making a library. If
//! you are making an executable, the convention is to delete this file and
//! start with main.zig instead.
const std = @import("std");
const testing = std.testing;

pub const Hazard = @import("Hazard.zig");
pub const HazardPointer = @import("Hazard.zig").HazardPointer;
// HazardPointer
pub const HazardGuard = @import("Hazard.zig").HazardGuard;


