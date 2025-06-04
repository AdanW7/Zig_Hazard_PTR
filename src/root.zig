//! By convention, root.zig is the root source file when making a library. If
//! you are making an executable, the convention is to delete this file and
//! start with main.zig instead.
const std = @import("std");
const testing = std.testing;

const Hazard = @import("Hazard.zig");
pub const HazardPointer = @import("Hazard.zig").HazardPointer;
pub const HazardGuard = @import("Hazard.zig").HazardGuard;

pub const MAX_HAZARDS_PER_THREAD = Hazard.MAX_HAZARDS_PER_THREAD;
pub const MAX_RETIRED_POINTERS = Hazard.MAX_RETIRED_POINTERS;



