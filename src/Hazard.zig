const std = @import("std");

/// Maximum number of hazard pointers per thread
pub const MAX_HAZARDS_PER_THREAD = 8;

/// Maximum number of retired pointers before forcing cleanup
pub const MAX_RETIRED_POINTERS = 64;

pub fn HazardPointer(comptime T: type) type {
    return struct {

        allocator: std.mem.Allocator,
        head: std.atomic.Value(?*HazardRecord),
        global_epoch: std.atomic.Value(u64),
        
        const Self = @This();

        // ******************** Core structs *************************
        /// A single slot that can hold one protected pointer per thread.
        const HazardSlot = struct {
            ptr: std.atomic.Value(?*T),
            active: std.atomic.Value(bool),

            ///creates a new hazard slot with null pointer and inactive state
            fn init() HazardSlot {
                return HazardSlot{
                    .ptr = std.atomic.Value(?*T).init(null),
                    .active = std.atomic.Value(bool).init(false),
                };
            }

            ///atomically attempts to mark this slot as active/in-use, returns true if successful
            fn tryAcquire(self: *HazardSlot) bool {
                if (!self.active.load(.acquire)) {
                    return self.active.cmpxchgStrong(false, true, .acq_rel, .acquire) == null;
                }
                return false;
            }
            
            ///clears the protected pointer and marks the slot as inactive
            fn release(self: *HazardSlot) void {
                self.ptr.store(null, .release);
                self.active.store(false, .release);
            }
        };
        
        /// Thread-local storage containing multiple hazard slots and a list of retired (to-be-freed) pointers.
        const HazardRecord = struct {
            hazards: [MAX_HAZARDS_PER_THREAD]HazardSlot,
            retired: std.ArrayList(*T),
            next: std.atomic.Value(?*HazardRecord),
            thread_id: std.Thread.Id,
            epoch: std.atomic.Value(u64),  //  epoch for safe cleanup
            in_use: std.atomic.Value(bool), // Mark if record is actively used
            
            /// creates a new hazard record for a specific thread with empty hazard slots and retired list
            fn init(allocator: std.mem.Allocator, thread_id: std.Thread.Id) !*HazardRecord {
                const record = try allocator.create(HazardRecord);
                record.* = HazardRecord{
                    .hazards = [_]HazardSlot{HazardSlot.init()} ** MAX_HAZARDS_PER_THREAD,
                    .retired = std.ArrayList(*T).init(allocator),
                    .next = std.atomic.Value(?*HazardRecord).init(null),
                    .thread_id = thread_id,
                    .epoch = std.atomic.Value(u64).init(0),
                    .in_use = std.atomic.Value(bool).init(true),
                };
                return record;
            }
            
            /// cleans up the retired pointer list and deallocates the record
            fn deinit(self: *HazardRecord, allocator: std.mem.Allocator) void {
                self.retired.deinit();
                allocator.destroy(self);
            }

            /// marks this record as no longer in use (for dead thread cleanup)
            fn markUnused(self: *HazardRecord) void {
                self.in_use.store(false, .release);
            }
            
            /// checks if this record is actively being used by a live thread
            fn isInUse(self: *HazardRecord) bool {
                return self.in_use.load(.acquire);
            }
        };
        // ***********************************************************
        

        // ******************** Core Management **********************
        /// creates a new hazard pointer manager with empty record list and zero global epoch
        pub fn init(allocator: std.mem.Allocator) Self {
            return Self{
                .allocator = allocator,
                .head = std.atomic.Value(?*HazardRecord).init(null),
                .global_epoch = std.atomic.Value(u64).init(0),
            };
        }

        /// Cleans up all hazard records and force-frees all retired pointers (called at shutdown)
        pub fn deinit(self: *Self) void {
            // Clean up all records
            var current = self.head.load(.acquire);
            while (current) |record| {
                const next = record.next.load(.acquire);
                
                // Force cleanup of all retired pointers
                for (record.retired.items) |ptr| {
                    self.allocator.destroy(ptr);
                }
                
                record.deinit(self.allocator);
                current = next;
            }
        }
        // ***********************************************************
        

        // ******************** Epoch Management *********************
        /// Returns the current global epoch counter value
        pub fn getCurrentEpoch(self: *Self) u64 {
            return self.global_epoch.load(.acquire);
        }
        
        /// Increments the global epoch counter and returns the new value (used for safe cleanup timing)
        pub fn advanceEpoch(self: *Self) u64 {
            return self.global_epoch.fetchAdd(1, .acq_rel) + 1;
        }
        // ***********************************************************
    

        // **************** Thread Record Management  ****************
        /// Finds existing hazard record for current thread or creates a new one, 
        /// updates the record's epoch to current global epoch
        pub fn getOrCreateRecord(self: *Self) !*HazardRecord {
            const current_thread_id = std.Thread.getCurrentId();
            
            // Look for existing record for this thread
            var current = self.head.load(.acquire);
            while (current) |record| {
                if (record.thread_id == current_thread_id and record.isInUse()) {
                    // Update epoch to current
                    record.epoch.store(self.getCurrentEpoch(), .release);
                    return record;
                }
                current = record.next.load(.acquire);
            }
            
            // Create new record for this thread
            const record = try HazardRecord.init(self.allocator, current_thread_id);
            record.epoch.store(self.getCurrentEpoch(), .release);
            
            var head = self.head.load(.acquire);
            while (true) {
                record.next.store(head, .release);
                if (self.head.cmpxchgStrong(head, record, .acq_rel, .acquire)) |actual_head| {
                    head = actual_head;  // CAS failed, retry with actual current value
                } else {
                    break;  // CAS succeeded
                }
            }
            
            return record;
        }
        // ***********************************************************
        

        // ***************** Pointer Protection  *********************
        /// Safely loads a pointer from an atomic variable while protecting it from deallocation. Uses a retry loop to handle ABA problem:
        /// Loads the pointer value
        /// Stores it in a hazard slot
        /// Re-reads the pointer to verify it hasn't changed
        /// If changed, retries; if same, returns a guard protecting the pointer
        pub fn protectLoad(self: *Self, atomic_ptr: *std.atomic.Value(?*T)) !?HazardGuard(T) {
            const record = try self.getOrCreateRecord();
            
            // Find available hazard slot
            for (&record.hazards) |*slot| {
                if (!slot.active.load(.acquire)) {
                    if (slot.active.cmpxchgStrong(false, true, .acq_rel, .acquire) == null) {
                        // FIXED: Proper retry loop to handle ABA problem
                        while (true) {
                            // Step 1: Load the pointer we want to protect
                            const ptr1 = atomic_ptr.load(.acquire);
                            
                            // Step 2: Store it in our hazard pointer slot with seq_cst ordering
                            // This ensures the store is globally visible before we continue
                            slot.ptr.store(ptr1, .seq_cst);
                            
                            // Step 3: Re-read the atomic pointer with seq_cst to check for races
                            // The seq_cst ordering ensures proper synchronization without explicit fence
                            const ptr2 = atomic_ptr.load(.seq_cst);
                            
                            // Step 4: If they match, we successfully protected it
                            if (ptr1 == ptr2) {
                                if (ptr1) |p| {
                                    return HazardGuard(T){
                                        .slot = slot,
                                        .ptr = p,
                                    };
                                } else {
                                    // Pointer is null, release slot and return null
                                    slot.active.store(false, .release);
                                    return null;
                                }
                            }
                            
                            // Step 5: Pointers don't match - ABA detected, retry
                            // The atomic_ptr changed between our load and store,
                            // so we need to try again with the new value
                        }
                    }
                }
            }
            
            return error.NoAvailableHazardSlots;
        }

        
        /// Simpler protection for already-valid pointers 
        /// (WARNING: only safe if caller guarantees pointer validity)
        pub fn protect(self: *Self, ptr: *T) !HazardGuard(T) {
            const record = try self.getOrCreateRecord();
            
            // Find available hazard slot
            for (&record.hazards) |*slot| {
                if (slot.tryAcquire()) {
                    slot.ptr.store(ptr, .release);
                    return HazardGuard(T){
                        .slot = slot,
                        .ptr = ptr,
                    };
                }
            }
            
            return error.NoAvailableHazardSlots;
        }
        // ***********************************************************


        // ***************** Memory Reclamation **********************
        /// Adds a pointer to the current thread's retired list for later cleanup, triggers cleanup if retired list gets too large
        pub fn retire(self: *Self, ptr: *T) !void {
            const record = try self.getOrCreateRecord();
            
            // Try to append, handle allocation failure gracefully
            record.retired.append(ptr) catch |err| {
                // If we can't track it for later cleanup, we have to leak it
                // This is better than use-after-free
                std.log.warn("Failed to retire pointer due to allocation failure: {}", .{err});
                return err;
            };
            
            // Only cleanup when we have enough retired pointers to make it worthwhile
            if (record.retired.items.len >= MAX_RETIRED_POINTERS) {
                try self.cleanup(record);
            }
        }
        
        /// Immediately attempts to clean up retired pointers for the current thread
        pub fn forceCleanup(self: *Self) !void {
            const current_thread_id = std.Thread.getCurrentId();
            
            var current = self.head.load(.acquire);
            while (current) |record| {
                if (record.thread_id == current_thread_id and record.isInUse()) {
                    try self.cleanup(record);
                    break;
                }
                current = record.next.load(.acquire);
            }
        }
        
        ///  Garbage collects hazard records from threads that have died, freeing their retired pointers
        pub fn cleanupDeadThreads(self: *Self) void {
            var prev: ?*HazardRecord = null;
            var current = self.head.load(.acquire);
            
            while (current) |record| {
                const next = record.next.load(.acquire);
                
                if (!record.isInUse()) {
                    // Attempt to remove dead record
                    if (prev) |p| {
                        if (p.next.cmpxchgStrong(record, next, .acq_rel, .acquire) == null) {
                            // Successfully unlinked, clean up
                            for (record.retired.items) |ptr| {
                                self.allocator.destroy(ptr);
                            }
                            record.deinit(self.allocator);
                        }
                    } else {
                        // Trying to remove head
                        if (self.head.cmpxchgStrong(record, next, .acq_rel, .acquire) == null) {
                            for (record.retired.items) |ptr| {
                                self.allocator.destroy(ptr);
                            }
                            record.deinit(self.allocator);
                        }
                    }
                } else {
                    prev = record;
                }
                
                current = next;
            }
        }
        // ***********************************************************
        
        
        // ***************** Internal Cleanup Logic ******************
        /// Core cleanup algorithm:
        /// Advances global epoch
        /// Scans all active hazard pointers across all threads
        /// Sorts protected pointers for efficient lookup
        /// Frees retired pointers that are not currently protected by any thread
        fn cleanup(self: *Self, record: *HazardRecord) !void {
            if (record.retired.items.len == 0) return;
            
            // Advance epoch before cleanup
            _ = self.advanceEpoch();
            
            var protected = std.ArrayList(*T).init(self.allocator);
            defer protected.deinit();
            
            // Collect all protected pointers from all threads safely
            try self.scanAllHazards(&protected);
            
            // Sort protected pointers for efficient lookup
            std.mem.sort(*T, protected.items, {}, struct {
                fn lessThan(_: void, a: *T, b: *T) bool {
                    return @intFromPtr(a) < @intFromPtr(b);
                }
            }.lessThan);
            
            // Free unprotected retired pointers
            var i: usize = 0;
            while (i < record.retired.items.len) {
                const ptr = record.retired.items[i];
                
                // Binary search for this pointer in protected list
                const found = std.sort.binarySearch(*T, protected.items, ptr, struct {
                    fn compare(key: *T, mid_item: *T) std.math.Order {
                        const key_addr = @intFromPtr(key);
                        const mid_addr = @intFromPtr(mid_item);
                        if (key_addr < mid_addr) return .lt;
                        if (key_addr > mid_addr) return .gt;
                        return .eq;
                    }
                }.compare);
                
                if (found == null) {
                    // Not protected, safe to free
                    self.allocator.destroy(ptr);
                    _ = record.retired.swapRemove(i);
                } else {
                    i += 1;
                }
            }
        }
        
        /// Collects all currently protected pointers from all active thread records, validates epochs to ensure safety
        fn scanAllHazards(self: *Self, protected: *std.ArrayList(*T)) !void {
            const scan_epoch = self.getCurrentEpoch();
            
            var current = self.head.load(.acquire);
            while (current) |record| {
                // Only scan records that are in use and from current or recent epoch
                if (record.isInUse() and record.epoch.load(.acquire) <= scan_epoch) {
                    // Scan hazards with double-check
                    for (&record.hazards) |*slot| {
                        if (slot.active.load(.acquire)) {
                            if (slot.ptr.load(.acquire)) |ptr| {
                                // Verify slot is still active after reading pointer
                                if (slot.active.load(.acquire)) {
                                    try protected.append(ptr);
                                }
                            }
                        }
                    }
                }
                current = record.next.load(.acquire);
            }
        }
        // ***********************************************************
    };
}

/// HazardGuard: RAII Wrapper for pointer protections
pub fn HazardGuard(comptime T: type) type {
    return struct {
        const Self = @This();
        
        slot: *HazardPointer(T).HazardSlot,
        ptr: *T,
        
        pub fn get(self: *const Self) *T {
            return self.ptr;
        }
        
        pub fn release(self: *Self) void {
            self.slot.release();
        }
    };
}
