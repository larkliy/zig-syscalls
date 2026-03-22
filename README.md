# zig-syscalls

## Features
- Dynamic SSN discovery by parsing PEB and export tables.
- SSN caching using FNV1a hashing.
- Supports up to 10 syscall arguments.
- Manual stack adjustment for x64 calling convention.

## Usage

```zig
const std = @import("std");

// Initialize the global finder instance
s_instance = try SyscallFinder.init(allocator);
defer s_instance.deinit();

// Execute a syscall by name
const status = doSyscall("NtOpenProcess", .{
    &handle,
    PROCESS_ALL_ACCESS,
    &obj_attr,
    &client_id,
});
```

## Implementation Details
- **Resolution**: Iterates through `InLoadOrderModuleList` to find exports.
- **Pattern**: Searches for the `mov eax, SSN` instruction sequence (`4C 8B D1 B8`).
- **Assembly**: Uses `asm volatile` with manual stack management for 5+ arguments.
