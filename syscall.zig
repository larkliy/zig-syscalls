const std = @import("std");
const win = std.os.windows;
const Coff = std.coff.Coff;

const L = std.unicode.utf8ToUtf16LeStringLiteral;

const IMAGE_EXPORT_DIRECTORY = extern struct {
    Characteristics: u32,
    TimeDateStamp: u32,
    MajorVersion: u16,
    MinorVersion: u16,
    Name: u32,
    Base: u32,
    NumberOfFunctions: u32,
    NumberOfNames: u32,
    AddressOfFunctions: u32,
    AddressOfNames: u32,
    AddressOfNameOrdinals: u32,
};

pub threadlocal var s_instance: SyscallFinder = undefined;

pub const SyscallFinder = struct {
    allocator: std.mem.Allocator,
    syscalls: std.AutoHashMap(u32, u32),
    modules: []ModuleInfo,

    pub fn init(allocator: std.mem.Allocator) !SyscallFinder {
        return SyscallFinder{
            .allocator = allocator,
            .syscalls = .init(allocator),
            .modules = try getAllModules(allocator)
        };
    }

    pub fn getSyscallCodeByName(self: *SyscallFinder, comptime sys_name: []const u8) !u32 {
        comptime {
            if (!std.mem.startsWith(u8, sys_name, "Zw") 
                and !std.mem.startsWith(u8, sys_name, "Nt")) {
                @compileError("The function must have the prefix 'Zw' or 'Nt'.");
            }
        }

        var func_addr: ?usize = undefined; 
        const sys_name_hash = comptime hashU8(sys_name);

        if (self.syscalls.get(sys_name_hash)) |value| {
            return value;
        }

        for (self.modules) |module| {
            func_addr = try getExportAddressByHash(sys_name_hash, module);
            if (func_addr != null) break;
        }

        if (func_addr) |value| {
            const code = try getSyscallcode(value);
            try self.syscalls.put(sys_name_hash, code);

            return code;
        } else {
            return error.SyscallNotFound;
        }
    }

    fn getSyscallcode(func_addr: usize) !u32 {
        var addr: [*]const u8 = @ptrFromInt(func_addr);
        const code_pos = std.mem.indexOf(u8, addr[0..16], &[_]u8{ 0x4C, 0x8B, 0xD1, 0xB8 }).?;
        addr += code_pos;
        return std.mem.readInt(u32, addr[4..8], .little);
    }

    const ModuleInfo = struct { 
        base: [*]const u8,
        len: usize,
    };

    fn getAllModules(allocator: std.mem.Allocator) ![]ModuleInfo {
        var module_list = std.ArrayList(ModuleInfo).empty;

        const head = &win.peb().Ldr.InLoadOrderModuleList;

        var curr = head.Flink;

        while (head != curr) : (curr = curr.Flink) {
            const entry: *win.LDR_DATA_TABLE_ENTRY = @ptrCast(curr);

            try module_list.append(allocator, ModuleInfo{ 
                .base = @ptrCast(entry.DllBase), 
                .len = @intCast(entry.SizeOfImage)
            });
        }

        return try module_list.toOwnedSlice(allocator);
    }

    fn getExportAddressByHash(syscall_hash: u32, info: ModuleInfo) !?usize {
        var coff = try Coff.init(info.base[0..info.len], true);

        const export_dir = coff.getDataDirectories()[@intFromEnum(std.coff.DirectoryEntry.EXPORT)];
        if (export_dir.virtual_address == 0) return null;

        const exports: *const IMAGE_EXPORT_DIRECTORY = @ptrCast(@alignCast(&coff.data[export_dir.virtual_address]));

        const names_rva_ptr: [*]const u32 = @ptrCast(@alignCast(&coff.data[exports.AddressOfNames]));
        const ordinals_ptr: [*]const u16 = @ptrCast(@alignCast(&coff.data[exports.AddressOfNameOrdinals]));
        const functions_ptr: [*]const u32 = @ptrCast(@alignCast(&coff.data[exports.AddressOfFunctions]));

        for (0..exports.NumberOfNames) |i| {
            const name_rva = names_rva_ptr[i];
            const current_name_ptr: [*:0]const u8 = @ptrCast(&coff.data[name_rva]);
            const current_name = std.mem.span(current_name_ptr);

            if (hashU8(current_name) == syscall_hash) {
                const ordinal = ordinals_ptr[i];
                const func_rva = functions_ptr[ordinal];
                return @intFromPtr(info.base) + func_rva;
            }
        }

        return null;
    }

    fn hashU8(buffer: []const u8) u32 {
        return std.hash.Fnv1a_32.hash(buffer);
    }

    pub fn hashU16(name_u16: []const u16) u32 {
        var hasher = std.hash.Fnv1a_32.init();
        
        for (name_u16) |wc| {
            const c = std.ascii.toLower(@as(u8, @truncate(wc)));
            hasher.update(&[_]u8{c});
        }
        
        return hasher.final();
    }

    pub fn deinit(self: *SyscallFinder) void {
        self.syscalls.deinit();
        self.allocator.free(self.modules);
    }
};

fn toUsize(val: anytype) usize {
    const T = @TypeOf(val);
    if (T == @TypeOf(null)) return 0;
    switch (@typeInfo(T)) {
        .bool => return if (val) 1 else 0,
        .int, .comptime_int => return @bitCast(@as(isize, @intCast(val))),
        .pointer => return @intFromPtr(val),
        .optional => {
            if (val) |v| return toUsize(v);
            return 0;
        },
        else => @compileError("Unsupported argument type for syscall: " ++ @typeName(T)),
    }
}

pub fn doSyscall(comptime name: []const u8, args: anytype) usize {
    var abi_args: [10]usize = .{0} ** 10;
    inline for (args, 0..) |arg, i| {
        abi_args[i] = toUsize(arg);
    }

    const ssn = s_instance.getSyscallCodeByName(name) catch return 0;

    return switch (args.len) {
        0 => asm volatile ("syscall"
            : [ret] "={rax}" (-> usize),
            : [ssn] "{rax}" (ssn),
            : .{ .rcx = true, .r11 = true, .memory = true }
        ),
        1 => asm volatile ("syscall"
            : [ret] "={rax}" (-> usize),
            : [ssn] "{rax}" (ssn),
              [a1] "{r10}" (abi_args[0]),
            : .{ .rcx = true, .r11 = true, .memory = true }
        ),
        2 => asm volatile ("syscall"
            : [ret] "={rax}" (-> usize),
            : [ssn] "{rax}" (ssn),
              [a1] "{r10}" (abi_args[0]),
              [a2] "{rdx}" (abi_args[1]),
            : .{ .rcx = true, .r11 = true, .memory = true }
        ),
        3 => asm volatile ("syscall"
            : [ret] "={rax}" (-> usize),
            : [ssn] "{rax}" (ssn),
              [a1] "{r10}" (abi_args[0]),
              [a2] "{rdx}" (abi_args[1]),
              [a3] "{r8}" (abi_args[2]),
            : .{ .rcx = true, .r11 = true, .memory = true }
        ),
        4 => asm volatile ("syscall"
            : [ret] "={rax}" (-> usize),
            : [ssn] "{rax}" (ssn),
              [a1] "{r10}" (abi_args[0]),
              [a2] "{rdx}" (abi_args[1]),
              [a3] "{r8}" (abi_args[2]),
              [a4] "{r9}" (abi_args[3]),
            : .{ .rcx = true, .r11 = true, .memory = true }
        ),
        5 => asm volatile (
            \\ sub $0x30, %%rsp
            \\ mov %[a5], 0x28(%%rsp)
            \\ syscall
            \\ add $0x30, %%rsp
            : [ret] "={rax}" (-> usize),
            : [ssn] "{rax}" (ssn),
              [a1] "{r10}" (abi_args[0]),
              [a2] "{rdx}" (abi_args[1]),
              [a3] "{r8}" (abi_args[2]),
              [a4] "{r9}" (abi_args[3]),
              [a5] "r" (abi_args[4]),
            : .{ .rcx = true, .r11 = true, .memory = true }
        ),
        6 => asm volatile (
            \\ sub $0x38, %%rsp
            \\ mov %[a5], 0x28(%%rsp)
            \\ mov %[a6], 0x30(%%rsp)
            \\ syscall
            \\ add $0x38, %%rsp
            : [ret] "={rax}" (-> usize),
            : [ssn] "{rax}" (ssn),
              [a1] "{r10}" (abi_args[0]),
              [a2] "{rdx}" (abi_args[1]),
              [a3] "{r8}" (abi_args[2]),
              [a4] "{r9}" (abi_args[3]),
              [a5] "r" (abi_args[4]),
              [a6] "r" (abi_args[5]),
            : .{ .rcx = true, .r11 = true, .memory = true }
        ),
        7 => asm volatile (
            \\ sub $0x40, %%rsp
            \\ mov %[a5], 0x28(%%rsp)
            \\ mov %[a6], 0x30(%%rsp)
            \\ mov %[a7], 0x38(%%rsp)
            \\ syscall
            \\ add $0x40, %%rsp
            : [ret] "={rax}" (-> usize),
            : [ssn] "{rax}" (ssn),
              [a1] "{r10}" (abi_args[0]),
              [a2] "{rdx}" (abi_args[1]),
              [a3] "{r8}" (abi_args[2]),
              [a4] "{r9}" (abi_args[3]),
              [a5] "r" (abi_args[4]),
              [a6] "r" (abi_args[5]),
              [a7] "r" (abi_args[6]),
            : .{ .rcx = true, .r11 = true, .memory = true }
        ),
        8 => asm volatile (
            \\ sub $0x48, %%rsp
            \\ mov %[a5], 0x28(%%rsp)
            \\ mov %[a6], 0x30(%%rsp)
            \\ mov %[a7], 0x38(%%rsp)
            \\ mov %[a8], 0x40(%%rsp)
            \\ syscall
            \\ add $0x48, %%rsp
            : [ret] "={rax}" (-> usize),
            : [ssn] "{rax}" (ssn),
              [a1] "{r10}" (abi_args[0]),
              [a2] "{rdx}" (abi_args[1]),
              [a3] "{r8}" (abi_args[2]),
              [a4] "{r9}" (abi_args[3]),
              [a5] "r" (abi_args[4]),
              [a6] "r" (abi_args[5]),
              [a7] "r" (abi_args[6]),
              [a8] "r" (abi_args[7]),
            : .{ .rcx = true, .r11 = true, .memory = true }
        ),
        9 => asm volatile (
            \\ sub $0x50, %%rsp
            \\ mov %[a5], 0x28(%%rsp)
            \\ mov %[a6], 0x30(%%rsp)
            \\ mov %[a7], 0x38(%%rsp)
            \\ mov %[a8], 0x40(%%rsp)
            \\ mov %[a9], 0x48(%%rsp)
            \\ syscall
            \\ add $0x50, %%rsp
            : [ret] "={rax}" (-> usize),
            : [ssn] "{rax}" (ssn),
              [a1] "{r10}" (abi_args[0]),
              [a2] "{rdx}" (abi_args[1]),
              [a3] "{r8}" (abi_args[2]),
              [a4] "{r9}" (abi_args[3]),
              [a5] "r" (abi_args[4]),
              [a6] "r" (abi_args[5]),
              [a7] "r" (abi_args[6]),
              [a8] "r" (abi_args[7]),
              [a9] "r" (abi_args[8]),
            : .{ .rcx = true, .r11 = true, .memory = true }
        ),
        10 => asm volatile (
            \\ sub $0x58, %%rsp
            \\ mov %[a5], 0x28(%%rsp)
            \\ mov %[a6], 0x30(%%rsp)
            \\ mov %[a7], 0x38(%%rsp)
            \\ mov %[a8], 0x40(%%rsp)
            \\ mov %[a9], 0x48(%%rsp)
            \\ mov %[a10], 0x50(%%rsp)
            \\ syscall
            \\ add $0x58, %%rsp
            : [ret] "={rax}" (-> usize),
            : [ssn] "{rax}" (ssn),
              [a1] "{r10}" (abi_args[0]),
              [a2] "{rdx}" (abi_args[1]),
              [a3] "{r8}" (abi_args[2]),
              [a4] "{r9}" (abi_args[3]),
              [a5] "r" (abi_args[4]),
              [a6] "r" (abi_args[5]),
              [a7] "r" (abi_args[6]),
              [a8] "r" (abi_args[7]),
              [a9] "r" (abi_args[8]),
              [a10] "r" (abi_args[9]),
            : .{ .rcx = true, .r11 = true, .memory = true }
        ),
        else => @compileError("doSyscall supports a maximum of 10 arguments."),
    };
}