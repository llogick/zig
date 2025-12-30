const Threaded = @This();

const builtin = @import("builtin");
const native_os = builtin.os.tag;
const is_windows = native_os == .windows;
const is_darwin = native_os.isDarwin();
const is_debug = builtin.mode == .Debug;

const std = @import("../std.zig");
const Io = std.Io;
const net = std.Io.net;
const File = std.Io.File;
const Dir = std.Io.Dir;
const HostName = std.Io.net.HostName;
const IpAddress = std.Io.net.IpAddress;
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;
const assert = std.debug.assert;
const posix = std.posix;
const windows = std.os.windows;
const ws2_32 = std.os.windows.ws2_32;

/// Thread-safe.
allocator: Allocator,
mutex: std.Thread.Mutex = .{},
cond: std.Thread.Condition = .{},
run_queue: std.SinglyLinkedList = .{},
join_requested: bool = false,
stack_size: usize,
/// All threads are spawned detached; this is how we wait until they all exit.
wait_group: std.Thread.WaitGroup = .{},
async_limit: Io.Limit,
concurrent_limit: Io.Limit = .unlimited,
/// Error from calling `std.Thread.getCpuCount` in `init`.
cpu_count_error: ?std.Thread.CpuCountError,
/// Number of threads that are unavailable to take tasks. To calculate
/// available count, subtract this from either `async_limit` or
/// `concurrent_limit`.
busy_count: usize = 0,
worker_threads: std.atomic.Value(?*Thread),
pid: Pid = .unknown,

wsa: if (is_windows) Wsa else struct {} = .{},

have_signal_handler: bool,
old_sig_io: if (have_sig_io) posix.Sigaction else void,
old_sig_pipe: if (have_sig_pipe) posix.Sigaction else void,

use_sendfile: UseSendfile = .default,
use_copy_file_range: UseCopyFileRange = .default,
use_fcopyfile: UseFcopyfile = .default,
use_fchmodat2: UseFchmodat2 = .default,

stderr_writer: File.Writer = .{
    .io = undefined,
    .interface = Io.File.Writer.initInterface(&.{}),
    .file = if (is_windows) undefined else .stderr(),
    .mode = .streaming,
},
stderr_mode: Io.Terminal.Mode = .no_color,
stderr_writer_initialized: bool = false,

argv0: Argv0,
environ: Environ,

pub const Argv0 = switch (native_os) {
    .openbsd, .haiku => struct {
        value: ?[*:0]const u8 = null,
    },
    else => struct {},
};

pub const Environ = struct {
    /// Unmodified data directly from the OS.
    block: Block = &.{},
    /// Protected by `mutex`. Determines whether the other fields have been
    /// memoized based on `block`.
    initialized: bool = false,
    /// Protected by `mutex`. Memoized based on `block`. Tracks whether the
    /// environment variables are present, ignoring their value.
    exist: Exist = .{},
    /// Protected by `mutex`. Memoized based on `block`.
    string: String = .{},
    /// Protected by `mutex`. Tracks the problem, if any, that occurred when
    /// trying to scan environment variables.
    ///
    /// Errors are only possible on WASI.
    err: ?Error = null,

    pub const Error = Allocator.Error || Io.UnexpectedError;

    pub const Block = []const [*:0]const u8;

    pub const Exist = struct {
        NO_COLOR: bool = false,
        CLICOLOR_FORCE: bool = false,
    };

    pub const String = switch (native_os) {
        .openbsd, .haiku => struct {
            PATH: ?[:0]const u8 = null,
        },
        else => struct {},
    };
};

pub const Pid = if (native_os == .linux) enum(posix.pid_t) {
    unknown = 0,
    _,
} else enum(u0) { unknown = 0 };

pub const UseSendfile = if (have_sendfile) enum {
    enabled,
    disabled,
    pub const default: UseSendfile = .enabled;
} else enum {
    disabled,
    pub const default: UseSendfile = .disabled;
};

pub const UseCopyFileRange = if (have_copy_file_range) enum {
    enabled,
    disabled,
    pub const default: UseCopyFileRange = .enabled;
} else enum {
    disabled,
    pub const default: UseCopyFileRange = .disabled;
};

pub const UseFcopyfile = if (have_fcopyfile) enum {
    enabled,
    disabled,
    pub const default: UseFcopyfile = .enabled;
} else enum {
    disabled,
    pub const default: UseFcopyfile = .disabled;
};

pub const UseFchmodat2 = if (have_fchmodat2 and !have_fchmodat_flags) enum {
    enabled,
    disabled,
    pub const default: UseFchmodat2 = .enabled;
} else enum {
    disabled,
    pub const default: UseFchmodat2 = .disabled;
};

const Runnable = struct {
    node: std.SinglyLinkedList.Node,
    startFn: *const fn (*Runnable, *Thread, *Threaded) void,
};

const Group = struct {
    ptr: *Io.Group,

    /// Returns a correctly-typed pointer to the `Io.Group.token` field.
    ///
    /// The status indicates how many pending tasks are in the group, whether the group has been
    /// canceled, and whether the group has been awaited.
    ///
    /// Note that the zero value of `Status` intentionally represents the initial group state (empty
    /// with no awaiters). This is a requirement of `Io.Group`.
    fn status(g: Group) *std.atomic.Value(Status) {
        return @ptrCast(&g.ptr.token);
    }
    /// Returns a correctly-typed pointer to the `Io.Group.state` field. The double-pointer here is
    /// intentional, because the `state` field itself stores a pointer, and this function returns a
    /// pointer to that field.
    ///
    /// On completion of the whole group, if `status` indicates that there is an awaiter, the last
    /// task must increment this `u32` and do a futex wake on it to signal that awaiter.
    fn awaiter(g: Group) **std.atomic.Value(u32) {
        return @ptrCast(&g.ptr.state);
    }

    const Status = packed struct(usize) {
        num_running: @Int(.unsigned, @bitSizeOf(usize) - 2),
        have_awaiter: bool,
        canceled: bool,
    };

    const Task = struct {
        runnable: Runnable,
        group: *Io.Group,
        func: *const fn (context: *const anyopaque) void,
        context_alignment: Alignment,
        alloc_len: usize,

        /// `Task.runnable.node` is `undefined` in the created `Task`.
        fn create(
            gpa: Allocator,
            group: Group,
            context: []const u8,
            context_alignment: Alignment,
            func: *const fn (context: *const anyopaque) void,
        ) Allocator.Error!*Task {
            const max_context_misalignment = context_alignment.toByteUnits() -| @alignOf(Task);
            const worst_case_context_offset = context_alignment.forward(@sizeOf(Task) + max_context_misalignment);
            const alloc_len = worst_case_context_offset + context.len;

            const task: *Task = @ptrCast(@alignCast(try gpa.alignedAlloc(u8, .of(Task), alloc_len)));
            errdefer comptime unreachable;

            task.* = .{
                .runnable = .{
                    .node = undefined,
                    .startFn = &start,
                },
                .group = group.ptr,
                .func = func,
                .context_alignment = context_alignment,
                .alloc_len = alloc_len,
            };
            @memcpy(task.contextPointer()[0..context.len], context);
            return task;
        }

        fn destroy(task: *Task, gpa: Allocator) void {
            const base: [*]align(@alignOf(Task)) u8 = @ptrCast(task);
            gpa.free(base[0..task.alloc_len]);
        }

        fn contextPointer(task: *Task) [*]u8 {
            const base: [*]u8 = @ptrCast(task);
            const offset = task.context_alignment.forward(@intFromPtr(base) + @sizeOf(Task)) - @intFromPtr(base);
            return base + offset;
        }

        fn start(r: *Runnable, thread: *Thread, t: *Threaded) void {
            const task: *Task = @fieldParentPtr("runnable", r);
            const group: Group = .{ .ptr = task.group };

            // This would be a simple store, but it's upgraded to an RMW so we can use `.acquire` to
            // enforce the ordering between this and the `group.status().load` below. Paired with
            // the `.release` rmw on `Thread.status` in `cancelThreads`, this creates a StoreLoad
            // barrier which guarantees that when a group is canceled, either we see the cancelation
            // in the group status, or the canceler sees our thread status so can directly notify us
            // of the cancelation.
            _ = thread.status.swap(.{
                .cancelation = .none,
                .awaitable = .fromGroup(group.ptr),
            }, .acquire);
            if (group.status().load(.monotonic).canceled) {
                thread.status.store(.{
                    .cancelation = .canceling,
                    .awaitable = .fromGroup(group.ptr),
                }, .monotonic);
            }

            assertGroupResult(task.func(task.contextPointer()));

            thread.status.store(.{ .cancelation = .none, .awaitable = .null }, .monotonic);
            const old_status = group.status().fetchSub(.{
                .num_running = 1,
                .have_awaiter = false,
                .canceled = false,
            }, .acq_rel); // acquire `group.awaiter()`, release task results
            assert(old_status.num_running > 0);
            if (old_status.have_awaiter and old_status.num_running == 1) {
                const to_signal = group.awaiter().*;
                // `awaiter` should only be modified by us. For another thread to see `num_running`
                // drop to 0 after this point would indicate that another task started up, meaning
                // `async`/`cancel` was racing with awaited group completion.
                group.awaiter().* = undefined;
                _ = to_signal.fetchAdd(1, .release); // release results
                Thread.futexWake(&to_signal.raw, 1);
            }

            // Task completed. Self-destruct sequence initiated.
            task.destroy(t.allocator);
        }
    };

    /// Assumes the caller has already atomically updated the group status to indicate cancelation,
    /// and notifies any already-running threads of this cancelation.
    fn cancelThreads(g: Group, t: *Threaded) bool {
        var any_blocked = false;
        var it = t.worker_threads.load(.acquire); // acquire `Thread` values
        while (it) |thread| : (it = thread.next) {
            // This non-mutating RMW exists for ordering reasons: see comment in `Group.Task.start` for reasons.
            _ = thread.status.fetchOr(.{ .cancelation = @enumFromInt(0), .awaitable = .null }, .release);
            if (thread.cancelAwaitable(.fromGroup(g.ptr))) any_blocked = true;
        }
        return any_blocked;
    }

    /// Uses `Thread.signalCanceledSyscall` to signal any threads which are still blocked in a
    /// syscall for this group and have not observed a cancelation request yet. Returns `true` if
    /// more signals may be necessary, in which case the caller must call this again after a delay.
    fn signalAllCanceledSyscalls(g: Group, t: *Threaded) bool {
        var any_signaled = false;
        var it = t.worker_threads.load(.acquire); // acquire `Thread` values
        while (it) |thread| : (it = thread.next) {
            if (thread.signalCanceledSyscall(t, .fromGroup(g.ptr))) any_signaled = true;
        }
        return any_signaled;
    }

    /// The caller has canceled `g`. Inform any threads working on that group of the cancelation if
    /// necessary, and wait for `g` to finish (indicated by `num_completed` being incremented from 0
    /// to 1), while sending regular signals to threads if necessary for them to unblock from any
    /// cancelable syscalls.
    ///
    /// `skip_signals` means it is already known that no threads are currently working on the group
    /// so no notifications or signals are necessary.
    fn waitForCancelWithSignaling(
        g: Group,
        t: *Threaded,
        num_completed: *std.atomic.Value(u32),
        skip_signals: bool,
    ) void {
        var need_signal: bool = !skip_signals and g.cancelThreads(t);
        var timeout_ns: u64 = 1 << 10;
        while (true) {
            need_signal = need_signal and g.signalAllCanceledSyscalls(t);
            Thread.futexWaitUncancelable(&num_completed.raw, 0, if (need_signal) timeout_ns else null);
            switch (num_completed.load(.acquire)) { // acquire task results
                0 => {},
                1 => break,
                else => unreachable,
            }
            timeout_ns <<|= 1;
        }
    }
};

/// Trailing data:
/// 1. context
/// 2. result
const Future = struct {
    runnable: Runnable,
    func: *const fn (context: *const anyopaque, result: *anyopaque) void,
    status: std.atomic.Value(Status),
    /// On completion, increment this `u32` and do a futex wake on it.
    awaiter: *std.atomic.Value(u32),
    context_alignment: Alignment,
    result_offset: usize,
    alloc_len: usize,

    const Status = packed struct(usize) {
        /// The values of this enum are chosen so that await/cancel can just OR with 0b01 and 0b11
        /// respectively. That *does* clobber `.done`, but that's actually fine, because if the tag
        /// is `.done` then only the awaiter is referencing this `Future` anyway.
        tag: enum(u2) {
            /// The future is queued or running (depending on whether `thread` is set).
            pending = 0b00,
            /// Like `pending`, but the future is being awaited. `Future.awaiter` is populated.
            pending_awaited = 0b01,
            /// Like `pending`, but the future is being canceled. `Future.awaiter` is populated.
            pending_canceled = 0b11,
            /// The future has already completed. `thread` is `null`.
            done = 0b10,
        },
        /// When the future begins execution, this is atomically updated from `null` to the thread running the
        /// `Future`, so that cancelation knows which thread to cancel.
        thread: Thread.PackedPtr,
    };

    /// `Future.runnable.node` is `undefined` in the created `Future`.
    fn create(
        gpa: Allocator,
        result_len: usize,
        result_alignment: Alignment,
        context: []const u8,
        context_alignment: Alignment,
        func: *const fn (context: *const anyopaque, result: *anyopaque) void,
    ) Allocator.Error!*Future {
        const max_context_misalignment = context_alignment.toByteUnits() -| @alignOf(Future);
        const worst_case_context_offset = context_alignment.forward(@sizeOf(Future) + max_context_misalignment);
        const worst_case_result_offset = result_alignment.forward(worst_case_context_offset + context.len);
        const alloc_len = worst_case_result_offset + result_len;

        const future: *Future = @ptrCast(@alignCast(try gpa.alignedAlloc(u8, .of(Future), alloc_len)));
        errdefer comptime unreachable;

        const actual_context_addr = context_alignment.forward(@intFromPtr(future) + @sizeOf(Future));
        const actual_result_addr = result_alignment.forward(actual_context_addr + context.len);
        const actual_result_offset = actual_result_addr - @intFromPtr(future);
        future.* = .{
            .runnable = .{
                .node = undefined,
                .startFn = &start,
            },
            .func = func,
            .status = .init(.{
                .tag = .pending,
                .thread = .null,
            }),
            .awaiter = undefined,
            .context_alignment = context_alignment,
            .result_offset = actual_result_offset,
            .alloc_len = alloc_len,
        };
        @memcpy(future.contextPointer()[0..context.len], context);
        return future;
    }

    fn destroy(future: *Future, gpa: Allocator) void {
        const base: [*]align(@alignOf(Future)) u8 = @ptrCast(future);
        gpa.free(base[0..future.alloc_len]);
    }

    fn resultPointer(future: *Future) [*]u8 {
        const base: [*]u8 = @ptrCast(future);
        return base + future.result_offset;
    }

    fn contextPointer(future: *Future) [*]u8 {
        const base: [*]u8 = @ptrCast(future);
        const context_offset = future.context_alignment.forward(@intFromPtr(future) + @sizeOf(Future)) - @intFromPtr(future);
        return base + context_offset;
    }

    fn start(r: *Runnable, thread: *Thread, t: *Threaded) void {
        _ = t;
        const future: *Future = @fieldParentPtr("runnable", r);

        thread.status.store(.{
            .cancelation = .none,
            .awaitable = .fromFuture(future),
        }, .monotonic);
        {
            const old_status = future.status.fetchOr(.{
                .tag = .pending,
                .thread = .pack(thread),
            }, .release);
            assert(old_status.thread == .null);
            switch (old_status.tag) {
                .pending, .pending_awaited => {},
                .pending_canceled => thread.status.store(.{
                    .cancelation = .canceling,
                    .awaitable = .fromFuture(future),
                }, .monotonic),
                .done => unreachable,
            }
        }

        future.func(future.contextPointer(), future.resultPointer());

        thread.status.store(.{ .cancelation = .none, .awaitable = .null }, .monotonic);
        const old_status = future.status.swap(.{
            .tag = .done,
            .thread = .null,
        }, .acq_rel); // acquire `future.awaiter`, release results
        switch (old_status.tag) {
            .pending => {},
            .pending_awaited, .pending_canceled => {
                const to_signal = future.awaiter;
                _ = to_signal.fetchAdd(1, .release); // release results
                Thread.futexWake(&to_signal.raw, 1);
            },
            .done => unreachable,
        }
    }

    /// The caller has canceled `future`. `thread` is the thread currently running that future.
    /// Inform `thread` of the cancelation if necessary, and wait for `future` to finish (indicated
    /// by `num_completed` being incremented from 0 to 1), while sending regular signals to `thread`
    /// if necessary for it to unblock from a cancelable syscall.
    fn waitForCancelWithSignaling(
        future: *Future,
        t: *Threaded,
        num_completed: *std.atomic.Value(u32),
        thread: ?*Thread,
    ) void {
        var need_signal: bool = thread != null and thread.?.cancelAwaitable(.fromFuture(future));
        var timeout_ns: u64 = 1 << 10;
        while (true) {
            need_signal = need_signal and thread.?.signalCanceledSyscall(t, .fromFuture(future));
            Thread.futexWaitUncancelable(&num_completed.raw, 0, if (need_signal) timeout_ns else null);
            switch (num_completed.load(.acquire)) { // acquire task results
                0 => {},
                1 => break,
                else => unreachable,
            }
            timeout_ns <<|= 1;
        }
    }
};

/// A sequence of (ptr_bit_width - 3) bits which uniquely identifies a group or future. The bits are
/// the MSBs of the `*Io.Group` or `*Future`. These things do not necessarily have 3 zero bits at
/// the end (they are pointer-aligned, so on 32-bit targets only have 2), but because they both have
/// a *size* of at least 8 bytes, no two groups/futures in memory at the same time will have the
/// same value for all of these bits. In other words, given a group/future pointer, the next group
/// or future must be at least 8 bytes later, so its address will have a different value for one of
/// the top (ptr_bit_width - 3) bits.
const AwaitableId = enum(@Int(.unsigned, @bitSizeOf(usize) - 3)) {
    comptime {
        assert(@sizeOf(Future) >= 8);
        assert(@sizeOf(Io.Group) >= 8);
    }
    null = 0,
    all_ones = std.math.maxInt(@Int(.unsigned, @bitSizeOf(usize) - 3)),
    _,
    const Split = packed struct(usize) { low: u3, high: AwaitableId };
    fn fromGroup(g: *Io.Group) AwaitableId {
        const split: Split = @bitCast(@intFromPtr(g));
        return split.high;
    }
    fn fromFuture(f: *Future) AwaitableId {
        const split: Split = @bitCast(@intFromPtr(f));
        return split.high;
    }
};

const Thread = struct {
    next: ?*Thread,

    id: std.Thread.Id,
    handle: Handle,

    status: std.atomic.Value(Status),

    cancel_protection: Io.CancelProtection,
    /// Always released when `Status.cancelation` is set to `.parked`.
    futex_waiter: if (use_parking_futex) ?*parking_futex.Waiter else ?noreturn,

    const Handle = Handle: {
        if (std.Thread.use_pthreads) break :Handle std.c.pthread_t;
        if (builtin.target.os.tag == .windows) break :Handle windows.HANDLE;
        break :Handle void;
    };

    const Status = packed struct(usize) {
        /// The specific values of these enum fields are chosen to simplify the implementation of
        /// the transformations we need to apply to this state.
        cancelation: enum(u3) {
            /// The thread has not yet been canceled, and is not in a cancelable operation.
            /// To request cancelation, just set the status to `.canceling`.
            none = 0b000,

            /// The thread is parked in a cancelable futex wait or sleep.
            /// Only applicable if `use_parking_futex` or `use_parking_sleep`.
            /// To request cancelation, set the status to `.canceling` and unpark the thread.
            /// To unpark for another reason (futex wake), set the status to `.none` and unpark the thread.
            parked = 0b001,

            /// The thread is blocked in a cancelable system call.
            /// To request cancelation, set the status to `.blocked_canceling` and repeatedly interrupt the system call until the status changes.
            blocked = 0b011,

            /// Windows-only: the thread is blocked in a call to `GetAddrInfoExW`.
            /// To request cancelation, set the status to `.canceling` and call `GetAddrInfoExCancel`.
            blocked_windows_dns = 0b010,

            /// The thread has an outstanding cancelation request but is not in a cancelable operation.
            /// When it acknowledges the cancelation, it will set the status to `.canceled`.
            canceling = 0b110,

            /// The thread has received and acknowledged a cancelation request.
            /// If `recancel` is called, the status will revert to `.canceling`, but otherwise, the status
            /// will not change for the remainder of this task's execution.
            canceled = 0b111,

            /// The thread is blocked in a cancelable system call, and is being canceled. The thread which triggered the cancelation will send signals to this thread
            /// until its status changes.
            blocked_canceling = 0b101,
        },

        /// We cannot turn this value back into a pointer. Instead, it exists so that a task can be
        /// canceled by a cmpxchg on thread status: if it is running the task we want to cancel,
        /// then update the `cancelation` field.
        awaitable: AwaitableId,
    };

    const SignaleeId = if (std.Thread.use_pthreads) std.c.pthread_t else std.Thread.Id;

    threadlocal var current: ?*Thread = null;

    /// The thread is neither in a syscall nor entering one, but we want to check for cancelation
    /// anyway. If there is a pending cancel request, acknowledge it and return `error.Canceled`.
    fn checkCancel() Io.Cancelable!void {
        const thread = Thread.current orelse return;
        switch (thread.cancel_protection) {
            .blocked => return,
            .unblocked => {},
        }
        // Here, unlike `Syscall.checkCancel`, it's not particularly likely that we're canceled, so
        // it seems preferable to do a cheap atomic load and, in the unlikely case, a separate store
        // to acknowledge. Besides, the state transitions we need here can't be done with one atomic
        // OR/AND/XOR on `Status.cancelation`, so we don't actually have any other option.
        const status = thread.status.load(.monotonic);
        switch (status.cancelation) {
            .parked => unreachable,
            .blocked => unreachable,
            .blocked_windows_dns => unreachable,
            .blocked_canceling => unreachable,
            .none, .canceled => {},
            .canceling => {
                thread.status.store(.{
                    .cancelation = .canceled,
                    .awaitable = status.awaitable,
                }, .monotonic);
                return error.Canceled;
            },
        }
    }

    fn futexWaitUncancelable(ptr: *const u32, expect: u32, timeout_ns: ?u64) void {
        return Thread.futexWaitInner(ptr, expect, true, timeout_ns) catch unreachable;
    }

    fn futexWait(ptr: *const u32, expect: u32, timeout_ns: ?u64) Io.Cancelable!void {
        return Thread.futexWaitInner(ptr, expect, false, timeout_ns);
    }

    fn futexWaitInner(ptr: *const u32, expect: u32, uncancelable: bool, timeout_ns: ?u64) Io.Cancelable!void {
        @branchHint(.cold);

        if (builtin.single_threaded) unreachable; // nobody would ever wake us

        if (use_parking_futex) {
            return parking_futex.wait(
                ptr,
                expect,
                uncancelable,
                if (timeout_ns) |ns| .{ .duration = .{
                    .raw = .fromNanoseconds(ns),
                    .clock = .boot,
                } } else .none,
            );
        } else if (builtin.cpu.arch.isWasm()) {
            comptime assert(builtin.cpu.has(.wasm, .atomics));
            // TODO implement cancelation for WASM futex waits by signaling the futex
            if (!uncancelable) try Thread.checkCancel();
            const to: i64 = if (timeout_ns) |ns| ns else -1;
            const signed_expect: i32 = @bitCast(expect);
            const result = asm volatile (
                \\local.get %[ptr]
                \\local.get %[expected]
                \\local.get %[timeout]
                \\memory.atomic.wait32 0
                \\local.set %[ret]
                : [ret] "=r" (-> u32),
                : [ptr] "r" (ptr),
                  [expected] "r" (signed_expect),
                  [timeout] "r" (to),
            );
            switch (result) {
                0 => {}, // ok
                1 => {}, // expected != loaded
                2 => {}, // timeout
                else => assert(!is_debug),
            }
        } else switch (native_os) {
            .linux => {
                const linux = std.os.linux;
                var ts_buffer: linux.timespec = undefined;
                const ts: ?*linux.timespec = if (timeout_ns) |ns| ts: {
                    ts_buffer = timestampToPosix(ns);
                    break :ts &ts_buffer;
                } else null;
                const syscall: Syscall = if (uncancelable) .{ .thread = null } else try .start();
                const rc = linux.futex_4arg(ptr, .{ .cmd = .WAIT, .private = true }, expect, ts);
                syscall.finish();
                switch (linux.errno(rc)) {
                    .SUCCESS => {}, // notified by `wake()`
                    .INTR => {}, // caller's responsibility to retry
                    .AGAIN => {}, // ptr.* != expect
                    .INVAL => {}, // possibly timeout overflow
                    .TIMEDOUT => {},
                    .FAULT => recoverableOsBugDetected(), // ptr was invalid
                    else => recoverableOsBugDetected(),
                }
            },
            .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos => {
                const c = std.c;
                const flags: c.UL = .{
                    .op = .COMPARE_AND_WAIT,
                    .NO_ERRNO = true,
                };
                const syscall: Syscall = if (uncancelable) .{ .thread = null } else try .start();
                const status = switch (darwin_supports_ulock_wait2) {
                    true => c.__ulock_wait2(flags, ptr, expect, ns: {
                        const ns = timeout_ns orelse break :ns 0;
                        if (ns == 0) break :ns 1;
                        break :ns ns;
                    }, 0),
                    false => c.__ulock_wait(flags, ptr, expect, us: {
                        const ns = timeout_ns orelse break :us 0;
                        const us = std.math.lossyCast(u32, ns / std.time.ns_per_us);
                        if (us == 0) break :us 1;
                        break :us us;
                    }),
                };
                syscall.finish();
                if (status >= 0) return;
                switch (@as(c.E, @enumFromInt(-status))) {
                    .INTR => {}, // spurious wake
                    // Address of the futex was paged out. This is unlikely, but possible in theory, and
                    // pthread/libdispatch on darwin bother to handle it. In this case we'll return
                    // without waiting, but the caller should retry anyway.
                    .FAULT => {},
                    .TIMEDOUT => {}, // timeout
                    else => recoverableOsBugDetected(),
                }
            },
            .freebsd => {
                const flags = @intFromEnum(std.c.UMTX_OP.WAIT_UINT_PRIVATE);
                var tm_size: usize = 0;
                var tm: std.c._umtx_time = undefined;
                var tm_ptr: ?*const std.c._umtx_time = null;
                if (timeout_ns) |ns| {
                    tm_ptr = &tm;
                    tm_size = @sizeOf(@TypeOf(tm));
                    tm.flags = 0; // use relative time not UMTX_ABSTIME
                    tm.clockid = .MONOTONIC;
                    tm.timeout = timestampToPosix(ns);
                }
                const syscall: Syscall = if (uncancelable) .{ .thread = null } else try .start();
                const rc = std.c._umtx_op(@intFromPtr(ptr), flags, @as(c_ulong, expect), tm_size, @intFromPtr(tm_ptr));
                syscall.finish();
                if (is_debug) switch (posix.errno(rc)) {
                    .SUCCESS => {},
                    .FAULT => unreachable, // one of the args points to invalid memory
                    .INVAL => unreachable, // arguments should be correct
                    .TIMEDOUT => {}, // timeout
                    .INTR => {}, // spurious wake
                    else => unreachable,
                };
            },
            .openbsd => {
                var tm: std.c.timespec = undefined;
                var tm_ptr: ?*const std.c.timespec = null;
                if (timeout_ns) |ns| {
                    tm_ptr = &tm;
                    tm = timestampToPosix(ns);
                }
                const syscall: Syscall = if (uncancelable) .{ .thread = null } else try .start();
                const rc = std.c.futex(
                    ptr,
                    std.c.FUTEX.WAIT | std.c.FUTEX.PRIVATE_FLAG,
                    @as(c_int, @bitCast(expect)),
                    tm_ptr,
                    null, // uaddr2 is ignored
                );
                syscall.finish();
                if (is_debug) switch (posix.errno(rc)) {
                    .SUCCESS => {},
                    .NOSYS => unreachable, // constant op known good value
                    .AGAIN => {}, // contents of uaddr != val
                    .INVAL => unreachable, // invalid timeout
                    .TIMEDOUT => {}, // timeout
                    .INTR => {}, // a signal arrived
                    .CANCELED => {}, // a signal arrived and SA_RESTART was set
                    else => unreachable,
                };
            },
            .dragonfly => {
                var timeout_us: c_int = undefined;
                if (timeout_ns) |ns| {
                    timeout_us = std.math.cast(c_int, ns / std.time.ns_per_us) orelse std.math.maxInt(c_int);
                } else {
                    timeout_us = 0;
                }
                const syscall: Syscall = if (uncancelable) .{ .thread = null } else try .start();
                const rc = std.c.umtx_sleep(@ptrCast(ptr), @bitCast(expect), timeout_us);
                syscall.finish();
                if (is_debug) switch (std.posix.errno(rc)) {
                    .SUCCESS => {},
                    .BUSY => {}, // ptr != expect
                    .AGAIN => {}, // maybe timed out, or paged out, or hit 2s kernel refresh
                    .INTR => {}, // spurious wake
                    .INVAL => unreachable, // invalid timeout
                    else => unreachable,
                };
            },
            else => @compileError("unimplemented: futexWait"),
        }
    }

    fn futexWake(ptr: *const u32, max_waiters: u32) void {
        @branchHint(.cold);
        assert(max_waiters != 0);

        if (builtin.single_threaded) return; // nothing to wake up

        if (use_parking_futex) {
            return parking_futex.wake(ptr, max_waiters);
        } else if (builtin.cpu.arch.isWasm()) {
            comptime assert(builtin.cpu.has(.wasm, .atomics));
            const woken_count = asm volatile (
                \\local.get %[ptr]
                \\local.get %[waiters]
                \\memory.atomic.notify 0
                \\local.set %[ret]
                : [ret] "=r" (-> u32),
                : [ptr] "r" (ptr),
                  [waiters] "r" (max_waiters),
            );
            _ = woken_count; // can be 0 when linker flag 'shared-memory' is not enabled
        } else switch (native_os) {
            .linux => {
                const linux = std.os.linux;
                switch (linux.errno(linux.futex_3arg(
                    ptr,
                    .{ .cmd = .WAKE, .private = true },
                    @min(max_waiters, std.math.maxInt(i32)),
                ))) {
                    .SUCCESS => return, // successful wake up
                    .INVAL => return, // invalid futex_wait() on ptr done elsewhere
                    .FAULT => return, // pointer became invalid while doing the wake
                    else => return recoverableOsBugDetected(), // deadlock due to operating system bug
                }
            },
            .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos => {
                const c = std.c;
                const flags: c.UL = .{
                    .op = .COMPARE_AND_WAIT,
                    .NO_ERRNO = true,
                    .WAKE_ALL = max_waiters > 1,
                };
                while (true) {
                    const status = c.__ulock_wake(flags, ptr, 0);
                    if (status >= 0) return;
                    switch (@as(c.E, @enumFromInt(-status))) {
                        .INTR, .CANCELED => continue, // spurious wake()
                        .FAULT => unreachable, // __ulock_wake doesn't generate EFAULT according to darwin pthread_cond_t
                        .NOENT => return, // nothing was woken up
                        .ALREADY => unreachable, // only for UL.Op.WAKE_THREAD
                        else => unreachable, // deadlock due to operating system bug
                    }
                }
            },
            .freebsd => {
                const rc = std.c._umtx_op(
                    @intFromPtr(ptr),
                    @intFromEnum(std.c.UMTX_OP.WAKE_PRIVATE),
                    @as(c_ulong, max_waiters),
                    0, // there is no timeout struct
                    0, // there is no timeout struct pointer
                );
                switch (posix.errno(rc)) {
                    .SUCCESS => {},
                    .FAULT => {}, // it's ok if the ptr doesn't point to valid memory
                    .INVAL => unreachable, // arguments should be correct
                    else => unreachable, // deadlock due to operating system bug
                }
            },
            .openbsd => {
                const rc = std.c.futex(
                    ptr,
                    std.c.FUTEX.WAKE | std.c.FUTEX.PRIVATE_FLAG,
                    @min(max_waiters, std.math.maxInt(c_int)),
                    null, // timeout is ignored
                    null, // uaddr2 is ignored
                );
                assert(rc >= 0);
            },
            .dragonfly => {
                // will generally return 0 unless the address is bad
                _ = std.c.umtx_wakeup(
                    @ptrCast(ptr),
                    @min(max_waiters, std.math.maxInt(c_int)),
                );
            },
            else => @compileError("unimplemented: futexWake"),
        }
    }

    /// Cancels `thread` if it is working on `awaitable`.
    ///
    /// It is possible that `thread` gets canceled by this function, but is blocked in a syscall. In
    /// that case, the thread may need to be sent a signal to interrupt the call. This function will
    /// return `true` to indicate this, in which case the caller must call `signalCanceledSyscall`.
    fn cancelAwaitable(thread: *Thread, awaitable: AwaitableId) bool {
        var status = thread.status.load(.monotonic);
        while (true) {
            if (status.awaitable != awaitable) return false; // thread is working on something else
            status = switch (status.cancelation) {
                .none => thread.status.cmpxchgWeak(
                    .{ .cancelation = .none, .awaitable = awaitable },
                    .{ .cancelation = .canceling, .awaitable = awaitable },
                    .monotonic,
                    .monotonic,
                ) orelse return false,

                .parked => thread.status.cmpxchgWeak(
                    .{ .cancelation = .parked, .awaitable = awaitable },
                    .{ .cancelation = .canceling, .awaitable = awaitable },
                    .acquire, // acquire `thread.futex_waiter`
                    .monotonic,
                ) orelse {
                    if (!use_parking_futex and !use_parking_sleep) unreachable;
                    if (thread.futex_waiter) |futex_waiter| {
                        parking_futex.removeCanceledWaiter(futex_waiter);
                    }
                    unpark(&.{thread.id}, null);
                    return false;
                },

                .blocked => thread.status.cmpxchgWeak(
                    .{ .cancelation = .blocked, .awaitable = awaitable },
                    .{ .cancelation = .blocked_canceling, .awaitable = awaitable },
                    .monotonic,
                    .monotonic,
                ) orelse return true,

                .blocked_windows_dns => thread.status.cmpxchgWeak(
                    .{ .cancelation = .blocked_windows_dns, .awaitable = awaitable },
                    .{ .cancelation = .canceling, .awaitable = awaitable },
                    .monotonic,
                    .monotonic,
                ) orelse {
                    if (builtin.target.os.tag != .windows) unreachable;
                    if (true) {
                        // TODO: cancel Windows DNS queries. This code path is currently impossible
                        // as `netLookupFallible` doesn't actually use `.blocked_windows_dns` yet.
                        unreachable;
                    }
                    return false;
                },

                .canceling, .canceled => {
                    // This can happen when the task start raced with the cancelation, so the thread
                    // saw the cancelation on the future/group *and* we are trying to signal the
                    // thread here.
                    return false;
                },

                .blocked_canceling => unreachable,
            };
        }
    }

    /// Sends a signal to `thread` if it is still blocked in a syscall (i.e. has not yet observed
    /// the cancelation request from `cancelAwaitable`).
    ///
    /// Unfortunately, the signal could arrive before the syscall actually starts, so the interrupt
    /// is missed. To handle this, we may need to send multiple signals. As such, if this function
    /// returns `true`, then it should be called again after a short delay to send another signal if
    /// the thread is still blocked. For the implementation, `Future.waitForCancelWithSignaling` and
    /// `Group.waitForCancelWithSignaling`: they use exponential backoff starting at a 1us delay and
    /// doubling each call. In practice, it is rare to send more than one signal.
    fn signalCanceledSyscall(thread: *Thread, t: *Threaded, awaitable: AwaitableId) bool {
        const bad_status: Status = .{ .cancelation = .blocked_canceling, .awaitable = awaitable };
        if (thread.status.load(.monotonic) != bad_status) return false;

        // The thread ID and/or handle can be read non-atomically because they never change and were
        // released by the store that made `thread` available to us.

        if (std.Thread.use_pthreads) {
            return switch (std.c.pthread_kill(thread.handle, .IO)) {
                0 => true,
                else => false,
            };
        } else switch (builtin.target.os.tag) {
            .linux => {
                const pid: posix.pid_t = pid: {
                    const cached_pid = @atomicLoad(Pid, &t.pid, .monotonic);
                    if (cached_pid != .unknown) break :pid @intFromEnum(cached_pid);
                    const pid = std.os.linux.getpid();
                    @atomicStore(Pid, &t.pid, @enumFromInt(pid), .monotonic);
                    break :pid pid;
                };
                return switch (std.os.linux.tgkill(pid, @bitCast(thread.id), .IO)) {
                    0 => true,
                    else => false,
                };
            },
            .windows => {
                var iosb: windows.IO_STATUS_BLOCK = undefined;
                return switch (windows.ntdll.NtCancelSynchronousIoFile(thread.handle, null, &iosb)) {
                    .NOT_FOUND => true, // this might mean the operation hasn't started yet
                    .SUCCESS => false, // the OS confirmed that our cancelation worked
                    else => false,
                };
            },
            else => return false,
        }
    }

    /// Like a `*Thread`, but 2 bits smaller than a pointer (because the LSBs are always 0 due to
    /// alignment) so that those two bits can be used in a `packed struct`.
    const PackedPtr = enum(@Int(.unsigned, @bitSizeOf(usize) - 2)) {
        null = 0,
        all_ones = std.math.maxInt(@Int(.unsigned, @bitSizeOf(usize) - 2)),
        _,

        const Split = packed struct(usize) { low: u2, high: PackedPtr };
        fn pack(ptr: *Thread) PackedPtr {
            const split: Split = @bitCast(@intFromPtr(ptr));
            assert(split.low == 0);
            return split.high;
        }
        fn unpack(ptr: PackedPtr) ?*Thread {
            const split: Split = .{ .low = 0, .high = ptr };
            return @ptrFromInt(@as(usize, @bitCast(split)));
        }
    };
};

const Syscall = struct {
    thread: ?*Thread,
    /// Marks entry to a syscall region. This should be tightly scoped around the actual syscall
    /// to minimize races. The syscall must be marked as "finished" by `checkCancel`, `finish`,
    /// or one of the wrappers of `finish`.
    fn start() Io.Cancelable!Syscall {
        const thread = Thread.current orelse return .{ .thread = null };
        switch (thread.cancel_protection) {
            .blocked => return .{ .thread = null },
            .unblocked => {},
        }
        switch (thread.status.fetchOr(.{
            .cancelation = @enumFromInt(0b011),
            .awaitable = .null,
        }, .monotonic).cancelation) {
            .parked => unreachable,
            .blocked => unreachable,
            .blocked_windows_dns => unreachable,
            .blocked_canceling => unreachable,
            .none => return .{ .thread = thread }, // new status is `.blocked`
            .canceling => return error.Canceled, // new status is `.canceled`
            .canceled => return .{ .thread = null }, // new status is `.canceled` (unchanged)
        }
    }
    /// Checks whether this syscall has been canceled. This should be called when a syscall is
    /// interrupted through a mechanism which may indicate cancelation, or may be spurious. If
    /// the syscall was canceled, it is finished and `error.Canceled` is returned. Otherwise,
    /// the syscall is not marked finished, and the caller should retry.
    fn checkCancel(s: Syscall) Io.Cancelable!void {
        const thread = s.thread orelse return;
        switch (thread.status.fetchOr(.{
            .cancelation = @enumFromInt(0b010),
            .awaitable = .null,
        }, .monotonic).cancelation) {
            .none => unreachable,
            .parked => unreachable,
            .blocked_windows_dns => unreachable,
            .canceling => unreachable,
            .canceled => unreachable,
            .blocked => {}, // new status is `.blocked` (unchanged)
            .blocked_canceling => return error.Canceled, // new status is `.canceled`
        }
    }
    /// Marks this syscall as finished.
    fn finish(s: Syscall) void {
        const thread = s.thread orelse return;
        switch (thread.status.fetchXor(.{
            .cancelation = @enumFromInt(0b011),
            .awaitable = .null,
        }, .monotonic).cancelation) {
            .none => unreachable,
            .parked => unreachable,
            .blocked_windows_dns => unreachable,
            .canceling => unreachable,
            .canceled => unreachable,
            .blocked => {}, // new status is `.none`
            .blocked_canceling => {}, // new status is `.canceling`
        }
    }
    /// Convenience wrapper which calls `finish`, then returns `err`.
    fn fail(s: Syscall, err: anytype) @TypeOf(err) {
        s.finish();
        return err;
    }
    /// Convenience wrapper which calls `finish`, then calls `Threaded.errnoBug`.
    fn errnoBug(s: Syscall, err: posix.E) Io.UnexpectedError {
        @branchHint(.cold);
        s.finish();
        return Threaded.errnoBug(err);
    }
    /// Convenience wrapper which calls `finish`, then calls `posix.unexpectedErrno`.
    fn unexpectedErrno(s: Syscall, err: posix.E) Io.UnexpectedError {
        @branchHint(.cold);
        s.finish();
        return posix.unexpectedErrno(err);
    }
    /// Convenience wrapper which calls `finish`, then calls `windows.statusBug`.
    fn ntstatusBug(s: Syscall, status: windows.NTSTATUS) Io.UnexpectedError {
        @branchHint(.cold);
        s.finish();
        return windows.statusBug(status);
    }
    /// Convenience wrapper which calls `finish`, then calls `windows.unexpectedStatus`.
    fn unexpectedNtstatus(s: Syscall, status: windows.NTSTATUS) Io.UnexpectedError {
        @branchHint(.cold);
        s.finish();
        return windows.unexpectedStatus(status);
    }
};

const max_iovecs_len = 8;
const splat_buffer_size = 64;

comptime {
    if (@TypeOf(posix.IOV_MAX) != void) assert(max_iovecs_len <= posix.IOV_MAX);
}

pub const InitOptions = struct {
    /// Affects how many bytes are memory-mapped for threads.
    stack_size: usize = std.Thread.SpawnConfig.default_stack_size,
    /// Maximum thread pool size (excluding main thread) when dispatching async
    /// tasks. Until this limit, calls to `Io.async` when all threads are busy will
    /// cause a new thread to be spawned and permanently added to the pool. After
    /// this limit, calls to `Io.async` when all threads are busy run the task
    /// immediately.
    ///
    /// Defaults to a number equal to logical CPU cores.
    ///
    /// Protected by `Threaded.mutex` once the I/O instance is already in use. See
    /// `setAsyncLimit`.
    async_limit: ?Io.Limit = null,
    /// Maximum thread pool size (excluding main thread) for dispatching concurrent
    /// tasks. Until this limit, calls to `Io.concurrent` will increase the thread
    /// pool size.
    ///
    /// concurrent tasks. After this number, calls to `Io.concurrent` return
    /// `error.ConcurrencyUnavailable`.
    concurrent_limit: Io.Limit = .unlimited,
    /// Affects the following operations:
    /// * `processExecutablePath` on OpenBSD and Haiku.
    argv0: Argv0 = .{},
    /// Affects the following operations:
    /// * `fileIsTty`
    /// * `processExecutablePath` on OpenBSD and Haiku (observes "PATH").
    environ: Environ = .{},
};

/// Related:
/// * `init_single_threaded`
pub fn init(
    /// Must be threadsafe. Only used for the following functions:
    /// * `Io.VTable.async`
    /// * `Io.VTable.concurrent`
    /// * `Io.VTable.groupAsync`
    /// * `Io.VTable.groupConcurrent`
    /// If these functions are avoided, then `Allocator.failing` may be passed
    /// here.
    gpa: Allocator,
    options: InitOptions,
) Threaded {
    if (builtin.single_threaded) return .init_single_threaded;

    const cpu_count = std.Thread.getCpuCount();

    var t: Threaded = .{
        .allocator = gpa,
        .stack_size = options.stack_size,
        .async_limit = options.async_limit orelse if (cpu_count) |n| .limited(n - 1) else |_| .nothing,
        .concurrent_limit = options.concurrent_limit,
        .cpu_count_error = if (cpu_count) |_| null else |e| e,
        .old_sig_io = undefined,
        .old_sig_pipe = undefined,
        .have_signal_handler = false,
        .argv0 = options.argv0,
        .environ = options.environ,
        .worker_threads = .init(null),
    };

    if (posix.Sigaction != void) {
        // This causes sending `posix.SIG.IO` to thread to interrupt blocking
        // syscalls, returning `posix.E.INTR`.
        const act: posix.Sigaction = .{
            .handler = .{ .handler = doNothingSignalHandler },
            .mask = posix.sigemptyset(),
            .flags = 0,
        };
        if (have_sig_io) posix.sigaction(.IO, &act, &t.old_sig_io);
        if (have_sig_pipe) posix.sigaction(.PIPE, &act, &t.old_sig_pipe);
        t.have_signal_handler = true;
    }

    return t;
}

/// Statically initialize such that calls to `Io.VTable.concurrent` will fail
/// with `error.ConcurrencyUnavailable`.
///
/// When initialized this way:
/// * cancel requests have no effect.
/// * `deinit` is safe, but unnecessary to call.
pub const init_single_threaded: Threaded = .{
    .allocator = .failing,
    .stack_size = std.Thread.SpawnConfig.default_stack_size,
    .async_limit = .nothing,
    .cpu_count_error = null,
    .concurrent_limit = .nothing,
    .old_sig_io = undefined,
    .old_sig_pipe = undefined,
    .have_signal_handler = false,
    .argv0 = .{},
    .environ = .{},
    .worker_threads = .init(null),
};

var global_single_threaded_instance: Threaded = .init_single_threaded;

/// In general, the application is responsible for choosing the `Io`
/// implementation and library code should accept an `Io` parameter rather than
/// accessing this declaration. Most code should avoid referencing this
/// declaration entirely.
///
/// However, in some cases such as debugging, it is desirable to hardcode a
/// reference to this `Io` implementation.
///
/// This instance does not support concurrency or cancelation.
pub const global_single_threaded: *Threaded = &global_single_threaded_instance;

pub fn setAsyncLimit(t: *Threaded, new_limit: Io.Limit) void {
    t.mutex.lock();
    defer t.mutex.unlock();
    t.async_limit = new_limit;
}

pub fn deinit(t: *Threaded) void {
    t.join();
    if (is_windows and t.wsa.status == .initialized) {
        if (ws2_32.WSACleanup() != 0) recoverableOsBugDetected();
    }
    if (posix.Sigaction != void and t.have_signal_handler) {
        if (have_sig_io) posix.sigaction(.IO, &t.old_sig_io, null);
        if (have_sig_pipe) posix.sigaction(.PIPE, &t.old_sig_pipe, null);
    }
    t.* = undefined;
}

fn join(t: *Threaded) void {
    if (builtin.single_threaded) return;
    {
        t.mutex.lock();
        defer t.mutex.unlock();
        t.join_requested = true;
    }
    t.cond.broadcast();
    t.wait_group.wait();
}

fn worker(t: *Threaded) void {
    var thread: Thread = .{
        .next = undefined,
        .id = std.Thread.getCurrentId(),
        .handle = handle: {
            if (std.Thread.use_pthreads) break :handle std.c.pthread_self();
            if (builtin.target.os.tag == .windows) break :handle undefined; // populated below
        },
        .status = .init(.{
            .cancelation = .none,
            .awaitable = .null,
        }),
        .cancel_protection = .unblocked,
        .futex_waiter = undefined,
    };
    Thread.current = &thread;

    if (builtin.target.os.tag == .windows) {
        assert(windows.ntdll.NtOpenThread(
            &thread.handle,
            .{
                .SPECIFIC = .{
                    .THREAD = .{
                        .TERMINATE = true, // for `NtCancelSynchronousIoFile`
                    },
                },
            },
            &.{
                .Length = @sizeOf(windows.OBJECT_ATTRIBUTES),
                .RootDirectory = null,
                .ObjectName = null,
                .Attributes = .{},
                .SecurityDescriptor = null,
                .SecurityQualityOfService = null,
            },
            &windows.teb().ClientId,
        ) == .SUCCESS);
    }
    defer if (builtin.target.os.tag == .windows) {
        windows.CloseHandle(thread.handle);
    };

    {
        var head = t.worker_threads.load(.monotonic);
        while (true) {
            thread.next = head;
            head = t.worker_threads.cmpxchgWeak(
                head,
                &thread,
                .release,
                .monotonic,
            ) orelse break;
        }
    }

    defer t.wait_group.finish();

    t.mutex.lock();
    defer t.mutex.unlock();

    while (true) {
        while (t.run_queue.popFirst()) |runnable_node| {
            t.mutex.unlock();
            thread.cancel_protection = .unblocked;
            const runnable: *Runnable = @fieldParentPtr("node", runnable_node);
            runnable.startFn(runnable, &thread, t);
            t.mutex.lock();
            t.busy_count -= 1;
        }
        if (t.join_requested) break;
        t.cond.wait(&t.mutex);
    }
}

pub fn io(t: *Threaded) Io {
    return .{
        .userdata = t,
        .vtable = &.{
            .async = async,
            .concurrent = concurrent,
            .await = await,
            .cancel = cancel,
            .select = select,

            .groupAsync = groupAsync,
            .groupConcurrent = groupConcurrent,
            .groupAwait = groupAwait,
            .groupCancel = groupCancel,

            .recancel = recancel,
            .swapCancelProtection = swapCancelProtection,
            .checkCancel = checkCancel,

            .futexWait = futexWait,
            .futexWaitUncancelable = futexWaitUncancelable,
            .futexWake = futexWake,

            .dirCreateDir = dirCreateDir,
            .dirCreateDirPath = dirCreateDirPath,
            .dirCreateDirPathOpen = dirCreateDirPathOpen,
            .dirStat = dirStat,
            .dirStatFile = dirStatFile,
            .dirAccess = dirAccess,
            .dirCreateFile = dirCreateFile,
            .dirOpenFile = dirOpenFile,
            .dirOpenDir = dirOpenDir,
            .dirClose = dirClose,
            .dirRead = dirRead,
            .dirRealPath = dirRealPath,
            .dirRealPathFile = dirRealPathFile,
            .dirDeleteFile = dirDeleteFile,
            .dirDeleteDir = dirDeleteDir,
            .dirRename = dirRename,
            .dirSymLink = dirSymLink,
            .dirReadLink = dirReadLink,
            .dirSetOwner = dirSetOwner,
            .dirSetFileOwner = dirSetFileOwner,
            .dirSetPermissions = dirSetPermissions,
            .dirSetFilePermissions = dirSetFilePermissions,
            .dirSetTimestamps = dirSetTimestamps,
            .dirHardLink = dirHardLink,

            .fileStat = fileStat,
            .fileLength = fileLength,
            .fileClose = fileClose,
            .fileWriteStreaming = fileWriteStreaming,
            .fileWritePositional = fileWritePositional,
            .fileWriteFileStreaming = fileWriteFileStreaming,
            .fileWriteFilePositional = fileWriteFilePositional,
            .fileReadStreaming = fileReadStreaming,
            .fileReadPositional = fileReadPositional,
            .fileSeekBy = fileSeekBy,
            .fileSeekTo = fileSeekTo,
            .fileSync = fileSync,
            .fileIsTty = fileIsTty,
            .fileEnableAnsiEscapeCodes = fileEnableAnsiEscapeCodes,
            .fileSupportsAnsiEscapeCodes = fileSupportsAnsiEscapeCodes,
            .fileSetLength = fileSetLength,
            .fileSetOwner = fileSetOwner,
            .fileSetPermissions = fileSetPermissions,
            .fileSetTimestamps = fileSetTimestamps,
            .fileLock = fileLock,
            .fileTryLock = fileTryLock,
            .fileUnlock = fileUnlock,
            .fileDowngradeLock = fileDowngradeLock,
            .fileRealPath = fileRealPath,

            .processExecutableOpen = processExecutableOpen,
            .processExecutablePath = processExecutablePath,
            .lockStderr = lockStderr,
            .tryLockStderr = tryLockStderr,
            .unlockStderr = unlockStderr,
            .processSetCurrentDir = processSetCurrentDir,

            .now = now,
            .sleep = sleep,

            .netListenIp = switch (native_os) {
                .windows => netListenIpWindows,
                else => netListenIpPosix,
            },
            .netListenUnix = switch (native_os) {
                .windows => netListenUnixWindows,
                else => netListenUnixPosix,
            },
            .netAccept = switch (native_os) {
                .windows => netAcceptWindows,
                else => netAcceptPosix,
            },
            .netBindIp = switch (native_os) {
                .windows => netBindIpWindows,
                else => netBindIpPosix,
            },
            .netConnectIp = switch (native_os) {
                .windows => netConnectIpWindows,
                else => netConnectIpPosix,
            },
            .netConnectUnix = switch (native_os) {
                .windows => netConnectUnixWindows,
                else => netConnectUnixPosix,
            },
            .netClose = netClose,
            .netShutdown = switch (native_os) {
                .windows => netShutdownWindows,
                else => netShutdownPosix,
            },
            .netRead = switch (native_os) {
                .windows => netReadWindows,
                else => netReadPosix,
            },
            .netWrite = switch (native_os) {
                .windows => netWriteWindows,
                else => netWritePosix,
            },
            .netWriteFile = netWriteFile,
            .netSend = switch (native_os) {
                .windows => netSendWindows,
                else => netSendPosix,
            },
            .netReceive = switch (native_os) {
                .windows => netReceiveWindows,
                else => netReceivePosix,
            },
            .netInterfaceNameResolve = netInterfaceNameResolve,
            .netInterfaceName = netInterfaceName,
            .netLookup = netLookup,
        },
    };
}

/// Same as `io` but disables all networking functionality, which has
/// an additional dependency on Windows (ws2_32).
pub fn ioBasic(t: *Threaded) Io {
    return .{
        .userdata = t,
        .vtable = &.{
            .async = async,
            .concurrent = concurrent,
            .await = await,
            .cancel = cancel,
            .select = select,

            .groupAsync = groupAsync,
            .groupConcurrent = groupConcurrent,
            .groupAwait = groupAwait,
            .groupCancel = groupCancel,

            .recancel = recancel,
            .swapCancelProtection = swapCancelProtection,
            .checkCancel = checkCancel,

            .futexWait = futexWait,
            .futexWaitUncancelable = futexWaitUncancelable,
            .futexWake = futexWake,

            .dirCreateDir = dirCreateDir,
            .dirCreateDirPath = dirCreateDirPath,
            .dirCreateDirPathOpen = dirCreateDirPathOpen,
            .dirStat = dirStat,
            .dirStatFile = dirStatFile,
            .dirAccess = dirAccess,
            .dirCreateFile = dirCreateFile,
            .dirOpenFile = dirOpenFile,
            .dirOpenDir = dirOpenDir,
            .dirClose = dirClose,
            .dirRead = dirRead,
            .dirRealPath = dirRealPath,
            .dirRealPathFile = dirRealPathFile,
            .dirDeleteFile = dirDeleteFile,
            .dirDeleteDir = dirDeleteDir,
            .dirRename = dirRename,
            .dirSymLink = dirSymLink,
            .dirReadLink = dirReadLink,
            .dirSetOwner = dirSetOwner,
            .dirSetFileOwner = dirSetFileOwner,
            .dirSetPermissions = dirSetPermissions,
            .dirSetFilePermissions = dirSetFilePermissions,
            .dirSetTimestamps = dirSetTimestamps,
            .dirHardLink = dirHardLink,

            .fileStat = fileStat,
            .fileLength = fileLength,
            .fileClose = fileClose,
            .fileWriteStreaming = fileWriteStreaming,
            .fileWritePositional = fileWritePositional,
            .fileWriteFileStreaming = fileWriteFileStreaming,
            .fileWriteFilePositional = fileWriteFilePositional,
            .fileReadStreaming = fileReadStreaming,
            .fileReadPositional = fileReadPositional,
            .fileSeekBy = fileSeekBy,
            .fileSeekTo = fileSeekTo,
            .fileSync = fileSync,
            .fileIsTty = fileIsTty,
            .fileEnableAnsiEscapeCodes = fileEnableAnsiEscapeCodes,
            .fileSupportsAnsiEscapeCodes = fileSupportsAnsiEscapeCodes,
            .fileSetLength = fileSetLength,
            .fileSetOwner = fileSetOwner,
            .fileSetPermissions = fileSetPermissions,
            .fileSetTimestamps = fileSetTimestamps,
            .fileLock = fileLock,
            .fileTryLock = fileTryLock,
            .fileUnlock = fileUnlock,
            .fileDowngradeLock = fileDowngradeLock,
            .fileRealPath = fileRealPath,

            .processExecutableOpen = processExecutableOpen,
            .processExecutablePath = processExecutablePath,
            .lockStderr = lockStderr,
            .tryLockStderr = tryLockStderr,
            .unlockStderr = unlockStderr,
            .processSetCurrentDir = processSetCurrentDir,

            .now = now,
            .sleep = sleep,

            .netListenIp = netListenIpUnavailable,
            .netListenUnix = netListenUnixUnavailable,
            .netAccept = netAcceptUnavailable,
            .netBindIp = netBindIpUnavailable,
            .netConnectIp = netConnectIpUnavailable,
            .netConnectUnix = netConnectUnixUnavailable,
            .netClose = netCloseUnavailable,
            .netShutdown = netShutdownUnavailable,
            .netRead = netReadUnavailable,
            .netWrite = netWriteUnavailable,
            .netWriteFile = netWriteFileUnavailable,
            .netSend = netSendUnavailable,
            .netReceive = netReceiveUnavailable,
            .netInterfaceNameResolve = netInterfaceNameResolveUnavailable,
            .netInterfaceName = netInterfaceNameUnavailable,
            .netLookup = netLookupUnavailable,
        },
    };
}

pub const socket_flags_unsupported = is_darwin or native_os == .haiku;
const have_accept4 = !socket_flags_unsupported;
const have_flock_open_flags = @hasField(posix.O, "EXLOCK");
const have_networking = native_os != .wasi;
const have_flock = @TypeOf(posix.system.flock) != void;
const have_sendmmsg = native_os == .linux;
const have_futex = switch (builtin.cpu.arch) {
    .wasm32, .wasm64 => builtin.cpu.has(.wasm, .atomics),
    else => true,
};
const have_preadv = switch (native_os) {
    .windows, .haiku => false,
    else => true,
};
const have_sig_io = posix.SIG != void and @hasField(posix.SIG, "IO");
const have_sig_pipe = posix.SIG != void and @hasField(posix.SIG, "PIPE");
const have_sendfile = if (builtin.link_libc) @TypeOf(std.c.sendfile) != void else native_os == .linux;
const have_copy_file_range = switch (native_os) {
    .linux, .freebsd => true,
    else => false,
};
const have_fcopyfile = is_darwin;
const have_fchmodat2 = native_os == .linux and
    (builtin.os.isAtLeast(.linux, .{ .major = 6, .minor = 6, .patch = 0 }) orelse true) and
    (builtin.abi.isAndroid() or !std.c.versionCheck(.{ .major = 2, .minor = 32, .patch = 0 }));
const have_fchmodat_flags = native_os != .linux or
    (!builtin.abi.isAndroid() and std.c.versionCheck(.{ .major = 2, .minor = 32, .patch = 0 }));

const have_fchown = switch (native_os) {
    .wasi, .windows => false,
    else => true,
};

const have_fchmod = switch (native_os) {
    .windows => false,
    .wasi => builtin.link_libc,
    else => true,
};

const openat_sym = if (posix.lfs64_abi) posix.system.openat64 else posix.system.openat;
const fstat_sym = if (posix.lfs64_abi) posix.system.fstat64 else posix.system.fstat;
const fstatat_sym = if (posix.lfs64_abi) posix.system.fstatat64 else posix.system.fstatat;
const lseek_sym = if (posix.lfs64_abi) posix.system.lseek64 else posix.system.lseek;
const preadv_sym = if (posix.lfs64_abi) posix.system.preadv64 else posix.system.preadv;
const ftruncate_sym = if (posix.lfs64_abi) posix.system.ftruncate64 else posix.system.ftruncate;
const pwritev_sym = if (posix.lfs64_abi) posix.system.pwritev64 else posix.system.pwritev;
const sendfile_sym = if (posix.lfs64_abi) posix.system.sendfile64 else posix.system.sendfile;
const linux_copy_file_range_use_c = std.c.versionCheck(if (builtin.abi.isAndroid()) .{
    .major = 34,
    .minor = 0,
    .patch = 0,
} else .{
    .major = 2,
    .minor = 27,
    .patch = 0,
});
const linux_copy_file_range_sys = if (linux_copy_file_range_use_c) std.c else std.os.linux;

fn async(
    userdata: ?*anyopaque,
    result: []u8,
    result_alignment: Alignment,
    context: []const u8,
    context_alignment: Alignment,
    start: *const fn (context: *const anyopaque, result: *anyopaque) void,
) ?*Io.AnyFuture {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    if (builtin.single_threaded) {
        start(context.ptr, result.ptr);
        return null;
    }

    const gpa = t.allocator;
    const future = Future.create(gpa, result.len, result_alignment, context, context_alignment, start) catch |err| switch (err) {
        error.OutOfMemory => {
            start(context.ptr, result.ptr);
            return null;
        },
    };

    t.mutex.lock();

    const busy_count = t.busy_count;

    if (busy_count >= @intFromEnum(t.async_limit)) {
        t.mutex.unlock();
        future.destroy(gpa);
        start(context.ptr, result.ptr);
        return null;
    }

    t.busy_count = busy_count + 1;

    const pool_size = t.wait_group.value();
    if (pool_size - busy_count == 0) {
        t.wait_group.start();
        const thread = std.Thread.spawn(.{ .stack_size = t.stack_size }, worker, .{t}) catch {
            t.wait_group.finish();
            t.busy_count = busy_count;
            t.mutex.unlock();
            future.destroy(gpa);
            start(context.ptr, result.ptr);
            return null;
        };
        thread.detach();
    }

    t.run_queue.prepend(&future.runnable.node);

    t.mutex.unlock();
    t.cond.signal();
    return @ptrCast(future);
}

fn concurrent(
    userdata: ?*anyopaque,
    result_len: usize,
    result_alignment: Alignment,
    context: []const u8,
    context_alignment: Alignment,
    start: *const fn (context: *const anyopaque, result: *anyopaque) void,
) Io.ConcurrentError!*Io.AnyFuture {
    if (builtin.single_threaded) return error.ConcurrencyUnavailable;

    const t: *Threaded = @ptrCast(@alignCast(userdata));

    const gpa = t.allocator;
    const future = Future.create(gpa, result_len, result_alignment, context, context_alignment, start) catch |err| switch (err) {
        error.OutOfMemory => return error.ConcurrencyUnavailable,
    };
    errdefer future.destroy(gpa);

    t.mutex.lock();
    defer t.mutex.unlock();

    const busy_count = t.busy_count;

    if (busy_count >= @intFromEnum(t.concurrent_limit))
        return error.ConcurrencyUnavailable;

    t.busy_count = busy_count + 1;
    errdefer t.busy_count = busy_count;

    const pool_size = t.wait_group.value();
    if (pool_size - busy_count == 0) {
        t.wait_group.start();
        errdefer t.wait_group.finish();

        const thread = std.Thread.spawn(.{ .stack_size = t.stack_size }, worker, .{t}) catch
            return error.ConcurrencyUnavailable;

        thread.detach();
    }

    t.run_queue.prepend(&future.runnable.node);

    t.cond.signal();
    return @ptrCast(future);
}

fn groupAsync(
    userdata: ?*anyopaque,
    type_erased: *Io.Group,
    context: []const u8,
    context_alignment: Alignment,
    start: *const fn (context: *const anyopaque) Io.Cancelable!void,
) void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const g: Group = .{ .ptr = type_erased };

    if (builtin.single_threaded) return start(context.ptr) catch unreachable;

    const gpa = t.allocator;
    const task = Group.Task.create(gpa, g, context, context_alignment, start) catch |err| switch (err) {
        error.OutOfMemory => return t.assertGroupResult(start(context.ptr)),
    };

    t.mutex.lock();

    const busy_count = t.busy_count;

    if (busy_count >= @intFromEnum(t.async_limit)) {
        t.mutex.unlock();
        task.destroy(gpa);
        return t.assertGroupResult(start(context.ptr));
    }

    t.busy_count = busy_count + 1;

    const pool_size = t.wait_group.value();
    if (pool_size - busy_count == 0) {
        t.wait_group.start();
        const thread = std.Thread.spawn(.{ .stack_size = t.stack_size }, worker, .{t}) catch {
            t.wait_group.finish();
            t.busy_count = busy_count;
            t.mutex.unlock();
            task.destroy(gpa);
            return t.assertGroupResult(start(context.ptr));
        };
        thread.detach();
    }

    // TODO: if this logic is changed to be lock-free, this `fetchAdd` must be released by the queue
    // prepend so that the task doesn't finish without observing this and try to decrement the count
    // below zero.
    _ = g.status().fetchAdd(.{
        .num_running = 1,
        .have_awaiter = false,
        .canceled = false,
    }, .monotonic);
    t.run_queue.prepend(&task.runnable.node);

    t.mutex.unlock();
    t.cond.signal();
}

fn assertGroupResult(result: Io.Cancelable!void) void {
    const cancel_acknowledged = if (Thread.current) |thread|
        switch (thread.status.load(.monotonic).cancelation) {
            .none, .canceling => false,
            .canceled => true,
            .parked => unreachable,
            .blocked => unreachable,
            .blocked_windows_dns => unreachable,
            .blocked_canceling => unreachable,
        }
    else
        false;
    if (result) {
        assert(!cancel_acknowledged); // group task acknowledged cancelation but did not return `error.Canceled`
    } else |err| switch (err) {
        error.Canceled => assert(cancel_acknowledged), // group task returned `error.Canceled` but was never canceled
    }
}

fn groupConcurrent(
    userdata: ?*anyopaque,
    type_erased: *Io.Group,
    context: []const u8,
    context_alignment: Alignment,
    start: *const fn (context: *const anyopaque) Io.Cancelable!void,
) Io.ConcurrentError!void {
    if (builtin.single_threaded) return error.ConcurrencyUnavailable;

    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const g: Group = .{ .ptr = type_erased };

    const gpa = t.allocator;
    const task = Group.Task.create(gpa, g, context, context_alignment, start) catch |err| switch (err) {
        error.OutOfMemory => return error.ConcurrencyUnavailable,
    };
    errdefer task.destroy(gpa);

    t.mutex.lock();
    defer t.mutex.unlock();

    const busy_count = t.busy_count;

    if (busy_count >= @intFromEnum(t.concurrent_limit))
        return error.ConcurrencyUnavailable;

    t.busy_count = busy_count + 1;
    errdefer t.busy_count = busy_count;

    const pool_size = t.wait_group.value();
    if (pool_size - busy_count == 0) {
        t.wait_group.start();
        errdefer t.wait_group.finish();

        const thread = std.Thread.spawn(.{ .stack_size = t.stack_size }, worker, .{t}) catch
            return error.ConcurrencyUnavailable;

        thread.detach();
    }

    // TODO: if this logic is changed to be lock-free, this `fetchAdd` must be released by the queue
    // prepend so that the task doesn't finish without observing this and try to decrement the count
    // below zero.
    _ = g.status().fetchAdd(.{
        .num_running = 1,
        .have_awaiter = false,
        .canceled = false,
    }, .monotonic);
    t.run_queue.prepend(&task.runnable.node);

    t.cond.signal();
}

fn groupAwait(userdata: ?*anyopaque, type_erased: *Io.Group, initial_token: *anyopaque) Io.Cancelable!void {
    _ = initial_token; // we need to load `token` *after* the group finishes
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const g: Group = .{ .ptr = type_erased };

    var num_completed: std.atomic.Value(u32) = .init(0);
    g.awaiter().* = &num_completed;

    const pre_await_status = g.status().fetchOr(.{
        .num_running = 0,
        .have_awaiter = true,
        .canceled = false,
    }, .acq_rel); // acquire results if complete; release `g.awaiter()`

    assert(!pre_await_status.have_awaiter);
    assert(!pre_await_status.canceled);
    if (pre_await_status.num_running == 0) {
        // Already done. Since the group is finished, it's illegal to spawn more tasks in it
        // until we return, so we can access `g.status()` non-atomically.
        g.status().raw.have_awaiter = false;
        return;
    }

    while (Thread.futexWait(&num_completed.raw, 0, null)) {
        switch (num_completed.load(.acquire)) { // acquire task results
            0 => continue,
            1 => break,
            else => unreachable, // group was reused before `await` returned
        }
    } else |err| switch (err) {
        error.Canceled => {
            const pre_cancel_status = g.status().fetchOr(.{
                .num_running = 0,
                .have_awaiter = false,
                .canceled = true,
            }, .acq_rel); // acquire results if complete; release `g.awaiter()`
            assert(pre_cancel_status.have_awaiter);
            assert(!pre_cancel_status.canceled);

            // Even if `pre_cancel_status.num_running == 0`, we still need to wait for the signal,
            // because in that case the last member of the group is already trying to modify it.
            // However, if we know everything is done, we *can* skip signaling blocked threads.
            const skip_signals = pre_cancel_status.num_running == 0;
            g.waitForCancelWithSignaling(t, &num_completed, skip_signals);

            // The group is finished, so it's illegal to spawn more tasks in it until we return, so
            // we can access `g.status()` non-atomically.
            g.status().raw.canceled = false;
            g.status().raw.have_awaiter = false;
            return error.Canceled;
        },
    }

    // The group is finished, so it's illegal to spawn more tasks in it until we return, so
    // we can access `g.status()` non-atomically.
    g.status().raw.have_awaiter = false;
}

fn groupCancel(userdata: ?*anyopaque, type_erased: *Io.Group, initial_token: *anyopaque) void {
    _ = initial_token;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const g: Group = .{ .ptr = type_erased };

    var num_completed: std.atomic.Value(u32) = .init(0);
    g.awaiter().* = &num_completed;

    const pre_cancel_status = g.status().fetchOr(.{
        .num_running = 0,
        .have_awaiter = true,
        .canceled = true,
    }, .acq_rel); // acquire results if complete; release `g.awaiter()`

    assert(!pre_cancel_status.have_awaiter);
    assert(!pre_cancel_status.canceled);
    if (pre_cancel_status.num_running == 0) {
        // Already done. Since the group is finished, it's illegal to spawn more tasks in it
        // until we return, so we can access `g.status()` non-atomically.
        g.status().raw.have_awaiter = false;
        g.status().raw.canceled = false;
        return;
    }

    g.waitForCancelWithSignaling(t, &num_completed, false);

    g.status().raw = .{ .num_running = 0, .have_awaiter = false, .canceled = false };
}

fn recancel(userdata: ?*anyopaque) void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const thread = Thread.current.?; // called `recancel` but was not canceled
    switch (thread.status.fetchXor(.{
        .cancelation = @enumFromInt(0b001),
        .awaitable = .null,
    }, .monotonic).cancelation) {
        .canceled => {},
        .none => unreachable, // called `recancel` but was not canceled
        .canceling => unreachable, // called `recancel` but cancelation was already pending
        .parked => unreachable,
        .blocked => unreachable,
        .blocked_windows_dns => unreachable,
        .blocked_canceling => unreachable,
    }
}

fn swapCancelProtection(userdata: ?*anyopaque, new: Io.CancelProtection) Io.CancelProtection {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const thread = Thread.current orelse return .unblocked;
    const old = thread.cancel_protection;
    thread.cancel_protection = new;
    return old;
}

fn checkCancel(userdata: ?*anyopaque) Io.Cancelable!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    return Thread.checkCancel();
}

fn await(
    userdata: ?*anyopaque,
    any_future: *Io.AnyFuture,
    result: []u8,
    result_alignment: Alignment,
) void {
    _ = result_alignment;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const future: *Future = @ptrCast(@alignCast(any_future));

    var num_completed: std.atomic.Value(u32) = .init(0);
    future.awaiter = &num_completed;

    const pre_await_status = future.status.fetchOr(.{
        .tag = .pending_awaited,
        .thread = .null,
    }, .acq_rel); // acquire results if complete; release `future.awaiter`
    switch (pre_await_status.tag) {
        .pending => while (Thread.futexWait(&num_completed.raw, 0, null)) {
            switch (num_completed.load(.acquire)) { // acquire task results
                0 => continue,
                1 => break,
                else => unreachable, // group was reused before `await` returned
            }
        } else |err| switch (err) {
            error.Canceled => {
                const pre_cancel_status = future.status.fetchOr(.{
                    .tag = .pending_canceled,
                    .thread = .null,
                }, .acq_rel); // acquire results if complete; release `future.awaiter`
                switch (pre_cancel_status.tag) {
                    .pending => unreachable, // invalid state: we already awaited
                    .pending_awaited => {
                        const working_thread = pre_cancel_status.thread.unpack();
                        future.waitForCancelWithSignaling(t, &num_completed, @alignCast(working_thread));
                    },
                    .pending_canceled => unreachable, // `await` raced with `cancel`
                    .done => {
                        // The task just finished, but we still need to wait for the signal, because the
                        // task thread already figured out that they need to update `future.awaiter`.
                        future.waitForCancelWithSignaling(t, &num_completed, null);
                    },
                }
                recancel(t);
            },
        },
        .pending_awaited => unreachable, // `await` raced with `await`
        .pending_canceled => unreachable, // `await` raced with `cancel`
        .done => {},
    }
    @memcpy(result, future.resultPointer());
    future.destroy(t.allocator);
}

fn cancel(
    userdata: ?*anyopaque,
    any_future: *Io.AnyFuture,
    result: []u8,
    result_alignment: Alignment,
) void {
    _ = result_alignment;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const future: *Future = @ptrCast(@alignCast(any_future));

    var num_completed: std.atomic.Value(u32) = .init(0);
    future.awaiter = &num_completed;

    const pre_cancel_status = future.status.fetchOr(.{
        .tag = .pending_canceled,
        .thread = .null,
    }, .acq_rel); // acquire results if complete; release `future.awaiter`
    switch (pre_cancel_status.tag) {
        .pending => {
            const working_thread = pre_cancel_status.thread.unpack();
            future.waitForCancelWithSignaling(t, &num_completed, @alignCast(working_thread));
        },
        .pending_awaited => unreachable, // `await` raced with `await`
        .pending_canceled => unreachable, // `await` raced with `cancel`
        .done => {},
    }
    @memcpy(result, future.resultPointer());
    future.destroy(t.allocator);
}

fn futexWait(userdata: ?*anyopaque, ptr: *const u32, expected: u32, timeout: Io.Timeout) Io.Cancelable!void {
    if (builtin.single_threaded) unreachable; // Deadlock.
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const t_io = ioBasic(t);
    const timeout_ns: ?u64 = ns: {
        const d = (timeout.toDurationFromNow(t_io) catch break :ns 10) orelse break :ns null;
        break :ns std.math.lossyCast(u64, d.raw.toNanoseconds());
    };
    return Thread.futexWait(ptr, expected, timeout_ns);
}

fn futexWaitUncancelable(userdata: ?*anyopaque, ptr: *const u32, expected: u32) void {
    if (builtin.single_threaded) unreachable; // Deadlock.
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    Thread.futexWaitUncancelable(ptr, expected, null);
}

fn futexWake(userdata: ?*anyopaque, ptr: *const u32, max_waiters: u32) void {
    if (builtin.single_threaded) unreachable; // Nothing to wake up.
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    Thread.futexWake(ptr, max_waiters);
}

const dirCreateDir = switch (native_os) {
    .windows => dirCreateDirWindows,
    .wasi => dirCreateDirWasi,
    else => dirCreateDirPosix,
};

fn dirCreateDirPosix(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, permissions: Dir.Permissions) Dir.CreateDirError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.mkdirat(dir.handle, sub_path_posix, permissions.toMode()))) {
            .SUCCESS => {
                syscall.finish();
                return;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ACCES => return error.AccessDenied,
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .PERM => return error.PermissionDenied,
                    .DQUOT => return error.DiskQuota,
                    .EXIST => return error.PathAlreadyExists,
                    .FAULT => |err| return errnoBug(err),
                    .LOOP => return error.SymLinkLoop,
                    .MLINK => return error.LinkQuotaExceeded,
                    .NAMETOOLONG => return error.NameTooLong,
                    .NOENT => return error.FileNotFound,
                    .NOMEM => return error.SystemResources,
                    .NOSPC => return error.NoSpaceLeft,
                    .NOTDIR => return error.NotDir,
                    .ROFS => return error.ReadOnlyFileSystem,
                    // dragonfly: when dir_fd is unlinked from filesystem
                    .NOTCONN => return error.FileNotFound,
                    .ILSEQ => return error.BadPathName,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn dirCreateDirWasi(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, permissions: Dir.Permissions) Dir.CreateDirError!void {
    if (builtin.link_libc) return dirCreateDirPosix(userdata, dir, sub_path, permissions);
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const syscall: Syscall = try .start();
    while (true) {
        switch (std.os.wasi.path_create_directory(dir.handle, sub_path.ptr, sub_path.len)) {
            .SUCCESS => {
                syscall.finish();
                return;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ACCES => return error.AccessDenied,
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .PERM => return error.PermissionDenied,
                    .DQUOT => return error.DiskQuota,
                    .EXIST => return error.PathAlreadyExists,
                    .FAULT => |err| return errnoBug(err),
                    .LOOP => return error.SymLinkLoop,
                    .MLINK => return error.LinkQuotaExceeded,
                    .NAMETOOLONG => return error.NameTooLong,
                    .NOENT => return error.FileNotFound,
                    .NOMEM => return error.SystemResources,
                    .NOSPC => return error.NoSpaceLeft,
                    .NOTDIR => return error.NotDir,
                    .ROFS => return error.ReadOnlyFileSystem,
                    .NOTCAPABLE => return error.AccessDenied,
                    .ILSEQ => return error.BadPathName,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn dirCreateDirWindows(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, permissions: Dir.Permissions) Dir.CreateDirError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    const sub_path_w = try windows.sliceToPrefixedFileW(dir.handle, sub_path);
    _ = permissions; // TODO use this value

    const syscall: Syscall = try .start();
    const sub_dir_handle = while (true) {
        break windows.OpenFile(sub_path_w.span(), .{
            .dir = dir.handle,
            .access_mask = .{
                .GENERIC = .{ .READ = true },
                .STANDARD = .{ .SYNCHRONIZE = true },
            },
            .creation = .CREATE,
            .filter = .dir_only,
        }) catch |err| switch (err) {
            error.IsDir => return syscall.fail(error.Unexpected),
            error.PipeBusy => return syscall.fail(error.Unexpected),
            error.NoDevice => return syscall.fail(error.Unexpected),
            error.WouldBlock => return syscall.fail(error.Unexpected),
            error.AntivirusInterference => return syscall.fail(error.Unexpected),
            error.OperationCanceled => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| return syscall.fail(e),
        };
    };
    syscall.finish();
    windows.CloseHandle(sub_dir_handle);
}

fn dirCreateDirPath(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    permissions: Dir.Permissions,
) Dir.CreateDirPathError!Dir.CreatePathStatus {
    const t: *Threaded = @ptrCast(@alignCast(userdata));

    var it = std.fs.path.componentIterator(sub_path);
    var status: Dir.CreatePathStatus = .existed;
    var component = it.last() orelse return error.BadPathName;
    while (true) {
        if (dirCreateDir(t, dir, component.path, permissions)) |_| {
            status = .created;
        } else |err| switch (err) {
            error.PathAlreadyExists => {
                // stat the file and return an error if it's not a directory
                // this is important because otherwise a dangling symlink
                // could cause an infinite loop
                const fstat = try dirStatFile(t, dir, component.path, .{});
                if (fstat.kind != .directory) return error.NotDir;
            },
            error.FileNotFound => |e| {
                component = it.previous() orelse return e;
                continue;
            },
            else => |e| return e,
        }
        component = it.next() orelse return status;
    }
}

const dirCreateDirPathOpen = switch (native_os) {
    .windows => dirCreateDirPathOpenWindows,
    .wasi => dirCreateDirPathOpenWasi,
    else => dirCreateDirPathOpenPosix,
};

fn dirCreateDirPathOpenPosix(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    permissions: Dir.Permissions,
    options: Dir.OpenOptions,
) Dir.CreateDirPathOpenError!Dir {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const t_io = ioBasic(t);
    return dirOpenDirPosix(t, dir, sub_path, options) catch |err| switch (err) {
        error.FileNotFound => {
            _ = try dir.createDirPathStatus(t_io, sub_path, permissions);
            return dirOpenDirPosix(t, dir, sub_path, options);
        },
        else => |e| return e,
    };
}

fn dirCreateDirPathOpenWindows(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    permissions: Dir.Permissions,
    options: Dir.OpenOptions,
) Dir.CreateDirPathOpenError!Dir {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const w = windows;

    _ = permissions; // TODO apply these permissions

    var it = std.fs.path.componentIterator(sub_path);
    // If there are no components in the path, then create a dummy component with the full path.
    var component: std.fs.path.NativeComponentIterator.Component = it.last() orelse .{
        .name = "",
        .path = sub_path,
    };

    components: while (true) {
        const sub_path_w_array = try w.sliceToPrefixedFileW(dir.handle, component.path);
        const sub_path_w = sub_path_w_array.span();
        const is_last = it.peekNext() == null;
        const create_disposition: w.FILE.CREATE_DISPOSITION = if (is_last) .OPEN_IF else .CREATE;

        var result: Dir = .{ .handle = undefined };

        const path_len_bytes: u16 = @intCast(sub_path_w.len * 2);
        var nt_name: w.UNICODE_STRING = .{
            .Length = path_len_bytes,
            .MaximumLength = path_len_bytes,
            .Buffer = @constCast(sub_path_w.ptr),
        };
        var io_status_block: w.IO_STATUS_BLOCK = undefined;

        const syscall: Syscall = try .start();
        while (true) switch (w.ntdll.NtCreateFile(
            &result.handle,
            .{
                .SPECIFIC = .{ .FILE_DIRECTORY = .{
                    .LIST = options.iterate,
                    .READ_EA = true,
                    .READ_ATTRIBUTES = true,
                    .TRAVERSE = true,
                } },
                .STANDARD = .{
                    .RIGHTS = .READ,
                    .SYNCHRONIZE = true,
                },
            },
            &.{
                .Length = @sizeOf(w.OBJECT_ATTRIBUTES),
                .RootDirectory = if (std.fs.path.isAbsoluteWindowsWtf16(sub_path_w)) null else dir.handle,
                .Attributes = .{},
                .ObjectName = &nt_name,
                .SecurityDescriptor = null,
                .SecurityQualityOfService = null,
            },
            &io_status_block,
            null,
            .{ .NORMAL = true },
            .VALID_FLAGS,
            create_disposition,
            .{
                .DIRECTORY_FILE = true,
                .IO = .SYNCHRONOUS_NONALERT,
                .OPEN_FOR_BACKUP_INTENT = true,
                .OPEN_REPARSE_POINT = !options.follow_symlinks,
            },
            null,
            0,
        )) {
            .SUCCESS => {
                syscall.finish();
                component = it.next() orelse return result;
                w.CloseHandle(result.handle);
                continue :components;
            },
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            .OBJECT_NAME_INVALID => return syscall.fail(error.BadPathName),
            .OBJECT_NAME_COLLISION => {
                syscall.finish();
                assert(!is_last);
                // stat the file and return an error if it's not a directory
                // this is important because otherwise a dangling symlink
                // could cause an infinite loop
                const fstat = try dirStatFileWindows(t, dir, component.path, .{
                    .follow_symlinks = options.follow_symlinks,
                });
                if (fstat.kind != .directory) return error.NotDir;

                component = it.next().?;
                continue :components;
            },

            .OBJECT_NAME_NOT_FOUND,
            .OBJECT_PATH_NOT_FOUND,
            => {
                syscall.finish();
                component = it.previous() orelse return error.FileNotFound;
                continue :components;
            },

            .NOT_A_DIRECTORY => return syscall.fail(error.NotDir),
            // This can happen if the directory has 'List folder contents' permission set to 'Deny'
            // and the directory is trying to be opened for iteration.
            .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
            .INVALID_PARAMETER => |s| return syscall.ntstatusBug(s),
            else => |s| return syscall.unexpectedNtstatus(s),
        };
    }
}

fn dirCreateDirPathOpenWasi(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    permissions: Dir.Permissions,
    options: Dir.OpenOptions,
) Dir.CreateDirPathOpenError!Dir {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const t_io = ioBasic(t);
    return dirOpenDirWasi(t, dir, sub_path, options) catch |err| switch (err) {
        error.FileNotFound => {
            _ = try dir.createDirPathStatus(t_io, sub_path, permissions);
            return dirOpenDirWasi(t, dir, sub_path, options);
        },
        else => |e| return e,
    };
}

fn dirStat(userdata: ?*anyopaque, dir: Dir) Dir.StatError!Dir.Stat {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const file: File = .{ .handle = dir.handle };
    return fileStat(t, file);
}

const dirStatFile = switch (native_os) {
    .linux => dirStatFileLinux,
    .windows => dirStatFileWindows,
    .wasi => dirStatFileWasi,
    else => dirStatFilePosix,
};

fn dirStatFileLinux(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    options: Dir.StatFileOptions,
) Dir.StatFileError!File.Stat {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const linux = std.os.linux;
    const use_c = std.c.versionCheck(if (builtin.abi.isAndroid())
        .{ .major = 30, .minor = 0, .patch = 0 }
    else
        .{ .major = 2, .minor = 28, .patch = 0 });
    const sys = if (use_c) std.c else std.os.linux;

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    const flags: u32 = linux.AT.NO_AUTOMOUNT |
        @as(u32, if (!options.follow_symlinks) linux.AT.SYMLINK_NOFOLLOW else 0);

    const syscall: Syscall = try .start();
    while (true) {
        var statx = std.mem.zeroes(linux.Statx);
        switch (sys.errno(sys.statx(dir.handle, sub_path_posix, flags, linux_statx_request, &statx))) {
            .SUCCESS => {
                syscall.finish();
                return statFromLinux(&statx);
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ACCES => return error.AccessDenied,
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err),
                    .LOOP => return error.SymLinkLoop,
                    .NAMETOOLONG => |err| return errnoBug(err), // Handled by pathToPosix() above.
                    .NOENT => return error.FileNotFound,
                    .NOTDIR => return error.NotDir,
                    .NOMEM => return error.SystemResources,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn dirStatFilePosix(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    options: Dir.StatFileOptions,
) Dir.StatFileError!File.Stat {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    const flags: u32 = if (!options.follow_symlinks) posix.AT.SYMLINK_NOFOLLOW else 0;

    return posixStatFile(dir.handle, sub_path_posix, flags);
}

fn posixStatFile(dir_fd: posix.fd_t, sub_path: [:0]const u8, flags: u32) Dir.StatFileError!File.Stat {
    const syscall: Syscall = try .start();
    while (true) {
        var stat = std.mem.zeroes(posix.Stat);
        switch (posix.errno(fstatat_sym(dir_fd, sub_path, &stat, flags))) {
            .SUCCESS => {
                syscall.finish();
                return statFromPosix(&stat);
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .INVAL => |err| return errnoBug(err),
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .NOMEM => return error.SystemResources,
                    .ACCES => return error.AccessDenied,
                    .PERM => return error.PermissionDenied,
                    .FAULT => |err| return errnoBug(err),
                    .NAMETOOLONG => return error.NameTooLong,
                    .LOOP => return error.SymLinkLoop,
                    .NOENT => return error.FileNotFound,
                    .NOTDIR => return error.FileNotFound,
                    .ILSEQ => return error.BadPathName,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn dirStatFileWindows(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    options: Dir.StatFileOptions,
) Dir.StatFileError!File.Stat {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const file = try dirOpenFileWindows(t, dir, sub_path, .{
        .follow_symlinks = options.follow_symlinks,
    });
    defer windows.CloseHandle(file.handle);
    return fileStatWindows(t, file);
}

fn dirStatFileWasi(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    options: Dir.StatFileOptions,
) Dir.StatFileError!File.Stat {
    if (builtin.link_libc) return dirStatFilePosix(userdata, dir, sub_path, options);
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const wasi = std.os.wasi;
    const flags: wasi.lookupflags_t = .{
        .SYMLINK_FOLLOW = options.follow_symlinks,
    };
    var stat: wasi.filestat_t = undefined;
    const syscall: Syscall = try .start();
    while (true) {
        switch (wasi.path_filestat_get(dir.handle, flags, sub_path.ptr, sub_path.len, &stat)) {
            .SUCCESS => {
                syscall.finish();
                return statFromWasi(&stat);
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .INVAL => |err| return errnoBug(err),
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .NOMEM => return error.SystemResources,
                    .ACCES => return error.AccessDenied,
                    .FAULT => |err| return errnoBug(err),
                    .NAMETOOLONG => return error.NameTooLong,
                    .NOENT => return error.FileNotFound,
                    .NOTDIR => return error.FileNotFound,
                    .NOTCAPABLE => return error.AccessDenied,
                    .ILSEQ => return error.BadPathName,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn fileLength(userdata: ?*anyopaque, file: File) File.LengthError!u64 {
    const t: *Threaded = @ptrCast(@alignCast(userdata));

    if (native_os == .linux) {
        const linux = std.os.linux;

        const syscall: Syscall = try .start();
        while (true) {
            var statx = std.mem.zeroes(linux.Statx);
            switch (linux.errno(linux.statx(file.handle, "", linux.AT.EMPTY_PATH, .{ .SIZE = true }, &statx))) {
                .SUCCESS => {
                    syscall.finish();
                    if (!statx.mask.SIZE) return error.Unexpected;
                    return statx.size;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .ACCES => |err| return errnoBug(err),
                        .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                        .FAULT => |err| return errnoBug(err),
                        .INVAL => |err| return errnoBug(err),
                        .LOOP => |err| return errnoBug(err),
                        .NAMETOOLONG => |err| return errnoBug(err),
                        .NOENT => |err| return errnoBug(err),
                        .NOMEM => return error.SystemResources,
                        .NOTDIR => |err| return errnoBug(err),
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    } else if (is_windows) {
        // TODO call NtQueryInformationFile and ask for only the size instead of "all"
    }

    const stat = try fileStat(t, file);
    return stat.size;
}

const fileStat = switch (native_os) {
    .linux => fileStatLinux,
    .windows => fileStatWindows,
    .wasi => fileStatWasi,
    else => fileStatPosix,
};

fn fileStatPosix(userdata: ?*anyopaque, file: File) File.StatError!File.Stat {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (posix.Stat == void) return error.Streaming;

    const syscall: Syscall = try .start();
    while (true) {
        var stat = std.mem.zeroes(posix.Stat);
        switch (posix.errno(fstat_sym(file.handle, &stat))) {
            .SUCCESS => {
                syscall.finish();
                return statFromPosix(&stat);
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .INVAL => |err| return errnoBug(err),
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .NOMEM => return error.SystemResources,
                    .ACCES => return error.AccessDenied,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn fileStatLinux(userdata: ?*anyopaque, file: File) File.StatError!File.Stat {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const linux = std.os.linux;
    const use_c = std.c.versionCheck(if (builtin.abi.isAndroid())
        .{ .major = 30, .minor = 0, .patch = 0 }
    else
        .{ .major = 2, .minor = 28, .patch = 0 });
    const sys = if (use_c) std.c else std.os.linux;

    const syscall: Syscall = try .start();
    while (true) {
        var statx = std.mem.zeroes(linux.Statx);
        switch (sys.errno(sys.statx(file.handle, "", linux.AT.EMPTY_PATH, linux_statx_request, &statx))) {
            .SUCCESS => {
                syscall.finish();
                return statFromLinux(&statx);
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ACCES => |err| return errnoBug(err),
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err),
                    .LOOP => |err| return errnoBug(err),
                    .NAMETOOLONG => |err| return errnoBug(err),
                    .NOENT => |err| return errnoBug(err),
                    .NOMEM => return error.SystemResources,
                    .NOTDIR => |err| return errnoBug(err),
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn fileStatWindows(userdata: ?*anyopaque, file: File) File.StatError!File.Stat {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var io_status_block: windows.IO_STATUS_BLOCK = undefined;
    var info: windows.FILE.ALL_INFORMATION = undefined;
    {
        const syscall: Syscall = try .start();
        while (true) switch (windows.ntdll.NtQueryInformationFile(
            file.handle,
            &io_status_block,
            &info,
            @sizeOf(windows.FILE.ALL_INFORMATION),
            .All,
        )) {
            .SUCCESS => break syscall.finish(),
            // Buffer overflow here indicates that there is more information available than was able to be stored in the buffer
            // size provided. This is treated as success because the type of variable-length information that this would be relevant for
            // (name, volume name, etc) we don't care about.
            .BUFFER_OVERFLOW => break syscall.finish(),
            .INVALID_PARAMETER => |err| return syscall.ntstatusBug(err),
            .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            else => |s| return syscall.unexpectedNtstatus(s),
        };
    }
    return .{
        .inode = info.InternalInformation.IndexNumber,
        .size = @as(u64, @bitCast(info.StandardInformation.EndOfFile)),
        .permissions = .default_file,
        .kind = if (info.BasicInformation.FileAttributes.REPARSE_POINT) reparse_point: {
            var tag_info: windows.FILE.ATTRIBUTE_TAG_INFO = undefined;
            const syscall: Syscall = try .start();
            while (true) switch (windows.ntdll.NtQueryInformationFile(
                file.handle,
                &io_status_block,
                &tag_info,
                @sizeOf(windows.FILE.ATTRIBUTE_TAG_INFO),
                .AttributeTag,
            )) {
                .SUCCESS => break syscall.finish(),
                // INFO_LENGTH_MISMATCH and ACCESS_DENIED are the only documented possible errors
                // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/d295752f-ce89-4b98-8553-266d37c84f0e
                .INFO_LENGTH_MISMATCH => |err| return syscall.ntstatusBug(err),
                .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
                .CANCELLED => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |s| return syscall.unexpectedNtstatus(s),
            };
            if (tag_info.ReparseTag.IsSurrogate) break :reparse_point .sym_link;
            // Unknown reparse point
            break :reparse_point .unknown;
        } else if (info.BasicInformation.FileAttributes.DIRECTORY)
            .directory
        else
            .file,
        .atime = windows.fromSysTime(info.BasicInformation.LastAccessTime),
        .mtime = windows.fromSysTime(info.BasicInformation.LastWriteTime),
        .ctime = windows.fromSysTime(info.BasicInformation.ChangeTime),
        .nlink = 0,
    };
}

fn fileStatWasi(userdata: ?*anyopaque, file: File) File.StatError!File.Stat {
    if (builtin.link_libc) return fileStatPosix(userdata, file);

    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    const syscall: Syscall = try .start();
    while (true) {
        var stat: std.os.wasi.filestat_t = undefined;
        switch (std.os.wasi.fd_filestat_get(file.handle, &stat)) {
            .SUCCESS => {
                syscall.finish();
                return statFromWasi(&stat);
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .INVAL => |err| return errnoBug(err),
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .NOMEM => return error.SystemResources,
                    .ACCES => return error.AccessDenied,
                    .NOTCAPABLE => return error.AccessDenied,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

const dirAccess = switch (native_os) {
    .windows => dirAccessWindows,
    .wasi => dirAccessWasi,
    else => dirAccessPosix,
};

fn dirAccessPosix(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    options: Dir.AccessOptions,
) Dir.AccessError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    const flags: u32 = @as(u32, if (!options.follow_symlinks) posix.AT.SYMLINK_NOFOLLOW else 0);

    const mode: u32 =
        @as(u32, if (options.read) posix.R_OK else 0) |
        @as(u32, if (options.write) posix.W_OK else 0) |
        @as(u32, if (options.execute) posix.X_OK else 0);

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.faccessat(dir.handle, sub_path_posix, mode, flags))) {
            .SUCCESS => {
                syscall.finish();
                return;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ACCES => return error.AccessDenied,
                    .PERM => return error.PermissionDenied,
                    .ROFS => return error.ReadOnlyFileSystem,
                    .LOOP => return error.SymLinkLoop,
                    .TXTBSY => return error.FileBusy,
                    .NOTDIR => return error.FileNotFound,
                    .NOENT => return error.FileNotFound,
                    .NAMETOOLONG => return error.NameTooLong,
                    .INVAL => |err| return errnoBug(err),
                    .FAULT => |err| return errnoBug(err),
                    .IO => return error.InputOutput,
                    .NOMEM => return error.SystemResources,
                    .ILSEQ => return error.BadPathName,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn dirAccessWasi(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    options: Dir.AccessOptions,
) Dir.AccessError!void {
    if (builtin.link_libc) return dirAccessPosix(userdata, dir, sub_path, options);
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const wasi = std.os.wasi;
    const flags: wasi.lookupflags_t = .{
        .SYMLINK_FOLLOW = options.follow_symlinks,
    };
    var stat: wasi.filestat_t = undefined;

    const syscall: Syscall = try .start();
    while (true) {
        switch (wasi.path_filestat_get(dir.handle, flags, sub_path.ptr, sub_path.len, &stat)) {
            .SUCCESS => {
                syscall.finish();
                break;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .INVAL => |err| return errnoBug(err),
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .NOMEM => return error.SystemResources,
                    .ACCES => return error.AccessDenied,
                    .FAULT => |err| return errnoBug(err),
                    .NAMETOOLONG => return error.NameTooLong,
                    .NOENT => return error.FileNotFound,
                    .NOTDIR => return error.FileNotFound,
                    .NOTCAPABLE => return error.AccessDenied,
                    .ILSEQ => return error.BadPathName,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }

    if (!options.read and !options.write and !options.execute)
        return;

    var directory: wasi.fdstat_t = undefined;
    if (wasi.fd_fdstat_get(dir.handle, &directory) != .SUCCESS)
        return error.AccessDenied;

    var rights: wasi.rights_t = .{};
    if (options.read) {
        if (stat.filetype == .DIRECTORY) {
            rights.FD_READDIR = true;
        } else {
            rights.FD_READ = true;
        }
    }
    if (options.write)
        rights.FD_WRITE = true;

    // No validation for execution.

    // https://github.com/ziglang/zig/issues/18882
    const rights_int: u64 = @bitCast(rights);
    const inheriting_int: u64 = @bitCast(directory.fs_rights_inheriting);
    if ((rights_int & inheriting_int) != rights_int)
        return error.AccessDenied;
}

fn dirAccessWindows(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    options: Dir.AccessOptions,
) Dir.AccessError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    _ = options; // TODO

    const sub_path_w_array = try windows.sliceToPrefixedFileW(dir.handle, sub_path);
    const sub_path_w = sub_path_w_array.span();

    if (sub_path_w[0] == '.' and sub_path_w[1] == 0) return;
    if (sub_path_w[0] == '.' and sub_path_w[1] == '.' and sub_path_w[2] == 0) return;

    const path_len_bytes = std.math.cast(u16, std.mem.sliceTo(sub_path_w, 0).len * 2) orelse
        return error.NameTooLong;
    var nt_name: windows.UNICODE_STRING = .{
        .Length = path_len_bytes,
        .MaximumLength = path_len_bytes,
        .Buffer = @constCast(sub_path_w.ptr),
    };
    var attr: windows.OBJECT_ATTRIBUTES = .{
        .Length = @sizeOf(windows.OBJECT_ATTRIBUTES),
        .RootDirectory = if (std.fs.path.isAbsoluteWindowsWtf16(sub_path_w)) null else dir.handle,
        .Attributes = .{},
        .ObjectName = &nt_name,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };
    var basic_info: windows.FILE.BASIC_INFORMATION = undefined;
    const syscall: Syscall = try .start();
    while (true) switch (windows.ntdll.NtQueryAttributesFile(&attr, &basic_info)) {
        .SUCCESS => return syscall.finish(),
        .CANCELLED => {
            try syscall.checkCancel();
            continue;
        },
        .OBJECT_NAME_NOT_FOUND => return syscall.fail(error.FileNotFound),
        .OBJECT_PATH_NOT_FOUND => return syscall.fail(error.FileNotFound),
        .OBJECT_NAME_INVALID => |err| return syscall.ntstatusBug(err),
        .INVALID_PARAMETER => |err| return syscall.ntstatusBug(err),
        .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
        .OBJECT_PATH_SYNTAX_BAD => |err| return syscall.ntstatusBug(err),
        else => |rc| return syscall.unexpectedNtstatus(rc),
    };
}

const dirCreateFile = switch (native_os) {
    .windows => dirCreateFileWindows,
    .wasi => dirCreateFileWasi,
    else => dirCreateFilePosix,
};

fn dirCreateFilePosix(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    flags: File.CreateFlags,
) File.OpenError!File {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    var os_flags: posix.O = .{
        .ACCMODE = if (flags.read) .RDWR else .WRONLY,
        .CREAT = true,
        .TRUNC = flags.truncate,
        .EXCL = flags.exclusive,
    };
    if (@hasField(posix.O, "LARGEFILE")) os_flags.LARGEFILE = true;
    if (@hasField(posix.O, "CLOEXEC")) os_flags.CLOEXEC = true;

    // Use the O locking flags if the os supports them to acquire the lock
    // atomically. Note that the NONBLOCK flag is removed after the openat()
    // call is successful.
    if (have_flock_open_flags) switch (flags.lock) {
        .none => {},
        .shared => {
            os_flags.SHLOCK = true;
            os_flags.NONBLOCK = flags.lock_nonblocking;
        },
        .exclusive => {
            os_flags.EXLOCK = true;
            os_flags.NONBLOCK = flags.lock_nonblocking;
        },
    };

    const fd: posix.fd_t = fd: {
        const syscall: Syscall = try .start();
        while (true) {
            const rc = openat_sym(dir.handle, sub_path_posix, os_flags, flags.permissions.toMode());
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    syscall.finish();
                    break :fd @intCast(rc);
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .FAULT => |err| return errnoBug(err),
                        .INVAL => return error.BadPathName,
                        .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                        .ACCES => return error.AccessDenied,
                        .FBIG => return error.FileTooBig,
                        .OVERFLOW => return error.FileTooBig,
                        .ISDIR => return error.IsDir,
                        .LOOP => return error.SymLinkLoop,
                        .MFILE => return error.ProcessFdQuotaExceeded,
                        .NAMETOOLONG => return error.NameTooLong,
                        .NFILE => return error.SystemFdQuotaExceeded,
                        .NODEV => return error.NoDevice,
                        .NOENT => return error.FileNotFound,
                        .SRCH => return error.FileNotFound, // Linux when accessing procfs.
                        .NOMEM => return error.SystemResources,
                        .NOSPC => return error.NoSpaceLeft,
                        .NOTDIR => return error.NotDir,
                        .PERM => return error.PermissionDenied,
                        .EXIST => return error.PathAlreadyExists,
                        .BUSY => return error.DeviceBusy,
                        .OPNOTSUPP => return error.FileLocksUnsupported,
                        .AGAIN => return error.WouldBlock,
                        .TXTBSY => return error.FileBusy,
                        .NXIO => return error.NoDevice,
                        .ILSEQ => return error.BadPathName,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    };
    errdefer posix.close(fd);

    if (have_flock and !have_flock_open_flags and flags.lock != .none) {
        const lock_nonblocking: i32 = if (flags.lock_nonblocking) posix.LOCK.NB else 0;
        const lock_flags = switch (flags.lock) {
            .none => unreachable,
            .shared => posix.LOCK.SH | lock_nonblocking,
            .exclusive => posix.LOCK.EX | lock_nonblocking,
        };

        const syscall: Syscall = try .start();
        while (true) {
            switch (posix.errno(posix.system.flock(fd, lock_flags))) {
                .SUCCESS => {
                    syscall.finish();
                    break;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                        .INVAL => |err| return errnoBug(err), // invalid parameters
                        .NOLCK => return error.SystemResources,
                        .AGAIN => return error.WouldBlock,
                        .OPNOTSUPP => return error.FileLocksUnsupported,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    }

    if (have_flock_open_flags and flags.lock_nonblocking) {
        var fl_flags: usize = fl: {
            const syscall: Syscall = try .start();
            while (true) {
                const rc = posix.system.fcntl(fd, posix.F.GETFL, @as(usize, 0));
                switch (posix.errno(rc)) {
                    .SUCCESS => {
                        syscall.finish();
                        break :fl @intCast(rc);
                    },
                    .INTR => {
                        try syscall.checkCancel();
                        continue;
                    },
                    else => |err| {
                        syscall.finish();
                        return posix.unexpectedErrno(err);
                    },
                }
            }
        };

        fl_flags |= @as(usize, 1 << @bitOffsetOf(posix.O, "NONBLOCK"));

        const syscall: Syscall = try .start();
        while (true) {
            switch (posix.errno(posix.system.fcntl(fd, posix.F.SETFL, fl_flags))) {
                .SUCCESS => {
                    syscall.finish();
                    break;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |err| {
                    syscall.finish();
                    return posix.unexpectedErrno(err);
                },
            }
        }
    }

    return .{ .handle = fd };
}

fn dirCreateFileWindows(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    flags: File.CreateFlags,
) File.OpenError!File {
    const w = windows;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    const sub_path_w_array = try w.sliceToPrefixedFileW(dir.handle, sub_path);
    const sub_path_w = sub_path_w_array.span();

    const handle = handle: {
        const syscall: Syscall = try .start();
        while (true) {
            if (w.OpenFile(sub_path_w, .{
                .dir = dir.handle,
                .access_mask = .{
                    .STANDARD = .{ .SYNCHRONIZE = true },
                    .GENERIC = .{
                        .WRITE = true,
                        .READ = flags.read,
                    },
                },
                .creation = if (flags.exclusive)
                    .CREATE
                else if (flags.truncate)
                    .OVERWRITE_IF
                else
                    .OPEN_IF,
            })) |handle| {
                syscall.finish();
                break :handle handle;
            } else |err| switch (err) {
                error.OperationCanceled => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| return syscall.fail(e),
            }
        }
    };
    errdefer w.CloseHandle(handle);

    var io_status_block: w.IO_STATUS_BLOCK = undefined;
    const exclusive = switch (flags.lock) {
        .none => return .{ .handle = handle },
        .shared => false,
        .exclusive => true,
    };
    const syscall: Syscall = try .start();
    while (true) switch (w.ntdll.NtLockFile(
        handle,
        null,
        null,
        null,
        &io_status_block,
        &windows_lock_range_off,
        &windows_lock_range_len,
        null,
        @intFromBool(flags.lock_nonblocking),
        @intFromBool(exclusive),
    )) {
        .SUCCESS => {
            syscall.finish();
            return .{ .handle = handle };
        },
        .INSUFFICIENT_RESOURCES => return syscall.fail(error.SystemResources),
        .LOCK_NOT_GRANTED => return syscall.fail(error.WouldBlock),
        .ACCESS_VIOLATION => |err| return syscall.ntstatusBug(err), // bad io_status_block pointer
        else => |status| return syscall.unexpectedNtstatus(status),
    };
}

fn dirCreateFileWasi(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    flags: File.CreateFlags,
) File.OpenError!File {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const wasi = std.os.wasi;
    const lookup_flags: wasi.lookupflags_t = .{};
    const oflags: wasi.oflags_t = .{
        .CREAT = true,
        .TRUNC = flags.truncate,
        .EXCL = flags.exclusive,
    };
    const fdflags: wasi.fdflags_t = .{};
    const base: wasi.rights_t = .{
        .FD_READ = flags.read,
        .FD_WRITE = true,
        .FD_DATASYNC = true,
        .FD_SEEK = true,
        .FD_TELL = true,
        .FD_FDSTAT_SET_FLAGS = true,
        .FD_SYNC = true,
        .FD_ALLOCATE = true,
        .FD_ADVISE = true,
        .FD_FILESTAT_SET_TIMES = true,
        .FD_FILESTAT_SET_SIZE = true,
        .FD_FILESTAT_GET = true,
        // POLL_FD_READWRITE only grants extra rights if the corresponding FD_READ and/or
        // FD_WRITE is also set.
        .POLL_FD_READWRITE = true,
    };
    const inheriting: wasi.rights_t = .{};
    var fd: posix.fd_t = undefined;
    const syscall: Syscall = try .start();
    while (true) {
        switch (wasi.path_open(dir.handle, lookup_flags, sub_path.ptr, sub_path.len, oflags, base, inheriting, fdflags, &fd)) {
            .SUCCESS => {
                syscall.finish();
                return .{ .handle = fd };
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => return error.BadPathName,
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .ACCES => return error.AccessDenied,
                    .FBIG => return error.FileTooBig,
                    .OVERFLOW => return error.FileTooBig,
                    .ISDIR => return error.IsDir,
                    .LOOP => return error.SymLinkLoop,
                    .MFILE => return error.ProcessFdQuotaExceeded,
                    .NAMETOOLONG => return error.NameTooLong,
                    .NFILE => return error.SystemFdQuotaExceeded,
                    .NODEV => return error.NoDevice,
                    .NOENT => return error.FileNotFound,
                    .NOMEM => return error.SystemResources,
                    .NOSPC => return error.NoSpaceLeft,
                    .NOTDIR => return error.NotDir,
                    .PERM => return error.PermissionDenied,
                    .EXIST => return error.PathAlreadyExists,
                    .BUSY => return error.DeviceBusy,
                    .NOTCAPABLE => return error.AccessDenied,
                    .ILSEQ => return error.BadPathName,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

const dirOpenFile = switch (native_os) {
    .windows => dirOpenFileWindows,
    .wasi => dirOpenFileWasi,
    else => dirOpenFilePosix,
};

fn dirOpenFilePosix(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    flags: File.OpenFlags,
) File.OpenError!File {
    const t: *Threaded = @ptrCast(@alignCast(userdata));

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    var os_flags: posix.O = switch (native_os) {
        .wasi => .{
            .read = flags.mode != .write_only,
            .write = flags.mode != .read_only,
            .NOFOLLOW = !flags.follow_symlinks,
        },
        else => .{
            .ACCMODE = switch (flags.mode) {
                .read_only => .RDONLY,
                .write_only => .WRONLY,
                .read_write => .RDWR,
            },
            .NOFOLLOW = !flags.follow_symlinks,
        },
    };
    if (@hasField(posix.O, "CLOEXEC")) os_flags.CLOEXEC = true;
    if (@hasField(posix.O, "LARGEFILE")) os_flags.LARGEFILE = true;
    if (@hasField(posix.O, "NOCTTY")) os_flags.NOCTTY = !flags.allow_ctty;
    if (@hasField(posix.O, "PATH") and flags.path_only) os_flags.PATH = true;

    // Use the O locking flags if the os supports them to acquire the lock
    // atomically. Note that the NONBLOCK flag is removed after the openat()
    // call is successful.
    if (have_flock_open_flags) switch (flags.lock) {
        .none => {},
        .shared => {
            os_flags.SHLOCK = true;
            os_flags.NONBLOCK = flags.lock_nonblocking;
        },
        .exclusive => {
            os_flags.EXLOCK = true;
            os_flags.NONBLOCK = flags.lock_nonblocking;
        },
    };

    const fd: posix.fd_t = fd: {
        const syscall: Syscall = try .start();
        while (true) {
            const rc = openat_sym(dir.handle, sub_path_posix, os_flags, @as(posix.mode_t, 0));
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    syscall.finish();
                    break :fd @intCast(rc);
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .FAULT => |err| return errnoBug(err),
                        .INVAL => return error.BadPathName,
                        .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                        .ACCES => return error.AccessDenied,
                        .FBIG => return error.FileTooBig,
                        .OVERFLOW => return error.FileTooBig,
                        .ISDIR => return error.IsDir,
                        .LOOP => return error.SymLinkLoop,
                        .MFILE => return error.ProcessFdQuotaExceeded,
                        .NAMETOOLONG => return error.NameTooLong,
                        .NFILE => return error.SystemFdQuotaExceeded,
                        .NODEV => return error.NoDevice,
                        .NOENT => return error.FileNotFound,
                        .SRCH => return error.FileNotFound, // Linux when opening procfs files.
                        .NOMEM => return error.SystemResources,
                        .NOSPC => return error.NoSpaceLeft,
                        .NOTDIR => return error.NotDir,
                        .PERM => return error.PermissionDenied,
                        .EXIST => return error.PathAlreadyExists,
                        .BUSY => return error.DeviceBusy,
                        .OPNOTSUPP => return error.FileLocksUnsupported,
                        .AGAIN => return error.WouldBlock,
                        .TXTBSY => return error.FileBusy,
                        .NXIO => return error.NoDevice,
                        .ILSEQ => return error.BadPathName,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    };
    errdefer posix.close(fd);

    if (!flags.allow_directory) {
        const is_dir = is_dir: {
            const stat = fileStat(t, .{ .handle = fd }) catch |err| switch (err) {
                // The directory-ness is either unknown or unknowable
                error.Streaming => break :is_dir false,
                else => |e| return e,
            };
            break :is_dir stat.kind == .directory;
        };
        if (is_dir) return error.IsDir;
    }

    if (have_flock and !have_flock_open_flags and flags.lock != .none) {
        const lock_nonblocking: i32 = if (flags.lock_nonblocking) posix.LOCK.NB else 0;
        const lock_flags = switch (flags.lock) {
            .none => unreachable,
            .shared => posix.LOCK.SH | lock_nonblocking,
            .exclusive => posix.LOCK.EX | lock_nonblocking,
        };
        const syscall: Syscall = try .start();
        while (true) {
            switch (posix.errno(posix.system.flock(fd, lock_flags))) {
                .SUCCESS => {
                    syscall.finish();
                    break;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                        .INVAL => |err| return errnoBug(err), // invalid parameters
                        .NOLCK => return error.SystemResources,
                        .AGAIN => return error.WouldBlock,
                        .OPNOTSUPP => return error.FileLocksUnsupported,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    }

    if (have_flock_open_flags and flags.lock_nonblocking) {
        var fl_flags: usize = fl: {
            const syscall: Syscall = try .start();
            while (true) {
                const rc = posix.system.fcntl(fd, posix.F.GETFL, @as(usize, 0));
                switch (posix.errno(rc)) {
                    .SUCCESS => {
                        syscall.finish();
                        break :fl @intCast(rc);
                    },
                    .INTR => {
                        try syscall.checkCancel();
                        continue;
                    },
                    else => |err| {
                        syscall.finish();
                        return posix.unexpectedErrno(err);
                    },
                }
            }
        };

        fl_flags |= @as(usize, 1 << @bitOffsetOf(posix.O, "NONBLOCK"));

        const syscall: Syscall = try .start();
        while (true) {
            switch (posix.errno(posix.system.fcntl(fd, posix.F.SETFL, fl_flags))) {
                .SUCCESS => {
                    syscall.finish();
                    break;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |err| {
                    syscall.finish();
                    return posix.unexpectedErrno(err);
                },
            }
        }
    }

    return .{ .handle = fd };
}

fn dirOpenFileWindows(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    flags: File.OpenFlags,
) File.OpenError!File {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const sub_path_w_array = try windows.sliceToPrefixedFileW(dir.handle, sub_path);
    const sub_path_w = sub_path_w_array.span();
    const dir_handle = if (std.fs.path.isAbsoluteWindowsWtf16(sub_path_w)) null else dir.handle;
    return dirOpenFileWtf16(dir_handle, sub_path_w, flags);
}

pub fn dirOpenFileWtf16(
    dir_handle: ?windows.HANDLE,
    sub_path_w: [:0]const u16,
    flags: File.OpenFlags,
) File.OpenError!File {
    const allow_directory = flags.allow_directory and !flags.isWrite();
    if (!allow_directory and std.mem.eql(u16, sub_path_w, &.{'.'})) return error.IsDir;
    if (!allow_directory and std.mem.eql(u16, sub_path_w, &.{ '.', '.' })) return error.IsDir;
    const path_len_bytes = std.math.cast(u16, sub_path_w.len * 2) orelse return error.NameTooLong;
    const w = windows;

    var nt_name: w.UNICODE_STRING = .{
        .Length = path_len_bytes,
        .MaximumLength = path_len_bytes,
        .Buffer = @constCast(sub_path_w.ptr),
    };
    var attr: w.OBJECT_ATTRIBUTES = .{
        .Length = @sizeOf(w.OBJECT_ATTRIBUTES),
        .RootDirectory = dir_handle,
        .Attributes = .{},
        .ObjectName = &nt_name,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };
    var io_status_block: w.IO_STATUS_BLOCK = undefined;

    // There are multiple kernel bugs being worked around with retries.
    const max_attempts = 13;
    var attempt: u5 = 0;

    var syscall: Syscall = try .start();
    const handle = while (true) {
        var result: w.HANDLE = undefined;
        switch (w.ntdll.NtCreateFile(
            &result,
            .{
                .STANDARD = .{ .SYNCHRONIZE = true },
                .GENERIC = .{
                    .READ = flags.isRead(),
                    .WRITE = flags.isWrite(),
                },
            },
            &attr,
            &io_status_block,
            null,
            .{ .NORMAL = true },
            .VALID_FLAGS,
            .OPEN,
            .{
                .IO = if (flags.follow_symlinks) .SYNCHRONOUS_NONALERT else .ASYNCHRONOUS,
                .NON_DIRECTORY_FILE = !allow_directory,
                .OPEN_REPARSE_POINT = !flags.follow_symlinks,
            },
            null,
            0,
        )) {
            .SUCCESS => {
                syscall.finish();
                break result;
            },
            .OBJECT_NAME_INVALID => return syscall.fail(error.BadPathName),
            .OBJECT_NAME_NOT_FOUND => return syscall.fail(error.FileNotFound),
            .OBJECT_PATH_NOT_FOUND => return syscall.fail(error.FileNotFound),
            .BAD_NETWORK_PATH => return syscall.fail(error.NetworkNotFound), // \\server was not found
            .BAD_NETWORK_NAME => return syscall.fail(error.NetworkNotFound), // \\server was found but \\server\share wasn't
            .NO_MEDIA_IN_DEVICE => return syscall.fail(error.NoDevice),
            .INVALID_PARAMETER => |err| return syscall.ntstatusBug(err),
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            .SHARING_VIOLATION => {
                // This occurs if the file attempting to be opened is a running
                // executable. However, there's a kernel bug: the error may be
                // incorrectly returned for an indeterminate amount of time
                // after an executable file is closed. Here we work around the
                // kernel bug with retry attempts.
                syscall.finish();
                if (max_attempts - attempt == 0) return error.SharingViolation;
                _ = w.kernel32.SleepEx((@as(u32, 1) << attempt) >> 1, w.TRUE);
                attempt += 1;
                syscall = try .start();
                continue;
            },
            .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
            .PIPE_BUSY => return syscall.fail(error.PipeBusy),
            .PIPE_NOT_AVAILABLE => return syscall.fail(error.NoDevice),
            .OBJECT_PATH_SYNTAX_BAD => |err| return syscall.ntstatusBug(err),
            .OBJECT_NAME_COLLISION => return syscall.fail(error.PathAlreadyExists),
            .FILE_IS_A_DIRECTORY => return syscall.fail(error.IsDir),
            .NOT_A_DIRECTORY => return syscall.fail(error.NotDir),
            .USER_MAPPED_FILE => return syscall.fail(error.AccessDenied),
            .INVALID_HANDLE => |err| return syscall.ntstatusBug(err),
            .DELETE_PENDING => {
                // This error means that there *was* a file in this location on
                // the file system, but it was deleted. However, the OS is not
                // finished with the deletion operation, and so this CreateFile
                // call has failed. Here, we simulate the kernel bug being
                // fixed by sleeping and retrying until the error goes away.
                syscall.finish();
                if (max_attempts - attempt == 0) return error.SharingViolation;
                _ = w.kernel32.SleepEx((@as(u32, 1) << attempt) >> 1, w.TRUE);
                attempt += 1;
                syscall = try .start();
                continue;
            },
            .VIRUS_INFECTED, .VIRUS_DELETED => return syscall.fail(error.AntivirusInterference),
            else => |rc| return syscall.unexpectedNtstatus(rc),
        }
    };
    errdefer w.CloseHandle(handle);

    const exclusive = switch (flags.lock) {
        .none => return .{ .handle = handle },
        .shared => false,
        .exclusive => true,
    };
    syscall = try .start();
    while (true) switch (w.ntdll.NtLockFile(
        handle,
        null,
        null,
        null,
        &io_status_block,
        &windows_lock_range_off,
        &windows_lock_range_len,
        null,
        @intFromBool(flags.lock_nonblocking),
        @intFromBool(exclusive),
    )) {
        .SUCCESS => break syscall.finish(),
        .INSUFFICIENT_RESOURCES => return syscall.fail(error.SystemResources),
        .LOCK_NOT_GRANTED => return syscall.fail(error.WouldBlock),
        .ACCESS_VIOLATION => |err| return syscall.ntstatusBug(err), // bad io_status_block pointer
        else => |status| return syscall.unexpectedNtstatus(status),
    };
    return .{ .handle = handle };
}

fn dirOpenFileWasi(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    flags: File.OpenFlags,
) File.OpenError!File {
    if (builtin.link_libc) return dirOpenFilePosix(userdata, dir, sub_path, flags);
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const wasi = std.os.wasi;
    var base: std.os.wasi.rights_t = .{};
    // POLL_FD_READWRITE only grants extra rights if the corresponding FD_READ and/or FD_WRITE
    // is also set.
    if (flags.isRead()) {
        base.FD_READ = true;
        base.FD_TELL = true;
        base.FD_SEEK = true;
        base.FD_FILESTAT_GET = true;
        base.POLL_FD_READWRITE = true;
    }
    if (flags.isWrite()) {
        base.FD_WRITE = true;
        base.FD_TELL = true;
        base.FD_SEEK = true;
        base.FD_DATASYNC = true;
        base.FD_FDSTAT_SET_FLAGS = true;
        base.FD_SYNC = true;
        base.FD_ALLOCATE = true;
        base.FD_ADVISE = true;
        base.FD_FILESTAT_SET_TIMES = true;
        base.FD_FILESTAT_SET_SIZE = true;
        base.POLL_FD_READWRITE = true;
    }
    const lookup_flags: wasi.lookupflags_t = .{};
    const oflags: wasi.oflags_t = .{};
    const inheriting: wasi.rights_t = .{};
    const fdflags: wasi.fdflags_t = .{};
    var fd: posix.fd_t = undefined;
    const syscall: Syscall = try .start();
    while (true) {
        switch (wasi.path_open(dir.handle, lookup_flags, sub_path.ptr, sub_path.len, oflags, base, inheriting, fdflags, &fd)) {
            .SUCCESS => {
                syscall.finish();
                break;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .FAULT => |err| return errnoBug(err),
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .ACCES => return error.AccessDenied,
                    .FBIG => return error.FileTooBig,
                    .OVERFLOW => return error.FileTooBig,
                    .ISDIR => return error.IsDir,
                    .LOOP => return error.SymLinkLoop,
                    .MFILE => return error.ProcessFdQuotaExceeded,
                    .NFILE => return error.SystemFdQuotaExceeded,
                    .NODEV => return error.NoDevice,
                    .NOENT => return error.FileNotFound,
                    .NOMEM => return error.SystemResources,
                    .NOTDIR => return error.NotDir,
                    .PERM => return error.PermissionDenied,
                    .BUSY => return error.DeviceBusy,
                    .NOTCAPABLE => return error.AccessDenied,
                    .NAMETOOLONG => return error.NameTooLong,
                    .INVAL => return error.BadPathName,
                    .ILSEQ => return error.BadPathName,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
    errdefer posix.close(fd);

    if (!flags.allow_directory) {
        const is_dir = is_dir: {
            const stat = fileStat(t, .{ .handle = fd }) catch |err| switch (err) {
                // The directory-ness is either unknown or unknowable
                error.Streaming => break :is_dir false,
                else => |e| return e,
            };
            break :is_dir stat.kind == .directory;
        };
        if (is_dir) return error.IsDir;
    }

    return .{ .handle = fd };
}

const dirOpenDir = switch (native_os) {
    .wasi => dirOpenDirWasi,
    .haiku => dirOpenDirHaiku,
    else => dirOpenDirPosix,
};

/// This function is also used for WASI when libc is linked.
fn dirOpenDirPosix(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    options: Dir.OpenOptions,
) Dir.OpenError!Dir {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (is_windows) {
        const sub_path_w = try windows.sliceToPrefixedFileW(dir.handle, sub_path);
        return dirOpenDirWindows(dir, sub_path_w.span(), options);
    }

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    var flags: posix.O = switch (native_os) {
        .wasi => .{
            .read = true,
            .NOFOLLOW = !options.follow_symlinks,
            .DIRECTORY = true,
        },
        else => .{
            .ACCMODE = .RDONLY,
            .NOFOLLOW = !options.follow_symlinks,
            .DIRECTORY = true,
            .CLOEXEC = true,
        },
    };

    if (@hasField(posix.O, "PATH") and !options.iterate)
        flags.PATH = true;

    const syscall: Syscall = try .start();
    while (true) {
        const rc = openat_sym(dir.handle, sub_path_posix, flags, @as(usize, 0));
        switch (posix.errno(rc)) {
            .SUCCESS => {
                syscall.finish();
                return .{ .handle = @intCast(rc) };
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => return error.BadPathName,
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .ACCES => return error.AccessDenied,
                    .LOOP => return error.SymLinkLoop,
                    .MFILE => return error.ProcessFdQuotaExceeded,
                    .NAMETOOLONG => return error.NameTooLong,
                    .NFILE => return error.SystemFdQuotaExceeded,
                    .NODEV => return error.NoDevice,
                    .NOENT => return error.FileNotFound,
                    .NOMEM => return error.SystemResources,
                    .NOTDIR => return error.NotDir,
                    .PERM => return error.PermissionDenied,
                    .BUSY => return error.DeviceBusy,
                    .NXIO => return error.NoDevice,
                    .ILSEQ => return error.BadPathName,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn dirOpenDirHaiku(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    options: Dir.OpenOptions,
) Dir.OpenError!Dir {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    _ = options;

    const syscall: Syscall = try .start();
    while (true) {
        const rc = posix.system._kern_open_dir(dir.handle, sub_path_posix);
        if (rc >= 0) {
            syscall.finish();
            return .{ .handle = rc };
        }
        switch (@as(posix.E, @enumFromInt(rc))) {
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err),
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .ACCES => return error.AccessDenied,
                    .LOOP => return error.SymLinkLoop,
                    .MFILE => return error.ProcessFdQuotaExceeded,
                    .NAMETOOLONG => return error.NameTooLong,
                    .NFILE => return error.SystemFdQuotaExceeded,
                    .NODEV => return error.NoDevice,
                    .NOENT => return error.FileNotFound,
                    .NOMEM => return error.SystemResources,
                    .NOTDIR => return error.NotDir,
                    .PERM => return error.PermissionDenied,
                    .BUSY => return error.DeviceBusy,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

pub fn dirOpenDirWindows(
    dir: Dir,
    sub_path_w: [:0]const u16,
    options: Dir.OpenOptions,
) Dir.OpenError!Dir {
    const w = windows;

    const path_len_bytes: u16 = @intCast(sub_path_w.len * 2);
    var nt_name: w.UNICODE_STRING = .{
        .Length = path_len_bytes,
        .MaximumLength = path_len_bytes,
        .Buffer = @constCast(sub_path_w.ptr),
    };
    var io_status_block: w.IO_STATUS_BLOCK = undefined;
    var result: Dir = .{ .handle = undefined };

    const syscall: Syscall = try .start();
    while (true) switch (w.ntdll.NtCreateFile(
        &result.handle,
        // TODO remove some of these flags if options.access_sub_paths is false
        .{
            .SPECIFIC = .{ .FILE_DIRECTORY = .{
                .LIST = options.iterate,
                .READ_EA = true,
                .TRAVERSE = true,
                .READ_ATTRIBUTES = true,
            } },
            .STANDARD = .{
                .RIGHTS = .READ,
                .SYNCHRONIZE = true,
            },
        },
        &.{
            .Length = @sizeOf(w.OBJECT_ATTRIBUTES),
            .RootDirectory = if (std.fs.path.isAbsoluteWindowsWtf16(sub_path_w)) null else dir.handle,
            .Attributes = .{},
            .ObjectName = &nt_name,
            .SecurityDescriptor = null,
            .SecurityQualityOfService = null,
        },
        &io_status_block,
        null,
        .{ .NORMAL = true },
        .VALID_FLAGS,
        .OPEN,
        .{
            .DIRECTORY_FILE = true,
            .IO = .SYNCHRONOUS_NONALERT,
            .OPEN_FOR_BACKUP_INTENT = true,
            .OPEN_REPARSE_POINT = !options.follow_symlinks,
        },
        null,
        0,
    )) {
        .SUCCESS => {
            syscall.finish();
            return result;
        },
        .CANCELLED => {
            try syscall.checkCancel();
            continue;
        },
        .OBJECT_NAME_INVALID => return syscall.fail(error.BadPathName),
        .OBJECT_NAME_NOT_FOUND => return syscall.fail(error.FileNotFound),
        .OBJECT_NAME_COLLISION => |err| return w.statusBug(err),
        .OBJECT_PATH_NOT_FOUND => return syscall.fail(error.FileNotFound),
        .NOT_A_DIRECTORY => return syscall.fail(error.NotDir),
        // This can happen if the directory has 'List folder contents' permission set to 'Deny'
        // and the directory is trying to be opened for iteration.
        .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
        .INVALID_PARAMETER => |err| return syscall.ntstatusBug(err),
        else => |rc| return syscall.unexpectedNtstatus(rc),
    };
}

fn dirClose(userdata: ?*anyopaque, dirs: []const Dir) void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    for (dirs) |dir| posix.close(dir.handle);
}

const dirRead = switch (native_os) {
    .linux => dirReadLinux,
    .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos => dirReadDarwin,
    .freebsd, .netbsd, .dragonfly, .openbsd => dirReadBsd,
    .illumos => dirReadIllumos,
    .haiku => dirReadHaiku,
    .windows => dirReadWindows,
    .wasi => dirReadWasi,
    else => dirReadUnimplemented,
};

fn dirReadLinux(userdata: ?*anyopaque, dr: *Dir.Reader, buffer: []Dir.Entry) Dir.Reader.Error!usize {
    const linux = std.os.linux;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    var buffer_index: usize = 0;
    while (buffer.len - buffer_index != 0) {
        if (dr.end - dr.index == 0) {
            // Refill the buffer, unless we've already created references to
            // buffered data.
            if (buffer_index != 0) break;
            if (dr.state == .reset) {
                posixSeekTo(dr.dir.handle, 0) catch |err| switch (err) {
                    error.Unseekable => return error.Unexpected,
                    else => |e| return e,
                };
                dr.state = .reading;
            }
            const syscall: Syscall = try .start();
            const n = while (true) {
                const rc = linux.getdents64(dr.dir.handle, dr.buffer.ptr, dr.buffer.len);
                switch (linux.errno(rc)) {
                    .SUCCESS => {
                        syscall.finish();
                        break rc;
                    },
                    .INTR => {
                        try syscall.checkCancel();
                        continue;
                    },
                    else => |e| {
                        syscall.finish();
                        switch (e) {
                            .BADF => |err| return errnoBug(err), // Dir is invalid or was opened without iteration ability.
                            .FAULT => |err| return errnoBug(err),
                            .NOTDIR => |err| return errnoBug(err),
                            // To be consistent across platforms, iteration
                            // ends if the directory being iterated is deleted
                            // during iteration. This matches the behavior of
                            // non-Linux, non-WASI UNIX platforms.
                            .NOENT => {
                                dr.state = .finished;
                                return 0;
                            },
                            // This can occur when reading /proc/$PID/net, or
                            // if the provided buffer is too small. Neither
                            // scenario is intended to be handled by this API.
                            .INVAL => return error.Unexpected,
                            .ACCES => return error.AccessDenied, // Lacking permission to iterate this directory.
                            else => |err| return posix.unexpectedErrno(err),
                        }
                    },
                }
            };
            if (n == 0) {
                dr.state = .finished;
                return 0;
            }
            dr.index = 0;
            dr.end = n;
        }
        // Linux aligns the header by padding after the null byte of the name
        // to align the next entry. This means we can find the end of the name
        // by looking at only the 8 bytes before the next record. However since
        // file names are usually short it's better to keep the machine code
        // simpler.
        //
        // Furthermore, I observed qemu user mode to not align this struct, so
        // this code makes the conservative choice to not assume alignment.
        const linux_entry: *align(1) linux.dirent64 = @ptrCast(&dr.buffer[dr.index]);
        const next_index = dr.index + linux_entry.reclen;
        dr.index = next_index;
        const name_ptr: [*]u8 = &linux_entry.name;
        const padded_name = name_ptr[0 .. linux_entry.reclen - @offsetOf(linux.dirent64, "name")];
        const name_len = std.mem.findScalar(u8, padded_name, 0).?;
        const name = name_ptr[0..name_len :0];

        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;

        const entry_kind: File.Kind = switch (linux_entry.type) {
            linux.DT.BLK => .block_device,
            linux.DT.CHR => .character_device,
            linux.DT.DIR => .directory,
            linux.DT.FIFO => .named_pipe,
            linux.DT.LNK => .sym_link,
            linux.DT.REG => .file,
            linux.DT.SOCK => .unix_domain_socket,
            else => .unknown,
        };
        buffer[buffer_index] = .{
            .name = name,
            .kind = entry_kind,
            .inode = linux_entry.ino,
        };
        buffer_index += 1;
    }
    return buffer_index;
}

fn dirReadDarwin(userdata: ?*anyopaque, dr: *Dir.Reader, buffer: []Dir.Entry) Dir.Reader.Error!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const Header = extern struct {
        seek: i64,
    };
    const header: *Header = @ptrCast(dr.buffer.ptr);
    const header_end: usize = @sizeOf(Header);
    if (dr.index < header_end) {
        // Initialize header.
        dr.index = header_end;
        dr.end = header_end;
        header.* = .{ .seek = 0 };
    }
    var buffer_index: usize = 0;
    while (buffer.len - buffer_index != 0) {
        if (dr.end - dr.index == 0) {
            // Refill the buffer, unless we've already created references to
            // buffered data.
            if (buffer_index != 0) break;
            if (dr.state == .reset) {
                posixSeekTo(dr.dir.handle, 0) catch |err| switch (err) {
                    error.Unseekable => return error.Unexpected,
                    else => |e| return e,
                };
                dr.state = .reading;
            }
            const dents_buffer = dr.buffer[header_end..];
            const syscall: Syscall = try .start();
            const n: usize = while (true) {
                const rc = posix.system.getdirentries(dr.dir.handle, dents_buffer.ptr, dents_buffer.len, &header.seek);
                switch (posix.errno(rc)) {
                    .SUCCESS => {
                        syscall.finish();
                        break @intCast(rc);
                    },
                    .INTR => {
                        try syscall.checkCancel();
                        continue;
                    },
                    else => |e| {
                        syscall.finish();
                        switch (e) {
                            .BADF => |err| return errnoBug(err), // Dir is invalid or was opened without iteration ability.
                            .FAULT => |err| return errnoBug(err),
                            .NOTDIR => |err| return errnoBug(err),
                            .INVAL => |err| return errnoBug(err),
                            else => |err| return posix.unexpectedErrno(err),
                        }
                    },
                }
            };
            if (n == 0) {
                dr.state = .finished;
                return 0;
            }
            dr.index = header_end;
            dr.end = header_end + n;
        }
        const darwin_entry = @as(*align(1) posix.system.dirent, @ptrCast(&dr.buffer[dr.index]));
        const next_index = dr.index + darwin_entry.reclen;
        dr.index = next_index;

        const name = @as([*]u8, @ptrCast(&darwin_entry.name))[0..darwin_entry.namlen];
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..") or (darwin_entry.ino == 0))
            continue;

        const entry_kind: File.Kind = switch (darwin_entry.type) {
            posix.DT.BLK => .block_device,
            posix.DT.CHR => .character_device,
            posix.DT.DIR => .directory,
            posix.DT.FIFO => .named_pipe,
            posix.DT.LNK => .sym_link,
            posix.DT.REG => .file,
            posix.DT.SOCK => .unix_domain_socket,
            posix.DT.WHT => .whiteout,
            else => .unknown,
        };
        buffer[buffer_index] = .{
            .name = name,
            .kind = entry_kind,
            .inode = darwin_entry.ino,
        };
        buffer_index += 1;
    }
    return buffer_index;
}

fn dirReadBsd(userdata: ?*anyopaque, dr: *Dir.Reader, buffer: []Dir.Entry) Dir.Reader.Error!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    var buffer_index: usize = 0;
    while (buffer.len - buffer_index != 0) {
        if (dr.end - dr.index == 0) {
            // Refill the buffer, unless we've already created references to
            // buffered data.
            if (buffer_index != 0) break;
            if (dr.state == .reset) {
                posixSeekTo(dr.dir.handle, 0) catch |err| switch (err) {
                    error.Unseekable => return error.Unexpected,
                    else => |e| return e,
                };
                dr.state = .reading;
            }
            const syscall: Syscall = try .start();
            const n: usize = while (true) {
                const rc = posix.system.getdents(dr.dir.handle, dr.buffer.ptr, dr.buffer.len);
                switch (posix.errno(rc)) {
                    .SUCCESS => {
                        syscall.finish();
                        break @intCast(rc);
                    },
                    .INTR => {
                        try syscall.checkCancel();
                        continue;
                    },
                    else => |e| {
                        syscall.finish();
                        switch (e) {
                            .BADF => |err| return errnoBug(err), // Dir is invalid or was opened without iteration ability
                            .FAULT => |err| return errnoBug(err),
                            .NOTDIR => |err| return errnoBug(err),
                            .INVAL => |err| return errnoBug(err),
                            // Introduced in freebsd 13.2: directory unlinked
                            // but still open. To be consistent, iteration ends
                            // if the directory being iterated is deleted
                            // during iteration.
                            .NOENT => {
                                dr.state = .finished;
                                return 0;
                            },
                            else => |err| return posix.unexpectedErrno(err),
                        }
                    },
                }
            };
            if (n == 0) {
                dr.state = .finished;
                return 0;
            }
            dr.index = 0;
            dr.end = n;
        }
        const bsd_entry = @as(*align(1) posix.system.dirent, @ptrCast(&dr.buffer[dr.index]));
        const next_index = dr.index +
            if (@hasField(posix.system.dirent, "reclen")) bsd_entry.reclen else bsd_entry.reclen();
        dr.index = next_index;

        const name = @as([*]u8, @ptrCast(&bsd_entry.name))[0..bsd_entry.namlen];

        const skip_zero_fileno = switch (native_os) {
            // fileno=0 is used to mark invalid entries or deleted files.
            .openbsd, .netbsd => true,
            else => false,
        };
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..") or
            (skip_zero_fileno and bsd_entry.fileno == 0))
        {
            continue;
        }

        const entry_kind: File.Kind = switch (bsd_entry.type) {
            posix.DT.BLK => .block_device,
            posix.DT.CHR => .character_device,
            posix.DT.DIR => .directory,
            posix.DT.FIFO => .named_pipe,
            posix.DT.LNK => .sym_link,
            posix.DT.REG => .file,
            posix.DT.SOCK => .unix_domain_socket,
            posix.DT.WHT => .whiteout,
            else => .unknown,
        };
        buffer[buffer_index] = .{
            .name = name,
            .kind = entry_kind,
            .inode = bsd_entry.fileno,
        };
        buffer_index += 1;
    }
    return buffer_index;
}

fn dirReadIllumos(userdata: ?*anyopaque, dr: *Dir.Reader, buffer: []Dir.Entry) Dir.Reader.Error!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    var buffer_index: usize = 0;
    while (buffer.len - buffer_index != 0) {
        if (dr.end - dr.index == 0) {
            // Refill the buffer, unless we've already created references to
            // buffered data.
            if (buffer_index != 0) break;
            if (dr.state == .reset) {
                posixSeekTo(dr.dir.handle, 0) catch |err| switch (err) {
                    error.Unseekable => return error.Unexpected,
                    else => |e| return e,
                };
                dr.state = .reading;
            }
            const syscall: Syscall = try .start();
            const n: usize = while (true) {
                const rc = posix.system.getdents(dr.dir.handle, dr.buffer.ptr, dr.buffer.len);
                switch (posix.errno(rc)) {
                    .SUCCESS => {
                        syscall.finish();
                        break rc;
                    },
                    .INTR => {
                        try syscall.checkCancel();
                        continue;
                    },
                    else => |e| {
                        syscall.finish();
                        switch (e) {
                            .BADF => |err| return errnoBug(err), // Dir is invalid or was opened without iteration ability
                            .FAULT => |err| return errnoBug(err),
                            .NOTDIR => |err| return errnoBug(err),
                            .INVAL => |err| return errnoBug(err),
                            else => |err| return posix.unexpectedErrno(err),
                        }
                    },
                }
            };
            if (n == 0) {
                dr.state = .finished;
                return 0;
            }
            dr.index = 0;
            dr.end = n;
        }
        const entry = @as(*align(1) posix.system.dirent, @ptrCast(&dr.buffer[dr.index]));
        const next_index = dr.index + entry.reclen;
        dr.index = next_index;

        const name = std.mem.sliceTo(@as([*:0]u8, @ptrCast(&entry.name)), 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;

        // illumos dirent doesn't expose type, so we have to call stat to get it.
        const stat = try posixStatFile(dr.dir.handle, name, posix.AT.SYMLINK_NOFOLLOW);

        buffer[buffer_index] = .{
            .name = name,
            .kind = stat.kind,
            .inode = entry.ino,
        };
        buffer_index += 1;
    }
    return buffer_index;
}

fn dirReadHaiku(userdata: ?*anyopaque, dr: *Dir.Reader, buffer: []Dir.Entry) Dir.Reader.Error!usize {
    _ = userdata;
    _ = dr;
    _ = buffer;
    @panic("TODO implement dirReadHaiku");
}

fn dirReadWindows(userdata: ?*anyopaque, dr: *Dir.Reader, buffer: []Dir.Entry) Dir.Reader.Error!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const w = windows;

    // We want to be able to use the `dr.buffer` for both the NtQueryDirectoryFile call (which
    // returns WTF-16 names) *and* as a buffer for storing those WTF-16 names as WTF-8 to be able
    // to return them in `Dir.Entry.name`. However, the problem that needs to be overcome in order to do
    // that is that each WTF-16 code unit can be encoded as a maximum of 3 WTF-8 bytes, which means
    // that it's not guaranteed that the memory used for the WTF-16 name will be sufficient
    // for the WTF-8 encoding of the same name (for example, € is encoded as one WTF-16 code unit,
    // [2 bytes] but encoded in WTF-8 as 3 bytes).
    //
    // The approach taken here is to "reserve" enough space in the `dr.buffer` to ensure that
    // at least one entry with the maximum possible WTF-8 name length can be stored without clobbering
    // any entries that follow it. That is, we determine how much space is needed to allow that,
    // and then only provide the remaining portion of `dr.buffer` to the NtQueryDirectoryFile
    // call. The WTF-16 names can then be safely converted using the full `dr.buffer` slice, making
    // sure that each name can only potentially overwrite the data of its own entry.
    //
    // The worst case, where an entry's name is both the maximum length of a component and
    // made up entirely of code points that are encoded as one WTF-16 code unit/three WTF-8 bytes,
    // would therefore look like the diagram below, and only one entry would be able to be returned:
    //
    //     |   reserved  | remaining unreserved buffer |
    //                   | entry 1 | entry 2 |   ...   |
    //     | wtf-8 name of entry 1 |
    //
    // However, in the average case we will be able to store more than one WTF-8 name at a time in the
    // available buffer and therefore we will be able to populate more than one `Dir.Entry` at a time.
    // That might look something like this (where name 1, name 2, etc are the converted WTF-8 names):
    //
    //     |   reserved  | remaining unreserved buffer |
    //                   | entry 1 | entry 2 |   ...   |
    //     | name 1 | name 2 | name 3 | name 4 |  ...  |
    //
    // Note: More than the minimum amount of space could be reserved to make the "worst case"
    // less likely, but since the worst-case also requires a maximum length component to matter,
    // it's unlikely for it to become a problem in normal scenarios even if all names on the filesystem
    // are made up of non-ASCII characters that have the "one WTF-16 code unit <-> three WTF-8 bytes"
    // property (e.g. code points >= U+0800 and <= U+FFFF), as it's unlikely for a significant
    // number of components to be maximum length.

    // We need `3 * NAME_MAX` bytes to store a max-length component as WTF-8 safely.
    // Because needing to store a max-length component depends on a `FileName` *with* the maximum
    // component length, we know that the corresponding populated `FILE_BOTH_DIR_INFORMATION` will
    // be of size `@sizeOf(w.FILE_BOTH_DIR_INFORMATION) + 2 * NAME_MAX` bytes, so we only need to
    // reserve enough to get us to up to having `3 * NAME_MAX` bytes available when taking into account
    // that we have the ability to write over top of the reserved memory + the full footprint of that
    // particular `FILE_BOTH_DIR_INFORMATION`.
    const max_info_len = @sizeOf(w.FILE_BOTH_DIR_INFORMATION) + w.NAME_MAX * 2;
    const info_align = @alignOf(w.FILE_BOTH_DIR_INFORMATION);
    const reserve_needed = std.mem.alignForward(usize, Dir.max_name_bytes, info_align) - max_info_len;
    const unreserved_start = std.mem.alignForward(usize, reserve_needed, info_align);
    const unreserved_buffer = dr.buffer[unreserved_start..];
    // This is enforced by `Dir.Reader`
    assert(unreserved_buffer.len >= max_info_len);

    var name_index: usize = 0;
    var buffer_index: usize = 0;
    while (buffer.len - buffer_index != 0) {
        if (dr.end - dr.index == 0) {
            // Refill the buffer, unless we've already created references to
            // buffered data.
            if (buffer_index != 0) break;

            var io_status_block: w.IO_STATUS_BLOCK = undefined;
            const syscall: Syscall = try .start();
            const rc = while (true) switch (w.ntdll.NtQueryDirectoryFile(
                dr.dir.handle,
                null,
                null,
                null,
                &io_status_block,
                unreserved_buffer.ptr,
                std.math.lossyCast(w.ULONG, unreserved_buffer.len),
                .BothDirectory,
                w.FALSE,
                null,
                @intFromBool(dr.state == .reset),
            )) {
                .CANCELLED => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |rc| {
                    syscall.finish();
                    break rc;
                },
            };
            dr.state = .reading;
            if (io_status_block.Information == 0) {
                dr.state = .finished;
                return 0;
            }
            dr.index = 0;
            dr.end = io_status_block.Information;
            switch (rc) {
                .SUCCESS => {},
                .ACCESS_DENIED => return error.AccessDenied, // Double-check that the Dir was opened with iteration ability
                else => return w.unexpectedStatus(rc),
            }
        }

        // While the official API docs guarantee FILE_BOTH_DIR_INFORMATION to be aligned properly
        // this may not always be the case (e.g. due to faulty VM/sandboxing tools)
        const dir_info: *align(2) w.FILE_BOTH_DIR_INFORMATION = @ptrCast(@alignCast(&unreserved_buffer[dr.index]));
        const backtrack_index = dr.index;
        if (dir_info.NextEntryOffset != 0) {
            dr.index += dir_info.NextEntryOffset;
        } else {
            dr.index = dr.end;
        }

        const name_wtf16le = @as([*]u16, @ptrCast(&dir_info.FileName))[0 .. dir_info.FileNameLength / 2];

        if (std.mem.eql(u16, name_wtf16le, &[_]u16{'.'}) or std.mem.eql(u16, name_wtf16le, &[_]u16{ '.', '.' })) {
            continue;
        }

        // Read any relevant information from the `dir_info` now since it's possible the WTF-8
        // name will overwrite it.
        const kind: File.Kind = blk: {
            const attrs = dir_info.FileAttributes;
            if (attrs.REPARSE_POINT) break :blk .sym_link;
            if (attrs.DIRECTORY) break :blk .directory;
            break :blk .file;
        };
        const inode: File.INode = dir_info.FileIndex;

        // If there's no more space for WTF-8 names without bleeding over into
        // the remaining unprocessed entries, then backtrack and return what we have so far.
        if (name_index + std.unicode.calcWtf8Len(name_wtf16le) > unreserved_start + dr.index) {
            // We should always be able to fit at least one entry into the buffer no matter what
            assert(buffer_index != 0);
            dr.index = backtrack_index;
            break;
        }

        const name_buf = dr.buffer[name_index..];
        const name_wtf8_len = std.unicode.wtf16LeToWtf8(name_buf, name_wtf16le);
        const name_wtf8 = name_buf[0..name_wtf8_len];
        name_index += name_wtf8_len;

        buffer[buffer_index] = .{
            .name = name_wtf8,
            .kind = kind,
            .inode = inode,
        };
        buffer_index += 1;
    }

    return buffer_index;
}

fn dirReadWasi(userdata: ?*anyopaque, dr: *Dir.Reader, buffer: []Dir.Entry) Dir.Reader.Error!usize {
    // We intentinally use fd_readdir even when linked with libc, since its
    // implementation is exactly the same as below, and we avoid the code
    // complexity here.
    const wasi = std.os.wasi;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const Header = extern struct {
        cookie: u64,
    };
    const header: *align(@alignOf(usize)) Header = @ptrCast(dr.buffer.ptr);
    const header_end: usize = @sizeOf(Header);
    if (dr.index < header_end) {
        // Initialize header.
        dr.index = header_end;
        dr.end = header_end;
        header.* = .{ .cookie = wasi.DIRCOOKIE_START };
    }
    var buffer_index: usize = 0;
    while (buffer.len - buffer_index != 0) {
        // According to the WASI spec, the last entry might be truncated, so we
        // need to check if the remaining buffer contains the whole dirent.
        if (dr.end - dr.index < @sizeOf(wasi.dirent_t)) {
            // Refill the buffer, unless we've already created references to
            // buffered data.
            if (buffer_index != 0) break;
            if (dr.state == .reset) {
                header.* = .{ .cookie = wasi.DIRCOOKIE_START };
                dr.state = .reading;
            }
            const dents_buffer = dr.buffer[header_end..];
            var n: usize = undefined;
            const syscall: Syscall = try .start();
            while (true) {
                switch (wasi.fd_readdir(dr.dir.handle, dents_buffer.ptr, dents_buffer.len, header.cookie, &n)) {
                    .SUCCESS => {
                        syscall.finish();
                        break;
                    },
                    .INTR => {
                        try syscall.checkCancel();
                        continue;
                    },
                    else => |e| {
                        syscall.finish();
                        switch (e) {
                            .BADF => |err| return errnoBug(err), // Dir is invalid or was opened without iteration ability.
                            .FAULT => |err| return errnoBug(err),
                            .NOTDIR => |err| return errnoBug(err),
                            .INVAL => |err| return errnoBug(err),
                            // To be consistent across platforms, iteration
                            // ends if the directory being iterated is deleted
                            // during iteration. This matches the behavior of
                            // non-Linux, non-WASI UNIX platforms.
                            .NOENT => {
                                dr.state = .finished;
                                return 0;
                            },
                            .NOTCAPABLE => return error.AccessDenied,
                            else => |err| return posix.unexpectedErrno(err),
                        }
                    },
                }
            }
            if (n == 0) {
                dr.state = .finished;
                return 0;
            }
            dr.index = header_end;
            dr.end = header_end + n;
        }
        const entry: *align(1) wasi.dirent_t = @ptrCast(&dr.buffer[dr.index]);
        const entry_size = @sizeOf(wasi.dirent_t);
        const name_index = dr.index + entry_size;
        if (name_index + entry.namlen > dr.end) {
            // This case, the name is truncated, so we need to call readdir to store the entire name.
            dr.end = dr.index; // Force fd_readdir in the next loop.
            continue;
        }
        const name = dr.buffer[name_index..][0..entry.namlen];
        const next_index = name_index + entry.namlen;
        dr.index = next_index;
        header.cookie = entry.next;

        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, ".."))
            continue;

        const entry_kind: File.Kind = switch (entry.type) {
            .BLOCK_DEVICE => .block_device,
            .CHARACTER_DEVICE => .character_device,
            .DIRECTORY => .directory,
            .SYMBOLIC_LINK => .sym_link,
            .REGULAR_FILE => .file,
            .SOCKET_STREAM, .SOCKET_DGRAM => .unix_domain_socket,
            else => .unknown,
        };
        buffer[buffer_index] = .{
            .name = name,
            .kind = entry_kind,
            .inode = entry.ino,
        };
        buffer_index += 1;
    }
    return buffer_index;
}

fn dirReadUnimplemented(userdata: ?*anyopaque, dir_reader: *Dir.Reader, buffer: []Dir.Entry) Dir.Reader.Error!usize {
    _ = userdata;
    _ = dir_reader;
    _ = buffer;
    return error.Unimplemented;
}

const dirRealPathFile = switch (native_os) {
    .windows => dirRealPathFileWindows,
    else => dirRealPathFilePosix,
};

fn dirRealPathFileWindows(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, out_buffer: []u8) Dir.RealPathFileError!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var path_name_w = try windows.sliceToPrefixedFileW(dir.handle, sub_path);

    const h_file = handle: {
        const syscall: Syscall = try .start();
        while (true) {
            if (windows.OpenFile(path_name_w.span(), .{
                .dir = dir.handle,
                .access_mask = .{
                    .GENERIC = .{ .READ = true },
                    .STANDARD = .{ .SYNCHRONIZE = true },
                },
                .creation = .OPEN,
                .filter = .any,
            })) |handle| {
                syscall.finish();
                break :handle handle;
            } else |err| switch (err) {
                error.WouldBlock => unreachable,
                error.OperationCanceled => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| return syscall.fail(e),
            }
        }
    };
    defer windows.CloseHandle(h_file);
    return realPathWindows(h_file, out_buffer);
}

fn realPathWindows(h_file: windows.HANDLE, out_buffer: []u8) File.RealPathError!usize {
    var wide_buf: [windows.PATH_MAX_WIDE]u16 = undefined;
    // TODO move GetFinalPathNameByHandle logic into std.Io.Threaded and add cancel checks
    try Thread.checkCancel();
    const wide_slice = try windows.GetFinalPathNameByHandle(h_file, .{}, &wide_buf);

    const len = std.unicode.calcWtf8Len(wide_slice);
    if (len > out_buffer.len)
        return error.NameTooLong;

    return std.unicode.wtf16LeToWtf8(out_buffer, wide_slice);
}

fn dirRealPathFilePosix(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, out_buffer: []u8) Dir.RealPathFileError!usize {
    if (native_os == .wasi) return error.OperationUnsupported;

    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    if (builtin.link_libc and dir.handle == posix.AT.FDCWD) {
        if (out_buffer.len < posix.PATH_MAX) return error.NameTooLong;
        const syscall: Syscall = try .start();
        while (true) {
            if (std.c.realpath(sub_path_posix, out_buffer.ptr)) |redundant_pointer| {
                syscall.finish();
                assert(redundant_pointer == out_buffer.ptr);
                return std.mem.indexOfScalar(u8, out_buffer, 0) orelse out_buffer.len;
            }
            const err: posix.E = @enumFromInt(std.c._errno().*);
            if (err == .INTR) {
                try syscall.checkCancel();
                continue;
            }
            syscall.finish();
            switch (err) {
                .INVAL => return errnoBug(err),
                .BADF => return errnoBug(err),
                .FAULT => return errnoBug(err),
                .ACCES => return error.AccessDenied,
                .NOENT => return error.FileNotFound,
                .OPNOTSUPP => return error.OperationUnsupported,
                .NOTDIR => return error.NotDir,
                .NAMETOOLONG => return error.NameTooLong,
                .LOOP => return error.SymLinkLoop,
                .IO => return error.InputOutput,
                else => return posix.unexpectedErrno(err),
            }
        }
    }

    var flags: posix.O = .{};
    if (@hasField(posix.O, "NONBLOCK")) flags.NONBLOCK = true;
    if (@hasField(posix.O, "CLOEXEC")) flags.CLOEXEC = true;
    if (@hasField(posix.O, "PATH")) flags.PATH = true;

    const mode: posix.mode_t = 0;

    const syscall: Syscall = try .start();
    const fd: posix.fd_t = while (true) {
        const rc = openat_sym(dir.handle, sub_path_posix, flags, mode);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                syscall.finish();
                break @intCast(rc);
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => return error.BadPathName,
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .ACCES => return error.AccessDenied,
                    .FBIG => return error.FileTooBig,
                    .OVERFLOW => return error.FileTooBig,
                    .ISDIR => return error.IsDir,
                    .LOOP => return error.SymLinkLoop,
                    .MFILE => return error.ProcessFdQuotaExceeded,
                    .NAMETOOLONG => return error.NameTooLong,
                    .NFILE => return error.SystemFdQuotaExceeded,
                    .NODEV => return error.NoDevice,
                    .NOENT => return error.FileNotFound,
                    .SRCH => return error.FileNotFound, // Linux when accessing procfs.
                    .NOMEM => return error.SystemResources,
                    .NOSPC => return error.NoSpaceLeft,
                    .NOTDIR => return error.NotDir,
                    .PERM => return error.PermissionDenied,
                    .EXIST => return error.PathAlreadyExists,
                    .BUSY => return error.DeviceBusy,
                    .NXIO => return error.NoDevice,
                    .ILSEQ => return error.BadPathName,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    };
    defer posix.close(fd);
    return realPathPosix(fd, out_buffer);
}

const dirRealPath = switch (native_os) {
    .windows => dirRealPathWindows,
    else => dirRealPathPosix,
};

fn dirRealPathPosix(userdata: ?*anyopaque, dir: Dir, out_buffer: []u8) Dir.RealPathError!usize {
    if (native_os == .wasi) return error.OperationUnsupported;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    return realPathPosix(dir.handle, out_buffer);
}

fn dirRealPathWindows(userdata: ?*anyopaque, dir: Dir, out_buffer: []u8) Dir.RealPathError!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    return realPathWindows(dir.handle, out_buffer);
}

const fileRealPath = switch (native_os) {
    .windows => fileRealPathWindows,
    else => fileRealPathPosix,
};

fn fileRealPathWindows(userdata: ?*anyopaque, file: File, out_buffer: []u8) File.RealPathError!usize {
    if (native_os == .wasi) return error.OperationUnsupported;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    return realPathWindows(file.handle, out_buffer);
}

fn fileRealPathPosix(userdata: ?*anyopaque, file: File, out_buffer: []u8) File.RealPathError!usize {
    if (native_os == .wasi) return error.OperationUnsupported;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    return realPathPosix(file.handle, out_buffer);
}

fn realPathPosix(fd: posix.fd_t, out_buffer: []u8) File.RealPathError!usize {
    switch (native_os) {
        .netbsd, .dragonfly, .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos => {
            var sufficient_buffer: [posix.PATH_MAX]u8 = undefined;
            @memset(&sufficient_buffer, 0);
            const syscall: Syscall = try .start();
            while (true) {
                switch (posix.errno(posix.system.fcntl(fd, posix.F.GETPATH, &sufficient_buffer))) {
                    .SUCCESS => {
                        syscall.finish();
                        break;
                    },
                    .INTR => {
                        try syscall.checkCancel();
                        continue;
                    },
                    else => |e| {
                        syscall.finish();
                        switch (e) {
                            .ACCES => return error.AccessDenied,
                            .BADF => return error.FileNotFound,
                            .NOENT => return error.FileNotFound,
                            .NOMEM => return error.SystemResources,
                            .NOSPC => return error.NameTooLong,
                            .RANGE => return error.NameTooLong,
                            else => |err| return posix.unexpectedErrno(err),
                        }
                    },
                }
            }
            const n = std.mem.indexOfScalar(u8, &sufficient_buffer, 0) orelse sufficient_buffer.len;
            if (n > out_buffer.len) return error.NameTooLong;
            @memcpy(out_buffer[0..n], sufficient_buffer[0..n]);
            return n;
        },
        .linux, .serenity, .illumos => {
            var procfs_buf: ["/proc/self/path/-2147483648\x00".len]u8 = undefined;
            const template = if (native_os == .illumos) "/proc/self/path/{d}" else "/proc/self/fd/{d}";
            const proc_path = std.fmt.bufPrintSentinel(&procfs_buf, template, .{fd}, 0) catch unreachable;
            const syscall: Syscall = try .start();
            while (true) {
                const rc = posix.system.readlink(proc_path, out_buffer.ptr, out_buffer.len);
                switch (posix.errno(rc)) {
                    .SUCCESS => {
                        syscall.finish();
                        const len: usize = @bitCast(rc);
                        return len;
                    },
                    .INTR => {
                        try syscall.checkCancel();
                        continue;
                    },
                    else => |e| {
                        syscall.finish();
                        switch (e) {
                            .ACCES => return error.AccessDenied,
                            .FAULT => |err| return errnoBug(err),
                            .IO => return error.FileSystem,
                            .LOOP => return error.SymLinkLoop,
                            .NAMETOOLONG => return error.NameTooLong,
                            .NOENT => return error.FileNotFound,
                            .NOMEM => return error.SystemResources,
                            .NOTDIR => return error.NotDir,
                            .ILSEQ => |err| return errnoBug(err),
                            else => |err| return posix.unexpectedErrno(err),
                        }
                    },
                }
            }
        },
        .freebsd => {
            var k_file: std.c.kinfo_file = undefined;
            k_file.structsize = std.c.KINFO_FILE_SIZE;
            const syscall: Syscall = try .start();
            while (true) {
                switch (posix.errno(std.c.fcntl(fd, std.c.F.KINFO, @intFromPtr(&k_file)))) {
                    .SUCCESS => {
                        syscall.finish();
                        break;
                    },
                    .INTR => {
                        try syscall.checkCancel();
                        continue;
                    },
                    .BADF => {
                        syscall.finish();
                        return error.FileNotFound;
                    },
                    else => |err| {
                        syscall.finish();
                        return posix.unexpectedErrno(err);
                    },
                }
            }
            const len = std.mem.findScalar(u8, &k_file.path, 0) orelse k_file.path.len;
            if (len == 0) return error.NameTooLong;
            @memcpy(out_buffer[0..len], k_file.path[0..len]);
            return len;
        },
        else => return error.OperationUnsupported,
    }
    comptime unreachable;
}

const dirDeleteFile = switch (native_os) {
    .windows => dirDeleteFileWindows,
    .wasi => dirDeleteFileWasi,
    else => dirDeleteFilePosix,
};

fn dirDeleteFileWindows(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8) Dir.DeleteFileError!void {
    return dirDeleteWindows(userdata, dir, sub_path, false) catch |err| switch (err) {
        error.DirNotEmpty => unreachable,
        else => |e| return e,
    };
}

fn dirDeleteFileWasi(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8) Dir.DeleteFileError!void {
    if (builtin.link_libc) return dirDeleteFilePosix(userdata, dir, sub_path);
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const syscall: Syscall = try .start();
    while (true) {
        const res = std.os.wasi.path_unlink_file(dir.handle, sub_path.ptr, sub_path.len);
        switch (res) {
            .SUCCESS => {
                syscall.finish();
                return;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ACCES => return error.AccessDenied,
                    .PERM => return error.PermissionDenied,
                    .BUSY => return error.FileBusy,
                    .FAULT => |err| return errnoBug(err),
                    .IO => return error.FileSystem,
                    .ISDIR => return error.IsDir,
                    .LOOP => return error.SymLinkLoop,
                    .NAMETOOLONG => return error.NameTooLong,
                    .NOENT => return error.FileNotFound,
                    .NOTDIR => return error.NotDir,
                    .NOMEM => return error.SystemResources,
                    .ROFS => return error.ReadOnlyFileSystem,
                    .NOTCAPABLE => return error.AccessDenied,
                    .ILSEQ => return error.BadPathName,
                    .INVAL => |err| return errnoBug(err), // invalid flags, or pathname has . as last component
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn dirDeleteFilePosix(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8) Dir.DeleteFileError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.unlinkat(dir.handle, sub_path_posix, 0))) {
            .SUCCESS => {
                syscall.finish();
                return;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            // Some systems return permission errors when trying to delete a
            // directory, so we need to handle that case specifically and
            // translate the error.
            .PERM => switch (native_os) {
                .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos, .freebsd, .netbsd, .dragonfly, .openbsd, .illumos => {

                    // Don't follow symlinks to match unlinkat (which acts on symlinks rather than follows them).
                    var st = std.mem.zeroes(posix.Stat);
                    while (true) {
                        try syscall.checkCancel();
                        switch (posix.errno(fstatat_sym(dir.handle, sub_path_posix, &st, posix.AT.SYMLINK_NOFOLLOW))) {
                            .SUCCESS => {
                                syscall.finish();
                                break;
                            },
                            .INTR => continue,
                            else => {
                                syscall.finish();
                                return error.PermissionDenied;
                            },
                        }
                    }
                    const is_dir = st.mode & posix.S.IFMT == posix.S.IFDIR;
                    if (is_dir)
                        return error.IsDir
                    else
                        return error.PermissionDenied;
                },
                else => {
                    syscall.finish();
                    return error.PermissionDenied;
                },
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ACCES => return error.AccessDenied,
                    .BUSY => return error.FileBusy,
                    .FAULT => |err| return errnoBug(err),
                    .IO => return error.FileSystem,
                    .ISDIR => return error.IsDir,
                    .LOOP => return error.SymLinkLoop,
                    .NAMETOOLONG => return error.NameTooLong,
                    .NOENT => return error.FileNotFound,
                    .NOTDIR => return error.NotDir,
                    .NOMEM => return error.SystemResources,
                    .ROFS => return error.ReadOnlyFileSystem,
                    .EXIST => |err| return errnoBug(err),
                    .NOTEMPTY => |err| return errnoBug(err), // Not passing AT.REMOVEDIR
                    .ILSEQ => return error.BadPathName,
                    .INVAL => |err| return errnoBug(err), // invalid flags, or pathname has . as last component
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

const dirDeleteDir = switch (native_os) {
    .windows => dirDeleteDirWindows,
    .wasi => dirDeleteDirWasi,
    else => dirDeleteDirPosix,
};

fn dirDeleteDirWindows(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8) Dir.DeleteDirError!void {
    return dirDeleteWindows(userdata, dir, sub_path, true) catch |err| switch (err) {
        error.IsDir => unreachable,
        else => |e| return e,
    };
}

fn dirDeleteWindows(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, remove_dir: bool) (Dir.DeleteDirError || Dir.DeleteFileError)!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const w = windows;

    const sub_path_w_buf = try w.sliceToPrefixedFileW(dir.handle, sub_path);
    const sub_path_w = sub_path_w_buf.span();

    const path_len_bytes = @as(u16, @intCast(sub_path_w.len * 2));
    var nt_name: w.UNICODE_STRING = .{
        .Length = path_len_bytes,
        .MaximumLength = path_len_bytes,
        // The Windows API makes this mutable, but it will not mutate here.
        .Buffer = @constCast(sub_path_w.ptr),
    };

    if (sub_path_w[0] == '.' and sub_path_w[1] == 0) {
        // Windows does not recognize this, but it does work with empty string.
        nt_name.Length = 0;
    }
    if (sub_path_w[0] == '.' and sub_path_w[1] == '.' and sub_path_w[2] == 0) {
        // Can't remove the parent directory with an open handle.
        return error.FileBusy;
    }

    var io_status_block: w.IO_STATUS_BLOCK = undefined;
    var tmp_handle: w.HANDLE = undefined;
    {
        const syscall: Syscall = try .start();
        while (true) switch (w.ntdll.NtCreateFile(
            &tmp_handle,
            .{ .STANDARD = .{
                .RIGHTS = .{ .DELETE = true },
                .SYNCHRONIZE = true,
            } },
            &.{
                .Length = @sizeOf(w.OBJECT_ATTRIBUTES),
                .RootDirectory = if (std.fs.path.isAbsoluteWindowsWtf16(sub_path_w)) null else dir.handle,
                .Attributes = .{},
                .ObjectName = &nt_name,
                .SecurityDescriptor = null,
                .SecurityQualityOfService = null,
            },
            &io_status_block,
            null,
            .{},
            .VALID_FLAGS,
            .OPEN,
            .{
                .DIRECTORY_FILE = remove_dir,
                .NON_DIRECTORY_FILE = !remove_dir,
                .OPEN_REPARSE_POINT = true, // would we ever want to delete the target instead?
            },
            null,
            0,
        )) {
            .SUCCESS => break syscall.finish(),
            .OBJECT_NAME_INVALID => |err| return syscall.ntstatusBug(err),
            .OBJECT_NAME_NOT_FOUND => return syscall.fail(error.FileNotFound),
            .OBJECT_PATH_NOT_FOUND => return syscall.fail(error.FileNotFound),
            .BAD_NETWORK_PATH => return syscall.fail(error.NetworkNotFound), // \\server was not found
            .BAD_NETWORK_NAME => return syscall.fail(error.NetworkNotFound), // \\server was found but \\server\share wasn't
            .INVALID_PARAMETER => |err| return syscall.ntstatusBug(err),
            .FILE_IS_A_DIRECTORY => return syscall.fail(error.IsDir),
            .NOT_A_DIRECTORY => return syscall.fail(error.NotDir),
            .SHARING_VIOLATION => return syscall.fail(error.FileBusy),
            .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
            .DELETE_PENDING => return syscall.finish(),
            else => |rc| return syscall.unexpectedNtstatus(rc),
        };
    }
    defer w.CloseHandle(tmp_handle);

    // FileDispositionInformationEx has varying levels of support:
    // - FILE_DISPOSITION_INFORMATION_EX requires >= win10_rs1
    //   (INVALID_INFO_CLASS is returned if not supported)
    // - Requires the NTFS filesystem
    //   (on filesystems like FAT32, INVALID_PARAMETER is returned)
    // - FILE_DISPOSITION_POSIX_SEMANTICS requires >= win10_rs1
    // - FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE requires >= win10_rs5
    //   (NOT_SUPPORTED is returned if a flag is unsupported)
    //
    // The strategy here is just to try using FileDispositionInformationEx and fall back to
    // FileDispositionInformation if the return value lets us know that some aspect of it is not supported.
    const rc = rc: {
        // Deletion with posix semantics if the filesystem supports it.
        const info: w.FILE.DISPOSITION.INFORMATION.EX = .{ .Flags = .{
            .DELETE = true,
            .POSIX_SEMANTICS = true,
            .IGNORE_READONLY_ATTRIBUTE = true,
        } };

        const syscall: Syscall = try .start();
        while (true) switch (w.ntdll.NtSetInformationFile(
            tmp_handle,
            &io_status_block,
            &info,
            @sizeOf(w.FILE.DISPOSITION.INFORMATION.EX),
            .DispositionEx,
        )) {
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            // The filesystem does not support FileDispositionInformationEx
            .INVALID_PARAMETER,
            // The operating system does not support FileDispositionInformationEx
            .INVALID_INFO_CLASS,
            // The operating system does not support one of the flags
            .NOT_SUPPORTED,
            => break, // use fallback path below; `syscall` still active

            // For all other statuses, fall down to the switch below to handle them.
            else => |rc| {
                syscall.finish();
                break :rc rc;
            },
        };

        // Deletion with file pending semantics, which requires waiting or moving
        // files to get them removed (from here).
        const file_dispo: w.FILE.DISPOSITION.INFORMATION = .{
            .DeleteFile = w.TRUE,
        };

        while (true) switch (w.ntdll.NtSetInformationFile(
            tmp_handle,
            &io_status_block,
            &file_dispo,
            @sizeOf(w.FILE.DISPOSITION.INFORMATION),
            .Disposition,
        )) {
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            else => |rc| {
                syscall.finish();
                break :rc rc;
            },
        };
    };
    switch (rc) {
        .SUCCESS => {},
        .DIRECTORY_NOT_EMPTY => return error.DirNotEmpty,
        .INVALID_PARAMETER => |err| return w.statusBug(err),
        .CANNOT_DELETE => return error.AccessDenied,
        .MEDIA_WRITE_PROTECTED => return error.AccessDenied,
        .ACCESS_DENIED => return error.AccessDenied,
        else => return w.unexpectedStatus(rc),
    }
}

fn dirDeleteDirWasi(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8) Dir.DeleteDirError!void {
    if (builtin.link_libc) return dirDeleteDirPosix(userdata, dir, sub_path);

    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    const syscall: Syscall = try .start();
    while (true) {
        const res = std.os.wasi.path_remove_directory(dir.handle, sub_path.ptr, sub_path.len);
        switch (res) {
            .SUCCESS => {
                syscall.finish();
                return;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ACCES => return error.AccessDenied,
                    .PERM => return error.PermissionDenied,
                    .BUSY => return error.FileBusy,
                    .FAULT => |err| return errnoBug(err),
                    .IO => return error.FileSystem,
                    .LOOP => return error.SymLinkLoop,
                    .NAMETOOLONG => return error.NameTooLong,
                    .NOENT => return error.FileNotFound,
                    .NOTDIR => return error.NotDir,
                    .NOMEM => return error.SystemResources,
                    .ROFS => return error.ReadOnlyFileSystem,
                    .NOTEMPTY => return error.DirNotEmpty,
                    .NOTCAPABLE => return error.AccessDenied,
                    .ILSEQ => return error.BadPathName,
                    .INVAL => |err| return errnoBug(err), // invalid flags, or pathname has . as last component
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn dirDeleteDirPosix(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8) Dir.DeleteDirError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.unlinkat(dir.handle, sub_path_posix, posix.AT.REMOVEDIR))) {
            .SUCCESS => {
                syscall.finish();
                return;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ACCES => return error.AccessDenied,
                    .PERM => return error.PermissionDenied,
                    .BUSY => return error.FileBusy,
                    .FAULT => |err| return errnoBug(err),
                    .IO => return error.FileSystem,
                    .ISDIR => |err| return errnoBug(err),
                    .LOOP => return error.SymLinkLoop,
                    .NAMETOOLONG => return error.NameTooLong,
                    .NOENT => return error.FileNotFound,
                    .NOTDIR => return error.NotDir,
                    .NOMEM => return error.SystemResources,
                    .ROFS => return error.ReadOnlyFileSystem,
                    .EXIST => |err| return errnoBug(err),
                    .NOTEMPTY => return error.DirNotEmpty,
                    .ILSEQ => return error.BadPathName,
                    .INVAL => |err| return errnoBug(err), // invalid flags, or pathname has . as last component
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

const dirRename = switch (native_os) {
    .windows => dirRenameWindows,
    .wasi => dirRenameWasi,
    else => dirRenamePosix,
};

fn dirRenameWindows(
    userdata: ?*anyopaque,
    old_dir: Dir,
    old_sub_path: []const u8,
    new_dir: Dir,
    new_sub_path: []const u8,
) Dir.RenameError!void {
    const w = windows;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    const old_path_w_buf = try windows.sliceToPrefixedFileW(old_dir.handle, old_sub_path);
    const old_path_w = old_path_w_buf.span();
    const new_path_w_buf = try windows.sliceToPrefixedFileW(new_dir.handle, new_sub_path);
    const new_path_w = new_path_w_buf.span();
    const replace_if_exists = true;

    const src_fd = src_fd: {
        const syscall: Syscall = try .start();
        while (true) {
            if (w.OpenFile(old_path_w, .{
                .dir = old_dir.handle,
                .access_mask = .{
                    .GENERIC = .{ .WRITE = true },
                    .STANDARD = .{
                        .RIGHTS = .{ .DELETE = true },
                        .SYNCHRONIZE = true,
                    },
                },
                .creation = .OPEN,
                .filter = .any, // This function is supposed to rename both files and directories.
                .follow_symlinks = false,
            })) |handle| {
                syscall.finish();
                break :src_fd handle;
            } else |err| switch (err) {
                error.WouldBlock => unreachable, // Not possible without `.share_access_nonblocking = true`.
                error.OperationCanceled => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| return e,
            }
        }
    };
    defer w.CloseHandle(src_fd);

    var rc: w.NTSTATUS = undefined;
    // FileRenameInformationEx has varying levels of support:
    // - FILE_RENAME_INFORMATION_EX requires >= win10_rs1
    //   (INVALID_INFO_CLASS is returned if not supported)
    // - Requires the NTFS filesystem
    //   (on filesystems like FAT32, INVALID_PARAMETER is returned)
    // - FILE_RENAME_POSIX_SEMANTICS requires >= win10_rs1
    // - FILE_RENAME_IGNORE_READONLY_ATTRIBUTE requires >= win10_rs5
    //   (NOT_SUPPORTED is returned if a flag is unsupported)
    //
    // The strategy here is just to try using FileRenameInformationEx and fall back to
    // FileRenameInformation if the return value lets us know that some aspect of it is not supported.
    const need_fallback = need_fallback: {
        const rename_info: w.FILE.RENAME_INFORMATION = .init(.{
            .Flags = .{
                .REPLACE_IF_EXISTS = replace_if_exists,
                .POSIX_SEMANTICS = true,
                .IGNORE_READONLY_ATTRIBUTE = true,
            },
            .RootDirectory = if (std.fs.path.isAbsoluteWindowsWtf16(new_path_w)) null else new_dir.handle,
            .FileName = new_path_w,
        });
        var io_status_block: w.IO_STATUS_BLOCK = undefined;
        const rename_info_buf = rename_info.toBuffer();
        rc = w.ntdll.NtSetInformationFile(
            src_fd,
            &io_status_block,
            rename_info_buf.ptr,
            @intCast(rename_info_buf.len),
            .RenameEx,
        );
        switch (rc) {
            .SUCCESS => return,
            // The filesystem does not support FileDispositionInformationEx
            .INVALID_PARAMETER,
            // The operating system does not support FileDispositionInformationEx
            .INVALID_INFO_CLASS,
            // The operating system does not support one of the flags
            .NOT_SUPPORTED,
            => break :need_fallback true,
            // For all other statuses, fall down to the switch below to handle them.
            else => break :need_fallback false,
        }
    };

    if (need_fallback) {
        const rename_info: w.FILE.RENAME_INFORMATION = .init(.{
            .Flags = .{ .REPLACE_IF_EXISTS = replace_if_exists },
            .RootDirectory = if (std.fs.path.isAbsoluteWindowsWtf16(new_path_w)) null else new_dir.handle,
            .FileName = new_path_w,
        });
        var io_status_block: w.IO_STATUS_BLOCK = undefined;
        const rename_info_buf = rename_info.toBuffer();
        rc = w.ntdll.NtSetInformationFile(
            src_fd,
            &io_status_block,
            rename_info_buf.ptr,
            @intCast(rename_info_buf.len),
            .Rename,
        );
    }

    switch (rc) {
        .SUCCESS => {},
        .INVALID_HANDLE => |err| return w.statusBug(err),
        .INVALID_PARAMETER => |err| return w.statusBug(err),
        .OBJECT_PATH_SYNTAX_BAD => |err| return w.statusBug(err),
        .ACCESS_DENIED => return error.AccessDenied,
        .OBJECT_NAME_NOT_FOUND => return error.FileNotFound,
        .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
        .NOT_SAME_DEVICE => return error.RenameAcrossMountPoints,
        .OBJECT_NAME_COLLISION => return error.PathAlreadyExists,
        .DIRECTORY_NOT_EMPTY => return error.PathAlreadyExists,
        .FILE_IS_A_DIRECTORY => return error.IsDir,
        .NOT_A_DIRECTORY => return error.NotDir,
        else => return w.unexpectedStatus(rc),
    }
}

fn dirRenameWasi(
    userdata: ?*anyopaque,
    old_dir: Dir,
    old_sub_path: []const u8,
    new_dir: Dir,
    new_sub_path: []const u8,
) Dir.RenameError!void {
    if (builtin.link_libc) return dirRenamePosix(userdata, old_dir, old_sub_path, new_dir, new_sub_path);

    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    const syscall: Syscall = try .start();
    while (true) {
        switch (std.os.wasi.path_rename(old_dir.handle, old_sub_path.ptr, old_sub_path.len, new_dir.handle, new_sub_path.ptr, new_sub_path.len)) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ACCES => return error.AccessDenied,
                    .PERM => return error.PermissionDenied,
                    .BUSY => return error.FileBusy,
                    .DQUOT => return error.DiskQuota,
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err),
                    .ISDIR => return error.IsDir,
                    .LOOP => return error.SymLinkLoop,
                    .MLINK => return error.LinkQuotaExceeded,
                    .NAMETOOLONG => return error.NameTooLong,
                    .NOENT => return error.FileNotFound,
                    .NOTDIR => return error.NotDir,
                    .NOMEM => return error.SystemResources,
                    .NOSPC => return error.NoSpaceLeft,
                    .EXIST => return error.PathAlreadyExists,
                    .NOTEMPTY => return error.PathAlreadyExists,
                    .ROFS => return error.ReadOnlyFileSystem,
                    .XDEV => return error.RenameAcrossMountPoints,
                    .NOTCAPABLE => return error.AccessDenied,
                    .ILSEQ => return error.BadPathName,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn dirRenamePosix(
    userdata: ?*anyopaque,
    old_dir: Dir,
    old_sub_path: []const u8,
    new_dir: Dir,
    new_sub_path: []const u8,
) Dir.RenameError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var old_path_buffer: [posix.PATH_MAX]u8 = undefined;
    var new_path_buffer: [posix.PATH_MAX]u8 = undefined;

    const old_sub_path_posix = try pathToPosix(old_sub_path, &old_path_buffer);
    const new_sub_path_posix = try pathToPosix(new_sub_path, &new_path_buffer);

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.renameat(old_dir.handle, old_sub_path_posix, new_dir.handle, new_sub_path_posix))) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ACCES => return error.AccessDenied,
                    .PERM => return error.PermissionDenied,
                    .BUSY => return error.FileBusy,
                    .DQUOT => return error.DiskQuota,
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err),
                    .ISDIR => return error.IsDir,
                    .LOOP => return error.SymLinkLoop,
                    .MLINK => return error.LinkQuotaExceeded,
                    .NAMETOOLONG => return error.NameTooLong,
                    .NOENT => return error.FileNotFound,
                    .NOTDIR => return error.NotDir,
                    .NOMEM => return error.SystemResources,
                    .NOSPC => return error.NoSpaceLeft,
                    .EXIST => return error.PathAlreadyExists,
                    .NOTEMPTY => return error.PathAlreadyExists,
                    .ROFS => return error.ReadOnlyFileSystem,
                    .XDEV => return error.RenameAcrossMountPoints,
                    .ILSEQ => return error.BadPathName,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

const dirSymLink = switch (native_os) {
    .windows => dirSymLinkWindows,
    .wasi => dirSymLinkWasi,
    else => dirSymLinkPosix,
};

fn dirSymLinkWindows(
    userdata: ?*anyopaque,
    dir: Dir,
    target_path: []const u8,
    sym_link_path: []const u8,
    flags: Dir.SymLinkFlags,
) Dir.SymLinkError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const w = windows;

    // Target path does not use sliceToPrefixedFileW because certain paths
    // are handled differently when creating a symlink than they would be
    // when converting to an NT namespaced path. CreateSymbolicLink in
    // symLinkW will handle the necessary conversion.
    var target_path_w: w.PathSpace = undefined;
    target_path_w.len = try w.wtf8ToWtf16Le(&target_path_w.data, target_path);
    target_path_w.data[target_path_w.len] = 0;
    // However, we need to canonicalize any path separators to `\`, since if
    // the target path is relative, then it must use `\` as the path separator.
    std.mem.replaceScalar(
        u16,
        target_path_w.data[0..target_path_w.len],
        std.mem.nativeToLittle(u16, '/'),
        std.mem.nativeToLittle(u16, '\\'),
    );

    const sym_link_path_w = try w.sliceToPrefixedFileW(dir.handle, sym_link_path);

    const SYMLINK_DATA = extern struct {
        ReparseTag: w.IO_REPARSE_TAG,
        ReparseDataLength: w.USHORT,
        Reserved: w.USHORT,
        SubstituteNameOffset: w.USHORT,
        SubstituteNameLength: w.USHORT,
        PrintNameOffset: w.USHORT,
        PrintNameLength: w.USHORT,
        Flags: w.ULONG,
    };

    const symlink_handle = handle: {
        const syscall: Syscall = try .start();
        while (true) {
            if (w.OpenFile(sym_link_path_w.span(), .{
                .access_mask = .{
                    .GENERIC = .{ .READ = true, .WRITE = true },
                    .STANDARD = .{ .SYNCHRONIZE = true },
                },
                .dir = dir.handle,
                .creation = .CREATE,
                .filter = if (flags.is_directory) .dir_only else .non_directory_only,
            })) |handle| {
                syscall.finish();
                break :handle handle;
            } else |err| switch (err) {
                error.IsDir => return syscall.fail(error.PathAlreadyExists),
                error.NotDir => return syscall.fail(error.Unexpected),
                error.WouldBlock => return syscall.fail(error.Unexpected),
                error.PipeBusy => return syscall.fail(error.Unexpected),
                error.NoDevice => return syscall.fail(error.Unexpected),
                error.AntivirusInterference => return syscall.fail(error.Unexpected),
                error.OperationCanceled => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| return e,
            }
        }
    };
    defer w.CloseHandle(symlink_handle);

    // Relevant portions of the documentation:
    // > Relative links are specified using the following conventions:
    // > - Root relative—for example, "\Windows\System32" resolves to "current drive:\Windows\System32".
    // > - Current working directory–relative—for example, if the current working directory is
    // >   C:\Windows\System32, "C:File.txt" resolves to "C:\Windows\System32\File.txt".
    // > Note: If you specify a current working directory–relative link, it is created as an absolute
    // > link, due to the way the current working directory is processed based on the user and the thread.
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createsymboliclinkw
    var is_target_absolute = false;
    const final_target_path = target_path: {
        if (w.hasCommonNtPrefix(u16, target_path_w.span())) {
            // Already an NT path, no need to do anything to it
            break :target_path target_path_w.span();
        } else {
            switch (w.getWin32PathType(u16, target_path_w.span())) {
                // Rooted paths need to avoid getting put through wToPrefixedFileW
                // (and they are treated as relative in this context)
                // Note: It seems that rooted paths in symbolic links are relative to
                //       the drive that the symbolic exists on, not to the CWD's drive.
                //       So, if the symlink is on C:\ and the CWD is on D:\,
                //       it will still resolve the path relative to the root of
                //       the C:\ drive.
                .rooted => break :target_path target_path_w.span(),
                // Keep relative paths relative, but anything else needs to get NT-prefixed.
                else => if (!std.fs.path.isAbsoluteWindowsWtf16(target_path_w.span()))
                    break :target_path target_path_w.span(),
            }
        }
        var prefixed_target_path = try w.wToPrefixedFileW(dir.handle, target_path_w.span());
        // We do this after prefixing to ensure that drive-relative paths are treated as absolute
        is_target_absolute = std.fs.path.isAbsoluteWindowsWtf16(prefixed_target_path.span());
        break :target_path prefixed_target_path.span();
    };

    // prepare reparse data buffer
    var buffer: [w.MAXIMUM_REPARSE_DATA_BUFFER_SIZE]u8 = undefined;
    const buf_len = @sizeOf(SYMLINK_DATA) + final_target_path.len * 4;
    const header_len = @sizeOf(w.ULONG) + @sizeOf(w.USHORT) * 2;
    const target_is_absolute = std.fs.path.isAbsoluteWindowsWtf16(final_target_path);
    const symlink_data = SYMLINK_DATA{
        .ReparseTag = .SYMLINK,
        .ReparseDataLength = @intCast(buf_len - header_len),
        .Reserved = 0,
        .SubstituteNameOffset = @intCast(final_target_path.len * 2),
        .SubstituteNameLength = @intCast(final_target_path.len * 2),
        .PrintNameOffset = 0,
        .PrintNameLength = @intCast(final_target_path.len * 2),
        .Flags = if (!target_is_absolute) w.SYMLINK_FLAG_RELATIVE else 0,
    };

    @memcpy(buffer[0..@sizeOf(SYMLINK_DATA)], std.mem.asBytes(&symlink_data));
    @memcpy(buffer[@sizeOf(SYMLINK_DATA)..][0 .. final_target_path.len * 2], @as([*]const u8, @ptrCast(final_target_path)));
    const paths_start = @sizeOf(SYMLINK_DATA) + final_target_path.len * 2;
    @memcpy(buffer[paths_start..][0 .. final_target_path.len * 2], @as([*]const u8, @ptrCast(final_target_path)));
    const rc = w.DeviceIoControl(symlink_handle, w.FSCTL.SET_REPARSE_POINT, .{ .in = buffer[0..buf_len] });
    switch (rc) {
        .SUCCESS => {},
        .PRIVILEGE_NOT_HELD => return error.PermissionDenied,
        .ACCESS_DENIED => return error.AccessDenied,
        .INVALID_DEVICE_REQUEST => return error.FileSystem,
        else => return windows.unexpectedStatus(rc),
    }
}

fn dirSymLinkWasi(
    userdata: ?*anyopaque,
    dir: Dir,
    target_path: []const u8,
    sym_link_path: []const u8,
    flags: Dir.SymLinkFlags,
) Dir.SymLinkError!void {
    if (builtin.link_libc) return dirSymLinkPosix(userdata, dir, target_path, sym_link_path, flags);

    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    const syscall: Syscall = try .start();
    while (true) {
        switch (std.os.wasi.path_symlink(target_path.ptr, target_path.len, dir.handle, sym_link_path.ptr, sym_link_path.len)) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err),
                    .BADF => |err| return errnoBug(err),
                    .ACCES => return error.AccessDenied,
                    .PERM => return error.PermissionDenied,
                    .DQUOT => return error.DiskQuota,
                    .EXIST => return error.PathAlreadyExists,
                    .IO => return error.FileSystem,
                    .LOOP => return error.SymLinkLoop,
                    .NAMETOOLONG => return error.NameTooLong,
                    .NOENT => return error.FileNotFound,
                    .NOTDIR => return error.NotDir,
                    .NOMEM => return error.SystemResources,
                    .NOSPC => return error.NoSpaceLeft,
                    .ROFS => return error.ReadOnlyFileSystem,
                    .NOTCAPABLE => return error.AccessDenied,
                    .ILSEQ => return error.BadPathName,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn dirSymLinkPosix(
    userdata: ?*anyopaque,
    dir: Dir,
    target_path: []const u8,
    sym_link_path: []const u8,
    flags: Dir.SymLinkFlags,
) Dir.SymLinkError!void {
    _ = flags;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var target_path_buffer: [posix.PATH_MAX]u8 = undefined;
    var sym_link_path_buffer: [posix.PATH_MAX]u8 = undefined;

    const target_path_posix = try pathToPosix(target_path, &target_path_buffer);
    const sym_link_path_posix = try pathToPosix(sym_link_path, &sym_link_path_buffer);

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.symlinkat(target_path_posix, dir.handle, sym_link_path_posix))) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err),
                    .ACCES => return error.AccessDenied,
                    .PERM => return error.PermissionDenied,
                    .DQUOT => return error.DiskQuota,
                    .EXIST => return error.PathAlreadyExists,
                    .IO => return error.FileSystem,
                    .LOOP => return error.SymLinkLoop,
                    .NAMETOOLONG => return error.NameTooLong,
                    .NOENT => return error.FileNotFound,
                    .NOTDIR => return error.NotDir,
                    .NOMEM => return error.SystemResources,
                    .NOSPC => return error.NoSpaceLeft,
                    .ROFS => return error.ReadOnlyFileSystem,
                    .ILSEQ => return error.BadPathName,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

const dirReadLink = switch (native_os) {
    .windows => dirReadLinkWindows,
    .wasi => dirReadLinkWasi,
    else => dirReadLinkPosix,
};

fn dirReadLinkWindows(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, buffer: []u8) Dir.ReadLinkError!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const w = windows;

    var sub_path_w_buf = try windows.sliceToPrefixedFileW(dir.handle, sub_path);

    const syscall: Syscall = try .start();
    const result_w = while (true) {
        if (w.ReadLink(dir.handle, sub_path_w_buf.span(), &sub_path_w_buf.data)) |res| {
            syscall.finish();
            break res;
        } else |err| switch (err) {
            error.OperationCanceled => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| return syscall.fail(e),
        }
    };

    const len = std.unicode.calcWtf8Len(result_w);
    if (len > buffer.len) return error.NameTooLong;

    return std.unicode.wtf16LeToWtf8(buffer, result_w);
}

fn dirReadLinkWasi(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, buffer: []u8) Dir.ReadLinkError!usize {
    if (builtin.link_libc) return dirReadLinkPosix(userdata, dir, sub_path, buffer);

    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var n: usize = undefined;
    const syscall: Syscall = try .start();
    while (true) {
        switch (std.os.wasi.path_readlink(dir.handle, sub_path.ptr, sub_path.len, buffer.ptr, buffer.len, &n)) {
            .SUCCESS => {
                syscall.finish();
                return n;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ACCES => return error.AccessDenied,
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => return error.NotLink,
                    .IO => return error.FileSystem,
                    .LOOP => return error.SymLinkLoop,
                    .NAMETOOLONG => return error.NameTooLong,
                    .NOENT => return error.FileNotFound,
                    .NOMEM => return error.SystemResources,
                    .NOTDIR => return error.NotDir,
                    .NOTCAPABLE => return error.AccessDenied,
                    .ILSEQ => return error.BadPathName,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn dirReadLinkPosix(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, buffer: []u8) Dir.ReadLinkError!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var sub_path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &sub_path_buffer);

    const syscall: Syscall = try .start();
    while (true) {
        const rc = posix.system.readlinkat(dir.handle, sub_path_posix, buffer.ptr, buffer.len);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                syscall.finish();
                const len: usize = @bitCast(rc);
                return len;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ACCES => return error.AccessDenied,
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => return error.NotLink,
                    .IO => return error.FileSystem,
                    .LOOP => return error.SymLinkLoop,
                    .NAMETOOLONG => return error.NameTooLong,
                    .NOENT => return error.FileNotFound,
                    .NOMEM => return error.SystemResources,
                    .NOTDIR => return error.NotDir,
                    .ILSEQ => return error.BadPathName,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

const dirSetPermissions = switch (native_os) {
    .windows => dirSetPermissionsWindows,
    else => dirSetPermissionsPosix,
};

fn dirSetPermissionsWindows(userdata: ?*anyopaque, dir: Dir, permissions: Dir.Permissions) Dir.SetPermissionsError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    _ = dir;
    _ = permissions;
    @panic("TODO implement dirSetPermissionsWindows");
}

fn dirSetPermissionsPosix(userdata: ?*anyopaque, dir: Dir, permissions: Dir.Permissions) Dir.SetPermissionsError!void {
    if (@sizeOf(Dir.Permissions) == 0) return;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    return setPermissionsPosix(dir.handle, permissions.toMode());
}

fn dirSetFilePermissions(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    permissions: Dir.Permissions,
    options: Dir.SetFilePermissionsOptions,
) Dir.SetFilePermissionsError!void {
    if (@sizeOf(Dir.Permissions) == 0) return;
    if (is_windows) @panic("TODO implement dirSetFilePermissions windows");
    const t: *Threaded = @ptrCast(@alignCast(userdata));

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    const mode = permissions.toMode();
    const flags: u32 = if (!options.follow_symlinks) posix.AT.SYMLINK_NOFOLLOW else 0;

    return posixFchmodat(t, dir.handle, sub_path_posix, mode, flags);
}

fn posixFchmodat(
    t: *Threaded,
    dir_fd: posix.fd_t,
    path: [*:0]const u8,
    mode: posix.mode_t,
    flags: u32,
) Dir.SetFilePermissionsError!void {
    // No special handling for linux is needed if we can use the libc fallback
    // or `flags` is empty. Glibc only added the fallback in 2.32.
    if (have_fchmodat_flags or flags == 0) {
        const syscall: Syscall = try .start();
        while (true) {
            const rc = if (have_fchmodat_flags or builtin.link_libc)
                posix.system.fchmodat(dir_fd, path, mode, flags)
            else
                posix.system.fchmodat(dir_fd, path, mode);
            switch (posix.errno(rc)) {
                .SUCCESS => return syscall.finish(),
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .BADF => |err| return errnoBug(err),
                        .FAULT => |err| return errnoBug(err),
                        .INVAL => |err| return errnoBug(err),
                        .ACCES => return error.AccessDenied,
                        .IO => return error.InputOutput,
                        .LOOP => return error.SymLinkLoop,
                        .MFILE => return error.ProcessFdQuotaExceeded,
                        .NAMETOOLONG => return error.NameTooLong,
                        .NFILE => return error.SystemFdQuotaExceeded,
                        .NOENT => return error.FileNotFound,
                        .NOTDIR => return error.FileNotFound,
                        .NOMEM => return error.SystemResources,
                        .OPNOTSUPP => return error.OperationUnsupported,
                        .PERM => return error.PermissionDenied,
                        .ROFS => return error.ReadOnlyFileSystem,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    }

    if (@atomicLoad(UseFchmodat2, &t.use_fchmodat2, .monotonic) == .disabled)
        return fchmodatFallback(dir_fd, path, mode);

    comptime assert(native_os == .linux);

    const syscall: Syscall = try .start();
    while (true) {
        switch (std.os.linux.errno(std.os.linux.fchmodat2(dir_fd, path, mode, flags))) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .BADF => |err| return errnoBug(err),
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err),
                    .ACCES => return error.AccessDenied,
                    .IO => return error.InputOutput,
                    .LOOP => return error.SymLinkLoop,
                    .NOENT => return error.FileNotFound,
                    .NOMEM => return error.SystemResources,
                    .NOTDIR => return error.FileNotFound,
                    .OPNOTSUPP => return error.OperationUnsupported,
                    .PERM => return error.PermissionDenied,
                    .ROFS => return error.ReadOnlyFileSystem,
                    .NOSYS => {
                        @atomicStore(UseFchmodat2, &t.use_fchmodat2, .disabled, .monotonic);
                        return fchmodatFallback(dir_fd, path, mode);
                    },
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn fchmodatFallback(
    dir_fd: posix.fd_t,
    path: [*:0]const u8,
    mode: posix.mode_t,
) Dir.SetFilePermissionsError!void {
    comptime assert(native_os == .linux);
    const use_c = std.c.versionCheck(if (builtin.abi.isAndroid())
        .{ .major = 30, .minor = 0, .patch = 0 }
    else
        .{ .major = 2, .minor = 28, .patch = 0 });
    const sys = if (use_c) std.c else std.os.linux;

    // Fallback to changing permissions using procfs:
    //
    // 1. Open `path` as a `PATH` descriptor.
    // 2. Stat the fd and check if it isn't a symbolic link.
    // 3. Generate the procfs reference to the fd via `/proc/self/fd/{fd}`.
    // 4. Pass the procfs path to `chmod` with the `mode`.
    const path_fd: posix.fd_t = fd: {
        const syscall: Syscall = try .start();
        while (true) {
            const rc = posix.system.openat(dir_fd, path, .{
                .PATH = true,
                .NOFOLLOW = true,
                .CLOEXEC = true,
            }, @as(posix.mode_t, 0));
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    syscall.finish();
                    break :fd @intCast(rc);
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .FAULT => |err| return errnoBug(err),
                        .INVAL => |err| return errnoBug(err),
                        .ACCES => return error.AccessDenied,
                        .PERM => return error.PermissionDenied,
                        .LOOP => return error.SymLinkLoop,
                        .MFILE => return error.ProcessFdQuotaExceeded,
                        .NAMETOOLONG => return error.NameTooLong,
                        .NFILE => return error.SystemFdQuotaExceeded,
                        .NOENT => return error.FileNotFound,
                        .NOMEM => return error.SystemResources,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    };
    defer posix.close(path_fd);

    const path_mode = mode: {
        const syscall: Syscall = try .start();
        while (true) {
            var statx = std.mem.zeroes(std.os.linux.Statx);
            switch (sys.errno(sys.statx(path_fd, "", posix.AT.EMPTY_PATH, .{ .TYPE = true }, &statx))) {
                .SUCCESS => {
                    syscall.finish();
                    if (!statx.mask.TYPE) return error.Unexpected;
                    break :mode statx.mode;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .ACCES => return error.AccessDenied,
                        .LOOP => return error.SymLinkLoop,
                        .NOMEM => return error.SystemResources,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    };

    // Even though we only wanted TYPE, the kernel can still fill in the additional bits.
    if ((path_mode & posix.S.IFMT) == posix.S.IFLNK)
        return error.OperationUnsupported;

    var procfs_buf: ["/proc/self/fd/-2147483648\x00".len]u8 = undefined;
    const proc_path = std.fmt.bufPrintSentinel(&procfs_buf, "/proc/self/fd/{d}", .{path_fd}, 0) catch unreachable;
    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.chmod(proc_path, mode))) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .NOENT => return error.OperationUnsupported, // procfs not mounted.
                    .BADF => |err| return errnoBug(err),
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err),
                    .ACCES => return error.AccessDenied,
                    .IO => return error.InputOutput,
                    .LOOP => return error.SymLinkLoop,
                    .NOMEM => return error.SystemResources,
                    .NOTDIR => return error.FileNotFound,
                    .PERM => return error.PermissionDenied,
                    .ROFS => return error.ReadOnlyFileSystem,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

const dirSetOwner = switch (native_os) {
    .windows => dirSetOwnerUnsupported,
    else => dirSetOwnerPosix,
};

fn dirSetOwnerUnsupported(userdata: ?*anyopaque, dir: Dir, owner: ?File.Uid, group: ?File.Gid) Dir.SetOwnerError!void {
    _ = userdata;
    _ = dir;
    _ = owner;
    _ = group;
    return error.Unexpected;
}

fn dirSetOwnerPosix(userdata: ?*anyopaque, dir: Dir, owner: ?File.Uid, group: ?File.Gid) Dir.SetOwnerError!void {
    if (!have_fchown) return error.Unexpected; // Unsupported OS, don't call this function.
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const uid = owner orelse ~@as(posix.uid_t, 0);
    const gid = group orelse ~@as(posix.gid_t, 0);
    return posixFchown(dir.handle, uid, gid);
}

fn posixFchown(fd: posix.fd_t, uid: posix.uid_t, gid: posix.gid_t) File.SetOwnerError!void {
    comptime assert(have_fchown);
    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.fchown(fd, uid, gid))) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .BADF => |err| return errnoBug(err), // likely fd refers to directory opened without `Dir.OpenOptions.iterate`
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err),
                    .ACCES => return error.AccessDenied,
                    .IO => return error.InputOutput,
                    .LOOP => return error.SymLinkLoop,
                    .NOENT => return error.FileNotFound,
                    .NOMEM => return error.SystemResources,
                    .NOTDIR => return error.FileNotFound,
                    .PERM => return error.PermissionDenied,
                    .ROFS => return error.ReadOnlyFileSystem,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn dirSetFileOwner(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    owner: ?File.Uid,
    group: ?File.Gid,
    options: Dir.SetFileOwnerOptions,
) Dir.SetFileOwnerError!void {
    if (!have_fchown) return error.Unexpected; // Unsupported OS, don't call this function.
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    _ = dir;
    _ = sub_path_posix;
    _ = owner;
    _ = group;
    _ = options;
    @panic("TODO implement dirSetFileOwner");
}

const fileSync = switch (native_os) {
    .windows => fileSyncWindows,
    .wasi => fileSyncWasi,
    else => fileSyncPosix,
};

fn fileSyncWindows(userdata: ?*anyopaque, file: File) File.SyncError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    const syscall: Syscall = try .start();
    while (true) {
        if (windows.kernel32.FlushFileBuffers(file.handle) != 0) {
            return syscall.finish();
        }
        switch (windows.GetLastError()) {
            .SUCCESS => unreachable, // `FlushFileBuffers` returned nonzero
            .INVALID_HANDLE => unreachable,
            .ACCESS_DENIED => return syscall.fail(error.AccessDenied), // a sync was performed but the system couldn't update the access time
            .UNEXP_NET_ERR => return syscall.fail(error.InputOutput),
            .OPERATION_ABORTED => {
                try syscall.checkCancel();
                continue;
            },
            else => |err| {
                syscall.finish();
                return windows.unexpectedError(err);
            },
        }
    }
}

fn fileSyncPosix(userdata: ?*anyopaque, file: File) File.SyncError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.fsync(file.handle))) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .BADF => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err),
                    .ROFS => |err| return errnoBug(err),
                    .IO => return error.InputOutput,
                    .NOSPC => return error.NoSpaceLeft,
                    .DQUOT => return error.DiskQuota,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn fileSyncWasi(userdata: ?*anyopaque, file: File) File.SyncError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const syscall: Syscall = try .start();
    while (true) {
        switch (std.os.wasi.fd_sync(file.handle)) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .BADF => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err),
                    .ROFS => |err| return errnoBug(err),
                    .IO => return error.InputOutput,
                    .NOSPC => return error.NoSpaceLeft,
                    .DQUOT => return error.DiskQuota,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn fileIsTty(userdata: ?*anyopaque, file: File) Io.Cancelable!bool {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    return isTty(file);
}

fn isTty(file: File) Io.Cancelable!bool {
    if (is_windows) {
        if (try isCygwinPty(file)) return true;
        var out: windows.DWORD = undefined;
        const syscall: Syscall = try .start();
        while (windows.kernel32.GetConsoleMode(file.handle, &out) == 0) {
            switch (windows.GetLastError()) {
                .OPERATION_ABORTED => {
                    try syscall.checkCancel();
                    continue;
                },
                else => {
                    syscall.finish();
                    return false;
                },
            }
        }
        syscall.finish();
        return true;
    }

    if (builtin.link_libc) {
        const syscall: Syscall = try .start();
        while (true) {
            const rc = posix.system.isatty(file.handle);
            switch (posix.errno(rc - 1)) {
                .SUCCESS => {
                    syscall.finish();
                    return true;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => {
                    syscall.finish();
                    return false;
                },
            }
        }
    }

    if (native_os == .wasi) {
        var statbuf: std.os.wasi.fdstat_t = undefined;
        const err = std.os.wasi.fd_fdstat_get(file.handle, &statbuf);
        if (err != .SUCCESS)
            return false;

        // A tty is a character device that we can't seek or tell on.
        if (statbuf.fs_filetype != .CHARACTER_DEVICE)
            return false;
        if (statbuf.fs_rights_base.FD_SEEK or statbuf.fs_rights_base.FD_TELL)
            return false;

        return true;
    }

    if (native_os == .linux) {
        const linux = std.os.linux;
        const syscall: Syscall = try .start();
        while (true) {
            var wsz: posix.winsize = undefined;
            const fd: usize = @bitCast(@as(isize, file.handle));
            const rc = linux.syscall3(.ioctl, fd, linux.T.IOCGWINSZ, @intFromPtr(&wsz));
            switch (linux.errno(rc)) {
                .SUCCESS => {
                    syscall.finish();
                    return true;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => {
                    syscall.finish();
                    return false;
                },
            }
        }
    }

    @compileError("unimplemented");
}

fn fileEnableAnsiEscapeCodes(userdata: ?*anyopaque, file: File) File.EnableAnsiEscapeCodesError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (!is_windows) {
        if (try supportsAnsiEscapeCodes(file)) return;
        return error.NotTerminalDevice;
    }

    // For Windows Terminal, VT Sequences processing is enabled by default.
    var original_console_mode: windows.DWORD = 0;

    {
        const syscall: Syscall = try .start();
        while (windows.kernel32.GetConsoleMode(file.handle, &original_console_mode) == 0) {
            switch (windows.GetLastError()) {
                .OPERATION_ABORTED => {
                    try syscall.checkCancel();
                    continue;
                },
                else => {
                    syscall.finish();
                    if (try isCygwinPty(file)) return;
                    return error.NotTerminalDevice;
                },
            }
        }
        syscall.finish();
    }

    if (original_console_mode & windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0) return;

    // For Windows Console, VT Sequences processing support was added in Windows 10 build 14361, but disabled by default.
    // https://devblogs.microsoft.com/commandline/tmux-support-arrives-for-bash-on-ubuntu-on-windows/
    //
    // Note: In Microsoft's example for enabling virtual terminal processing, it
    // shows attempting to enable `DISABLE_NEWLINE_AUTO_RETURN` as well:
    // https://learn.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences#example-of-enabling-virtual-terminal-processing
    // This is avoided because in the old Windows Console, that flag causes \n (as opposed to \r\n)
    // to behave unexpectedly (the cursor moves down 1 row but remains on the same column).
    // Additionally, the default console mode in Windows Terminal does not have
    // `DISABLE_NEWLINE_AUTO_RETURN` set, so by only enabling `ENABLE_VIRTUAL_TERMINAL_PROCESSING`
    // we end up matching the mode of Windows Terminal.
    const requested_console_modes = windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    const console_mode = original_console_mode | requested_console_modes;

    {
        const syscall: Syscall = try .start();
        while (windows.kernel32.SetConsoleMode(file.handle, console_mode) == 0) {
            switch (windows.GetLastError()) {
                .OPERATION_ABORTED => {
                    try syscall.checkCancel();
                    continue;
                },
                else => {
                    syscall.finish();
                    if (try isCygwinPty(file)) return;
                    return error.NotTerminalDevice;
                },
            }
        }
        syscall.finish();
    }
}

fn fileSupportsAnsiEscapeCodes(userdata: ?*anyopaque, file: File) Io.Cancelable!bool {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    return supportsAnsiEscapeCodes(file);
}

fn supportsAnsiEscapeCodes(file: File) Io.Cancelable!bool {
    if (is_windows) {
        var console_mode: windows.DWORD = 0;

        const syscall: Syscall = try .start();
        while (windows.kernel32.GetConsoleMode(file.handle, &console_mode) == 0) {
            switch (windows.GetLastError()) {
                .OPERATION_ABORTED => {
                    try syscall.checkCancel();
                    continue;
                },
                else => {
                    syscall.finish();
                    break;
                },
            }
        } else {
            syscall.finish();
            if (console_mode & windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0) {
                return true;
            }
        }

        return isCygwinPty(file);
    }

    if (native_os == .wasi) {
        // WASI sanitizes stdout when fd is a tty so ANSI escape codes will not
        // be interpreted as actual cursor commands, and stderr is always
        // sanitized.
        return false;
    }

    if (try isTty(file)) return true;

    return false;
}

fn isCygwinPty(file: File) Io.Cancelable!bool {
    if (!is_windows) return false;

    const handle = file.handle;

    // If this is a MSYS2/cygwin pty, then it will be a named pipe with a name in one of these formats:
    //   msys-[...]-ptyN-[...]
    //   cygwin-[...]-ptyN-[...]
    //
    // Example: msys-1888ae32e00d56aa-pty0-to-master

    // First, just check that the handle is a named pipe.
    // This allows us to avoid the more costly NtQueryInformationFile call
    // for handles that aren't named pipes.
    {
        var io_status: windows.IO_STATUS_BLOCK = undefined;
        var device_info: windows.FILE.FS_DEVICE_INFORMATION = undefined;
        const syscall: Syscall = try .start();
        while (true) switch (windows.ntdll.NtQueryVolumeInformationFile(
            handle,
            &io_status,
            &device_info,
            @sizeOf(windows.FILE.FS_DEVICE_INFORMATION),
            .Device,
        )) {
            .SUCCESS => break syscall.finish(),
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            else => {
                syscall.finish();
                return false;
            },
        };
        if (device_info.DeviceType.FileDevice != .NAMED_PIPE) return false;
    }

    const name_bytes_offset = @offsetOf(windows.FILE.NAME_INFORMATION, "FileName");
    // `NAME_MAX` UTF-16 code units (2 bytes each)
    // This buffer may not be long enough to handle *all* possible paths
    // (PATH_MAX_WIDE would be necessary for that), but because we only care
    // about certain paths and we know they must be within a reasonable length,
    // we can use this smaller buffer and just return false on any error from
    // NtQueryInformationFile.
    const num_name_bytes = windows.MAX_PATH * 2;
    var name_info_bytes align(@alignOf(windows.FILE.NAME_INFORMATION)) = [_]u8{0} ** (name_bytes_offset + num_name_bytes);

    var io_status_block: windows.IO_STATUS_BLOCK = undefined;
    const syscall: Syscall = try .start();
    while (true) switch (windows.ntdll.NtQueryInformationFile(
        handle,
        &io_status_block,
        &name_info_bytes,
        @intCast(name_info_bytes.len),
        .Name,
    )) {
        .SUCCESS => break syscall.finish(),
        .CANCELLED => {
            try syscall.checkCancel();
            continue;
        },
        .INVALID_PARAMETER => unreachable,
        else => {
            syscall.finish();
            return false;
        },
    };

    const name_info: *const windows.FILE_NAME_INFO = @ptrCast(&name_info_bytes);
    const name_bytes = name_info_bytes[name_bytes_offset .. name_bytes_offset + name_info.FileNameLength];
    const name_wide = std.mem.bytesAsSlice(u16, name_bytes);
    // The name we get from NtQueryInformationFile will be prefixed with a '\', e.g. \msys-1888ae32e00d56aa-pty0-to-master
    return (std.mem.startsWith(u16, name_wide, &[_]u16{ '\\', 'm', 's', 'y', 's', '-' }) or
        std.mem.startsWith(u16, name_wide, &[_]u16{ '\\', 'c', 'y', 'g', 'w', 'i', 'n', '-' })) and
        std.mem.indexOf(u16, name_wide, &[_]u16{ '-', 'p', 't', 'y' }) != null;
}

fn fileSetLength(userdata: ?*anyopaque, file: File, length: u64) File.SetLengthError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    const signed_len: i64 = @bitCast(length);
    if (signed_len < 0) return error.FileTooBig; // Avoid ambiguous EINVAL errors.

    if (is_windows) {
        var io_status_block: windows.IO_STATUS_BLOCK = undefined;
        const eof_info: windows.FILE.END_OF_FILE_INFORMATION = .{
            .EndOfFile = signed_len,
        };

        const syscall: Syscall = try .start();
        while (true) switch (windows.ntdll.NtSetInformationFile(
            file.handle,
            &io_status_block,
            &eof_info,
            @sizeOf(windows.FILE.END_OF_FILE_INFORMATION),
            .EndOfFile,
        )) {
            .SUCCESS => return syscall.finish(),
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            .INVALID_HANDLE => |err| return syscall.ntstatusBug(err), // Handle not open for writing.
            .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
            .USER_MAPPED_FILE => return syscall.fail(error.AccessDenied),
            .INVALID_PARAMETER => return syscall.fail(error.FileTooBig),
            else => |status| return syscall.unexpectedNtstatus(status),
        };
    }

    if (native_os == .wasi and !builtin.link_libc) {
        const syscall: Syscall = try .start();
        while (true) {
            switch (std.os.wasi.fd_filestat_set_size(file.handle, length)) {
                .SUCCESS => return syscall.finish(),
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .FBIG => return error.FileTooBig,
                        .IO => return error.InputOutput,
                        .PERM => return error.PermissionDenied,
                        .TXTBSY => return error.FileBusy,
                        .BADF => |err| return errnoBug(err), // Handle not open for writing
                        .INVAL => return error.NonResizable,
                        .NOTCAPABLE => return error.AccessDenied,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    }

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(ftruncate_sym(file.handle, signed_len))) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .FBIG => return error.FileTooBig,
                    .IO => return error.InputOutput,
                    .PERM => return error.PermissionDenied,
                    .TXTBSY => return error.FileBusy,
                    .BADF => |err| return errnoBug(err), // Handle not open for writing.
                    .INVAL => return error.NonResizable, // This is returned for /dev/null for example.
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn fileSetOwner(userdata: ?*anyopaque, file: File, owner: ?File.Uid, group: ?File.Gid) File.SetOwnerError!void {
    if (!have_fchown) return error.Unexpected; // Unsupported OS, don't call this function.
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const uid = owner orelse ~@as(posix.uid_t, 0);
    const gid = group orelse ~@as(posix.gid_t, 0);
    return posixFchown(file.handle, uid, gid);
}

fn fileSetPermissions(userdata: ?*anyopaque, file: File, permissions: File.Permissions) File.SetPermissionsError!void {
    if (@sizeOf(File.Permissions) == 0) return;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    switch (native_os) {
        .windows => {
            var io_status_block: windows.IO_STATUS_BLOCK = undefined;
            const info: windows.FILE.BASIC_INFORMATION = .{
                .CreationTime = 0,
                .LastAccessTime = 0,
                .LastWriteTime = 0,
                .ChangeTime = 0,
                .FileAttributes = permissions.toAttributes(),
            };
            const syscall: Syscall = try .start();
            while (true) switch (windows.ntdll.NtSetInformationFile(
                file.handle,
                &io_status_block,
                &info,
                @sizeOf(windows.FILE.BASIC_INFORMATION),
                .Basic,
            )) {
                .SUCCESS => return syscall.finish(),
                .CANCELLED => {
                    try syscall.checkCancel();
                    continue;
                },
                .INVALID_HANDLE => |err| return syscall.ntstatusBug(err),
                .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
                else => |status| return syscall.unexpectedNtstatus(status),
            };
        },
        .wasi => return error.Unexpected, // Unsupported OS.
        else => return setPermissionsPosix(file.handle, permissions.toMode()),
    }
}

fn setPermissionsPosix(fd: posix.fd_t, mode: posix.mode_t) File.SetPermissionsError!void {
    comptime assert(have_fchmod);
    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.fchmod(fd, mode))) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .BADF => |err| return errnoBug(err),
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err),
                    .ACCES => return error.AccessDenied,
                    .IO => return error.InputOutput,
                    .LOOP => return error.SymLinkLoop,
                    .NOENT => return error.FileNotFound,
                    .NOMEM => return error.SystemResources,
                    .NOTDIR => return error.FileNotFound,
                    .PERM => return error.PermissionDenied,
                    .ROFS => return error.ReadOnlyFileSystem,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn dirSetTimestamps(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    options: Dir.SetTimestampsOptions,
) Dir.SetTimestampsError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (is_windows) {
        @panic("TODO implement dirSetTimestamps windows");
    }

    if (native_os == .wasi and !builtin.link_libc) {
        @panic("TODO implement dirSetTimestamps wasi");
    }

    var times_buffer: [2]posix.timespec = undefined;
    const times = if (options.modify_timestamp == .now and options.access_timestamp == .now) null else p: {
        times_buffer = .{
            setTimestampToPosix(options.access_timestamp),
            setTimestampToPosix(options.modify_timestamp),
        };
        break :p &times_buffer;
    };

    const flags: u32 = if (!options.follow_symlinks) posix.AT.SYMLINK_NOFOLLOW else 0;

    var path_buffer: [posix.PATH_MAX]u8 = undefined;
    const sub_path_posix = try pathToPosix(sub_path, &path_buffer);

    const syscall: Syscall = try .start();
    while (true) switch (posix.errno(posix.system.utimensat(dir.handle, sub_path_posix, times, flags))) {
        .SUCCESS => return syscall.finish(),
        .INTR => {
            try syscall.checkCancel();
            continue;
        },
        .BADF => |err| return syscall.errnoBug(err), // always a race condition
        .FAULT => |err| return syscall.errnoBug(err),
        .INVAL => |err| return syscall.errnoBug(err),
        .ACCES => return syscall.fail(error.AccessDenied),
        .PERM => return syscall.fail(error.PermissionDenied),
        .ROFS => return syscall.fail(error.ReadOnlyFileSystem),
        else => |err| return syscall.unexpectedErrno(err),
    };
}

fn fileSetTimestamps(
    userdata: ?*anyopaque,
    file: File,
    options: File.SetTimestampsOptions,
) File.SetTimestampsError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (is_windows) {
        var access_time_buffer: windows.FILETIME = undefined;
        var modify_time_buffer: windows.FILETIME = undefined;
        var system_time_buffer: windows.LARGE_INTEGER = undefined;

        if (options.access_timestamp == .now or options.modify_timestamp == .now) {
            system_time_buffer = windows.ntdll.RtlGetSystemTimePrecise();
        }

        const access_ptr = switch (options.access_timestamp) {
            .unchanged => null,
            .now => @panic("TODO do SystemTimeToFileTime logic here"),
            .new => |ts| p: {
                access_time_buffer = windows.nanoSecondsToFileTime(ts);
                break :p &access_time_buffer;
            },
        };

        const modify_ptr = switch (options.modify_timestamp) {
            .unchanged => null,
            .now => @panic("TODO do SystemTimeToFileTime logic here"),
            .new => |ts| p: {
                modify_time_buffer = windows.nanoSecondsToFileTime(ts);
                break :p &modify_time_buffer;
            },
        };

        // https://github.com/ziglang/zig/issues/1840
        const syscall: Syscall = try .start();
        while (true) {
            switch (windows.kernel32.SetFileTime(file.handle, null, access_ptr, modify_ptr)) {
                0 => switch (windows.GetLastError()) {
                    .OPERATION_ABORTED => {
                        try syscall.checkCancel();
                        continue;
                    },
                    else => |err| {
                        syscall.finish();
                        return windows.unexpectedError(err);
                    },
                },
                else => return syscall.finish(),
            }
        }
    }

    if (native_os == .wasi and !builtin.link_libc) {
        var atime: std.os.wasi.timestamp_t = 0;
        var mtime: std.os.wasi.timestamp_t = 0;
        var flags: std.os.wasi.fstflags_t = .{};

        switch (options.access_timestamp) {
            .unchanged => {},
            .now => flags.ATIM_NOW = true,
            .new => |ts| {
                atime = timestampToPosix(ts.nanoseconds).toTimestamp();
                flags.ATIM = true;
            },
        }

        switch (options.modify_timestamp) {
            .unchanged => {},
            .now => flags.MTIM_NOW = true,
            .new => |ts| {
                mtime = timestampToPosix(ts.nanoseconds).toTimestamp();
                flags.MTIM = true;
            },
        }

        const syscall: Syscall = try .start();
        while (true) switch (std.os.wasi.fd_filestat_set_times(file.handle, atime, mtime, flags)) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            .BADF => |err| return syscall.errnoBug(err), // File descriptor use-after-free.
            .FAULT => |err| return syscall.errnoBug(err),
            .INVAL => |err| return syscall.errnoBug(err),
            .ACCES => return syscall.fail(error.AccessDenied),
            .PERM => return syscall.fail(error.PermissionDenied),
            .ROFS => return syscall.fail(error.ReadOnlyFileSystem),
            else => |err| return syscall.unexpectedErrno(err),
        };
    }

    var times_buffer: [2]posix.timespec = undefined;
    const times = if (options.modify_timestamp == .now and options.access_timestamp == .now) null else p: {
        times_buffer = .{
            setTimestampToPosix(options.access_timestamp),
            setTimestampToPosix(options.modify_timestamp),
        };
        break :p &times_buffer;
    };

    const syscall: Syscall = try .start();
    while (true) switch (posix.errno(posix.system.futimens(file.handle, times))) {
        .SUCCESS => return syscall.finish(),
        .INTR => {
            try syscall.checkCancel();
            continue;
        },
        .BADF => |err| return syscall.errnoBug(err), // always a race condition
        .FAULT => |err| return syscall.errnoBug(err),
        .INVAL => |err| return syscall.errnoBug(err),
        .ACCES => return syscall.fail(error.AccessDenied),
        .PERM => return syscall.fail(error.PermissionDenied),
        .ROFS => return syscall.fail(error.ReadOnlyFileSystem),
        else => |err| return syscall.unexpectedErrno(err),
    };
}

const windows_lock_range_off: windows.LARGE_INTEGER = 0;
const windows_lock_range_len: windows.LARGE_INTEGER = 1;

fn fileLock(userdata: ?*anyopaque, file: File, lock: File.Lock) File.LockError!void {
    if (native_os == .wasi) return error.FileLocksUnsupported;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (is_windows) {
        const exclusive = switch (lock) {
            .none => {
                // To match the non-Windows behavior, unlock
                var io_status_block: windows.IO_STATUS_BLOCK = undefined;
                while (true) switch (windows.ntdll.NtUnlockFile(
                    file.handle,
                    &io_status_block,
                    &windows_lock_range_off,
                    &windows_lock_range_len,
                    0,
                )) {
                    .SUCCESS => return,
                    .CANCELLED => continue,
                    .RANGE_NOT_LOCKED => return,
                    .ACCESS_VIOLATION => |err| return windows.statusBug(err), // bad io_status_block pointer
                    else => |status| return windows.unexpectedStatus(status),
                };
            },
            .shared => false,
            .exclusive => true,
        };
        var io_status_block: windows.IO_STATUS_BLOCK = undefined;
        const syscall: Syscall = try .start();
        while (true) switch (windows.ntdll.NtLockFile(
            file.handle,
            null,
            null,
            null,
            &io_status_block,
            &windows_lock_range_off,
            &windows_lock_range_len,
            null,
            windows.FALSE,
            @intFromBool(exclusive),
        )) {
            .SUCCESS => return syscall.finish(),
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            .INSUFFICIENT_RESOURCES => return syscall.fail(error.SystemResources),
            .LOCK_NOT_GRANTED => |err| return syscall.ntstatusBug(err), // passed FailImmediately=false
            .ACCESS_VIOLATION => |err| return syscall.ntstatusBug(err), // bad io_status_block pointer
            else => |status| return syscall.unexpectedNtstatus(status),
        };
    }

    const operation: i32 = switch (lock) {
        .none => posix.LOCK.UN,
        .shared => posix.LOCK.SH,
        .exclusive => posix.LOCK.EX,
    };
    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.flock(file.handle, operation))) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .BADF => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err), // invalid parameters
                    .NOLCK => return error.SystemResources,
                    .AGAIN => |err| return errnoBug(err),
                    .OPNOTSUPP => return error.FileLocksUnsupported,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn fileTryLock(userdata: ?*anyopaque, file: File, lock: File.Lock) File.LockError!bool {
    if (native_os == .wasi) return error.FileLocksUnsupported;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (is_windows) {
        const exclusive = switch (lock) {
            .none => {
                // To match the non-Windows behavior, unlock
                var io_status_block: windows.IO_STATUS_BLOCK = undefined;
                while (true) switch (windows.ntdll.NtUnlockFile(
                    file.handle,
                    &io_status_block,
                    &windows_lock_range_off,
                    &windows_lock_range_len,
                    0,
                )) {
                    .SUCCESS => return true,
                    .CANCELLED => continue,
                    .RANGE_NOT_LOCKED => return false,
                    .ACCESS_VIOLATION => |err| return windows.statusBug(err), // bad io_status_block pointer
                    else => |status| return windows.unexpectedStatus(status),
                };
            },
            .shared => false,
            .exclusive => true,
        };
        var io_status_block: windows.IO_STATUS_BLOCK = undefined;
        const syscall: Syscall = try .start();
        while (true) switch (windows.ntdll.NtLockFile(
            file.handle,
            null,
            null,
            null,
            &io_status_block,
            &windows_lock_range_off,
            &windows_lock_range_len,
            null,
            windows.TRUE,
            @intFromBool(exclusive),
        )) {
            .SUCCESS => {
                syscall.finish();
                return true;
            },
            .LOCK_NOT_GRANTED => {
                syscall.finish();
                return false;
            },
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            .INSUFFICIENT_RESOURCES => return syscall.fail(error.SystemResources),
            .ACCESS_VIOLATION => |err| return syscall.ntstatusBug(err), // bad io_status_block pointer
            else => |status| return syscall.unexpectedNtstatus(status),
        };
    }

    const operation: i32 = switch (lock) {
        .none => posix.LOCK.UN,
        .shared => posix.LOCK.SH | posix.LOCK.NB,
        .exclusive => posix.LOCK.EX | posix.LOCK.NB,
    };
    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.flock(file.handle, operation))) {
            .SUCCESS => {
                syscall.finish();
                return true;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            .AGAIN => {
                syscall.finish();
                return false;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .BADF => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err), // invalid parameters
                    .NOLCK => return error.SystemResources,
                    .OPNOTSUPP => return error.FileLocksUnsupported,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn fileUnlock(userdata: ?*anyopaque, file: File) void {
    if (native_os == .wasi) return;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (is_windows) {
        var io_status_block: windows.IO_STATUS_BLOCK = undefined;
        while (true) switch (windows.ntdll.NtUnlockFile(
            file.handle,
            &io_status_block,
            &windows_lock_range_off,
            &windows_lock_range_len,
            0,
        )) {
            .SUCCESS => return,
            .CANCELLED => continue,
            .RANGE_NOT_LOCKED => if (is_debug) unreachable else return, // Function asserts unlocked.
            .ACCESS_VIOLATION => if (is_debug) unreachable else return, // bad io_status_block pointer
            else => if (is_debug) unreachable else return, // Resource deallocation must succeed.
        };
    }

    while (true) {
        switch (posix.errno(posix.system.flock(file.handle, posix.LOCK.UN))) {
            .SUCCESS => return,
            .CANCELED, .INTR => continue,
            .AGAIN => return assert(!is_debug), // unlocking can't block
            .BADF => return assert(!is_debug), // File descriptor used after closed.
            .INVAL => return assert(!is_debug), // invalid parameters
            .NOLCK => return assert(!is_debug), // Resource deallocation.
            .OPNOTSUPP => return assert(!is_debug), // We already got the lock.
            else => return assert(!is_debug), // Resource deallocation must succeed.
        }
    }
}

fn fileDowngradeLock(userdata: ?*anyopaque, file: File) File.DowngradeLockError!void {
    if (native_os == .wasi) return;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (is_windows) {
        // On Windows it works like a semaphore + exclusivity flag. To
        // implement this function, we first obtain another lock in shared
        // mode. This changes the exclusivity flag, but increments the
        // semaphore to 2. So we follow up with an NtUnlockFile which
        // decrements the semaphore but does not modify the exclusivity flag.
        var io_status_block: windows.IO_STATUS_BLOCK = undefined;
        const syscall: Syscall = try .start();
        while (true) switch (windows.ntdll.NtLockFile(
            file.handle,
            null,
            null,
            null,
            &io_status_block,
            &windows_lock_range_off,
            &windows_lock_range_len,
            null,
            windows.TRUE,
            windows.FALSE,
        )) {
            .SUCCESS => break syscall.finish(),
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            .INSUFFICIENT_RESOURCES => |err| return syscall.ntstatusBug(err),
            .LOCK_NOT_GRANTED => |err| return syscall.ntstatusBug(err), // File was not locked in exclusive mode.
            .ACCESS_VIOLATION => |err| return syscall.ntstatusBug(err), // bad io_status_block pointer
            else => |status| return syscall.unexpectedNtstatus(status),
        };
        while (true) switch (windows.ntdll.NtUnlockFile(
            file.handle,
            &io_status_block,
            &windows_lock_range_off,
            &windows_lock_range_len,
            0,
        )) {
            .SUCCESS => return,
            .CANCELLED => continue,
            .RANGE_NOT_LOCKED => if (is_debug) unreachable else return, // File was not locked.
            .ACCESS_VIOLATION => if (is_debug) unreachable else return, // bad io_status_block pointer
            else => if (is_debug) unreachable else return, // Resource deallocation must succeed.
        };
    }

    const operation = posix.LOCK.SH | posix.LOCK.NB;

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.flock(file.handle, operation))) {
            .SUCCESS => {
                syscall.finish();
                return;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .AGAIN => |err| return errnoBug(err), // File was not locked in exclusive mode.
                    .BADF => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err), // invalid parameters
                    .NOLCK => |err| return errnoBug(err), // Lock already obtained.
                    .OPNOTSUPP => |err| return errnoBug(err), // Lock already obtained.
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn dirOpenDirWasi(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    options: Dir.OpenOptions,
) Dir.OpenError!Dir {
    if (builtin.link_libc) return dirOpenDirPosix(userdata, dir, sub_path, options);
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const wasi = std.os.wasi;

    var base: std.os.wasi.rights_t = .{
        .FD_FILESTAT_GET = true,
        .FD_FDSTAT_SET_FLAGS = true,
        .FD_FILESTAT_SET_TIMES = true,
    };
    if (options.access_sub_paths) {
        base.FD_READDIR = true;
        base.PATH_CREATE_DIRECTORY = true;
        base.PATH_CREATE_FILE = true;
        base.PATH_LINK_SOURCE = true;
        base.PATH_LINK_TARGET = true;
        base.PATH_OPEN = true;
        base.PATH_READLINK = true;
        base.PATH_RENAME_SOURCE = true;
        base.PATH_RENAME_TARGET = true;
        base.PATH_FILESTAT_GET = true;
        base.PATH_FILESTAT_SET_SIZE = true;
        base.PATH_FILESTAT_SET_TIMES = true;
        base.PATH_SYMLINK = true;
        base.PATH_REMOVE_DIRECTORY = true;
        base.PATH_UNLINK_FILE = true;
    }

    const lookup_flags: wasi.lookupflags_t = .{ .SYMLINK_FOLLOW = options.follow_symlinks };
    const oflags: wasi.oflags_t = .{ .DIRECTORY = true };
    const fdflags: wasi.fdflags_t = .{};
    var fd: posix.fd_t = undefined;
    const syscall: Syscall = try .start();
    while (true) {
        switch (wasi.path_open(dir.handle, lookup_flags, sub_path.ptr, sub_path.len, oflags, base, base, fdflags, &fd)) {
            .SUCCESS => {
                syscall.finish();
                return .{ .handle = fd };
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => return error.BadPathName,
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .ACCES => return error.AccessDenied,
                    .LOOP => return error.SymLinkLoop,
                    .MFILE => return error.ProcessFdQuotaExceeded,
                    .NAMETOOLONG => return error.NameTooLong,
                    .NFILE => return error.SystemFdQuotaExceeded,
                    .NODEV => return error.NoDevice,
                    .NOENT => return error.FileNotFound,
                    .NOMEM => return error.SystemResources,
                    .NOTDIR => return error.NotDir,
                    .PERM => return error.PermissionDenied,
                    .BUSY => return error.DeviceBusy,
                    .NOTCAPABLE => return error.AccessDenied,
                    .ILSEQ => return error.BadPathName,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn dirHardLink(
    userdata: ?*anyopaque,
    old_dir: Dir,
    old_sub_path: []const u8,
    new_dir: Dir,
    new_sub_path: []const u8,
    options: Dir.HardLinkOptions,
) Dir.HardLinkError!void {
    if (is_windows) return error.OperationUnsupported;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (native_os == .wasi and !builtin.link_libc) {
        const flags: std.os.wasi.lookupflags_t = .{
            .SYMLINK_FOLLOW = options.follow_symlinks,
        };
        const syscall: Syscall = try .start();
        while (true) {
            switch (std.os.wasi.path_link(
                old_dir.handle,
                flags,
                old_sub_path.ptr,
                old_sub_path.len,
                new_dir.handle,
                new_sub_path.ptr,
                new_sub_path.len,
            )) {
                .SUCCESS => return syscall.finish(),
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .ACCES => return error.AccessDenied,
                        .DQUOT => return error.DiskQuota,
                        .EXIST => return error.PathAlreadyExists,
                        .FAULT => |err| return errnoBug(err),
                        .IO => return error.HardwareFailure,
                        .LOOP => return error.SymLinkLoop,
                        .MLINK => return error.LinkQuotaExceeded,
                        .NAMETOOLONG => return error.NameTooLong,
                        .NOENT => return error.FileNotFound,
                        .NOMEM => return error.SystemResources,
                        .NOSPC => return error.NoSpaceLeft,
                        .NOTDIR => return error.NotDir,
                        .PERM => return error.PermissionDenied,
                        .ROFS => return error.ReadOnlyFileSystem,
                        .XDEV => return error.NotSameFileSystem,
                        .INVAL => |err| return errnoBug(err),
                        .ILSEQ => return error.BadPathName,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    }

    var old_path_buffer: [posix.PATH_MAX]u8 = undefined;
    var new_path_buffer: [posix.PATH_MAX]u8 = undefined;

    const old_sub_path_posix = try pathToPosix(old_sub_path, &old_path_buffer);
    const new_sub_path_posix = try pathToPosix(new_sub_path, &new_path_buffer);

    const flags: u32 = if (!options.follow_symlinks) posix.AT.SYMLINK_NOFOLLOW else 0;

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.linkat(
            old_dir.handle,
            old_sub_path_posix,
            new_dir.handle,
            new_sub_path_posix,
            flags,
        ))) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ACCES => return error.AccessDenied,
                    .DQUOT => return error.DiskQuota,
                    .EXIST => return error.PathAlreadyExists,
                    .FAULT => |err| return errnoBug(err),
                    .IO => return error.HardwareFailure,
                    .LOOP => return error.SymLinkLoop,
                    .MLINK => return error.LinkQuotaExceeded,
                    .NAMETOOLONG => return error.NameTooLong,
                    .NOENT => return error.FileNotFound,
                    .NOMEM => return error.SystemResources,
                    .NOSPC => return error.NoSpaceLeft,
                    .NOTDIR => return error.NotDir,
                    .PERM => return error.PermissionDenied,
                    .ROFS => return error.ReadOnlyFileSystem,
                    .XDEV => return error.NotSameFileSystem,
                    .INVAL => |err| return errnoBug(err),
                    .ILSEQ => return error.BadPathName,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn fileClose(userdata: ?*anyopaque, files: []const File) void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    for (files) |file| posix.close(file.handle);
}

const fileReadStreaming = switch (native_os) {
    .windows => fileReadStreamingWindows,
    else => fileReadStreamingPosix,
};

fn fileReadStreamingPosix(userdata: ?*anyopaque, file: File, data: []const []u8) File.Reader.Error!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var iovecs_buffer: [max_iovecs_len]posix.iovec = undefined;
    var i: usize = 0;
    for (data) |buf| {
        if (iovecs_buffer.len - i == 0) break;
        if (buf.len != 0) {
            iovecs_buffer[i] = .{ .base = buf.ptr, .len = buf.len };
            i += 1;
        }
    }
    if (i == 0) return 0;
    const dest = iovecs_buffer[0..i];
    assert(dest[0].len > 0);

    if (native_os == .wasi and !builtin.link_libc) {
        const syscall: Syscall = try .start();
        while (true) {
            var nread: usize = undefined;
            switch (std.os.wasi.fd_read(file.handle, dest.ptr, dest.len, &nread)) {
                .SUCCESS => {
                    syscall.finish();
                    return nread;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .INVAL => |err| return errnoBug(err),
                        .FAULT => |err| return errnoBug(err),
                        .BADF => return error.NotOpenForReading, // File operation on directory.
                        .IO => return error.InputOutput,
                        .ISDIR => return error.IsDir,
                        .NOBUFS => return error.SystemResources,
                        .NOMEM => return error.SystemResources,
                        .NOTCONN => return error.SocketUnconnected,
                        .CONNRESET => return error.ConnectionResetByPeer,
                        .TIMEDOUT => return error.Timeout,
                        .NOTCAPABLE => return error.AccessDenied,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    }

    const syscall: Syscall = try .start();
    while (true) {
        const rc = posix.system.readv(file.handle, dest.ptr, @intCast(dest.len));
        switch (posix.errno(rc)) {
            .SUCCESS => {
                syscall.finish();
                return @intCast(rc);
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .INVAL => |err| return errnoBug(err),
                    .FAULT => |err| return errnoBug(err),
                    .AGAIN => return error.WouldBlock,
                    .BADF => |err| {
                        if (native_os == .wasi) return error.NotOpenForReading; // File operation on directory.
                        return errnoBug(err); // File descriptor used after closed.
                    },
                    .IO => return error.InputOutput,
                    .ISDIR => return error.IsDir,
                    .NOBUFS => return error.SystemResources,
                    .NOMEM => return error.SystemResources,
                    .NOTCONN => return error.SocketUnconnected,
                    .CONNRESET => return error.ConnectionResetByPeer,
                    .TIMEDOUT => return error.Timeout,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn fileReadStreamingWindows(userdata: ?*anyopaque, file: File, data: []const []u8) File.Reader.Error!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    const DWORD = windows.DWORD;
    var index: usize = 0;
    while (index < data.len and data[index].len == 0) index += 1;
    if (index == data.len) return 0;
    const buffer = data[index];
    const want_read_count: DWORD = @min(std.math.maxInt(DWORD), buffer.len);

    const syscall: Syscall = try .start();
    while (true) {
        var n: DWORD = undefined;
        if (windows.kernel32.ReadFile(file.handle, buffer.ptr, want_read_count, &n, null) != 0) {
            syscall.finish();
            return n;
        }
        switch (windows.GetLastError()) {
            .IO_PENDING => |err| {
                syscall.finish();
                return windows.errorBug(err);
            },
            .OPERATION_ABORTED => {
                try syscall.checkCancel();
                continue;
            },
            .BROKEN_PIPE, .HANDLE_EOF => {
                syscall.finish();
                return 0;
            },
            .NETNAME_DELETED => return syscall.fail(error.ConnectionResetByPeer),
            .LOCK_VIOLATION => return syscall.fail(error.LockViolation),
            .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
            .INVALID_HANDLE => return syscall.fail(error.NotOpenForReading),
            else => |err| {
                syscall.finish();
                return windows.unexpectedError(err);
            },
        }
    }
}

fn fileReadPositionalPosix(userdata: ?*anyopaque, file: File, data: []const []u8, offset: u64) File.ReadPositionalError!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (!have_preadv) @compileError("TODO implement fileReadPositionalPosix for cursed operating systems that don't support preadv (it's only Haiku)");

    var iovecs_buffer: [max_iovecs_len]posix.iovec = undefined;
    var i: usize = 0;
    for (data) |buf| {
        if (iovecs_buffer.len - i == 0) break;
        if (buf.len != 0) {
            iovecs_buffer[i] = .{ .base = buf.ptr, .len = buf.len };
            i += 1;
        }
    }
    if (i == 0) return 0;
    const dest = iovecs_buffer[0..i];
    assert(dest[0].len > 0);

    if (native_os == .wasi and !builtin.link_libc) {
        const syscall: Syscall = try .start();
        while (true) {
            var nread: usize = undefined;
            switch (std.os.wasi.fd_pread(file.handle, dest.ptr, dest.len, offset, &nread)) {
                .SUCCESS => {
                    syscall.finish();
                    return nread;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .INVAL => |err| return errnoBug(err),
                        .FAULT => |err| return errnoBug(err),
                        .AGAIN => |err| return errnoBug(err),
                        .BADF => return error.NotOpenForReading, // File operation on directory.
                        .IO => return error.InputOutput,
                        .ISDIR => return error.IsDir,
                        .NOBUFS => return error.SystemResources,
                        .NOMEM => return error.SystemResources,
                        .NOTCONN => return error.SocketUnconnected,
                        .CONNRESET => return error.ConnectionResetByPeer,
                        .TIMEDOUT => return error.Timeout,
                        .NXIO => return error.Unseekable,
                        .SPIPE => return error.Unseekable,
                        .OVERFLOW => return error.Unseekable,
                        .NOTCAPABLE => return error.AccessDenied,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    }

    const syscall: Syscall = try .start();
    while (true) {
        const rc = preadv_sym(file.handle, dest.ptr, @intCast(dest.len), @bitCast(offset));
        switch (posix.errno(rc)) {
            .SUCCESS => {
                syscall.finish();
                return @bitCast(rc);
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .INVAL => |err| return errnoBug(err),
                    .FAULT => |err| return errnoBug(err),
                    .AGAIN => return error.WouldBlock,
                    .BADF => |err| {
                        if (native_os == .wasi) return error.NotOpenForReading; // File operation on directory.
                        return errnoBug(err); // File descriptor used after closed.
                    },
                    .IO => return error.InputOutput,
                    .ISDIR => return error.IsDir,
                    .NOBUFS => return error.SystemResources,
                    .NOMEM => return error.SystemResources,
                    .NOTCONN => return error.SocketUnconnected,
                    .CONNRESET => return error.ConnectionResetByPeer,
                    .TIMEDOUT => return error.Timeout,
                    .NXIO => return error.Unseekable,
                    .SPIPE => return error.Unseekable,
                    .OVERFLOW => return error.Unseekable,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

const fileReadPositional = switch (native_os) {
    .windows => fileReadPositionalWindows,
    else => fileReadPositionalPosix,
};

fn fileReadPositionalWindows(userdata: ?*anyopaque, file: File, data: []const []u8, offset: u64) File.ReadPositionalError!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    const DWORD = windows.DWORD;

    var index: usize = 0;
    while (index < data.len and data[index].len == 0) index += 1;
    if (index == data.len) return 0;
    const buffer = data[index];
    const want_read_count: DWORD = @min(std.math.maxInt(DWORD), buffer.len);

    var overlapped: windows.OVERLAPPED = .{
        .Internal = 0,
        .InternalHigh = 0,
        .DUMMYUNIONNAME = .{
            .DUMMYSTRUCTNAME = .{
                .Offset = @truncate(offset),
                .OffsetHigh = @truncate(offset >> 32),
            },
        },
        .hEvent = null,
    };

    const syscall: Syscall = try .start();
    while (true) {
        var n: DWORD = undefined;
        if (windows.kernel32.ReadFile(file.handle, buffer.ptr, want_read_count, &n, &overlapped) != 0) {
            syscall.finish();
            return n;
        }
        switch (windows.GetLastError()) {
            .IO_PENDING => |err| {
                syscall.finish();
                return windows.errorBug(err);
            },
            .OPERATION_ABORTED => {
                try syscall.checkCancel();
                continue;
            },
            .BROKEN_PIPE, .HANDLE_EOF => {
                syscall.finish();
                return 0;
            },
            .NETNAME_DELETED => return syscall.fail(error.ConnectionResetByPeer),
            .LOCK_VIOLATION => return syscall.fail(error.LockViolation),
            .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
            .INVALID_HANDLE => return syscall.fail(error.NotOpenForReading),
            else => |err| {
                syscall.finish();
                return windows.unexpectedError(err);
            },
        }
    }
}

fn fileSeekBy(userdata: ?*anyopaque, file: File, offset: i64) File.SeekError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const fd = file.handle;

    if (native_os == .linux and !builtin.link_libc and @sizeOf(usize) == 4) {
        var result: u64 = undefined;
        const syscall: Syscall = try .start();
        while (true) {
            switch (posix.errno(posix.system.llseek(fd, @bitCast(offset), &result, posix.SEEK.CUR))) {
                .SUCCESS => {
                    syscall.finish();
                    return;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                        .INVAL => return error.Unseekable,
                        .OVERFLOW => return error.Unseekable,
                        .SPIPE => return error.Unseekable,
                        .NXIO => return error.Unseekable,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    }

    if (native_os == .windows) {
        const syscall: Syscall = try .start();
        while (true) {
            if (windows.kernel32.SetFilePointerEx(fd, offset, null, windows.FILE_CURRENT) != 0) {
                return syscall.finish();
            }
            switch (windows.GetLastError()) {
                .OPERATION_ABORTED => {
                    try syscall.checkCancel();
                    continue;
                },
                .INVALID_FUNCTION => return syscall.fail(error.Unseekable),
                .NEGATIVE_SEEK => return syscall.fail(error.Unseekable),
                .INVALID_PARAMETER => unreachable,
                .INVALID_HANDLE => unreachable,
                else => |err| {
                    syscall.finish();
                    return windows.unexpectedError(err);
                },
            }
        }
    }

    if (native_os == .wasi and !builtin.link_libc) {
        var new_offset: std.os.wasi.filesize_t = undefined;
        const syscall: Syscall = try .start();
        while (true) {
            switch (std.os.wasi.fd_seek(fd, offset, .CUR, &new_offset)) {
                .SUCCESS => {
                    syscall.finish();
                    return;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                        .INVAL => return error.Unseekable,
                        .OVERFLOW => return error.Unseekable,
                        .SPIPE => return error.Unseekable,
                        .NXIO => return error.Unseekable,
                        .NOTCAPABLE => return error.AccessDenied,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    }

    if (posix.SEEK == void) return error.Unseekable;

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(lseek_sym(fd, offset, posix.SEEK.CUR))) {
            .SUCCESS => {
                syscall.finish();
                return;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .INVAL => return error.Unseekable,
                    .OVERFLOW => return error.Unseekable,
                    .SPIPE => return error.Unseekable,
                    .NXIO => return error.Unseekable,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn fileSeekTo(userdata: ?*anyopaque, file: File, offset: u64) File.SeekError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const fd = file.handle;

    if (native_os == .windows) {
        // "The starting point is zero or the beginning of the file. If [FILE_BEGIN]
        // is specified, then the liDistanceToMove parameter is interpreted as an unsigned value."
        // https://docs.microsoft.com/en-us/windows/desktop/api/fileapi/nf-fileapi-setfilepointerex
        const ipos: windows.LARGE_INTEGER = @bitCast(offset);

        const syscall: Syscall = try .start();
        while (true) {
            if (windows.kernel32.SetFilePointerEx(fd, ipos, null, windows.FILE_BEGIN) != 0) {
                return syscall.finish();
            }
            switch (windows.GetLastError()) {
                .OPERATION_ABORTED => {
                    try syscall.checkCancel();
                    continue;
                },
                .INVALID_FUNCTION => return syscall.fail(error.Unseekable),
                .NEGATIVE_SEEK => return syscall.fail(error.Unseekable),
                .INVALID_PARAMETER => unreachable,
                .INVALID_HANDLE => unreachable,
                else => |err| {
                    syscall.finish();
                    return windows.unexpectedError(err);
                },
            }
        }
    }

    if (native_os == .wasi and !builtin.link_libc) {
        const syscall: Syscall = try .start();
        while (true) {
            var new_offset: std.os.wasi.filesize_t = undefined;
            switch (std.os.wasi.fd_seek(fd, @bitCast(offset), .SET, &new_offset)) {
                .SUCCESS => {
                    syscall.finish();
                    return;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                        .INVAL => return error.Unseekable,
                        .OVERFLOW => return error.Unseekable,
                        .SPIPE => return error.Unseekable,
                        .NXIO => return error.Unseekable,
                        .NOTCAPABLE => return error.AccessDenied,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    }

    if (posix.SEEK == void) return error.Unseekable;

    return posixSeekTo(fd, offset);
}

fn posixSeekTo(fd: posix.fd_t, offset: u64) File.SeekError!void {
    if (native_os == .linux and !builtin.link_libc and @sizeOf(usize) == 4) {
        const syscall: Syscall = try .start();
        while (true) {
            var result: u64 = undefined;
            switch (posix.errno(posix.system.llseek(fd, offset, &result, posix.SEEK.SET))) {
                .SUCCESS => {
                    syscall.finish();
                    return;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                        .INVAL => return error.Unseekable,
                        .OVERFLOW => return error.Unseekable,
                        .SPIPE => return error.Unseekable,
                        .NXIO => return error.Unseekable,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    }

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(lseek_sym(fd, @bitCast(offset), posix.SEEK.SET))) {
            .SUCCESS => {
                syscall.finish();
                return;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .INVAL => return error.Unseekable,
                    .OVERFLOW => return error.Unseekable,
                    .SPIPE => return error.Unseekable,
                    .NXIO => return error.Unseekable,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn processExecutableOpen(userdata: ?*anyopaque, flags: File.OpenFlags) std.process.OpenExecutableError!File {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    switch (native_os) {
        .wasi => return error.OperationUnsupported,
        .linux, .serenity => return dirOpenFilePosix(t, .{ .handle = posix.AT.FDCWD }, "/proc/self/exe", flags),
        .windows => {
            // If ImagePathName is a symlink, then it will contain the path of the symlink,
            // not the path that the symlink points to. However, because we are opening
            // the file, we can let the openFileW call follow the symlink for us.
            const image_path_unicode_string = &windows.peb().ProcessParameters.ImagePathName;
            const image_path_name = image_path_unicode_string.Buffer.?[0 .. image_path_unicode_string.Length / 2 :0];
            const prefixed_path_w = try windows.wToPrefixedFileW(null, image_path_name);
            return dirOpenFileWtf16(null, prefixed_path_w.span(), flags);
        },
        .driverkit,
        .ios,
        .maccatalyst,
        .macos,
        .tvos,
        .visionos,
        .watchos,
        => {
            // _NSGetExecutablePath() returns a path that might be a symlink to
            // the executable. Here it does not matter since we open it.
            var symlink_path_buf: [posix.PATH_MAX + 1]u8 = undefined;
            var n: u32 = symlink_path_buf.len;
            const rc = std.c._NSGetExecutablePath(&symlink_path_buf, &n);
            if (rc != 0) return error.NameTooLong;
            const symlink_path = std.mem.sliceTo(&symlink_path_buf, 0);
            return dirOpenFilePosix(t, .cwd(), symlink_path, flags);
        },
        else => {
            var buffer: [Dir.max_path_bytes]u8 = undefined;
            const n = try processExecutablePath(t, &buffer);
            buffer[n] = 0;
            const executable_path = buffer[0..n :0];
            return dirOpenFilePosix(t, .cwd(), executable_path, flags);
        },
    }
}

fn processExecutablePath(userdata: ?*anyopaque, out_buffer: []u8) std.process.ExecutablePathError!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));

    switch (native_os) {
        .driverkit,
        .ios,
        .maccatalyst,
        .macos,
        .tvos,
        .visionos,
        .watchos,
        => {
            // _NSGetExecutablePath() returns a path that might be a symlink to
            // the executable.
            var symlink_path_buf: [posix.PATH_MAX + 1]u8 = undefined;
            var n: u32 = symlink_path_buf.len;
            const rc = std.c._NSGetExecutablePath(&symlink_path_buf, &n);
            if (rc != 0) return error.NameTooLong;
            const symlink_path = std.mem.sliceTo(&symlink_path_buf, 0);
            return Io.Dir.realPathFileAbsolute(ioBasic(t), symlink_path, out_buffer) catch |err| switch (err) {
                error.NetworkNotFound => unreachable, // Windows-only
                else => |e| return e,
            };
        },
        .linux, .serenity => return Io.Dir.readLinkAbsolute(ioBasic(t), "/proc/self/exe", out_buffer) catch |err| switch (err) {
            error.UnsupportedReparsePointType => unreachable, // Windows-only
            error.NetworkNotFound => unreachable, // Windows-only
            else => |e| return e,
        },
        .illumos => return Io.Dir.readLinkAbsolute(ioBasic(t), "/proc/self/path/a.out", out_buffer) catch |err| switch (err) {
            error.UnsupportedReparsePointType => unreachable, // Windows-only
            error.NetworkNotFound => unreachable, // Windows-only
            else => |e| return e,
        },
        .freebsd, .dragonfly => {
            var mib: [4]c_int = .{ posix.CTL.KERN, posix.KERN.PROC, posix.KERN.PROC_PATHNAME, -1 };
            var out_len: usize = out_buffer.len;
            const syscall: Syscall = try .start();
            while (true) {
                switch (posix.errno(posix.system.sysctl(&mib, mib.len, out_buffer.ptr, &out_len, null, 0))) {
                    .SUCCESS => {
                        syscall.finish();
                        return out_len - 1; // discard terminating NUL
                    },
                    .INTR => {
                        try syscall.checkCancel();
                        continue;
                    },
                    else => |e| {
                        syscall.finish();
                        switch (e) {
                            .FAULT => |err| return errnoBug(err),
                            .PERM => return error.PermissionDenied,
                            .NOMEM => return error.SystemResources,
                            .NOENT => |err| return errnoBug(err),
                            else => |err| return posix.unexpectedErrno(err),
                        }
                    },
                }
            }
        },
        .netbsd => {
            var mib = [4]c_int{ posix.CTL.KERN, posix.KERN.PROC_ARGS, -1, posix.KERN.PROC_PATHNAME };
            var out_len: usize = out_buffer.len;
            const syscall: Syscall = try .start();
            while (true) {
                switch (posix.errno(posix.system.sysctl(&mib, mib.len, out_buffer.ptr, &out_len, null, 0))) {
                    .SUCCESS => {
                        syscall.finish();
                        return out_len - 1; // discard terminating NUL
                    },
                    .INTR => {
                        try syscall.checkCancel();
                        continue;
                    },
                    else => |e| {
                        syscall.finish();
                        switch (e) {
                            .FAULT => |err| return errnoBug(err),
                            .PERM => return error.PermissionDenied,
                            .NOMEM => return error.SystemResources,
                            .NOENT => |err| return errnoBug(err),
                            else => |err| return posix.unexpectedErrno(err),
                        }
                    },
                }
            }
        },
        .openbsd, .haiku => {
            // The best we can do on these operating systems is check based on
            // the first process argument.
            const argv0 = std.mem.span(t.argv0.value orelse return error.OperationUnsupported);
            if (std.mem.findScalar(u8, argv0, '/') != null) {
                // argv[0] is a path (relative or absolute): use realpath(3) directly
                var resolved_buf: [std.c.PATH_MAX]u8 = undefined;
                const syscall: Syscall = try .start();
                while (true) {
                    if (std.c.realpath(argv0, &resolved_buf)) |p| {
                        assert(p == &resolved_buf);
                        break syscall.finish();
                    } else switch (@as(std.c.E, @enumFromInt(std.c._errno().*))) {
                        .INTR => {
                            try syscall.checkCancel();
                            continue;
                        },
                        else => |e| {
                            syscall.finish();
                            switch (e) {
                                .ACCES => return error.AccessDenied,
                                .INVAL => |err| return errnoBug(err), // the pathname argument is a null pointer
                                .IO => return error.InputOutput,
                                .LOOP => return error.SymLinkLoop,
                                .NAMETOOLONG => return error.NameTooLong,
                                .NOENT => return error.FileNotFound,
                                .NOTDIR => return error.NotDir,
                                .NOMEM => |err| return errnoBug(err), // sufficient storage space is unavailable for allocation
                                else => |err| return posix.unexpectedErrno(err),
                            }
                        },
                    }
                }
                const resolved = std.mem.sliceTo(&resolved_buf, 0);
                if (resolved.len > out_buffer.len)
                    return error.NameTooLong;
                @memcpy(out_buffer[0..resolved.len], resolved);
                return resolved.len;
            } else if (argv0.len != 0) {
                // argv[0] is not empty (and not a path): search PATH
                t.scanEnviron();
                const PATH = t.environ.string.PATH orelse return error.FileNotFound;
                var it = std.mem.tokenizeScalar(u8, PATH, ':');
                it: while (it.next()) |dir| {
                    var resolved_path_buf: [std.c.PATH_MAX]u8 = undefined;
                    const resolved_path = std.fmt.bufPrintSentinel(&resolved_path_buf, "{s}/{s}", .{
                        dir, argv0,
                    }, 0) catch continue;

                    var resolved_buf: [std.c.PATH_MAX]u8 = undefined;
                    const syscall: Syscall = try .start();
                    while (true) {
                        if (std.c.realpath(resolved_path, &resolved_buf)) |p| {
                            assert(p == &resolved_buf);
                            break syscall.finish();
                        } else switch (@as(std.c.E, @enumFromInt(std.c._errno().*))) {
                            .INTR => {
                                try syscall.checkCancel();
                                continue;
                            },
                            .NAMETOOLONG => {
                                syscall.finish();
                                return error.NameTooLong;
                            },
                            .NOMEM => {
                                syscall.finish();
                                return error.SystemResources;
                            },
                            .IO => {
                                syscall.finish();
                                return error.InputOutput;
                            },
                            .ACCES, .LOOP, .NOENT, .NOTDIR => {
                                syscall.finish();
                                continue :it;
                            },
                            else => |err| {
                                syscall.finish();
                                return posix.unexpectedErrno(err);
                            },
                        }
                    }
                    const resolved = std.mem.sliceTo(&resolved_buf, 0);
                    if (resolved.len > out_buffer.len)
                        return error.NameTooLong;
                    @memcpy(out_buffer[0..resolved.len], resolved);
                    return resolved.len;
                }
            }
            return error.FileNotFound;
        },
        .windows => {
            const w = windows;
            const image_path_unicode_string = &w.peb().ProcessParameters.ImagePathName;
            const image_path_name = image_path_unicode_string.Buffer.?[0 .. image_path_unicode_string.Length / 2 :0];

            // If ImagePathName is a symlink, then it will contain the path of the
            // symlink, not the path that the symlink points to. We want the path
            // that the symlink points to, though, so we need to get the realpath.
            var path_name_w_buf = try w.wToPrefixedFileW(null, image_path_name);

            const h_file = handle: {
                const syscall: Syscall = try .start();
                while (true) {
                    if (w.OpenFile(path_name_w_buf.span(), .{
                        .dir = null,
                        .access_mask = .{
                            .GENERIC = .{ .READ = true },
                            .STANDARD = .{ .SYNCHRONIZE = true },
                        },
                        .creation = .OPEN,
                        .filter = .any,
                    })) |handle| {
                        syscall.finish();
                        break :handle handle;
                    } else |err| switch (err) {
                        error.WouldBlock => unreachable,
                        error.OperationCanceled => {
                            try syscall.checkCancel();
                            continue;
                        },
                        else => |e| return e,
                    }
                }
            };
            defer w.CloseHandle(h_file);

            // TODO move GetFinalPathNameByHandle logic into std.Io.Threaded and add cancel checks
            try Thread.checkCancel();
            const wide_slice = try w.GetFinalPathNameByHandle(h_file, .{}, &path_name_w_buf.data);

            const len = std.unicode.calcWtf8Len(wide_slice);
            if (len > out_buffer.len)
                return error.NameTooLong;

            const end_index = std.unicode.wtf16LeToWtf8(out_buffer, wide_slice);
            return end_index;
        },
        else => return error.OperationUnsupported,
    }
}

fn fileWritePositional(
    userdata: ?*anyopaque,
    file: File,
    header: []const u8,
    data: []const []const u8,
    splat: usize,
    offset: u64,
) File.WritePositionalError!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (is_windows) {
        if (header.len != 0) {
            return writeFilePositionalWindows(file.handle, header, offset);
        }
        for (data[0 .. data.len - 1]) |buf| {
            if (buf.len == 0) continue;
            return writeFilePositionalWindows(file.handle, buf, offset);
        }
        const pattern = data[data.len - 1];
        if (pattern.len == 0 or splat == 0) return 0;
        return writeFilePositionalWindows(file.handle, pattern, offset);
    }

    var iovecs: [max_iovecs_len]posix.iovec_const = undefined;
    var iovlen: iovlen_t = 0;
    addBuf(&iovecs, &iovlen, header);
    for (data[0 .. data.len - 1]) |bytes| addBuf(&iovecs, &iovlen, bytes);
    const pattern = data[data.len - 1];
    if (iovecs.len - iovlen != 0) switch (splat) {
        0 => {},
        1 => addBuf(&iovecs, &iovlen, pattern),
        else => switch (pattern.len) {
            0 => {},
            1 => {
                var backup_buffer: [splat_buffer_size]u8 = undefined;
                const splat_buffer = &backup_buffer;
                const memset_len = @min(splat_buffer.len, splat);
                const buf = splat_buffer[0..memset_len];
                @memset(buf, pattern[0]);
                addBuf(&iovecs, &iovlen, buf);
                var remaining_splat = splat - buf.len;
                while (remaining_splat > splat_buffer.len and iovecs.len - iovlen != 0) {
                    assert(buf.len == splat_buffer.len);
                    addBuf(&iovecs, &iovlen, splat_buffer);
                    remaining_splat -= splat_buffer.len;
                }
                addBuf(&iovecs, &iovlen, splat_buffer[0..@min(remaining_splat, splat_buffer.len)]);
            },
            else => for (0..@min(splat, iovecs.len - iovlen)) |_| {
                addBuf(&iovecs, &iovlen, pattern);
            },
        },
    };

    if (iovlen == 0) return 0;

    if (native_os == .wasi and !builtin.link_libc) {
        var n_written: usize = undefined;
        const syscall: Syscall = try .start();
        while (true) {
            switch (std.os.wasi.fd_pwrite(file.handle, &iovecs, iovlen, offset, &n_written)) {
                .SUCCESS => {
                    syscall.finish();
                    return n_written;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .INVAL => |err| return errnoBug(err),
                        .FAULT => |err| return errnoBug(err),
                        .AGAIN => |err| return errnoBug(err),
                        .BADF => return error.NotOpenForWriting, // can be a race condition.
                        .DESTADDRREQ => |err| return errnoBug(err), // `connect` was never called.
                        .DQUOT => return error.DiskQuota,
                        .FBIG => return error.FileTooBig,
                        .IO => return error.InputOutput,
                        .NOSPC => return error.NoSpaceLeft,
                        .PERM => return error.PermissionDenied,
                        .PIPE => return error.BrokenPipe,
                        .NOTCAPABLE => return error.AccessDenied,
                        .NXIO => return error.Unseekable,
                        .SPIPE => return error.Unseekable,
                        .OVERFLOW => return error.Unseekable,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    }

    const syscall: Syscall = try .start();
    while (true) {
        const rc = pwritev_sym(file.handle, &iovecs, @intCast(iovlen), @bitCast(offset));
        switch (posix.errno(rc)) {
            .SUCCESS => {
                syscall.finish();
                return @intCast(rc);
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .INVAL => |err| return errnoBug(err),
                    .FAULT => |err| return errnoBug(err),
                    .AGAIN => return error.WouldBlock,
                    .BADF => return error.NotOpenForWriting, // Usually a race condition.
                    .DESTADDRREQ => |err| return errnoBug(err), // `connect` was never called.
                    .DQUOT => return error.DiskQuota,
                    .FBIG => return error.FileTooBig,
                    .IO => return error.InputOutput,
                    .NOSPC => return error.NoSpaceLeft,
                    .PERM => return error.PermissionDenied,
                    .PIPE => return error.BrokenPipe,
                    .CONNRESET => |err| return errnoBug(err), // Not a socket handle.
                    .BUSY => return error.DeviceBusy,
                    .TXTBSY => return error.FileBusy,
                    .NXIO => return error.Unseekable,
                    .SPIPE => return error.Unseekable,
                    .OVERFLOW => return error.Unseekable,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn writeFilePositionalWindows(
    handle: windows.HANDLE,
    bytes: []const u8,
    offset: u64,
) File.WritePositionalError!usize {
    var bytes_written: windows.DWORD = undefined;
    var overlapped: windows.OVERLAPPED = .{
        .Internal = 0,
        .InternalHigh = 0,
        .DUMMYUNIONNAME = .{
            .DUMMYSTRUCTNAME = .{
                .Offset = @truncate(offset),
                .OffsetHigh = @truncate(offset >> 32),
            },
        },
        .hEvent = null,
    };
    const adjusted_len = std.math.lossyCast(u32, bytes.len);
    const syscall: Syscall = try .start();
    while (true) {
        if (windows.kernel32.WriteFile(handle, bytes.ptr, adjusted_len, &bytes_written, &overlapped) != 0) {
            syscall.finish();
            return bytes_written;
        }
        switch (windows.GetLastError()) {
            .OPERATION_ABORTED => {
                try syscall.checkCancel();
                continue;
            },
            .INVALID_USER_BUFFER => return syscall.fail(error.SystemResources),
            .NOT_ENOUGH_MEMORY => return syscall.fail(error.SystemResources),
            .NOT_ENOUGH_QUOTA => return syscall.fail(error.SystemResources),
            .NO_DATA => return syscall.fail(error.BrokenPipe),
            .INVALID_HANDLE => return syscall.fail(error.NotOpenForWriting),
            .LOCK_VIOLATION => return syscall.fail(error.LockViolation),
            .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
            .WORKING_SET_QUOTA => return syscall.fail(error.SystemResources),
            else => |err| {
                syscall.finish();
                return windows.unexpectedError(err);
            },
        }
    }
}

fn fileWriteStreaming(
    userdata: ?*anyopaque,
    file: File,
    header: []const u8,
    data: []const []const u8,
    splat: usize,
) File.Writer.Error!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (is_windows) {
        if (header.len != 0) {
            return writeFileStreamingWindows(file.handle, header);
        }
        for (data[0 .. data.len - 1]) |buf| {
            if (buf.len == 0) continue;
            return writeFileStreamingWindows(file.handle, buf);
        }
        const pattern = data[data.len - 1];
        if (pattern.len == 0 or splat == 0) return 0;
        return writeFileStreamingWindows(file.handle, pattern);
    }

    var iovecs: [max_iovecs_len]posix.iovec_const = undefined;
    var iovlen: iovlen_t = 0;
    addBuf(&iovecs, &iovlen, header);
    for (data[0 .. data.len - 1]) |bytes| addBuf(&iovecs, &iovlen, bytes);
    const pattern = data[data.len - 1];
    if (iovecs.len - iovlen != 0) switch (splat) {
        0 => {},
        1 => addBuf(&iovecs, &iovlen, pattern),
        else => switch (pattern.len) {
            0 => {},
            1 => {
                var backup_buffer: [splat_buffer_size]u8 = undefined;
                const splat_buffer = &backup_buffer;
                const memset_len = @min(splat_buffer.len, splat);
                const buf = splat_buffer[0..memset_len];
                @memset(buf, pattern[0]);
                addBuf(&iovecs, &iovlen, buf);
                var remaining_splat = splat - buf.len;
                while (remaining_splat > splat_buffer.len and iovecs.len - iovlen != 0) {
                    assert(buf.len == splat_buffer.len);
                    addBuf(&iovecs, &iovlen, splat_buffer);
                    remaining_splat -= splat_buffer.len;
                }
                addBuf(&iovecs, &iovlen, splat_buffer[0..@min(remaining_splat, splat_buffer.len)]);
            },
            else => for (0..@min(splat, iovecs.len - iovlen)) |_| {
                addBuf(&iovecs, &iovlen, pattern);
            },
        },
    };

    if (iovlen == 0) return 0;

    if (native_os == .wasi and !builtin.link_libc) {
        var n_written: usize = undefined;
        const syscall: Syscall = try .start();
        while (true) {
            switch (std.os.wasi.fd_write(file.handle, &iovecs, iovlen, &n_written)) {
                .SUCCESS => {
                    syscall.finish();
                    return n_written;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .INVAL => |err| return errnoBug(err),
                        .FAULT => |err| return errnoBug(err),
                        .AGAIN => |err| return errnoBug(err),
                        .BADF => return error.NotOpenForWriting, // can be a race condition.
                        .DESTADDRREQ => |err| return errnoBug(err), // `connect` was never called.
                        .DQUOT => return error.DiskQuota,
                        .FBIG => return error.FileTooBig,
                        .IO => return error.InputOutput,
                        .NOSPC => return error.NoSpaceLeft,
                        .PERM => return error.PermissionDenied,
                        .PIPE => return error.BrokenPipe,
                        .NOTCAPABLE => return error.AccessDenied,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    }

    const syscall: Syscall = try .start();
    while (true) {
        const rc = posix.system.writev(file.handle, &iovecs, @intCast(iovlen));
        switch (posix.errno(rc)) {
            .SUCCESS => {
                syscall.finish();
                return @intCast(rc);
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .INVAL => |err| return errnoBug(err),
                    .FAULT => |err| return errnoBug(err),
                    .AGAIN => return error.WouldBlock,
                    .BADF => return error.NotOpenForWriting, // Can be a race condition.
                    .DESTADDRREQ => |err| return errnoBug(err), // `connect` was never called.
                    .DQUOT => return error.DiskQuota,
                    .FBIG => return error.FileTooBig,
                    .IO => return error.InputOutput,
                    .NOSPC => return error.NoSpaceLeft,
                    .PERM => return error.PermissionDenied,
                    .PIPE => return error.BrokenPipe,
                    .CONNRESET => |err| return errnoBug(err), // Not a socket handle.
                    .BUSY => return error.DeviceBusy,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn writeFileStreamingWindows(
    handle: windows.HANDLE,
    bytes: []const u8,
) File.Writer.Error!usize {
    var bytes_written: windows.DWORD = undefined;
    const adjusted_len = std.math.lossyCast(u32, bytes.len);
    const syscall: Syscall = try .start();
    while (true) {
        if (windows.kernel32.WriteFile(handle, bytes.ptr, adjusted_len, &bytes_written, null) != 0) {
            syscall.finish();
            return bytes_written;
        }
        switch (windows.GetLastError()) {
            .OPERATION_ABORTED => {
                try syscall.checkCancel();
                continue;
            },
            .INVALID_USER_BUFFER => return syscall.fail(error.SystemResources),
            .NOT_ENOUGH_MEMORY => return syscall.fail(error.SystemResources),
            .NOT_ENOUGH_QUOTA => return syscall.fail(error.SystemResources),
            .NO_DATA => return syscall.fail(error.BrokenPipe),
            .INVALID_HANDLE => return syscall.fail(error.NotOpenForWriting),
            .LOCK_VIOLATION => return syscall.fail(error.LockViolation),
            .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
            .WORKING_SET_QUOTA => return syscall.fail(error.SystemResources),
            else => |err| {
                syscall.finish();
                return windows.unexpectedError(err);
            },
        }
    }
}

fn fileWriteFileStreaming(
    userdata: ?*anyopaque,
    file: File,
    header: []const u8,
    file_reader: *File.Reader,
    limit: Io.Limit,
) File.Writer.WriteFileError!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const reader_buffered = file_reader.interface.buffered();
    if (reader_buffered.len >= @intFromEnum(limit)) {
        const n = try fileWriteStreaming(t, file, header, &.{limit.slice(reader_buffered)}, 1);
        file_reader.interface.toss(n -| header.len);
        return n;
    }
    const file_limit = @intFromEnum(limit) - reader_buffered.len;
    const out_fd = file.handle;
    const in_fd = file_reader.file.handle;

    if (file_reader.size) |size| {
        if (size - file_reader.pos == 0) {
            if (reader_buffered.len != 0) {
                const n = try fileWriteStreaming(t, file, header, &.{limit.slice(reader_buffered)}, 1);
                file_reader.interface.toss(n -| header.len);
                return n;
            } else {
                return error.EndOfStream;
            }
        }
    }

    if (native_os == .freebsd) sf: {
        // Try using sendfile on FreeBSD.
        if (@atomicLoad(UseSendfile, &t.use_sendfile, .monotonic) == .disabled) break :sf;
        const offset = std.math.cast(std.c.off_t, file_reader.pos) orelse break :sf;
        var hdtr_data: std.c.sf_hdtr = undefined;
        var headers: [2]posix.iovec_const = undefined;
        var headers_i: u8 = 0;
        if (header.len != 0) {
            headers[headers_i] = .{ .base = header.ptr, .len = header.len };
            headers_i += 1;
        }
        if (reader_buffered.len != 0) {
            headers[headers_i] = .{ .base = reader_buffered.ptr, .len = reader_buffered.len };
            headers_i += 1;
        }
        const hdtr: ?*std.c.sf_hdtr = if (headers_i == 0) null else b: {
            hdtr_data = .{
                .headers = &headers,
                .hdr_cnt = headers_i,
                .trailers = null,
                .trl_cnt = 0,
            };
            break :b &hdtr_data;
        };
        var sbytes: std.c.off_t = 0;
        const nbytes: usize = @min(file_limit, std.math.maxInt(usize));
        const flags = 0;

        const syscall: Syscall = try .start();
        while (true) {
            switch (posix.errno(std.c.sendfile(in_fd, out_fd, offset, nbytes, hdtr, &sbytes, flags))) {
                .SUCCESS => {
                    syscall.finish();
                    break;
                },
                .INVAL, .OPNOTSUPP, .NOTSOCK, .NOSYS => {
                    // Give calling code chance to observe before trying
                    // something else.
                    syscall.finish();
                    @atomicStore(UseSendfile, &t.use_sendfile, .disabled, .monotonic);
                    return 0;
                },
                .INTR, .BUSY => {
                    if (sbytes == 0) {
                        try syscall.checkCancel();
                        continue;
                    } else {
                        // Even if we are being canceled, there have been side
                        // effects, so it is better to report those side
                        // effects to the caller.
                        syscall.finish();
                        break;
                    }
                },
                .AGAIN => {
                    syscall.finish();
                    if (sbytes == 0) return error.WouldBlock;
                    break;
                },
                else => |e| {
                    syscall.finish();
                    assert(error.Unexpected == switch (e) {
                        .NOTCONN => return error.BrokenPipe,
                        .IO => return error.InputOutput,
                        .PIPE => return error.BrokenPipe,
                        .NOBUFS => return error.SystemResources,
                        .BADF => |err| errnoBug(err),
                        .FAULT => |err| errnoBug(err),
                        else => |err| posix.unexpectedErrno(err),
                    });
                    // Give calling code chance to observe the error before trying
                    // something else.
                    @atomicStore(UseSendfile, &t.use_sendfile, .disabled, .monotonic);
                    return 0;
                },
            }
        }
        if (sbytes == 0) {
            file_reader.size = file_reader.pos;
            return error.EndOfStream;
        }
        const ubytes: usize = @intCast(sbytes);
        file_reader.interface.toss(ubytes -| header.len);
        return ubytes;
    }

    if (is_darwin) sf: {
        // Try using sendfile on macOS.
        if (@atomicLoad(UseSendfile, &t.use_sendfile, .monotonic) == .disabled) break :sf;
        const offset = std.math.cast(std.c.off_t, file_reader.pos) orelse break :sf;
        var hdtr_data: std.c.sf_hdtr = undefined;
        var headers: [2]posix.iovec_const = undefined;
        var headers_i: u8 = 0;
        if (header.len != 0) {
            headers[headers_i] = .{ .base = header.ptr, .len = header.len };
            headers_i += 1;
        }
        if (reader_buffered.len != 0) {
            headers[headers_i] = .{ .base = reader_buffered.ptr, .len = reader_buffered.len };
            headers_i += 1;
        }
        const hdtr: ?*std.c.sf_hdtr = if (headers_i == 0) null else b: {
            hdtr_data = .{
                .headers = &headers,
                .hdr_cnt = headers_i,
                .trailers = null,
                .trl_cnt = 0,
            };
            break :b &hdtr_data;
        };
        const max_count = std.math.maxInt(i32); // Avoid EINVAL.
        var len: std.c.off_t = @min(file_limit, max_count);
        const flags = 0;
        const syscall: Syscall = try .start();
        while (true) {
            switch (posix.errno(std.c.sendfile(in_fd, out_fd, offset, &len, hdtr, flags))) {
                .SUCCESS => {
                    syscall.finish();
                    break;
                },
                .OPNOTSUPP, .NOTSOCK, .NOSYS => {
                    // Give calling code chance to observe before trying
                    // something else.
                    syscall.finish();
                    @atomicStore(UseSendfile, &t.use_sendfile, .disabled, .monotonic);
                    return 0;
                },
                .INTR => {
                    if (len == 0) {
                        try syscall.checkCancel();
                        continue;
                    } else {
                        // Even if we are being canceled, there have been side
                        // effects, so it is better to report those side
                        // effects to the caller.
                        syscall.finish();
                        break;
                    }
                },
                .AGAIN => {
                    syscall.finish();
                    if (len == 0) return error.WouldBlock;
                    break;
                },
                else => |e| {
                    syscall.finish();
                    assert(error.Unexpected == switch (e) {
                        .NOTCONN => return error.BrokenPipe,
                        .IO => return error.InputOutput,
                        .PIPE => return error.BrokenPipe,
                        .BADF => |err| errnoBug(err),
                        .FAULT => |err| errnoBug(err),
                        .INVAL => |err| errnoBug(err),
                        else => |err| posix.unexpectedErrno(err),
                    });
                    // Give calling code chance to observe the error before trying
                    // something else.
                    @atomicStore(UseSendfile, &t.use_sendfile, .disabled, .monotonic);
                    return 0;
                },
            }
        }
        if (len == 0) {
            file_reader.size = file_reader.pos;
            return error.EndOfStream;
        }
        const u_len: usize = @bitCast(len);
        file_reader.interface.toss(u_len -| header.len);
        return u_len;
    }

    if (native_os == .linux) sf: {
        // Try using sendfile on Linux.
        if (@atomicLoad(UseSendfile, &t.use_sendfile, .monotonic) == .disabled) break :sf;
        // Linux sendfile does not support headers.
        if (header.len != 0 or reader_buffered.len != 0) {
            const n = try fileWriteStreaming(t, file, header, &.{limit.slice(reader_buffered)}, 1);
            file_reader.interface.toss(n -| header.len);
            return n;
        }
        const max_count = 0x7ffff000; // Avoid EINVAL.
        var off: std.os.linux.off_t = undefined;
        const off_ptr: ?*std.os.linux.off_t, const count: usize = switch (file_reader.mode) {
            .positional => o: {
                const size = file_reader.getSize() catch return 0;
                off = std.math.cast(std.os.linux.off_t, file_reader.pos) orelse return error.ReadFailed;
                break :o .{ &off, @min(@intFromEnum(limit), size - file_reader.pos, max_count) };
            },
            .streaming => .{ null, limit.minInt(max_count) },
            .streaming_simple, .positional_simple => break :sf,
            .failure => return error.ReadFailed,
        };
        const syscall: Syscall = try .start();
        const n: usize = while (true) {
            const rc = sendfile_sym(out_fd, in_fd, off_ptr, count);
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    syscall.finish();
                    break @intCast(rc);
                },
                .NOSYS, .INVAL => {
                    // Give calling code chance to observe before trying
                    // something else.
                    syscall.finish();
                    @atomicStore(UseSendfile, &t.use_sendfile, .disabled, .monotonic);
                    return 0;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    assert(error.Unexpected == switch (e) {
                        .NOTCONN => return error.BrokenPipe, // `out_fd` is an unconnected socket
                        .AGAIN => return error.WouldBlock,
                        .IO => return error.InputOutput,
                        .PIPE => return error.BrokenPipe,
                        .NOMEM => return error.SystemResources,
                        .NXIO, .SPIPE => {
                            file_reader.mode = file_reader.mode.toStreaming();
                            const pos = file_reader.pos;
                            if (pos != 0) {
                                file_reader.pos = 0;
                                file_reader.seekBy(@intCast(pos)) catch {
                                    file_reader.mode = .failure;
                                    return error.ReadFailed;
                                };
                            }
                            return 0;
                        },
                        .BADF => |err| errnoBug(err), // Always a race condition.
                        .FAULT => |err| errnoBug(err), // Segmentation fault.
                        .OVERFLOW => |err| errnoBug(err), // We avoid passing too large of a `count`.
                        else => |err| posix.unexpectedErrno(err),
                    });
                    // Give calling code chance to observe the error before trying
                    // something else.
                    @atomicStore(UseSendfile, &t.use_sendfile, .disabled, .monotonic);
                    return 0;
                },
            }
        };
        if (n == 0) {
            file_reader.size = file_reader.pos;
            return error.EndOfStream;
        }
        file_reader.pos += n;
        return n;
    }

    if (have_copy_file_range) cfr: {
        if (@atomicLoad(UseCopyFileRange, &t.use_copy_file_range, .monotonic) == .disabled) break :cfr;
        if (header.len != 0 or reader_buffered.len != 0) {
            const n = try fileWriteStreaming(t, file, header, &.{limit.slice(reader_buffered)}, 1);
            file_reader.interface.toss(n -| header.len);
            return n;
        }
        var off_in: i64 = undefined;
        const off_in_ptr: ?*i64 = switch (file_reader.mode) {
            .positional_simple, .streaming_simple => return error.Unimplemented,
            .positional => p: {
                off_in = @intCast(file_reader.pos);
                break :p &off_in;
            },
            .streaming => null,
            .failure => return error.ReadFailed,
        };
        const n: usize = switch (native_os) {
            .linux => n: {
                const syscall: Syscall = try .start();
                while (true) {
                    const rc = linux_copy_file_range_sys.copy_file_range(in_fd, off_in_ptr, out_fd, null, @intFromEnum(limit), 0);
                    switch (linux_copy_file_range_sys.errno(rc)) {
                        .SUCCESS => {
                            syscall.finish();
                            break :n @intCast(rc);
                        },
                        .INTR => {
                            try syscall.checkCancel();
                            continue;
                        },
                        .OPNOTSUPP, .INVAL, .NOSYS => {
                            // Give calling code chance to observe before trying
                            // something else.
                            syscall.finish();
                            @atomicStore(UseCopyFileRange, &t.use_copy_file_range, .disabled, .monotonic);
                            return 0;
                        },
                        else => |e| {
                            syscall.finish();
                            assert(error.Unexpected == switch (e) {
                                .FBIG => return error.FileTooBig,
                                .IO => return error.InputOutput,
                                .NOMEM => return error.SystemResources,
                                .NOSPC => return error.NoSpaceLeft,
                                .OVERFLOW => |err| errnoBug(err), // We avoid passing too large a count.
                                .PERM => return error.PermissionDenied,
                                .BUSY => return error.DeviceBusy,
                                .TXTBSY => return error.FileBusy,
                                // copy_file_range can still work but not on
                                // this pair of file descriptors.
                                .XDEV => return error.Unimplemented,
                                .ISDIR => |err| errnoBug(err),
                                .BADF => |err| errnoBug(err),
                                else => |err| posix.unexpectedErrno(err),
                            });
                            @atomicStore(UseCopyFileRange, &t.use_copy_file_range, .disabled, .monotonic);
                            return 0;
                        },
                    }
                }
            },
            .freebsd => n: {
                const syscall: Syscall = try .start();
                while (true) {
                    const rc = std.c.copy_file_range(in_fd, off_in_ptr, out_fd, null, @intFromEnum(limit), 0);
                    switch (std.c.errno(rc)) {
                        .SUCCESS => {
                            syscall.finish();
                            break :n @intCast(rc);
                        },
                        .INTR => {
                            try syscall.checkCancel();
                            continue;
                        },
                        .OPNOTSUPP, .INVAL, .NOSYS => {
                            // Give calling code chance to observe before trying
                            // something else.
                            syscall.finish();
                            @atomicStore(UseCopyFileRange, &t.use_copy_file_range, .disabled, .monotonic);
                            return 0;
                        },
                        else => |e| {
                            syscall.finish();
                            assert(error.Unexpected == switch (e) {
                                .FBIG => return error.FileTooBig,
                                .IO => return error.InputOutput,
                                .INTEGRITY => return error.CorruptedData,
                                .NOSPC => return error.NoSpaceLeft,
                                .ISDIR => |err| errnoBug(err),
                                .BADF => |err| errnoBug(err),
                                else => |err| posix.unexpectedErrno(err),
                            });
                            @atomicStore(UseCopyFileRange, &t.use_copy_file_range, .disabled, .monotonic);
                            return 0;
                        },
                    }
                }
            },
            else => comptime unreachable,
        };
        if (n == 0) {
            file_reader.size = file_reader.pos;
            return error.EndOfStream;
        }
        file_reader.pos += n;
        return n;
    }

    return error.Unimplemented;
}

fn netWriteFile(
    userdata: ?*anyopaque,
    socket_handle: net.Socket.Handle,
    header: []const u8,
    file_reader: *File.Reader,
    limit: Io.Limit,
) net.Stream.Writer.WriteFileError!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    _ = socket_handle;
    _ = header;
    _ = file_reader;
    _ = limit;
    @panic("TODO implement netWriteFile");
}

fn netWriteFileUnavailable(
    userdata: ?*anyopaque,
    socket_handle: net.Socket.Handle,
    header: []const u8,
    file_reader: *File.Reader,
    limit: Io.Limit,
) net.Stream.Writer.WriteFileError!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    _ = socket_handle;
    _ = header;
    _ = file_reader;
    _ = limit;
    return error.NetworkDown;
}

fn fileWriteFilePositional(
    userdata: ?*anyopaque,
    file: File,
    header: []const u8,
    file_reader: *File.Reader,
    limit: Io.Limit,
    offset: u64,
) File.WriteFilePositionalError!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const reader_buffered = file_reader.interface.buffered();
    if (reader_buffered.len >= @intFromEnum(limit)) {
        const n = try fileWritePositional(t, file, header, &.{limit.slice(reader_buffered)}, 1, offset);
        file_reader.interface.toss(n -| header.len);
        return n;
    }
    const out_fd = file.handle;
    const in_fd = file_reader.file.handle;

    if (file_reader.size) |size| {
        if (size - file_reader.pos == 0) {
            if (reader_buffered.len != 0) {
                const n = try fileWritePositional(t, file, header, &.{limit.slice(reader_buffered)}, 1, offset);
                file_reader.interface.toss(n -| header.len);
                return n;
            } else {
                return error.EndOfStream;
            }
        }
    }

    if (have_copy_file_range) cfr: {
        if (@atomicLoad(UseCopyFileRange, &t.use_copy_file_range, .monotonic) == .disabled) break :cfr;
        if (header.len != 0 or reader_buffered.len != 0) {
            const n = try fileWritePositional(t, file, header, &.{limit.slice(reader_buffered)}, 1, offset);
            file_reader.interface.toss(n -| header.len);
            return n;
        }
        var off_in: i64 = undefined;
        const off_in_ptr: ?*i64 = switch (file_reader.mode) {
            .positional_simple, .streaming_simple => return error.Unimplemented,
            .positional => p: {
                off_in = @intCast(file_reader.pos);
                break :p &off_in;
            },
            .streaming => null,
            .failure => return error.ReadFailed,
        };
        var off_out: i64 = @intCast(offset);
        const n: usize = switch (native_os) {
            .linux => n: {
                const syscall: Syscall = try .start();
                while (true) {
                    const rc = linux_copy_file_range_sys.copy_file_range(in_fd, off_in_ptr, out_fd, &off_out, @intFromEnum(limit), 0);
                    switch (linux_copy_file_range_sys.errno(rc)) {
                        .SUCCESS => {
                            syscall.finish();
                            break :n @intCast(rc);
                        },
                        .INTR => {
                            try syscall.checkCancel();
                            continue;
                        },
                        .OPNOTSUPP, .INVAL, .NOSYS => {
                            // Give calling code chance to observe before trying
                            // something else.
                            syscall.finish();
                            @atomicStore(UseCopyFileRange, &t.use_copy_file_range, .disabled, .monotonic);
                            return 0;
                        },
                        else => |e| {
                            syscall.finish();
                            assert(error.Unexpected == switch (e) {
                                .FBIG => return error.FileTooBig,
                                .IO => return error.InputOutput,
                                .NOMEM => return error.SystemResources,
                                .NOSPC => return error.NoSpaceLeft,
                                .OVERFLOW => return error.Unseekable,
                                .NXIO => return error.Unseekable,
                                .SPIPE => return error.Unseekable,
                                .PERM => return error.PermissionDenied,
                                .TXTBSY => return error.FileBusy,
                                // copy_file_range can still work but not on
                                // this pair of file descriptors.
                                .XDEV => return error.Unimplemented,
                                .ISDIR => |err| errnoBug(err),
                                .BADF => |err| errnoBug(err),
                                else => |err| posix.unexpectedErrno(err),
                            });
                            @atomicStore(UseCopyFileRange, &t.use_copy_file_range, .disabled, .monotonic);
                            return 0;
                        },
                    }
                }
            },
            .freebsd => n: {
                const syscall: Syscall = try .start();
                while (true) {
                    const rc = std.c.copy_file_range(in_fd, off_in_ptr, out_fd, &off_out, @intFromEnum(limit), 0);
                    switch (std.c.errno(rc)) {
                        .SUCCESS => {
                            syscall.finish();
                            break :n @intCast(rc);
                        },
                        .INTR => {
                            try syscall.checkCancel();
                            continue;
                        },
                        .OPNOTSUPP, .INVAL, .NOSYS => {
                            // Give calling code chance to observe before trying
                            // something else.
                            syscall.finish();
                            @atomicStore(UseCopyFileRange, &t.use_copy_file_range, .disabled, .monotonic);
                            return 0;
                        },
                        else => |e| {
                            syscall.finish();
                            assert(error.Unexpected == switch (e) {
                                .FBIG => return error.FileTooBig,
                                .IO => return error.InputOutput,
                                .INTEGRITY => return error.CorruptedData,
                                .NOSPC => return error.NoSpaceLeft,
                                .OVERFLOW => return error.Unseekable,
                                .NXIO => return error.Unseekable,
                                .SPIPE => return error.Unseekable,
                                .ISDIR => |err| errnoBug(err),
                                .BADF => |err| errnoBug(err),
                                else => |err| posix.unexpectedErrno(err),
                            });
                            @atomicStore(UseCopyFileRange, &t.use_copy_file_range, .disabled, .monotonic);
                            return 0;
                        },
                    }
                }
            },
            else => comptime unreachable,
        };
        if (n == 0) {
            file_reader.size = file_reader.pos;
            return error.EndOfStream;
        }
        file_reader.pos += n;
        return n;
    }

    if (is_darwin) fcf: {
        if (@atomicLoad(UseFcopyfile, &t.use_fcopyfile, .monotonic) == .disabled) break :fcf;
        if (file_reader.pos != 0) break :fcf;
        if (offset != 0) break :fcf;
        if (limit != .unlimited) break :fcf;
        const size = file_reader.getSize() catch break :fcf;
        if (header.len != 0 or reader_buffered.len != 0) {
            const n = try fileWritePositional(t, file, header, &.{limit.slice(reader_buffered)}, 1, offset);
            file_reader.interface.toss(n -| header.len);
            return n;
        }
        const syscall: Syscall = try .start();
        while (true) {
            const rc = std.c.fcopyfile(in_fd, out_fd, null, .{ .DATA = true });
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    syscall.finish();
                    break;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                .OPNOTSUPP => {
                    // Give calling code chance to observe before trying
                    // something else.
                    syscall.finish();
                    @atomicStore(UseFcopyfile, &t.use_fcopyfile, .disabled, .monotonic);
                    return 0;
                },
                else => |e| {
                    syscall.finish();
                    assert(error.Unexpected == switch (e) {
                        .NOMEM => return error.SystemResources,
                        .INVAL => |err| errnoBug(err),
                        else => |err| posix.unexpectedErrno(err),
                    });
                    return 0;
                },
            }
        }
        file_reader.pos = size;
        return size;
    }

    return error.Unimplemented;
}

fn nowPosix(clock: Io.Clock) Io.Clock.Error!Io.Timestamp {
    const clock_id: posix.clockid_t = clockToPosix(clock);
    var tp: posix.timespec = undefined;
    switch (posix.errno(posix.system.clock_gettime(clock_id, &tp))) {
        .SUCCESS => return timestampFromPosix(&tp),
        .INVAL => return error.UnsupportedClock,
        else => |err| return posix.unexpectedErrno(err),
    }
}

fn now(userdata: ?*anyopaque, clock: Io.Clock) Io.Clock.Error!Io.Timestamp {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    return switch (native_os) {
        .windows => nowWindows(clock),
        .wasi => nowWasi(clock),
        else => nowPosix(clock),
    };
}

fn nowWindows(clock: Io.Clock) Io.Clock.Error!Io.Timestamp {
    switch (clock) {
        .real => {
            // RtlGetSystemTimePrecise() has a granularity of 100 nanoseconds
            // and uses the NTFS/Windows epoch, which is 1601-01-01.
            const epoch_ns = std.time.epoch.windows * std.time.ns_per_s;
            return .{ .nanoseconds = @as(i96, windows.ntdll.RtlGetSystemTimePrecise()) * 100 + epoch_ns };
        },
        .awake, .boot => {
            // QPC on windows doesn't fail on >= XP/2000 and includes time suspended.
            const qpc = windows.QueryPerformanceCounter();
            // We don't need to cache QPF as it's internally just a memory read to KUSER_SHARED_DATA
            // (a read-only page of info updated and mapped by the kernel to all processes):
            // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-kuser_shared_data
            // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi_x/kuser_shared_data/index.htm
            const qpf = windows.QueryPerformanceFrequency();

            // 10Mhz (1 qpc tick every 100ns) is a common enough QPF value that we can optimize on it.
            // https://github.com/microsoft/STL/blob/785143a0c73f030238ef618890fd4d6ae2b3a3a0/stl/inc/chrono#L694-L701
            const common_qpf = 10_000_000;
            if (qpf == common_qpf) return .{ .nanoseconds = qpc * (std.time.ns_per_s / common_qpf) };

            // Convert to ns using fixed point.
            const scale = @as(u64, std.time.ns_per_s << 32) / @as(u32, @intCast(qpf));
            const result = (@as(u96, qpc) * scale) >> 32;
            return .{ .nanoseconds = @intCast(result) };
        },
        .cpu_process,
        .cpu_thread,
        => return error.UnsupportedClock,
    }
}

fn nowWasi(clock: Io.Clock) Io.Clock.Error!Io.Timestamp {
    var ns: std.os.wasi.timestamp_t = undefined;
    const err = std.os.wasi.clock_time_get(clockToWasi(clock), 1, &ns);
    if (err != .SUCCESS) return error.Unexpected;
    return .fromNanoseconds(ns);
}

fn sleep(userdata: ?*anyopaque, timeout: Io.Timeout) Io.SleepError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    if (use_parking_sleep) return parking_sleep.sleep(timeout);
    switch (native_os) {
        .wasi => return sleepWasi(t, timeout),
        .linux => return sleepLinux(timeout),
        else => return sleepPosix(t, timeout),
    }
}

fn sleepLinux(timeout: Io.Timeout) Io.SleepError!void {
    const clock_id: posix.clockid_t = clockToPosix(switch (timeout) {
        .none => .awake,
        .duration => |d| d.clock,
        .deadline => |d| d.clock,
    });
    const deadline_nanoseconds: i96 = switch (timeout) {
        .none => std.math.maxInt(i96),
        .duration => |duration| duration.raw.nanoseconds,
        .deadline => |deadline| deadline.raw.nanoseconds,
    };
    var timespec: posix.timespec = timestampToPosix(deadline_nanoseconds);
    const syscall: Syscall = try .start();
    while (true) {
        switch (std.os.linux.errno(std.os.linux.clock_nanosleep(clock_id, .{ .ABSTIME = switch (timeout) {
            .none, .duration => false,
            .deadline => true,
        } }, &timespec, &timespec))) {
            .SUCCESS => {
                syscall.finish();
                return;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .INVAL => return error.UnsupportedClock,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn sleepWasi(t: *Threaded, timeout: Io.Timeout) Io.SleepError!void {
    const t_io = ioBasic(t);
    const w = std.os.wasi;

    const clock: w.subscription_clock_t = if (try timeout.toDurationFromNow(t_io)) |d| .{
        .id = clockToWasi(d.clock),
        .timeout = std.math.lossyCast(u64, d.raw.nanoseconds),
        .precision = 0,
        .flags = 0,
    } else .{
        .id = .MONOTONIC,
        .timeout = std.math.maxInt(u64),
        .precision = 0,
        .flags = 0,
    };
    const in: w.subscription_t = .{
        .userdata = 0,
        .u = .{
            .tag = .CLOCK,
            .u = .{ .clock = clock },
        },
    };
    var event: w.event_t = undefined;
    var nevents: usize = undefined;
    const syscall: Syscall = try .start();
    _ = w.poll_oneoff(&in, &event, 1, &nevents);
    syscall.finish();
}

fn sleepPosix(t: *Threaded, timeout: Io.Timeout) Io.SleepError!void {
    const t_io = ioBasic(t);
    const sec_type = @typeInfo(posix.timespec).@"struct".fields[0].type;
    const nsec_type = @typeInfo(posix.timespec).@"struct".fields[1].type;

    var timespec: posix.timespec = t: {
        const d = (try timeout.toDurationFromNow(t_io)) orelse break :t .{
            .sec = std.math.maxInt(sec_type),
            .nsec = std.math.maxInt(nsec_type),
        };
        break :t timestampToPosix(d.raw.toNanoseconds());
    };
    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.nanosleep(&timespec, &timespec))) {
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            // This prong handles success as well as unexpected errors.
            else => return syscall.finish(),
        }
    }
}

fn select(userdata: ?*anyopaque, futures: []const *Io.AnyFuture) Io.Cancelable!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var num_completed: std.atomic.Value(u32) = .init(0);

    for (futures, 0..) |any_future, i| {
        const future: *Future = @ptrCast(@alignCast(any_future));
        future.awaiter = &num_completed;
        const old_status = future.status.fetchOr(
            .{ .tag = .pending_awaited, .thread = .null },
            .release, // release `future.awaiter`
        );
        switch (old_status.tag) {
            .pending => {},
            .pending_awaited => unreachable, // `await` raced with `select`
            .pending_canceled => unreachable, // `cancel` raced with `select`
            .done => {
                future.status.store(old_status, .monotonic);
                _ = finishSelect(&num_completed, futures[0..i]);
                return i;
            },
        }
    }

    errdefer _ = finishSelect(&num_completed, futures);

    while (true) {
        const n = num_completed.load(.acquire);
        if (n > 0) break;
        assert(n < futures.len);
        try Thread.futexWait(&num_completed.raw, n, null);
    }
    return finishSelect(&num_completed, futures).?;
}
fn finishSelect(
    num_completed: *std.atomic.Value(u32),
    futures: []const *Io.AnyFuture,
) ?usize {
    var completed_index: ?usize = null;
    var expect_completed: u32 = 0;
    for (futures, 0..) |any_future, i| {
        const future: *Future = @ptrCast(@alignCast(any_future));
        // This operation will convert `.pending_awaited` to `.pending`, or leave `.done` untouched.
        switch (future.status.fetchAnd(
            .{ .tag = @enumFromInt(0b10), .thread = .all_ones },
            .monotonic,
        ).tag) {
            .pending_awaited => {},
            .pending => unreachable,
            .pending_canceled => unreachable,
            .done => {
                expect_completed += 1;
                completed_index = i;
            },
        }
    }
    // If any future has just finished, wait for it to signal `num_completed` to avoid dangling
    // references to stack memory.
    while (true) {
        const n = num_completed.load(.acquire);
        if (n == expect_completed) break;
        assert(n < expect_completed);
        Thread.futexWaitUncancelable(&num_completed.raw, n, null);
    }
    return completed_index;
}

fn netListenIpPosix(
    userdata: ?*anyopaque,
    address: IpAddress,
    options: IpAddress.ListenOptions,
) IpAddress.ListenError!net.Server {
    if (!have_networking) return error.NetworkDown;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const family = posixAddressFamily(&address);
    const socket_fd = try openSocketPosix(family, .{
        .mode = options.mode,
        .protocol = options.protocol,
    });
    errdefer posix.close(socket_fd);

    if (options.reuse_address) {
        try setSocketOption(socket_fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, 1);
        if (@hasDecl(posix.SO, "REUSEPORT"))
            try setSocketOption(socket_fd, posix.SOL.SOCKET, posix.SO.REUSEPORT, 1);
    }

    var storage: PosixAddress = undefined;
    var addr_len = addressToPosix(&address, &storage);
    try posixBind(socket_fd, &storage.any, addr_len);

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.listen(socket_fd, options.kernel_backlog))) {
            .SUCCESS => {
                syscall.finish();
                break;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ADDRINUSE => return error.AddressInUse,
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }

    try posixGetSockName(socket_fd, &storage.any, &addr_len);
    return .{
        .socket = .{
            .handle = socket_fd,
            .address = addressFromPosix(&storage),
        },
    };
}

fn netListenIpWindows(
    userdata: ?*anyopaque,
    address: IpAddress,
    options: IpAddress.ListenOptions,
) IpAddress.ListenError!net.Server {
    if (!have_networking) return error.NetworkDown;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const family = posixAddressFamily(&address);
    const socket_handle = try openSocketWsa(t, family, .{
        .mode = options.mode,
        .protocol = options.protocol,
    });
    errdefer closeSocketWindows(socket_handle);

    if (options.reuse_address)
        try setSocketOptionWsa(t, socket_handle, posix.SOL.SOCKET, posix.SO.REUSEADDR, 1);

    var storage: WsaAddress = undefined;
    var addr_len = addressToWsa(&address, &storage);

    var syscall: Syscall = try .start();
    while (true) {
        const rc = ws2_32.bind(socket_handle, &storage.any, addr_len);
        if (rc != ws2_32.SOCKET_ERROR) {
            syscall.finish();
            break;
        }
        switch (ws2_32.WSAGetLastError()) {
            .NOTINITIALISED => {
                syscall.finish();
                try initializeWsa(t);
                syscall = try .start();
                continue;
            },
            .EINTR, .ECANCELLED, .E_CANCELLED, .OPERATION_ABORTED => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .EADDRINUSE => return error.AddressInUse,
                    .EADDRNOTAVAIL => return error.AddressUnavailable,
                    .ENOTSOCK => |err| return wsaErrorBug(err),
                    .EFAULT => |err| return wsaErrorBug(err),
                    .EINVAL => |err| return wsaErrorBug(err),
                    .ENOBUFS => return error.SystemResources,
                    .ENETDOWN => return error.NetworkDown,
                    else => |err| return windows.unexpectedWSAError(err),
                }
            },
        }
    }

    syscall = try .start();
    while (true) {
        const rc = ws2_32.listen(socket_handle, options.kernel_backlog);
        if (rc != ws2_32.SOCKET_ERROR) {
            syscall.finish();
            break;
        }
        switch (ws2_32.WSAGetLastError()) {
            .NOTINITIALISED => {
                syscall.finish();
                try initializeWsa(t);
                syscall = try .start();
                continue;
            },
            .EINTR, .ECANCELLED, .E_CANCELLED, .OPERATION_ABORTED => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ENETDOWN => return error.NetworkDown,
                    .EADDRINUSE => return error.AddressInUse,
                    .EISCONN => |err| return wsaErrorBug(err),
                    .EINVAL => |err| return wsaErrorBug(err),
                    .EMFILE, .ENOBUFS => return error.SystemResources,
                    .ENOTSOCK => |err| return wsaErrorBug(err),
                    .EOPNOTSUPP => |err| return wsaErrorBug(err),
                    .EINPROGRESS => |err| return wsaErrorBug(err),
                    else => |err| return windows.unexpectedWSAError(err),
                }
            },
        }
    }

    try wsaGetSockName(t, socket_handle, &storage.any, &addr_len);

    return .{
        .socket = .{
            .handle = socket_handle,
            .address = addressFromWsa(&storage),
        },
    };
}

fn netListenIpUnavailable(
    userdata: ?*anyopaque,
    address: IpAddress,
    options: IpAddress.ListenOptions,
) IpAddress.ListenError!net.Server {
    _ = userdata;
    _ = address;
    _ = options;
    return error.NetworkDown;
}

fn netListenUnixPosix(
    userdata: ?*anyopaque,
    address: *const net.UnixAddress,
    options: net.UnixAddress.ListenOptions,
) net.UnixAddress.ListenError!net.Socket.Handle {
    if (!net.has_unix_sockets) return error.AddressFamilyUnsupported;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const socket_fd = openSocketPosix(posix.AF.UNIX, .{ .mode = .stream }) catch |err| switch (err) {
        error.ProtocolUnsupportedBySystem => return error.AddressFamilyUnsupported,
        error.ProtocolUnsupportedByAddressFamily => return error.AddressFamilyUnsupported,
        error.SocketModeUnsupported => return error.AddressFamilyUnsupported,
        error.OptionUnsupported => return error.Unexpected,
        else => |e| return e,
    };
    errdefer posix.close(socket_fd);

    var storage: UnixAddress = undefined;
    const addr_len = addressUnixToPosix(address, &storage);
    try posixBindUnix(socket_fd, &storage.any, addr_len);

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.listen(socket_fd, options.kernel_backlog))) {
            .SUCCESS => {
                syscall.finish();
                break;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ADDRINUSE => return error.AddressInUse,
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }

    return socket_fd;
}

fn netListenUnixWindows(
    userdata: ?*anyopaque,
    address: *const net.UnixAddress,
    options: net.UnixAddress.ListenOptions,
) net.UnixAddress.ListenError!net.Socket.Handle {
    if (!net.has_unix_sockets) return error.AddressFamilyUnsupported;
    const t: *Threaded = @ptrCast(@alignCast(userdata));

    const socket_handle = openSocketWsa(t, posix.AF.UNIX, .{ .mode = .stream }) catch |err| switch (err) {
        error.ProtocolUnsupportedByAddressFamily => return error.AddressFamilyUnsupported,
        else => |e| return e,
    };
    errdefer closeSocketWindows(socket_handle);

    var storage: WsaAddress = undefined;
    const addr_len = addressUnixToWsa(address, &storage);

    var syscall: Syscall = try .start();
    while (true) {
        const rc = ws2_32.bind(socket_handle, &storage.any, addr_len);
        if (rc != ws2_32.SOCKET_ERROR) break;
        switch (ws2_32.WSAGetLastError()) {
            .NOTINITIALISED => {
                syscall.finish();
                try initializeWsa(t);
                syscall = try .start();
                continue;
            },
            .EINTR, .ECANCELLED, .E_CANCELLED, .OPERATION_ABORTED => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .EADDRINUSE => return error.AddressInUse,
                    .EADDRNOTAVAIL => return error.AddressUnavailable,
                    .ENOTSOCK => |err| return wsaErrorBug(err),
                    .EFAULT => |err| return wsaErrorBug(err),
                    .EINVAL => |err| return wsaErrorBug(err),
                    .ENOBUFS => return error.SystemResources,
                    .ENETDOWN => return error.NetworkDown,
                    else => |err| return windows.unexpectedWSAError(err),
                }
            },
        }
    }

    while (true) {
        try syscall.checkCancel();
        const rc = ws2_32.listen(socket_handle, options.kernel_backlog);
        if (rc != ws2_32.SOCKET_ERROR) {
            syscall.finish();
            return socket_handle;
        }
        switch (ws2_32.WSAGetLastError()) {
            .EINTR, .ECANCELLED, .E_CANCELLED, .OPERATION_ABORTED => continue,
            .NOTINITIALISED => {
                syscall.finish();
                try initializeWsa(t);
                syscall = try .start();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ENETDOWN => return error.NetworkDown,
                    .EADDRINUSE => return error.AddressInUse,
                    .EISCONN => |err| return wsaErrorBug(err),
                    .EINVAL => |err| return wsaErrorBug(err),
                    .EMFILE, .ENOBUFS => return error.SystemResources,
                    .ENOTSOCK => |err| return wsaErrorBug(err),
                    .EOPNOTSUPP => |err| return wsaErrorBug(err),
                    .EINPROGRESS => |err| return wsaErrorBug(err),
                    else => |err| return windows.unexpectedWSAError(err),
                }
            },
        }
    }
}

fn netListenUnixUnavailable(
    userdata: ?*anyopaque,
    address: *const net.UnixAddress,
    options: net.UnixAddress.ListenOptions,
) net.UnixAddress.ListenError!net.Socket.Handle {
    _ = userdata;
    _ = address;
    _ = options;
    return error.AddressFamilyUnsupported;
}

fn posixBindUnix(
    fd: posix.socket_t,
    addr: *const posix.sockaddr,
    addr_len: posix.socklen_t,
) !void {
    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.bind(fd, addr, addr_len))) {
            .SUCCESS => {
                syscall.finish();
                break;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ACCES => return error.AccessDenied,
                    .ADDRINUSE => return error.AddressInUse,
                    .AFNOSUPPORT => return error.AddressFamilyUnsupported,
                    .ADDRNOTAVAIL => return error.AddressUnavailable,
                    .NOMEM => return error.SystemResources,

                    .LOOP => return error.SymLinkLoop,
                    .NOENT => return error.FileNotFound,
                    .NOTDIR => return error.NotDir,
                    .ROFS => return error.ReadOnlyFileSystem,
                    .PERM => return error.PermissionDenied,

                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .INVAL => |err| return errnoBug(err), // invalid parameters
                    .NOTSOCK => |err| return errnoBug(err), // invalid `sockfd`
                    .FAULT => |err| return errnoBug(err), // invalid `addr` pointer
                    .NAMETOOLONG => |err| return errnoBug(err),
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn posixBind(
    socket_fd: posix.socket_t,
    addr: *const posix.sockaddr,
    addr_len: posix.socklen_t,
) !void {
    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.bind(socket_fd, addr, addr_len))) {
            .SUCCESS => {
                syscall.finish();
                break;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ADDRINUSE => return error.AddressInUse,
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .INVAL => |err| return errnoBug(err), // invalid parameters
                    .NOTSOCK => |err| return errnoBug(err), // invalid `sockfd`
                    .AFNOSUPPORT => return error.AddressFamilyUnsupported,
                    .ADDRNOTAVAIL => return error.AddressUnavailable,
                    .FAULT => |err| return errnoBug(err), // invalid `addr` pointer
                    .NOMEM => return error.SystemResources,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn posixConnect(
    socket_fd: posix.socket_t,
    addr: *const posix.sockaddr,
    addr_len: posix.socklen_t,
) !void {
    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.connect(socket_fd, addr, addr_len))) {
            .SUCCESS => {
                syscall.finish();
                return;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ADDRNOTAVAIL => return error.AddressUnavailable,
                    .AFNOSUPPORT => return error.AddressFamilyUnsupported,
                    .AGAIN, .INPROGRESS => return error.WouldBlock,
                    .ALREADY => return error.ConnectionPending,
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .CONNREFUSED => return error.ConnectionRefused,
                    .CONNRESET => return error.ConnectionResetByPeer,
                    .FAULT => |err| return errnoBug(err),
                    .ISCONN => |err| return errnoBug(err),
                    .HOSTUNREACH => return error.HostUnreachable,
                    .NETUNREACH => return error.NetworkUnreachable,
                    .NOTSOCK => |err| return errnoBug(err),
                    .PROTOTYPE => |err| return errnoBug(err),
                    .TIMEDOUT => return error.Timeout,
                    .CONNABORTED => |err| return errnoBug(err),
                    .ACCES => return error.AccessDenied,
                    .PERM => |err| return errnoBug(err),
                    .NOENT => |err| return errnoBug(err),
                    .NETDOWN => return error.NetworkDown,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn posixConnectUnix(
    fd: posix.socket_t,
    addr: *const posix.sockaddr,
    addr_len: posix.socklen_t,
) !void {
    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.connect(fd, addr, addr_len))) {
            .SUCCESS => {
                syscall.finish();
                return;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .AFNOSUPPORT => return error.AddressFamilyUnsupported,
                    .AGAIN => return error.WouldBlock,
                    .INPROGRESS => return error.WouldBlock,
                    .ACCES => return error.AccessDenied,

                    .LOOP => return error.SymLinkLoop,
                    .NOENT => return error.FileNotFound,
                    .NOTDIR => return error.NotDir,
                    .ROFS => return error.ReadOnlyFileSystem,
                    .PERM => return error.PermissionDenied,

                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .CONNABORTED => |err| return errnoBug(err),
                    .FAULT => |err| return errnoBug(err),
                    .ISCONN => |err| return errnoBug(err),
                    .NOTSOCK => |err| return errnoBug(err),
                    .PROTOTYPE => |err| return errnoBug(err),
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn posixGetSockName(
    socket_fd: posix.fd_t,
    addr: *posix.sockaddr,
    addr_len: *posix.socklen_t,
) !void {
    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.getsockname(socket_fd, addr, addr_len))) {
            .SUCCESS => {
                syscall.finish();
                break;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err), // invalid parameters
                    .NOTSOCK => |err| return errnoBug(err), // always a race condition
                    .NOBUFS => return error.SystemResources,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn wsaGetSockName(
    t: *Threaded,
    handle: ws2_32.SOCKET,
    addr: *ws2_32.sockaddr,
    addr_len: *i32,
) !void {
    var syscall: Syscall = try .start();
    while (true) {
        const rc = ws2_32.getsockname(handle, addr, addr_len);
        if (rc != ws2_32.SOCKET_ERROR) {
            syscall.finish();
            return;
        }
        switch (ws2_32.WSAGetLastError()) {
            .EINTR, .ECANCELLED, .E_CANCELLED, .OPERATION_ABORTED => {
                try syscall.checkCancel();
                continue;
            },
            .NOTINITIALISED => {
                syscall.finish();
                try initializeWsa(t);
                syscall = try .start();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ENETDOWN => return error.NetworkDown,
                    .EFAULT => |err| return wsaErrorBug(err),
                    .ENOTSOCK => |err| return wsaErrorBug(err),
                    .EINVAL => |err| return wsaErrorBug(err),
                    else => |err| return windows.unexpectedWSAError(err),
                }
            },
        }
    }
}

fn setSocketOption(fd: posix.fd_t, level: i32, opt_name: u32, option: u32) !void {
    const o: []const u8 = @ptrCast(&option);
    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.setsockopt(fd, level, opt_name, o.ptr, @intCast(o.len)))) {
            .SUCCESS => {
                syscall.finish();
                return;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .NOTSOCK => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err),
                    .FAULT => |err| return errnoBug(err),
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn setSocketOptionWsa(t: *Threaded, socket: Io.net.Socket.Handle, level: i32, opt_name: u32, option: u32) !void {
    const o: []const u8 = @ptrCast(&option);
    var syscall: Syscall = try .start();
    const rc = ws2_32.setsockopt(socket, level, @bitCast(opt_name), o.ptr, @intCast(o.len));
    while (true) {
        if (rc != ws2_32.SOCKET_ERROR) return syscall.finish();
        switch (ws2_32.WSAGetLastError()) {
            .EINTR, .ECANCELLED, .E_CANCELLED, .OPERATION_ABORTED => {
                try syscall.checkCancel();
                continue;
            },
            .NOTINITIALISED => {
                syscall.finish();
                try initializeWsa(t);
                syscall = try .start();
                continue;
            },
            .ENETDOWN => return syscall.fail(error.NetworkDown),
            .EFAULT, .ENOTSOCK, .EINVAL => |err| {
                syscall.finish();
                return wsaErrorBug(err);
            },
            else => |err| {
                syscall.finish();
                return windows.unexpectedWSAError(err);
            },
        }
    }
}

fn netConnectIpPosix(
    userdata: ?*anyopaque,
    address: *const IpAddress,
    options: IpAddress.ConnectOptions,
) IpAddress.ConnectError!net.Stream {
    if (!have_networking) return error.NetworkDown;
    if (options.timeout != .none) @panic("TODO implement netConnectIpPosix with timeout");
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const family = posixAddressFamily(address);
    const socket_fd = try openSocketPosix(family, .{
        .mode = options.mode,
        .protocol = options.protocol,
    });
    errdefer posix.close(socket_fd);
    var storage: PosixAddress = undefined;
    var addr_len = addressToPosix(address, &storage);
    try posixConnect(socket_fd, &storage.any, addr_len);
    try posixGetSockName(socket_fd, &storage.any, &addr_len);
    return .{ .socket = .{
        .handle = socket_fd,
        .address = addressFromPosix(&storage),
    } };
}

fn netConnectIpWindows(
    userdata: ?*anyopaque,
    address: *const IpAddress,
    options: IpAddress.ConnectOptions,
) IpAddress.ConnectError!net.Stream {
    if (!have_networking) return error.NetworkDown;
    if (options.timeout != .none) @panic("TODO implement netConnectIpWindows with timeout");
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const family = posixAddressFamily(address);
    const socket_handle = try openSocketWsa(t, family, .{
        .mode = options.mode,
        .protocol = options.protocol,
    });
    errdefer closeSocketWindows(socket_handle);

    var storage: WsaAddress = undefined;
    var addr_len = addressToWsa(address, &storage);

    var syscall: Syscall = try .start();
    while (true) {
        const rc = ws2_32.connect(socket_handle, &storage.any, addr_len);
        if (rc != ws2_32.SOCKET_ERROR) {
            syscall.finish();
            break;
        }
        switch (ws2_32.WSAGetLastError()) {
            .EINTR, .ECANCELLED, .E_CANCELLED, .OPERATION_ABORTED => {
                try syscall.checkCancel();
                continue;
            },
            .NOTINITIALISED => {
                syscall.finish();
                try initializeWsa(t);
                syscall = try .start();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .EADDRNOTAVAIL => return error.AddressUnavailable,
                    .ECONNREFUSED => return error.ConnectionRefused,
                    .ECONNRESET => return error.ConnectionResetByPeer,
                    .ETIMEDOUT => return error.Timeout,
                    .EHOSTUNREACH => return error.HostUnreachable,
                    .ENETUNREACH => return error.NetworkUnreachable,
                    .EFAULT => |err| return wsaErrorBug(err),
                    .EINVAL => |err| return wsaErrorBug(err),
                    .EISCONN => |err| return wsaErrorBug(err),
                    .ENOTSOCK => |err| return wsaErrorBug(err),
                    .EWOULDBLOCK => return error.WouldBlock,
                    .EACCES => return error.AccessDenied,
                    .ENOBUFS => return error.SystemResources,
                    .EAFNOSUPPORT => return error.AddressFamilyUnsupported,
                    else => |err| return windows.unexpectedWSAError(err),
                }
            },
        }
    }

    try wsaGetSockName(t, socket_handle, &storage.any, &addr_len);

    return .{ .socket = .{
        .handle = socket_handle,
        .address = addressFromWsa(&storage),
    } };
}

fn netConnectIpUnavailable(
    userdata: ?*anyopaque,
    address: *const IpAddress,
    options: IpAddress.ConnectOptions,
) IpAddress.ConnectError!net.Stream {
    _ = userdata;
    _ = address;
    _ = options;
    return error.NetworkDown;
}

fn netConnectUnixPosix(
    userdata: ?*anyopaque,
    address: *const net.UnixAddress,
) net.UnixAddress.ConnectError!net.Socket.Handle {
    if (!net.has_unix_sockets) return error.AddressFamilyUnsupported;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const socket_fd = openSocketPosix(posix.AF.UNIX, .{ .mode = .stream }) catch |err| switch (err) {
        error.OptionUnsupported => return error.Unexpected,
        else => |e| return e,
    };
    errdefer posix.close(socket_fd);
    var storage: UnixAddress = undefined;
    const addr_len = addressUnixToPosix(address, &storage);
    try posixConnectUnix(socket_fd, &storage.any, addr_len);
    return socket_fd;
}

fn netConnectUnixWindows(
    userdata: ?*anyopaque,
    address: *const net.UnixAddress,
) net.UnixAddress.ConnectError!net.Socket.Handle {
    if (!net.has_unix_sockets) return error.AddressFamilyUnsupported;
    const t: *Threaded = @ptrCast(@alignCast(userdata));

    const socket_handle = try openSocketWsa(t, posix.AF.UNIX, .{ .mode = .stream });
    errdefer closeSocketWindows(socket_handle);
    var storage: WsaAddress = undefined;
    const addr_len = addressUnixToWsa(address, &storage);

    var syscall: Syscall = try .start();
    while (true) {
        const rc = ws2_32.connect(socket_handle, &storage.any, addr_len);
        if (rc != ws2_32.SOCKET_ERROR) break;
        switch (ws2_32.WSAGetLastError()) {
            .EINTR, .ECANCELLED, .E_CANCELLED, .OPERATION_ABORTED => {
                try syscall.checkCancel();
                continue;
            },
            .NOTINITIALISED => {
                syscall.finish();
                try initializeWsa(t);
                syscall = try .start();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ECONNREFUSED => return error.FileNotFound,
                    .EFAULT => |err| return wsaErrorBug(err),
                    .EINVAL => |err| return wsaErrorBug(err),
                    .EISCONN => |err| return wsaErrorBug(err),
                    .ENOTSOCK => |err| return wsaErrorBug(err),
                    .EWOULDBLOCK => return error.WouldBlock,
                    .EACCES => return error.AccessDenied,
                    .ENOBUFS => return error.SystemResources,
                    .EAFNOSUPPORT => return error.AddressFamilyUnsupported,
                    else => |err| return windows.unexpectedWSAError(err),
                }
            },
        }
    }

    return socket_handle;
}

fn netConnectUnixUnavailable(
    userdata: ?*anyopaque,
    address: *const net.UnixAddress,
) net.UnixAddress.ConnectError!net.Socket.Handle {
    _ = userdata;
    _ = address;
    return error.AddressFamilyUnsupported;
}

fn netBindIpPosix(
    userdata: ?*anyopaque,
    address: *const IpAddress,
    options: IpAddress.BindOptions,
) IpAddress.BindError!net.Socket {
    if (!have_networking) return error.NetworkDown;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    const family = posixAddressFamily(address);
    const socket_fd = try openSocketPosix(family, options);
    errdefer posix.close(socket_fd);
    var storage: PosixAddress = undefined;
    var addr_len = addressToPosix(address, &storage);
    try posixBind(socket_fd, &storage.any, addr_len);
    try posixGetSockName(socket_fd, &storage.any, &addr_len);
    return .{
        .handle = socket_fd,
        .address = addressFromPosix(&storage),
    };
}

fn netBindIpWindows(
    userdata: ?*anyopaque,
    address: *const IpAddress,
    options: IpAddress.BindOptions,
) IpAddress.BindError!net.Socket {
    if (!have_networking) return error.NetworkDown;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const family = posixAddressFamily(address);
    const socket_handle = try openSocketWsa(t, family, .{
        .mode = options.mode,
        .protocol = options.protocol,
    });
    errdefer closeSocketWindows(socket_handle);

    var storage: WsaAddress = undefined;
    var addr_len = addressToWsa(address, &storage);

    var syscall: Syscall = try .start();
    while (true) {
        const rc = ws2_32.bind(socket_handle, &storage.any, addr_len);
        if (rc != ws2_32.SOCKET_ERROR) {
            syscall.finish();
            break;
        }
        switch (ws2_32.WSAGetLastError()) {
            .EINTR, .ECANCELLED, .E_CANCELLED, .OPERATION_ABORTED => {
                try syscall.checkCancel();
                continue;
            },
            .NOTINITIALISED => {
                syscall.finish();
                try initializeWsa(t);
                syscall = try .start();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .EADDRINUSE => return error.AddressInUse,
                    .EADDRNOTAVAIL => return error.AddressUnavailable,
                    .ENOTSOCK => |err| return wsaErrorBug(err),
                    .EFAULT => |err| return wsaErrorBug(err),
                    .EINVAL => |err| return wsaErrorBug(err),
                    .ENOBUFS => return error.SystemResources,
                    .ENETDOWN => return error.NetworkDown,
                    else => |err| return windows.unexpectedWSAError(err),
                }
            },
        }
    }

    try wsaGetSockName(t, socket_handle, &storage.any, &addr_len);

    return .{
        .handle = socket_handle,
        .address = addressFromWsa(&storage),
    };
}

fn netBindIpUnavailable(
    userdata: ?*anyopaque,
    address: *const IpAddress,
    options: IpAddress.BindOptions,
) IpAddress.BindError!net.Socket {
    _ = userdata;
    _ = address;
    _ = options;
    return error.NetworkDown;
}

fn openSocketPosix(
    family: posix.sa_family_t,
    options: IpAddress.BindOptions,
) error{
    AddressFamilyUnsupported,
    ProtocolUnsupportedBySystem,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    ProtocolUnsupportedByAddressFamily,
    SocketModeUnsupported,
    OptionUnsupported,
    Unexpected,
    Canceled,
}!posix.socket_t {
    const mode = posixSocketMode(options.mode);
    const protocol = posixProtocol(options.protocol);
    const syscall: Syscall = try .start();
    const socket_fd = while (true) {
        const flags: u32 = mode | if (socket_flags_unsupported) 0 else posix.SOCK.CLOEXEC;
        const socket_rc = posix.system.socket(family, flags, protocol);
        switch (posix.errno(socket_rc)) {
            .SUCCESS => {
                const fd: posix.fd_t = @intCast(socket_rc);
                errdefer posix.close(fd);
                if (socket_flags_unsupported) while (true) {
                    try syscall.checkCancel();
                    switch (posix.errno(posix.system.fcntl(fd, posix.F.SETFD, @as(usize, posix.FD_CLOEXEC)))) {
                        .SUCCESS => break,
                        .INTR => continue,
                        else => |err| {
                            syscall.finish();
                            return posix.unexpectedErrno(err);
                        },
                    }
                };
                syscall.finish();
                break fd;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .AFNOSUPPORT => return error.AddressFamilyUnsupported,
                    .INVAL => return error.ProtocolUnsupportedBySystem,
                    .MFILE => return error.ProcessFdQuotaExceeded,
                    .NFILE => return error.SystemFdQuotaExceeded,
                    .NOBUFS => return error.SystemResources,
                    .NOMEM => return error.SystemResources,
                    .PROTONOSUPPORT => return error.ProtocolUnsupportedByAddressFamily,
                    .PROTOTYPE => return error.SocketModeUnsupported,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    };
    errdefer posix.close(socket_fd);

    if (options.ip6_only) {
        if (posix.IPV6 == void) return error.OptionUnsupported;
        try setSocketOption(socket_fd, posix.IPPROTO.IPV6, posix.IPV6.V6ONLY, 0);
    }

    return socket_fd;
}

fn openSocketWsa(
    t: *Threaded,
    family: posix.sa_family_t,
    options: IpAddress.BindOptions,
) !ws2_32.SOCKET {
    const mode = posixSocketMode(options.mode);
    const protocol = posixProtocol(options.protocol);
    const flags: u32 = ws2_32.WSA_FLAG_OVERLAPPED | ws2_32.WSA_FLAG_NO_HANDLE_INHERIT;
    var syscall: Syscall = try .start();
    while (true) {
        const rc = ws2_32.WSASocketW(family, @bitCast(mode), @bitCast(protocol), null, 0, flags);
        if (rc != ws2_32.INVALID_SOCKET) {
            syscall.finish();
            return rc;
        }
        switch (ws2_32.WSAGetLastError()) {
            .EINTR, .ECANCELLED, .E_CANCELLED, .OPERATION_ABORTED => {
                try syscall.checkCancel();
                continue;
            },
            .NOTINITIALISED => {
                syscall.finish();
                try initializeWsa(t);
                syscall = try .start();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .EAFNOSUPPORT => return error.AddressFamilyUnsupported,
                    .EMFILE => return error.ProcessFdQuotaExceeded,
                    .ENOBUFS => return error.SystemResources,
                    .EPROTONOSUPPORT => return error.ProtocolUnsupportedByAddressFamily,
                    else => |err| return windows.unexpectedWSAError(err),
                }
            },
        }
    }
}

fn netAcceptPosix(userdata: ?*anyopaque, listen_fd: net.Socket.Handle) net.Server.AcceptError!net.Stream {
    if (!have_networking) return error.NetworkDown;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    var storage: PosixAddress = undefined;
    var addr_len: posix.socklen_t = @sizeOf(PosixAddress);
    const syscall: Syscall = try .start();
    const fd = while (true) {
        const rc = if (have_accept4)
            posix.system.accept4(listen_fd, &storage.any, &addr_len, posix.SOCK.CLOEXEC)
        else
            posix.system.accept(listen_fd, &storage.any, &addr_len);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                const fd: posix.fd_t = @intCast(rc);
                errdefer posix.close(fd);
                if (!have_accept4) while (true) {
                    try syscall.checkCancel();
                    switch (posix.errno(posix.system.fcntl(fd, posix.F.SETFD, @as(usize, posix.FD_CLOEXEC)))) {
                        .SUCCESS => break,
                        .INTR => continue,
                        else => |err| {
                            syscall.finish();
                            return posix.unexpectedErrno(err);
                        },
                    }
                };
                syscall.finish();
                break fd;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .AGAIN => |err| return errnoBug(err),
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .CONNABORTED => return error.ConnectionAborted,
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => return error.SocketNotListening,
                    .NOTSOCK => |err| return errnoBug(err),
                    .MFILE => return error.ProcessFdQuotaExceeded,
                    .NFILE => return error.SystemFdQuotaExceeded,
                    .NOBUFS => return error.SystemResources,
                    .NOMEM => return error.SystemResources,
                    .OPNOTSUPP => |err| return errnoBug(err),
                    .PROTO => return error.ProtocolFailure,
                    .PERM => return error.BlockedByFirewall,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    };
    return .{ .socket = .{
        .handle = fd,
        .address = addressFromPosix(&storage),
    } };
}

fn netAcceptWindows(userdata: ?*anyopaque, listen_handle: net.Socket.Handle) net.Server.AcceptError!net.Stream {
    if (!have_networking) return error.NetworkDown;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    var storage: WsaAddress = undefined;
    var addr_len: i32 = @sizeOf(WsaAddress);
    var syscall: Syscall = try .start();
    while (true) {
        const rc = ws2_32.accept(listen_handle, &storage.any, &addr_len);
        if (rc != ws2_32.INVALID_SOCKET) {
            syscall.finish();
            return .{ .socket = .{
                .handle = rc,
                .address = addressFromWsa(&storage),
            } };
        }
        switch (ws2_32.WSAGetLastError()) {
            .EINTR, .ECANCELLED, .E_CANCELLED, .OPERATION_ABORTED => {
                try syscall.checkCancel();
                continue;
            },
            .NOTINITIALISED => {
                syscall.finish();
                try initializeWsa(t);
                syscall = try .start();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ECONNRESET => return error.ConnectionAborted,
                    .EFAULT => |err| return wsaErrorBug(err),
                    .ENOTSOCK => |err| return wsaErrorBug(err),
                    .EINVAL => |err| return wsaErrorBug(err),
                    .EMFILE => return error.ProcessFdQuotaExceeded,
                    .ENETDOWN => return error.NetworkDown,
                    .ENOBUFS => return error.SystemResources,
                    .EOPNOTSUPP => |err| return wsaErrorBug(err),
                    else => |err| return windows.unexpectedWSAError(err),
                }
            },
        }
    }
}

fn netAcceptUnavailable(userdata: ?*anyopaque, listen_handle: net.Socket.Handle) net.Server.AcceptError!net.Stream {
    _ = userdata;
    _ = listen_handle;
    return error.NetworkDown;
}

fn netReadPosix(userdata: ?*anyopaque, fd: net.Socket.Handle, data: [][]u8) net.Stream.Reader.Error!usize {
    if (!have_networking) return error.NetworkDown;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var iovecs_buffer: [max_iovecs_len]posix.iovec = undefined;
    var i: usize = 0;
    for (data) |buf| {
        if (iovecs_buffer.len - i == 0) break;
        if (buf.len != 0) {
            iovecs_buffer[i] = .{ .base = buf.ptr, .len = buf.len };
            i += 1;
        }
    }
    const dest = iovecs_buffer[0..i];
    assert(dest[0].len > 0);

    if (native_os == .wasi and !builtin.link_libc) {
        const syscall: Syscall = try .start();
        while (true) {
            var n: usize = undefined;
            switch (std.os.wasi.fd_read(fd, dest.ptr, dest.len, &n)) {
                .SUCCESS => {
                    syscall.finish();
                    return n;
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .INVAL => |err| return errnoBug(err),
                        .FAULT => |err| return errnoBug(err),
                        .AGAIN => |err| return errnoBug(err),
                        .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                        .NOBUFS => return error.SystemResources,
                        .NOMEM => return error.SystemResources,
                        .NOTCONN => return error.SocketUnconnected,
                        .CONNRESET => return error.ConnectionResetByPeer,
                        .TIMEDOUT => return error.Timeout,
                        .NOTCAPABLE => return error.AccessDenied,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    }

    const syscall: Syscall = try .start();
    while (true) {
        const rc = posix.system.readv(fd, dest.ptr, @intCast(dest.len));
        switch (posix.errno(rc)) {
            .SUCCESS => {
                syscall.finish();
                return @intCast(rc);
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .INVAL => |err| return errnoBug(err),
                    .FAULT => |err| return errnoBug(err),
                    .AGAIN => |err| return errnoBug(err),
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .NOBUFS => return error.SystemResources,
                    .NOMEM => return error.SystemResources,
                    .NOTCONN => return error.SocketUnconnected,
                    .CONNRESET => return error.ConnectionResetByPeer,
                    .TIMEDOUT => return error.Timeout,
                    .PIPE => return error.SocketUnconnected,
                    .NETDOWN => return error.NetworkDown,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn netReadWindows(userdata: ?*anyopaque, handle: net.Socket.Handle, data: [][]u8) net.Stream.Reader.Error!usize {
    if (!have_networking) return error.NetworkDown;
    const t: *Threaded = @ptrCast(@alignCast(userdata));

    const bufs = b: {
        var iovec_buffer: [max_iovecs_len]ws2_32.WSABUF = undefined;
        var i: usize = 0;
        var n: usize = 0;
        for (data) |buf| {
            if (iovec_buffer.len - i == 0) break;
            if (buf.len == 0) continue;
            if (std.math.cast(u32, buf.len)) |len| {
                iovec_buffer[i] = .{ .buf = buf.ptr, .len = len };
                i += 1;
                n += len;
                continue;
            }
            iovec_buffer[i] = .{ .buf = buf.ptr, .len = std.math.maxInt(u32) };
            i += 1;
            n += std.math.maxInt(u32);
            break;
        }

        const bufs = iovec_buffer[0..i];
        assert(bufs[0].len != 0);

        break :b bufs;
    };

    var syscall: Syscall = try .start();
    while (true) {
        var flags: u32 = 0;
        var n: u32 = undefined;
        const rc = ws2_32.WSARecv(handle, bufs.ptr, @intCast(bufs.len), &n, &flags, null, null);
        if (rc != ws2_32.SOCKET_ERROR) {
            syscall.finish();
            return n;
        }
        switch (ws2_32.WSAGetLastError()) {
            .EINTR, .ECANCELLED, .E_CANCELLED, .OPERATION_ABORTED => {
                try syscall.checkCancel();
                continue;
            },
            .NOTINITIALISED => {
                syscall.finish();
                try initializeWsa(t);
                syscall = try .start();
                continue;
            },

            .ECONNRESET => return syscall.fail(error.ConnectionResetByPeer),
            .ENETDOWN => return syscall.fail(error.NetworkDown),
            .ENETRESET => return syscall.fail(error.ConnectionResetByPeer),
            .ENOTCONN => return syscall.fail(error.SocketUnconnected),
            .EFAULT => unreachable, // a pointer is not completely contained in user address space.

            else => |err| {
                syscall.finish();
                switch (err) {
                    .EINVAL => return wsaErrorBug(err),
                    .EMSGSIZE => return wsaErrorBug(err),
                    else => return windows.unexpectedWSAError(err),
                }
            },
        }
    }
}

fn netReadUnavailable(userdata: ?*anyopaque, fd: net.Socket.Handle, data: [][]u8) net.Stream.Reader.Error!usize {
    _ = userdata;
    _ = fd;
    _ = data;
    return error.NetworkDown;
}

fn netSendPosix(
    userdata: ?*anyopaque,
    handle: net.Socket.Handle,
    messages: []net.OutgoingMessage,
    flags: net.SendFlags,
) struct { ?net.Socket.SendError, usize } {
    if (!have_networking) return .{ error.NetworkDown, 0 };
    const t: *Threaded = @ptrCast(@alignCast(userdata));

    const posix_flags: u32 =
        @as(u32, if (@hasDecl(posix.MSG, "CONFIRM") and flags.confirm) posix.MSG.CONFIRM else 0) |
        @as(u32, if (@hasDecl(posix.MSG, "DONTROUTE") and flags.dont_route) posix.MSG.DONTROUTE else 0) |
        @as(u32, if (@hasDecl(posix.MSG, "EOR") and flags.eor) posix.MSG.EOR else 0) |
        @as(u32, if (@hasDecl(posix.MSG, "OOB") and flags.oob) posix.MSG.OOB else 0) |
        @as(u32, if (@hasDecl(posix.MSG, "FASTOPEN") and flags.fastopen) posix.MSG.FASTOPEN else 0) |
        posix.MSG.NOSIGNAL;

    var i: usize = 0;
    while (messages.len - i != 0) {
        if (have_sendmmsg) {
            i += netSendMany(handle, messages[i..], posix_flags) catch |err| return .{ err, i };
            continue;
        }
        netSendOne(t, handle, &messages[i], posix_flags) catch |err| return .{ err, i };
        i += 1;
    }
    return .{ null, i };
}

fn netSendWindows(
    userdata: ?*anyopaque,
    handle: net.Socket.Handle,
    messages: []net.OutgoingMessage,
    flags: net.SendFlags,
) struct { ?net.Socket.SendError, usize } {
    if (!have_networking) return .{ error.NetworkDown, 0 };
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    _ = handle;
    _ = messages;
    _ = flags;
    @panic("TODO netSendWindows");
}

fn netSendUnavailable(
    userdata: ?*anyopaque,
    handle: net.Socket.Handle,
    messages: []net.OutgoingMessage,
    flags: net.SendFlags,
) struct { ?net.Socket.SendError, usize } {
    _ = userdata;
    _ = handle;
    _ = messages;
    _ = flags;
    return .{ error.NetworkDown, 0 };
}

fn netSendOne(
    t: *Threaded,
    handle: net.Socket.Handle,
    message: *net.OutgoingMessage,
    flags: u32,
) net.Socket.SendError!void {
    var addr: PosixAddress = undefined;
    var iovec: posix.iovec_const = .{ .base = @constCast(message.data_ptr), .len = message.data_len };
    const msg: posix.msghdr_const = .{
        .name = &addr.any,
        .namelen = addressToPosix(message.address, &addr),
        .iov = (&iovec)[0..1],
        .iovlen = 1,
        // OS returns EINVAL if this pointer is invalid even if controllen is zero.
        .control = if (message.control.len == 0) null else @constCast(message.control.ptr),
        .controllen = @intCast(message.control.len),
        .flags = 0,
    };
    var syscall: Syscall = try .start();
    while (true) {
        const rc = posix.system.sendmsg(handle, &msg, flags);
        if (is_windows) {
            if (rc != ws2_32.SOCKET_ERROR) {
                syscall.finish();
                message.data_len = @intCast(rc);
                return;
            }
            switch (ws2_32.WSAGetLastError()) {
                .EINTR, .ECANCELLED, .E_CANCELLED, .OPERATION_ABORTED => {
                    try syscall.checkCancel();
                    continue;
                },
                .NOTINITIALISED => {
                    syscall.finish();
                    try initializeWsa(t);
                    syscall = try .start();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .EACCES => return error.AccessDenied,
                        .EADDRNOTAVAIL => return error.AddressUnavailable,
                        .ECONNRESET => return error.ConnectionResetByPeer,
                        .EMSGSIZE => return error.MessageOversize,
                        .ENOBUFS => return error.SystemResources,
                        .ENOTSOCK => return error.FileDescriptorNotASocket,
                        .EAFNOSUPPORT => return error.AddressFamilyUnsupported,
                        .EDESTADDRREQ => unreachable, // A destination address is required.
                        .EFAULT => unreachable, // The lpBuffers, lpTo, lpOverlapped, lpNumberOfBytesSent, or lpCompletionRoutine parameters are not part of the user address space, or the lpTo parameter is too small.
                        .EHOSTUNREACH => return error.NetworkUnreachable,
                        .EINVAL => unreachable,
                        .ENETDOWN => return error.NetworkDown,
                        .ENETRESET => return error.ConnectionResetByPeer,
                        .ENETUNREACH => return error.NetworkUnreachable,
                        .ENOTCONN => return error.SocketUnconnected,
                        .ESHUTDOWN => |err| return wsaErrorBug(err),
                        else => |err| return windows.unexpectedWSAError(err),
                    }
                },
            }
        }
        switch (posix.errno(rc)) {
            .SUCCESS => {
                syscall.finish();
                message.data_len = @intCast(rc);
                return;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ACCES => return error.AccessDenied,
                    .ALREADY => return error.FastOpenAlreadyInProgress,
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .CONNRESET => return error.ConnectionResetByPeer,
                    .DESTADDRREQ => |err| return errnoBug(err),
                    .FAULT => |err| return errnoBug(err),
                    .INVAL => |err| return errnoBug(err),
                    .ISCONN => |err| return errnoBug(err),
                    .MSGSIZE => return error.MessageOversize,
                    .NOBUFS => return error.SystemResources,
                    .NOMEM => return error.SystemResources,
                    .NOTSOCK => |err| return errnoBug(err),
                    .OPNOTSUPP => |err| return errnoBug(err),
                    .PIPE => return error.SocketUnconnected,
                    .AFNOSUPPORT => return error.AddressFamilyUnsupported,
                    .HOSTUNREACH => return error.HostUnreachable,
                    .NETUNREACH => return error.NetworkUnreachable,
                    .NOTCONN => return error.SocketUnconnected,
                    .NETDOWN => return error.NetworkDown,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn netSendMany(
    handle: net.Socket.Handle,
    messages: []net.OutgoingMessage,
    flags: u32,
) net.Socket.SendError!usize {
    var msg_buffer: [64]posix.system.mmsghdr = undefined;
    var addr_buffer: [msg_buffer.len]PosixAddress = undefined;
    var iovecs_buffer: [msg_buffer.len]posix.iovec = undefined;
    const min_len: usize = @min(messages.len, msg_buffer.len);
    const clamped_messages = messages[0..min_len];
    const clamped_msgs = (&msg_buffer)[0..min_len];
    const clamped_addrs = (&addr_buffer)[0..min_len];
    const clamped_iovecs = (&iovecs_buffer)[0..min_len];

    for (clamped_messages, clamped_msgs, clamped_addrs, clamped_iovecs) |*message, *msg, *addr, *iovec| {
        iovec.* = .{ .base = @constCast(message.data_ptr), .len = message.data_len };
        msg.* = .{
            .hdr = .{
                .name = &addr.any,
                .namelen = addressToPosix(message.address, addr),
                .iov = iovec[0..1],
                .iovlen = 1,
                .control = @constCast(message.control.ptr),
                .controllen = message.control.len,
                .flags = 0,
            },
            .len = undefined, // Populated by calling sendmmsg below.
        };
    }

    const syscall: Syscall = try .start();
    while (true) {
        const rc = posix.system.sendmmsg(handle, clamped_msgs.ptr, @intCast(clamped_msgs.len), flags);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                syscall.finish();
                const n: usize = @intCast(rc);
                for (clamped_messages[0..n], clamped_msgs[0..n]) |*message, *msg| {
                    message.data_len = msg.len;
                }
                return n;
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .AGAIN => |err| return errnoBug(err),
                    .ALREADY => return error.FastOpenAlreadyInProgress,
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .CONNRESET => return error.ConnectionResetByPeer,
                    .DESTADDRREQ => |err| return errnoBug(err), // The socket is not connection-mode, and no peer address is set.
                    .FAULT => |err| return errnoBug(err), // An invalid user space address was specified for an argument.
                    .INVAL => |err| return errnoBug(err), // Invalid argument passed.
                    .ISCONN => |err| return errnoBug(err), // connection-mode socket was connected already but a recipient was specified
                    .MSGSIZE => return error.MessageOversize,
                    .NOBUFS => return error.SystemResources,
                    .NOMEM => return error.SystemResources,
                    .NOTSOCK => |err| return errnoBug(err), // The file descriptor sockfd does not refer to a socket.
                    .OPNOTSUPP => |err| return errnoBug(err), // Some bit in the flags argument is inappropriate for the socket type.
                    .PIPE => return error.SocketUnconnected,
                    .AFNOSUPPORT => return error.AddressFamilyUnsupported,
                    .HOSTUNREACH => return error.HostUnreachable,
                    .NETUNREACH => return error.NetworkUnreachable,
                    .NOTCONN => return error.SocketUnconnected,
                    .NETDOWN => return error.NetworkDown,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn netReceivePosix(
    userdata: ?*anyopaque,
    handle: net.Socket.Handle,
    message_buffer: []net.IncomingMessage,
    data_buffer: []u8,
    flags: net.ReceiveFlags,
    timeout: Io.Timeout,
) struct { ?net.Socket.ReceiveTimeoutError, usize } {
    if (!have_networking) return .{ error.NetworkDown, 0 };
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    const t_io = io(t);

    // recvmmsg is useless, here's why:
    // * [timeout bug](https://bugzilla.kernel.org/show_bug.cgi?id=75371)
    // * it wants iovecs for each message but we have a better API: one data
    //   buffer to handle all the messages. The better API cannot be lowered to
    //   the split vectors though because reducing the buffer size might make
    //   some messages unreceivable.

    // So the strategy instead is to use non-blocking recvmsg calls, calling
    // poll() with timeout if the first one returns EAGAIN.
    const posix_flags: u32 =
        @as(u32, if (flags.oob) posix.MSG.OOB else 0) |
        @as(u32, if (flags.peek) posix.MSG.PEEK else 0) |
        @as(u32, if (flags.trunc) posix.MSG.TRUNC else 0) |
        posix.MSG.DONTWAIT | posix.MSG.NOSIGNAL;

    var poll_fds: [1]posix.pollfd = .{
        .{
            .fd = handle,
            .events = posix.POLL.IN,
            .revents = undefined,
        },
    };
    var message_i: usize = 0;
    var data_i: usize = 0;

    const deadline = timeout.toDeadline(t_io) catch |err| return .{ err, message_i };

    recv: while (true) {
        if (message_buffer.len - message_i == 0) return .{ null, message_i };
        const message = &message_buffer[message_i];
        const remaining_data_buffer = data_buffer[data_i..];
        var storage: PosixAddress = undefined;
        var iov: posix.iovec = .{ .base = remaining_data_buffer.ptr, .len = remaining_data_buffer.len };
        var msg: posix.msghdr = .{
            .name = &storage.any,
            .namelen = @sizeOf(PosixAddress),
            .iov = (&iov)[0..1],
            .iovlen = 1,
            .control = message.control.ptr,
            .controllen = @intCast(message.control.len),
            .flags = undefined,
        };

        const recv_rc = rc: {
            const syscall = Syscall.start() catch |err| return .{ err, message_i };
            const rc = posix.system.recvmsg(handle, &msg, posix_flags);
            syscall.finish();
            break :rc rc;
        };
        switch (posix.errno(recv_rc)) {
            .SUCCESS => {
                const data = remaining_data_buffer[0..@intCast(recv_rc)];
                data_i += data.len;
                message.* = .{
                    .from = addressFromPosix(&storage),
                    .data = data,
                    .control = if (msg.control) |ptr| @as([*]u8, @ptrCast(ptr))[0..msg.controllen] else message.control,
                    .flags = .{
                        .eor = (msg.flags & posix.MSG.EOR) != 0,
                        .trunc = (msg.flags & posix.MSG.TRUNC) != 0,
                        .ctrunc = (msg.flags & posix.MSG.CTRUNC) != 0,
                        .oob = (msg.flags & posix.MSG.OOB) != 0,
                        .errqueue = if (@hasDecl(posix.MSG, "ERRQUEUE")) (msg.flags & posix.MSG.ERRQUEUE) != 0 else false,
                    },
                };
                message_i += 1;
                continue;
            },
            .AGAIN => while (true) {
                if (message_i != 0) return .{ null, message_i };

                const max_poll_ms = std.math.maxInt(u31);
                const timeout_ms: u31 = if (deadline) |d| t: {
                    const duration = d.durationFromNow(t_io) catch |err| return .{ err, message_i };
                    if (duration.raw.nanoseconds <= 0) return .{ error.Timeout, message_i };
                    break :t @intCast(@min(max_poll_ms, duration.raw.toMilliseconds()));
                } else max_poll_ms;

                const syscall = Syscall.start() catch |err| return .{ err, message_i };
                const poll_rc = posix.system.poll(&poll_fds, poll_fds.len, timeout_ms);
                syscall.finish();

                switch (posix.errno(poll_rc)) {
                    .SUCCESS => {
                        if (poll_rc == 0) {
                            // Although spurious timeouts are OK, when no deadline
                            // is passed we must not return `error.Timeout`.
                            if (deadline == null) continue;
                            return .{ error.Timeout, message_i };
                        }
                        continue :recv;
                    },
                    .INTR => continue,

                    .FAULT => |err| return .{ errnoBug(err), message_i },
                    .INVAL => |err| return .{ errnoBug(err), message_i },
                    .NOMEM => return .{ error.SystemResources, message_i },
                    else => |err| return .{ posix.unexpectedErrno(err), message_i },
                }
            },
            .INTR => continue,

            .BADF => |err| return .{ errnoBug(err), message_i },
            .NFILE => return .{ error.SystemFdQuotaExceeded, message_i },
            .MFILE => return .{ error.ProcessFdQuotaExceeded, message_i },
            .FAULT => |err| return .{ errnoBug(err), message_i },
            .INVAL => |err| return .{ errnoBug(err), message_i },
            .NOBUFS => return .{ error.SystemResources, message_i },
            .NOMEM => return .{ error.SystemResources, message_i },
            .NOTCONN => return .{ error.SocketUnconnected, message_i },
            .NOTSOCK => |err| return .{ errnoBug(err), message_i },
            .MSGSIZE => return .{ error.MessageOversize, message_i },
            .PIPE => return .{ error.SocketUnconnected, message_i },
            .OPNOTSUPP => |err| return .{ errnoBug(err), message_i },
            .CONNRESET => return .{ error.ConnectionResetByPeer, message_i },
            .NETDOWN => return .{ error.NetworkDown, message_i },
            else => |err| return .{ posix.unexpectedErrno(err), message_i },
        }
    }
}

fn netReceiveWindows(
    userdata: ?*anyopaque,
    handle: net.Socket.Handle,
    message_buffer: []net.IncomingMessage,
    data_buffer: []u8,
    flags: net.ReceiveFlags,
    timeout: Io.Timeout,
) struct { ?net.Socket.ReceiveTimeoutError, usize } {
    if (!have_networking) return .{ error.NetworkDown, 0 };
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    _ = handle;
    _ = message_buffer;
    _ = data_buffer;
    _ = flags;
    _ = timeout;
    @panic("TODO implement netReceiveWindows");
}

fn netReceiveUnavailable(
    userdata: ?*anyopaque,
    handle: net.Socket.Handle,
    message_buffer: []net.IncomingMessage,
    data_buffer: []u8,
    flags: net.ReceiveFlags,
    timeout: Io.Timeout,
) struct { ?net.Socket.ReceiveTimeoutError, usize } {
    _ = userdata;
    _ = handle;
    _ = message_buffer;
    _ = data_buffer;
    _ = flags;
    _ = timeout;
    return .{ error.NetworkDown, 0 };
}

fn netWritePosix(
    userdata: ?*anyopaque,
    fd: net.Socket.Handle,
    header: []const u8,
    data: []const []const u8,
    splat: usize,
) net.Stream.Writer.Error!usize {
    if (!have_networking) return error.NetworkDown;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    var iovecs: [max_iovecs_len]posix.iovec_const = undefined;
    var msg: posix.msghdr_const = .{
        .name = null,
        .namelen = 0,
        .iov = &iovecs,
        .iovlen = 0,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };
    addBuf(&iovecs, &msg.iovlen, header);
    for (data[0 .. data.len - 1]) |bytes| addBuf(&iovecs, &msg.iovlen, bytes);
    const pattern = data[data.len - 1];
    if (iovecs.len - msg.iovlen != 0) switch (splat) {
        0 => {},
        1 => addBuf(&iovecs, &msg.iovlen, pattern),
        else => switch (pattern.len) {
            0 => {},
            1 => {
                var backup_buffer: [splat_buffer_size]u8 = undefined;
                const splat_buffer = &backup_buffer;
                const memset_len = @min(splat_buffer.len, splat);
                const buf = splat_buffer[0..memset_len];
                @memset(buf, pattern[0]);
                addBuf(&iovecs, &msg.iovlen, buf);
                var remaining_splat = splat - buf.len;
                while (remaining_splat > splat_buffer.len and iovecs.len - msg.iovlen != 0) {
                    assert(buf.len == splat_buffer.len);
                    addBuf(&iovecs, &msg.iovlen, splat_buffer);
                    remaining_splat -= splat_buffer.len;
                }
                addBuf(&iovecs, &msg.iovlen, splat_buffer[0..@min(remaining_splat, splat_buffer.len)]);
            },
            else => for (0..@min(splat, iovecs.len - msg.iovlen)) |_| {
                addBuf(&iovecs, &msg.iovlen, pattern);
            },
        },
    };
    const flags = posix.MSG.NOSIGNAL;

    const syscall: Syscall = try .start();
    while (true) {
        const rc = posix.system.sendmsg(fd, &msg, flags);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                syscall.finish();
                return @intCast(rc);
            },
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ACCES => |err| return errnoBug(err),
                    .AGAIN => |err| return errnoBug(err),
                    .ALREADY => return error.FastOpenAlreadyInProgress,
                    .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                    .CONNRESET => return error.ConnectionResetByPeer,
                    .DESTADDRREQ => |err| return errnoBug(err), // The socket is not connection-mode, and no peer address is set.
                    .FAULT => |err| return errnoBug(err), // An invalid user space address was specified for an argument.
                    .INVAL => |err| return errnoBug(err), // Invalid argument passed.
                    .ISCONN => |err| return errnoBug(err), // connection-mode socket was connected already but a recipient was specified
                    .MSGSIZE => |err| return errnoBug(err),
                    .NOBUFS => return error.SystemResources,
                    .NOMEM => return error.SystemResources,
                    .NOTSOCK => |err| return errnoBug(err), // The file descriptor sockfd does not refer to a socket.
                    .OPNOTSUPP => |err| return errnoBug(err), // Some bit in the flags argument is inappropriate for the socket type.
                    .PIPE => return error.SocketUnconnected,
                    .AFNOSUPPORT => return error.AddressFamilyUnsupported,
                    .HOSTUNREACH => return error.HostUnreachable,
                    .NETUNREACH => return error.NetworkUnreachable,
                    .NOTCONN => return error.SocketUnconnected,
                    .NETDOWN => return error.NetworkDown,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn netWriteWindows(
    userdata: ?*anyopaque,
    handle: net.Socket.Handle,
    header: []const u8,
    data: []const []const u8,
    splat: usize,
) net.Stream.Writer.Error!usize {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    comptime assert(native_os == .windows);

    var iovecs: [max_iovecs_len]ws2_32.WSABUF = undefined;
    var len: u32 = 0;
    addWsaBuf(&iovecs, &len, header);
    for (data[0 .. data.len - 1]) |bytes| addWsaBuf(&iovecs, &len, bytes);
    const pattern = data[data.len - 1];
    if (iovecs.len - len != 0) switch (splat) {
        0 => {},
        1 => addWsaBuf(&iovecs, &len, pattern),
        else => switch (pattern.len) {
            0 => {},
            1 => {
                var backup_buffer: [64]u8 = undefined;
                const splat_buffer = &backup_buffer;
                const memset_len = @min(splat_buffer.len, splat);
                const buf = splat_buffer[0..memset_len];
                @memset(buf, pattern[0]);
                addWsaBuf(&iovecs, &len, buf);
                var remaining_splat = splat - buf.len;
                while (remaining_splat > splat_buffer.len and len < iovecs.len) {
                    addWsaBuf(&iovecs, &len, splat_buffer);
                    remaining_splat -= splat_buffer.len;
                }
                addWsaBuf(&iovecs, &len, splat_buffer[0..@min(remaining_splat, splat_buffer.len)]);
            },
            else => for (0..@min(splat, iovecs.len - len)) |_| {
                addWsaBuf(&iovecs, &len, pattern);
            },
        },
    };

    var syscall: Syscall = try .start();
    while (true) {
        var n: u32 = undefined;
        const rc = ws2_32.WSASend(handle, &iovecs, len, &n, 0, null, null);
        if (rc != ws2_32.SOCKET_ERROR) {
            syscall.finish();
            return n;
        }
        switch (ws2_32.WSAGetLastError()) {
            .IO_PENDING => unreachable, // not overlapped
            .EINTR, .ECANCELLED, .E_CANCELLED, .OPERATION_ABORTED => {
                try syscall.checkCancel();
                continue;
            },
            .NOTINITIALISED => {
                syscall.finish();
                try initializeWsa(t);
                syscall = try .start();
                continue;
            },

            .ECONNABORTED => return syscall.fail(error.ConnectionResetByPeer),
            .ECONNRESET => return syscall.fail(error.ConnectionResetByPeer),
            .EINVAL => return syscall.fail(error.SocketUnconnected),
            .ENETDOWN => return syscall.fail(error.NetworkDown),
            .ENETRESET => return syscall.fail(error.ConnectionResetByPeer),
            .ENOBUFS => return syscall.fail(error.SystemResources),
            .ENOTCONN => return syscall.fail(error.SocketUnconnected),

            else => |err| {
                syscall.finish();
                switch (err) {
                    .ENOTSOCK => return wsaErrorBug(err),
                    .EOPNOTSUPP => return wsaErrorBug(err),
                    .ESHUTDOWN => return wsaErrorBug(err),
                    else => return windows.unexpectedWSAError(err),
                }
            },
        }
    }
}

fn addWsaBuf(v: []ws2_32.WSABUF, i: *u32, bytes: []const u8) void {
    const cap = std.math.maxInt(u32);
    var remaining = bytes;
    while (remaining.len > cap) {
        if (v.len - i.* == 0) return;
        v[i.*] = .{ .buf = @constCast(remaining.ptr), .len = cap };
        i.* += 1;
        remaining = remaining[cap..];
    } else {
        @branchHint(.likely);
        if (v.len - i.* == 0) return;
        v[i.*] = .{ .buf = @constCast(remaining.ptr), .len = @intCast(remaining.len) };
        i.* += 1;
    }
}

fn netWriteUnavailable(
    userdata: ?*anyopaque,
    handle: net.Socket.Handle,
    header: []const u8,
    data: []const []const u8,
    splat: usize,
) net.Stream.Writer.Error!usize {
    _ = userdata;
    _ = handle;
    _ = header;
    _ = data;
    _ = splat;
    return error.NetworkDown;
}

/// This is either usize or u32. Since, either is fine, let's use the same
/// `addBuf` function for both writing to a file and sending network messages.
const iovlen_t = switch (native_os) {
    .wasi => u32,
    else => @FieldType(posix.msghdr_const, "iovlen"),
};

fn addBuf(v: []posix.iovec_const, i: *iovlen_t, bytes: []const u8) void {
    // OS checks ptr addr before length so zero length vectors must be omitted.
    if (bytes.len == 0) return;
    if (v.len - i.* == 0) return;
    v[i.*] = .{ .base = bytes.ptr, .len = bytes.len };
    i.* += 1;
}

fn netClose(userdata: ?*anyopaque, handles: []const net.Socket.Handle) void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    switch (native_os) {
        .windows => for (handles) |handle| closeSocketWindows(handle),
        else => for (handles) |handle| posix.close(handle),
    }
}

fn netCloseUnavailable(userdata: ?*anyopaque, handles: []const net.Socket.Handle) void {
    _ = userdata;
    _ = handles;
    unreachable; // How you gonna close something that was impossible to open?
}

fn netShutdownPosix(userdata: ?*anyopaque, handle: net.Socket.Handle, how: net.ShutdownHow) net.ShutdownError!void {
    if (!have_networking) return error.NetworkDown;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    const posix_how: i32 = switch (how) {
        .recv => posix.SHUT.RD,
        .send => posix.SHUT.WR,
        .both => posix.SHUT.RDWR,
    };

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.shutdown(handle, posix_how))) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .BADF, .NOTSOCK, .INVAL => |err| return errnoBug(err),
                    .NOTCONN => return error.SocketUnconnected,
                    .NOBUFS => return error.SystemResources,
                    else => |err| return posix.unexpectedErrno(err),
                }
            },
        }
    }
}

fn netShutdownWindows(userdata: ?*anyopaque, handle: net.Socket.Handle, how: net.ShutdownHow) net.ShutdownError!void {
    if (!have_networking) return error.NetworkDown;
    const t: *Threaded = @ptrCast(@alignCast(userdata));

    const wsa_how: i32 = switch (how) {
        .recv => ws2_32.SD_RECEIVE,
        .send => ws2_32.SD_SEND,
        .both => ws2_32.SD_BOTH,
    };

    var syscall: Syscall = try .start();
    while (true) {
        const rc = ws2_32.shutdown(handle, wsa_how);
        if (rc != ws2_32.SOCKET_ERROR) {
            syscall.finish();
            return;
        }
        switch (ws2_32.WSAGetLastError()) {
            .EINTR, .ECANCELLED, .E_CANCELLED, .OPERATION_ABORTED => {
                try syscall.checkCancel();
                continue;
            },
            .NOTINITIALISED => {
                syscall.finish();
                try initializeWsa(t);
                syscall = try .start();
                continue;
            },
            else => |e| {
                syscall.finish();
                switch (e) {
                    .ECONNABORTED => return error.ConnectionAborted,
                    .ECONNRESET => return error.ConnectionResetByPeer,
                    .ENETDOWN => return error.NetworkDown,
                    .ENOTCONN => return error.SocketUnconnected,
                    .EINVAL, .ENOTSOCK => |err| return wsaErrorBug(err),
                    else => |err| return windows.unexpectedWSAError(err),
                }
            },
        }
    }
}

fn netShutdownUnavailable(_: ?*anyopaque, _: net.Socket.Handle, _: net.ShutdownHow) net.ShutdownError!void {
    unreachable; // How you gonna shutdown something that was impossible to open?
}

fn netInterfaceNameResolve(
    userdata: ?*anyopaque,
    name: *const net.Interface.Name,
) net.Interface.Name.ResolveError!net.Interface {
    if (!have_networking) return error.InterfaceNotFound;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (native_os == .linux) {
        const sock_fd = openSocketPosix(posix.AF.UNIX, .{ .mode = .dgram }) catch |err| switch (err) {
            error.ProcessFdQuotaExceeded => return error.SystemResources,
            error.SystemFdQuotaExceeded => return error.SystemResources,
            error.AddressFamilyUnsupported => return error.Unexpected,
            error.ProtocolUnsupportedBySystem => return error.Unexpected,
            error.ProtocolUnsupportedByAddressFamily => return error.Unexpected,
            error.SocketModeUnsupported => return error.Unexpected,
            error.OptionUnsupported => return error.Unexpected,
            else => |e| return e,
        };
        defer posix.close(sock_fd);

        var ifr: posix.ifreq = .{
            .ifrn = .{ .name = @bitCast(name.bytes) },
            .ifru = undefined,
        };

        const syscall: Syscall = try .start();
        while (true) {
            switch (posix.errno(posix.system.ioctl(sock_fd, posix.SIOCGIFINDEX, @intFromPtr(&ifr)))) {
                .SUCCESS => {
                    syscall.finish();
                    return .{ .index = @bitCast(ifr.ifru.ivalue) };
                },
                .INTR => {
                    try syscall.checkCancel();
                    continue;
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .INVAL => |err| return errnoBug(err), // Bad parameters.
                        .NOTTY => |err| return errnoBug(err),
                        .NXIO => |err| return errnoBug(err),
                        .BADF => |err| return errnoBug(err), // File descriptor used after closed.
                        .FAULT => |err| return errnoBug(err), // Bad pointer parameter.
                        .IO => |err| return errnoBug(err), // sock_fd is not a file descriptor
                        .NODEV => return error.InterfaceNotFound,
                        else => |err| return posix.unexpectedErrno(err),
                    }
                },
            }
        }
    }

    if (native_os == .windows) {
        try Thread.checkCancel();
        @panic("TODO implement netInterfaceNameResolve for Windows");
    }

    if (builtin.link_libc) {
        try Thread.checkCancel();
        const index = std.c.if_nametoindex(&name.bytes);
        if (index == 0) return error.InterfaceNotFound;
        return .{ .index = @bitCast(index) };
    }

    @panic("unimplemented");
}

fn netInterfaceNameResolveUnavailable(
    userdata: ?*anyopaque,
    name: *const net.Interface.Name,
) net.Interface.Name.ResolveError!net.Interface {
    _ = userdata;
    _ = name;
    return error.InterfaceNotFound;
}

fn netInterfaceName(userdata: ?*anyopaque, interface: net.Interface) net.Interface.NameError!net.Interface.Name {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;
    try Thread.checkCancel();

    if (native_os == .linux) {
        _ = interface;
        @panic("TODO implement netInterfaceName for linux");
    }

    if (native_os == .windows) {
        @panic("TODO implement netInterfaceName for windows");
    }

    if (builtin.link_libc) {
        @panic("TODO implement netInterfaceName for libc");
    }

    @panic("unimplemented");
}

fn netInterfaceNameUnavailable(userdata: ?*anyopaque, interface: net.Interface) net.Interface.NameError!net.Interface.Name {
    _ = userdata;
    _ = interface;
    return error.Unexpected;
}

fn netLookup(
    userdata: ?*anyopaque,
    host_name: HostName,
    resolved: *Io.Queue(HostName.LookupResult),
    options: HostName.LookupOptions,
) net.HostName.LookupError!void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    defer resolved.close(io(t));
    netLookupFallible(t, host_name, resolved, options) catch |err| switch (err) {
        error.Closed => unreachable, // `resolved` must not be closed until `netLookup` returns
        else => |e| return e,
    };
}

fn netLookupUnavailable(
    userdata: ?*anyopaque,
    host_name: HostName,
    resolved: *Io.Queue(HostName.LookupResult),
    options: HostName.LookupOptions,
) net.HostName.LookupError!void {
    _ = host_name;
    _ = options;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    resolved.close(ioBasic(t));
    return error.NetworkDown;
}

fn netLookupFallible(
    t: *Threaded,
    host_name: HostName,
    resolved: *Io.Queue(HostName.LookupResult),
    options: HostName.LookupOptions,
) (net.HostName.LookupError || Io.QueueClosedError)!void {
    if (!have_networking) return error.NetworkDown;

    const t_io = io(t);
    const name = host_name.bytes;
    assert(name.len <= HostName.max_len);

    if (is_windows) {
        var name_buffer: [HostName.max_len + 1]u16 = undefined;
        const name_len = std.unicode.wtf8ToWtf16Le(&name_buffer, host_name.bytes) catch
            unreachable; // HostName is prevalidated.
        name_buffer[name_len] = 0;
        const name_w = name_buffer[0..name_len :0];

        var port_buffer: [8]u8 = undefined;
        var port_buffer_wide: [8]u16 = undefined;
        const port = std.fmt.bufPrint(&port_buffer, "{d}", .{options.port}) catch
            unreachable; // `port_buffer` is big enough for decimal u16.
        for (port, port_buffer_wide[0..port.len]) |byte, *wide|
            wide.* = std.mem.nativeToLittle(u16, byte);
        port_buffer_wide[port.len] = 0;
        const port_w = port_buffer_wide[0..port.len :0];

        const hints: ws2_32.ADDRINFOEXW = .{
            .flags = .{ .NUMERICSERV = true },
            .family = if (options.family) |f| switch (f) {
                .ip4 => posix.AF.INET,
                .ip6 => posix.AF.INET6,
            } else posix.AF.UNSPEC,
            .socktype = posix.SOCK.STREAM,
            .protocol = posix.IPPROTO.TCP,
            .canonname = null,
            .addr = null,
            .addrlen = 0,
            .blob = null,
            .bloblen = 0,
            .provider = null,
            .next = null,
        };
        var res: *ws2_32.ADDRINFOEXW = undefined;
        const timeout: ?*ws2_32.timeval = null;
        while (true) {
            // TODO: hook this up to cancelation with `Thread.Status.cancelation.blocked_windows_dns`.
            // See matching TODO in `Thread.cancelAwaitable`.
            try Thread.checkCancel();
            // TODO make this append to the queue eagerly rather than blocking until the whole thing finishes
            const rc: ws2_32.WinsockError = @enumFromInt(ws2_32.GetAddrInfoExW(name_w, port_w, .DNS, null, &hints, &res, timeout, null, null, null));
            switch (rc) {
                @as(ws2_32.WinsockError, @enumFromInt(0)) => break,
                .EINTR, .ECANCELLED, .E_CANCELLED, .OPERATION_ABORTED => continue,
                .NOTINITIALISED => {
                    try initializeWsa(t);
                    continue;
                },
                .TRY_AGAIN => return error.NameServerFailure,
                .EINVAL => |err| return wsaErrorBug(err),
                .NO_RECOVERY => return error.NameServerFailure,
                .EAFNOSUPPORT => return error.AddressFamilyUnsupported,
                .NOT_ENOUGH_MEMORY => return error.SystemResources,
                .HOST_NOT_FOUND => return error.UnknownHostName,
                .TYPE_NOT_FOUND => return error.ProtocolUnsupportedByAddressFamily,
                .ESOCKTNOSUPPORT => return error.ProtocolUnsupportedBySystem,
                else => |err| return windows.unexpectedWSAError(err),
            }
        }
        defer ws2_32.FreeAddrInfoExW(res);

        var it: ?*ws2_32.ADDRINFOEXW = res;
        var canon_name: ?[*:0]const u16 = null;
        while (it) |info| : (it = info.next) {
            const addr = info.addr orelse continue;
            const storage: WsaAddress = .{ .any = addr.* };
            try resolved.putOne(t_io, .{ .address = addressFromWsa(&storage) });

            if (info.canonname) |n| {
                if (canon_name == null) {
                    canon_name = n;
                }
            }
        }
        if (canon_name) |n| {
            const len = std.unicode.wtf16LeToWtf8(options.canonical_name_buffer, std.mem.sliceTo(n, 0));
            try resolved.putOne(t_io, .{ .canonical_name = .{
                .bytes = options.canonical_name_buffer[0..len],
            } });
        }
        return;
    }

    // On Linux, glibc provides getaddrinfo_a which is capable of supporting our semantics.
    // However, musl's POSIX-compliant getaddrinfo is not, so we bypass it.

    if (builtin.target.isGnuLibC()) {
        // TODO use getaddrinfo_a / gai_cancel
    }

    if (native_os == .linux) {
        if (options.family != .ip4) {
            if (IpAddress.parseIp6(name, options.port)) |addr| {
                try resolved.putAll(t_io, &.{
                    .{ .address = addr },
                    .{ .canonical_name = copyCanon(options.canonical_name_buffer, name) },
                });
                return;
            } else |_| {}
        }

        if (options.family != .ip6) {
            if (IpAddress.parseIp4(name, options.port)) |addr| {
                try resolved.putAll(t_io, &.{
                    .{ .address = addr },
                    .{ .canonical_name = copyCanon(options.canonical_name_buffer, name) },
                });
                return;
            } else |_| {}
        }

        lookupHosts(t, host_name, resolved, options) catch |err| switch (err) {
            error.UnknownHostName => {},
            else => |e| return e,
        };

        // RFC 6761 Section 6.3.3
        // Name resolution APIs and libraries SHOULD recognize
        // localhost names as special and SHOULD always return the IP
        // loopback address for address queries and negative responses
        // for all other query types.

        // Check for equal to "localhost(.)" or ends in ".localhost(.)"
        const localhost = if (name[name.len - 1] == '.') "localhost." else "localhost";
        if (std.mem.endsWith(u8, name, localhost) and
            (name.len == localhost.len or name[name.len - localhost.len] == '.'))
        {
            var results_buffer: [3]HostName.LookupResult = undefined;
            var results_index: usize = 0;
            if (options.family != .ip4) {
                results_buffer[results_index] = .{ .address = .{ .ip6 = .loopback(options.port) } };
                results_index += 1;
            }
            if (options.family != .ip6) {
                results_buffer[results_index] = .{ .address = .{ .ip4 = .loopback(options.port) } };
                results_index += 1;
            }
            const canon_name = "localhost";
            const canon_name_dest = options.canonical_name_buffer[0..canon_name.len];
            canon_name_dest.* = canon_name.*;
            results_buffer[results_index] = .{ .canonical_name = .{ .bytes = canon_name_dest } };
            results_index += 1;
            try resolved.putAll(t_io, results_buffer[0..results_index]);
            return;
        }

        return lookupDnsSearch(t, host_name, resolved, options);
    }

    if (native_os == .openbsd) {
        // TODO use getaddrinfo_async / asr_abort
    }

    if (native_os == .freebsd) {
        // TODO use dnsres_getaddrinfo
    }

    if (is_darwin) {
        // TODO use CFHostStartInfoResolution / CFHostCancelInfoResolution
    }

    if (builtin.link_libc) {
        // This operating system lacks a way to resolve asynchronously. We are
        // stuck with getaddrinfo.
        var name_buffer: [HostName.max_len + 1]u8 = undefined;
        @memcpy(name_buffer[0..host_name.bytes.len], host_name.bytes);
        name_buffer[host_name.bytes.len] = 0;
        const name_c = name_buffer[0..host_name.bytes.len :0];

        var port_buffer: [8]u8 = undefined;
        const port_c = std.fmt.bufPrintZ(&port_buffer, "{d}", .{options.port}) catch unreachable;

        const hints: posix.addrinfo = .{
            .flags = .{ .NUMERICSERV = true },
            .family = posix.AF.UNSPEC,
            .socktype = posix.SOCK.STREAM,
            .protocol = posix.IPPROTO.TCP,
            .canonname = null,
            .addr = null,
            .addrlen = 0,
            .next = null,
        };
        var res: ?*posix.addrinfo = null;
        const syscall: Syscall = try .start();
        while (true) {
            switch (posix.system.getaddrinfo(name_c.ptr, port_c.ptr, &hints, &res)) {
                @as(posix.system.EAI, @enumFromInt(0)) => {
                    syscall.finish();
                    break;
                },
                .SYSTEM => switch (posix.errno(-1)) {
                    .INTR => {
                        try syscall.checkCancel();
                        continue;
                    },
                    else => |e| {
                        syscall.finish();
                        return posix.unexpectedErrno(e);
                    },
                },
                else => |e| {
                    syscall.finish();
                    switch (e) {
                        .ADDRFAMILY => return error.AddressFamilyUnsupported,
                        .AGAIN => return error.NameServerFailure,
                        .FAIL => return error.NameServerFailure,
                        .FAMILY => return error.AddressFamilyUnsupported,
                        .MEMORY => return error.SystemResources,
                        .NODATA => return error.UnknownHostName,
                        .NONAME => return error.UnknownHostName,
                        else => return error.Unexpected,
                    }
                },
            }
        }
        defer if (res) |some| posix.system.freeaddrinfo(some);

        var it = res;
        var canon_name: ?[*:0]const u8 = null;
        while (it) |info| : (it = info.next) {
            const addr = info.addr orelse continue;
            const storage: PosixAddress = .{ .any = addr.* };
            try resolved.putOne(t_io, .{ .address = addressFromPosix(&storage) });

            if (info.canonname) |n| {
                if (canon_name == null) {
                    canon_name = n;
                }
            }
        }
        if (canon_name) |n| {
            try resolved.putOne(t_io, .{
                .canonical_name = copyCanon(options.canonical_name_buffer, std.mem.sliceTo(n, 0)),
            });
        }
        return;
    }

    return error.OptionUnsupported;
}

fn lockStderr(userdata: ?*anyopaque, terminal_mode: ?Io.Terminal.Mode) Io.Cancelable!Io.LockedStderr {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    // Only global mutex since this is Threaded.
    std.process.stderr_thread_mutex.lock();
    return initLockedStderr(t, terminal_mode);
}

fn tryLockStderr(userdata: ?*anyopaque, terminal_mode: ?Io.Terminal.Mode) Io.Cancelable!?Io.LockedStderr {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    // Only global mutex since this is Threaded.
    if (!std.process.stderr_thread_mutex.tryLock()) return null;
    return try initLockedStderr(t, terminal_mode);
}

fn initLockedStderr(t: *Threaded, terminal_mode: ?Io.Terminal.Mode) Io.Cancelable!Io.LockedStderr {
    if (!t.stderr_writer_initialized) {
        const io_t = ioBasic(t);
        if (is_windows) t.stderr_writer.file = .stderr();
        t.stderr_writer.io = io_t;
        t.stderr_writer_initialized = true;
        t.scanEnviron();
        const NO_COLOR = t.environ.exist.NO_COLOR;
        const CLICOLOR_FORCE = t.environ.exist.CLICOLOR_FORCE;
        t.stderr_mode = terminal_mode orelse try .detect(io_t, t.stderr_writer.file, NO_COLOR, CLICOLOR_FORCE);
    }
    return .{
        .file_writer = &t.stderr_writer,
        .terminal_mode = terminal_mode orelse t.stderr_mode,
    };
}

fn unlockStderr(userdata: ?*anyopaque) void {
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    t.stderr_writer.interface.flush() catch |err| switch (err) {
        error.WriteFailed => switch (t.stderr_writer.err.?) {
            error.Canceled => recancel(t),
            else => {},
        },
    };
    t.stderr_writer.interface.end = 0;
    t.stderr_writer.interface.buffer = &.{};
    std.process.stderr_thread_mutex.unlock();
}

fn processSetCurrentDir(userdata: ?*anyopaque, dir: Dir) std.process.SetCurrentDirError!void {
    if (native_os == .wasi) return error.OperationUnsupported;
    const t: *Threaded = @ptrCast(@alignCast(userdata));
    _ = t;

    if (is_windows) {
        var dir_path_buffer: [windows.PATH_MAX_WIDE]u16 = undefined;
        // TODO move GetFinalPathNameByHandle logic into std.Io.Threaded and add cancel checks
        try Thread.checkCancel();
        const dir_path = try windows.GetFinalPathNameByHandle(dir.handle, .{}, &dir_path_buffer);
        const path_len_bytes = std.math.cast(u16, dir_path.len * 2) orelse return error.NameTooLong;
        var nt_name: windows.UNICODE_STRING = .{
            .Length = path_len_bytes,
            .MaximumLength = path_len_bytes,
            .Buffer = @constCast(dir_path.ptr),
        };
        const syscall: Syscall = try .start();
        while (true) switch (windows.ntdll.RtlSetCurrentDirectory_U(&nt_name)) {
            .SUCCESS => return syscall.finish(),
            .OBJECT_NAME_INVALID => return syscall.fail(error.BadPathName),
            .OBJECT_NAME_NOT_FOUND => return syscall.fail(error.FileNotFound),
            .OBJECT_PATH_NOT_FOUND => return syscall.fail(error.FileNotFound),
            .NO_MEDIA_IN_DEVICE => return syscall.fail(error.NoDevice),
            .INVALID_PARAMETER => |err| return syscall.ntstatusBug(err),
            .ACCESS_DENIED => return syscall.fail(error.AccessDenied),
            .OBJECT_PATH_SYNTAX_BAD => |err| return syscall.ntstatusBug(err),
            .NOT_A_DIRECTORY => return syscall.fail(error.NotDir),
            .CANCELLED => {
                try syscall.checkCancel();
                continue;
            },
            else => |status| return syscall.unexpectedNtstatus(status),
        };
    }

    if (dir.handle == posix.AT.FDCWD) return;

    const syscall: Syscall = try .start();
    while (true) {
        switch (posix.errno(posix.system.fchdir(dir.handle))) {
            .SUCCESS => return syscall.finish(),
            .INTR => {
                try syscall.checkCancel();
                continue;
            },
            .ACCES => {
                syscall.finish();
                return error.AccessDenied;
            },
            .BADF => |err| {
                syscall.finish();
                return errnoBug(err);
            },
            .NOTDIR => {
                syscall.finish();
                return error.NotDir;
            },
            .IO => {
                syscall.finish();
                return error.FileSystem;
            },
            else => |err| {
                syscall.finish();
                return posix.unexpectedErrno(err);
            },
        }
    }
}

pub const PosixAddress = extern union {
    any: posix.sockaddr,
    in: posix.sockaddr.in,
    in6: posix.sockaddr.in6,
};

const UnixAddress = extern union {
    any: posix.sockaddr,
    un: posix.sockaddr.un,
};

const WsaAddress = extern union {
    any: ws2_32.sockaddr,
    in: ws2_32.sockaddr.in,
    in6: ws2_32.sockaddr.in6,
    un: ws2_32.sockaddr.un,
};

pub fn posixAddressFamily(a: *const IpAddress) posix.sa_family_t {
    return switch (a.*) {
        .ip4 => posix.AF.INET,
        .ip6 => posix.AF.INET6,
    };
}

pub fn addressFromPosix(posix_address: *const PosixAddress) IpAddress {
    return switch (posix_address.any.family) {
        posix.AF.INET => .{ .ip4 = address4FromPosix(&posix_address.in) },
        posix.AF.INET6 => .{ .ip6 = address6FromPosix(&posix_address.in6) },
        else => .{ .ip4 = .loopback(0) },
    };
}

fn addressFromWsa(wsa_address: *const WsaAddress) IpAddress {
    return switch (wsa_address.any.family) {
        posix.AF.INET => .{ .ip4 = address4FromWsa(&wsa_address.in) },
        posix.AF.INET6 => .{ .ip6 = address6FromWsa(&wsa_address.in6) },
        else => .{ .ip4 = .loopback(0) },
    };
}

pub fn addressToPosix(a: *const IpAddress, storage: *PosixAddress) posix.socklen_t {
    return switch (a.*) {
        .ip4 => |ip4| {
            storage.in = address4ToPosix(ip4);
            return @sizeOf(posix.sockaddr.in);
        },
        .ip6 => |*ip6| {
            storage.in6 = address6ToPosix(ip6);
            return @sizeOf(posix.sockaddr.in6);
        },
    };
}

fn addressToWsa(a: *const IpAddress, storage: *WsaAddress) i32 {
    return switch (a.*) {
        .ip4 => |ip4| {
            storage.in = address4ToPosix(ip4);
            return @sizeOf(posix.sockaddr.in);
        },
        .ip6 => |*ip6| {
            storage.in6 = address6ToPosix(ip6);
            return @sizeOf(posix.sockaddr.in6);
        },
    };
}

fn addressUnixToPosix(a: *const net.UnixAddress, storage: *UnixAddress) posix.socklen_t {
    @memcpy(storage.un.path[0..a.path.len], a.path);
    storage.un.family = posix.AF.UNIX;
    storage.un.path[a.path.len] = 0;
    return @sizeOf(posix.sockaddr.un);
}

fn addressUnixToWsa(a: *const net.UnixAddress, storage: *WsaAddress) i32 {
    @memcpy(storage.un.path[0..a.path.len], a.path);
    storage.un.family = posix.AF.UNIX;
    storage.un.path[a.path.len] = 0;
    return @sizeOf(posix.sockaddr.un);
}

fn address4FromPosix(in: *const posix.sockaddr.in) net.Ip4Address {
    return .{
        .port = std.mem.bigToNative(u16, in.port),
        .bytes = @bitCast(in.addr),
    };
}

fn address6FromPosix(in6: *const posix.sockaddr.in6) net.Ip6Address {
    return .{
        .port = std.mem.bigToNative(u16, in6.port),
        .bytes = in6.addr,
        .flow = in6.flowinfo,
        .interface = .{ .index = in6.scope_id },
    };
}

fn address4FromWsa(in: *const ws2_32.sockaddr.in) net.Ip4Address {
    return .{
        .port = std.mem.bigToNative(u16, in.port),
        .bytes = @bitCast(in.addr),
    };
}

fn address6FromWsa(in6: *const ws2_32.sockaddr.in6) net.Ip6Address {
    return .{
        .port = std.mem.bigToNative(u16, in6.port),
        .bytes = in6.addr,
        .flow = in6.flowinfo,
        .interface = .{ .index = in6.scope_id },
    };
}

fn address4ToPosix(a: net.Ip4Address) posix.sockaddr.in {
    return .{
        .port = std.mem.nativeToBig(u16, a.port),
        .addr = @bitCast(a.bytes),
    };
}

fn address6ToPosix(a: *const net.Ip6Address) posix.sockaddr.in6 {
    return .{
        .port = std.mem.nativeToBig(u16, a.port),
        .flowinfo = a.flow,
        .addr = a.bytes,
        .scope_id = a.interface.index,
    };
}

pub fn errnoBug(err: posix.E) Io.UnexpectedError {
    if (is_debug) std.debug.panic("programmer bug caused syscall error: {t}", .{err});
    return error.Unexpected;
}

fn wsaErrorBug(err: ws2_32.WinsockError) Io.UnexpectedError {
    if (is_debug) std.debug.panic("programmer bug caused syscall error: {t}", .{err});
    return error.Unexpected;
}

pub fn posixSocketMode(mode: net.Socket.Mode) u32 {
    return switch (mode) {
        .stream => posix.SOCK.STREAM,
        .dgram => posix.SOCK.DGRAM,
        .seqpacket => posix.SOCK.SEQPACKET,
        .raw => posix.SOCK.RAW,
        .rdm => posix.SOCK.RDM,
    };
}

pub fn posixProtocol(protocol: ?net.Protocol) u32 {
    return @intFromEnum(protocol orelse return 0);
}

fn recoverableOsBugDetected() void {
    if (is_debug) unreachable;
}

fn clockToPosix(clock: Io.Clock) posix.clockid_t {
    return switch (clock) {
        .real => posix.CLOCK.REALTIME,
        .awake => switch (native_os) {
            .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos => posix.CLOCK.UPTIME_RAW,
            else => posix.CLOCK.MONOTONIC,
        },
        .boot => switch (native_os) {
            .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos => posix.CLOCK.MONOTONIC_RAW,
            // On freebsd derivatives, use MONOTONIC_FAST as currently there's
            // no precision tradeoff.
            .freebsd, .dragonfly => posix.CLOCK.MONOTONIC_FAST,
            // On linux, use BOOTTIME instead of MONOTONIC as it ticks while
            // suspended.
            .linux => posix.CLOCK.BOOTTIME,
            // On other posix systems, MONOTONIC is generally the fastest and
            // ticks while suspended.
            else => posix.CLOCK.MONOTONIC,
        },
        .cpu_process => posix.CLOCK.PROCESS_CPUTIME_ID,
        .cpu_thread => posix.CLOCK.THREAD_CPUTIME_ID,
    };
}

fn clockToWasi(clock: Io.Clock) std.os.wasi.clockid_t {
    return switch (clock) {
        .real => .REALTIME,
        .awake => .MONOTONIC,
        .boot => .MONOTONIC,
        .cpu_process => .PROCESS_CPUTIME_ID,
        .cpu_thread => .THREAD_CPUTIME_ID,
    };
}

const linux_statx_request: std.os.linux.STATX = .{
    .TYPE = true,
    .MODE = true,
    .ATIME = true,
    .MTIME = true,
    .CTIME = true,
    .INO = true,
    .SIZE = true,
    .NLINK = true,
};

const linux_statx_check: std.os.linux.STATX = .{
    .TYPE = true,
    .MODE = true,
    .ATIME = false,
    .MTIME = true,
    .CTIME = true,
    .INO = true,
    .SIZE = true,
    .NLINK = true,
};

fn statFromLinux(stx: *const std.os.linux.Statx) Io.UnexpectedError!File.Stat {
    const actual_mask_int: u32 = @bitCast(stx.mask);
    const wanted_mask_int: u32 = @bitCast(linux_statx_check);
    if ((actual_mask_int | wanted_mask_int) != actual_mask_int) return error.Unexpected;

    return .{
        .inode = stx.ino,
        .nlink = stx.nlink,
        .size = stx.size,
        .permissions = .fromMode(stx.mode),
        .kind = switch (stx.mode & std.os.linux.S.IFMT) {
            std.os.linux.S.IFDIR => .directory,
            std.os.linux.S.IFCHR => .character_device,
            std.os.linux.S.IFBLK => .block_device,
            std.os.linux.S.IFREG => .file,
            std.os.linux.S.IFIFO => .named_pipe,
            std.os.linux.S.IFLNK => .sym_link,
            std.os.linux.S.IFSOCK => .unix_domain_socket,
            else => .unknown,
        },
        .atime = if (!stx.mask.ATIME) null else .{
            .nanoseconds = @intCast(@as(i128, stx.atime.sec) * std.time.ns_per_s + stx.atime.nsec),
        },
        .mtime = .{ .nanoseconds = @intCast(@as(i128, stx.mtime.sec) * std.time.ns_per_s + stx.mtime.nsec) },
        .ctime = .{ .nanoseconds = @intCast(@as(i128, stx.ctime.sec) * std.time.ns_per_s + stx.ctime.nsec) },
    };
}

fn statFromPosix(st: *const posix.Stat) File.Stat {
    const atime = st.atime();
    const mtime = st.mtime();
    const ctime = st.ctime();
    return .{
        .inode = st.ino,
        .nlink = st.nlink,
        .size = @bitCast(st.size),
        .permissions = .fromMode(st.mode),
        .kind = k: {
            const m = st.mode & posix.S.IFMT;
            switch (m) {
                posix.S.IFBLK => break :k .block_device,
                posix.S.IFCHR => break :k .character_device,
                posix.S.IFDIR => break :k .directory,
                posix.S.IFIFO => break :k .named_pipe,
                posix.S.IFLNK => break :k .sym_link,
                posix.S.IFREG => break :k .file,
                posix.S.IFSOCK => break :k .unix_domain_socket,
                else => {},
            }
            if (native_os == .illumos) switch (m) {
                posix.S.IFDOOR => break :k .door,
                posix.S.IFPORT => break :k .event_port,
                else => {},
            };

            break :k .unknown;
        },
        .atime = timestampFromPosix(&atime),
        .mtime = timestampFromPosix(&mtime),
        .ctime = timestampFromPosix(&ctime),
    };
}

fn statFromWasi(st: *const std.os.wasi.filestat_t) File.Stat {
    return .{
        .inode = st.ino,
        .nlink = st.nlink,
        .size = @bitCast(st.size),
        .permissions = .default_file,
        .kind = switch (st.filetype) {
            .BLOCK_DEVICE => .block_device,
            .CHARACTER_DEVICE => .character_device,
            .DIRECTORY => .directory,
            .SYMBOLIC_LINK => .sym_link,
            .REGULAR_FILE => .file,
            .SOCKET_STREAM, .SOCKET_DGRAM => .unix_domain_socket,
            else => .unknown,
        },
        .atime = .fromNanoseconds(st.atim),
        .mtime = .fromNanoseconds(st.mtim),
        .ctime = .fromNanoseconds(st.ctim),
    };
}

fn timestampFromPosix(timespec: *const posix.timespec) Io.Timestamp {
    return .{ .nanoseconds = @intCast(@as(i128, timespec.sec) * std.time.ns_per_s + timespec.nsec) };
}

fn timestampToPosix(nanoseconds: i96) posix.timespec {
    if (builtin.zig_backend == .stage2_wasm) {
        // Workaround for https://codeberg.org/ziglang/zig/issues/30575
        return .{
            .sec = @intCast(@divTrunc(nanoseconds, std.time.ns_per_s)),
            .nsec = @intCast(@rem(nanoseconds, std.time.ns_per_s)),
        };
    }
    return .{
        .sec = @intCast(@divFloor(nanoseconds, std.time.ns_per_s)),
        .nsec = @intCast(@mod(nanoseconds, std.time.ns_per_s)),
    };
}

fn setTimestampToPosix(set_ts: File.SetTimestamp) posix.timespec {
    return switch (set_ts) {
        .unchanged => .OMIT,
        .now => .NOW,
        .new => |t| timestampToPosix(t.nanoseconds),
    };
}

fn pathToPosix(file_path: []const u8, buffer: *[posix.PATH_MAX]u8) Dir.PathNameError![:0]u8 {
    if (std.mem.containsAtLeastScalar2(u8, file_path, 0, 1)) return error.BadPathName;
    // >= rather than > to make room for the null byte
    if (file_path.len >= buffer.len) return error.NameTooLong;
    @memcpy(buffer[0..file_path.len], file_path);
    buffer[file_path.len] = 0;
    return buffer[0..file_path.len :0];
}

fn lookupDnsSearch(
    t: *Threaded,
    host_name: HostName,
    resolved: *Io.Queue(HostName.LookupResult),
    options: HostName.LookupOptions,
) (HostName.LookupError || Io.QueueClosedError)!void {
    const t_io = io(t);
    const rc = HostName.ResolvConf.init(t_io) catch return error.ResolvConfParseFailed;

    // Count dots, suppress search when >=ndots or name ends in
    // a dot, which is an explicit request for global scope.
    const dots = std.mem.countScalar(u8, host_name.bytes, '.');
    const search_len = if (dots >= rc.ndots or std.mem.endsWith(u8, host_name.bytes, ".")) 0 else rc.search_len;
    const search = rc.search_buffer[0..search_len];

    var canon_name = host_name.bytes;

    // Strip final dot for canon, fail if multiple trailing dots.
    if (std.mem.endsWith(u8, canon_name, ".")) canon_name.len -= 1;
    if (std.mem.endsWith(u8, canon_name, ".")) return error.UnknownHostName;

    // Name with search domain appended is set up in `canon_name`. This
    // both provides the desired default canonical name (if the requested
    // name is not a CNAME record) and serves as a buffer for passing the
    // full requested name to `lookupDns`.
    @memcpy(options.canonical_name_buffer[0..canon_name.len], canon_name);
    options.canonical_name_buffer[canon_name.len] = '.';
    var it = std.mem.tokenizeAny(u8, search, " \t");
    while (it.next()) |token| {
        @memcpy(options.canonical_name_buffer[canon_name.len + 1 ..][0..token.len], token);
        const lookup_canon_name = options.canonical_name_buffer[0 .. canon_name.len + 1 + token.len];
        if (lookupDns(t, lookup_canon_name, &rc, resolved, options)) |result| {
            return result;
        } else |err| switch (err) {
            error.UnknownHostName => continue,
            else => |e| return e,
        }
    }

    const lookup_canon_name = options.canonical_name_buffer[0..canon_name.len];
    return lookupDns(t, lookup_canon_name, &rc, resolved, options);
}

fn lookupDns(
    t: *Threaded,
    lookup_canon_name: []const u8,
    rc: *const HostName.ResolvConf,
    resolved: *Io.Queue(HostName.LookupResult),
    options: HostName.LookupOptions,
) (HostName.LookupError || Io.QueueClosedError)!void {
    const t_io = io(t);
    const family_records: [2]struct { af: IpAddress.Family, rr: HostName.DnsRecord } = .{
        .{ .af = .ip6, .rr = .A },
        .{ .af = .ip4, .rr = .AAAA },
    };
    var query_buffers: [2][280]u8 = undefined;
    var answer_buffer: [2 * 512]u8 = undefined;
    var queries_buffer: [2][]const u8 = undefined;
    var answers_buffer: [2][]const u8 = undefined;
    var nq: usize = 0;
    var answer_buffer_i: usize = 0;

    for (family_records) |fr| {
        if (options.family != fr.af) {
            const entropy = std.crypto.random.array(u8, 2);
            const len = writeResolutionQuery(&query_buffers[nq], 0, lookup_canon_name, 1, fr.rr, entropy);
            queries_buffer[nq] = query_buffers[nq][0..len];
            nq += 1;
        }
    }

    var ip4_mapped_buffer: [HostName.ResolvConf.max_nameservers]IpAddress = undefined;
    const ip4_mapped = ip4_mapped_buffer[0..rc.nameservers_len];
    var any_ip6 = false;
    for (rc.nameservers(), ip4_mapped) |*ns, *m| {
        m.* = .{ .ip6 = .fromAny(ns.*) };
        any_ip6 = any_ip6 or ns.* == .ip6;
    }
    var socket = s: {
        if (any_ip6) ip6: {
            const ip6_addr: IpAddress = .{ .ip6 = .unspecified(0) };
            const socket = ip6_addr.bind(t_io, .{ .ip6_only = true, .mode = .dgram }) catch |err| switch (err) {
                error.AddressFamilyUnsupported => break :ip6,
                else => |e| return e,
            };
            break :s socket;
        }
        any_ip6 = false;
        const ip4_addr: IpAddress = .{ .ip4 = .unspecified(0) };
        const socket = try ip4_addr.bind(t_io, .{ .mode = .dgram });
        break :s socket;
    };
    defer socket.close(t_io);

    const mapped_nameservers = if (any_ip6) ip4_mapped else rc.nameservers();
    const queries = queries_buffer[0..nq];
    const answers = answers_buffer[0..queries.len];
    var answers_remaining = answers.len;
    for (answers) |*answer| answer.len = 0;

    // boot clock is chosen because time the computer is suspended should count
    // against time spent waiting for external messages to arrive.
    const clock: Io.Clock = .boot;
    var now_ts = try clock.now(t_io);
    const final_ts = now_ts.addDuration(.fromSeconds(rc.timeout_seconds));
    const attempt_duration: Io.Duration = .{
        .nanoseconds = (std.time.ns_per_s / rc.attempts) * @as(i96, rc.timeout_seconds),
    };

    send: while (now_ts.nanoseconds < final_ts.nanoseconds) : (now_ts = try clock.now(t_io)) {
        const max_messages = queries_buffer.len * HostName.ResolvConf.max_nameservers;
        {
            var message_buffer: [max_messages]Io.net.OutgoingMessage = undefined;
            var message_i: usize = 0;
            for (queries, answers) |query, *answer| {
                if (answer.len != 0) continue;
                for (mapped_nameservers) |*ns| {
                    message_buffer[message_i] = .{
                        .address = ns,
                        .data_ptr = query.ptr,
                        .data_len = query.len,
                    };
                    message_i += 1;
                }
            }
            _ = netSendPosix(t, socket.handle, message_buffer[0..message_i], .{});
        }

        const timeout: Io.Timeout = .{ .deadline = .{
            .raw = now_ts.addDuration(attempt_duration),
            .clock = clock,
        } };

        while (true) {
            var message_buffer: [max_messages]Io.net.IncomingMessage = @splat(.init);
            const buf = answer_buffer[answer_buffer_i..];
            const recv_err, const recv_n = socket.receiveManyTimeout(t_io, &message_buffer, buf, .{}, timeout);
            for (message_buffer[0..recv_n]) |*received_message| {
                const reply = received_message.data;
                // Ignore non-identifiable packets.
                if (reply.len < 4) continue;

                // Ignore replies from addresses we didn't send to.
                const ns = for (mapped_nameservers) |*ns| {
                    if (received_message.from.eql(ns)) break ns;
                } else {
                    continue;
                };

                // Find which query this answer goes with, if any.
                const query, const answer = for (queries, answers) |query, *answer| {
                    if (reply[0] == query[0] and reply[1] == query[1]) break .{ query, answer };
                } else {
                    continue;
                };
                if (answer.len != 0) continue;

                // Only accept positive or negative responses; retry immediately on
                // server failure, and ignore all other codes such as refusal.
                switch (reply[3] & 15) {
                    0, 3 => {
                        answer.* = reply;
                        answer_buffer_i += reply.len;
                        answers_remaining -= 1;
                        if (answer_buffer.len - answer_buffer_i == 0) break :send;
                        if (answers_remaining == 0) break :send;
                    },
                    2 => {
                        var retry_message: Io.net.OutgoingMessage = .{
                            .address = ns,
                            .data_ptr = query.ptr,
                            .data_len = query.len,
                        };
                        _ = netSendPosix(t, socket.handle, (&retry_message)[0..1], .{});
                        continue;
                    },
                    else => continue,
                }
            }
            if (recv_err) |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.Timeout => continue :send,
                else => continue,
            };
        }
    } else {
        return error.NameServerFailure;
    }

    var addresses_len: usize = 0;
    var canonical_name: ?HostName = null;

    for (answers) |answer| {
        var it = HostName.DnsResponse.init(answer) catch {
            // Here we could potentially add diagnostics to the results queue.
            continue;
        };
        while (it.next() catch {
            // Here we could potentially add diagnostics to the results queue.
            continue;
        }) |record| switch (record.rr) {
            .A => {
                const data = record.packet[record.data_off..][0..record.data_len];
                if (data.len != 4) return error.InvalidDnsARecord;
                try resolved.putOne(t_io, .{ .address = .{ .ip4 = .{
                    .bytes = data[0..4].*,
                    .port = options.port,
                } } });
                addresses_len += 1;
            },
            .AAAA => {
                const data = record.packet[record.data_off..][0..record.data_len];
                if (data.len != 16) return error.InvalidDnsAAAARecord;
                try resolved.putOne(t_io, .{ .address = .{ .ip6 = .{
                    .bytes = data[0..16].*,
                    .port = options.port,
                } } });
                addresses_len += 1;
            },
            .CNAME => {
                _, canonical_name = HostName.expand(record.packet, record.data_off, options.canonical_name_buffer) catch
                    return error.InvalidDnsCnameRecord;
            },
            _ => continue,
        };
    }

    try resolved.putOne(t_io, .{ .canonical_name = canonical_name orelse .{ .bytes = lookup_canon_name } });
    if (addresses_len == 0) return error.NameServerFailure;
}

fn lookupHosts(
    t: *Threaded,
    host_name: HostName,
    resolved: *Io.Queue(HostName.LookupResult),
    options: HostName.LookupOptions,
) !void {
    const t_io = io(t);
    const file = Dir.openFileAbsolute(t_io, "/etc/hosts", .{}) catch |err| switch (err) {
        error.FileNotFound,
        error.NotDir,
        error.AccessDenied,
        => return error.UnknownHostName,

        error.Canceled => |e| return e,

        else => {
            // Here we could add more detailed diagnostics to the results queue.
            return error.DetectingNetworkConfigurationFailed;
        },
    };
    defer file.close(t_io);

    var line_buf: [512]u8 = undefined;
    var file_reader = file.reader(t_io, &line_buf);
    return lookupHostsReader(t, host_name, resolved, options, &file_reader.interface) catch |err| switch (err) {
        error.ReadFailed => switch (file_reader.err.?) {
            error.Canceled => |e| return e,
            else => {
                // Here we could add more detailed diagnostics to the results queue.
                return error.DetectingNetworkConfigurationFailed;
            },
        },
        error.Canceled,
        error.Closed,
        error.UnknownHostName,
        => |e| return e,
    };
}

fn lookupHostsReader(
    t: *Threaded,
    host_name: HostName,
    resolved: *Io.Queue(HostName.LookupResult),
    options: HostName.LookupOptions,
    reader: *Io.Reader,
) error{ ReadFailed, Canceled, UnknownHostName, Closed }!void {
    const t_io = io(t);
    var addresses_len: usize = 0;
    var canonical_name: ?HostName = null;
    while (true) {
        const line = reader.takeDelimiterExclusive('\n') catch |err| switch (err) {
            error.StreamTooLong => {
                // Skip lines that are too long.
                _ = reader.discardDelimiterInclusive('\n') catch |e| switch (e) {
                    error.EndOfStream => break,
                    error.ReadFailed => return error.ReadFailed,
                };
                continue;
            },
            error.ReadFailed => return error.ReadFailed,
            error.EndOfStream => break,
        };
        reader.toss(1);
        var split_it = std.mem.splitScalar(u8, line, '#');
        const no_comment_line = split_it.first();

        var line_it = std.mem.tokenizeAny(u8, no_comment_line, " \t");
        const ip_text = line_it.next() orelse continue;
        var first_name_text: ?[]const u8 = null;
        while (line_it.next()) |name_text| {
            if (std.mem.eql(u8, name_text, host_name.bytes)) {
                if (first_name_text == null) first_name_text = name_text;
                break;
            }
        } else continue;

        if (canonical_name == null) {
            if (HostName.init(first_name_text.?)) |name_text| {
                if (name_text.bytes.len <= options.canonical_name_buffer.len) {
                    const canonical_name_dest = options.canonical_name_buffer[0..name_text.bytes.len];
                    @memcpy(canonical_name_dest, name_text.bytes);
                    canonical_name = .{ .bytes = canonical_name_dest };
                }
            } else |_| {}
        }

        if (options.family != .ip6) {
            if (IpAddress.parseIp4(ip_text, options.port)) |addr| {
                try resolved.putOne(t_io, .{ .address = addr });
                addresses_len += 1;
            } else |_| {}
        }
        if (options.family != .ip4) {
            if (IpAddress.parseIp6(ip_text, options.port)) |addr| {
                try resolved.putOne(t_io, .{ .address = addr });
                addresses_len += 1;
            } else |_| {}
        }
    }

    if (canonical_name) |canon_name| try resolved.putOne(t_io, .{ .canonical_name = canon_name });
    if (addresses_len == 0) return error.UnknownHostName;
}

/// Writes DNS resolution query packet data to `w`; at most 280 bytes.
fn writeResolutionQuery(q: *[280]u8, op: u4, dname: []const u8, class: u8, ty: HostName.DnsRecord, entropy: [2]u8) usize {
    // This implementation is ported from musl libc.
    // A more idiomatic "ziggy" implementation would be welcome.
    var name = dname;
    if (std.mem.endsWith(u8, name, ".")) name.len -= 1;
    assert(name.len <= 253);
    const n = 17 + name.len + @intFromBool(name.len != 0);

    // Construct query template - ID will be filled later
    q[0..2].* = entropy;
    @memset(q[2..n], 0);
    q[2] = @as(u8, op) * 8 + 1;
    q[5] = 1;
    @memcpy(q[13..][0..name.len], name);
    var i: usize = 13;
    var j: usize = undefined;
    while (q[i] != 0) : (i = j + 1) {
        j = i;
        while (q[j] != 0 and q[j] != '.') : (j += 1) {}
        // TODO determine the circumstances for this and whether or
        // not this should be an error.
        if (j - i - 1 > 62) unreachable;
        q[i - 1] = @intCast(j - i);
    }
    q[i + 1] = @intFromEnum(ty);
    q[i + 3] = class;
    return n;
}

fn copyCanon(canonical_name_buffer: *[HostName.max_len]u8, name: []const u8) HostName {
    const dest = canonical_name_buffer[0..name.len];
    @memcpy(dest, name);
    return .{ .bytes = dest };
}

/// Darwin XNU 7195.50.7.100.1 introduced __ulock_wait2 and migrated code paths (notably pthread_cond_t) towards it:
/// https://github.com/apple/darwin-xnu/commit/d4061fb0260b3ed486147341b72468f836ed6c8f#diff-08f993cc40af475663274687b7c326cc6c3031e0db3ac8de7b24624610616be6
///
/// This XNU version appears to correspond to 11.0.1:
/// https://kernelshaman.blogspot.com/2021/01/building-xnu-for-macos-big-sur-1101.html
///
/// ulock_wait() uses 32-bit micro-second timeouts where 0 = INFINITE or no-timeout
/// ulock_wait2() uses 64-bit nano-second timeouts (with the same convention)
const darwin_supports_ulock_wait2 = builtin.os.version_range.semver.min.major >= 11;

fn closeSocketWindows(s: ws2_32.SOCKET) void {
    const rc = ws2_32.closesocket(s);
    if (is_debug) switch (rc) {
        0 => {},
        ws2_32.SOCKET_ERROR => switch (ws2_32.WSAGetLastError()) {
            else => recoverableOsBugDetected(),
        },
        else => recoverableOsBugDetected(),
    };
}

const Wsa = struct {
    status: Status = .uninitialized,
    mutex: Io.Mutex = .init,
    init_error: ?Wsa.InitError = null,

    const Status = enum { uninitialized, initialized, failure };

    const InitError = error{
        ProcessFdQuotaExceeded,
        NetworkDown,
        VersionUnsupported,
        BlockingOperationInProgress,
    } || Io.UnexpectedError;
};

fn initializeWsa(t: *Threaded) error{ NetworkDown, Canceled }!void {
    const t_io = io(t);
    const wsa = &t.wsa;
    try wsa.mutex.lock(t_io);
    defer wsa.mutex.unlock(t_io);
    switch (wsa.status) {
        .uninitialized => {
            var wsa_data: ws2_32.WSADATA = undefined;
            const minor_version = 2;
            const major_version = 2;
            switch (ws2_32.WSAStartup((@as(windows.WORD, minor_version) << 8) | major_version, &wsa_data)) {
                0 => {
                    wsa.status = .initialized;
                    return;
                },
                else => |err_int| {
                    wsa.status = .failure;
                    wsa.init_error = switch (@as(ws2_32.WinsockError, @enumFromInt(@as(u16, @intCast(err_int))))) {
                        .SYSNOTREADY => error.NetworkDown,
                        .VERNOTSUPPORTED => error.VersionUnsupported,
                        .EINPROGRESS => error.BlockingOperationInProgress,
                        .EPROCLIM => error.ProcessFdQuotaExceeded,
                        else => |err| windows.unexpectedWSAError(err),
                    };
                },
            }
        },
        .initialized => return,
        .failure => {},
    }
    return error.NetworkDown;
}

fn doNothingSignalHandler(_: posix.SIG) callconv(.c) void {}

fn scanEnviron(t: *Threaded) void {
    t.mutex.lock();
    defer t.mutex.unlock();

    if (t.environ.initialized) return;
    t.environ.initialized = true;

    if (is_windows) {
        const ptr = windows.peb().ProcessParameters.Environment;

        var i: usize = 0;
        while (ptr[i] != 0) {
            const key_start = i;

            // There are some special environment variables that start with =,
            // so we need a special case to not treat = as a key/value separator
            // if it's the first character.
            // https://devblogs.microsoft.com/oldnewthing/20100506-00/?p=14133
            if (ptr[key_start] == '=') i += 1;

            while (ptr[i] != 0 and ptr[i] != '=') : (i += 1) {}
            const key_w = ptr[key_start..i];
            if (std.mem.eql(u16, key_w, &.{ 'N', 'O', '_', 'C', 'O', 'L', 'O', 'R' })) {
                t.environ.exist.NO_COLOR = true;
            } else if (std.mem.eql(u16, key_w, &.{ 'C', 'L', 'I', 'C', 'O', 'L', 'O', 'R', '_', 'F', 'O', 'R', 'C', 'E' })) {
                t.environ.exist.CLICOLOR_FORCE = true;
            }
            comptime assert(@sizeOf(Environ.String) == 0);

            while (ptr[i] != 0) : (i += 1) {} // skip over '=' and value
            i += 1; // skip over null byte
        }
    } else if (native_os == .wasi and !builtin.link_libc) {
        var environ_count: usize = undefined;
        var environ_buf_size: usize = undefined;

        switch (std.os.wasi.environ_sizes_get(&environ_count, &environ_buf_size)) {
            .SUCCESS => {},
            else => |err| {
                t.environ.err = posix.unexpectedErrno(err);
                return;
            },
        }
        if (environ_count == 0) return;

        const environ = t.allocator.alloc([*:0]u8, environ_count) catch |err| {
            t.environ.err = err;
            return;
        };
        defer t.allocator.free(environ);
        const environ_buf = t.allocator.alloc(u8, environ_buf_size) catch |err| {
            t.environ.err = err;
            return;
        };
        defer t.allocator.free(environ_buf);

        switch (std.os.wasi.environ_get(environ.ptr, environ_buf.ptr)) {
            .SUCCESS => {},
            else => |err| {
                t.environ.err = posix.unexpectedErrno(err);
                return;
            },
        }

        for (environ) |env| {
            const pair = std.mem.sliceTo(env, 0);
            var parts = std.mem.splitScalar(u8, pair, '=');
            const key = parts.first();
            if (std.mem.eql(u8, key, "NO_COLOR")) {
                t.environ.exist.NO_COLOR = true;
            } else if (std.mem.eql(u8, key, "CLICOLOR_FORCE")) {
                t.environ.exist.CLICOLOR_FORCE = true;
            }
            comptime assert(@sizeOf(Environ.String) == 0);
        }
    } else if (builtin.link_libc) {
        var ptr = std.c.environ;
        while (ptr[0]) |line| : (ptr += 1) {
            var line_i: usize = 0;
            while (line[line_i] != 0 and line[line_i] != '=') : (line_i += 1) {}
            const key = line[0..line_i];

            var end_i: usize = line_i;
            while (line[end_i] != 0) : (end_i += 1) {}
            const value = line[line_i + 1 .. end_i :0];

            if (std.mem.eql(u8, key, "NO_COLOR")) {
                t.environ.exist.NO_COLOR = true;
            } else if (std.mem.eql(u8, key, "CLICOLOR_FORCE")) {
                t.environ.exist.CLICOLOR_FORCE = true;
            } else if (@hasField(Environ.String, "PATH") and std.mem.eql(u8, key, "PATH")) {
                t.environ.string.PATH = value;
            }
        }
    } else {
        for (t.environ.block) |line| {
            var line_i: usize = 0;
            while (line[line_i] != 0 and line[line_i] != '=') : (line_i += 1) {}
            const key = line[0..line_i];

            var end_i: usize = line_i;
            while (line[end_i] != 0) : (end_i += 1) {}
            const value = line[line_i + 1 .. end_i :0];

            if (std.mem.eql(u8, key, "NO_COLOR")) {
                t.environ.exist.NO_COLOR = true;
            } else if (std.mem.eql(u8, key, "CLICOLOR_FORCE")) {
                t.environ.exist.CLICOLOR_FORCE = true;
            } else if (@hasField(Environ.String, "PATH") and std.mem.eql(u8, key, "PATH")) {
                t.environ.string.PATH = value;
            }
        }
    }
}

test {
    _ = @import("Threaded/test.zig");
}

const use_parking_futex = switch (builtin.target.os.tag) {
    .windows => true, // RtlWaitOnAddress is a userland implementation anyway
    .netbsd => true, // NetBSD has `futex(2)`, but it's historically been quite buggy. TODO: evaluate whether it's okay to use now.
    .illumos => true, // Illumos has no futex mechanism
    else => false,
};
const use_parking_sleep = switch (builtin.target.os.tag) {
    // On Windows, we can implement sleep either with `NtDelayExecution` (which is how `SleepEx` in
    // kernel32 works) or `NtWaitForAlertByThreadId` (thread parking). We're already using the
    // latter for futex, so we may as well use it for sleeping too, to maximise code reuse. I'm
    // also more confident that it will always correctly handle the cancelation race (so "unpark"
    // before "park" causes "park" to return immediately): it *seems* like alertable sleeps paired
    // with `NtAlertThread` do actually do this too, but there could be some caveat (e.g. it might
    // fail under some specific condition), whereas `NtWaitForAlertByThreadId` must reliably trigger
    // this behavior because `RtlWaitOnAddress` relies on it.
    .windows => true,

    // These targets have `_lwp_park`, which is superior to POSIX nanosleep because it has a better
    // cancelation mechanism.
    .netbsd,
    .illumos,
    => true,

    else => false,
};

const parking_futex = struct {
    comptime {
        assert(use_parking_futex);
    }

    const Bucket = struct {
        /// Used as a fast check for `wake` to avoid having to acquire `mutex` to discover there are no
        /// waiters. It is important for `wait` to increment this *before* checking the futex value to
        /// avoid a race.
        num_waiters: std.atomic.Value(u32),
        /// Protects `waiters`.
        mutex: std.Thread.Mutex,
        waiters: std.DoublyLinkedList,

        /// Prevent false sharing between buckets.
        _: void align(std.atomic.cache_line) = {},

        const init: Bucket = .{ .num_waiters = .init(0), .mutex = .{}, .waiters = .{} };
    };

    const Waiter = struct {
        node: std.DoublyLinkedList.Node,
        address: usize,
        tid: std.Thread.Id,
        /// `thread_status.cancelation` is `.parked` while the thread is waiting. The single thread
        /// which atomically updates it (to `.none` or `.canceling`) is responsible for:
        ///
        /// * Removing the `Waiter` from `Bucket.waiters`
        /// * Decrementing `Bucket.num_waiters`
        /// * Unparking the thread (*after* the above, so that the `Waiter` does not go out of scope
        ///   while it is still in the `Bucket`).
        thread_status: *std.atomic.Value(Thread.Status),
    };

    fn bucketForAddress(address: usize) *Bucket {
        const global = struct {
            /// Length must be a power of two. The longer this array, the less likely contention is
            /// between different futexes. This length seems like it'll provide a reasonable balance
            /// between contention and memory usage: assuming a 128-byte `Bucket` (due to cache line
            /// alignment), this uses 32 KiB of memory.
            var buckets: [256]Bucket = @splat(.init);
        };

        // Here we use Fibonacci hashing: the golden ratio can be used to evenly redistribute input
        // values across a range, giving a poor, but extremely quick to compute, hash.

        // This literal is the rounded value of '2^64 / phi' (where 'phi' is the golden ratio). The
        // shift then converts it to '2^b / phi', where 'b' is the pointer bit width.
        const fibonacci_multiplier = 0x9E3779B97F4A7C15 >> (64 - @bitSizeOf(usize));
        const hashed = address *% fibonacci_multiplier;

        comptime assert(std.math.isPowerOfTwo(global.buckets.len));
        // The high bits of `hashed` have better entropy than the low bits.
        const index = hashed >> (@bitSizeOf(usize) - @ctz(global.buckets.len));

        return &global.buckets[index];
    }

    fn wait(ptr: *const u32, expect: u32, uncancelable: bool, timeout: Io.Timeout) Io.Cancelable!void {
        const bucket = bucketForAddress(@intFromPtr(ptr));

        // Put the threadlocal access outside of the critical section.
        const opt_thread = Thread.current;
        const self_tid = if (opt_thread) |thread| thread.id else std.Thread.getCurrentId();

        var waiter: Waiter = .{
            .node = undefined, // populated by list append
            .address = @intFromPtr(ptr),
            .tid = self_tid,
            .thread_status = undefined, // populated in critical section
        };

        var status_buf: std.atomic.Value(Thread.Status) = undefined;

        {
            bucket.mutex.lock();
            defer bucket.mutex.unlock();

            _ = bucket.num_waiters.fetchAdd(1, .acquire);

            if (@atomicLoad(u32, ptr, .monotonic) != expect) {
                assert(bucket.num_waiters.fetchSub(1, .monotonic) > 0);
                return;
            }

            // This is in the critical section to avoid marking the thread as parked until we're
            // certain that we're actually going to park.
            waiter.thread_status = status: {
                cancelable: {
                    if (uncancelable) break :cancelable;
                    const thread = opt_thread orelse break :cancelable;
                    switch (thread.cancel_protection) {
                        .blocked => break :cancelable,
                        .unblocked => {},
                    }
                    thread.futex_waiter = &waiter;
                    const old_status = thread.status.fetchOr(
                        .{ .cancelation = @enumFromInt(0b001), .awaitable = .null },
                        .release, // release `thread.futex_waiter`
                    );
                    switch (old_status.cancelation) {
                        .none => {}, // status is now `.parked`
                        .canceling => {
                            // status is now `.canceled`
                            assert(bucket.num_waiters.fetchSub(1, .monotonic) > 0);
                            return error.Canceled;
                        },
                        .canceled => break :cancelable, // status is still `.canceled`
                        .parked => unreachable,
                        .blocked => unreachable,
                        .blocked_windows_dns => unreachable,
                        .blocked_canceling => unreachable,
                    }
                    // We could now be unparked for a cancelation at any time!
                    break :status &thread.status;
                }
                // This is an uncancelable wait, so just use `status_buf`. Note that the value of
                // `status_buf.awaitable` is irrelevant because this is only visible to futex code,
                // while only cancelation cares about `awaitable`.
                status_buf.raw = .{ .cancelation = .parked, .awaitable = .null };
                break :status &status_buf;
            };

            bucket.waiters.append(&waiter.node);
        }

        if (park(timeout, ptr)) {
            // We were unparked by either `wake` or cancelation, so our current status is either
            // `.none` or `.canceling`. In either case, they've already removed `waiter` from
            // `bucket`, so we have nothing more to do!
        } else |err| switch (err) {
            error.Timeout => {
                // We're not out of the woods yet: an unpark could race with the timeout.
                const old_status = waiter.thread_status.fetchAnd(
                    .{ .cancelation = @enumFromInt(0b110), .awaitable = .all_ones },
                    .monotonic,
                );
                switch (old_status.cancelation) {
                    .parked => {
                        // No race. It is our responsibility to remove `waiter` from `bucket`.
                        // New status is `.none`.
                        bucket.mutex.lock();
                        defer bucket.mutex.unlock();
                        bucket.waiters.remove(&waiter.node);
                        assert(bucket.num_waiters.fetchSub(1, .monotonic) > 0);
                    },
                    .none, .canceling => {
                        // Race condition: the timeout was reached, then `wake` or a canceler tried
                        // to unpark us. Whoever did that will remove us from `bucket`. Wait for
                        // that (and drop the unpark request in doing so).
                        // New status is `.none` or `.canceling` respectively.
                        park(.none, ptr) catch |e| switch (e) {
                            error.Timeout => unreachable,
                        };
                    },
                    .canceled => unreachable,
                    .blocked => unreachable,
                    .blocked_windows_dns => unreachable,
                    .blocked_canceling => unreachable,
                }
            },
        }
    }

    fn wake(ptr: *const u32, max_waiters: u32) void {
        if (max_waiters == 0) return;

        const bucket = bucketForAddress(@intFromPtr(ptr));

        // To ensure the store to `ptr` is ordered before this check, we effectively want a `.release`
        // load, but that doesn't exist in the C11 memory model, so emulate it with a non-mutating rmw.
        if (bucket.num_waiters.fetchAdd(0, .release) == 0) {
            @branchHint(.likely);
            return; // no waiters
        }

        // Waiters removed from the linked list under the mutex so we can unpark their threads outside
        // of the critical section. This forms a singly-linked list of waiters using `Waiter.node.next`.
        var waking_head: ?*std.DoublyLinkedList.Node = null;
        {
            bucket.mutex.lock();
            defer bucket.mutex.unlock();

            var num_removed: u32 = 0;
            var it = bucket.waiters.first;
            while (num_removed < max_waiters) {
                const waiter: *Waiter = @fieldParentPtr("node", it orelse break);
                it = waiter.node.next;
                if (waiter.address != @intFromPtr(ptr)) continue;
                const old_status = waiter.thread_status.fetchAnd(
                    .{ .cancelation = @enumFromInt(0b110), .awaitable = .all_ones },
                    .monotonic,
                );
                switch (old_status.cancelation) {
                    .parked => {}, // state updated to `.none`
                    .none => unreachable, // if another `wake` call is unparking this thread, it should have removed it from the list
                    .canceling => continue, // race with a canceler who hasn't called `removeCanceledWaiter` yet
                    .canceled => unreachable,
                    .blocked => unreachable,
                    .blocked_windows_dns => unreachable,
                    .blocked_canceling => unreachable,
                }
                // We're waking this waiter. Remove them from the bucket and add them to our local list.
                bucket.waiters.remove(&waiter.node);
                waiter.node.next = waking_head;
                waking_head = &waiter.node;
                num_removed += 1;
                // Signal to `waiter` that they're about to be unparked, in case we're racing with their
                // timeout. See corresponding logic in `wake`.
                waiter.address = 0;
            }

            _ = bucket.num_waiters.fetchSub(num_removed, .monotonic);
        }

        var unpark_buf: [128]UnparkTid = undefined;
        var unpark_len: usize = 0;

        // Finally, unpark the threads.
        while (waking_head) |node| {
            waking_head = node.next;
            const waiter: *Waiter = @fieldParentPtr("node", node);
            unpark_buf[unpark_len] = waiter.tid;
            unpark_len += 1;
            if (unpark_len == unpark_buf.len) {
                unpark(&unpark_buf, ptr);
                unpark_len = 0;
            }
        }
        if (unpark_len > 0) {
            unpark(unpark_buf[0..unpark_len], ptr);
        }
    }

    fn removeCanceledWaiter(waiter: *Waiter) void {
        const bucket = bucketForAddress(waiter.address);
        bucket.mutex.lock();
        defer bucket.mutex.unlock();
        bucket.waiters.remove(&waiter.node);
        assert(bucket.num_waiters.fetchSub(1, .monotonic) > 0);
    }
};
const parking_sleep = struct {
    comptime {
        assert(use_parking_sleep);
    }
    fn sleep(timeout: Io.Timeout) Io.Cancelable!void {
        const opt_thread = Thread.current;
        cancelable: {
            const thread = opt_thread orelse break :cancelable;
            switch (thread.cancel_protection) {
                .blocked => break :cancelable,
                .unblocked => {},
            }
            thread.futex_waiter = null;
            {
                const old_status = thread.status.fetchOr(
                    .{ .cancelation = @enumFromInt(0b001), .awaitable = .null },
                    .release, // release `thread.futex_waiter`
                );
                switch (old_status.cancelation) {
                    .none => {}, // status is now `.parked`
                    .canceling => return error.Canceled, // status is now `.canceled`
                    .canceled => break :cancelable, // status is still `.canceled`
                    .parked => unreachable,
                    .blocked => unreachable,
                    .blocked_windows_dns => unreachable,
                    .blocked_canceling => unreachable,
                }
            }
            if (park(timeout, null)) {
                // The only reason this could possibly happen is cancelation.
                const old_status = thread.status.load(.monotonic);
                assert(old_status.cancelation == .canceling);
                thread.status.store(
                    .{ .cancelation = .canceled, .awaitable = old_status.awaitable },
                    .monotonic,
                );
                return error.Canceled;
            } else |err| switch (err) {
                error.Timeout => {
                    // We're not out of the woods yet: an unpark could race with the timeout.
                    const old_status = thread.status.fetchAnd(
                        .{ .cancelation = @enumFromInt(0b110), .awaitable = .all_ones },
                        .monotonic,
                    );
                    switch (old_status.cancelation) {
                        .parked => return, // No race; new status is `.none`
                        .canceling => {
                            // Race condition: the timeout was reached, then someone tried to unpark
                            // us for a cancelation. Whoever did that will have called `unpark`, so
                            // drop that unpark request by waiting for it.
                            // Status is still `.canceling`.
                            park(.none, null) catch |e| switch (e) {
                                error.Timeout => unreachable,
                            };
                            return;
                        },
                        .none => unreachable,
                        .canceled => unreachable,
                        .blocked => unreachable,
                        .blocked_windows_dns => unreachable,
                        .blocked_canceling => unreachable,
                    }
                },
            }
        }
        // Uncancelable sleep; we expect not to be manually unparked.
        if (park(timeout, null)) {
            unreachable; // unexpected unpark
        } else |err| switch (err) {
            error.Timeout => return,
        }
    }
};

/// `addr_hint` has no semantic effect, but may allow the OS to optimize this operation.
fn park(timeout: Io.Timeout, addr_hint: ?*const anyopaque) error{Timeout}!void {
    comptime assert(use_parking_futex or use_parking_sleep);
    switch (builtin.target.os.tag) {
        .windows => {
            var timeout_buf: windows.LARGE_INTEGER = undefined;
            const raw_timeout: ?*windows.LARGE_INTEGER = timeout: switch (timeout) {
                .none => null,
                .deadline => |timestamp| continue :timeout .{ .duration = .{
                    .clock = timestamp.clock,
                    .raw = (nowWindows(timestamp.clock) catch unreachable).durationTo(timestamp.raw),
                } },
                .duration => |duration| {
                    _ = duration.clock; // Windows only supports monotonic
                    timeout_buf = @intCast(@divTrunc(-duration.raw.nanoseconds, 100));
                    break :timeout &timeout_buf;
                },
            };
            // `RtlWaitOnAddress` passes the futex address in as the first argument to this call,
            // but it's unclear what that actually does, especially since `NtAlertThreadByThreadId`
            // does *not* accept the address so the kernel can't really be using it as a hint. An
            // old Microsoft blog post discusses a more traditional futex-like mechanism in the
            // kernel which definitely isn't how `RtlWaitOnAddress` works today:
            //
            // https://devblogs.microsoft.com/oldnewthing/20160826-00/?p=94185
            //
            // ...so it's possible this argument is simply a remnant which no longer does anything
            // (perhaps the implementation changed during development but someone forgot to remove
            // this parameter). However, to err on the side of caution, let's match the behavior of
            // `RtlWaitOnAddress` and pass the pointer, in case the kernel ever does something
            // stupid such as trying to dereference it.
            switch (windows.ntdll.NtWaitForAlertByThreadId(addr_hint, raw_timeout)) {
                .ALERTED => return,
                .TIMEOUT => return error.Timeout,
                else => unreachable,
            }
        },
        .netbsd => {
            var ts_buf: posix.timespec = undefined;
            const ts: ?*posix.timespec, const abstime: bool, const clock_real: bool = switch (timeout) {
                .none => .{ null, false, false },
                .deadline => |timestamp| timeout: {
                    ts_buf = timestampToPosix(timestamp.raw.nanoseconds);
                    break :timeout .{ &ts_buf, true, timestamp.clock == .real };
                },
                .duration => |duration| timeout: {
                    ts_buf = timestampToPosix(duration.raw.nanoseconds);
                    break :timeout .{ &ts_buf, false, duration.clock == .real };
                },
            };
            switch (posix.errno(std.c._lwp_park(
                if (clock_real) .REALTIME else .MONOTONIC,
                .{ .ABSTIME = abstime },
                ts,
                0,
                addr_hint,
                null,
            ))) {
                .SUCCESS, .ALREADY, .INTR => return,
                .TIMEDOUT => return error.Timeout,
                .INVAL => unreachable,
                .SRCH => unreachable,
                else => unreachable,
            }
        },
        .illumos => @panic("TODO: illumos lwp_park"),
        else => comptime unreachable,
    }
}

const UnparkTid = switch (builtin.target.os.tag) {
    // `NtAlertMultipleThreadByThreadId` is weird and wants 64-bit thread handles?
    .windows => usize,
    else => std.Thread.Id,
};
/// `addr_hint` has no semantic effect, but may allow the OS to optimize this operation.
fn unpark(tids: []const UnparkTid, addr_hint: ?*const anyopaque) void {
    comptime assert(use_parking_futex or use_parking_sleep);
    switch (builtin.target.os.tag) {
        .windows => {
            // TODO: this condition is currently disabled because mingw-w64 does not contain this
            // symbol. Once it's added, enable this check to use the new bulk API where possible.
            if (false and (builtin.os.version_range.windows.isAtLeast(.win11_dt) orelse false)) {
                _ = windows.ntdll.NtAlertMultipleThreadByThreadId(tids.ptr, @intCast(tids.len), null, null);
            } else {
                for (tids) |tid| {
                    _ = windows.ntdll.NtAlertThreadByThreadId(@intCast(tid));
                }
            }
        },
        .netbsd => {
            switch (posix.errno(std.c._lwp_unpark_all(@ptrCast(tids.ptr), tids.len, addr_hint))) {
                .SUCCESS => return,
                // For errors, fall through to a loop over `tids`, though this is only expected to
                // be possible for ENOMEM (and even that is questionable).
                .SRCH => recoverableOsBugDetected(),
                .FAULT => recoverableOsBugDetected(),
                .INVAL => recoverableOsBugDetected(),
                .NOMEM => {},
                else => recoverableOsBugDetected(),
            }
            for (tids) |tid| {
                switch (posix.errno(std.c._lwp_unpark(@bitCast(tid), addr_hint))) {
                    .SUCCESS => {},
                    .SRCH => recoverableOsBugDetected(),
                    else => recoverableOsBugDetected(),
                }
            }
        },
        .illumos => @panic("TODO: illumos lwp_unpark"),
        else => comptime unreachable,
    }
}
