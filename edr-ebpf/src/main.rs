//! Programme eBPF de l'EDR.
//!
//! Utilise un tracepoint sur syscalls/sys_enter_execve (plus stable
//! que kprobe/__x64_sys_execve sur les kernels récents).
//! Les événements sont envoyés vers l'userspace via un PerfEventArray.

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};
use aya_log_ebpf::debug;

// ── Structure partagée noyau ↔ userspace ─────────────────────────────

/// Événement execve envoyé vers l'userspace.
/// Taille fixe pour pouvoir être transmis via PerfEventArray.
#[repr(C)]
pub struct ExecEvent {
    pub pid:      u32,
    pub uid:      u32,
    pub filename: [u8; 256],
}

// ── Map PerfEventArray ────────────────────────────────────────────────

#[map]
static EXEC_EVENTS: PerfEventArray<ExecEvent> = PerfEventArray::new(0);

// ── Tracepoint syscalls/sys_enter_execve ─────────────────────────────

#[tracepoint]
pub fn edr_execve(ctx: TracePointContext) -> u32 {
    match try_execve(ctx) {
        Ok(r)  => r,
        Err(_) => 0,
    }
}

fn try_execve(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid  = bpf_get_current_uid_gid();

    let mut event = ExecEvent {
        pid:      (pid_tgid & 0xffff_ffff) as u32,
        uid:      (uid_gid  & 0xffff_ffff) as u32,
        filename: [0u8; 256],
    };

    // Le tracepoint sys_enter_execve expose :
    //   offset 16 = *filename  (const char __user *)
    let filename_ptr: u64 = unsafe { ctx.read_at(16)? };
    let filename_ptr = filename_ptr as *const u8;

    if !filename_ptr.is_null() {
        unsafe {
            let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename);
        }
    }

    EXEC_EVENTS.output(&ctx, &event, 0);
    Ok(0)
}

// ── Panic handler (requis no_std) ─────────────────────────────────────

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
