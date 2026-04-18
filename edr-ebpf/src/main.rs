//! Programmes eBPF de l'EDR — compilés pour la cible bpfel-unknown-none.
//!
//! Ce binaire est compilé séparément avec `cargo build --target bpfel-unknown-none`
//! et embarqué dans l'agent via `aya::include_bytes_aligned!`.
//!
//! Chaque sonde kprobe/tracepoint capture un événement noyau et l'envoie
//! vers l'userspace via le ring buffer `EDR_EVENTS`.

#![no_std]
#![no_main]

use aya_bpf::{
    bindings::path,
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
               bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_str_bytes,
               bpf_get_current_comm},
    macros::{kprobe, kretprobe, map, tracepoint},
    maps::RingBuf,
    programs::{ProbeContext, TracePointContext},
    BpfContext,
};
use aya_log_ebpf::info;
use edr_common::{RawEvent, RawEventType, MAX_ARGS_LEN, MAX_PATH_LEN, MAX_FILENAME_LEN};

// ─────────────────────────────────────────────
//  Map partagée : ring buffer d'événements
// ─────────────────────────────────────────────

/// Ring buffer principal — capacité 4 Mo.
/// L'userspace lit en continu via `AsyncFd<RingBuf>`.
#[map]
static EDR_EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

// ─────────────────────────────────────────────
//  Helpers internes
// ─────────────────────────────────────────────

/// Émet un `RawEvent` dans le ring buffer.
/// Retourne 0 en cas de succès, -1 si le buffer est plein.
#[inline(always)]
fn emit_event(event: RawEvent) -> i32 {
    if let Some(mut entry) = EDR_EVENTS.reserve::<RawEvent>(0) {
        unsafe { entry.write(event) };
        entry.submit(0);
        0
    } else {
        -1
    }
}

/// Construit un `RawEvent` vide avec le pid/uid courant.
#[inline(always)]
fn base_event(event_type: RawEventType) -> RawEvent {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid  = bpf_get_current_uid_gid();

    let mut ev: RawEvent = unsafe { core::mem::zeroed() };
    ev.event_type   = event_type as u32;
    ev.pid          = (pid_tgid & 0xffff_ffff) as u32;
    ev.ppid         = 0; // enrichi côté userspace via /proc
    ev.uid          = (uid_gid & 0xffff_ffff) as u32;
    ev.gid          = (uid_gid >> 32) as u32;
    ev.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    ev
}

// ─────────────────────────────────────────────
//  Sonde execve — capture les exécutions de binaires
// ─────────────────────────────────────────────

/// Kprobe sur `__x64_sys_execve`.
///
/// Capture : PID, UID, GID, chemin du binaire (256 oct.), arguments (256 oct.).
/// Le PPID et le chemin complet sont enrichis côté userspace.
#[kprobe(name = "kprobe_execve")]
pub fn kprobe_execve(ctx: ProbeContext) -> u32 {
    match try_kprobe_execve(ctx) {
        Ok(ret) => ret,
        Err(_)  => 0,
    }
}

fn try_kprobe_execve(ctx: ProbeContext) -> Result<u32, i64> {
    let mut ev = base_event(RawEventType::Execve);

    // arg0 = filename (const char __user *)
    let filename_ptr: *const u8 = ctx.arg(0).ok_or(-1i64)?;
    unsafe {
        bpf_probe_read_user_str_bytes(filename_ptr, &mut ev.exe_path)
            .map_err(|e| e)?;
    }

    // arg1 = argv (const char __user * const __user *)
    // On lit seulement argv[1] (premier argument) pour garder < 512 oct.
    let argv_ptr: *const *const u8 = ctx.arg(1).ok_or(-1i64)?;
    if !argv_ptr.is_null() {
        let arg1_ptr: *const u8 = unsafe {
            *(argv_ptr.add(1))
        };
        if !arg1_ptr.is_null() {
            unsafe {
                let _ = bpf_probe_read_user_str_bytes(arg1_ptr, &mut ev.args);
            }
        }
    }

    emit_event(ev);
    Ok(0)
}

// ─────────────────────────────────────────────
//  Sonde fork/clone — capture les créations de processus
// ─────────────────────────────────────────────

/// Kretprobe sur `kernel_clone` (remplace `do_fork` depuis kernel 5.10).
///
/// Le PID parent est le processus courant ; le PID enfant est la valeur de retour.
#[kretprobe(name = "kretprobe_clone")]
pub fn kretprobe_clone(ctx: ProbeContext) -> u32 {
    let child_pid: u32 = ctx.ret().unwrap_or(0u32);
    if child_pid == 0 {
        // Contexte enfant — on ignore
        return 0;
    }

    let mut ev = base_event(RawEventType::Fork);
    ev.ppid = ev.pid;       // parent = processus courant
    ev.pid  = child_pid;    // enfant = valeur de retour
    emit_event(ev);
    0
}

// ─────────────────────────────────────────────
//  Tracepoint sched_process_exit — fin de processus
// ─────────────────────────────────────────────

/// Tracepoint `sched/sched_process_exit`.
///
/// Capture le code de sortie pour calculer la durée de vie côté userspace.
#[tracepoint(name = "sched_process_exit", category = "sched")]
pub fn tp_sched_process_exit(ctx: TracePointContext) -> u32 {
    let mut ev = base_event(RawEventType::Exit);

    // Offset 8 = champ `exit_code` dans le tracepoint sched_process_exit
    let exit_code: i32 = unsafe {
        ctx.read_at::<i32>(8).unwrap_or(0)
    };
    ev.exit_code = exit_code >> 8; // WEXITSTATUS
    emit_event(ev);
    0
}

// ─────────────────────────────────────────────
//  Sonde réseau TCP — connexions sortantes
// ─────────────────────────────────────────────

/// Kprobe sur `tcp_connect`.
///
/// Capture IP destination, port destination et PID pour chaque tentative
/// de connexion TCP sortante. Le protocole réseau est toujours TCP ici.
#[kprobe(name = "kprobe_tcp_connect")]
pub fn kprobe_tcp_connect(ctx: ProbeContext) -> u32 {
    match try_tcp_connect(ctx) {
        Ok(ret) => ret,
        Err(_)  => 0,
    }
}

fn try_tcp_connect(ctx: ProbeContext) -> Result<u32, i64> {
    let mut ev = base_event(RawEventType::NetConn);

    // arg0 = struct sock *
    // Offsets dans struct sock (x86-64, kernel 5.x) :
    //   __sk_common.skc_daddr  offset 0x00 = IPv4 dest
    //   __sk_common.skc_dport  offset 0x0C = dest port (big-endian)
    let sock_ptr: *const u8 = ctx.arg(0).ok_or(-1i64)?;

    let dst_ip: u32 = unsafe {
        *(sock_ptr.add(0x00) as *const u32)
    };
    let dst_port_be: u16 = unsafe {
        *(sock_ptr.add(0x0C) as *const u16)
    };

    ev.dst_ip   = u32::from_be(dst_ip);
    ev.dst_port = u16::from_be(dst_port_be);

    emit_event(ev);
    Ok(0)
}

// ─────────────────────────────────────────────
//  Sonde fichier — chmod sur des binaires
// ─────────────────────────────────────────────

/// Kprobe sur `security_inode_setattr` pour capturer les chmod.
///
/// Op code 7 = CHMOD dans notre convention FileOperation.
#[kprobe(name = "kprobe_chmod")]
pub fn kprobe_chmod(ctx: ProbeContext) -> u32 {
    let mut ev = base_event(RawEventType::FileOp);
    ev.file_op = 7; // FileOperation::Chmod

    // arg0 = struct dentry *
    // dentry->d_name.name est à offset 0x28 sur x86-64
    let dentry_ptr: *const u8 = match ctx.arg::<*const u8>(0) {
        Some(p) => p,
        None    => return 0,
    };

    unsafe {
        let name_ptr = *(dentry_ptr.add(0x28) as *const *const u8);
        if !name_ptr.is_null() {
            let _ = bpf_probe_read_kernel_str_bytes(name_ptr, &mut ev.filename);
        }
    }

    emit_event(ev);
    0
}

// ─────────────────────────────────────────────
//  Point d'entrée requis par le linker no_std
// ─────────────────────────────────────────────

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
