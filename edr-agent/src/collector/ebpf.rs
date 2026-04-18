//! Chargement du bytecode eBPF et lecture du ring buffer.
//!
//! Le bytecode est embarqué à la compilation via `include_bytes_aligned!`.
//! En développement sans compilation eBPF, un stub émet des événements factices.

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::RingBuf,
    programs::{KProbe, TracePoint},
    Bpf,
};
use aya_log::BpfLogger;
use edr_common::{EdrEvent, RawEvent, RawEventType};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::Sender;
use tracing::{debug, info, warn};

use super::proc_enricher::ProcEnricher;
use super::hasher::sha256_file;

/// Bytecode eBPF compilé embarqué dans le binaire agent.
/// Compilé avec : cargo build --target bpfel-unknown-none -p edr-ebpf
#[cfg(not(feature = "stub_ebpf"))]
static EDR_BPF_BYTES: &[u8] = include_bytes_aligned!(
    "../../edr-ebpf/target/bpfel-unknown-none/release/edr-ebpf"
);

/// Charge le bytecode eBPF, attache les sondes et lit le ring buffer.
pub async fn run(event_tx: Sender<EdrEvent>) -> Result<()> {
    #[cfg(feature = "stub_ebpf")]
    {
        warn!("Mode stub eBPF actif — émission d'événements synthétiques");
        return run_stub(event_tx).await;
    }

    #[cfg(not(feature = "stub_ebpf"))]
    {
        run_real(event_tx).await
    }
}

#[cfg(not(feature = "stub_ebpf"))]
async fn run_real(event_tx: Sender<EdrEvent>) -> Result<()> {
    // Chargement du bytecode eBPF
    let mut bpf = Bpf::load(EDR_BPF_BYTES)
        .context("Échec du chargement du bytecode eBPF")?;

    // Logger eBPF → tracing
    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("BpfLogger non disponible : {}", e);
    }

    // ── Attachement des sondes ──────────────────────────────────────────

    // kprobe execve
    {
        let prog: &mut KProbe = bpf
            .program_mut("kprobe_execve")
            .context("Programme kprobe_execve introuvable")?
            .try_into()?;
        prog.load()?;
        prog.attach("__x64_sys_execve", 0)
            .context("Attachement kprobe execve")?;
        info!("kprobe/__x64_sys_execve attaché");
    }

    // kretprobe clone (fork)
    {
        let prog: &mut KProbe = bpf
            .program_mut("kretprobe_clone")
            .context("Programme kretprobe_clone introuvable")?
            .try_into()?;
        prog.load()?;
        prog.attach("kernel_clone", 0)
            .context("Attachement kretprobe clone")?;
        info!("kretprobe/kernel_clone attaché");
    }

    // tracepoint sched_process_exit
    {
        let prog: &mut TracePoint = bpf
            .program_mut("tp_sched_process_exit")
            .context("Programme tp_sched_process_exit introuvable")?
            .try_into()?;
        prog.load()?;
        prog.attach("sched", "sched_process_exit")
            .context("Attachement tracepoint sched_process_exit")?;
        info!("tracepoint/sched/sched_process_exit attaché");
    }

    // kprobe tcp_connect
    {
        let prog: &mut KProbe = bpf
            .program_mut("kprobe_tcp_connect")
            .context("Programme kprobe_tcp_connect introuvable")?
            .try_into()?;
        prog.load()?;
        prog.attach("tcp_connect", 0)
            .context("Attachement kprobe tcp_connect")?;
        info!("kprobe/tcp_connect attaché");
    }

    // kprobe chmod
    {
        let prog: &mut KProbe = bpf
            .program_mut("kprobe_chmod")
            .context("Programme kprobe_chmod introuvable")?
            .try_into()?;
        prog.load()?;
        prog.attach("security_inode_setattr", 0)
            .context("Attachement kprobe chmod")?;
        info!("kprobe/security_inode_setattr attaché");
    }

    // ── Lecture du ring buffer ─────────────────────────────────────────

    let ring_buf: &mut RingBuf = bpf
        .map_mut("EDR_EVENTS")
        .context("Map EDR_EVENTS introuvable")?
        .try_into()?;

    let async_fd = AsyncFd::new(ring_buf)?;
    let enricher = ProcEnricher::new();

    info!("Ring buffer prêt — lecture des événements eBPF");

    loop {
        let mut guard = async_fd.readable_mut().await?;
        guard.get_inner_mut().next();

        // Drainer tous les événements disponibles
        while let Some(item) = guard.get_inner_mut().next() {
            if item.len() < std::mem::size_of::<RawEvent>() {
                warn!("Événement eBPF tronqué ({} octets)", item.len());
                continue;
            }

            let raw: RawEvent = unsafe {
                std::ptr::read_unaligned(item.as_ptr() as *const RawEvent)
            };

            match build_edr_event(raw, &enricher).await {
                Some(ev) => {
                    if event_tx.send(ev).await.is_err() {
                        return Ok(()); // Récepteur fermé — arrêt propre
                    }
                }
                None => debug!("Événement ignoré (type inconnu)"),
            }
        }
        guard.clear_ready();
    }
}

/// Convertit un `RawEvent` en `EdrEvent` enrichi.
async fn build_edr_event(raw: RawEvent, enricher: &ProcEnricher) -> Option<EdrEvent> {
    use chrono::Utc;
    use edr_common::{
        ProcessEvent, ForkEvent, ExitEvent, FileEvent, NetworkEvent,
        FileOperation, NetworkProtocol,
    };

    let now = Utc::now();

    match RawEventType::try_from(raw.event_type).ok()? {
        RawEventType::Execve => {
            let exe_path = raw.exe_path_str().to_owned();
            let info     = enricher.get_proc_info(raw.pid);
            let sha256   = sha256_file(&exe_path).ok();

            Some(EdrEvent::Process(ProcessEvent {
                pid:      raw.pid,
                ppid:     info.ppid.unwrap_or(raw.ppid),
                uid:      raw.uid,
                gid:      raw.gid,
                timestamp: now,
                exe_path,
                args:     raw.args_str().to_owned(),
                cwd:      info.cwd.unwrap_or_default(),
                username: info.username.unwrap_or_else(|| raw.uid.to_string()),
                sha256,
            }))
        }

        RawEventType::Fork => {
            Some(EdrEvent::Fork(ForkEvent {
                parent_pid: raw.ppid,
                child_pid:  raw.pid,
                timestamp:  now,
            }))
        }

        RawEventType::Exit => {
            Some(EdrEvent::Exit(ExitEvent {
                pid:         raw.pid,
                exit_code:   raw.exit_code,
                timestamp:   now,
                lifetime_ms: 0, // calculé côté analyseur
            }))
        }

        RawEventType::FileOp => {
            Some(EdrEvent::File(FileEvent {
                pid:       raw.pid,
                timestamp: now,
                path:      raw.filename_str().to_owned(),
                operation: FileOperation::from(raw.file_op),
                sha256:    None,
            }))
        }

        RawEventType::NetConn => {
            let dst = std::net::Ipv4Addr::from(raw.dst_ip);
            Some(EdrEvent::Network(NetworkEvent {
                pid:       raw.pid,
                timestamp: now,
                src_ip:    "0.0.0.0".into(),
                src_port:  raw.src_port,
                dst_ip:    dst.to_string(),
                dst_port:  raw.dst_port,
                protocol:  NetworkProtocol::Tcp,
            }))
        }
    }
}

impl TryFrom<u32> for RawEventType {
    type Error = ();
    fn try_from(v: u32) -> Result<Self, ()> {
        match v {
            0 => Ok(Self::Execve),
            1 => Ok(Self::Fork),
            2 => Ok(Self::Exit),
            3 => Ok(Self::FileOp),
            4 => Ok(Self::NetConn),
            _ => Err(()),
        }
    }
}

// ─────────────────────────────────────────────
//  Stub pour développement sans eBPF
// ─────────────────────────────────────────────

#[cfg(feature = "stub_ebpf")]
async fn run_stub(event_tx: Sender<EdrEvent>) -> Result<()> {
    use edr_common::{ProcessEvent, NetworkEvent, NetworkProtocol};
    use chrono::Utc;
    use std::time::Duration;

    let mut counter = 0u32;
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        counter += 1;

        let ev = if counter % 3 == 0 {
            EdrEvent::Network(NetworkEvent {
                pid: 1234 + counter,
                timestamp: Utc::now(),
                src_ip: "192.168.1.10".into(),
                src_port: 54321,
                dst_ip: "1.2.3.4".into(),
                dst_port: 443,
                protocol: NetworkProtocol::Tcp,
            })
        } else {
            EdrEvent::Process(ProcessEvent {
                pid: 1000 + counter,
                ppid: 1,
                uid: 0,
                gid: 0,
                timestamp: Utc::now(),
                exe_path: if counter % 5 == 0 {
                    "/tmp/malicious".into()
                } else {
                    "/usr/bin/bash".into()
                },
                args: "--stub-event".into(),
                cwd: "/".into(),
                username: "root".into(),
                sha256: None,
            })
        };

        if event_tx.send(ev).await.is_err() {
            break;
        }
    }
    Ok(())
}
