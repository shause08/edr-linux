//! Collecteur eBPF : charge le bytecode et lit les événements execve.
//!
//! Le bytecode est lu depuis le chemin de build fixe.
//! Il doit être compilé en premier par `cargo xtask build`.

use anyhow::{Context, Result};
use aya::{
    maps::perf::AsyncPerfEventArray,
    programs::TracePoint,
    util::online_cpus,
    Ebpf,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use chrono::Utc;
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};

use crate::events::{Event, ProcessEvent};

/// Chemin du bytecode eBPF compilé.
/// Doit correspondre à : cargo build -p edr-ebpf --target bpfel-unknown-none --release
const EBPF_BYTECODE: &str = "target/bpfel-unknown-none/release/edr-ebpf";

#[repr(C)]
#[derive(Clone, Copy)]
struct ExecEvent {
    pid:      u32,
    uid:      u32,
    filename: [u8; 256],
}

unsafe impl Send for ExecEvent {}

pub async fn run(tx: Sender<Event>) -> Result<()> {
    // Lecture du bytecode depuis le chemin de build
    let bytecode = std::fs::read(EBPF_BYTECODE)
        .with_context(|| format!(
            "Bytecode eBPF introuvable : {}\nLancer 'cargo xtask build' d'abord.",
            EBPF_BYTECODE
        ))?;

    let mut ebpf = Ebpf::load(&bytecode)
        .context("Impossible de charger le bytecode eBPF")?;

    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        warn!("EbpfLogger indisponible : {}", e);
    }

    // Attachement tracepoint
    let prog: &mut TracePoint = ebpf
        .program_mut("edr_execve")
        .context("Programme eBPF 'edr_execve' introuvable")?
        .try_into()?;
    prog.load()?;
    prog.attach("syscalls", "sys_enter_execve")
        .context("Attachement tracepoint sys_enter_execve")?;
    info!("tracepoint/syscalls/sys_enter_execve attaché");

    // Lecture PerfEventArray
    let mut perf_array = AsyncPerfEventArray::try_from(
        ebpf.take_map("EXEC_EVENTS")
            .context("Map EXEC_EVENTS introuvable")?,
    )?;

    let cpus = online_cpus().map_err(|e| anyhow::anyhow!("online_cpus: {:?}", e))?;

    for cpu in cpus {
        let mut buf = perf_array.open(cpu, None)?;
        let tx = tx.clone();

        tokio::spawn(async move {
            let mut buffers = vec![BytesMut::with_capacity(512); 10];
            loop {
                let events = match buf.read_events(&mut buffers).await {
                    Ok(e)  => e,
                    Err(e) => { warn!("Erreur perf CPU {}: {}", cpu, e); break; }
                };
                for buf in buffers.iter().take(events.read) {
                    if buf.len() < std::mem::size_of::<ExecEvent>() { continue; }
                    let raw: ExecEvent = unsafe {
                        std::ptr::read_unaligned(buf.as_ptr() as *const ExecEvent)
                    };
                    let end = raw.filename.iter().position(|&b| b == 0).unwrap_or(256);
                    let exe = String::from_utf8_lossy(&raw.filename[..end]).to_string();
                    let ev  = Event::Process(ProcessEvent {
                        pid: raw.pid, uid: raw.uid, exe,
                        timestamp: Utc::now(),
                    });
                    if tx.send(ev).await.is_err() { return; }
                }
            }
        });
    }

    std::future::pending::<()>().await;
    Ok(())
}