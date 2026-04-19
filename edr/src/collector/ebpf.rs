//! Collecteur eBPF : charge le bytecode et lit les événements execve.

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
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

/// Structure miroir de ExecEvent dans edr-ebpf/src/main.rs.
/// Doit être identique (même layout C).
#[repr(C)]
#[derive(Clone, Copy)]
struct ExecEvent {
    pid:      u32,
    uid:      u32,
    filename: [u8; 256],
}

unsafe impl Send for ExecEvent {}

pub async fn run(tx: Sender<Event>) -> Result<()> {
    // Bytecode eBPF compilé embarqué à la compilation par le build script
    let mut ebpf = Ebpf::load(include_bytes_aligned!(
        concat!(env!("OUT_DIR"), "/edr-ebpf")
    ))
    .context("Impossible de charger le bytecode eBPF. \
              Avez-vous lancé 'cargo xtask build' ?")?;

    // Logger eBPF → tracing (optionnel)
    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        warn!("EbpfLogger indisponible : {}", e);
    }

    // Attachement du tracepoint syscalls/sys_enter_execve
    let prog: &mut TracePoint = ebpf
        .program_mut("edr_execve")
        .context("Programme eBPF 'edr_execve' introuvable")?
        .try_into()?;
    prog.load()?;
    prog.attach("syscalls", "sys_enter_execve")
        .context("Attachement tracepoint sys_enter_execve")?;
    info!("tracepoint/syscalls/sys_enter_execve attaché");

    // Lecture du PerfEventArray
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
                    Ok(e) => e,
                    Err(e) => {
                        warn!("Erreur lecture perf CPU {}: {}", cpu, e);
                        break;
                    }
                };

                for buf in buffers.iter().take(events.read) {
                    if buf.len() < std::mem::size_of::<ExecEvent>() {
                        continue;
                    }
                    let raw: ExecEvent = unsafe {
                        std::ptr::read_unaligned(buf.as_ptr() as *const ExecEvent)
                    };

                    let end = raw.filename.iter().position(|&b| b == 0).unwrap_or(256);
                    let exe = String::from_utf8_lossy(&raw.filename[..end]).to_string();

                    let ev = Event::Process(ProcessEvent {
                        pid:       raw.pid,
                        uid:       raw.uid,
                        exe,
                        timestamp: Utc::now(),
                    });

                    if tx.send(ev).await.is_err() {
                        return;
                    }
                }
            }
        });
    }

    // Cette tâche tourne indéfiniment (les spawns ci-dessus lisent en boucle)
    std::future::pending::<()>().await;
    Ok(())
}
