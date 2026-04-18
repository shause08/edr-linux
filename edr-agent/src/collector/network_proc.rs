//! Collecteur réseau de secours basé sur `/proc/net/tcp` et `/proc/net/udp`.
//!
//! Utilisé quand la sonde eBPF `kprobe_tcp_connect` n'est pas disponible
//! ou pour compléter les informations réseau (EF-N03).
//!
//! Détecte également les processus ouvrant > N connexions en 10 secondes (EF-N05).

use anyhow::Result;
use edr_common::{EdrEvent, NetworkEvent, NetworkProtocol};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Sender;
use tokio::time;
use tracing::{debug, warn};

/// Intervalle de polling de /proc/net/tcp.
const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Fenêtre de détection des scans réseau (EF-N05).
const SCAN_WINDOW: Duration = Duration::from_secs(10);

/// Entrée dans /proc/net/tcp.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TcpEntry {
    local_addr:  String,
    local_port:  u16,
    remote_addr: String,
    remote_port: u16,
    inode:       u64,
}

pub async fn run(scan_threshold: u32, event_tx: Sender<EdrEvent>) -> Result<()> {
    let mut seen:     HashSet<TcpEntry>             = HashSet::new();
    let mut conn_log: HashMap<u32, VecDeque<Instant>> = HashMap::new();
    let mut interval  = time::interval(POLL_INTERVAL);

    loop {
        interval.tick().await;

        let entries = match parse_proc_net_tcp("/proc/net/tcp") {
            Ok(e) => e,
            Err(e) => {
                warn!("Lecture /proc/net/tcp : {}", e);
                continue;
            }
        };

        let current_set: HashSet<TcpEntry> = entries.iter().cloned().collect();

        // Nouvelles connexions = présentes maintenant mais pas avant
        for entry in current_set.difference(&seen) {
            let pid = inode_to_pid(entry.inode).unwrap_or(0);

            debug!(
                pid = pid,
                dst = %entry.remote_addr,
                port = entry.remote_port,
                "Nouvelle connexion TCP (/proc)"
            );

            // Détection de scan réseau
            let now = Instant::now();
            let log = conn_log.entry(pid).or_default();
            log.push_back(now);
            // Purger les entrées hors fenêtre
            while log.front().map(|t| now.duration_since(*t) > SCAN_WINDOW).unwrap_or(false) {
                log.pop_front();
            }

            if log.len() as u32 > scan_threshold {
                warn!(
                    pid = pid,
                    count = log.len(),
                    "Scan réseau potentiel détecté (> {} connexions en 10s)",
                    scan_threshold
                );
            }

            let ev = NetworkEvent {
                pid,
                timestamp:  chrono::Utc::now(),
                src_ip:     entry.local_addr.clone(),
                src_port:   entry.local_port,
                dst_ip:     entry.remote_addr.clone(),
                dst_port:   entry.remote_port,
                protocol:   NetworkProtocol::Tcp,
            };

            if event_tx.send(EdrEvent::Network(ev)).await.is_err() {
                return Ok(());
            }
        }

        seen = current_set;
    }
}

/// Parse /proc/net/tcp et retourne la liste des connexions ESTABLISHED.
fn parse_proc_net_tcp(path: &str) -> Result<Vec<TcpEntry>> {
    let content = std::fs::read_to_string(path)?;
    let mut result = Vec::new();

    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 12 {
            continue;
        }

        // State 01 = TCP_ESTABLISHED
        if parts[3] != "01" {
            continue;
        }

        if let (Some(local), Some(remote)) = (
            parse_hex_addr(parts[1]),
            parse_hex_addr(parts[2]),
        ) {
            let inode: u64 = parts[9].parse().unwrap_or(0);
            result.push(TcpEntry {
                local_addr:  local.0,
                local_port:  local.1,
                remote_addr: remote.0,
                remote_port: remote.1,
                inode,
            });
        }
    }

    Ok(result)
}

/// Convertit une adresse hexadécimale /proc/net/tcp en (ip_str, port).
/// Format : "0100007F:0050" → ("127.0.0.1", 80)
fn parse_hex_addr(hex: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 {
        return None;
    }

    let addr_hex = parts[0];
    let port_hex = parts[1];

    let addr_num: u32 = u32::from_str_radix(addr_hex, 16).ok()?;
    let port:     u16 = u16::from_str_radix(port_hex, 16).ok()?;

    // Little-endian sur x86
    let a = (addr_num)       & 0xFF;
    let b = (addr_num >> 8)  & 0xFF;
    let c = (addr_num >> 16) & 0xFF;
    let d = (addr_num >> 24) & 0xFF;

    Some((format!("{}.{}.{}.{}", a, b, c, d), port))
}

/// Résout un inode vers un PID en parcourant /proc/*/fd/*.
fn inode_to_pid(inode: u64) -> Option<u32> {
    let target = format!("socket:[{}]", inode);

    let proc_dir = std::fs::read_dir("/proc").ok()?;
    for entry in proc_dir.flatten() {
        let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
        let fd_dir = format!("/proc/{}/fd", pid);

        if let Ok(fds) = std::fs::read_dir(&fd_dir) {
            for fd in fds.flatten() {
                if let Ok(link) = std::fs::read_link(fd.path()) {
                    if link.to_str() == Some(&target) {
                        return Some(pid);
                    }
                }
            }
        }
    }

    None
}
