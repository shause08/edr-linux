//! Surveillance réseau via /proc/net/tcp.
//! Détecte les nouvelles connexions TCP établies.

use anyhow::Result;
use chrono::Utc;
use std::collections::HashSet;
use tokio::sync::mpsc::Sender;
use tokio::time::{sleep, Duration};

use crate::events::{Event, NetworkEvent};

pub async fn run(tx: Sender<Event>) -> Result<()> {
    let mut seen: HashSet<String> = HashSet::new();

    loop {
        if let Ok(conns) = parse_tcp() {
            for conn in &conns {
                if !seen.contains(conn) {
                    // Nouvelle connexion
                    let parts: Vec<&str> = conn.split('|').collect();
                    if parts.len() == 3 {
                        let ev = Event::Network(NetworkEvent {
                            pid:       parts[0].parse().unwrap_or(0),
                            dst_ip:    parts[1].to_string(),
                            dst_port:  parts[2].parse().unwrap_or(0),
                            timestamp: Utc::now(),
                        });
                        if tx.send(ev).await.is_err() {
                            return Ok(());
                        }
                    }
                }
            }
            seen = conns.into_iter().collect();
        }

        sleep(Duration::from_secs(2)).await;
    }
}

/// Parse /proc/net/tcp et retourne les connexions ESTABLISHED.
/// Chaque entrée est formatée "pid|ip|port".
fn parse_tcp() -> Result<Vec<String>> {
    let content = std::fs::read_to_string("/proc/net/tcp")?;
    let mut result = Vec::new();

    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 12 { continue; }

        // State 01 = ESTABLISHED
        if cols[3] != "01" { continue; }

        if let Some((ip, port)) = parse_addr(cols[2]) {
            let inode: u64 = cols[9].parse().unwrap_or(0);
            let pid = inode_to_pid(inode).unwrap_or(0);
            result.push(format!("{}|{}|{}", pid, ip, port));
        }
    }

    Ok(result)
}

fn parse_addr(hex: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 { return None; }

    let addr = u32::from_str_radix(parts[0], 16).ok()?;
    let port = u16::from_str_radix(parts[1], 16).ok()?;

    // Little-endian sur x86
    let ip = std::net::Ipv4Addr::new(
        (addr & 0xFF) as u8,
        ((addr >> 8) & 0xFF) as u8,
        ((addr >> 16) & 0xFF) as u8,
        ((addr >> 24) & 0xFF) as u8,
    );
    Some((ip.to_string(), port))
}

fn inode_to_pid(inode: u64) -> Option<u32> {
    let target = format!("socket:[{}]", inode);
    let proc = std::fs::read_dir("/proc").ok()?;
    for entry in proc.flatten() {
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
