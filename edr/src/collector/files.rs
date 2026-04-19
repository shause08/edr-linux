//! Surveillance de fichiers sensibles via inotify.

use anyhow::Result;
use chrono::Utc;
use inotify::{EventMask, Inotify, WatchMask};
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};

use crate::events::{Event, FileEvent};

/// Chemins surveillés par défaut.
const WATCHED: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/root/.ssh",
    "/tmp",
    "/var/spool/cron",
];

pub async fn run(tx: Sender<Event>) -> Result<()> {
    let mut inotify = Inotify::init()?;

    for path in WATCHED {
        match inotify.watches().add(
            path,
            WatchMask::CREATE
                | WatchMask::MODIFY
                | WatchMask::DELETE
                | WatchMask::OPEN
                | WatchMask::CLOSE_WRITE,
        ) {
            Ok(_)  => info!("inotify : surveillance de {}", path),
            Err(e) => warn!("inotify : impossible de surveiller {} : {}", path, e),
        }
    }

    let mut buffer = [0u8; 4096];

    loop {
        let events = inotify.read_events_blocking(&mut buffer)?;

        for event in events {
            let op = mask_to_str(event.mask);
            let name = event.name
                .and_then(|n| n.to_str().map(String::from))
                .unwrap_or_default();

            let ev = Event::File(FileEvent {
                path:      name,
                operation: op.to_string(),
                timestamp: Utc::now(),
            });

            if tx.send(ev).await.is_err() {
                return Ok(());
            }
        }
    }
}

fn mask_to_str(mask: EventMask) -> &'static str {
    if mask.contains(EventMask::CREATE)      { "CREATE" }
    else if mask.contains(EventMask::MODIFY) { "MODIFY" }
    else if mask.contains(EventMask::DELETE) { "DELETE" }
    else if mask.contains(EventMask::OPEN)   { "OPEN"   }
    else                                     { "OTHER"  }
}
