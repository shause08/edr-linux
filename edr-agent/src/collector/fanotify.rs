//! Surveillance du système de fichiers via l'API fanotify du noyau Linux.
//!
//! fanotify offre deux modes :
//! - **Non-bloquant** (FAN_MODIFY, FAN_CREATE, etc.) : notification après l'opération.
//! - **Bloquant** (FAN_OPEN_PERM) : nécessite une décision allow/deny (nécessite CAP_SYS_ADMIN).
//!
//! Cet implémentation utilise le mode non-bloquant pour éviter les latences.

use anyhow::{Context, Result};
use edr_common::{EdrEvent, FileEvent, FileOperation};
use nix::sys::fanotify::{self, EventFFlags, InitFlags, MarkFlags, MaskFlags};
use std::os::unix::io::AsRawFd;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::Sender;
use tracing::{debug, info, warn};

/// Lance la surveillance fanotify sur les chemins configurés.
pub async fn run(watched_paths: Vec<String>, event_tx: Sender<EdrEvent>) -> Result<()> {
    info!("Initialisation de fanotify…");

    // Initialisation fanotify
    let fan = fanotify::Fanotify::init(
        InitFlags::FAN_CLOEXEC | InitFlags::FAN_CLASS_NOTIF | InitFlags::FAN_NONBLOCK,
        EventFFlags::O_RDONLY | EventFFlags::O_LARGEFILE | EventFFlags::O_CLOEXEC,
    )
    .context("Échec fanotify::init — CAP_SYS_ADMIN requis")?;

    // Enregistrement des chemins à surveiller
    for path in &watched_paths {
        match fan.mark(
            MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_FILESYSTEM,
            MaskFlags::FAN_OPEN
                | MaskFlags::FAN_CLOSE_WRITE
                | MaskFlags::FAN_CREATE
                | MaskFlags::FAN_DELETE
                | MaskFlags::FAN_MODIFY,
            None,
            Some(path.as_str()),
        ) {
            Ok(_) => info!("fanotify : surveillance de {}", path),
            Err(e) => warn!("fanotify : impossible de surveiller {} : {}", path, e),
        }
    }

    // Lecture async des événements
    let fd = fan.as_raw_fd();
    let async_fd = AsyncFd::new(fan)?;

    info!("fanotify prêt — en attente d'événements");

    loop {
        let mut guard = async_fd.readable().await?;

        match guard.get_ref().read_events() {
            Ok(events) => {
                for event in events {
                    let path = resolve_path_from_fd(event.fd());

                    let operation = mask_to_operation(event.mask());
                    let pid       = event.pid() as u32;

                    debug!(
                        pid = pid,
                        path = %path.as_deref().unwrap_or("<inconnu>"),
                        op   = ?operation,
                        "Événement fanotify"
                    );

                    let file_event = FileEvent {
                        pid,
                        timestamp: chrono::Utc::now(),
                        path:      path.unwrap_or_else(|| "<inconnu>".into()),
                        operation,
                        sha256:    None, // enrichi par l'analyseur si nécessaire
                    };

                    if event_tx.send(EdrEvent::File(file_event)).await.is_err() {
                        return Ok(());
                    }
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                warn!("Erreur lecture fanotify : {}", e);
            }
        }
        guard.clear_ready();
    }
}

/// Résout le chemin complet depuis le file descriptor fanotify.
fn resolve_path_from_fd(fd: Option<std::os::unix::io::RawFd>) -> Option<String> {
    let fd = fd?;
    let link = format!("/proc/self/fd/{}", fd);
    std::fs::read_link(&link)
        .ok()
        .and_then(|p| p.to_str().map(String::from))
}

/// Convertit un masque fanotify en `FileOperation`.
fn mask_to_operation(mask: MaskFlags) -> FileOperation {
    if mask.contains(MaskFlags::FAN_CREATE) {
        FileOperation::Create
    } else if mask.contains(MaskFlags::FAN_DELETE) {
        FileOperation::Delete
    } else if mask.contains(MaskFlags::FAN_CLOSE_WRITE) {
        FileOperation::Write
    } else if mask.contains(MaskFlags::FAN_MODIFY) {
        FileOperation::Write
    } else if mask.contains(MaskFlags::FAN_OPEN) {
        FileOperation::Open
    } else {
        FileOperation::Unknown(0)
    }
}
