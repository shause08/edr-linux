//! Détection de séquences temporelles (EF-D05).
//!
//! Permet de détecter des patterns comme :
//! - execve → connexion réseau dans les 2 secondes (R-007)
//! - chmod → exécution dans les 5 secondes (R-008)

use edr_common::EdrEvent;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::sync::Mutex;

/// Événement dans une séquence.
#[derive(Debug, Clone)]
pub enum SeqEventKind {
    Execve,
    Chmod,
    NetConn,
    FileCreate,
}

/// Entrée dans le journal de séquences d'un PID.
#[derive(Debug)]
struct SeqEntry {
    kind:      SeqEventKind,
    timestamp: Instant,
    path:      Option<String>,
}

/// Détecteur de séquences temporelles.
pub struct SequenceEngine {
    /// Journal des événements récents par PID.
    log: Mutex<HashMap<u32, Vec<SeqEntry>>>,
    /// Durée de rétention maximale des entrées.
    retention: Duration,
}

impl SequenceEngine {
    pub fn new() -> Self {
        Self {
            log:       Mutex::new(HashMap::new()),
            retention: Duration::from_secs(30),
        }
    }

    /// Enregistre un événement et vérifie si une séquence est complète.
    ///
    /// Retourne `Some(rule_id)` si une séquence détectée correspond.
    pub fn process(&self, event: &EdrEvent) -> Option<&'static str> {
        let pid = event.pid();
        let now = Instant::now();

        let kind = match event {
            EdrEvent::Process(_) => SeqEventKind::Execve,
            EdrEvent::Network(_) => SeqEventKind::NetConn,
            EdrEvent::File(f) => match f.operation {
                edr_common::FileOperation::Chmod  => SeqEventKind::Chmod,
                edr_common::FileOperation::Create => SeqEventKind::FileCreate,
                _                                 => return None,
            },
            _ => return None,
        };

        let mut log = self.log.lock().ok()?;
        let entries = log.entry(pid).or_default();

        // Purge des entrées expirées
        entries.retain(|e| now.duration_since(e.timestamp) <= self.retention);

        // Vérification des séquences AVANT d'ajouter le nouvel événement

        // R-007 : execve → NetConn dans < 2s
        if matches!(kind, SeqEventKind::NetConn) {
            if entries.iter().any(|e| {
                matches!(e.kind, SeqEventKind::Execve)
                    && now.duration_since(e.timestamp) < Duration::from_secs(2)
            }) {
                entries.push(SeqEntry { kind, timestamp: now, path: None });
                return Some("R-007");
            }
        }

        // R-008 : chmod → execve dans < 5s
        if matches!(kind, SeqEventKind::Execve) {
            let exe_path = if let EdrEvent::Process(p) = event {
                Some(p.exe_path.clone())
            } else {
                None
            };

            if entries.iter().any(|e| {
                matches!(e.kind, SeqEventKind::Chmod)
                    && now.duration_since(e.timestamp) < Duration::from_secs(5)
                    && exe_path == e.path
            }) {
                entries.push(SeqEntry { kind, timestamp: now, path: exe_path });
                return Some("R-008");
            }
        }

        // Enregistrement de l'événement courant
        let path = match event {
            EdrEvent::File(f) => Some(f.path.clone()),
            EdrEvent::Process(p) => Some(p.exe_path.clone()),
            _ => None,
        };
        entries.push(SeqEntry { kind, timestamp: now, path });

        None
    }
}
