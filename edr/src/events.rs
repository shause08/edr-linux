//! Types d'événements partagés entre tous les modules.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Événement unifié produit par les collecteurs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    /// Exécution d'un processus (depuis eBPF)
    Process(ProcessEvent),
    /// Accès à un fichier sensible (depuis inotify)
    File(FileEvent),
    /// Nouvelle connexion réseau (depuis /proc/net/tcp)
    Network(NetworkEvent),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub pid:      u32,
    pub uid:      u32,
    pub exe:      String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub path:      String,
    pub operation: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub pid:      u32,
    pub dst_ip:   String,
    pub dst_port: u16,
    pub timestamp: DateTime<Utc>,
}

impl Event {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Process(_) => "process",
            Self::File(_)    => "file",
            Self::Network(_) => "network",
        }
    }

    pub fn timestamp(&self) -> DateTime<Utc> {
        match self {
            Self::Process(e) => e.timestamp,
            Self::File(e)    => e.timestamp,
            Self::Network(e) => e.timestamp,
        }
    }

    pub fn summary(&self) -> String {
        match self {
            Self::Process(e) => format!("EXEC  pid={} uid={} {}", e.pid, e.uid, e.exe),
            Self::File(e)    => format!("FILE  [{}] {}", e.operation, e.path),
            Self::Network(e) => format!("NET   pid={} → {}:{}", e.pid, e.dst_ip, e.dst_port),
        }
    }
}

/// Alerte générée par le détecteur.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub rule:      String,
    pub severity:  Severity,
    pub message:   String,
    pub timestamp: DateTime<Utc>,
    pub event_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low      => write!(f, "LOW"),
            Self::Medium   => write!(f, "MEDIUM"),
            Self::High     => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}
