//! Types partagés entre les composants eBPF et userspace de l'EDR.
//!
//! Ce crate définit les structures d'événements transmises via le ring buffer
//! ainsi que les types communs utilisés par l'agent et l'interface.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────
//  Événements bruts eBPF (structures C-compatibles)
// ─────────────────────────────────────────────

/// Taille maximale d'un chemin de fichier capturé en eBPF.
pub const MAX_PATH_LEN: usize = 256;
/// Taille maximale des arguments de ligne de commande.
pub const MAX_ARGS_LEN: usize = 256;
/// Taille maximale d'un nom de fichier.
pub const MAX_FILENAME_LEN: usize = 128;

/// Type d'événement transmis depuis l'espace noyau.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RawEventType {
    Execve = 0,
    Fork   = 1,
    Exit   = 2,
    FileOp = 3,
    NetConn = 4,
}

/// Événement brut transmis via le ring buffer eBPF.
///
/// Structure identique côté noyau (aya-bpf) et userspace (aya).
/// Les tableaux de taille fixe sont nécessaires pour la compatibilité C.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawEvent {
    pub event_type: u32,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub timestamp_ns: u64,
    pub exe_path: [u8; MAX_PATH_LEN],
    pub args: [u8; MAX_ARGS_LEN],
    pub filename: [u8; MAX_FILENAME_LEN],
    /// Pour les événements réseau : IP destination (IPv4)
    pub dst_ip: u32,
    pub dst_port: u16,
    pub src_port: u16,
    pub exit_code: i32,
    pub file_op: u32,
}

// SAFETY: RawEvent ne contient que des types primitifs, safe à envoyer entre threads.
unsafe impl Send for RawEvent {}
unsafe impl Sync for RawEvent {}

impl RawEvent {
    /// Extrait une &str depuis un tableau de bytes null-terminé.
    pub fn str_from_bytes(buf: &[u8]) -> &str {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        std::str::from_utf8(&buf[..end]).unwrap_or("<invalid utf8>")
    }

    pub fn exe_path_str(&self) -> &str {
        Self::str_from_bytes(&self.exe_path)
    }

    pub fn args_str(&self) -> &str {
        Self::str_from_bytes(&self.args)
    }

    pub fn filename_str(&self) -> &str {
        Self::str_from_bytes(&self.filename)
    }
}

// ─────────────────────────────────────────────
//  Événements enrichis (userspace)
// ─────────────────────────────────────────────

/// Opération sur un fichier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileOperation {
    Open,
    Read,
    Write,
    Create,
    Delete,
    Rename,
    Chmod,
    Unknown(u32),
}

impl From<u32> for FileOperation {
    fn from(v: u32) -> Self {
        match v {
            1 => Self::Open,
            2 => Self::Read,
            3 => Self::Write,
            4 => Self::Create,
            5 => Self::Delete,
            6 => Self::Rename,
            7 => Self::Chmod,
            other => Self::Unknown(other),
        }
    }
}

/// Événement de création/exécution de processus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub timestamp: DateTime<Utc>,
    pub exe_path: String,
    pub args: String,
    pub cwd: String,
    pub username: String,
    pub sha256: Option<String>,
}

/// Événement de fork/clone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkEvent {
    pub parent_pid: u32,
    pub child_pid: u32,
    pub timestamp: DateTime<Utc>,
}

/// Événement de fin de processus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitEvent {
    pub pid: u32,
    pub exit_code: i32,
    pub timestamp: DateTime<Utc>,
    pub lifetime_ms: u64,
}

/// Événement sur un fichier (fanotify ou eBPF).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub pid: u32,
    pub timestamp: DateTime<Utc>,
    pub path: String,
    pub operation: FileOperation,
    pub sha256: Option<String>,
}

/// Événement réseau (connexion TCP/UDP).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub pid: u32,
    pub timestamp: DateTime<Utc>,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: NetworkProtocol,
}

/// Protocole réseau observé.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkProtocol {
    Tcp,
    Udp,
}

/// Enum d'enveloppe regroupant tous les types d'événements enrichis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EdrEvent {
    Process(ProcessEvent),
    Fork(ForkEvent),
    Exit(ExitEvent),
    File(FileEvent),
    Network(NetworkEvent),
}

impl EdrEvent {
    /// Retourne le PID associé à l'événement.
    pub fn pid(&self) -> u32 {
        match self {
            Self::Process(e) => e.pid,
            Self::Fork(e) => e.parent_pid,
            Self::Exit(e) => e.pid,
            Self::File(e) => e.pid,
            Self::Network(e) => e.pid,
        }
    }

    /// Retourne le timestamp de l'événement.
    pub fn timestamp(&self) -> DateTime<Utc> {
        match self {
            Self::Process(e) => e.timestamp,
            Self::Fork(e) => e.timestamp,
            Self::Exit(e) => e.timestamp,
            Self::File(e) => e.timestamp,
            Self::Network(e) => e.timestamp,
        }
    }

    /// Retourne le type sous forme de &str pour le stockage.
    pub fn event_type_str(&self) -> &'static str {
        match self {
            Self::Process(_) => "process",
            Self::Fork(_)    => "fork",
            Self::Exit(_)    => "exit",
            Self::File(_)    => "file",
            Self::Network(_) => "network",
        }
    }
}

// ─────────────────────────────────────────────
//  Alertes
// ─────────────────────────────────────────────

/// Niveau de sévérité d'une alerte.
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

impl std::str::FromStr for Severity {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "low"      => Ok(Self::Low),
            "medium"   => Ok(Self::Medium),
            "high"     => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            other => Err(anyhow::anyhow!("Sévérité inconnue: {}", other)),
        }
    }
}

/// Alerte générée par le moteur de détection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: Option<i64>,
    pub rule_id: String,
    pub rule_description: String,
    pub severity: Severity,
    pub timestamp: DateTime<Utc>,
    pub pid: u32,
    pub mitre_technique: Option<String>,
    pub event_json: String,
    pub action_taken: Option<String>,
}

impl Alert {
    /// Exporte l'alerte au format Elastic Common Schema (ECS).
    pub fn to_ecs(&self) -> serde_json::Value {
        serde_json::json!({
            "@timestamp": self.timestamp.to_rfc3339(),
            "event": {
                "kind": "alert",
                "category": ["intrusion_detection"],
                "type": ["indicator"],
                "severity": self.severity_as_int(),
            },
            "rule": {
                "id": self.rule_id,
                "description": self.rule_description,
            },
            "process": {
                "pid": self.pid,
            },
            "threat": {
                "technique": {
                    "id": self.mitre_technique,
                }
            },
            "message": self.rule_description,
            "labels": {
                "edr_action": self.action_taken,
            }
        })
    }

    fn severity_as_int(&self) -> u8 {
        match self.severity {
            Severity::Low      => 25,
            Severity::Medium   => 50,
            Severity::High     => 75,
            Severity::Critical => 100,
        }
    }
}
