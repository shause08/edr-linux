//! Chargement et validation de la configuration TOML de l'agent EDR.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;

/// Configuration principale de l'agent (edr.toml).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub agent: AgentConfig,
    pub storage: StorageConfig,
    pub collector: CollectorConfig,
    pub response: ResponseConfig,
    pub export: ExportConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Fichier PID du daemon
    pub pid_file: String,
    /// Répertoire de quarantaine
    pub quarantine_dir: String,
    /// Répertoire de logs
    pub log_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Chemin de la base SQLite
    pub db_path: String,
    /// Rétention des événements en jours
    pub retention_days: u32,
    /// Taille max du buffer mémoire si SQLite indisponible
    pub memory_buffer_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorConfig {
    /// Chemins surveillés par fanotify
    pub watched_paths: Vec<String>,
    /// Taille du ring buffer eBPF en octets
    pub ring_buffer_size: usize,
    /// Activer la surveillance réseau via eBPF
    pub network_monitoring: bool,
    /// Liste de réputation IP (CIDR, un par ligne)
    pub ip_reputation_file: Option<String>,
    /// Seuil de connexions pour détecter un scan (connexions/10s)
    pub network_scan_threshold: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseConfig {
    /// Mode actif : exécute réellement les actions de réponse
    pub active_mode: bool,
    /// Journaliser toutes les actions de réponse
    pub log_actions: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportConfig {
    /// Activer l'export webhook
    pub webhook_url: Option<String>,
    /// Fichier de log des alertes (format JSON-lines)
    pub alert_log_file: Option<String>,
}

impl Config {
    /// Charge la configuration depuis un fichier TOML.
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            agent: AgentConfig {
                pid_file:       "/run/edr.pid".into(),
                quarantine_dir: "/var/edr/quarantine".into(),
                log_dir:        "/var/log/edr".into(),
            },
            storage: StorageConfig {
                db_path:            "/var/lib/edr/events.db".into(),
                retention_days:     30,
                memory_buffer_size: 10_000,
            },
            collector: CollectorConfig {
                watched_paths: vec![
                    "/etc/".into(),
                    "/root/.ssh/".into(),
                    "/home/".into(),
                    "/var/spool/cron/".into(),
                ],
                ring_buffer_size:       4 * 1024 * 1024,
                network_monitoring:     true,
                ip_reputation_file:     None,
                network_scan_threshold: 50,
            },
            response: ResponseConfig {
                active_mode: false,
                log_actions: true,
            },
            export: ExportConfig {
                webhook_url:    None,
                alert_log_file: Some("/var/log/edr/alerts.jsonl".into()),
            },
        }
    }
}
