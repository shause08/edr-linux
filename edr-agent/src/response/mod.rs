//! Module de réponse automatisée de l'EDR.
//!
//! Actions disponibles (EF-R01 à EF-R05) :
//! - **Kill**       : envoie SIGKILL au processus suspect
//! - **Quarantine** : déplace le fichier vers /var/edr/quarantine/ avec métadonnées JSON
//! - **BlockIp**    : ajoute une règle iptables pour bloquer l'IP
//!
//! Toutes les actions sont journalisées (EF-R04).
//! En mode `dry_run`, aucune action n'est exécutée réellement (EF-R05).

use anyhow::Result;
use edr_common::{Alert, EdrEvent, RuleAction};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::process::Command;
use chrono::Utc;
use tracing::{info, warn};

pub struct ResponseEngine {
    dry_run:       bool,
    quarantine_dir: PathBuf,
}

impl ResponseEngine {
    pub fn new(dry_run: bool) -> Self {
        let quarantine_dir = PathBuf::from("/var/edr/quarantine");
        if !dry_run {
            let _ = fs::create_dir_all(&quarantine_dir);
        }
        Self { dry_run, quarantine_dir }
    }

    /// Exécute l'action prescrite par l'alerte.
    pub async fn execute(&self, alert: &Alert) -> Result<()> {
        // Détermine l'action depuis le champ action_taken de l'alerte
        let action = match alert.action_taken.as_deref() {
            Some("Kill")       => RuleAction::Kill,
            Some("Quarantine") => RuleAction::Quarantine,
            Some("BlockIp")    => RuleAction::BlockIp,
            _                  => RuleAction::Alert, // Pas d'action physique
        };

        match action {
            RuleAction::Alert => {
                // Émission vers stderr / fichier log déjà faite par tracing
                Ok(())
            }
            RuleAction::Kill => {
                self.kill_process(alert).await
            }
            RuleAction::Quarantine => {
                // Extraire le chemin depuis l'événement JSON
                if let Some(path) = extract_file_path(&alert.event_json) {
                    self.quarantine_file(alert, &path).await
                } else {
                    warn!(rule = %alert.rule_id, "Quarantaine : chemin introuvable dans l'événement");
                    Ok(())
                }
            }
            RuleAction::BlockIp => {
                if let Some(ip) = extract_ip(&alert.event_json) {
                    self.block_ip(alert, &ip).await
                } else {
                    warn!(rule = %alert.rule_id, "BlockIp : IP introuvable dans l'événement");
                    Ok(())
                }
            }
        }
    }

    // ─────────────────────────────────────────
    //  Kill (EF-R01)
    // ─────────────────────────────────────────

    async fn kill_process(&self, alert: &Alert) -> Result<()> {
        let pid = Pid::from_raw(alert.pid as i32);

        if self.dry_run {
            info!(
                dry_run = true,
                pid = alert.pid,
                rule = %alert.rule_id,
                "[DRY-RUN] SIGKILL → PID {}", alert.pid
            );
            return Ok(());
        }

        info!(
            pid = alert.pid,
            rule = %alert.rule_id,
            "Envoi SIGKILL → PID {}", alert.pid
        );

        match kill(pid, Signal::SIGKILL) {
            Ok(_) => {
                info!("PID {} terminé avec succès", alert.pid);
                self.log_action("kill", &format!("pid:{}", alert.pid), true, alert);
            }
            Err(e) => {
                warn!("Impossible de tuer PID {} : {}", alert.pid, e);
                self.log_action("kill", &format!("pid:{}", alert.pid), false, alert);
            }
        }

        Ok(())
    }

    // ─────────────────────────────────────────
    //  Quarantaine (EF-R02)
    // ─────────────────────────────────────────

    async fn quarantine_file(&self, alert: &Alert, path: &str) -> Result<()> {
        if self.dry_run {
            info!(
                dry_run = true,
                path = path,
                rule = %alert.rule_id,
                "[DRY-RUN] Quarantaine → {}", path
            );
            return Ok(());
        }

        let src = Path::new(path);
        if !src.exists() {
            warn!("Fichier à mettre en quarantaine introuvable : {}", path);
            return Ok(());
        }

        let ts   = Utc::now().format("%Y%m%d_%H%M%S%.3f");
        let name = src.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        let dst_dir  = self.quarantine_dir.join(format!("{}_{}", ts, alert.rule_id));
        let dst_file = dst_dir.join(name);
        let meta_file = dst_dir.join("metadata.json");

        fs::create_dir_all(&dst_dir)?;

        // Déplacement du fichier
        match fs::rename(src, &dst_file) {
            Ok(_) => {
                info!("Fichier mis en quarantaine : {} → {:?}", path, dst_file);

                // Métadonnées JSON
                let meta = serde_json::json!({
                    "original_path": path,
                    "quarantine_path": dst_file,
                    "rule_id": alert.rule_id,
                    "severity": alert.severity.to_string(),
                    "pid": alert.pid,
                    "timestamp": Utc::now().to_rfc3339(),
                });
                fs::write(&meta_file, serde_json::to_string_pretty(&meta)?)?;

                self.log_action("quarantine", path, true, alert);
            }
            Err(e) => {
                warn!("Erreur quarantaine {} : {}", path, e);
                self.log_action("quarantine", path, false, alert);
            }
        }

        Ok(())
    }

    // ─────────────────────────────────────────
    //  Blocage IP via iptables (EF-R03)
    // ─────────────────────────────────────────

    async fn block_ip(&self, alert: &Alert, ip: &str) -> Result<()> {
        if self.dry_run {
            info!(
                dry_run = true,
                ip = ip,
                rule = %alert.rule_id,
                "[DRY-RUN] iptables DROP → {}", ip
            );
            return Ok(());
        }

        info!(ip = ip, rule = %alert.rule_id, "Blocage iptables → {}", ip);

        // Ajout d'une règle INPUT et OUTPUT pour l'IP
        for chain in &["INPUT", "OUTPUT"] {
            let status = Command::new("iptables")
                .args(["-A", chain, "-s", ip, "-j", "DROP"])
                .status();

            match status {
                Ok(s) if s.success() => {
                    info!("Règle iptables ajoutée : {} DROP {}", chain, ip);
                }
                Ok(s) => {
                    warn!("iptables a retourné un code d'erreur {} pour {} {}", s, chain, ip);
                }
                Err(e) => {
                    warn!("Impossible d'exécuter iptables : {}", e);
                }
            }
        }

        self.log_action("block_ip", ip, true, alert);
        Ok(())
    }

    // ─────────────────────────────────────────
    //  Journalisation des actions
    // ─────────────────────────────────────────

    fn log_action(&self, action_type: &str, target: &str, success: bool, alert: &Alert) {
        info!(
            action    = action_type,
            target    = target,
            success   = success,
            dry_run   = self.dry_run,
            rule      = %alert.rule_id,
            severity  = %alert.severity,
            pid       = alert.pid,
            timestamp = %Utc::now().to_rfc3339(),
            "Action de réponse exécutée"
        );
    }
}

// ─────────────────────────────────────────────
//  Helpers d'extraction depuis le JSON d'événement
// ─────────────────────────────────────────────

fn extract_file_path(event_json: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(event_json).ok()?;
    v.get("File")
        .and_then(|f| f.get("path"))
        .and_then(|p| p.as_str())
        .map(String::from)
}

fn extract_ip(event_json: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(event_json).ok()?;
    v.get("Network")
        .and_then(|n| n.get("dst_ip"))
        .and_then(|ip| ip.as_str())
        .map(String::from)
}
