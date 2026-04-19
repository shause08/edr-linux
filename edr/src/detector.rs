//! Moteur de détection : évalue chaque événement contre les règles.

use anyhow::Result;
use chrono::Utc;
use std::sync::Arc;
use tokio::sync::mpsc::Receiver;
use tracing::warn;

use crate::events::{Alert, Event, Severity};
use crate::storage::Database;

pub async fn run(mut rx: Receiver<Event>, db: Arc<Database>) -> Result<()> {
    while let Some(event) = rx.recv().await {
        // Persistance de l'événement
        if let Err(e) = db.insert_event(&event) {
            warn!("Stockage événement : {}", e);
        }

        // Évaluation des règles
        for alert in evaluate(&event) {
            tracing::warn!(
                rule     = %alert.rule,
                severity = %alert.severity,
                "{}",
                alert.message
            );
            if let Err(e) = db.insert_alert(&alert) {
                warn!("Stockage alerte : {}", e);
            }
        }
    }
    Ok(())
}

/// Applique toutes les règles à un événement et retourne les alertes.
fn evaluate(event: &Event) -> Vec<Alert> {
    RULES.iter()
        .filter_map(|rule| rule(event))
        .collect()
}

type Rule = fn(&Event) -> Option<Alert>;

/// Liste des règles de détection.
static RULES: &[Rule] = &[
    rule_exec_from_tmp,
    rule_shadow_access,
    rule_crontab_write,
    rule_suspicious_shell,
    rule_ssh_key_write,
];

// ── Règles ────────────────────────────────────────────────────────────

/// R-001 : Exécution d'un binaire depuis /tmp ou /dev/shm
fn rule_exec_from_tmp(event: &Event) -> Option<Alert> {
    let Event::Process(e) = event else { return None };
    if e.exe.starts_with("/tmp/") || e.exe.starts_with("/dev/shm/") {
        return Some(alert(
            "R-001",
            Severity::High,
            format!("Exécution depuis répertoire temporaire : {} (pid={})", e.exe, e.pid),
            event,
        ));
    }
    None
}

/// R-002 : Lecture ou modification de /etc/shadow
fn rule_shadow_access(event: &Event) -> Option<Alert> {
    let Event::File(e) = event else { return None };
    if e.path.contains("shadow") {
        return Some(alert(
            "R-002",
            Severity::Critical,
            format!("Accès à /etc/shadow : {} ({})", e.path, e.operation),
            event,
        ));
    }
    None
}

/// R-003 : Modification d'une crontab
fn rule_crontab_write(event: &Event) -> Option<Alert> {
    let Event::File(e) = event else { return None };
    if e.path.contains("cron") && matches!(e.operation.as_str(), "MODIFY" | "CREATE") {
        return Some(alert(
            "R-003",
            Severity::High,
            format!("Modification crontab : {}", e.path),
            event,
        ));
    }
    None
}

/// R-004 : Shell interactif lancé par un utilisateur non-root
fn rule_suspicious_shell(event: &Event) -> Option<Alert> {
    let Event::Process(e) = event else { return None };
    let is_shell = e.exe.ends_with("/bash")
        || e.exe.ends_with("/sh")
        || e.exe.ends_with("/zsh")
        || e.exe.ends_with("/dash");
    if is_shell && e.uid > 0 {
        return Some(alert(
            "R-004",
            Severity::Medium,
            format!("Shell interactif lancé : {} (uid={}, pid={})", e.exe, e.uid, e.pid),
            event,
        ));
    }
    None
}

/// R-005 : Écriture dans ~/.ssh/
fn rule_ssh_key_write(event: &Event) -> Option<Alert> {
    let Event::File(e) = event else { return None };
    if e.path.contains(".ssh") && matches!(e.operation.as_str(), "MODIFY" | "CREATE") {
        return Some(alert(
            "R-005",
            Severity::High,
            format!("Modification clé SSH : {}", e.path),
            event,
        ));
    }
    None
}

// ── Helper ────────────────────────────────────────────────────────────

fn alert(rule: &str, severity: Severity, message: String, event: &Event) -> Alert {
    Alert {
        rule:       rule.to_string(),
        severity,
        message,
        timestamp:  Utc::now(),
        event_json: serde_json::to_string(event).unwrap_or_default(),
    }
}
