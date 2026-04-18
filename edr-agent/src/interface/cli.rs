//! Implémentation des sous-commandes CLI de l'EDR.
//!
//! Toutes les commandes autres que `start` lisent la base SQLite directement
//! (le daemon n'a pas besoin d'être en cours d'exécution).

use anyhow::Result;
use std::fs;
use std::io::Write;

use crate::config::Config;
use crate::storage::Database;

// ─────────────────────────────────────────────
//  edr status
// ─────────────────────────────────────────────

/// Affiche l'état du daemon et les compteurs d'événements.
pub async fn print_status(config: &Config) -> Result<()> {
    println!("\n╔══════════════════════════════════════╗");
    println!("║       EDR Linux — Status             ║");
    println!("╚══════════════════════════════════════╝\n");

    // Vérification PID file
    let pid_file = &config.agent.pid_file;
    match fs::read_to_string(pid_file) {
        Ok(pid_str) => {
            let pid = pid_str.trim();
            let proc_path = format!("/proc/{}", pid);
            if std::path::Path::new(&proc_path).exists() {
                println!("  Daemon  : \x1b[32m● En cours\x1b[0m  (PID {})", pid);
            } else {
                println!("  Daemon  : \x1b[31m● Arrêté\x1b[0m  (PID file présent mais processus mort)");
            }
        }
        Err(_) => {
            println!("  Daemon  : \x1b[33m● Inconnu\x1b[0m  (PID file absent)");
        }
    }

    // Statistiques base de données
    match Database::open(&config.storage.db_path) {
        Ok(db) => {
            match db.stats() {
                Ok(stats) => {
                    println!("\n  ── Base de données ──────────────────");
                    println!("  Événements   : {:>10}", stats.event_count);
                    println!("  Alertes      : {:>10}", stats.alert_count);
                    println!("  Critiques    : {:>10}", stats.critical_count);
                    println!("  DB           : {}", config.storage.db_path);
                }
                Err(e) => println!("  Erreur lecture DB : {}", e),
            }
        }
        Err(e) => println!("\n  Base de données inaccessible : {}", e),
    }

    println!("\n  ── Configuration ────────────────────");
    println!("  Quarantaine  : {}", config.agent.quarantine_dir);
    println!("  Rétention    : {} jours", config.storage.retention_days);
    println!("  Réseau       : {}", config.collector.network_monitoring);
    println!();
    Ok(())
}

// ─────────────────────────────────────────────
//  edr alerts
// ─────────────────────────────────────────────

/// Liste les alertes avec filtres optionnels.
pub async fn list_alerts(
    config: &Config,
    severity: Option<String>,
    last_hours: Option<u64>,
    limit: usize,
) -> Result<()> {
    let db = Database::open(&config.storage.db_path)?;
    let alerts = db.query_alerts(
        severity.as_deref(),
        last_hours,
        limit,
    )?;

    if alerts.is_empty() {
        println!("Aucune alerte trouvée.");
        return Ok(());
    }

    println!("\n{:<10} {:<12} {:<10} {:<25} {:<14} {}",
        "ID", "Règle", "Sévérité", "Timestamp", "PID", "Description");
    println!("{}", "─".repeat(100));

    for alert in &alerts {
        let sev_colored = match alert.severity {
            edr_common::Severity::Critical => format!("\x1b[31m{:<10}\x1b[0m", "CRITICAL"),
            edr_common::Severity::High     => format!("\x1b[33m{:<10}\x1b[0m", "HIGH"),
            edr_common::Severity::Medium   => format!("\x1b[34m{:<10}\x1b[0m", "MEDIUM"),
            edr_common::Severity::Low      => format!("\x1b[37m{:<10}\x1b[0m", "LOW"),
        };

        println!("{:<10} {:<12} {} {:<25} {:<14} {}",
            alert.id.unwrap_or(0),
            alert.rule_id,
            sev_colored,
            alert.timestamp.format("%Y-%m-%d %H:%M:%S"),
            alert.pid,
            truncate(&alert.rule_description, 50),
        );

        if let Some(mitre) = &alert.mitre_technique {
            println!("           \x1b[36mMITRE ATT&CK: {}\x1b[0m", mitre);
        }
    }

    println!("\n  {} alerte(s) affichée(s)\n", alerts.len());
    Ok(())
}

// ─────────────────────────────────────────────
//  edr export
// ─────────────────────────────────────────────

/// Exporte les alertes en JSON (ECS) ou CSV.
pub async fn export_alerts(
    config: &Config,
    format: &str,
    output: Option<&str>,
) -> Result<()> {
    let db     = Database::open(&config.storage.db_path)?;
    let alerts = db.query_alerts(None, None, usize::MAX)?;

    let content = match format {
        "json" | "JSON" => export_json(&alerts)?,
        "csv"  | "CSV"  => export_csv(&alerts)?,
        other => {
            anyhow::bail!("Format non supporté : {} (utiliser json ou csv)", other)
        }
    };

    match output {
        Some(path) => {
            fs::write(path, &content)?;
            println!("Export écrit dans : {}", path);
        }
        None => {
            print!("{}", content);
        }
    }

    Ok(())
}

fn export_json(alerts: &[edr_common::Alert]) -> Result<String> {
    let ecs_alerts: Vec<serde_json::Value> = alerts.iter().map(|a| a.to_ecs()).collect();
    Ok(serde_json::to_string_pretty(&ecs_alerts)?)
}

fn export_csv(alerts: &[edr_common::Alert]) -> Result<String> {
    let mut out = String::new();
    out.push_str("id,rule_id,severity,pid,timestamp,mitre_technique,description,action_taken\n");

    for a in alerts {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            a.id.unwrap_or(0),
            csv_escape(&a.rule_id),
            csv_escape(&a.severity.to_string()),
            a.pid,
            a.timestamp.to_rfc3339(),
            csv_escape(a.mitre_technique.as_deref().unwrap_or("")),
            csv_escape(&a.rule_description),
            csv_escape(a.action_taken.as_deref().unwrap_or("")),
        ));
    }

    Ok(out)
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// ─────────────────────────────────────────────
//  edr stop / rules reload
// ─────────────────────────────────────────────

/// Envoie SIGTERM au daemon.
pub fn send_stop_signal() -> Result<()> {
    send_signal_to_daemon(nix::sys::signal::Signal::SIGTERM, "SIGTERM")
}

/// Envoie SIGHUP au daemon pour recharger les règles.
pub fn send_sighup() -> Result<()> {
    send_signal_to_daemon(nix::sys::signal::Signal::SIGHUP, "SIGHUP")
}

fn send_signal_to_daemon(sig: nix::sys::signal::Signal, name: &str) -> Result<()> {
    let pid_file = "/run/edr.pid";
    let pid_str  = fs::read_to_string(pid_file)
        .map_err(|_| anyhow::anyhow!("Daemon non démarré (PID file absent : {})", pid_file))?;

    let pid: i32 = pid_str.trim().parse()
        .map_err(|_| anyhow::anyhow!("PID invalide dans {}", pid_file))?;

    nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), sig)?;
    println!("{} envoyé au daemon (PID {})", name, pid);
    Ok(())
}

// ─────────────────────────────────────────────
//  Utilitaires
// ─────────────────────────────────────────────

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}
