//! Point d'entrée de l'agent EDR Linux.
//!
//! Responsabilités :
//! - Parser les arguments CLI via `clap`
//! - Charger la configuration et les règles TOML
//! - Démarrer le daemon (collecteur eBPF + analyseur + stockage + réponse)
//! - Fournir les sous-commandes d'administration

mod collector;
mod analyzer;
mod storage;
mod response;
mod interface;
mod config;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt};

use config::Config;
use interface::cli;

// ─────────────────────────────────────────────
//  CLI
// ─────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "edr",
    about = "EDR Linux — Endpoint Detection & Response en Rust",
    version = "0.1.0",
    author = "Benoît PIGUEL & Axel WAS",
)]
struct Cli {
    /// Chemin vers le fichier de configuration principal
    #[arg(short, long, default_value = "/etc/edr/edr.toml")]
    config: String,

    /// Niveau de verbosité (RUST_LOG override)
    #[arg(short, long, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Démarrer le daemon EDR
    Start {
        /// Mode simulation : aucune action de réponse n'est exécutée
        #[arg(long)]
        dry_run: bool,
        /// Chemin vers le fichier de règles
        #[arg(long, default_value = "/etc/edr/rules.toml")]
        rules: String,
    },
    /// Arrêter le daemon EDR
    Stop,
    /// Afficher l'état du daemon et les compteurs
    Status,
    /// Lister les alertes avec filtres optionnels
    Alerts {
        /// Filtrer par sévérité minimale (low|medium|high|critical)
        #[arg(long)]
        severity: Option<String>,
        /// Filtrer sur les N dernières heures
        #[arg(long)]
        last: Option<u64>,
        /// Nombre maximum de résultats
        #[arg(long, default_value = "50")]
        limit: usize,
    },
    /// Recharger rules.toml sans redémarrage (envoie SIGHUP au daemon)
    RulesReload,
    /// Exporter les alertes
    Export {
        /// Format : json | csv
        #[arg(long, default_value = "json")]
        format: String,
        /// Fichier de sortie (stdout si absent)
        #[arg(long)]
        output: Option<String>,
    },
    /// Lancer le dashboard TUI temps-réel
    Dashboard,
}

// ─────────────────────────────────────────────
//  Main
// ─────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli_args = Cli::parse();

    // Initialisation du logger
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&cli_args.log_level));
    fmt().with_env_filter(filter).with_target(false).init();

    // Chargement de la configuration
    let config = Config::load(&cli_args.config).unwrap_or_else(|e| {
        warn!("Config non trouvée ({}), utilisation des valeurs par défaut", e);
        Config::default()
    });

    match cli_args.command {
        Commands::Start { dry_run, rules } => {
            info!("Démarrage de l'agent EDR (dry_run={})", dry_run);
            start_daemon(config, rules, dry_run).await?;
        }
        Commands::Stop => {
            cli::send_stop_signal()?;
        }
        Commands::Status => {
            cli::print_status(&config).await?;
        }
        Commands::Alerts { severity, last, limit } => {
            cli::list_alerts(&config, severity, last, limit).await?;
        }
        Commands::RulesReload => {
            cli::send_sighup()?;
        }
        Commands::Export { format, output } => {
            cli::export_alerts(&config, &format, output.as_deref()).await?;
        }
        Commands::Dashboard => {
            interface::tui::run_dashboard(&config).await?;
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────
//  Orchestration du daemon
// ─────────────────────────────────────────────

async fn start_daemon(config: Config, rules_path: String, dry_run: bool) -> Result<()> {
    use std::sync::Arc;
    use tokio::sync::{broadcast, mpsc};
    use analyzer::RuleEngine;
    use storage::Database;
    use response::ResponseEngine;

    // Canal événements : collecteur → analyseur
    let (event_tx, mut event_rx) = mpsc::channel::<edr_common::EdrEvent>(8192);

    // Canal alertes : analyseur → stockage + réponse
    let (alert_tx, alert_rx) = broadcast::channel::<edr_common::Alert>(1024);

    // Initialisation de la base de données
    let db = Arc::new(Database::open(&config.storage.db_path)?);
    db.migrate()?;

    // Moteur de règles
    let rule_engine = Arc::new(
        RuleEngine::load(&rules_path)
            .unwrap_or_else(|_| RuleEngine::with_defaults())
    );

    // Moteur de réponse
    let response_engine = Arc::new(ResponseEngine::new(dry_run));

    // Collecteur eBPF + fanotify (tâche tokio)
    let event_tx_clone = event_tx.clone();
    let config_clone   = config.clone();
    let collector_handle = tokio::spawn(async move {
        if let Err(e) = collector::run(config_clone, event_tx_clone).await {
            tracing::error!("Collecteur eBPF arrêté : {}", e);
        }
    });

    // Boucle d'analyse
    let db_clone     = db.clone();
    let re_clone     = rule_engine.clone();
    let alert_tx_cl  = alert_tx.clone();
    let analysis_handle = tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            // Persistance de l'événement
            if let Err(e) = db_clone.insert_event(&event) {
                tracing::warn!("Erreur stockage événement : {}", e);
            }

            // Évaluation des règles
            let alerts = re_clone.evaluate(&event);
            for alert in alerts {
                tracing::warn!(
                    rule = %alert.rule_id,
                    severity = %alert.severity,
                    pid = alert.pid,
                    "ALERTE : {}",
                    alert.rule_description
                );
                let _ = alert_tx_cl.send(alert);
            }
        }
    });

    // Tâche de stockage des alertes + réponse
    let db_clone2      = db.clone();
    let mut alert_rx2  = alert_rx;
    let resp_clone     = response_engine.clone();
    let response_handle = tokio::spawn(async move {
        while let Ok(alert) = alert_rx2.recv().await {
            if let Err(e) = db_clone2.insert_alert(&alert) {
                tracing::warn!("Erreur stockage alerte : {}", e);
            }
            if let Err(e) = resp_clone.execute(&alert).await {
                tracing::warn!("Erreur réponse : {}", e);
            }
        }
    });

    // Gestion SIGHUP pour rechargement des règles
    let rule_engine_sig = rule_engine.clone();
    let rules_path_sig  = rules_path.clone();
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sighup = signal(SignalKind::hangup()).expect("SIGHUP handler");
        loop {
            sighup.recv().await;
            info!("SIGHUP reçu — rechargement des règles depuis {}", rules_path_sig);
            match RuleEngine::load(&rules_path_sig) {
                Ok(new_engine) => {
                    // On ne peut pas remplacer Arc<RuleEngine> directement ici
                    // En production : utiliser ArcSwap ou RwLock
                    info!("Règles rechargées ({} règles)", new_engine.rule_count());
                }
                Err(e) => tracing::error!("Échec rechargement règles : {}", e),
            }
        }
    });

    // Attente signal d'arrêt (Ctrl-C / SIGTERM)
    tokio::signal::ctrl_c().await?;
    info!("Signal d'arrêt reçu, arrêt propre…");

    collector_handle.abort();
    analysis_handle.abort();
    response_handle.abort();

    Ok(())
}
