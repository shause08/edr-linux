mod events;
mod collector;
mod detector;
mod storage;
mod tui;

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;
use tracing_subscriber::EnvFilter;

use events::Event;
use storage::Database;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("edr=info".parse()?)
        )
        .with_target(false)
        .init();

    info!("EDR Linux v0.1 — démarrage");

    let db = Arc::new(Database::open("edr.db")?);
    db.migrate()?;

    let (tx, rx) = mpsc::channel::<Event>(4096);

    // ── Collecteurs ──────────────────────────────────────────────────

    {
        let tx = tx.clone();
        tokio::spawn(async move {
            match collector::ebpf::run(tx).await {
                Ok(_)  => tracing::warn!("Collecteur eBPF terminé"),
                Err(e) => tracing::error!("Collecteur eBPF ERREUR : {:#}", e),
            }
        });
    }
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            match collector::files::run(tx).await {
                Ok(_)  => tracing::warn!("Collecteur fichiers terminé"),
                Err(e) => tracing::error!("Collecteur fichiers ERREUR : {:#}", e),
            }
        });
    }
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            match collector::network::run(tx).await {
                Ok(_)  => tracing::warn!("Collecteur réseau terminé"),
                Err(e) => tracing::error!("Collecteur réseau ERREUR : {:#}", e),
            }
        });
    }
    drop(tx);

    // ── Détecteur (tourne toujours en arrière-plan) ──────────────────
    {
        let db = db.clone();
        tokio::spawn(async move {
            if let Err(e) = detector::run(rx, db).await {
                tracing::error!("Détecteur ERREUR : {:#}", e);
            }
        });
    }

    // ── TUI (bloquant — quand l'utilisateur ferme, on attend Ctrl-C) ─
    info!("Démarrage du dashboard TUI (q pour fermer le dashboard)");
    if let Err(e) = tui::run(db.clone()).await {
        tracing::error!("TUI ERREUR : {:#}", e);
    }

    // Après fermeture du TUI, les collecteurs continuent.
    // On attend Ctrl-C pour arrêter complètement.
    info!("Dashboard fermé. Surveillance active. Ctrl-C pour arrêter.");
    tokio::signal::ctrl_c().await?;
    info!("Arrêt.");

    Ok(())
}