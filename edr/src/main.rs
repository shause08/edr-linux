//! EDR Linux — Agent userspace principal.
//!
//! Compile et lance avec :
//!   cargo xtask run
//!
//! Ou manuellement :
//!   cargo xtask build && sudo ./target/release/edr

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
    // Logs : RUST_LOG=debug pour plus de détails
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env()
            .add_directive("edr=info".parse()?))
        .with_target(false)
        .init();

    info!("EDR Linux v0.1 — démarrage");

    // Base de données SQLite locale
    let db = Arc::new(Database::open("edr.db")?);
    db.migrate()?;

    // Canal principal : tous les collecteurs → détecteur
    let (tx, rx) = mpsc::channel::<Event>(4096);

    // Lancement des collecteurs en parallèle
    let tx_ebpf    = tx.clone();
    let tx_files   = tx.clone();
    let tx_network = tx.clone();

    tokio::spawn(async move {
        if let Err(e) = collector::ebpf::run(tx_ebpf).await {
            tracing::error!("Collecteur eBPF arrêté : {:#}", e);
        }
    });

    tokio::spawn(async move {
        if let Err(e) = collector::files::run(tx_files).await {
            tracing::error!("Collecteur fichiers arrêté : {:#}", e);
        }
    });

    tokio::spawn(async move {
        if let Err(e) = collector::network::run(tx_network).await {
            tracing::error!("Collecteur réseau arrêté : {:#}", e);
        }
    });

    // Lancement du détecteur + stockage + TUI
    let db_det = db.clone();
    let db_tui = db.clone();

    let detector_handle = tokio::spawn(async move {
        detector::run(rx, db_det).await
    });

    let tui_handle = tokio::spawn(async move {
        tui::run(db_tui).await
    });

    // Attente Ctrl-C
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Signal reçu, arrêt…");
        }
        r = detector_handle => {
            if let Ok(Err(e)) = r { tracing::error!("Détecteur : {:#}", e); }
        }
        r = tui_handle => {
            if let Ok(Err(e)) = r { tracing::error!("TUI : {:#}", e); }
        }
    }

    Ok(())
}
