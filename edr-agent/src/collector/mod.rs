//! Module collecteur — charge les programmes eBPF et reçoit les événements bruts.
//!
//! Responsabilités :
//! 1. Charger le bytecode eBPF compilé et attacher les sondes
//! 2. Lire le ring buffer en boucle async et désérialiser les `RawEvent`
//! 3. Enrichir chaque événement via `/proc` (cwd, exe, cmdline, user)
//! 4. Calculer le SHA-256 des binaires exécutés
//! 5. Lancer le collecteur fanotify pour la surveillance des fichiers
//! 6. Émettre des `EdrEvent` vers l'analyseur

pub mod ebpf;
pub mod fanotify;
pub mod proc_enricher;
pub mod hasher;
pub mod network_proc;

use anyhow::Result;
use edr_common::EdrEvent;
use tokio::sync::mpsc::Sender;
use tracing::info;

use crate::config::Config;

/// Lance les deux collecteurs (eBPF + fanotify) en parallèle.
pub async fn run(config: Config, event_tx: Sender<EdrEvent>) -> Result<()> {
    info!("Démarrage du collecteur eBPF…");

    let tx_ebpf     = event_tx.clone();
    let tx_fanotify = event_tx.clone();
    let tx_network  = event_tx.clone();

    let config_clone = config.clone();

    // Collecteur eBPF principal
    let ebpf_handle = tokio::spawn(async move {
        if let Err(e) = ebpf::run(tx_ebpf).await {
            tracing::error!("Collecteur eBPF : {}", e);
        }
    });

    // Collecteur fanotify pour les fichiers
    let watched = config.collector.watched_paths.clone();
    let fanotify_handle = tokio::spawn(async move {
        if let Err(e) = fanotify::run(watched, tx_fanotify).await {
            tracing::error!("Collecteur fanotify : {}", e);
        }
    });

    // Collecteur réseau fallback /proc/net/tcp
    let net_handle = tokio::spawn(async move {
        if config_clone.collector.network_monitoring {
            if let Err(e) = network_proc::run(
                config_clone.collector.network_scan_threshold,
                tx_network,
            ).await {
                tracing::error!("Collecteur réseau /proc : {}", e);
            }
        }
    });

    tokio::try_join!(
        async { ebpf_handle.await.map_err(|e| anyhow::anyhow!(e)) },
        async { fanotify_handle.await.map_err(|e| anyhow::anyhow!(e)) },
        async { net_handle.await.map_err(|e| anyhow::anyhow!(e)) },
    )?;

    Ok(())
}
