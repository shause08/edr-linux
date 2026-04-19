//! xtask — script de build unifié pour l'EDR.
//!
//! Usage :
//!   cargo xtask build   — compile eBPF + agent
//!   cargo xtask run     — compile eBPF + lance l'agent (nécessite sudo)
//!
//! Plus besoin de gérer manuellement les deux crates séparément.

use std::{
    env,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};
use anyhow::{Context, Result};

fn main() -> Result<()> {
    let task = env::args().nth(1).unwrap_or_else(|| "build".to_string());
    let workspace = workspace_root();

    match task.as_str() {
        "build" => {
            build_ebpf(&workspace)?;
            build_agent(&workspace)?;
            println!("\n✓ Build complet. Lancer avec : sudo ./target/release/edr");
        }
        "run" => {
            build_ebpf(&workspace)?;
            run_agent(&workspace)?;
        }
        other => {
            anyhow::bail!("Tâche inconnue : '{}'. Utiliser 'build' ou 'run'.", other);
        }
    }
    Ok(())
}

fn build_ebpf(workspace: &Path) -> Result<()> {
    println!("── Compilation du bytecode eBPF…");
    let status = Command::new("cargo")
        .current_dir(workspace)
        .args([
            "build",
            "--package", "edr-ebpf",
            "--release",
            "--target", "bpfel-unknown-none",
            "-Z", "build-std=core",
        ])
        .status()
        .context("Impossible de lancer cargo pour edr-ebpf")?;

    ensure_success(status, "Compilation eBPF échouée")
}

fn build_agent(workspace: &Path) -> Result<()> {
    println!("── Compilation de l'agent…");
    let status = Command::new("cargo")
        .current_dir(workspace)
        .args(["build", "--package", "edr", "--release"])
        .status()
        .context("Impossible de lancer cargo pour edr")?;

    ensure_success(status, "Compilation agent échouée")
}

fn run_agent(workspace: &Path) -> Result<()> {
    println!("── Lancement de l'agent (sudo requis)…");
    let binary = workspace.join("target/release/edr");
    let status = Command::new("sudo")
        .arg(binary)
        .status()
        .context("Impossible de lancer l'agent")?;

    ensure_success(status, "L'agent s'est arrêté avec une erreur")
}

fn ensure_success(status: ExitStatus, msg: &str) -> Result<()> {
    if status.success() { Ok(()) } else { anyhow::bail!("{}", msg) }
}

fn workspace_root() -> PathBuf {
    // __file__ est dans xtask/src/, on remonte de 3 niveaux
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap()  // xtask/
        .parent().unwrap()  // workspace root
        .to_path_buf()
}
