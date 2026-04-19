//! Build script de l'agent EDR.
//!
//! Compile automatiquement le crate edr-ebpf pour bpfel-unknown-none
//! et place le bytecode dans OUT_DIR pour que include_bytes_aligned! fonctionne.

use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=../edr-ebpf/src/main.rs");

    let out_dir    = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_file   = out_dir.join("edr-ebpf");
    let workspace  = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent().unwrap()
        .to_path_buf();

    let status = Command::new("cargo")
        .current_dir(&workspace)
        .args([
            "build",
            "--package", "edr-ebpf",
            "--release",
            "--target", "bpfel-unknown-none",
            "-Z", "build-std=core",
        ])
        .status()
        .expect("Impossible de lancer cargo pour edr-ebpf");

    if !status.success() {
        // Écrire un fichier vide pour que la compilation continue
        // (le chargement aya échouera au runtime avec un message clair)
        eprintln!("cargo:warning=Compilation eBPF échouée — l'agent ne pourra pas charger les sondes.");
        std::fs::write(&out_file, b"").unwrap();
        return;
    }

    let bytecode = workspace
        .join("target/bpfel-unknown-none/release/edr-ebpf");

    if bytecode.exists() {
        std::fs::copy(&bytecode, &out_file).expect("Copie bytecode eBPF");
    } else {
        eprintln!("cargo:warning=Bytecode eBPF introuvable à {:?}", bytecode);
        std::fs::write(&out_file, b"").unwrap();
    }
}
