# EDR Linux

Endpoint Detection & Response léger pour Linux, écrit en Rust.

## Prérequis

```bash
# 1. Rust nightly + composants eBPF
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly

# 2. Installer bpf-linker (nécessaire pour compiler le code noyau)
cargo install bpf-linker
```

> Le fichier `rust-toolchain.toml` à la racine du projet force automatiquement
> nightly dans ce répertoire — pas besoin de taper `+nightly` manuellement.

## Compilation et lancement

```bash
# Tout en une commande (compile eBPF + agent, puis lance)
cargo xtask run

# Ou séparément :
cargo xtask build          # compile seulement
sudo ./target/release/edr  # lance manuellement
```

> **sudo est requis** pour charger les programmes eBPF dans le noyau.

## Fonctionnalités

| Module | Méthode | Ce qui est détecté |
|---|---|---|
| Processus | eBPF tracepoint `sys_enter_execve` | Toutes les exécutions de binaires |
| Fichiers | inotify | `/etc/passwd`, `/etc/shadow`, `/tmp`, `~/.ssh`, crontabs |
| Réseau | `/proc/net/tcp` | Nouvelles connexions TCP établies |
| Dashboard | ratatui TUI | Alertes en temps réel, compteurs |

## Règles de détection

| ID | Description | Sévérité |
|---|---|---|
| R-001 | Exécution depuis `/tmp` ou `/dev/shm` | HIGH |
| R-002 | Accès à `/etc/shadow` | CRITICAL |
| R-003 | Modification d'une crontab | HIGH |
| R-004 | Shell interactif lancé (uid > 0) | MEDIUM |
| R-005 | Écriture dans `~/.ssh/` | HIGH |

## Structure du projet

```
edr-linux/
├── rust-toolchain.toml   ← force nightly automatiquement
├── edr-ebpf/             ← programme noyau (no_std, tracepoint execve)
│   └── src/main.rs
├── edr/                  ← agent userspace
│   ├── build.rs          ← compile edr-ebpf automatiquement
│   └── src/
│       ├── main.rs
│       ├── events.rs     ← types partagés
│       ├── collector/
│       │   ├── ebpf.rs   ← lecture PerfEventArray
│       │   ├── files.rs  ← inotify
│       │   └── network.rs← /proc/net/tcp
│       ├── detector.rs   ← moteur de règles
│       ├── storage.rs    ← SQLite
│       └── tui.rs        ← dashboard ratatui
└── xtask/                ← script de build unifié
    └── src/main.rs
```

## Commandes utiles

```bash
# Voir les logs détaillés
RUST_LOG=debug sudo ./target/release/edr

# Tester une règle (R-001)
cp /usr/bin/ls /tmp/test_edr && /tmp/test_edr && rm /tmp/test_edr
```
