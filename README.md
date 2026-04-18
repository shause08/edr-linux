# EDR Linux — Endpoint Detection & Response en Rust

> Projet Annuel — Benoît PIGUEL & Axel WAS  
> Implémentation d'un EDR Linux complet en Rust avec eBPF, fanotify, SQLite et TUI.

---

## Table des matières

1. [Prérequis](#prérequis)
2. [Architecture](#architecture)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Utilisation](#utilisation)
6. [Règles de détection](#règles-de-détection)
7. [Tests](#tests)
8. [Structure du projet](#structure-du-projet)

---

## Prérequis

### Système

| Prérequis | Version minimale |
|-----------|-----------------|
| Noyau Linux | ≥ 5.4 (x86-64) |
| Distribution | Ubuntu 22.04+, Debian 12+, Fedora 38+, Arch |
| Rust toolchain | stable + nightly (pour eBPF) |
| bpf-linker | dernière version |

### Capabilities requises

L'agent doit être lancé avec les capabilities suivantes (ou en root) :

```
CAP_BPF        — chargement des programmes eBPF
CAP_PERFMON    — accès aux événements perf
CAP_SYS_ADMIN  — fanotify filesystem-wide
CAP_NET_ADMIN  — ajout de règles iptables (mode actif)
```

### Dépendances système

```bash
# Ubuntu/Debian
apt install linux-headers-$(uname -r) clang llvm libelf-dev

# Fedora
dnf install kernel-headers clang llvm elfutils-libelf-devel
```

---

## Architecture

```
edr-linux/
├── edr-common/          # Types partagés (RawEvent, EdrEvent, Alert…)
│   └── src/lib.rs
├── edr-ebpf/            # Programmes eBPF (compilés pour bpfel-unknown-none)
│   └── src/main.rs      # kprobes: execve, clone, tcp_connect, chmod
│                        # tracepoint: sched_process_exit
└── edr-agent/           # Agent userspace principal
    └── src/
        ├── main.rs          # CLI (clap) + orchestration daemon
        ├── config.rs        # Chargement edr.toml
        ├── collector/
        │   ├── ebpf.rs      # Lecteur ring buffer eBPF
        │   ├── fanotify.rs  # Surveillance fichiers fanotify
        │   ├── proc_enricher.rs  # Enrichissement /proc
        │   ├── hasher.rs    # SHA-256 des binaires
        │   └── network_proc.rs   # Fallback /proc/net/tcp
        ├── analyzer/
        │   ├── mod.rs       # Moteur de règles TOML + 10 règles par défaut
        │   ├── scoring.rs   # Scoring composite par PID
        │   └── sequence.rs  # Détection de séquences temporelles
        ├── storage/
        │   └── mod.rs       # SQLite (events, alerts, actions, rules_log)
        ├── response/
        │   └── mod.rs       # Kill, Quarantaine, BlockIp (+ dry-run)
        └── interface/
            ├── cli.rs       # status, alerts, export, stop, rules reload
            └── tui.rs       # Dashboard ratatui temps-réel
```

**Flux de données :**

```
[Kernel]  kprobe/execve  ──┐
          kprobe/clone   ──┤  Ring Buffer  ──►  Collecteur eBPF
          tracepoint/exit──┘     (aya)              │
                                                     ▼
[Kernel]  fanotify       ────────────────►  Collecteur fichiers
                                                     │
          /proc/net/tcp  ────────────────►  Collecteur réseau
                                                     │
                                              Enrichissement /proc
                                                     │
                                              Moteur de règles
                                                     │
                                         ┌───────────┴──────────┐
                                         ▼                        ▼
                                       SQLite               Moteur réponse
                                     (events/alerts)    (kill/quarantine/iptables)
```

---

## Installation

### 1. Cloner et compiler

```bash
git clone https://github.com/votre-repo/edr-linux.git
cd edr-linux

# Compiler le bytecode eBPF (cible no_std)
rustup target add bpfel-unknown-none
cargo install bpf-linker

cargo build --target bpfel-unknown-none -p edr-ebpf --release

# Compiler l'agent userspace
cargo build -p edr-agent --release
```

### 2. Installer

```bash
# Binaire
install -m 755 target/release/edr /usr/local/bin/edr

# Configuration
mkdir -p /etc/edr
install -m 640 edr.toml  /etc/edr/edr.toml
install -m 640 rules.toml /etc/edr/rules.toml
chown root:root /etc/edr/*.toml

# Répertoires de données
mkdir -p /var/lib/edr /var/log/edr /var/edr/quarantine
```

### 3. Service systemd (optionnel)

```ini
# /etc/systemd/system/edr.service
[Unit]
Description=EDR Linux — Endpoint Detection & Response
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/edr --config /etc/edr/edr.toml start --rules /etc/edr/rules.toml
ExecReload=/bin/kill -HUP $MAINPID
PIDFile=/run/edr.pid
Restart=on-failure
RestartSec=5s
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now edr
```

---

## Configuration

### edr.toml

```toml
[agent]
pid_file       = "/run/edr.pid"
quarantine_dir = "/var/edr/quarantine"

[storage]
db_path        = "/var/lib/edr/events.db"
retention_days = 30

[collector]
watched_paths  = ["/etc/", "/root/.ssh/", "/home/"]
network_monitoring = true
network_scan_threshold = 50   # connexions/10s → alerte scan

[response]
active_mode = false  # passer à true après validation
log_actions = true
```

### Fichier de réputation IP (EF-N04)

```text
# /etc/edr/ip_reputation.txt
# Un CIDR ou IP par ligne
185.220.101.0/24   # Tor exit nodes
198.51.100.42
```

Configurer dans edr.toml :
```toml
[collector]
ip_reputation_file = "/etc/edr/ip_reputation.txt"
```

---

## Utilisation

### Commandes principales

```bash
# Démarrer le daemon (mode simulation)
sudo edr start --dry-run --rules /etc/edr/rules.toml

# Démarrer en mode actif (kill/quarantaine réels)
sudo edr start --rules /etc/edr/rules.toml

# État du daemon
edr status

# Lister les alertes hautes et critiques des 6 dernières heures
edr alerts --severity high --last 6

# Recharger les règles sans redémarrage
edr rules-reload

# Exporter les alertes en JSON (ECS)
edr export --format json --output /tmp/alerts.json

# Exporter en CSV
edr export --format csv --output /tmp/alerts.csv

# Dashboard TUI temps-réel
edr dashboard
```

### Dashboard TUI

```
╔══════════════════════════════════════════════════════════╗
║  EDR Linux  ─  Événements: 14823  │  Alertes: 37  │  ...║
╚══════════════════════════════════════════════════════════╝

 Événements / seconde (60s)          Statistiques
 ▁▂▄▇▅▃▆▄▂▁▃▅▄▂▁▃...               Événements : 14823
                                      Alertes    :    37
 Dernières alertes (24h)             Critiques  :     5
 CRIT R-009 PID:1234  ...
 HIGH R-001 PID:5678  ...
 MED  R-006 PID:9012  ...
```

Raccourcis : `q` quitter, `r` rafraîchir, `Ctrl+C` quitter.

---

## Règles de détection

Les 10 règles par défaut couvrent les techniques MITRE ATT&CK suivantes :

| ID    | Description | Sévérité | MITRE |
|-------|-------------|----------|-------|
| R-001 | Exécution depuis /tmp ou /dev/shm | High | T1059 |
| R-002 | Shell interactif spawné par un service | Critical | T1059.004 |
| R-003 | Modification /etc/passwd ou /etc/shadow | Critical | T1098 |
| R-004 | Modification crontab ou timer systemd | High | T1053.003 |
| R-005 | Variable LD_PRELOAD définie | High | T1574.006 |
| R-006 | Scan réseau (> 50 connexions/10s) | Medium | T1046 |
| R-007 | Connexion réseau < 2s après execve | High | T1071 |
| R-008 | Chmod +x suivi d'exécution < 5s | High | T1222 |
| R-009 | Lecture /etc/shadow par proc non autorisé | Critical | T1003.008 |
| R-010 | Création .so dans répertoire world-writable | High | T1574.001 |

### Ajouter une règle personnalisée dans rules.toml

```toml
[[rules]]
id              = "R-CUSTOM-001"
description     = "Connexion vers le port Metasploit 4444"
severity        = "Critical"
event_type      = "Network"
logic           = "or"
action          = "BlockIp"
mitre_technique = "T1571"
score           = 60

[[rules.conditions]]
field    = "dst_port"
operator = "equals"
value    = "4444"
```

Puis recharger sans redémarrage :
```bash
edr rules-reload
```

---

## Tests

```bash
# Tests unitaires rapides
cargo nextest run -p edr-agent

# Avec rapport de couverture (llvm-cov)
cargo llvm-cov nextest --html --output-dir coverage/

# Audit des dépendances
cargo audit

# Linting
cargo clippy -- -D warnings
```

### Tests d'intégration (nécessite un système Linux)

```bash
# Simulation d'exécution depuis /tmp (déclenchement R-001)
cp /usr/bin/ls /tmp/evil && /tmp/evil

# Simulation lecture /etc/shadow (déclenchement R-009)
cat /etc/shadow

# Vérification des alertes générées
edr alerts --severity medium --last 1
```

---

## Livrables

- [x] Code source complet (ce dépôt)
- [x] Documentation Rustdoc — `cargo doc --open`
- [x] README d'installation et d'utilisation
- [x] Suite de tests unitaires (`src/tests.rs`)
- [x] Fichiers de configuration (`edr.toml`, `rules.toml`)
- [ ] Rapport de projet (PDF) — à rédiger
- [ ] Présentation PPTX — à préparer

---

## Sécurité de l'agent

- S'exécuter avec les capabilities minimales (`CAP_BPF`, `CAP_PERFMON`)
- Permissions des fichiers de config : `640 root:root`
- Aucun secret dans les logs
- `cargo audit` avant chaque livraison

## Licence

Projet pédagogique — usage interne uniquement.
