//! Moteur d'analyse et de détection de l'EDR.
//!
//! Architecture :
//! - `RuleEngine`     : charge les règles TOML et les évalue sur chaque événement
//! - `Rule`           : structure d'une règle avec conditions et actions
//! - `Condition`      : prédicat évaluable sur un `EdrEvent`
//! - `ScoringEngine`  : accumule les scores et génère des alertes composites
//! - `SequenceEngine` : détecte les séquences temporelles A→B pour un même PID

pub mod scoring;
pub mod sequence;

use anyhow::Result;
use edr_common::{Alert, EdrEvent, ProcessEvent, FileEvent, NetworkEvent, Severity};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::str::FromStr;
use std::sync::Arc;
use chrono::Utc;
use tracing::{debug, info, warn};

use scoring::ScoringEngine;
use sequence::SequenceEngine;

// ─────────────────────────────────────────────
//  Types de règles TOML
// ─────────────────────────────────────────────

/// Type d'événement ciblé par une règle.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum EventType {
    Process,
    File,
    Network,
    Any,
}

/// Opérateur de comparaison dans une condition.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    StartsWith,
    Contains,
    Equals,
    Regex,
    Gt,
    Lt,
    NotEquals,
}

/// Combinaison logique des conditions.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogicOp {
    And,
    Or,
}

impl Default for LogicOp {
    fn default() -> Self { Self::And }
}

/// Condition atomique sur un champ de l'événement.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Condition {
    pub field:    String,
    pub operator: Operator,
    pub value:    String,
    #[serde(skip)]
    pub compiled_regex: Option<Arc<Regex>>,
}

/// Action prescrite par la règle.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum RuleAction {
    Alert,
    Kill,
    Quarantine,
    BlockIp,
}

/// Définition complète d'une règle.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    pub id:              String,
    pub description:     String,
    pub severity:        String,
    pub event_type:      EventType,
    pub conditions:      Vec<Condition>,
    #[serde(default)]
    pub logic:           LogicOp,
    pub action:          RuleAction,
    pub mitre_technique: Option<String>,
    /// Score de cette règle pour le système de scoring composite.
    #[serde(default = "default_score")]
    pub score:           u32,
}

fn default_score() -> u32 { 10 }

#[derive(Debug, Deserialize)]
struct RulesFile {
    rules: Vec<Rule>,
}

// ─────────────────────────────────────────────
//  Moteur de règles
// ─────────────────────────────────────────────

/// Moteur de détection principal.
pub struct RuleEngine {
    rules:           Vec<Rule>,
    scoring_engine:  ScoringEngine,
    sequence_engine: SequenceEngine,
}

impl RuleEngine {
    /// Charge les règles depuis un fichier TOML.
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let mut rules_file: RulesFile = toml::from_str(&content)?;

        // Compilation des regex
        for rule in &mut rules_file.rules {
            for cond in &mut rule.conditions {
                if matches!(cond.operator, Operator::Regex) {
                    match Regex::new(&cond.value) {
                        Ok(re) => cond.compiled_regex = Some(Arc::new(re)),
                        Err(e) => warn!("Regex invalide dans la règle {} : {}", rule.id, e),
                    }
                }
            }
        }

        info!("{} règles chargées depuis {}", rules_file.rules.len(), path);

        Ok(Self {
            rules:           rules_file.rules,
            scoring_engine:  ScoringEngine::new(100),
            sequence_engine: SequenceEngine::new(),
        })
    }

    /// Retourne le moteur avec les 10 règles par défaut intégrées.
    pub fn with_defaults() -> Self {
        let mut engine = Self {
            rules:           Vec::new(),
            scoring_engine:  ScoringEngine::new(100),
            sequence_engine: SequenceEngine::new(),
        };
        engine.rules = default_rules();
        info!("{} règles par défaut chargées", engine.rules.len());
        engine
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Évalue un événement contre toutes les règles.
    ///
    /// Retourne la liste des alertes générées (peut être vide).
    pub fn evaluate(&self, event: &EdrEvent) -> Vec<Alert> {
        let mut alerts = Vec::new();

        for rule in &self.rules {
            // Filtre par type d'événement
            if !event_matches_type(event, &rule.event_type) {
                continue;
            }

            // Évaluation des conditions
            if self.evaluate_rule(rule, event) {
                debug!(rule = %rule.id, pid = event.pid(), "Règle déclenchée");

                let alert = build_alert(rule, event);
                alerts.push(alert);
            }
        }

        // Alertes issues du scoring composite
        let score_alerts = self.scoring_engine.check(event.pid(), &alerts, event);
        alerts.extend(score_alerts);

        alerts
    }

    /// Évalue les conditions d'une règle contre un événement.
    fn evaluate_rule(&self, rule: &Rule, event: &EdrEvent) -> bool {
        if rule.conditions.is_empty() {
            return false;
        }

        let results: Vec<bool> = rule.conditions
            .iter()
            .map(|cond| self.evaluate_condition(cond, event))
            .collect();

        match rule.logic {
            LogicOp::And => results.iter().all(|&r| r),
            LogicOp::Or  => results.iter().any(|&r| r),
        }
    }

    /// Évalue une condition atomique.
    fn evaluate_condition(&self, cond: &Condition, event: &EdrEvent) -> bool {
        let field_value = extract_field(event, &cond.field);

        match &cond.operator {
            Operator::StartsWith => field_value.starts_with(&cond.value),
            Operator::Contains   => field_value.contains(&cond.value),
            Operator::Equals     => field_value == cond.value,
            Operator::NotEquals  => field_value != cond.value,
            Operator::Regex      => {
                if let Some(re) = &cond.compiled_regex {
                    re.is_match(&field_value)
                } else if let Ok(re) = Regex::new(&cond.value) {
                    re.is_match(&field_value)
                } else {
                    false
                }
            }
            Operator::Gt => {
                let lhs: f64 = field_value.parse().unwrap_or(0.0);
                let rhs: f64 = cond.value.parse().unwrap_or(0.0);
                lhs > rhs
            }
            Operator::Lt => {
                let lhs: f64 = field_value.parse().unwrap_or(0.0);
                let rhs: f64 = cond.value.parse().unwrap_or(0.0);
                lhs < rhs
            }
        }
    }
}

/// Extrait la valeur d'un champ nommé depuis un événement.
fn extract_field(event: &EdrEvent, field: &str) -> String {
    match event {
        EdrEvent::Process(e) => match field {
            "exe_path"  => e.exe_path.clone(),
            "args"      => e.args.clone(),
            "cwd"       => e.cwd.clone(),
            "username"  => e.username.clone(),
            "pid"       => e.pid.to_string(),
            "uid"       => e.uid.to_string(),
            _           => String::new(),
        },
        EdrEvent::File(e) => match field {
            "path"      => e.path.clone(),
            "operation" => format!("{:?}", e.operation),
            "pid"       => e.pid.to_string(),
            _           => String::new(),
        },
        EdrEvent::Network(e) => match field {
            "dst_ip"    => e.dst_ip.clone(),
            "src_ip"    => e.src_ip.clone(),
            "dst_port"  => e.dst_port.to_string(),
            "pid"       => e.pid.to_string(),
            _           => String::new(),
        },
        _ => String::new(),
    }
}

fn event_matches_type(event: &EdrEvent, rule_type: &EventType) -> bool {
    match rule_type {
        EventType::Any     => true,
        EventType::Process => matches!(event, EdrEvent::Process(_)),
        EventType::File    => matches!(event, EdrEvent::File(_)),
        EventType::Network => matches!(event, EdrEvent::Network(_)),
    }
}

fn build_alert(rule: &Rule, event: &EdrEvent) -> Alert {
    Alert {
        id:               None,
        rule_id:          rule.id.clone(),
        rule_description: rule.description.clone(),
        severity:         Severity::from_str(&rule.severity).unwrap_or(Severity::Medium),
        timestamp:        Utc::now(),
        pid:              event.pid(),
        mitre_technique:  rule.mitre_technique.clone(),
        event_json:       serde_json::to_string(event).unwrap_or_default(),
        action_taken:     Some(format!("{:?}", rule.action)),
    }
}

// ─────────────────────────────────────────────
//  Règles par défaut (§4.4.1 du cahier des charges)
// ─────────────────────────────────────────────

fn default_rules() -> Vec<Rule> {
    vec![
        // R-001 : Exécution depuis /tmp ou /dev/shm
        Rule {
            id:              "R-001".into(),
            description:     "Exécution d'un binaire depuis /tmp ou /dev/shm".into(),
            severity:        "High".into(),
            event_type:      EventType::Process,
            conditions:      vec![
                Condition {
                    field:           "exe_path".into(),
                    operator:        Operator::Regex,
                    value:           r"^(/tmp|/dev/shm)/".into(),
                    compiled_regex:  Some(Arc::new(Regex::new(r"^(/tmp|/dev/shm)/").unwrap())),
                },
            ],
            logic:           LogicOp::Or,
            action:          RuleAction::Alert,
            mitre_technique: Some("T1059".into()),
            score:           25,
        },

        // R-002 : Shell interactif spawné par un service
        Rule {
            id:              "R-002".into(),
            description:     "Shell interactif (bash/sh/zsh) spawné par un service non-interactif".into(),
            severity:        "Critical".into(),
            event_type:      EventType::Process,
            conditions:      vec![
                Condition {
                    field:           "exe_path".into(),
                    operator:        Operator::Regex,
                    value:           r"/(bash|sh|zsh|dash|fish)$".into(),
                    compiled_regex:  Some(Arc::new(Regex::new(r"/(bash|sh|zsh|dash|fish)$").unwrap())),
                },
                Condition {
                    field:           "uid".into(),
                    operator:        Operator::Gt,
                    value:           "0".into(),
                    compiled_regex:  None,
                },
            ],
            logic:           LogicOp::And,
            action:          RuleAction::Alert,
            mitre_technique: Some("T1059.004".into()),
            score:           40,
        },

        // R-003 : Modification de /etc/passwd ou /etc/shadow
        Rule {
            id:              "R-003".into(),
            description:     "Modification de /etc/passwd ou /etc/shadow".into(),
            severity:        "Critical".into(),
            event_type:      EventType::File,
            conditions:      vec![
                Condition {
                    field:           "path".into(),
                    operator:        Operator::Regex,
                    value:           r"^/etc/(passwd|shadow)$".into(),
                    compiled_regex:  Some(Arc::new(Regex::new(r"^/etc/(passwd|shadow)$").unwrap())),
                },
                Condition {
                    field:           "operation".into(),
                    operator:        Operator::Regex,
                    value:           r"Write|Create".into(),
                    compiled_regex:  Some(Arc::new(Regex::new(r"Write|Create").unwrap())),
                },
            ],
            logic:           LogicOp::And,
            action:          RuleAction::Alert,
            mitre_technique: Some("T1098".into()),
            score:           50,
        },

        // R-004 : Modification de crontab ou timer systemd
        Rule {
            id:              "R-004".into(),
            description:     "Création ou modification d'une crontab ou timer systemd".into(),
            severity:        "High".into(),
            event_type:      EventType::File,
            conditions:      vec![
                Condition {
                    field:           "path".into(),
                    operator:        Operator::Regex,
                    value:           r"(/var/spool/cron|/etc/cron\.|\.timer$)".into(),
                    compiled_regex:  Some(Arc::new(Regex::new(r"(/var/spool/cron|/etc/cron\.|\.timer$)").unwrap())),
                },
            ],
            logic:           LogicOp::Or,
            action:          RuleAction::Alert,
            mitre_technique: Some("T1053.003".into()),
            score:           30,
        },

        // R-005 : LD_PRELOAD (détecté via /proc/environ — traitement spécial)
        Rule {
            id:              "R-005".into(),
            description:     "Variable d'environnement LD_PRELOAD définie".into(),
            severity:        "High".into(),
            event_type:      EventType::Process,
            conditions:      vec![
                Condition {
                    field:           "args".into(),
                    operator:        Operator::Contains,
                    value:           "LD_PRELOAD".into(),
                    compiled_regex:  None,
                },
            ],
            logic:           LogicOp::Or,
            action:          RuleAction::Alert,
            mitre_technique: Some("T1574.006".into()),
            score:           35,
        },

        // R-006 : Scan réseau > 50 connexions en 10 secondes
        // (détecté par le NetworkScanDetector dans le collecteur réseau)
        Rule {
            id:              "R-006".into(),
            description:     "Processus effectuant > 50 connexions réseau en 10 secondes".into(),
            severity:        "Medium".into(),
            event_type:      EventType::Network,
            conditions:      vec![
                Condition {
                    field:           "dst_port".into(),
                    operator:        Operator::Gt,
                    value:           "0".into(),
                    compiled_regex:  None,
                },
            ],
            logic:           LogicOp::Or,
            action:          RuleAction::Alert,
            mitre_technique: Some("T1046".into()),
            score:           15,
        },

        // R-007 : Connexion réseau immédiatement après execve (< 2s)
        // Séquence détectée par le SequenceEngine
        Rule {
            id:              "R-007".into(),
            description:     "Connexion réseau établie immédiatement après execve (< 2s)".into(),
            severity:        "High".into(),
            event_type:      EventType::Network,
            conditions:      vec![
                Condition {
                    field:           "dst_port".into(),
                    operator:        Operator::Gt,
                    value:           "0".into(),
                    compiled_regex:  None,
                },
            ],
            logic:           LogicOp::Or,
            action:          RuleAction::Alert,
            mitre_technique: Some("T1071".into()),
            score:           30,
        },

        // R-008 : Chmod +x suivi d'exécution (< 5s)
        Rule {
            id:              "R-008".into(),
            description:     "Chmod +x sur un fichier suivi de son exécution (< 5s)".into(),
            severity:        "High".into(),
            event_type:      EventType::File,
            conditions:      vec![
                Condition {
                    field:           "operation".into(),
                    operator:        Operator::Equals,
                    value:           "Chmod".into(),
                    compiled_regex:  None,
                },
            ],
            logic:           LogicOp::Or,
            action:          RuleAction::Alert,
            mitre_technique: Some("T1222".into()),
            score:           30,
        },

        // R-009 : Lecture de /etc/shadow par processus non autorisé
        Rule {
            id:              "R-009".into(),
            description:     "Lecture de /etc/shadow par un processus non autorisé".into(),
            severity:        "Critical".into(),
            event_type:      EventType::File,
            conditions:      vec![
                Condition {
                    field:           "path".into(),
                    operator:        Operator::Equals,
                    value:           "/etc/shadow".into(),
                    compiled_regex:  None,
                },
                Condition {
                    field:           "operation".into(),
                    operator:        Operator::Regex,
                    value:           r"Open|Read".into(),
                    compiled_regex:  Some(Arc::new(Regex::new(r"Open|Read").unwrap())),
                },
            ],
            logic:           LogicOp::And,
            action:          RuleAction::Alert,
            mitre_technique: Some("T1003.008".into()),
            score:           50,
        },

        // R-010 : Création de .so dans un répertoire world-writable
        Rule {
            id:              "R-010".into(),
            description:     "Création d'un fichier .so dans un répertoire world-writable".into(),
            severity:        "High".into(),
            event_type:      EventType::File,
            conditions:      vec![
                Condition {
                    field:           "path".into(),
                    operator:        Operator::Regex,
                    value:           r"^/(tmp|dev/shm|var/tmp).*\.so(\.\d+)*$".into(),
                    compiled_regex:  Some(Arc::new(Regex::new(r"^/(tmp|dev/shm|var/tmp).*\.so(\.\d+)*$").unwrap())),
                },
                Condition {
                    field:           "operation".into(),
                    operator:        Operator::Equals,
                    value:           "Create".into(),
                    compiled_regex:  None,
                },
            ],
            logic:           LogicOp::And,
            action:          RuleAction::Alert,
            mitre_technique: Some("T1574.001".into()),
            score:           40,
        },
    ]
}
