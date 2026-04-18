//! Moteur de scoring composite (EF-D04).
//!
//! Plusieurs règles de basse sévérité déclenchées pour le même PID
//! dans une fenêtre de temps génèrent une alerte de haute sévérité.

use edr_common::{Alert, EdrEvent, Severity};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use chrono::Utc;

/// Fenêtre d'accumulation des scores (5 minutes).
const SCORE_WINDOW: Duration = Duration::from_secs(300);

struct PidScore {
    total:      u32,
    last_event: Instant,
}

/// Moteur d'accumulation des scores par PID.
pub struct ScoringEngine {
    /// Seuil déclenchant une alerte composite.
    threshold: u32,
    scores:    std::sync::Mutex<HashMap<u32, PidScore>>,
}

impl ScoringEngine {
    pub fn new(threshold: u32) -> Self {
        Self {
            threshold,
            scores: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Met à jour le score d'un PID et retourne une alerte composite si le seuil est dépassé.
    pub fn check(&self, pid: u32, new_alerts: &[Alert], _event: &EdrEvent) -> Vec<Alert> {
        if new_alerts.is_empty() {
            return Vec::new();
        }

        let added_score: u32 = new_alerts
            .iter()
            .map(|a| match a.severity {
                Severity::Low      => 5,
                Severity::Medium   => 15,
                Severity::High     => 25,
                Severity::Critical => 50,
            })
            .sum();

        let mut scores = match self.scores.lock() {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let now = Instant::now();
        let entry = scores.entry(pid).or_insert(PidScore {
            total:      0,
            last_event: now,
        });

        // Reset si hors fenêtre
        if now.duration_since(entry.last_event) > SCORE_WINDOW {
            entry.total = 0;
        }

        entry.total      += added_score;
        entry.last_event  = now;

        if entry.total >= self.threshold {
            // Reset pour éviter les alertes répétées
            entry.total = 0;

            return vec![Alert {
                id:               None,
                rule_id:          "SCORE-COMPOSITE".into(),
                rule_description: format!(
                    "Score composite élevé pour PID {} (seuil {} dépassé)",
                    pid, self.threshold
                ),
                severity:         Severity::High,
                timestamp:        Utc::now(),
                pid,
                mitre_technique:  None,
                event_json:       String::new(),
                action_taken:     Some("Alert".into()),
            }];
        }

        Vec::new()
    }
}
