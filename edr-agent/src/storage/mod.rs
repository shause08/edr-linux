//! Module de persistance SQLite de l'EDR.
//!
//! Schéma :
//! - `events`    : tous les événements collectés (processus, fichier, réseau)
//! - `alerts`    : alertes générées par le moteur de détection
//! - `actions`   : actions de réponse exécutées
//! - `rules_log` : journal des chargements/rechargements de règles

use anyhow::{Context, Result};
use edr_common::{Alert, EdrEvent, Severity};
use rusqlite::{params, Connection};
use std::sync::Mutex;
use tracing::info;

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    /// Ouvre (ou crée) la base de données SQLite.
    pub fn open(path: &str) -> Result<Self> {
        // Créer le répertoire parent si nécessaire
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)
                .context("Création du répertoire de la base de données")?;
        }

        let conn = Connection::open(path)
            .with_context(|| format!("Ouverture de la base SQLite : {}", path))?;

        // Optimisations SQLite
        conn.execute_batch("
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous   = NORMAL;
            PRAGMA cache_size    = -32000;
            PRAGMA temp_store    = MEMORY;
            PRAGMA foreign_keys  = ON;
        ")?;

        info!("Base de données ouverte : {}", path);

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Applique les migrations DDL.
    pub fn migrate(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute_batch("
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type  TEXT    NOT NULL,
                pid         INTEGER NOT NULL,
                timestamp   TEXT    NOT NULL,
                data_json   TEXT    NOT NULL,
                created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_events_pid       ON events(pid);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_type      ON events(event_type);

            CREATE TABLE IF NOT EXISTS alerts (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id          TEXT    NOT NULL,
                description      TEXT    NOT NULL,
                severity         TEXT    NOT NULL,
                pid              INTEGER NOT NULL,
                timestamp        TEXT    NOT NULL,
                mitre_technique  TEXT,
                event_json       TEXT    NOT NULL,
                action_taken     TEXT,
                created_at       TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_rule_id   ON alerts(rule_id);

            CREATE TABLE IF NOT EXISTS actions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id    INTEGER REFERENCES alerts(id),
                action_type TEXT    NOT NULL,
                target      TEXT,
                success     INTEGER NOT NULL DEFAULT 0,
                dry_run     INTEGER NOT NULL DEFAULT 0,
                reason      TEXT,
                timestamp   TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS rules_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                event       TEXT NOT NULL,
                rule_count  INTEGER,
                path        TEXT,
                timestamp   TEXT NOT NULL DEFAULT (datetime('now'))
            );
        ")?;

        info!("Migrations SQLite appliquées");
        Ok(())
    }

    // ─────────────────────────────────────────
    //  Événements
    // ─────────────────────────────────────────

    /// Insère un événement dans la base.
    pub fn insert_event(&self, event: &EdrEvent) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let json = serde_json::to_string(event)?;

        conn.execute(
            "INSERT INTO events (event_type, pid, timestamp, data_json)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                event.event_type_str(),
                event.pid(),
                event.timestamp().to_rfc3339(),
                json,
            ],
        )?;

        Ok(conn.last_insert_rowid())
    }

    /// Retourne les N derniers événements.
    pub fn recent_events(&self, limit: usize) -> Result<Vec<serde_json::Value>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, event_type, pid, timestamp, data_json
             FROM events
             ORDER BY id DESC
             LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![limit], |row| {
            Ok(serde_json::json!({
                "id":         row.get::<_, i64>(0)?,
                "event_type": row.get::<_, String>(1)?,
                "pid":        row.get::<_, i64>(2)?,
                "timestamp":  row.get::<_, String>(3)?,
                "data":       row.get::<_, String>(4)?,
            }))
        })?;

        rows.map(|r| r.map_err(|e| anyhow::anyhow!(e)))
            .collect()
    }

    // ─────────────────────────────────────────
    //  Alertes
    // ─────────────────────────────────────────

    /// Insère une alerte dans la base et retourne son ID.
    pub fn insert_alert(&self, alert: &Alert) -> Result<i64> {
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "INSERT INTO alerts
                (rule_id, description, severity, pid, timestamp,
                 mitre_technique, event_json, action_taken)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                alert.rule_id,
                alert.rule_description,
                alert.severity.to_string(),
                alert.pid,
                alert.timestamp.to_rfc3339(),
                alert.mitre_technique,
                alert.event_json,
                alert.action_taken,
            ],
        )?;

        Ok(conn.last_insert_rowid())
    }

    /// Retourne les alertes avec filtres optionnels.
    pub fn query_alerts(
        &self,
        min_severity: Option<&str>,
        since_hours: Option<u64>,
        limit: usize,
    ) -> Result<Vec<Alert>> {
        let conn = self.conn.lock().unwrap();

        let mut query = String::from(
            "SELECT rule_id, description, severity, pid, timestamp,
                    mitre_technique, event_json, action_taken, id
             FROM alerts WHERE 1=1"
        );

        let mut params_dyn: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(sev) = min_severity {
            query.push_str(" AND severity IN (");
            // Sévérités >= seuil
            let sevs = severities_gte(sev);
            for (i, s) in sevs.iter().enumerate() {
                if i > 0 { query.push(','); }
                query.push_str(&format!("?{}", params_dyn.len() + 1));
                params_dyn.push(Box::new(s.to_string()));
            }
            query.push(')');
        }

        if let Some(hours) = since_hours {
            query.push_str(&format!(
                " AND timestamp >= datetime('now', '-{} hours')",
                hours
            ));
        }

        query.push_str(&format!(" ORDER BY id DESC LIMIT {}", limit));

        let mut stmt = conn.prepare(&query)?;

        let rows = stmt.query_map(
            rusqlite::params_from_iter(params_dyn.iter().map(|b| b.as_ref())),
            |row| {
                Ok(Alert {
                    id:               Some(row.get::<_, i64>(8)?),
                    rule_id:          row.get(0)?,
                    rule_description: row.get(1)?,
                    severity:         row.get::<_, String>(2)?
                        .parse()
                        .unwrap_or(Severity::Medium),
                    pid:              row.get::<_, i64>(3)? as u32,
                    timestamp:        chrono::DateTime::parse_from_rfc3339(
                                          &row.get::<_, String>(4)?
                                      )
                                      .map(|dt| dt.with_timezone(&chrono::Utc))
                                      .unwrap_or_else(|_| chrono::Utc::now()),
                    mitre_technique:  row.get(5)?,
                    event_json:       row.get(6)?,
                    action_taken:     row.get(7)?,
                })
            },
        )?;

        rows.map(|r| r.map_err(|e| anyhow::anyhow!(e))).collect()
    }

    // ─────────────────────────────────────────
    //  Actions
    // ─────────────────────────────────────────

    /// Journalise une action de réponse.
    pub fn log_action(
        &self,
        alert_id: Option<i64>,
        action_type: &str,
        target: Option<&str>,
        success: bool,
        dry_run: bool,
        reason: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO actions (alert_id, action_type, target, success, dry_run, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                alert_id,
                action_type,
                target,
                success as i32,
                dry_run as i32,
                reason,
            ],
        )?;
        Ok(())
    }

    // ─────────────────────────────────────────
    //  Statistiques
    // ─────────────────────────────────────────

    pub fn stats(&self) -> Result<DbStats> {
        let conn = self.conn.lock().unwrap();

        let event_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM events", [], |r| r.get(0)
        )?;

        let alert_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM alerts", [], |r| r.get(0)
        )?;

        let critical_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL'", [], |r| r.get(0)
        )?;

        Ok(DbStats { event_count, alert_count, critical_count })
    }

    // ─────────────────────────────────────────
    //  Rotation / rétention
    // ─────────────────────────────────────────

    /// Supprime les événements plus vieux que `days` jours.
    pub fn rotate_events(&self, days: u32) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "DELETE FROM events WHERE created_at < datetime('now', ?1)",
            params![format!("-{} days", days)],
        )?;
        info!("{} événements anciens supprimés", n);
        Ok(n)
    }
}

#[derive(Debug)]
pub struct DbStats {
    pub event_count:    i64,
    pub alert_count:    i64,
    pub critical_count: i64,
}

/// Retourne les niveaux de sévérité >= le niveau donné.
fn severities_gte(min: &str) -> Vec<&'static str> {
    match min.to_lowercase().as_str() {
        "low"      => vec!["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        "medium"   => vec!["MEDIUM", "HIGH", "CRITICAL"],
        "high"     => vec!["HIGH", "CRITICAL"],
        "critical" => vec!["CRITICAL"],
        _          => vec!["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    }
}
