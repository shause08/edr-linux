//! Persistance SQLite des événements et alertes.

use anyhow::Result;
use rusqlite::{params, Connection};
use std::sync::Mutex;

use crate::events::{Alert, Event};

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous   = NORMAL;
        ")?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    pub fn migrate(&self) -> Result<()> {
        self.conn.lock().unwrap().execute_batch("
            CREATE TABLE IF NOT EXISTS events (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                kind       TEXT NOT NULL,
                summary    TEXT NOT NULL,
                data_json  TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now', 'localtime'))
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                rule       TEXT NOT NULL,
                severity   TEXT NOT NULL,
                message    TEXT NOT NULL,
                data_json  TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now', 'localtime'))
            );
        ")?;
        Ok(())
    }

    pub fn insert_event(&self, event: &Event) -> Result<()> {
        let json = serde_json::to_string(event)?;
        self.conn.lock().unwrap().execute(
            "INSERT INTO events (kind, summary, data_json) VALUES (?1, ?2, ?3)",
            params![event.kind(), event.summary(), json],
        )?;
        Ok(())
    }

    pub fn insert_alert(&self, alert: &Alert) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO alerts (rule, severity, message, data_json) VALUES (?1, ?2, ?3, ?4)",
            params![
                alert.rule,
                alert.severity.to_string(),
                alert.message,
                alert.event_json,
            ],
        )?;
        Ok(())
    }

    /// Retourne les dernières alertes : (rule, severity, message, timestamp)
    pub fn recent_alerts(&self, limit: usize) -> Result<Vec<(String, String, String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT rule, severity, message, created_at \
             FROM alerts ORDER BY id DESC LIMIT ?1"
        )?;
        let rows = stmt.query_map(params![limit], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?;
        rows.map(|r| r.map_err(|e| anyhow::anyhow!(e))).collect()
    }

    pub fn stats(&self) -> Result<(i64, i64)> {
        let conn = self.conn.lock().unwrap();
        let events: i64 = conn.query_row(
            "SELECT COUNT(*) FROM events", [], |r| r.get(0)
        )?;
        let alerts: i64 = conn.query_row(
            "SELECT COUNT(*) FROM alerts", [], |r| r.get(0)
        )?;
        Ok((events, alerts))
    }
}