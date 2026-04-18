//! Enrichissement des événements via `/proc/[pid]/`.
//!
//! Lit les métadonnées disponibles dans le pseudo-filesystem proc :
//! - `exe`     → lien symbolique vers le binaire réel
//! - `cmdline` → arguments complets null-séparés
//! - `cwd`     → répertoire de travail
//! - `status`  → PPid, Uid, Name
//! - `environ` → variables d'environnement (pour détecter LD_PRELOAD)

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tracing::debug;

/// Informations récupérées depuis /proc/[pid].
#[derive(Debug, Default)]
pub struct ProcInfo {
    pub exe:      Option<String>,
    pub cmdline:  Option<String>,
    pub cwd:      Option<String>,
    pub ppid:     Option<u32>,
    pub uid:      Option<u32>,
    pub username: Option<String>,
    pub environ:  HashMap<String, String>,
}

/// Service d'enrichissement proc.
///
/// Actuellement sans cache (les processus sont éphémères).
/// En production, un cache LRU avec TTL court serait pertinent.
pub struct ProcEnricher {
    uid_cache: std::sync::Mutex<HashMap<u32, String>>,
}

impl ProcEnricher {
    pub fn new() -> Self {
        Self {
            uid_cache: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Lit toutes les informations disponibles pour un PID.
    pub fn get_proc_info(&self, pid: u32) -> ProcInfo {
        let base = PathBuf::from(format!("/proc/{}", pid));

        if !base.exists() {
            return ProcInfo::default();
        }

        let exe = fs::read_link(base.join("exe"))
            .ok()
            .and_then(|p| p.to_str().map(String::from));

        let cmdline = fs::read(base.join("cmdline"))
            .ok()
            .map(|b| {
                String::from_utf8_lossy(&b)
                    .replace('\0', " ")
                    .trim()
                    .to_string()
            });

        let cwd = fs::read_link(base.join("cwd"))
            .ok()
            .and_then(|p| p.to_str().map(String::from));

        let (ppid, uid) = Self::parse_status(&base);

        let username = uid.and_then(|u| self.uid_to_username(u));

        let environ = Self::parse_environ(&base);

        ProcInfo { exe, cmdline, cwd, ppid, uid, username, environ }
    }

    /// Vérifie si LD_PRELOAD est défini dans l'environnement du processus.
    pub fn has_ld_preload(&self, pid: u32) -> bool {
        let base = PathBuf::from(format!("/proc/{}", pid));
        let environ = Self::parse_environ(&base);
        environ.contains_key("LD_PRELOAD")
    }

    /// Parse /proc/[pid]/status pour extraire PPid et Uid.
    fn parse_status(base: &PathBuf) -> (Option<u32>, Option<u32>) {
        let content = match fs::read_to_string(base.join("status")) {
            Ok(c) => c,
            Err(_) => return (None, None),
        };

        let mut ppid: Option<u32> = None;
        let mut uid:  Option<u32> = None;

        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("PPid:") {
                ppid = rest.trim().parse().ok();
            } else if let Some(rest) = line.strip_prefix("Uid:") {
                // Format : real effective saved fs
                uid = rest.split_whitespace().next().and_then(|s| s.parse().ok());
            }
            if ppid.is_some() && uid.is_some() {
                break;
            }
        }

        (ppid, uid)
    }

    /// Parse /proc/[pid]/environ en une HashMap<String, String>.
    fn parse_environ(base: &PathBuf) -> HashMap<String, String> {
        let mut map = HashMap::new();

        let bytes = match fs::read(base.join("environ")) {
            Ok(b) => b,
            Err(_) => return map,
        };

        for entry in bytes.split(|&b| b == 0) {
            if entry.is_empty() {
                continue;
            }
            let s = String::from_utf8_lossy(entry);
            if let Some(pos) = s.find('=') {
                let key   = s[..pos].to_string();
                let value = s[pos + 1..].to_string();
                map.insert(key, value);
            }
        }

        map
    }

    /// Résolution UID → nom d'utilisateur depuis /etc/passwd.
    fn uid_to_username(&self, uid: u32) -> Option<String> {
        {
            let cache = self.uid_cache.lock().ok()?;
            if let Some(name) = cache.get(&uid) {
                return Some(name.clone());
            }
        }

        let passwd = fs::read_to_string("/etc/passwd").ok()?;
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                if let Ok(u) = parts[2].parse::<u32>() {
                    if u == uid {
                        let name = parts[0].to_string();
                        let mut cache = self.uid_cache.lock().ok()?;
                        cache.insert(uid, name.clone());
                        return Some(name);
                    }
                }
            }
        }

        debug!("UID {} non résolu", uid);
        None
    }
}
