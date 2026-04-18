//! Tests unitaires du moteur de règles EDR.
//!
//! Couvre : évaluation des conditions, règles par défaut,
//! scoring composite et extraction de champs.
//!
//! Lancer avec : cargo nextest run  ou  cargo test

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use edr_common::{
        EdrEvent, FileEvent, FileOperation, NetworkEvent, NetworkProtocol, ProcessEvent,
    };

    use crate::analyzer::RuleEngine;

    // ─────────────────────────────────────────
    //  Helpers de construction d'événements
    // ─────────────────────────────────────────

    fn make_process(exe: &str, uid: u32, args: &str) -> EdrEvent {
        EdrEvent::Process(ProcessEvent {
            pid:       1234,
            ppid:      1,
            uid,
            gid:       uid,
            timestamp: Utc::now(),
            exe_path:  exe.into(),
            args:      args.into(),
            cwd:       "/".into(),
            username:  "test".into(),
            sha256:    None,
        })
    }

    fn make_file(path: &str, op: FileOperation) -> EdrEvent {
        EdrEvent::File(FileEvent {
            pid:       999,
            timestamp: Utc::now(),
            path:      path.into(),
            operation: op,
            sha256:    None,
        })
    }

    fn make_network(dst_ip: &str, dst_port: u16) -> EdrEvent {
        EdrEvent::Network(NetworkEvent {
            pid:       5678,
            timestamp: Utc::now(),
            src_ip:    "192.168.1.10".into(),
            src_port:  54321,
            dst_ip:    dst_ip.into(),
            dst_port,
            protocol:  NetworkProtocol::Tcp,
        })
    }

    fn engine() -> RuleEngine {
        RuleEngine::with_defaults()
    }

    // ─────────────────────────────────────────
    //  R-001 : Exécution depuis /tmp
    // ─────────────────────────────────────────

    #[test]
    fn r001_execution_from_tmp_triggers() {
        let ev = make_process("/tmp/evil_binary", 0, "");
        let alerts = engine().evaluate(&ev);
        assert!(
            alerts.iter().any(|a| a.rule_id == "R-001"),
            "R-001 devrait être déclenchée pour /tmp/evil_binary"
        );
    }

    #[test]
    fn r001_execution_from_usr_bin_no_trigger() {
        let ev = make_process("/usr/bin/ls", 0, "-la");
        let alerts = engine().evaluate(&ev);
        assert!(
            !alerts.iter().any(|a| a.rule_id == "R-001"),
            "R-001 ne devrait pas être déclenchée pour /usr/bin/ls"
        );
    }

    #[test]
    fn r001_execution_from_dev_shm_triggers() {
        let ev = make_process("/dev/shm/payload", 1000, "");
        let alerts = engine().evaluate(&ev);
        assert!(alerts.iter().any(|a| a.rule_id == "R-001"));
    }

    // ─────────────────────────────────────────
    //  R-002 : Shell interactif
    // ─────────────────────────────────────────

    #[test]
    fn r002_bash_by_nonroot_triggers() {
        let ev = make_process("/bin/bash", 1000, "-i");
        let alerts = engine().evaluate(&ev);
        assert!(
            alerts.iter().any(|a| a.rule_id == "R-002"),
            "R-002 devrait être déclenchée pour bash par uid>0"
        );
    }

    #[test]
    fn r002_bash_by_root_no_trigger() {
        // uid=0 → condition uid > 0 non satisfaite
        let ev = make_process("/bin/bash", 0, "-i");
        let alerts = engine().evaluate(&ev);
        assert!(
            !alerts.iter().any(|a| a.rule_id == "R-002"),
            "R-002 ne devrait pas se déclencher pour root"
        );
    }

    // ─────────────────────────────────────────
    //  R-003 : Modification /etc/passwd
    // ─────────────────────────────────────────

    #[test]
    fn r003_write_passwd_triggers() {
        let ev = make_file("/etc/passwd", FileOperation::Write);
        let alerts = engine().evaluate(&ev);
        assert!(
            alerts.iter().any(|a| a.rule_id == "R-003"),
            "R-003 devrait être déclenchée pour écriture dans /etc/passwd"
        );
    }

    #[test]
    fn r003_write_shadow_triggers() {
        let ev = make_file("/etc/shadow", FileOperation::Write);
        let alerts = engine().evaluate(&ev);
        assert!(alerts.iter().any(|a| a.rule_id == "R-003"));
    }

    #[test]
    fn r003_read_passwd_no_trigger() {
        // Lecture seule ne déclenche pas R-003
        let ev = make_file("/etc/passwd", FileOperation::Read);
        let alerts = engine().evaluate(&ev);
        assert!(!alerts.iter().any(|a| a.rule_id == "R-003"));
    }

    // ─────────────────────────────────────────
    //  R-004 : Crontab
    // ─────────────────────────────────────────

    #[test]
    fn r004_crontab_write_triggers() {
        let ev = make_file("/var/spool/cron/crontabs/root", FileOperation::Write);
        let alerts = engine().evaluate(&ev);
        assert!(alerts.iter().any(|a| a.rule_id == "R-004"));
    }

    // ─────────────────────────────────────────
    //  R-005 : LD_PRELOAD
    // ─────────────────────────────────────────

    #[test]
    fn r005_ld_preload_in_args_triggers() {
        let ev = make_process("/usr/bin/env", 0, "LD_PRELOAD=/tmp/hook.so ./app");
        let alerts = engine().evaluate(&ev);
        assert!(alerts.iter().any(|a| a.rule_id == "R-005"));
    }

    // ─────────────────────────────────────────
    //  R-009 : Lecture /etc/shadow
    // ─────────────────────────────────────────

    #[test]
    fn r009_read_shadow_triggers() {
        let ev = make_file("/etc/shadow", FileOperation::Open);
        let alerts = engine().evaluate(&ev);
        assert!(
            alerts.iter().any(|a| a.rule_id == "R-009"),
            "R-009 devrait être déclenchée pour ouverture de /etc/shadow"
        );
    }

    // ─────────────────────────────────────────
    //  R-010 : Création .so dans /tmp
    // ─────────────────────────────────────────

    #[test]
    fn r010_so_in_tmp_triggers() {
        let ev = make_file("/tmp/libhook.so", FileOperation::Create);
        let alerts = engine().evaluate(&ev);
        assert!(alerts.iter().any(|a| a.rule_id == "R-010"));
    }

    #[test]
    fn r010_so_in_usr_lib_no_trigger() {
        let ev = make_file("/usr/lib/liblegit.so", FileOperation::Create);
        let alerts = engine().evaluate(&ev);
        assert!(!alerts.iter().any(|a| a.rule_id == "R-010"));
    }

    // ─────────────────────────────────────────
    //  Tests généraux
    // ─────────────────────────────────────────

    #[test]
    fn benign_event_no_alert() {
        let ev = make_process("/usr/bin/python3", 1000, "script.py");
        let alerts = engine().evaluate(&ev);
        // Seule R-002 pourrait se déclencher (bash/sh check), mais python3 ne correspond pas
        assert!(!alerts.iter().any(|a| a.rule_id == "R-002"));
        assert!(!alerts.iter().any(|a| a.rule_id == "R-001"));
    }

    #[test]
    fn rule_engine_has_ten_default_rules() {
        assert_eq!(engine().rule_count(), 10);
    }

    // ─────────────────────────────────────────
    //  Tests du module storage
    // ─────────────────────────────────────────

    mod storage_tests {
        use crate::storage::Database;
        use edr_common::{EdrEvent, ProcessEvent, Alert, Severity};
        use chrono::Utc;

        fn make_test_db() -> Database {
            let db = Database::open(":memory:").expect("DB en mémoire");
            db.migrate().expect("Migration");
            db
        }

        #[test]
        fn insert_and_query_event() {
            let db = make_test_db();
            let ev = EdrEvent::Process(ProcessEvent {
                pid:       42,
                ppid:      1,
                uid:       0,
                gid:       0,
                timestamp: Utc::now(),
                exe_path:  "/usr/bin/test".into(),
                args:      "".into(),
                cwd:       "/".into(),
                username:  "root".into(),
                sha256:    None,
            });
            let id = db.insert_event(&ev).expect("Insert event");
            assert!(id > 0);

            let stats = db.stats().expect("Stats");
            assert_eq!(stats.event_count, 1);
        }

        #[test]
        fn insert_and_query_alert() {
            let db = make_test_db();
            let alert = Alert {
                id:               None,
                rule_id:          "R-001".into(),
                rule_description: "Test alert".into(),
                severity:         Severity::High,
                timestamp:        Utc::now(),
                pid:              1234,
                mitre_technique:  Some("T1059".into()),
                event_json:       "{}".into(),
                action_taken:     Some("Alert".into()),
            };
            let id = db.insert_alert(&alert).expect("Insert alert");
            assert!(id > 0);

            let alerts = db.query_alerts(Some("high"), None, 10).expect("Query alerts");
            assert_eq!(alerts.len(), 1);
            assert_eq!(alerts[0].rule_id, "R-001");
        }

        #[test]
        fn severity_filter_works() {
            let db = make_test_db();

            let insert = |sev: Severity| {
                let a = Alert {
                    id: None,
                    rule_id: "TEST".into(),
                    rule_description: "test".into(),
                    severity: sev,
                    timestamp: Utc::now(),
                    pid: 1,
                    mitre_technique: None,
                    event_json: "{}".into(),
                    action_taken: None,
                };
                db.insert_alert(&a).unwrap();
            };

            insert(Severity::Low);
            insert(Severity::Medium);
            insert(Severity::High);
            insert(Severity::Critical);

            let high_plus = db.query_alerts(Some("high"), None, 100).unwrap();
            assert_eq!(high_plus.len(), 2, "Devrait retourner HIGH et CRITICAL uniquement");

            let all = db.query_alerts(Some("low"), None, 100).unwrap();
            assert_eq!(all.len(), 4);
        }
    }
}
