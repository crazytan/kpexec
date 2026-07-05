//! Milestone-zero spike 1: prove the `keepass` crate can create and modify a
//! KDBX4 vault that KeePassXC accepts, and read it back after KeePassXC
//! rewrites it — including kpexec's custom string fields.
//!
//! Usage:
//!   kdbx-roundtrip create <path>   create vault with a kpexec-shaped entry
//!   kdbx-roundtrip modify <path>   re-open, add a second entry, save again
//!   kdbx-roundtrip verify <path>   open and dump kpexec entries, check fields

use std::fs::File;
use std::process::exit;

use keepass::{config::DatabaseVersion, db::fields, Database, DatabaseKey};

const MASTER_PASSWORD: &str = "spike-master-password";
const SECRET: &str = "s3cr3t-EXAMPLE-token-1234";
const POLICY_JSON: &str = r#"{"schema":"kpexec.policy.v1","description":"spike entry","secret":{"field":"password","inject":{"type":"env","name":"GH_TOKEN"}},"commands":[{"name":"pr-list","exe":"/opt/homebrew/bin/gh","argv_prefix":["pr","list"]}],"output":{"max_stdout_bytes":200000,"max_stderr_bytes":50000}}"#;

fn key() -> DatabaseKey {
    DatabaseKey::new().with_password(MASTER_PASSWORD)
}

/// Save the database atomically: write to `<path>.tmp` in the same directory,
/// and rename over `<path>` only after `db.save()` returns Ok. A failed save
/// leaves the original vault untouched (the leg-4 UnsupportedVersion panic
/// previously truncated the vault to 0 bytes via File::create-then-save).
///
/// Also pin the in-memory version to KDBX 4.1 before saving: KeePassXC 2.7.x
/// writes KDBX 4.0, and `dump_kdbx4` in keepass 0.13 refuses anything but
/// KDB4(1), so every save must re-upgrade the version.
fn save_atomic(db: &mut Database, path: &str) {
    db.config.version = DatabaseVersion::KDB4(1);

    let tmp_path = format!("{path}.tmp");
    let result = {
        let mut tmp = File::create(&tmp_path).expect("create temp file");
        db.save(&mut tmp, key())
    };
    match result {
        Ok(()) => {
            std::fs::rename(&tmp_path, path).expect("rename temp over vault");
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path);
            panic!("save kdbx4 failed, original vault untouched: {e}");
        }
    }
}

fn create(path: &str) {
    let mut db = Database::new();
    let mut root = db.root_mut();
    let mut entry = root.add_entry();
    entry.set_unprotected(fields::TITLE, "GitHub Token");
    entry.set_unprotected(fields::USERNAME, "tan");
    entry.set_protected(fields::PASSWORD, SECRET);
    entry.set_unprotected("kpexec.id", "github");
    entry.set_unprotected("kpexec.policy.v1", POLICY_JSON);

    save_atomic(&mut db, path);
    println!("created {path} with entry kpexec.id=github");
}

fn modify(path: &str) {
    let mut db = {
        let mut file = File::open(path).expect("open file");
        Database::open(&mut file, key()).expect("open kdbx4")
    };
    let mut root = db.root_mut();
    let mut entry = root.add_entry();
    entry.set_unprotected(fields::TITLE, "Cloudflare Token");
    entry.set_protected(fields::PASSWORD, "another-EXAMPLE-secret");
    entry.set_unprotected("kpexec.id", "cloudflare");
    entry.set_unprotected("kpexec.policy.v1", POLICY_JSON);

    save_atomic(&mut db, path);
    println!("modified {path}: added entry kpexec.id=cloudflare");
}

fn verify(path: &str) {
    let mut file = File::open(path).expect("open file");
    let db = Database::open(&mut file, key()).expect("open kdbx4");

    let mut found_github = false;
    for entry in db.iter_all_entries() {
        let Some(id) = entry.get("kpexec.id") else {
            continue;
        };
        let title = entry.get_title().unwrap_or("<none>");
        let policy = entry.get("kpexec.policy.v1").unwrap_or("<missing>");
        let policy_ok = policy == POLICY_JSON;
        println!("entry kpexec.id={id} title={title:?} policy_intact={policy_ok}");
        if id == "github" {
            found_github = true;
            assert_eq!(entry.get_password(), Some(SECRET), "password survived");
            assert!(policy_ok, "policy JSON survived byte-for-byte");
        }
    }
    if !found_github {
        eprintln!("FAIL: entry kpexec.id=github not found");
        exit(1);
    }
    println!("verify OK");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match (args.get(1).map(String::as_str), args.get(2)) {
        (Some("create"), Some(path)) => create(path),
        (Some("modify"), Some(path)) => modify(path),
        (Some("verify"), Some(path)) => verify(path),
        _ => {
            eprintln!("usage: kdbx-roundtrip <create|modify|verify> <path>");
            exit(2);
        }
    }
}
