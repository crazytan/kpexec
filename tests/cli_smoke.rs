//! Smoke tests: every subcommand in the CLI design doc must parse, and the
//! sensitive maintenance commands must fail closed at the authorization gate.

use clap::Parser;
use kpexec::cli::{Cli, Command, DbCommand, EntryCommand};
use kpexec::commands;
use kpexec::error::{KpexecError, Result as KpexecResult};
use kpexec::status::KpexecStatus;
use kpexec::user_presence::UserPresence;

/// Parse an argv (excluding the program name) into a [`Cli`].
fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
    let mut full = vec!["kpexec"];
    full.extend_from_slice(args);
    Cli::try_parse_from(full)
}

#[test]
fn every_subcommand_parses() {
    let cases: &[&[&str]] = &[
        // run
        &["run", "--entry", "github", "--command", "pr-create"],
        &[
            "run",
            "--entry",
            "github",
            "--command",
            "pr-create",
            "--dry-run",
        ],
        &[
            "run",
            "--entry",
            "github",
            "--command",
            "pr-create",
            "--timeout",
            "10",
        ],
        &[
            "run",
            "--entry",
            "github",
            "--command",
            "pr-create",
            "--json",
        ],
        &[
            "run",
            "--entry",
            "github",
            "--command",
            "pr-create",
            "--",
            "--title",
            "Fix build",
            "--base",
            "main",
        ],
        // init
        &["init"],
        &["init", "--db", "/tmp/x.kdbx"],
        &["init", "--use-existing"],
        // doctor
        &["doctor"],
        // entry ...
        &["entry", "add"],
        &["entry", "add", "github"],
        &["entry", "add", "github", "--no-pin"],
        &["entry", "add", "github", "--secret-stdin"],
        &["entry", "add-command", "github"],
        &["entry", "rm-command", "github", "pr-create"],
        &["entry", "set-secret", "github"],
        &["entry", "edit", "github"],
        &["entry", "rm", "github"],
        &["entry", "list"],
        &["entry", "list", "--json"],
        &["entry", "show", "github"],
        &["entry", "show", "github", "--json"],
        &["entry", "repin", "github"],
        &["entry", "repin", "github", "pr-create"],
        // check
        &["check"],
        &["check", "--entry", "github"],
        // db
        &["db", "rotate-password"],
        &["db", "show-password"],
    ];

    for args in cases {
        let parsed = parse(args);
        assert!(parsed.is_ok(), "failed to parse {args:?}: {parsed:?}");
    }
}

#[test]
fn run_requires_entry_and_command() {
    // Missing --command is a parse error (the doc: "--command is required").
    assert!(parse(&["run", "--entry", "github"]).is_err());
    assert!(parse(&["run", "--command", "pr-create"]).is_err());
}

#[test]
fn run_trailing_args_after_double_dash_are_captured() {
    let cli = parse(&[
        "run",
        "--entry",
        "github",
        "--command",
        "pr-create",
        "--",
        "--title",
        "x",
    ])
    .unwrap();
    match cli.command {
        Command::Run(args) => {
            assert_eq!(args.entry, "github");
            assert_eq!(args.command, "pr-create");
            assert_eq!(args.trailing, vec!["--title", "x"]);
        }
        _ => panic!("expected run"),
    }
}

#[test]
fn unknown_subcommand_is_rejected() {
    assert!(parse(&["frobnicate"]).is_err());
}

#[test]
fn db_maintenance_commands_are_presence_gated_before_io() {
    struct Deny;
    impl UserPresence for Deny {
        fn authorize(&self, _reason: &str) -> KpexecResult<()> {
            Err(KpexecError::new(
                KpexecStatus::UserPresenceDenied,
                "test denial",
            ))
        }
    }

    // An injected denial proves these commands reach neither the real macOS
    // authentication sheet nor config, vault, or Keychain I/O in this test.
    let sensitive_args: &[&[&str]] = &[&["db", "rotate-password"], &["db", "show-password"]];
    for args in sensitive_args {
        let cli = parse(args).unwrap();
        let err = commands::dispatch_with_user_presence(cli.command, &Deny).unwrap_err();
        assert_eq!(
            err.status(),
            KpexecStatus::UserPresenceDenied,
            "expected user-presence denial for {args:?}"
        );
    }
}

#[test]
fn run_flags_parse_into_run_args() {
    // M4 implements `run`, so its real behavior is exercised end-to-end in
    // tests/run_path.rs against a temp vault + fake keychain. Here we only assert
    // the flag surface parses as intended — deterministic and touching neither
    // config nor the keychain (dispatching `run` would consult both).
    let cli = parse(&[
        "run",
        "--entry",
        "e",
        "--command",
        "c",
        "--json",
        "--dry-run",
        "--timeout",
        "42",
        "--",
        "trailing",
    ])
    .unwrap();
    match cli.command {
        Command::Run(args) => {
            assert_eq!(args.entry, "e");
            assert_eq!(args.command, "c");
            assert!(args.json);
            assert!(args.dry_run);
            assert_eq!(args.timeout, Some(42));
            assert_eq!(args.trailing, vec!["trailing"]);
        }
        other => panic!("expected run, got {other:?}"),
    }
}

#[test]
fn db_and_entry_subcommand_variants_map_correctly() {
    // A couple of structural sanity checks on the parsed tree.
    match parse(&["db", "show-password"]).unwrap().command {
        Command::Db(DbCommand::ShowPassword) => {}
        other => panic!("unexpected: {other:?}"),
    }
    match parse(&["entry", "rm-command", "e", "n"]).unwrap().command {
        Command::Entry(EntryCommand::RmCommand(a)) => {
            assert_eq!(a.id, "e");
            assert_eq!(a.name, "n");
        }
        other => panic!("unexpected: {other:?}"),
    }
}
