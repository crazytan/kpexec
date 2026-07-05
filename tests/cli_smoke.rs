//! Smoke tests: every subcommand in the CLI design doc must parse, and the
//! not-implemented stubs must fail through the structured error path.

use clap::Parser;
use kpexec::cli::{Cli, Command, DbCommand, EntryCommand};
use kpexec::commands;
use kpexec::status::KpexecStatus;

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
fn stubbed_commands_return_not_implemented_cleanly() {
    // Drive dispatch (not process spawn) for the vault-free stubs so we can
    // assert the structured status rather than just an exit code.
    let stub_args: &[&[&str]] = &[
        &["init"],
        &["check"],
        &["entry", "add", "github"],
        &["entry", "add-command", "github"],
        &["entry", "rm-command", "github", "pr-create"],
        &["entry", "set-secret", "github"],
        &["entry", "edit", "github"],
        &["entry", "rm", "github"],
        &["entry", "list"],
        &["entry", "show", "github"],
        &["entry", "repin", "github"],
        &["db", "rotate-password"],
        &["db", "show-password"],
    ];
    for args in stub_args {
        let cli = parse(args).unwrap();
        let err = commands::dispatch(cli.command).unwrap_err();
        assert_eq!(
            err.status(),
            KpexecStatus::NotImplemented,
            "expected not-implemented for {args:?}"
        );
        assert!(
            err.message().contains("milestone"),
            "message should name a milestone for {args:?}: {}",
            err.message()
        );
    }
}

#[test]
fn run_json_stub_emits_not_implemented_envelope() {
    // The run stub honors --json even before M4, returning the envelope shape.
    let cli = parse(&["run", "--entry", "e", "--command", "c", "--json"]).unwrap();
    // dispatch prints the envelope and returns an Outcome (not an Err) on the
    // --json path; we assert the exit code lands in the reserved band.
    let outcome = commands::dispatch(cli.command).unwrap();
    assert_eq!(
        outcome.exit_code(),
        KpexecStatus::NotImplemented.exit_code()
    );
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
