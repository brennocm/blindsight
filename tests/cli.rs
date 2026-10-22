//! End-to-end tests of the `blindsight` binary.

use std::process::Command;

fn blindsight() -> Command {
    Command::new(env!("CARGO_BIN_EXE_blindsight"))
}

#[test]
fn version_prints_crate_version() {
    let out = blindsight().arg("version").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        stdout,
        format!("blindsight {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn unknown_command_is_a_usage_error() {
    let out = blindsight().arg("no-such-command").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}
