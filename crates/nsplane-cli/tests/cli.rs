#![allow(clippy::expect_used, reason = "integration test")]

//! Command-line parsing of the daemon binary.
#![cfg(unix)]

use std::process::Command;

/// Runs the daemon with `env` set; device creation is expected to fail in
/// the test environment, but argument parsing must succeed.
fn run_with_env(env: &[(&str, &str)]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_nsplane-cli"))
        .args(["nsplane-clitest"])
        .envs(env.iter().copied())
        .output()
        .expect("run nsplane-cli")
}

#[test]
fn boolean_environment_variables_accept_1() {
    for value in ["1", "true", "yes"] {
        let output = run_with_env(&[("WG_SUDO", value)]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("invalid value"),
            "WG_SUDO={value} was rejected: {stderr}"
        );
        assert_ne!(
            output.status.code(),
            Some(2),
            "clap usage error for WG_SUDO={value}"
        );
    }
}

#[test]
fn help_lists_the_supported_flags() {
    let output = Command::new(env!("CARGO_BIN_EXE_nsplane-cli"))
        .arg("--help")
        .output()
        .expect("run nsplane-cli");
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    for flag in [
        "<INTERFACE_NAME>",
        "--threads",
        "WG_THREADS",
        "--verbosity",
        "WG_LOG_LEVEL",
        "--disable-drop-privileges",
        "WG_SUDO",
    ] {
        assert!(help.contains(flag), "--help does not list {flag}: {help}");
    }
    for removed in [
        "--tun-fd",
        "--uapi-fd",
        "--disable-connected-udp",
        "--disable-multi-queue",
    ] {
        assert!(!help.contains(removed), "--help still lists {removed}");
    }
}
