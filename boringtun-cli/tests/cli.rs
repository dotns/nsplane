#![allow(clippy::expect_used, reason = "integration test")]

//! Command-line parsing of the daemon binary.
#![cfg(unix)]

use std::process::Command;

/// Runs the daemon in the foreground with `env` set; device creation is expected to fail in
/// the test environment, but argument parsing must succeed.
fn run_with_env(env: &[(&str, &str)]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_boringtun-cli"))
        .args(["--foreground", "--log", "/dev/null", "nstun-cli-test"])
        .envs(env.iter().copied())
        .output()
        .expect("run boringtun-cli")
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
