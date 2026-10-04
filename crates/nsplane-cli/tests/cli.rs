#![allow(clippy::expect_used, reason = "integration test")]

//! Command-line parsing of the daemon binary.
#![cfg(unix)]

use std::process::Command;

/// Runs the daemon with `env` set; starting is expected to fail, but argument parsing
/// must succeed.
fn run_with_env(env: &[(&str, &str)]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_nsplane-cli"))
        .args(["nsplane-clitest"])
        .envs(env.iter().copied())
        .output()
        .expect("run nsplane-cli")
}

#[test]
fn boolean_environment_variables_accept_1() {
    for name in ["WG_SUDO", "WG_NO_OFFLOAD"] {
        for value in ["1", "true", "yes"] {
            // Adopting a descriptor that is not open makes startup fail whatever the
            // privileges: with CAP_NET_ADMIN a created device would keep the daemon running.
            let output = run_with_env(&[(name, value), ("WG_TUN_FD", "987654")]);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                !stderr.contains("invalid value"),
                "{name}={value} was rejected: {stderr}"
            );
            assert_ne!(
                output.status.code(),
                Some(2),
                "clap usage error for {name}={value}"
            );
        }
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
        "--tun-fd",
        "WG_TUN_FD",
        "--uapi-fd",
        "WG_UAPI_FD",
        "--crypto-workers",
        "WG_CRYPTO_WORKERS",
        "--no-offload",
        "WG_NO_OFFLOAD",
    ] {
        assert!(help.contains(flag), "--help does not list {flag}: {help}");
    }
    for removed in ["--disable-connected-udp", "--disable-multi-queue"] {
        assert!(!help.contains(removed), "--help still lists {removed}");
    }
}

#[test]
fn a_closed_fd_fails_startup() {
    // Never an open fd: far above any descriptor limit.
    let closed = i32::MAX.to_string();
    for (flag, env) in [("--tun-fd", "WG_TUN_FD"), ("--uapi-fd", "WG_UAPI_FD")] {
        let by_flag = Command::new(env!("CARGO_BIN_EXE_nsplane-cli"))
            .args([flag, &closed, "nsplane-clitest"])
            .output()
            .expect("run nsplane-cli");
        let by_env = run_with_env(&[(env, &closed)]);
        for output in [by_flag, by_env] {
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.code(), Some(1), "{flag}: {stderr}");
            assert!(
                stderr.contains(&format!("Invalid {flag} {closed}")),
                "{flag}: {stderr}"
            );
        }
    }
}
