//! Runs the in-process `relay_transport` example on each carrier: every step must pass.

use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const STEPS: [&str; 7] = [
    "discovery",
    "relay-engine",
    "direct-first",
    "direct-checks",
    "block",
    "unblock",
    "plain-endpoint",
];

async fn steps_pass(carrier: &str, extra: &[&str]) -> TestResult {
    let child = Command::new(env!("CARGO_BIN_EXE_relay_transport"))
        .args(["--carrier", carrier])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let output = timeout(Duration::from_secs(90), child.wait_with_output()).await??;
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "relay_transport --carrier {carrier} failed: {}\n{stdout}",
        output.status
    );
    for step in STEPS.iter().chain(extra) {
        assert!(
            stdout
                .lines()
                .any(|line| line == format!("STEP {step} PASS")),
            "{carrier} {step}: {stdout}"
        );
    }
    assert!(stdout.lines().any(|line| line == "STEPS PASS"), "{stdout}");
    Ok(())
}

#[tokio::test]
async fn relay_transport_steps_pass() -> TestResult {
    steps_pass("udp", &[]).await
}

#[tokio::test]
async fn relay_transport_steps_pass_over_wss() -> TestResult {
    steps_pass("wss", &["wss-carrier"]).await
}
