//! Runs the in-process `relay_transport` example: every step must pass.

use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn relay_transport_steps_pass() -> TestResult {
    let child = Command::new(env!("CARGO_BIN_EXE_relay_transport"))
        .args(["--carrier", "udp"])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let output = timeout(Duration::from_secs(90), child.wait_with_output()).await??;
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "relay_transport failed: {}\n{stdout}",
        output.status
    );
    for step in [
        "discovery",
        "relay-engine",
        "direct-first",
        "direct-checks",
        "block",
        "unblock",
        "plain-endpoint",
    ] {
        assert!(
            stdout
                .lines()
                .any(|line| line == format!("STEP {step} PASS")),
            "{step}: {stdout}"
        );
    }
    assert!(stdout.lines().any(|line| line == "STEPS PASS"), "{stdout}");
    Ok(())
}
