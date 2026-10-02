//! Runs the `udp_pair` quick start and checks that both echo checks pass.

use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn udp_pair_passes_its_checks() -> TestResult {
    let child = Command::new(env!("CARGO_BIN_EXE_udp_pair"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let output = timeout(Duration::from_secs(30), child.wait_with_output()).await??;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "udp_pair failed: {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );
    assert!(stdout.lines().any(|line| line == "CHECKS PASS"), "{stdout}");
    assert!(stdout.contains("CHECK tcp 10.0.0.2:7 PASS"), "{stdout}");
    assert!(stdout.contains("CHECK udp 10.0.0.2:7 PASS"), "{stdout}");
    assert!(stdout.contains("EVENT handshake"), "{stdout}");
    Ok(())
}
