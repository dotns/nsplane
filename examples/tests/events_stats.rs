//! Runs the `events_stats` walkthrough and checks that every step passes.

use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn events_stats_steps_pass() -> TestResult {
    let child = Command::new(env!("CARGO_BIN_EXE_events_stats"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let output = timeout(Duration::from_secs(90), child.wait_with_output()).await??;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "events_stats failed: {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );
    assert!(stdout.lines().any(|line| line == "STEPS PASS"), "{stdout}");
    for name in ["handshake", "suspend", "resume", "mtu", "drop"] {
        let line = format!("STEP {name} PASS");
        assert!(stdout.lines().any(|l| l == line), "{stdout}");
    }
    assert!(stdout.contains("EVENT a mtu-changed mtu=1280"), "{stdout}");
    Ok(())
}
