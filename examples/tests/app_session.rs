//! Runs the `app_session` example (no TUN) and checks that every step passes.

use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn app_session_passes_every_step() -> TestResult {
    let child = Command::new(env!("CARGO_BIN_EXE_app_session"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let output = timeout(Duration::from_secs(120), child.wait_with_output()).await??;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "app_session failed: {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );
    assert!(stdout.lines().any(|line| line == "CHECKS PASS"), "{stdout}");
    let steps: Vec<&str> = stdout
        .lines()
        .filter(|line| line.starts_with("STEP "))
        .collect();
    for name in [
        "reuse",
        "not-permitted",
        "revoke",
        "session-only-peer",
        "cross-namespace",
    ] {
        let line = format!("STEP {name} PASS");
        assert!(steps.contains(&line.as_str()), "{stdout}");
    }
    assert!(steps.iter().all(|line| line.ends_with(" PASS")), "{stdout}");
    Ok(())
}
