//! Runs the `dns_policy` example and checks that its policy checks pass.

use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn dns_policy_passes_its_checks() -> TestResult {
    let child = Command::new(env!("CARGO_BIN_EXE_dns_policy"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let output = timeout(Duration::from_secs(30), child.wait_with_output()).await??;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "dns_policy failed: {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );
    assert!(stdout.lines().any(|line| line == "CHECKS PASS"), "{stdout}");
    assert!(
        stdout.contains("CHECK A www.example CNAME:printer.lan,10.0.0.7 PASS"),
        "{stdout}"
    );
    assert!(
        stdout.contains("CHECK A blocked.example 192.0.2.9 PASS"),
        "{stdout}"
    );
    Ok(())
}
