//! Runs the `dns_netstack` example and checks that its DNS checks pass.

use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn dns_netstack_passes_its_checks() -> TestResult {
    let child = Command::new(env!("CARGO_BIN_EXE_dns_netstack"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let output = timeout(Duration::from_secs(30), child.wait_with_output()).await??;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "dns_netstack failed: {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );
    assert!(stdout.lines().any(|line| line == "CHECKS PASS"), "{stdout}");
    assert!(
        stdout.contains("CHECK udp A printer.lan 10.0.0.7 PASS"),
        "{stdout}"
    );
    assert!(
        stdout.contains("CHECK reverse 198.18.0.1 -> app.example PASS"),
        "{stdout}"
    );
    assert!(stdout.contains("CHECK tcp A api.example"), "{stdout}");
    assert!(
        stdout.contains("CHECK tcp 10.53.0.53:80 refused"),
        "{stdout}"
    );
    Ok(())
}
