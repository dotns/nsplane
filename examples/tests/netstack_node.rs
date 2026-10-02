//! Two `netstack_node` processes over loopback UDP: one serves echo, the other checks it
//! through the tunnel and writes a status file.

use std::net::UdpSocket;
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nsplane::x25519::PublicKey;
use nsplane_examples::node::{encode_key, encode_public_key, generate_key};
use serde_json::Value;
use tokio::process::Command;
use tokio::time::timeout;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A loopback UDP port that was free a moment ago.
fn free_port() -> std::io::Result<u16> {
    Ok(UdpSocket::bind("127.0.0.1:0")?.local_addr()?.port())
}

#[tokio::test]
async fn netstack_nodes_echo_through_the_tunnel() -> TestResult {
    let server_key = generate_key();
    let client_key = generate_key();
    let server_pub = encode_public_key(&PublicKey::from(&server_key));
    let client_pub = encode_public_key(&PublicKey::from(&client_key));
    let server_port = free_port()?;
    let client_port = free_port()?;
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let status_file = std::env::temp_dir().join(format!(
        "nsplane-netstack-node-{}-{nanos}.json",
        std::process::id()
    ));

    let mut server = Command::new(env!("CARGO_BIN_EXE_netstack_node"))
        .args(["--private-key", &encode_key(&server_key.to_bytes())])
        .args(["--listen", &format!("127.0.0.1:{server_port}")])
        .args(["--address", "10.9.0.1/24", "--address", "fd09::1/64"])
        .args([
            "--peer",
            &format!("{client_pub},allowed-ips=10.9.0.2/32+fd09::2/128"),
        ])
        .args(["--echo-port", "7"])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;

    let client = Command::new(env!("CARGO_BIN_EXE_netstack_node"))
        .args(["--private-key", &encode_key(&client_key.to_bytes())])
        .args(["--listen", &format!("127.0.0.1:{client_port}")])
        .args(["--address", "10.9.0.2/24", "--address", "fd09::2/64"])
        .args([
            "--peer",
            &format!(
                "{server_pub},endpoint=127.0.0.1:{server_port},allowed-ips=10.9.0.1/32+fd09::1/128,keepalive=1"
            ),
        ])
        .args(["--check", "tcp:10.9.0.1:7", "--check", "udp:[fd09::1]:7"])
        .args(["--check-timeout", "15", "--exit-after-checks"])
        .arg("--status-file")
        .arg(&status_file)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let output = timeout(Duration::from_secs(30), client.wait_with_output()).await??;
    server.kill().await?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "client failed: {}\n{stdout}",
        output.status
    );
    assert!(stdout.lines().any(|line| line == "CHECKS PASS"), "{stdout}");
    assert!(stdout.contains("CHECK tcp 10.9.0.1:7 PASS"), "{stdout}");
    assert!(stdout.contains("CHECK udp [fd09::1]:7 PASS"), "{stdout}");

    let status: Value = serde_json::from_slice(&std::fs::read(&status_file)?)?;
    let _ = std::fs::remove_file(&status_file);
    assert_eq!(status["public_key"], Value::from(client_pub));
    assert_eq!(
        status["listen"],
        Value::from(format!("127.0.0.1:{client_port}"))
    );
    assert!(status["mtu"].as_u64().is_some(), "{status}");
    assert!(status["drops"].is_object(), "{status}");
    assert!(status["extra"]["netstack"].is_object(), "{status}");
    let peers = status["peers"].as_array().ok_or("no peers array")?;
    assert_eq!(peers.len(), 1, "{status}");
    let peer = &peers[0];
    assert_eq!(peer["public_key"], Value::from(server_pub));
    assert_eq!(
        peer["endpoint"],
        Value::from(format!("127.0.0.1:{server_port}"))
    );
    assert!(peer["rx"].as_u64().unwrap_or(0) > 0, "{status}");
    assert!(peer["tx"].as_u64().unwrap_or(0) > 0, "{status}");
    assert!(peer["last_handshake_secs_ago"].is_u64(), "{status}");
    Ok(())
}
