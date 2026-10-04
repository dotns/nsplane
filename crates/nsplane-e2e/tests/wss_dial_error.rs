//! Upgrades refused with an HTTP response carry a `WssDialError` (status, headers and the
//! truncated body) in the dial error of `WssDialer` and `WssStreamClient`; a 401 is still
//! a rejection.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use nsplane::{LinkDialer as _, LinkState};
use nsplane_e2e::{TestResult, WAIT};
use nsplane_wss::{WssConfig, WssDialError, WssDialer, WssStreamClient, WssStreamLimits, WssTls};
use rustls::RootCertStore;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// The body of every refusal: longer than the kept part.
fn body() -> Vec<u8> {
    (b'a'..=b'z').cycle().take(2000).collect()
}

/// A relay answering every upgrade request with `status`, an `X-Reason` header and
/// [`body`].
async fn refusing(status: &'static str) -> TestResult<SocketAddr> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(refuse(tcp, status));
        }
    });
    Ok(addr)
}

/// Reads the request head, answers it in one write and waits for the client to close.
async fn refuse(mut tcp: TcpStream, status: &str) -> io::Result<()> {
    let mut head = Vec::new();
    let mut buf = [0; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = tcp.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        head.extend_from_slice(&buf[..n]);
    }
    let body = body();
    let mut response = format!(
        "HTTP/1.1 {status}\r\nX-Reason: token-expired\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(&body);
    tcp.write_all(&response).await?;
    while tcp.read(&mut buf).await? > 0 {}
    Ok(())
}

fn config(addr: SocketAddr) -> WssConfig {
    WssConfig::new(
        format!("ws://{addr}/wss-relay"),
        WssTls::Roots(RootCertStore::empty()),
    )
    .allow_plaintext(true)
    .backoff(Duration::from_millis(20), Duration::from_millis(50))
    .connect_timeout(Duration::from_secs(2))
}

/// The detail inside `err`, checked against the relay's answer with `status`.
fn check_detail(err: &io::Error, status: u16) -> TestResult {
    let detail = err
        .get_ref()
        .and_then(|e| e.downcast_ref::<WssDialError>())
        .ok_or_else(|| format!("no WssDialError in `{err}`"))?;
    assert_eq!(detail.status, status);
    assert!(
        detail
            .headers
            .iter()
            .any(|(name, value)| name == "x-reason" && value == "token-expired"),
        "{:?}",
        detail.headers
    );
    assert_eq!(detail.body, body()[..WssDialError::MAX_BODY]);
    assert_eq!(err.to_string(), detail.to_string());
    Ok(())
}

/// One direct dial of `dialer`, which must fail.
async fn dial_error(dialer: &WssDialer) -> TestResult<io::Error> {
    match timeout(WAIT, dialer.dial()).await? {
        Ok(_) => Err("the dial succeeded".into()),
        Err(err) => Ok(err),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unauthorized_carries_the_detail_and_still_rejects() -> TestResult {
    let addr = refusing("401 Unauthorized").await?;
    let dialer = WssDialer::new(config(addr))?;
    let stats = dialer.stats();
    let state = dialer.state();
    let err = dial_error(&dialer).await?;
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(err.to_string(), "wss upgrade rejected with HTTP 401");
    check_detail(&err, 401)?;
    assert_eq!(*state.borrow(), LinkState::Rejected(401));
    assert_eq!(stats.rejected_unauthorized(), 1);
    assert_eq!(stats.rejected_forbidden(), 0);
    assert_eq!(stats.connect_failures(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unavailable_carries_the_detail() -> TestResult {
    let addr = refusing("503 Service Unavailable").await?;
    let dialer = WssDialer::new(config(addr))?;
    let stats = dialer.stats();
    let state = dialer.state();
    let err = dial_error(&dialer).await?;
    assert_eq!(err.kind(), io::ErrorKind::Other);
    assert_eq!(
        err.to_string(),
        "wss connect failed: HTTP error: 503 Service Unavailable"
    );
    check_detail(&err, 503)?;
    assert_eq!(*state.borrow(), LinkState::Disconnected);
    assert_eq!(
        stats.rejected_unauthorized() + stats.rejected_forbidden(),
        0
    );
    assert_eq!(stats.connect_failures(), 1);
    Ok(())
}

/// Every open behind a refused session dial gets the detail, the waiters behind the dial
/// included.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_opens_carry_the_detail() -> TestResult {
    let addr = refusing("401 Unauthorized").await?;
    let client = WssStreamClient::new(config(addr), WssStreamLimits::default())?;
    let target: SocketAddr = "10.0.0.1:80".parse()?;
    let opens: Vec<_> = (0..3)
        .map(|_| {
            let client = client.clone();
            tokio::spawn(async move { client.open_tcp(target).await.map(drop) })
        })
        .collect();
    for open in opens {
        let err = timeout(WAIT, open)
            .await??
            .err()
            .ok_or("the open succeeded")?;
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        check_detail(&err, 401)?;
    }
    assert!(client.stats().rejected_unauthorized() >= 1);
    Ok(())
}
