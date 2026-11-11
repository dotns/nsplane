//! `serve_tcp` while the process is out of file descriptors.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

use std::fs::File;
use std::net::Ipv4Addr;
use std::time::Duration;

use nsplane_dns::{Record, Server, ServerConfig, StaticRecords};
use simple_dns::{CLASS, Name, Packet, Question, TYPE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn nofile_limit() -> libc::rlimit {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    #[allow(unsafe_code, reason = "getrlimit into an owned struct")]
    let result = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) };
    assert_eq!(result, 0);
    limit
}

fn set_nofile_limit(limit: &libc::rlimit) {
    #[allow(unsafe_code, reason = "setrlimit from an owned struct")]
    let result = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, limit) };
    assert_eq!(result, 0);
}

/// The highest open file descriptor number.
fn highest_fd() -> libc::rlim_t {
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .map(|entry| {
            let name = entry.unwrap().file_name();
            name.to_str().unwrap().parse().unwrap()
        })
        .max()
        .unwrap()
}

#[tokio::test]
async fn tcp_accept_survives_descriptor_exhaustion() {
    let mut records = StaticRecords::default();
    records.insert(Record::a("host.test", 300, Ipv4Addr::new(10, 0, 0, 7)));
    let server = Server::new(records, ServerConfig::default());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serving = tokio::spawn(async move { server.serve_tcp(listener).await });

    // Leave exactly one free descriptor, which the client's socket takes: the connection
    // completes in the listen queue and `accept` has no descriptor for it.
    let original = nofile_limit();
    set_nofile_limit(&libc::rlimit {
        rlim_cur: highest_fd() + 8,
        rlim_max: original.rlim_max,
    });
    let mut fillers = Vec::new();
    while let Ok(file) = File::open("/dev/null") {
        fillers.push(file);
    }
    fillers.pop();
    let mut stream = TcpStream::connect(addr).await.unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;
    let finished = serving.is_finished();
    drop(fillers);
    set_nofile_limit(&original);
    assert!(!finished, "serve_tcp returned: {:?}", serving.await);

    // With descriptors free again the waiting connection is accepted and answered.
    let mut packet = Packet::new_query(7);
    packet.questions.push(Question::new(
        Name::new_unchecked("host.test"),
        TYPE::A.into(),
        CLASS::IN.into(),
        false,
    ));
    let message = packet.build_bytes_vec().unwrap();
    let len = u16::try_from(message.len()).unwrap();
    stream.write_all(&len.to_be_bytes()).await.unwrap();
    stream.write_all(&message).await.unwrap();
    let read = async {
        let len = stream.read_u16().await.unwrap();
        let mut response = vec![0; usize::from(len)];
        stream.read_exact(&mut response).await.unwrap();
        response
    };
    let response = tokio::time::timeout(Duration::from_secs(5), read)
        .await
        .unwrap();
    assert_eq!(Packet::parse(&response).unwrap().id(), 7);
}
