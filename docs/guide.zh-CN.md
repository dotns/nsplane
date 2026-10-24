# nsplane 使用指南

[English](guide.md)

本指南说明如何把 nsplane 嵌入应用：选哪些 crate、引擎如何组装，以及常见部署形态的完整代码。
内容对应 nsplane 0.17.0。

- 函数签名与契约：rustdoc（`cargo doc --workspace --no-deps --open`）。
- 设计：[architecture.md](architecture.md)；各 crate 的行为：[reference](reference/)；
  性能数据：[performance.md](performance.md)。
- 可运行的程序：[examples/README.md](../examples/README.md)。

## 目录

1. [nsplane 是什么](#1-nsplane-是什么)
2. [crate 一览与选择](#2-crate-一览与选择)
3. [添加依赖](#3-添加依赖)
4. [核心概念](#4-核心概念)
5. [快速上手：一个进程内的两个节点](#5-快速上手一个进程内的两个节点)
6. [基于 TUN 设备的客户端](#6-基于-tun-设备的客户端)
7. [移动端与宿主管理的设备](#7-移动端与宿主管理的设备)
8. [用户态节点：nsplane-netstack](#8-用户态节点nsplane-netstack)
9. [一个引擎同时接 TUN 和 netstack](#9-一个引擎同时接-tun-和-netstack)
10. [访问控制：nsplane-acl](#10-访问控制nsplane-acl)
11. [地址转换与 NAT：nsplane-nat](#11-地址转换与-natnsplane-nat)
12. [传输层：UDP、链路与 WebSocket over TLS](#12-传输层udp链路与-websocket-over-tls)
13. [多个本地身份](#13-多个本地身份)
14. [运行与运维](#14-运行与运维)
15. [平台与构建](#15-平台与构建)
16. [示例索引](#16-示例索引)

## 1. nsplane 是什么

nsplane 是用 Rust 编写的用户态 WireGuard<sup>®</sup> 数据面，以库的形式提供：配置、身份和策略由应用
负责，应用把通用输入（密钥、peer、allowed IPs、规则、标签）交给 nsplane。它不做控制面工作：没有协调
服务器、没有 DNS、没有产品模型。

提供的能力：

- WireGuard 协议（Noise IKpsk2 握手、会话、定时器、cookie），可与内核 WireGuard 和 wireguard-go
  互通；
- 引擎：在本地侧（TUN 设备、用户态 TCP/IP 栈、宿主回调桥或 channel）与一个或多个传输
  （UDP、消息链路、WebSocket over TLS）之间转发数据包；
- 数据路径上的包过滤器：基于标签的 ACL 与流闸门（flow gate）、IPv4/IPv6 转换、DNAT/SNAT 服务发布、
  到局域网的 NAT64；
- `wg` 配置协议（UAPI），`wg show` / `wg set` 可直接操作引擎；
- 批处理与分段卸载（Linux 和 Android 上 TUN 的 TSO/USO、UDP GSO/GRO），可选的加密 worker 池，
  可选的分片阶段。

没有安装的功能不在数据路径上：普通客户端不会为 ACL、NAT 或 netstack 付出任何开销。

## 2. crate 一览与选择

```text
nsplane-noise ─► nsplane-core ─► nsplane ─► nsplane-tun, nsplane-uapi ─► nsplane-cli
nsplane-packet ─► nsplane-core, nsplane
nsplane, nsplane-packet ─► nsplane-netstack
nsplane-core, nsplane-packet ─► nsplane-acl, nsplane-nat
nsplane ─► nsplane-nat, nsplane-wss
```

| crate | 用途 | 主要类型 |
|---|---|---|
| `nsplane` | 必选：tokio 引擎及其 I/O trait | `EngineBuilder`、`Engine`、`EngineHandle`、`Peer`、`UdpTransport`、`LinkTransport`、`Splitter`、`MergeSource`、`ChannelSource` / `ChannelSink`、`Event` |
| `nsplane-tun` | 以系统 TUN 设备作本地侧（Linux、Android、macOS、iOS，Windows 经 Wintun） | `Tun`、`TunSlot`（Android）、`host_tun`（iOS / 回调） |
| `nsplane-netstack` | 应用直接在隧道内建立 TCP/UDP 连接，无需 TUN 设备和 root | `NetStack`、`NetStackHandle`、`TcpConnection`、`UdpFlow`、`UdpSocket`、`FlowControl` |
| `nsplane-uapi` | 用 `wg show` / `wg set` 操作引擎（Unix socket，Windows 命名管道） | `Uapi`、`UapiListener` |
| `nsplane-acl` | 按 peer 标签、地址和端口做入站/出站访问控制；应用会话；有状态流闸门 | `AclEngine`、`AclFilter`、`FlowTracker`、`RuleSet`、`PeerLabelMap`、`gate::GateFilter` |
| `nsplane-nat` | IPv4 应用经 IPv6 peer 通信（RFC 7915）、发布本地服务、NAT64 到 IPv4 局域网、本地重定向与地址伪装 | `Translator`、`TranslationTable`、`PortMap`、`Conntrack`、`Nat64Lan`、`Redirect`、`Masquerade` |
| `nsplane-wss` | UDP 被封锁时，WireGuard over WebSocket over TLS | `WssDialer`、`WssServerTransport`、`WssAcceptor` |
| `nsplane-core` | 自己写驱动，或实现 `PacketFilter` / `PathPolicy`（二者已由 `nsplane` 重新导出；`Verdict` 在这里） | `Core`、`PacketFilter`、`PathPolicy`、`Verdict` |
| `nsplane-packet` | 在自定义过滤器、分流器或本地侧中使用包缓冲区与 IP 头视图 | `PacketBuf`、`IpPacket`、`SharedPacketPool`、`build::udp_packet` |
| `nsplane-noise` | 只用协议本身，I/O 自理 | `noise::Tunn` |
| `nsplane-cli` | 不是库：Linux 和 macOS 上的开发用守护进程，用 `wg` 配置 | — |

常见组合：

| 应用 | crate |
|---|---|
| 桌面或服务器 VPN 客户端 / 节点 | `nsplane`、`nsplane-tun`，可选 `nsplane-uapi` |
| Android / iOS VPN | `nsplane`、`nsplane-tun`（`TunSlot` / `host_tun`） |
| 嵌入应用的隧道、无 root（SDK、sidecar、测试工具） | `nsplane`、`nsplane-netstack` |
| 带访问控制的网关 | `nsplane`、`nsplane-tun`、`nsplane-acl` |
| 子网路由 / 纯 IPv6 网络 | `nsplane`、`nsplane-tun`、`nsplane-nat` |
| 位于封锁 UDP 的防火墙之后 | 再加 `nsplane-wss` |
| 虚拟机不经 TUN 设备访问 peer | `nsplane`、`nsplane-ether` |

## 3. 添加依赖

nsplane 通过 git 引用。固定 tag 或 commit 以保证构建可复现：

```toml
[dependencies]
nsplane = { git = "https://github.com/dotns/nsplane", tag = "v0.17.0" }
nsplane-tun = { git = "https://github.com/dotns/nsplane", tag = "v0.17.0" }
# 按需添加：
# nsplane-netstack, nsplane-uapi, nsplane-acl, nsplane-nat, nsplane-wss, nsplane-core,
# nsplane-ether, nsplane-dns
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

本地联调时用路径覆盖 git 源：

```toml
[patch."https://github.com/dotns/nsplane"]
nsplane = { path = "../nsplane/crates/nsplane" }
nsplane-tun = { path = "../nsplane/crates/nsplane-tun" }
```

要求：Rust 1.95 及以上（仓库固定 1.99.0）；`aws-lc-sys` 需要 C 编译器，x86_64 Windows 目标还需要
NASM。密钥类型是 `x25519_dalek` 的类型，由 `nsplane::x25519` 重新导出；生成密钥需添加
`rand_core = { version = "0.6", features = ["getrandom"] }`，再调用
`StaticSecret::random_from_rng(rand_core::OsRng)`。

## 4. 核心概念

```text
           本地侧                           引擎                          传输
 ┌──────────────────────────┐   ┌─────────────────────────┐   ┌──────────────────────┐
 │ PacketSource（来自宿主/   │──►│ 过滤器（出站）           │   │ UdpTransport         │
 │ 应用的包）                │   │ 密钥路由                 │──►│ LinkTransport (WSS)  │
 │                          │   │ 加密 ─► 路径策略         │   │ 自定义 Transport     │
 │ PacketSink（交给宿主/     │◄──│ 解密 ◄─ 过滤器（入站）   │◄──│                      │
 │ 应用的包）                │   │ 定时器、握手             │   │                      │
 └──────────────────────────┘   └─────────────────────────┘   └──────────────────────┘
       Tun / TunSlot / host_tun / NetStack / ChannelSource+ChannelSink / Splitter+MergeSource
```

- **引擎（Engine）**：`EngineBuilder::new(source, sink)`，加上私钥和至少一个传输，再 `build()`。
  引擎运行在当前 tokio runtime 上。`Engine::handle()` 返回可克隆的 `EngineHandle`，之后的所有变更都
  通过它；`Engine::wait()` 在引擎停止（`EngineHandle::shutdown()`）后返回。
- **本地侧**：任意 `PacketSource`（引擎要加密发出的 IP 包）与 `PacketSink`（引擎解密后的 IP 包，
  附带发送方 `PeerId`）。nsplane 自带 TUN 设备、用户态协议栈、宿主回调桥、channel 和组合器。
- **传输（Transport）**：`Transport` 以你指定的 `TransportId` 收发数据报。一个引擎可同时运行多个
  传输；每个 peer 的 `Path { transport, addr, ecn }` 指明通过哪个传输、哪个远端地址到达它。
- **Peer**：`Peer`（`PeerConfig` 的别名）包含公钥、allowed IPs（密钥路由）、可选预共享密钥、
  keepalive 与初始路径。`add_or_update_peer` 插入或更新；引擎为其分配 `PeerId`
  （`EngineHandle::peer_id(key)`），过滤器、sink 和统计都使用它。
- **漫游**：默认情况下 peer 的路径跟随来自新地址的已认证包（`StandardRoaming`）。
  `EngineBuilder::policy` 可安装其他 `PathPolicy`。
- **过滤器**：`EngineBuilder::filter(Box<dyn PacketFilter>)` 添加过滤器；过滤器按顺序作用于每个
  入站包（解密后）和出站包（路由前），返回 `Verdict`（放行，或带原因丢弃）。ACL 与 NAT 类型都是过滤器。
- **事件与统计**：`EngineHandle::subscribe()` 返回 `Event` 的 broadcast 接收端（握手、路径变化、
  会话过期、丢包、MTU、挂起/恢复）；计数器按需查询。

地址族由调用方决定：IPv4、IPv6 或双栈取决于传输的绑定地址、本地侧的地址以及 peer 的 allowed IPs。

## 5. 快速上手：一个进程内的两个节点

无需 root 和 TUN 设备：每个引擎的本地侧是用户态 TCP/IP 栈，传输是回环地址上的 UDP。节点 B 运行
TCP echo 服务，节点 A 经隧道连接它。（仓库中的 `udp_pair` 示例与此相同，另含 UDP 和统计输出。）

```rust
use std::net::SocketAddr;
use std::time::Duration;

use futures_util::StreamExt as _;
use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{AllowedIp, Ecn, Engine, EngineBuilder, Path, Peer, TransportId, UdpTransport};
use nsplane_netstack::{DEFAULT_MTU, NetStack, NetStackConfig, NetStackHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const UDP: TransportId = TransportId::new(0);

/// 一个节点：拥有 `addr` 的用户态 TCP/IP 栈，以及回环地址上的 UDP 传输。
fn node(key: StaticSecret, addr: AllowedIp) -> anyhow::Result<(Engine, NetStackHandle, SocketAddr)> {
    let (stack, handle) =
        NetStack::new(NetStackConfig::new(vec![(addr.addr, addr.cidr)], DEFAULT_MTU));
    let (source, sink) = stack.split();
    let udp = UdpTransport::bind(UDP, "127.0.0.1:0".parse()?)?;
    let outer = udp.local_addr();
    let engine = EngineBuilder::new(source, sink)
        .private_key(key)
        .transport(udp)
        .build()?;
    Ok((engine, handle, outer))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let key_a = StaticSecret::random_from_rng(rand_core::OsRng);
    let key_b = StaticSecret::random_from_rng(rand_core::OsRng);
    let (pub_a, pub_b) = (PublicKey::from(&key_a), PublicKey::from(&key_b));
    let (a, stack_a, _) = node(key_a, AllowedIp { addr: "10.0.0.1".parse()?, cidr: 24 })?;
    let (b, stack_b, outer_b) = node(key_b, AllowedIp { addr: "10.0.0.2".parse()?, cidr: 24 })?;

    // A 知道 B 的端点；B 从握手中得知 A 的端点。
    let mut peer_b = Peer::new(pub_b);
    peer_b.allowed_ips = vec![AllowedIp { addr: "10.0.0.2".parse()?, cidr: 32 }];
    peer_b.path = Some(Path { transport: UDP, addr: outer_b, ecn: Ecn::NotEct });
    a.handle().add_or_update_peer(peer_b).await?;
    let mut peer_a = Peer::new(pub_a);
    peer_a.allowed_ips = vec![AllowedIp { addr: "10.0.0.1".parse()?, cidr: 32 }];
    b.handle().add_or_update_peer(peer_a).await?;

    // B：在 10.0.0.2 的所有端口上提供 TCP echo。
    let mut incoming = stack_b.incoming_tcp();
    tokio::spawn(async move {
        while let Some(mut conn) = incoming.next().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n @ 1..) = conn.read(&mut buf).await {
                    if conn.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    // A：经隧道连接（第一个包触发握手）。
    let mut conn = tokio::time::timeout(
        Duration::from_secs(10),
        stack_a.connect_tcp("10.0.0.2:7".parse()?),
    )
    .await??;
    conn.write_all(b"hello").await?;
    let mut reply = [0u8; 5];
    conn.read_exact(&mut reply).await?;
    assert_eq!(&reply, b"hello");

    for engine in [a, b] {
        engine.handle().shutdown().await?;
        engine.wait().await?;
    }
    Ok(())
}
```

依赖：`nsplane`、`nsplane-netstack`、`tokio`（`macros`、`rt-multi-thread`、`io-util`、`time`）、
`futures-util`、`rand_core`（`getrandom`）、`anyhow`。

## 6. 基于 TUN 设备的客户端

典型 VPN 客户端：TUN 设备作本地侧，一个 UDP 传输，一个服务端 peer，可选地开启 UAPI 以便用 `wg`
查看和修改。需要 root 或 `CAP_NET_ADMIN`。

```rust ignore
use std::net::SocketAddr;

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{AllowedIp, Ecn, EngineBuilder, Path, Peer, StandardRoaming, TransportId, UdpTransport};
use nsplane_tun::Tun;
use nsplane_uapi::{TRANSPORT_ID, Uapi, UapiListener};

async fn client(key: StaticSecret, server_key: PublicKey, server: SocketAddr) -> anyhow::Result<()> {
    // `wg set listen-port` 会重新绑定 id 为 TRANSPORT_ID 的传输。
    const UDP: TransportId = TRANSPORT_ID;
    // 设备的地址和路由由 nsplane 之外配置，例如
    //   ip addr add 10.0.0.2/32 dev wg0 && ip link set wg0 up
    //   ip route add 10.0.0.0/24 dev wg0
    let tun = Tun::create("wg0")?;
    let name = tun.name()?;
    let (source, sink) = tun.split()?;
    let udp = UdpTransport::bind(UDP, "0.0.0.0:0".parse()?)?;
    let port = udp.local_addr().port();
    let engine = EngineBuilder::new(source, sink)
        .private_key(key)
        .transport(udp)
        .policy(Box::new(StandardRoaming))
        .build()?;

    let mut peer = Peer::new(server_key);
    peer.allowed_ips = vec![AllowedIp { addr: "10.0.0.0".parse()?, cidr: 24 }];
    peer.persistent_keepalive = Some(25);
    peer.path = Some(Path { transport: UDP, addr: server, ecn: Ecn::NotEct });
    engine.handle().add_or_update_peer(peer).await?;

    // 可选：通过 /var/run/wireguard/wg0.sock 使用 `wg show wg0` / `wg set wg0 ...`。
    let uapi = Uapi::with_listen_port(engine.handle(), port);
    let listener = UapiListener::bind(&name)?;
    tokio::spawn(async move { uapi.serve(listener).await });

    engine.wait().await?;
    Ok(())
}
```

说明：

- nsplane 不配置设备的地址、路由或 DNS，这些由宿主负责。
- `Tun::create` 在内核支持时开启 TSO/USO 卸载；
  `Tun::create_with(name, TunOptions::new().offload(false))` 可关闭。
  `UdpTransport::bind_with_offload(id, addr, false)` 对 GSO/GRO 同理。
- Linux 上调大 `net.core.rmem_max` / `wmem_max`（如 4194304）以获得完整的 socket 缓冲区。
- 服务端代码相同：使用固定监听地址（`0.0.0.0:51820`），peer 不设 `path`，端点从握手中学习。
- `Tun::from_fd` / `from_raw_fd(fd, mtu)` 接管其他进程创建的 TUN fd
  （参见 `nsplane-cli --tun-fd` 和 `fd_bridge` 示例）。

## 7. 移动端与宿主管理的设备

### Android：`TunSlot`

`VpnService.Builder.establish()` 每次重新配置都会返回新的 fd。`TunSlot` 让引擎持续运行，并在其下
替换 fd：

```rust ignore
use std::os::fd::OwnedFd;

use nsplane::EngineBuilder;
use nsplane_tun::TunSlot;

fn start(
    fd: OwnedFd,
    key: nsplane::x25519::StaticSecret,
    udp: nsplane::UdpTransport,
) -> anyhow::Result<(TunSlot, nsplane::Engine)> {
    let (slot, source, sink) = TunSlot::new(1280);
    slot.replace(fd)?; // 来自 VpnService.Builder.establish() 的 fd
    let engine = EngineBuilder::new(source, sink)
        .private_key(key)
        .transport(udp)
        .build()?;
    Ok((slot, engine))
}

fn reconfigure(slot: &TunSlot, new_fd: OwnedFd) -> std::io::Result<()> {
    // replace 返回后，旧 fd 上不会再有任何读写。
    slot.replace(new_fd)
}
```

`disable` / `enable` 在两次重新配置之间暂停 I/O，`clear` 释放 fd，`close` 结束该 slot。

### iOS 及其他回调式宿主：`host_tun`

`NEPacketTunnelFlow` 通过回调而非 fd 交付数据包：

```rust ignore
use std::sync::Arc;

use nsplane::EngineBuilder;
use nsplane_tun::{HOST_TUN_DEFAULT_CAPACITY, host_tun};

fn start(
    key: nsplane::x25519::StaticSecret,
    udp: nsplane::UdpTransport,
    write_packets: impl Fn(&[u8]) -> bool + Send + Sync + 'static,
) -> anyhow::Result<(nsplane_tun::HostTunInput, nsplane::Engine)> {
    let (input, source, sink) =
        host_tun(1280, HOST_TUN_DEFAULT_CAPACITY, Arc::new(write_packets));
    let engine = EngineBuilder::new(source, sink)
        .private_key(key)
        .transport(udp)
        .build()?;
    // 在 packetFlow.readPackets 回调中（任意线程）：
    //   input.push(&packet)  // 返回 Err(PushError::Full) 时该包被丢弃
    Ok((input, engine))
}
```

`write_packets` 在引擎任务上执行，不能阻塞（`writePackets` 本身不阻塞）；宿主无法再接收数据包时返回
`false`。`HostTunSource::set_mtu` 用于修改 MTU。

### 数据包 channel

宿主自己搬运数据包时（任意平台，或测试中），使用 channel：

```rust ignore
use nsplane::{ChannelSink, ChannelSource, EngineBuilder};

let (source, to_engine, mtu) = ChannelSource::new(1024, 1420);
let (sink, mut from_engine) = ChannelSink::new(1024);
let engine = EngineBuilder::new(source, sink).private_key(key).transport(udp).build()?;
// 宿主 -> 引擎：to_engine.send(PacketBuf::from_packet(&bytes)).await
// 引擎 -> 宿主：while let Some((peer, packet)) = from_engine.recv().await { packet.as_packet() }
// MTU 变化：    mtu.send(1280)
```

`pipe`、`pump`、`SwapSink` 和 `AbortSink` 分别用于进程内连接、运行中替换 sink、关闭时隔离 sink；
详见 rustdoc。

### 虚拟机的网络链路：nsplane-ether

通过 Unix socket 承载虚拟机以太网帧的 guest 运行时（QEMU `-netdev stream`、passt、libkrun）可以直接
作为引擎的本地侧：`spawn_port` 在该 socket 上运行一个 `nsplane-ether` 适配器，应答 guest 的 DHCP、
ARP 和邻居发现，并把它的 IP 数据包作为 packet source 和 sink 提供出来：

```rust ignore
use nsplane::{EngineBuilder, FragmentConfig};
use nsplane_ether::{DhcpConfig, EtherConfig, MacAddr, spawn_port, stream};

// guest 运行时连接到 `listener`（一个 tokio UnixListener）。
let (conn, _) = listener.accept().await?;
let (reader, writer) = stream::unix(conn);
let gateway: std::net::Ipv4Addr = "10.66.0.1".parse()?; // peer 的隧道地址
let config = EtherConfig {
    gateway_ipv4: Some(gateway),
    dhcp: Some(DhcpConfig {
        router: Some(gateway),
        dns: vec![gateway],
        mtu: Some(1420),
        ..DhcpConfig::new(gateway, "10.66.0.2".parse()?, 24) // guest 的隧道地址
    }),
    mtu: 1420, // 隧道 MTU
    ..EtherConfig::new(MacAddr([0x02, 0, 0, 0, 0, 1]))
};
let (source, sink, ether) = spawn_port(reader, writer, config);
let engine = EngineBuilder::new(source, sink)
    .private_key(key)
    .transport(udp)
    .fragmenter(FragmentConfig::default())
    .build()?;
// ether.stats()：适配器计数器；ether.guest_mac()：学习到的 guest MAC。
```

- **地址规划。** guest 通过 DHCP 租到自己的隧道地址和网关，网关通常就是 peer 自己的隧道地址。
  适配器只为网关地址应答 ARP；guest 发出的每个 IP 包都进入引擎，并发往 allowed IPs 包含其目的
  地址的 peer，因此 peer 的 allowed IPs 决定了 guest 能到达哪些网络。租约前缀内的其他地址对
  guest 而言是同链路地址且得不到 ARP 应答，因此隧道网络中网关以外的主机 guest 无法到达。IPv6
  可选：`EtherConfig::ipv6_prefix` 作为 /64 通告，guest 在其中自行选取地址。
- **MTU。** 链路 MTU 即隧道 MTU（1500 字节路径上 WireGuard 的 1420），写入租约、路由通告以及
  引擎读取的 source，guest 因而不会发送更大的包。仍然发出的大包由分片阶段处理：DF 置位的 IPv4
  回 ICMP Fragmentation Needed，未置 DF 的拆成分片，IPv6 回 `ICMPv6` Packet Too Big。
- **Masquerade。** 隧道只分配一个 IPv6 地址而不是 /64 时，在 source（`forward`）和 sink
  （`reverse`，例如放在 `MapSink` 中）外包一层 `nsplane_nat::Masquerade`，把 guest 来自通告前缀的
  flow 改写为该地址。IPv4 不需要，因为租约本身就是隧道地址。
- **访问控制。** peer 属于一个带出站规则的命名空间时，`AclFilter` 对两个方向都做判定：`rules`
  是 peer 可以向 guest 发起的 flow，`outbound` 是 guest 可以发起的 flow；已接受 flow 的回包放行。
  用 `store_namespace` 替换命名空间后，从下一个包起生效。

```rust ignore
use nsplane_acl::{AclEngine, AclFilter, Label, LabelSet, NamespaceMember, NamespacePolicy, PeerLabelMap};

let acl = Arc::new(AclEngine::new());
acl.store_namespace("vm", NamespacePolicy {
    members: vec![NamespaceMember { label: Label::from("remote"), addresses: vec![] }],
    rules: to_guest,           // Vec<Rule>：peer 可以向 guest 发起的 flow
    outbound: Some(from_guest), // Vec<OutboundRule>：guest 可以发起的 flow
    ..NamespacePolicy::default()
})?;
let labels = Arc::new(PeerLabelMap::new());
let filter = AclFilter::new(Arc::clone(&acl), Arc::clone(&labels));
// EngineBuilder::filter(Box::new(filter))；添加 peer 之后：
labels.insert(peer_id, LabelSet::new([Label::from("remote")]));
```

#### Firecracker：由监控程序持有的 TAP

Firecracker 只把 guest 接到宿主机的 TAP 设备上，并且自己持有该 TAP 的文件描述符。在 Linux 上，
适配器于是通过 `AF_PACKET` socket（`PacketSocket`，需要 `CAP_NET_RAW`）在 TAP 的宿主机一侧读写
guest 的帧，不需要网桥，也不需要第二个 TAP。`ensure_tap` 在监控程序启动前创建该 TAP（需要
`CAP_NET_ADMIN`）：持久化，指定的用户和组可以接入，关闭 IPv6、地址自动配置和 ARP，使宿主机内核
不介入 guest 的链路；返回的 `TapInterface` 被 drop 时删除它。已存在的接口按原样使用，并保留不动。

```rust ignore
use nsplane_ether::{PacketSocket, TapConfig, ensure_tap, spawn_port};

// 在 Firecracker 启动之前；它的配置里写明该 TAP：
// "network-interfaces": [{ "iface_id": "eth0", "host_dev_name": "fctap0" }]
let tap = ensure_tap(&TapConfig::new("fctap0").owner(firecracker_uid))?;
let (reader, writer) = PacketSocket::bind(tap.name())?.split();
let (source, sink, ether) = spawn_port(reader, writer, config); // `config` 同上
// ... 引擎同上；在引擎停止之前保留 `tap`。
```

- **Offload。** Firecracker 与 guest 协商校验和与分段 offload，因此一个帧可能带部分校验和，或者是
  一个大的 GSO 帧。reader 在适配器看到之前补全校验和，并把 GSO 帧拆成 guest 分段大小的帧；发往
  guest 的帧带完整的校验和。
- **生命周期。** packet socket 没有流结束：guest 关机或监控程序重启时传输保持打开，重启后的监控
  程序接入同一个持久化 TAP。停止 port 的方式是 drop 引擎；删除接口会让 reader 以 `ENETDOWN` 结束。
- **MTU。** 大于 TAP MTU（默认 1500）的发往 guest 的帧会被丢弃；租约中的隧道 MTU 应不大于它。

`vm_wireguard` 示例把这些组合在一起，策略放在可热加载的文件中。

## 8. 用户态节点：nsplane-netstack

`nsplane-netstack` 是一个 TCP/IP 协议栈（smoltcp 分支），既是引擎的本地侧，也是给应用使用的 API：
它拥有隧道内的地址，在这些地址上提供 TCP 和 UDP 端点，支持 IPv4 与 IPv6。无需 TUN 设备、root 或
宿主路由。

```rust ignore
let (stack, handle) = NetStack::new(NetStackConfig::new(
    vec![("10.0.0.1".parse()?, 24), ("fd00::1".parse()?, 64)],
    DEFAULT_MTU,
));
let (source, sink) = stack.split();
let engine = EngineBuilder::new(source, sink).private_key(key).transport(udp).build()?;
// `handle`（NetStackHandle，可 Clone）就是应用使用的 API。
```

### TCP 与 UDP

```rust ignore
use futures_util::StreamExt as _;
use nsplane_netstack::NetStackHandle;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// 服务端：所有发往本栈地址的入站连接都从这里到达；按端口筛选。
async fn tcp_server(stack: NetStackHandle) {
    let mut incoming = stack.incoming_tcp();
    while let Some(conn) = incoming.next().await {
        if conn.local_addr().port() != 80 {
            continue;
        }
        tokio::spawn(async move {
            let (mut rd, mut wr) = tokio::io::split(conn);
            let _ = tokio::io::copy(&mut rd, &mut wr).await;
        });
    }
}

// UDP 服务端：每个远端端点一个 UdpFlow。
async fn udp_server(stack: NetStackHandle) {
    let mut flows = stack.incoming_udp();
    while let Some(mut flow) = flows.next().await {
        tokio::spawn(async move {
            while let Some(datagram) = flow.recv().await {
                let _ = flow.send(&datagram).await;
            }
        });
    }
}

async fn clients(stack: &NetStackHandle) -> anyhow::Result<()> {
    // TcpConnection 实现了 AsyncRead + AsyncWrite。
    let mut tcp = stack.connect_tcp("10.0.0.2:80".parse()?).await?;
    tcp.write_all(b"GET / HTTP/1.0\r\n\r\n").await?;
    let mut body = Vec::new();
    tcp.read_to_end(&mut body).await?;

    // 未连接的 UDP socket。
    let mut udp = stack.bind_udp("0.0.0.0:0".parse()?).await?;
    udp.send_to(b"ping", "10.0.0.2:53".parse()?).await?;
    let (reply, from) = udp.recv_from().await?;

    // 已连接的 UDP socket。
    let connected = stack.connect_udp("10.0.0.2:53".parse()?).await?;
    connected.send(b"ping").await?;
    Ok(())
}
```

另外：`connect_tcp_from` / `connect_udp_from` 指定本地地址；`TcpConnection::abort` 发送 RST 并立即
释放 socket，`terminated()` 等待该释放完成；`UdpFlow::reply_handle()` 返回可克隆的 `UdpReply` 发送端；
`NetStackHandle::stats()` 返回丢包计数；`NetStackConfig::reassembly` 开启 IP 分片重组。

### 撤销单个 flow

在多个 flow 共享的栈上，`FlowControl` 可以立即结束某一个 flow，并报告其资源是否已释放。它独立于数据
句柄，即使连接已移交给其他任务也照样可用。

```rust ignore
use nsplane_netstack::RetirementOutcome;

let conn = stack.connect_tcp("10.0.0.2:80".parse()?).await?;
let control = conn.control(); // 可 Clone；UdpFlow、UdpReply、UdpSocket 上也有
let context = control.bind_context(42)?; // 可选，每个 flow 一次；42 是调用方自己的域
tokio::spawn(async move { use_connection(conn).await });

// 之后，例如调用方撤回该 flow 的许可时：
let receipt = control.revoke(); // 幂等，从不等待，不发送 FIN 或 RST
match receipt.wait().await {
    RetirementOutcome::Retired => {} // 状态已移除，排队中的输出已丢弃
    RetirementOutcome::Failed => {}  // 状态已移除，但某个上限已满：部分输出可能仍会发出
    RetirementOutcome::Unknown => {} // 协议栈先停止了
    _ => {}                          // non_exhaustive
}
```

- `revoke` 之后，该 flow 的所有句柄都返回 `ConnectionAborted`（`UdpFlow::recv` 返回 `None`），驱动的
  下一轮会移除该 flow 的 socket、队列和待发输出。其他 flow 和协议栈本身照常运行。
- `wait` 可安全取消，也可再次调用；`outcome()` 只查询、不等待。
- 保证范围仅限协议栈：已经交给引擎的包不在其内。
- `FlowContext`（`domain()`、`instance()`）是不透明标签，`instance` 来自进程级计数器，绝不重复分配；
  nsplane 从不解读它。同一五元组上的新连接是新的 flow，拥有新的 instance。
- `NetStackHandle::retired_drops()` 统计因 flow 被撤销而丢弃的包数。

### 透明终结

设置 `NetStackConfig::transparent` 后，协议栈成为发往其前缀内任意目的地址的 TCP 和 UDP 的端点，而不只是
自身地址的端点。被接受的连接或 flow 以被拨打的地址作为 `local_addr()`，并从该地址应答。哪些目的地址能
到达协议栈由它前面的组件决定（peer 的 allowed IPs、ACL、`Splitter`）；本例中客户端把所有流量都路由到
服务端。

在 `Admission::Decide` 下，每个新连接或 flow 都在 `incoming_pending` 上等待应用接受或拒绝；被拒绝的
连接收到 RST，被拒绝的 UDP flow 收到 ICMP 端口不可达，两者都来自被拨打的地址。`flow_events` 报告每个
决定。

```rust
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use futures_util::StreamExt as _;
use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{AllowedIp, Ecn, Engine, EngineBuilder, Path, Peer, TransportId, UdpTransport};
use nsplane_netstack::{
    Admission, DEFAULT_MTU, FlowEventReason, FlowEventsConfig, NetStack, NetStackConfig,
    NetStackHandle, TransparentConfig,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const UDP: TransportId = TransportId::new(0);
const WAIT: Duration = Duration::from_secs(10);
/// 服务端唯一接受的目的地址。
const ALLOWED: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 443);
/// 位于服务端前缀内，但会被拒绝。
const REJECTED: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)), 443);

/// 一个节点：按 `config` 构建的协议栈，加上回环地址上的 UDP 传输。
fn node(key: StaticSecret, config: NetStackConfig) -> anyhow::Result<(Engine, NetStackHandle, SocketAddr)> {
    let (stack, handle) = NetStack::new(config);
    let (source, sink) = stack.split();
    let udp = UdpTransport::bind(UDP, "127.0.0.1:0".parse()?)?;
    let outer = udp.local_addr();
    let engine = EngineBuilder::new(source, sink).private_key(key).transport(udp).build()?;
    Ok((engine, handle, outer))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let key_c = StaticSecret::random_from_rng(rand_core::OsRng);
    let key_s = StaticSecret::random_from_rng(rand_core::OsRng);
    let (pub_c, pub_s) = (PublicKey::from(&key_c), PublicKey::from(&key_s));

    // 客户端：位于 10.0.0.1 的普通协议栈。
    let client = NetStackConfig::new(vec![("10.0.0.1".parse()?, 32)], DEFAULT_MTU);
    let (c, stack_c, _) = node(key_c, client)?;
    // 服务端：拥有 10.0.0.2，并终结 192.0.2.0/24 内的所有地址，每个新连接或 flow
    // 都交由应用决定。
    let server = NetStackConfig {
        transparent: Some(TransparentConfig {
            prefixes: vec![("192.0.2.0".parse()?, 24)],
            admission: Admission::Decide { timeout: Duration::from_secs(5), max_pending: 256 },
            max_connections: Some(4096),
            events: Some(FlowEventsConfig::default()),
            ..Default::default()
        }),
        ..NetStackConfig::new(vec![("10.0.0.2".parse()?, 32)], DEFAULT_MTU)
    };
    let (s, stack_s, outer_s) = node(key_s, server)?;

    // 客户端把所有 IPv4 目的地址路由到服务端。
    let mut peer_s = Peer::new(pub_s);
    peer_s.allowed_ips = vec![AllowedIp { addr: Ipv4Addr::UNSPECIFIED.into(), cidr: 0 }];
    peer_s.path = Some(Path { transport: UDP, addr: outer_s, ecn: Ecn::NotEct });
    c.handle().add_or_update_peer(peer_s).await?;
    let mut peer_c = Peer::new(pub_c);
    peer_c.allowed_ips = vec![AllowedIp { addr: "10.0.0.1".parse()?, cidr: 32 }];
    s.handle().add_or_update_peer(peer_c).await?;

    // 服务端：按被拨打的地址做决定。
    let mut pending = stack_s.incoming_pending();
    tokio::spawn(async move {
        while let Some(flow) = pending.next().await {
            if flow.local_addr() == ALLOWED {
                flow.accept();
            } else {
                flow.reject(); // 直接丢弃 `flow` 同样是拒绝
            }
        }
    });
    // 服务端：被接受的连接从这里到达；告诉客户端它拨打的是哪个地址。
    let mut incoming = stack_s.incoming_tcp();
    tokio::spawn(async move {
        while let Some(mut conn) = incoming.next().await {
            let dialed = conn.local_addr().to_string();
            tokio::spawn(async move { conn.write_all(dialed.as_bytes()).await });
        }
    });

    // 接受：连接终结在服务端，服务端以 192.0.2.10 的身份应答。
    let mut conn = timeout(WAIT, stack_c.connect_tcp(ALLOWED)).await??;
    let mut dialed = String::new();
    conn.read_to_string(&mut dialed).await?;
    assert_eq!(dialed, ALLOWED.to_string());

    // 拒绝：SYN 收到来自 192.0.2.11 的 RST。
    let refused = timeout(WAIT, stack_c.connect_tcp(REJECTED)).await?;
    assert_eq!(refused.err().map(|e| e.kind()), Some(io::ErrorKind::ConnectionRefused));

    // 每个决定一个事件，按顺序到达。
    let mut events = stack_s.flow_events();
    for (dst, reason) in [(ALLOWED, FlowEventReason::Admitted), (REJECTED, FlowEventReason::Hook)] {
        let event = timeout(WAIT, events.next()).await?.expect("stack running");
        assert_eq!((event.dst, event.reason), (dst, reason));
    }
    let stats = stack_s.stats();
    assert_eq!((stats.accepted, stats.rejected_hook, stats.pending), (1, 1, 0));

    for engine in [c, s] {
        engine.handle().shutdown().await?;
        engine.wait().await?;
    }
    Ok(())
}
```

依赖：同[快速上手](#5-快速上手一个进程内的两个节点)。

- `Admission::Immediate`（默认）在到达时即接受；此时 `incoming_pending` 立即结束。使用 `Decide` 时，
  在 `timeout` 内没有得到决定的连接或 flow 会被拒绝（`rejected_timeout`），已持有 `max_pending` 个时
  新来的会立即被拒绝（`rejected_table_full`）。
- `max_connections` 限制协议栈的 TCP 连接数；超出后的 SYN 收到 RST（`rejected_connection_limit`）。
- 发往前缀之外目的地址的包被丢弃（计入 `rejected_prefix`，同时计入 `no_address`）。
- flow 事件有界、限速且可丢失：超出 `FlowEventsConfig` 的事件计入 `events_dropped`。不设置 `events`
  时不存在 channel。
- `connect_tcp`、`connect_udp` 和 `bind_udp` 仍然使用协议栈自身的地址。

## 9. 一个引擎同时接 TUN 和 netstack

`Splitter` 用闭包把每个解密后的包分发给多个 sink 之一；`MergeSource` 把多个 source 合并为一个。
下例中，发往 10.0.0.0/16 的包交给 TUN 设备，其余交给 netstack：

```rust ignore
use std::sync::Arc;

use nsplane::{EngineBuilder, MergeSource, PacketBuf, PacketSink, PeerId, Splitter};
use nsplane_netstack::{NetStack, NetStackConfig};
use nsplane_packet::IpPacket;

const TUN: usize = 0;
const STACK: usize = 1;

let (tun_source, tun_sink) = nsplane_tun::Tun::create("wg0")?.split()?;
let (stack, stack_handle) =
    NetStack::new(NetStackConfig::new(vec![("10.1.0.1".parse()?, 24)], 1420));
let (stack_source, stack_sink) = stack.split();

let splitter = Splitter::new(|_peer, packet: &PacketBuf| match IpPacket::parse(packet.as_packet()) {
    Ok(ip) if matches!(ip.dst(), std::net::IpAddr::V4(a) if a.octets()[..2] == [10, 0]) => TUN,
    Ok(_) => STACK,
    Err(_) => 2, // 不存在的 sink：计为 misrouted 并丢弃
})
.sink(tun_sink)
.sink(stack_sink);
let merge = MergeSource::new().source(tun_source).source(stack_source);
let engine = EngineBuilder::new(merge, splitter).private_key(key).transport(udp).build()?;
```

如需之后读取 `Splitter::misrouted()` 或 `stats()`，把它放进 `Arc`，再传入一个转发给它的小
`PacketSink` 包装（见 `hybrid` 示例）。`MapSink` / `MapSource` 可在一侧改写或丢弃包，无需完整的过滤器。

## 10. 访问控制：nsplane-acl

ACL 只有放行规则：只有规则允许的包才能通过。规则匹配发送方 peer 的**标签**（由你分配的不透明字符串）、
源和目的前缀以及协议/端口。策略原子安装，可随时重新加载；首次安装之前所有包都被丢弃（默认拒绝）。

```rust ignore
use std::sync::Arc;

use nsplane::{EngineBuilder, PeerId};
use nsplane_acl::{
    AclEngine, AclFilter, AclFilterConfig, FlowTracker, Label, LabelSet, PeerLabelMap, PortSet,
    ProtocolMatch, Rule, RuleSet,
};

fn rules() -> anyhow::Result<RuleSet> {
    let mut rule = Rule::new("ssh-from-ops", vec![ProtocolMatch::Tcp(PortSet::Ranges(vec![22..=22]))]);
    rule.labels = vec![Label::new("ops")];
    rule.destinations = vec!["10.0.0.1/32".parse()?];
    Ok(RuleSet::new([rule])?)
}

let acl = Arc::new(AclEngine::new());
let labels = Arc::new(PeerLabelMap::new());
let config = AclFilterConfig { stateful_replies: true, ..AclFilterConfig::default() };
let filter = AclFilter::with_config(Arc::clone(&acl), Arc::clone(&labels), config);
let tracker = FlowTracker::new(4096); // 可选：已放行流量的逐 flow 计数

let engine = EngineBuilder::new(source, sink)
    .private_key(key)
    .transport(udp)
    .filter(Box::new(filter.clone()))
    .filter(Box::new(tracker.clone()))
    .build()?;
let handle = engine.handle();
handle.add_or_update_peer(nsplane::Peer::new(ops_key)).await?;
let id: PeerId = handle.peer_id(ops_key).await?.expect("just added");
labels.insert(id, LabelSet::new([Label::new("ops")]));
acl.install(rules()?); // 再次调用即重新加载
```

- `Rule` 与 `RuleSet` 可从 JSON 反序列化（serde），例如
  [examples/policies/acl_gateway.json](../examples/policies/acl_gateway.json)。
- `stateful_replies` 放行本侧发起的连接的回包。
- `AclFilter::stats()` 和 `FlowTracker` 提供计数；`AclEngine::evaluate` 不需要包即可判定一个 flow。
- 静态规则之外：按来源划分的**命名空间**（`store_namespace`）、命名空间之间的定向**授权**
  （`store_grant`）、出站规则，以及用于应用会话的短期**临时放行（pinhole）**（`open_pinhole`，
  `PinholeGuard` 被 drop 时关闭）——见 `app_session` 示例和
  [nsplane-acl 参考文档](reference/nsplane-acl.md#namespaces)。
- `gate::GateFilter` 是按 peer 区分的有状态流闸门（准入、保持、超时、把包转交应用）；见
  [nsplane-acl 参考文档](reference/nsplane-acl.md)。

## 11. 地址转换与 NAT：nsplane-nat

所有 NAT 类型要么是包过滤器（`EngineBuilder::filter`），要么包装本地侧。

### IPv4 应用经 IPv6 peer 通信：`Translator`

`Translator`（RFC 7915）让本地 IPv4 流量到达以 IPv6 寻址的 peer，依据每个 peer 的显式地址映射（EAM）
以及 peer 背后的 LAN 前缀。映射表在 peer 拿到 id 后构建，并可通过 `Translator::store` 在线替换：

```rust ignore
use nsplane_nat::{LanPrefix, PeerMapping, SelfMapping, TranslationTable, Translator};

fn table(gw: PeerId, other: PeerId) -> anyhow::Result<TranslationTable> {
    Ok(TranslationTable::builder()
        .self_mapping(SelfMapping { eam4: "192.168.100.1".parse()?, eam6: "fd00::1".parse()? })
        .peer(gw, PeerMapping {
            peer6: "fd00::2".parse()?,
            eam6: "fd00::2".parse()?,
            local6: None,
            eam4: Some("192.168.100.2".parse()?),
        })
        // `gw` 后面是默认路由，`other` 后面是一个更具体的 LAN
        .lan(LanPrefix { lan4: ("0.0.0.0".parse()?, 0), lan6: ("fd64:1::".parse()?, 96), peer: Some(gw) })
        .lan(LanPrefix { lan4: ("10.1.0.0".parse()?, 16), lan6: ("fd64:2::".parse()?, 96), peer: Some(other) })
        .nested_lans() // 0.15.0：允许前缀嵌套，最长前缀优先
        .build()?)
}
```

不调用 `nested_lans()` 时，LAN 前缀必须互不重叠（默认的严格模式）。调用后，地址归属包含它的最长前缀，
且精确地址（本节点 `eam4`、每个 `eam4` 和 `peer6_eam4`）优先于任何前缀。

若要在引擎持有过滤器的同时保留一个用于 `store` 的句柄，用 `Arc` 加一个转发过滤器共享它
（`Verdict` 来自 `nsplane-core`）：

```rust ignore
use nsplane_core::{PacketFilter, Verdict};

struct Shared(Arc<Translator>);

impl PacketFilter for Shared {
    fn inbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        self.0.inbound(peer, packet)
    }
    fn outbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        self.0.outbound(peer, packet)
    }
}

let translator = Arc::new(Translator::new(TranslationTable::default()));
let builder = builder.filter(Box::new(Shared(Arc::clone(&translator))));
// ... build、添加 peer 之后：
translator.store(table(gw, other)?);
```

### 发布本地服务：`PortMap`

从面向隧道的地址 DNAT/SNAT 到本地服务，可限定只对部分 peer 开放：

```rust ignore
use nsplane_nat::{Conntrack, ConntrackConfig, PortMap, PortMapProtocol, PortMapRule};

let map = PortMap::with_conntrack(Vec::new(), Conntrack::new(ConntrackConfig::default()))?;
map.set_rules(vec![PortMapRule {
    protocol: PortMapProtocol::Tcp,
    listen: "10.0.0.1:8080".parse()?, // peer 连接的地址
    target: "127.0.0.1:80".parse()?,  // 本地服务
    peers: Some(vec![web_peer]),       // None：所有 peer
}])?;
```

### IPv6 peer 访问 IPv4 局域网：`Nat64Lan`

网关包装其本地侧，让 IPv6 peer 通过有状态 NAT64 访问 IPv4 局域网：

```rust ignore
use nsplane_nat::{LanRoute, LanRoutes, Nat64Lan, Nat64LanConfig, Nat64LanSink, Nat64LanSource};

let route = LanRoute::new(
    ("fd64:a::".parse()?, 96),      // peer 使用的 IPv6 前缀
    ("192.168.1.0".parse()?, 24),   // 真实局域网
    "192.168.1.250".parse()?,       // 局域网上的 SNAT 源地址（需路由进 TUN）
)?;
let nat = Arc::new(Nat64Lan::new(LanRoutes::new(vec![route]), Nat64LanConfig::default()));
let engine = EngineBuilder::new(
    Nat64LanSource::new(tun_source, Arc::clone(&nat)),
    Nat64LanSink::new(tun_sink, Arc::clone(&nat)),
)
.private_key(key)
.transport(udp)
.build()?;
```

`Nat64LanConfig::nested_routes` 允许路由的 IPv4 前缀嵌套（最长优先）。另有两个本地侧类型：`Redirect`
把本地应用发往某服务地址的 IPv4 TCP/UDP flow 转到调用方为每个 flow 选定的端点（DNAT，并对回包做反向
SNAT）；`Masquerade` 是针对路由进来的 LAN 流量的有状态 IPv6 源 NAPT。详见 rustdoc。

## 12. 传输层：UDP、链路与 WebSocket over TLS

- `UdpTransport::bind(id, addr)`：默认选择。`with_side_channel(classify, capacity)` 把非 WireGuard
  数据报（例如同端口上的自有发现协议）分流到 `SideSender` / 接收端；`set_path_mtu_discovery` 开启
  PMTU 上报。
- `LinkTransport::new(id, peer_addr, dialer, LinkConfig)`：在你的 `LinkDialer` 建立（并重建）的消息
  链路上传输数据报；该链路就是一条路径，`peer_addr` 是 peer 的 `Path` 用来指代它的地址。
- 自定义：为其他任何载体实现 `Transport`（含批量方法）。
- 可同时运行多个传输，各有自己的 `TransportId`；`EngineHandle::add_transport`、`remove_transport`、
  `replace_transport` 可在运行中修改。

### WebSocket over TLS：nsplane-wss

客户端：`WssDialer` 是一个 `LinkDialer`，因此一个 WSS 连接即成为一个传输。TLS 信任由调用方提供
（没有内置根证书）：

```rust ignore
use nsplane::{LinkConfig, TransportId};
use nsplane_wss::{WssConfig, WssDialer, WssTls};

const WSS: TransportId = TransportId::new(1);
let config = WssConfig::new("wss://relay.example.net/wg", WssTls::Roots(roots));
let dialer = WssDialer::new(config)?;
let state = dialer.state(); // 在 into_transport 之前取出 state/stats/events
let transport = dialer.into_transport(WSS, "192.0.2.10:443".parse()?, LinkConfig::default());
// builder.transport(transport)；经它到达的 peer 使用 Path { transport: WSS, addr: 192.0.2.10:443, .. }
```

`WssConfig` 还可设置额外请求头、`BearerProvider`（每次拨号获取 `Authorization: Bearer` 令牌）、
keepalive、退避，以及测试用的 `allow_plaintext`（允许 `ws://`）。

服务端：由嵌入方运行自己的 HTTP 服务器、完成认证和升级，再把每个 WebSocket 交给
`WssServerTransport` 的 `WssAcceptor`：

```rust ignore
use nsplane_wss::{WssAcceptor, WssServerConfig, WssServerTransport};

let (transport, acceptor) = WssServerTransport::new(TransportId::new(1), WssServerConfig::default());
// builder.transport(transport)

async fn on_upgrade<S>(acceptor: &WssAcceptor, stream: S) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let ws = tokio_tungstenite::accept_async_with_config(stream, Some(WssAcceptor::ws_config())).await?;
    let session = acceptor.accept(ws)?; // 会话地址为 session.addr()
    Ok(())
}
```

`WssStreamClient` / `WssStreamServer`（多路复用的 TCP/UDP 流）已弃用，请改用经 `WssDialer` 的
WireGuard peer。

## 13. 多个本地身份

一个引擎可以在同一组传输上以多个 WireGuard 身份（私钥）应答：

```rust ignore
let id = handle.add_local_identity(second_key).await?.expect("a new key");
let mut peer = nsplane::Peer::new(peer_key);
peer.local_identity = Some(id); // 这个 peer 与 `second_key` 通信
handle.add_or_update_peer(peer).await?;
```

`add_local_identity_on` 把身份限定在部分传输上；`set_local_sources` 按源地址把出站包路由到某身份的
peer（按身份路由）；`peer_id_in` / `remove_peer_in` 在某个身份内寻址 peer。

## 14. 运行与运维

### 事件与统计

```rust ignore
use nsplane::Event;

let mut events = handle.subscribe().await?;
tokio::spawn(async move {
    while let Ok(event) = events.recv().await {
        match event {
            Event::HandshakeCompleted { peer, .. } => println!("up {}", peer.get()),
            Event::SessionExpired { peer, .. } => println!("down {}", peer.get()),
            _ => {}
        }
    }
});

for p in handle.peers().await? {
    println!("{:?} rx={} tx={} last_handshake={:?}", p.path, p.rx, p.tx, p.last_handshake);
}
let drops = handle.drop_counters().await?; // 原因 -> 次数
let queues = handle.queue_stats().await?;  // 队列高水位
let status = handle.status().await?;
```

接收端落后时会收到 `RecvError::Lagged`，之后可继续接收。其他计数：`transport_stats`、
`fragment_stats`、`path_mtu_stats`、`peer_mtus`、`unanswered_handshakes`。

### 运行中修改

全部在 `EngineHandle` 上，无需重启即生效：`set_private_key`、`add_or_update_peer` / `remove_peer`、
`set_allowed_ips`、`set_preshared_key`、`set_keepalive`、`set_path`、`force_handshake`、传输（见上）、
`inject_inbound` / `inject_outbound`（把包交给本地 sink，如同某 peer 发来；或交给某 peer，如同本地侧
发出；注入的包绕过过滤器）、`suspend` / `resume`（移动端后台：停止定时器和 I/O，保留状态）、`shutdown`。

### 调优

| 参数 | 默认值 | 何时调整 |
|---|---|---|
| `EngineBuilder::crypto_workers(n)` | 0（加密在引擎任务上） | 多线程 runtime 上有多个繁忙 peer 的 hub；`n` >= 2 |
| `EngineBuilder::queue_capacity(n)` | 1024 个包 | 队列高水位达到容量，且出现 `DROP_SINK_FULL` / `DROP_TRANSMIT_FULL` |
| `EngineBuilder::fragmenter(FragmentConfig::default())` | 关 | 路径 MTU 小于内层包、且 peer 需要 IP 分片 |
| TUN / UDP 卸载 | 支持时开启 | 仅调试时关闭 |
| `EngineBuilder::stats_interval` | 关 | 需要周期性的 `Event::PeerStats` |

参考数据（x86-64，0.11.0，真实 TUN，iperf3）：两个 nsplane 节点之间单条 TCP 流约 11 Gbit/s，
2 个加密 worker 时 14.5 Gbit/s，两个 netstack 节点之间 8.6 Gbit/s。详见
[performance.md](performance.md)。

## 15. 平台与构建

| 平台 | 本地侧 | 说明 |
|---|---|---|
| Linux | `Tun`（TSO/USO）、`Tun::from_fd`、netstack | TUN 需要 `CAP_NET_ADMIN` |
| Android | 基于 `VpnService` fd 的 `TunSlot` | |
| macOS | `Tun`（`utun`） | |
| iOS | 基于 `NEPacketTunnelFlow` 的 `host_tun` | |
| Windows | 经 Wintun 的 `Tun` | `wintun.dll` 放在可执行文件旁并以管理员运行；UAPI 走命名管道 |
| 任意 | netstack、channel | 无需特权 |

```bash
cargo build -p nsplane -p nsplane-tun -p nsplane-uapi --release
cargo build -p nsplane-cli --release      # 开发用守护进程，Linux 和 macOS
```

开发用守护进程在 TUN 设备上运行一个引擎，用 `wg` 配置：

```bash
sudo setcap cap_net_admin+epi target/release/nsplane-cli
target/release/nsplane-cli -v info wg0
wg setconf wg0 /path/to/wg0.conf
```

参数见 [README](../README.md#development-cli-linux-and-macos)。

## 16. 示例索引

均位于 `examples/`（`cargo run -p nsplane-examples --bin <name> -- --help`）：

| 示例 | 演示内容 | 需要 root |
|---|---|---|
| `udp_pair` | 两个基于 netstack 的引擎经回环 UDP 通信 | 否 |
| `tun_node` | 用 `wg` 管理的 TUN 节点 | 是 |
| `netstack_node` | 本地侧为 netstack 的节点 | 否 |
| `netstack_bench` | netstack 节点上的压测负载生成 | 否 |
| `hybrid` | 一个引擎同时接 TUN 和 netstack | 是 |
| `acl_gateway` | 使用可热加载 ACL 策略的节点 | 是 |
| `translate_node` | 本地 IPv4 访问纯 IPv6 peer | 是 |
| `port_map` | 通过 DNAT/SNAT 发布服务 | 是 |
| `subnet_gateway` | IPv6 peer 经 NAT64 访问 IPv4 局域网 | 是 |
| `fd_bridge` | 引擎运行在宿主通过 fd 或 channel 交来的 TUN 上 | 是 |
| `events_stats` | 事件、统计、丢包、挂起/恢复、MTU | 否 |
| `relay_server` | 同时也是 WireGuard 节点的单端口 relay | 否 |
| `relay_transport` | relay 发现与直连/relay 路径逐级切换 | 否 |
| `app_session` | 基于 ACL 命名空间和临时放行的应用会话 | 否 |
| `vm_wireguard` | 以虚拟机链路为本地侧，带 ACL 和 masquerade | 否 |

`relay_server` / `relay_transport` 中的 relay 是示例代码，不是对外发布的 API。
