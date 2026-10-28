//! Fake routers on loopback addresses for the router protocols' tests
//! (design `direct` §12.2 "mapping"): [`FakePcp`] answers PCP and NAT-PMP
//! on `<ip>:5351` (crab_nat's fixed port), [`FakeIgd`] answers the SSDP
//! search and the UPnP-IGD description and control requests, one at a
//! time, over a port-mapping table of its own. Both log what they heard. Each test gives its fakes their own `127.0.0.N` (Linux and
//! Windows route all of `127/8` to loopback; macOS needs `lo0` aliases).
//! Built for this crate's tests and under the `test-support` feature only.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::AbortHandle;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// How a [`FakePcp`] answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcpMode {
    /// A PCP server (that also answers NAT-PMP): grants every mapping at
    /// `external`, for the lifetime asked but at most `max_lifetime`.
    Pcp {
        /// The router's external address.
        external: Ipv4Addr,
        /// The longest lifetime granted, in seconds.
        max_lifetime: u32,
    },
    /// A NAT-PMP-only router: a PCP request gets NAT-PMP's "unsupported
    /// version" answer, a NAT-PMP request is granted.
    NatPmpOnly {
        /// The router's external address.
        external: Ipv4Addr,
        /// The longest lifetime granted, in seconds.
        max_lifetime: u32,
    },
    /// Answers every PCP request with this result code (2: not
    /// authorized), every NAT-PMP one with "not authorized".
    Refuse(u8),
    /// Answers nothing.
    Silent,
}

/// What a [`FakePcp`] heard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcpHeard {
    /// A PCP MAP request (lifetime 0 deletes).
    Map {
        /// The lifetime asked, in seconds.
        lifetime: u32,
        /// The mapping nonce.
        nonce: [u32; 3],
        /// The client's internal port.
        internal_port: u16,
        /// The external port suggested (0: none).
        suggested_port: u16,
        /// The external address suggested (unspecified: none).
        suggested_ip: Ipv4Addr,
    },
    /// A NAT-PMP UDP mapping request (lifetime 0 deletes).
    NatPmpMap {
        /// The lifetime asked, in seconds.
        lifetime: u32,
        /// The client's internal port (0 with lifetime 0: every mapping).
        internal_port: u16,
        /// The external port suggested.
        external_port: u16,
    },
    /// A NAT-PMP external address request.
    NatPmpAddress,
    /// Anything else.
    Other,
}

struct PcpState {
    mode: PcpMode,
    heard: Vec<PcpHeard>,
}

/// A PCP and NAT-PMP router on `<ip>:5351`. Dropping it stops it.
pub struct FakePcp {
    ip: Ipv4Addr,
    state: Arc<Mutex<PcpState>>,
    task: AbortHandle,
}

impl Drop for FakePcp {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn u16_at(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

/// The answer to one datagram, and what it was.
fn answer_pcp(mode: PcpMode, req: &[u8]) -> (PcpHeard, Option<Vec<u8>>) {
    const EPOCH: u32 = 1234;
    match req.first() {
        Some(2) if req.len() >= 60 && req[1] == 1 => {
            let lifetime = u32_at(req, 4);
            let nonce = [u32_at(req, 24), u32_at(req, 28), u32_at(req, 32)];
            let internal_port = u16_at(req, 40);
            let suggested_port = u16_at(req, 42);
            let suggested_ip = Ipv4Addr::new(req[56], req[57], req[58], req[59]);
            let heard = PcpHeard::Map {
                lifetime,
                nonce,
                internal_port,
                suggested_port,
                suggested_ip,
            };
            let (result, granted, external) = match mode {
                PcpMode::Pcp {
                    external,
                    max_lifetime,
                } => (0_u8, lifetime.min(max_lifetime), external),
                PcpMode::NatPmpOnly { .. } => {
                    let mut out = vec![0, 0x81, 0, 1];
                    out.extend_from_slice(&EPOCH.to_be_bytes());
                    return (heard, Some(out));
                }
                PcpMode::Refuse(code) => (code, 0, Ipv4Addr::UNSPECIFIED),
                PcpMode::Silent => return (heard, None),
            };
            let mut out = vec![2, 0x81, 0, result];
            out.extend_from_slice(&granted.to_be_bytes());
            out.extend_from_slice(&EPOCH.to_be_bytes());
            out.extend_from_slice(&[0; 12]);
            out.extend_from_slice(&req[24..40]);
            out.extend_from_slice(&internal_port.to_be_bytes());
            let port = if suggested_port == 0 {
                internal_port
            } else {
                suggested_port
            };
            out.extend_from_slice(&port.to_be_bytes());
            out.extend_from_slice(&external.to_ipv6_mapped().octets());
            (heard, Some(out))
        }
        Some(0) if req.len() == 2 && req[1] == 0 => {
            let (result, external) = match mode {
                PcpMode::Pcp { external, .. } | PcpMode::NatPmpOnly { external, .. } => {
                    (0_u16, external)
                }
                PcpMode::Refuse(_) => (2, Ipv4Addr::UNSPECIFIED),
                PcpMode::Silent => return (PcpHeard::NatPmpAddress, None),
            };
            let mut out = vec![0, 0x80];
            out.extend_from_slice(&result.to_be_bytes());
            out.extend_from_slice(&EPOCH.to_be_bytes());
            out.extend_from_slice(&external.octets());
            (PcpHeard::NatPmpAddress, Some(out))
        }
        Some(0) if req.len() == 12 && req[1] == 1 => {
            let internal_port = u16_at(req, 4);
            let external_port = u16_at(req, 6);
            let lifetime = u32_at(req, 8);
            let heard = PcpHeard::NatPmpMap {
                lifetime,
                internal_port,
                external_port,
            };
            let (result, granted) = match mode {
                PcpMode::Pcp { max_lifetime, .. } | PcpMode::NatPmpOnly { max_lifetime, .. } => {
                    (0_u16, lifetime.min(max_lifetime))
                }
                PcpMode::Refuse(_) => (2, 0),
                PcpMode::Silent => return (heard, None),
            };
            let port = match (granted, external_port) {
                (0, _) => 0,
                (_, 0) => internal_port,
                (_, p) => p,
            };
            let mut out = vec![0, 0x81];
            out.extend_from_slice(&result.to_be_bytes());
            out.extend_from_slice(&EPOCH.to_be_bytes());
            out.extend_from_slice(&internal_port.to_be_bytes());
            out.extend_from_slice(&port.to_be_bytes());
            out.extend_from_slice(&granted.to_be_bytes());
            (heard, Some(out))
        }
        _ => (PcpHeard::Other, None),
    }
}

impl FakePcp {
    /// A router on `ip:5351` answering as `mode`, on the current runtime.
    ///
    /// # Errors
    ///
    /// The port could not be bound (`ip` is not a loopback address of this
    /// machine, or another test holds it).
    pub async fn start(ip: Ipv4Addr, mode: PcpMode) -> io::Result<Self> {
        let socket = UdpSocket::bind((ip, crab_nat::GATEWAY_PORT)).await?;
        let state = Arc::new(Mutex::new(PcpState {
            mode,
            heard: Vec::new(),
        }));
        let shared = Arc::clone(&state);
        let task = tokio::spawn(async move {
            let mut buf = [0_u8; 1100];
            loop {
                let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                    continue;
                };
                let reply = {
                    let mut state = lock(&shared);
                    let (heard, reply) = answer_pcp(state.mode, &buf[..n]);
                    state.heard.push(heard);
                    reply
                };
                if let Some(reply) = reply {
                    let _ = socket.send_to(&reply, from).await;
                }
            }
        });
        Ok(Self {
            ip,
            state,
            task: task.abort_handle(),
        })
    }

    /// Its address.
    #[must_use]
    pub fn ip(&self) -> Ipv4Addr {
        self.ip
    }

    /// Changes how it answers.
    pub fn set_mode(&self, mode: PcpMode) {
        lock(&self.state).mode = mode;
    }

    /// What it heard, in order.
    #[must_use]
    pub fn heard(&self) -> Vec<PcpHeard> {
        lock(&self.state).heard.clone()
    }
}

/// How a [`FakeIgd`] answers one control action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgdAnswer {
    /// Success.
    Ok,
    /// A SOAP fault with this UPnP error code (718 conflict, 725 only
    /// permanent leases, 606 not authorized, 714 no such entry).
    Fault(u16),
}

/// One mapping in a [`FakeIgd`]'s table (UDP unless `tcp`, wildcard remote
/// host).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgdMapping {
    /// `NewExternalPort`.
    pub external_port: u16,
    /// `NewProtocol` TCP rather than UDP.
    pub tcp: bool,
    /// `NewInternalClient`, as the router writes it.
    pub internal_client: String,
    /// `NewInternalPort`.
    pub internal_port: u16,
    /// `NewPortMappingDescription`.
    pub description: String,
}

impl IgdMapping {
    /// A UDP mapping of `external_port` to `client:internal_port` under
    /// `description`.
    #[must_use]
    pub fn udp(
        external_port: u16,
        client: Ipv4Addr,
        internal_port: u16,
        description: &str,
    ) -> Self {
        Self {
            external_port,
            tcp: false,
            internal_client: client.to_string(),
            internal_port,
            description: description.to_owned(),
        }
    }
}

/// How a [`FakeIgd`] behaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgdConfig {
    /// Whether it answers an SSDP search.
    pub answer_search: bool,
    /// `AddPortMapping`.
    pub add_port: IgdAnswer,
    /// `AddAnyPortMapping`: `None` leaves the action out of the service
    /// description.
    pub add_any_port: Option<IgdAnswer>,
    /// The port `AddAnyPortMapping` grants.
    pub any_port: u16,
    /// `DeletePortMapping`.
    pub delete: IgdAnswer,
    /// What `GetExternalIPAddress` answers.
    pub external: Ipv4Addr,
    /// The mappings in its table at start (another computer's, a crashed
    /// run's). An `AddPortMapping` it grants, or an `AddAnyPortMapping`,
    /// adds one; a `DeletePortMapping` it grants removes its port. An
    /// `AddPortMapping` of a port the table gives to another client or
    /// port is refused with 718, whatever `add_port` says.
    pub table: Vec<IgdMapping>,
    /// `GetGenericPortMappingEntry`: `Ok` answers the entry at the index,
    /// or 713 past the end; a fault answers every index with it.
    pub lookup: IgdAnswer,
    /// How long it takes to answer an `AddPortMapping`; it answers one
    /// control request at a time, so later requests wait behind it.
    pub add_delay: Duration,
}

impl IgdConfig {
    /// A router that answers the search and grants everything at
    /// `external`.
    #[must_use]
    pub fn granting(external: Ipv4Addr) -> Self {
        Self {
            answer_search: true,
            add_port: IgdAnswer::Ok,
            add_any_port: Some(IgdAnswer::Ok),
            any_port: 50_999,
            delete: IgdAnswer::Ok,
            external,
            table: Vec::new(),
            lookup: IgdAnswer::Ok,
            add_delay: Duration::ZERO,
        }
    }
}

/// What a [`FakeIgd`] heard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IgdHeard {
    /// An SSDP M-SEARCH datagram.
    Search,
    /// A GET of its device or service description.
    Describe,
    /// `AddPortMapping`.
    AddPort {
        /// `NewExternalPort`.
        external_port: u16,
        /// `NewInternalPort`.
        internal_port: u16,
        /// `NewLeaseDuration`.
        lease: u32,
        /// `NewPortMappingDescription`.
        description: String,
    },
    /// `AddAnyPortMapping`.
    AddAnyPort {
        /// `NewInternalPort`.
        internal_port: u16,
        /// `NewLeaseDuration`.
        lease: u32,
    },
    /// `GetExternalIPAddress`.
    ExternalIp,
    /// `DeletePortMapping`.
    DeletePort {
        /// `NewExternalPort`.
        external_port: u16,
    },
    /// `GetGenericPortMappingEntry`.
    MappingEntry {
        /// `NewPortMappingIndex`.
        index: u32,
    },
    /// Anything else.
    Other,
}

struct IgdState {
    config: IgdConfig,
    table: Vec<IgdMapping>,
    heard: Vec<IgdHeard>,
}

/// A UPnP-IGD router on `<ip>`: SSDP on a UDP port of its own, the
/// description and control on a TCP port. Dropping it stops it.
pub struct FakeIgd {
    ip: Ipv4Addr,
    ssdp_port: u16,
    state: Arc<Mutex<IgdState>>,
    tasks: [AbortHandle; 2],
}

const MAPPING_ENTRY_OUT: [&str; 8] = [
    "NewRemoteHost",
    "NewExternalPort",
    "NewProtocol",
    "NewInternalPort",
    "NewInternalClient",
    "NewEnabled",
    "NewPortMappingDescription",
    "NewLeaseDuration",
];

impl Drop for FakeIgd {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

const SERVICE: &str = "urn:schemas-upnp-org:service:WANIPConnection:1";

fn device_description() -> String {
    format!(
        r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
<specVersion><major>1</major><minor>0</minor></specVersion>
<device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<deviceList><device>
<deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
<deviceList><device>
<deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
<serviceList><service>
<serviceType>{SERVICE}</serviceType>
<serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
<SCPDURL>/scpd.xml</SCPDURL>
<controlURL>/ctl</controlURL>
<eventSubURL>/evt</eventSubURL>
</service></serviceList>
</device></deviceList>
</device></deviceList>
</device>
</root>"#
    )
}

fn arguments(names: &[&str], out: &[&str]) -> String {
    let mut text = String::from("<argumentList>");
    for name in names {
        text.push_str(&format!(
            "<argument><name>{name}</name><direction>in</direction></argument>"
        ));
    }
    for name in out {
        text.push_str(&format!(
            "<argument><name>{name}</name><direction>out</direction></argument>"
        ));
    }
    text.push_str("</argumentList>");
    text
}

fn service_description(with_any: bool) -> String {
    const ADD: [&str; 8] = [
        "NewRemoteHost",
        "NewExternalPort",
        "NewProtocol",
        "NewInternalPort",
        "NewInternalClient",
        "NewEnabled",
        "NewPortMappingDescription",
        "NewLeaseDuration",
    ];
    let mut actions = format!(
        "<action><name>AddPortMapping</name>{}</action>",
        arguments(&ADD, &[])
    );
    if with_any {
        actions.push_str(&format!(
            "<action><name>AddAnyPortMapping</name>{}</action>",
            arguments(&ADD, &["NewReservedPort"])
        ));
    }
    actions.push_str(&format!(
        "<action><name>DeletePortMapping</name>{}</action>",
        arguments(&["NewRemoteHost", "NewExternalPort", "NewProtocol"], &[])
    ));
    actions.push_str(&format!(
        "<action><name>GetExternalIPAddress</name>{}</action>",
        arguments(&[], &["NewExternalIPAddress"])
    ));
    actions.push_str(&format!(
        "<action><name>GetGenericPortMappingEntry</name>{}</action>",
        arguments(&["NewPortMappingIndex"], &MAPPING_ENTRY_OUT)
    ));
    format!(
        r#"<?xml version="1.0"?>
<scpd xmlns="urn:schemas-upnp-org:service-1-0">
<specVersion><major>1</major><minor>0</minor></specVersion>
<actionList>{actions}</actionList>
</scpd>"#
    )
}

fn envelope(body: &str) -> String {
    format!(
        r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>{body}</s:Body></s:Envelope>"#
    )
}

fn soap_ok(action: &str, out: &str) -> String {
    envelope(&format!(
        r#"<u:{action}Response xmlns:u="{SERVICE}">{out}</u:{action}Response>"#
    ))
}

fn soap_fault(code: u16) -> String {
    envelope(&format!(
        r#"<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>{code}</errorCode><errorDescription>refused</errorDescription></UPnPError></detail></s:Fault>"#
    ))
}

/// The text of `<tag>…</tag>` in `body`.
fn arg<'a>(body: &'a str, tag: &str) -> &'a str {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    body.find(&open)
        .and_then(|at| {
            let rest = &body[at + open.len()..];
            rest.find(&close).map(|end| &rest[..end])
        })
        .unwrap_or("")
}

/// The SOAP action of a control request's head.
fn soap_action(head: &str) -> &str {
    head.lines()
        .find(|l| l.to_ascii_lowercase().starts_with("soapaction:"))
        .and_then(|l| l.split('#').nth(1))
        .map(|a| a.trim_end_matches('"').trim())
        .unwrap_or("")
}

/// The index of `port` (UDP) in `table`.
fn slot(table: &[IgdMapping], port: u16) -> Option<usize> {
    table.iter().position(|m| !m.tcp && m.external_port == port)
}

/// The answer to one HTTP request: status, body, and what it was.
fn answer_http(state: &mut IgdState, head: &str, body: &str) -> (u16, String, IgdHeard) {
    let IgdState { config, table, .. } = state;
    let first = head.lines().next().unwrap_or("");
    if first.starts_with("GET /rootDesc.xml") {
        return (200, device_description(), IgdHeard::Describe);
    }
    if first.starts_with("GET /scpd.xml") {
        return (
            200,
            service_description(config.add_any_port.is_some()),
            IgdHeard::Describe,
        );
    }
    if !first.starts_with("POST /ctl") {
        return (404, String::new(), IgdHeard::Other);
    }
    let action = soap_action(head);
    let number = |tag: &str| arg(body, tag).parse::<u32>().unwrap_or(u32::MAX);
    let port = |tag: &str| arg(body, tag).parse::<u16>().unwrap_or(0);
    let reply = |answer: IgdAnswer, action: &str, out: &str| match answer {
        IgdAnswer::Ok => (200, soap_ok(action, out)),
        IgdAnswer::Fault(code) => (500, soap_fault(code)),
    };
    match action {
        "AddPortMapping" => {
            let mapping = IgdMapping {
                external_port: port("NewExternalPort"),
                tcp: arg(body, "NewProtocol") == "TCP",
                internal_client: arg(body, "NewInternalClient").to_owned(),
                internal_port: port("NewInternalPort"),
                description: arg(body, "NewPortMappingDescription").to_owned(),
            };
            let heard = IgdHeard::AddPort {
                external_port: mapping.external_port,
                internal_port: mapping.internal_port,
                lease: number("NewLeaseDuration"),
                description: mapping.description.clone(),
            };
            let at = slot(table, mapping.external_port);
            let taken = at.is_some_and(|i| {
                table[i].internal_client != mapping.internal_client
                    || table[i].internal_port != mapping.internal_port
            });
            let answer = if taken {
                IgdAnswer::Fault(718)
            } else {
                config.add_port
            };
            if answer == IgdAnswer::Ok {
                match at {
                    Some(i) => table[i] = mapping,
                    None => table.push(mapping),
                }
            }
            let (status, text) = reply(answer, action, "");
            (status, text, heard)
        }
        "AddAnyPortMapping" => {
            let heard = IgdHeard::AddAnyPort {
                internal_port: port("NewInternalPort"),
                lease: number("NewLeaseDuration"),
            };
            let answer = config.add_any_port.unwrap_or(IgdAnswer::Fault(401));
            if answer == IgdAnswer::Ok {
                let mapping = IgdMapping {
                    external_port: config.any_port,
                    tcp: false,
                    internal_client: arg(body, "NewInternalClient").to_owned(),
                    internal_port: port("NewInternalPort"),
                    description: arg(body, "NewPortMappingDescription").to_owned(),
                };
                match slot(table, config.any_port) {
                    Some(i) => table[i] = mapping,
                    None => table.push(mapping),
                }
            }
            let out = format!("<NewReservedPort>{}</NewReservedPort>", config.any_port);
            let (status, text) = reply(answer, action, &out);
            (status, text, heard)
        }
        "DeletePortMapping" => {
            let heard = IgdHeard::DeletePort {
                external_port: port("NewExternalPort"),
            };
            if config.delete == IgdAnswer::Ok
                && let Some(i) = slot(table, port("NewExternalPort"))
            {
                table.remove(i);
            }
            let (status, text) = reply(config.delete, action, "");
            (status, text, heard)
        }
        "GetGenericPortMappingEntry" => {
            let index = number("NewPortMappingIndex");
            let heard = IgdHeard::MappingEntry { index };
            let entry = usize::try_from(index).ok().and_then(|i| table.get(i));
            let (status, text) = match (config.lookup, entry) {
                (IgdAnswer::Fault(code), _) => (500, soap_fault(code)),
                (IgdAnswer::Ok, None) => (500, soap_fault(713)),
                (IgdAnswer::Ok, Some(m)) => {
                    let out = format!(
                        "<NewRemoteHost></NewRemoteHost><NewExternalPort>{}</NewExternalPort><NewProtocol>{}</NewProtocol><NewInternalPort>{}</NewInternalPort><NewInternalClient>{}</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>{}</NewPortMappingDescription><NewLeaseDuration>600</NewLeaseDuration>",
                        m.external_port,
                        if m.tcp { "TCP" } else { "UDP" },
                        m.internal_port,
                        m.internal_client,
                        m.description
                    );
                    reply(IgdAnswer::Ok, action, &out)
                }
            };
            (status, text, heard)
        }
        "GetExternalIPAddress" => {
            let out = format!(
                "<NewExternalIPAddress>{}</NewExternalIPAddress>",
                config.external
            );
            let (status, text) = reply(IgdAnswer::Ok, action, &out);
            (status, text, IgdHeard::ExternalIp)
        }
        _ => (500, soap_fault(401), IgdHeard::Other),
    }
}

/// Reads one HTTP request (head and a `Content-Length` body) of at most
/// 64 KiB.
async fn read_request(stream: &mut TcpStream) -> io::Result<(String, String)> {
    let mut data = Vec::new();
    let mut buf = [0_u8; 4096];
    loop {
        if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&data[..end]).into_owned();
            let length = head
                .lines()
                .find_map(|l| {
                    let (name, value) = l.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            while data.len() < end + 4 + length {
                let n = stream.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..n]);
            }
            let body = String::from_utf8_lossy(&data[end + 4..]).into_owned();
            return Ok((head, body));
        }
        if data.len() > 64 * 1024 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        data.extend_from_slice(&buf[..n]);
    }
}

impl FakeIgd {
    /// A router on `ip` behaving as `config`, on the current runtime.
    ///
    /// # Errors
    ///
    /// A port could not be bound.
    pub async fn start(ip: Ipv4Addr, config: IgdConfig) -> io::Result<Self> {
        let ssdp = UdpSocket::bind((ip, 0)).await?;
        let ssdp_port = ssdp.local_addr()?.port();
        let http = TcpListener::bind((ip, 0)).await?;
        let http_port = http.local_addr()?.port();
        let state = Arc::new(Mutex::new(IgdState {
            table: config.table.clone(),
            config,
            heard: Vec::new(),
        }));
        // One control request at a time, as a router's single control
        // thread answers them.
        let serial = Arc::new(tokio::sync::Mutex::new(()));
        let shared = Arc::clone(&state);
        let search = tokio::spawn(async move {
            let mut buf = [0_u8; 2048];
            loop {
                let Ok((n, from)) = ssdp.recv_from(&mut buf).await else {
                    continue;
                };
                if !buf[..n].starts_with(b"M-SEARCH") {
                    continue;
                }
                let answer = {
                    let mut state = lock(&shared);
                    state.heard.push(IgdHeard::Search);
                    state.config.answer_search
                };
                if answer {
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:00000000-0000-0000-0000-000000000000::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nEXT:\r\nSERVER: fake/1.0 UPnP/1.1\r\nLOCATION: http://{ip}:{http_port}/rootDesc.xml\r\n\r\n"
                    );
                    let _ = ssdp.send_to(reply.as_bytes(), from).await;
                }
            }
        });
        let shared = Arc::clone(&state);
        let control = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = http.accept().await else {
                    continue;
                };
                let shared = Arc::clone(&shared);
                let serial = Arc::clone(&serial);
                tokio::spawn(async move {
                    let Ok((head, body)) = read_request(&mut stream).await else {
                        return;
                    };
                    let _turn = serial.lock().await;
                    let delay = lock(&shared).config.add_delay;
                    if soap_action(&head) == "AddPortMapping" && !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    let (status, text) = {
                        let mut state = lock(&shared);
                        let (status, text, heard) = answer_http(&mut state, &head, &body);
                        state.heard.push(heard);
                        (status, text)
                    };
                    let reason = if status == 200 { "OK" } else { "Error" };
                    let reply = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                        text.len()
                    );
                    let _ = stream.write_all(reply.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Ok(Self {
            ip,
            ssdp_port,
            state,
            tasks: [search.abort_handle(), control.abort_handle()],
        })
    }

    /// Its address.
    #[must_use]
    pub fn ip(&self) -> Ipv4Addr {
        self.ip
    }

    /// Its SSDP port.
    #[must_use]
    pub fn ssdp_port(&self) -> u16 {
        self.ssdp_port
    }

    /// Its SSDP address, as a stand-in for the multicast group.
    #[must_use]
    pub fn ssdp(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(self.ip), self.ssdp_port)
    }

    /// What it heard, in order.
    #[must_use]
    pub fn heard(&self) -> Vec<IgdHeard> {
        lock(&self.state).heard.clone()
    }

    /// Its table now.
    #[must_use]
    pub fn table(&self) -> Vec<IgdMapping> {
        lock(&self.state).table.clone()
    }

    /// Replaces its table (a lease that ran out, another computer taking
    /// the port).
    pub fn set_table(&self, table: Vec<IgdMapping>) {
        lock(&self.state).table = table;
    }

    /// Changes how it answers `GetGenericPortMappingEntry`.
    pub fn set_lookup(&self, lookup: IgdAnswer) {
        lock(&self.state).config.lookup = lookup;
    }
}
