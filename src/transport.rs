use crate::language::text as tr;
use std::{borrow::Cow, collections::BTreeMap};

use serde::{Deserialize, Serialize};
use termina::style::StyleExt;

use crate::{
    Result,
    connection::{HttpVersion, Network, Security, Tls},
    form::{self, Value, choices, fields},
    tui::{Action, Item, Menu, Screen},
};

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum Transport {
    #[default]
    Default,
    WebSocket(WebSocket),
    HttpUpgrade(HttpUpgrade),
    Grpc(Grpc),
    XHttp(Box<XHttp>),
    Http(Http),
    Kcp(Kcp),
    Quic,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Http {
    pub version: HttpVersion,
    pub host: Vec<String>,
    pub path: Option<String>,
    pub method: Option<String>,
    pub headers: BTreeMap<String, Vec<String>>,
    pub random_headers: bool,
    pub idle_timeout: Option<String>,
    pub ping_timeout: Option<String>,
}

impl Http {
    pub fn version(&self, tls: bool) -> HttpVersion {
        match self.version {
            HttpVersion::Auto if tls => HttpVersion::Http2,
            HttpVersion::Auto => HttpVersion::Http1,
            version => version,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Kcp {
    pub mtu: Option<u32>,
    pub interval: Option<String>,
    pub upload: Option<u32>,
    pub download: Option<u32>,
    pub window_multiplier: Option<u32>,
    pub congestion: Option<bool>,
    pub write_buffer: Option<u32>,
    pub read_buffer: Option<u32>,
    pub checksum: bool,
    pub seed: Option<String>,
    pub header: Header,
    pub domain: Option<String>,
}

impl Default for Kcp {
    fn default() -> Self {
        Self {
            mtu: None,
            interval: None,
            upload: None,
            download: None,
            window_multiplier: None,
            congestion: None,
            write_buffer: None,
            read_buffer: None,
            checksum: true,
            seed: None,
            header: Header::default(),
            domain: None,
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Header {
    #[default]
    None,
    Srtp,
    Utp,
    WechatVideo,
    Dtls,
    Wireguard,
    Dns,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebSocket {
    pub host: Option<String>,
    pub path: Option<String>,
    pub headers: BTreeMap<String, Vec<String>>,
    pub early_data: Option<u32>,
    pub early_data_header: Option<String>,
    pub heartbeat: Option<String>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpUpgrade {
    pub host: Option<String>,
    pub path: Option<String>,
    pub headers: BTreeMap<String, Vec<String>>,
    pub early_data: Option<bool>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Grpc {
    pub authority: Option<String>,
    pub service_name: Option<String>,
    pub multi_mode: bool,
    pub keep_alive: Option<String>,
    pub ping_timeout: Option<String>,
    pub permit_without_stream: bool,
    pub receive_window: Option<u32>,
    pub user_agent: Option<String>,
    pub connections: Option<u32>,
    pub min_streams: Option<u32>,
    pub max_streams: Option<u32>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct XHttp {
    pub http: XHttpOptions,
    pub download: Option<Download>,
    pub quic: Quic,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct XHttpOptions {
    pub host: Option<String>,
    pub path: Option<String>,
    pub mode: Mode,
    pub headers: BTreeMap<String, Vec<String>>,
    pub padding_size: Option<String>,
    pub padding_obfuscation: bool,
    pub padding_key: Option<String>,
    pub padding_header: Option<String>,
    pub padding_placement: PaddingPlacement,
    pub padding_method: PaddingMethod,
    pub upload_method: Option<String>,
    pub session_placement: Placement,
    pub session_key: Option<String>,
    pub session_alphabet: Option<String>,
    pub session_length: Option<String>,
    pub sequence_placement: Placement,
    pub sequence_key: Option<String>,
    pub data_placement: DataPlacement,
    pub data_key: Option<String>,
    pub chunk_size: Option<String>,
    pub grpc_header: Option<bool>,
    pub sse_header: Option<bool>,
    pub upload_size: Option<String>,
    pub upload_interval: Option<String>,
    pub buffered_uploads: Option<i64>,
    pub stream_keep_alive: Option<String>,
    pub header_limit: Option<i32>,
    pub pool: Pool,
}

#[derive(Clone, Copy, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    #[default]
    Auto,
    PacketUp,
    StreamUp,
    StreamOne,
}

#[derive(Clone, Copy, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Placement {
    #[default]
    Path,
    Cookie,
    Header,
    Query,
}

#[derive(Clone, Copy, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PaddingPlacement {
    #[default]
    QueryInHeader,
    Cookie,
    Header,
    Query,
}

#[derive(Clone, Copy, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PaddingMethod {
    #[default]
    RepeatX,
    Tokenish,
}

#[derive(Clone, Copy, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DataPlacement {
    #[default]
    Auto,
    Body,
    Cookie,
    Header,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Pool {
    pub concurrency: Option<String>,
    pub connections: Option<String>,
    pub reuse_limit: Option<String>,
    pub request_limit: Option<String>,
    pub lifetime: Option<String>,
    pub keep_alive: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Download {
    pub server: String,
    pub port: u16,
    pub http: XHttpOptions,
    pub security: Security,
    pub network: Network,
    pub quic: Quic,
}

impl Default for Download {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 443,
            http: XHttpOptions::default(),
            security: Security::Tls(Tls::default()),
            network: Network::default(),
            quic: Quic::default(),
        }
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Quic {
    pub congestion: Congestion,
    pub debug: bool,
    pub bbr_profile: BbrProfile,
    pub upload_bandwidth: Option<String>,
    pub download_bandwidth: Option<String>,
    pub loss_compensation: Option<bool>,
    pub initial_stream_window: Option<u64>,
    pub max_stream_window: Option<u64>,
    pub initial_connection_window: Option<u64>,
    pub max_connection_window: Option<u64>,
    pub idle_timeout: Option<String>,
    pub keep_alive: Option<String>,
    pub path_mtu_discovery: Option<bool>,
    pub chrome_fingerprint: Option<bool>,
    pub gso: Option<bool>,
    pub incoming_streams: Option<i64>,
    pub stateless_reset: Option<bool>,
    pub initial_packet_size: Option<u16>,
    pub handshake_timeout: Option<String>,
    pub udp_mtu: Option<u16>,
    pub cwnd: Option<u32>,
}

#[derive(Clone, Copy, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Congestion {
    #[default]
    Default,
    Bbr,
    Reno,
    ForceBrutal,
    Brutal,
    Cubic,
}

#[derive(Clone, Copy, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BbrProfile {
    Conservative,
    #[default]
    Standard,
    Aggressive,
}

impl Transport {
    pub fn client_tls<'a>(&self, security: &'a Security) -> Cow<'a, Security> {
        let mut security = Cow::Borrowed(security);
        if let Self::Http(http) = self
            && let Security::Tls(tls) = security.as_ref()
            && tls.alpn.is_empty()
        {
            let alpn = match http.version(true) {
                HttpVersion::Http1 => Some("http/1.1"),
                HttpVersion::Http2 => Some("h2"),
                _ => None,
            };
            if let Some(alpn) = alpn
                && let Security::Tls(tls) = security.to_mut()
            {
                tls.alpn.push(alpn.to_owned());
            }
        }
        security
    }

    pub fn is_default(&self) -> bool {
        matches!(self, Self::Default)
    }

    pub fn udp(&self, tls: bool, alpn: &[String]) -> bool {
        matches!(self, Self::Quic | Self::Kcp(_))
            || matches!(self, Self::XHttp(_)) && tls && alpn == ["h3"]
    }

    pub fn quic(&self, security: &Security) -> bool {
        match security {
            Security::Tls(tls) => self.udp(true, &tls.alpn),
            _ => self.udp(false, &[]),
        }
    }

    pub fn xray_reality(&self) -> bool {
        matches!(
            self,
            Self::Default | Self::Http(_) | Self::Grpc(_) | Self::XHttp(_)
        )
    }
}

impl Value for Transport {
    fn text(&self) -> String {
        match self {
            Self::Default => tr("Default", "默认"),
            Self::WebSocket(_) => "WebSocket",
            Self::HttpUpgrade(_) => "HTTPUpgrade",
            Self::Grpc(_) => "gRPC",
            Self::XHttp(_) => "XHTTP",
            Self::Http(_) => "HTTP",
            Self::Kcp(_) => "KCP",
            Self::Quic => "QUIC",
        }
        .to_owned()
    }

    fn edit(&mut self, screen: &mut Screen, parent: &Menu<'_>, field: usize) -> Result<bool> {
        self.select(
            screen,
            parent,
            field,
            &Self::variants(),
            |value, screen, title| {
                let peers = crate::native::parameters::Peers::client(crate::native::stack::CORES);
                value.edit(screen, title, &peers, None)
            },
            form::edit,
        )
    }
}

impl Grpc {
    pub(crate) fn fit(&mut self, core: crate::inbound::Core, inbound: bool) {
        let names = core.grpc_fields(inbound);
        form::retain(self, |key| names.contains(key));
    }

    pub(crate) fn edit(
        &mut self,
        screen: &mut Screen,
        title: &str,
        peers: &crate::native::parameters::Peers,
        fixed_client: Option<crate::inbound::Core>,
    ) -> Result<bool> {
        form::scoped(screen, title, self, |raw| {
            let mut active = raw.clone();
            if let Some(core) = peers.server.or(fixed_client) {
                active.fit(core, peers.server.is_some());
            }
            let names = peers.grpc_fields(&active);
            let mut fields = form::Form::fields(raw, Self::default());
            fields.retain(|field| names.contains(field.key()));
            fields
        })
    }
}

impl Transport {
    pub(crate) fn draft(&self, effective: &Self) -> Self {
        if std::mem::discriminant(self) == std::mem::discriminant(effective) {
            self.clone()
        } else {
            effective.clone()
        }
    }

    pub(crate) fn variants() -> [(&'static str, Self); 8] {
        [
            ("default", Self::Default),
            ("websocket", Self::WebSocket(Default::default())),
            ("httpupgrade", Self::HttpUpgrade(Default::default())),
            ("grpc", Self::Grpc(Default::default())),
            ("xhttp", Self::XHttp(Box::default())),
            ("http", Self::Http(Default::default())),
            ("kcp", Self::Kcp(Default::default())),
            ("quic", Self::Quic),
        ]
    }

    pub(crate) fn select(
        &mut self,
        screen: &mut Screen,
        parent: &Menu<'_>,
        field: usize,
        choices: &[(&str, Self)],
        grpc: impl FnOnce(&mut Grpc, &mut Screen, &str) -> Result<bool>,
        xhttp: impl FnOnce(&mut Screen, &str, &mut XHttp) -> Result<bool>,
    ) -> Result<bool> {
        let title = format!("{} / {}", parent.title, parent.items[field].label.content);
        let current = choices
            .iter()
            .position(|(_, value)| std::mem::discriminant(value) == std::mem::discriminant(self));
        let mut selected = current.unwrap_or(0);
        let mut items: Vec<_> = choices
            .iter()
            .map(|(key, value)| Item::new(*key, value.text().stylized()))
            .collect();
        items.push(Item::new("back", tr("Back", "返回").stylized()));
        if let Some(index) = current {
            items[index].marker = "■";
        }
        loop {
            let menu = Menu {
                title: &title,
                heading: "",
                items: &items,
                help: tr(
                    "Arrow keys to select\nEnter to edit\nEsc to go back",
                    "方向键 选择\n回车键 编辑\nEsc 返回",
                ),
            };
            match screen.select(&menu, &mut selected, "")? {
                Action::Back => return Ok(false),
                Action::Select if selected == items.len() - 1 => return Ok(false),
                Action::Select => {
                    let switching = current != Some(selected);
                    if switching {
                        *self = choices[selected].1.clone();
                    }
                    let title = format!("{title} / {}", self.text());
                    let edited = match self {
                        Self::Default | Self::Quic => false,
                        Self::WebSocket(value) => form::edit(screen, &title, value)?,
                        Self::HttpUpgrade(value) => form::edit(screen, &title, value)?,
                        Self::Grpc(value) => grpc(value, screen, &title)?,
                        Self::XHttp(value) => xhttp(screen, &title, value.as_mut())?,
                        Self::Http(value) => form::edit(screen, &title, value)?,
                        Self::Kcp(value) => form::edit(screen, &title, value)?,
                    };
                    return Ok(edited || switching);
                }
                _ => {}
            }
        }
    }
}

fields!(Http {
    version: ("Version", "版本"),
    host: ("Host", "主机"),
    path: ("Path", "路径"),
    method: ("Method", "方法"),
    headers: ("Headers", "标头"),
    random_headers: ("Randomize header values", "随机标头值"),
    idle_timeout: ("Idle timeout", "空闲超时"),
    ping_timeout: ("Ping timeout", "心跳超时"),
} groups {
    headers: ("Request headers", "请求头") => [headers, random_headers],
    connection: ("Connection", "连接") => [idle_timeout, ping_timeout],
});

fields!(Kcp {
    mtu: "MTU",
    interval: ("Send interval", "发送间隔"),
    upload: ("Upload capacity (MiB/s)", "上传容量 MiB/s"),
    download: ("Download capacity (MiB/s)", "下载容量 MiB/s"),
    window_multiplier: ("Congestion window multiplier", "拥塞窗口倍率"),
    congestion: ("Congestion control", "拥塞控制"),
    write_buffer: ("Write buffer size (bytes)", "写缓冲字节数"),
    read_buffer: ("Read buffer size (bytes)", "读缓冲字节数"),
    checksum: ("Frame checksum", "帧校验"),
    seed: ("Encryption seed", "加密种子"),
    header: ("Packet header", "数据包伪装"),
    domain: ("DNS domain", "DNS 域名"),
} groups {
    packet: ("Packet", "数据包") => [mtu, interval, checksum, write_buffer, read_buffer],
    congestion: ("Congestion control", "拥塞控制") => [upload, download, window_multiplier, congestion],
    obfuscation: ("Camouflage", "伪装") => [seed, header, domain],
});

choices!(Header {
    None: "none" => ("None", "无"),
    Srtp: "srtp" => "SRTP",
    Utp: "utp" => "uTP",
    WechatVideo: "wechat-video" => ("WeChat video", "微信视频"),
    Dtls: "dtls" => "DTLS",
    Wireguard: "wireguard" => "WireGuard",
    Dns: "dns" => "DNS",
});
fields!(WebSocket {
    host: ("Hostname", "主机名"),
    path: ("Path", "路径"),
    headers: ("Request headers", "请求头"),
    early_data: ("Maximum early data", "握手数据上限"),
    early_data_header: ("Early data header", "握手数据请求头"),
    heartbeat: ("Ping interval", "心跳间隔"),
});

fields!(HttpUpgrade {
    host: ("Hostname", "主机名"),
    path: ("Path", "路径"),
    headers: ("Request headers", "请求头"),
    early_data: ("Send early data", "提前发送"),
});

fields!(Grpc {
    authority: ("Hostname", "主机名"),
    service_name: ("Server name", "服务名"),
    multi_mode: ("Multi-stream mode", "多流模式"),
    keep_alive: ("Keepalive interval", "保活间隔"),
    ping_timeout: ("Keepalive response timeout", "保活响应超时"),
    permit_without_stream: ("Keep idle connections alive", "空闲连接保活"),
    receive_window: ("Receive window", "接收窗口"),
    user_agent: ("User agent", "用户代理"),
    connections: ("Connections", "连接数"),
    min_streams: ("Minimum concurrent streams", "最小并发流数"),
    max_streams: ("Maximum concurrent streams", "最大并发流数"),
} groups {
    streams: ("Multiplexing", "多路复用") => [multi_mode, connections, min_streams, max_streams, receive_window],
    keep_alive: ("Keepalive", "保活") => [keep_alive, ping_timeout, permit_without_stream],
});

choices!(Mode {
    Auto: "auto" => ("Automatic", "自动"),
    PacketUp: "packet-up" => ("Packet uploads", "分包上传"),
    StreamUp: "stream-up" => ("Separate upload and download streams", "双流传输"),
    StreamOne: "stream-one" => ("Single stream", "单流传输"),
});

choices!(Placement {
    Path: "path" => ("Path", "路径"),
    Cookie: "cookie" => "Cookie",
    Header: "header" => ("Request headers", "请求头"),
    Query: "query" => ("Query parameter", "查询参数"),
});

choices!(PaddingPlacement {
    QueryInHeader: "query-in-header" => ("Query inside header", "请求头内的查询参数"),
    Cookie: "cookie" => "Cookie",
    Header: "header" => ("Request headers", "请求头"),
    Query: "query" => ("Query parameter", "查询参数"),
});

choices!(PaddingMethod {
    RepeatX: "repeat-x" => ("Repeated characters", "重复字符"),
    Tokenish: "tokenish" => ("Token-like", "仿令牌"),
});

choices!(Congestion {
    Default: "default" => ("Default", "默认"),
    Bbr: "bbr" => "BBR",
    Reno: "reno" => "Reno",
    ForceBrutal: "force-brutal" => ("Force Brutal", "强制 Brutal"),
    Brutal: "brutal" => "Brutal",
    Cubic: "cubic" => "Cubic",
});

choices!(BbrProfile {
    Conservative: "conservative" => ("Conservative", "保守"),
    Standard: "standard" => ("Standard", "标准"),
    Aggressive: "aggressive" => ("Aggressive", "积极"),
});

choices!(DataPlacement {
    Auto: "auto" => ("Automatic", "自动"),
    Body: "body" => ("Inline", "正文"),
    Cookie: "cookie" => "Cookie",
    Header: "header" => ("Request headers", "请求头"),
});

fields!(XHttp {
    http: ..,
    download: ("Download connection", "下载连接"),
    quic: "QUIC",
});

fields!(XHttpOptions {
    host: ("Hostname", "主机名"),
    path: ("Path", "路径"),
    mode: ("Mode", "模式"),
    headers: ("Request headers", "请求头"),
    padding_size: ("Padding bytes", "填充字节数"),
    padding_obfuscation: ("Obfuscate padding", "填充混淆"),
    padding_key: ("Padding parameter name", "填充参数名"),
    padding_header: ("Padding header", "填充请求头"),
    padding_placement: ("Padding placement", "填充位置"),
    padding_method: ("Padding method", "填充方式"),
    upload_method: ("Upload method", "上传方法"),
    session_placement: ("Session ID placement", "会话标识位置"),
    session_key: ("Session ID parameter name", "会话标识参数名"),
    session_alphabet: ("Session ID alphabet", "会话标识字符集"),
    session_length: ("Session ID length", "会话标识长度"),
    sequence_placement: ("Sequence number placement", "序号位置"),
    sequence_key: ("Sequence number parameter name", "序号参数名"),
    data_placement: ("Upload data placement", "上传数据位置"),
    data_key: ("Upload data parameter name", "上传数据参数名"),
    chunk_size: ("Upload chunk size", "上传数据分块大小"),
    grpc_header: ("gRPC request header", "gRPC 请求头"),
    sse_header: ("SSE response header", "SSE 响应头"),
    upload_size: ("Bytes per upload", "单次上传字节数"),
    upload_interval: ("Upload interval", "上传间隔"),
    buffered_uploads: ("Buffered uploads", "上传缓存数量"),
    stream_keep_alive: ("Streaming upload keepalive interval", "流上传保活间隔"),
    header_limit: ("Maximum header size", "请求头大小上限"),
    pool: ("Connection reuse", "连接复用"),
} groups {
    request: ("Requests and sessions", "请求与会话") => [upload_method, session_placement, session_key, session_alphabet, session_length, sequence_placement, sequence_key, data_placement, data_key, chunk_size],
    padding: ("Padding", "填充") => [padding_size, padding_obfuscation, padding_key, padding_header, padding_placement, padding_method],
    upload: ("Upload", "上传") => [upload_size, upload_interval, buffered_uploads, stream_keep_alive],
    protocol: ("Protocol headers", "协议头") => [grpc_header, sse_header, header_limit],
});

fields!(Pool {
    concurrency: ("Concurrent streams", "并发流数"),
    connections: ("Connections", "连接数"),
    reuse_limit: ("Connection reuse count", "连接复用次数"),
    request_limit: ("Request count", "请求次数"),
    lifetime: ("Connection reuse lifetime", "连接复用时限"),
    keep_alive: ("Keepalive interval", "保活间隔"),
});

fields!(Download {
    server: ("Address", "地址"),
    port: ("Port", "端口"),
    http: "XHTTP",
    security: ("Encryption", "加密"),
    network: ("Network", "网络"),
    quic: "QUIC",
});

fields!(Quic {
    congestion: ("Congestion algorithm", "拥塞算法"),
    debug: ("Debug", "调试"),
    bbr_profile: ("BBR profile", "BBR 策略"),
    upload_bandwidth: ("Upload bandwidth", "上传带宽"),
    download_bandwidth: ("Download bandwidth", "下载带宽"),
    loss_compensation: ("Packet loss compensation", "丢包补偿"),
    initial_stream_window: ("Initial stream receive window", "初始流接收窗口"),
    max_stream_window: ("Maximum stream receive window", "最大流接收窗口"),
    initial_connection_window: ("Initial connection receive window", "初始连接接收窗口"),
    max_connection_window: ("Maximum connection receive window", "最大连接接收窗口"),
    idle_timeout: ("Idle timeout", "空闲超时"),
    keep_alive: ("Keepalive interval", "保活间隔"),
    path_mtu_discovery: ("Path MTU discovery", "路径 MTU 探测"),
    chrome_fingerprint: ("Chrome fingerprint", "Chrome 指纹"),
    gso: ("Segmentation offload", "分段卸载"),
    incoming_streams: ("Incoming streams", "入站流数"),
    stateless_reset: ("Stateless reset", "无状态重置"),
    initial_packet_size: ("Initial packet", "初始数据包"),
    handshake_timeout: ("Handshake timeout", "握手超时"),
    udp_mtu: "UDP MTU",
    cwnd: ("Congestion window", "拥塞窗口"),
} groups {
    congestion: ("Congestion control", "拥塞控制") => [congestion, bbr_profile, upload_bandwidth, download_bandwidth, loss_compensation, cwnd],
    windows: ("Receive window", "接收窗口") => [initial_stream_window, max_stream_window, initial_connection_window, max_connection_window, incoming_streams, initial_packet_size],
    connection: ("Connection settings", "连接参数") => [idle_timeout, keep_alive, path_mtu_discovery, gso, handshake_timeout, udp_mtu],
    protocol: ("Protocol options", "协议选项") => [debug, chrome_fingerprint, stateless_reset],
});
