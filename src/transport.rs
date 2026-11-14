use std::{borrow::Cow, collections::BTreeMap, rc::Rc};

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

    pub fn supported(&self, security: &Security, networks: [bool; 2]) -> bool {
        networks[usize::from(self.quic(security))]
            && match self {
                Self::XHttp(value) => value.download.as_ref().is_none_or(|download| {
                    networks[usize::from(
                        matches!(&download.security, Security::Tls(tls) if tls.alpn == ["h3"]),
                    )]
                }),
                _ => true,
            }
    }

    fn index(&self) -> usize {
        match self {
            Self::Default => 0,
            Self::WebSocket(_) => 1,
            Self::HttpUpgrade(_) => 2,
            Self::Grpc(_) => 3,
            Self::XHttp(_) => 4,
            Self::Http(_) => 5,
            Self::Kcp(_) => 6,
            Self::Quic => 7,
        }
    }
}

impl Value for Transport {
    fn text(&self) -> String {
        match self {
            Self::Default => "默认",
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

    fn run(
        &mut self,
        screen: &mut Screen,
        parent: &Menu<'_>,
        field: usize,
        apply: form::Apply<'_, Self>,
        _: bool,
    ) -> Result<bool> {
        let title = format!("{} / {}", parent.title, parent.items[field].label.content);
        let mut saved = BTreeMap::new();
        let mut selected = self.index();
        let mut changed = false;
        let mut notice = String::new();
        loop {
            let mut items: Vec<_> = [
                ("default", "默认"),
                ("websocket", "WebSocket"),
                ("httpupgrade", "HTTPUpgrade"),
                ("grpc", "gRPC"),
                ("xhttp", "XHTTP"),
                ("http", "HTTP"),
                ("kcp", "KCP"),
                ("quic", "QUIC"),
                ("back", "返回"),
            ]
            .into_iter()
            .map(|(key, label)| Item::new(key, label.stylized()))
            .collect();
            items[self.index()].marker = "■";
            let menu = Menu {
                title: &title,
                heading: "",
                items: &items,
                help: "方向键 选择\n回车键 编辑\nEsc 返回",
            };
            match screen.select(&menu, &mut selected, &notice)? {
                Action::Back => return Ok(changed),
                Action::Select if selected == items.len() - 1 => return Ok(changed),
                Action::Select => {
                    saved.insert(self.index(), self.clone());
                    let mut candidate =
                        saved
                            .get(&selected)
                            .cloned()
                            .unwrap_or_else(|| match selected {
                                1 => Self::WebSocket(WebSocket::default()),
                                2 => Self::HttpUpgrade(HttpUpgrade::default()),
                                3 => Self::Grpc(Grpc::default()),
                                4 => Self::XHttp(Box::default()),
                                5 => Self::Http(Http::default()),
                                6 => Self::Kcp(Kcp::default()),
                                7 => Self::Quic,
                                _ => Self::Default,
                            });
                    let creating = selected != self.index();
                    let result = match &mut candidate {
                        Self::Default => form::set(screen, self, Self::Default, &apply),
                        Self::Quic => form::set(screen, self, Self::Quic, &apply),
                        Self::WebSocket(value) => {
                            let apply = apply.clone();
                            form::edit(
                                screen,
                                &format!("{title} / WebSocket"),
                                value,
                                Rc::new(move |value, screen| {
                                    apply(&Self::WebSocket(value.clone()), screen)
                                }),
                                creating,
                            )
                        }
                        Self::HttpUpgrade(value) => {
                            let apply = apply.clone();
                            form::edit(
                                screen,
                                &format!("{title} / HTTPUpgrade"),
                                value,
                                Rc::new(move |value, screen| {
                                    apply(&Self::HttpUpgrade(value.clone()), screen)
                                }),
                                creating,
                            )
                        }
                        Self::Grpc(value) => {
                            let apply = apply.clone();
                            form::edit(
                                screen,
                                &format!("{title} / gRPC"),
                                value,
                                Rc::new(move |value, screen| {
                                    apply(&Self::Grpc(value.clone()), screen)
                                }),
                                creating,
                            )
                        }
                        Self::XHttp(value) => {
                            let apply = apply.clone();
                            form::edit(
                                screen,
                                &format!("{title} / XHTTP"),
                                value.as_mut(),
                                Rc::new(move |value, screen| {
                                    apply(&Self::XHttp(Box::new(value.clone())), screen)
                                }),
                                creating,
                            )
                        }
                        Self::Http(value) => {
                            let apply = apply.clone();
                            form::edit(
                                screen,
                                &format!("{title} / HTTP"),
                                value,
                                Rc::new(move |value, screen| {
                                    apply(&Self::Http(value.clone()), screen)
                                }),
                                creating,
                            )
                        }
                        Self::Kcp(value) => {
                            let apply = apply.clone();
                            form::edit(
                                screen,
                                &format!("{title} / KCP"),
                                value,
                                Rc::new(move |value, screen| {
                                    apply(&Self::Kcp(value.clone()), screen)
                                }),
                                creating,
                            )
                        }
                    };
                    match result {
                        Ok(accepted) => {
                            if accepted {
                                *self = candidate;
                                changed = true;
                            }
                            notice.clear();
                        }
                        Err(error) => notice = error.to_string(),
                    }
                }
                _ => {}
            }
        }
    }
}

fields!(Http {
    version: "版本",
    host: "主机",
    path: "路径",
    method: "方法",
    headers: "标头",
    random_headers: "随机标头值",
    idle_timeout: "空闲超时",
    ping_timeout: "心跳超时",
} groups {
    headers: "请求头" => [headers, random_headers],
    connection: "连接" => [idle_timeout, ping_timeout],
});

fields!(Kcp {
    mtu: "MTU",
    interval: "发送间隔",
    upload: "上传容量 MiB/s",
    download: "下载容量 MiB/s",
    window_multiplier: "拥塞窗口倍率",
    congestion: "拥塞控制",
    write_buffer: "写缓冲字节数",
    read_buffer: "读缓冲字节数",
    checksum: "帧校验",
    seed: "加密种子",
    header: "数据包伪装",
    domain: "DNS 域名",
} groups {
    packet: "数据包" => [mtu, interval, checksum, write_buffer, read_buffer],
    congestion: "拥塞控制" => [upload, download, window_multiplier, congestion],
    obfuscation: "伪装" => [seed, header, domain],
});

choices!(Header {
    None: "none" => "无",
    Srtp: "srtp" => "SRTP",
    Utp: "utp" => "uTP",
    WechatVideo: "wechat-video" => "微信视频",
    Dtls: "dtls" => "DTLS",
    Wireguard: "wireguard" => "WireGuard",
    Dns: "dns" => "DNS",
});
fields!(WebSocket {
    host: "主机名",
    path: "路径",
    headers: "请求头",
    early_data: "握手数据上限",
    early_data_header: "握手数据请求头",
    heartbeat: "心跳间隔",
});

fields!(HttpUpgrade {
    host: "主机名",
    path: "路径",
    headers: "请求头",
    early_data: "提前发送",
});

fields!(Grpc {
    authority: "主机名",
    service_name: "服务名",
    multi_mode: "多流模式",
    keep_alive: "保活间隔",
    ping_timeout: "保活响应超时",
    permit_without_stream: "空闲连接保活",
    receive_window: "接收窗口",
    user_agent: "用户代理",
    connections: "连接数",
    min_streams: "最小并发流数",
    max_streams: "最大并发流数",
} groups {
    streams: "多路复用" => [multi_mode, connections, min_streams, max_streams, receive_window],
    keep_alive: "保活" => [keep_alive, ping_timeout, permit_without_stream],
});

choices!(Mode {
    Auto: "auto" => "自动",
    PacketUp: "packet-up" => "分包上传",
    StreamUp: "stream-up" => "双流传输",
    StreamOne: "stream-one" => "单流传输",
});

choices!(Placement {
    Path: "path" => "路径",
    Cookie: "cookie" => "Cookie",
    Header: "header" => "请求头",
    Query: "query" => "查询参数",
});

choices!(PaddingPlacement {
    QueryInHeader: "query-in-header" => "请求头内的查询参数",
    Cookie: "cookie" => "Cookie",
    Header: "header" => "请求头",
    Query: "query" => "查询参数",
});

choices!(PaddingMethod {
    RepeatX: "repeat-x" => "重复字符",
    Tokenish: "tokenish" => "仿令牌",
});

choices!(Congestion {
    Default: "default" => "默认",
    Bbr: "bbr" => "BBR",
    Reno: "reno" => "Reno",
    ForceBrutal: "force-brutal" => "强制 Brutal",
    Brutal: "brutal" => "Brutal",
    Cubic: "cubic" => "Cubic",
});

choices!(BbrProfile {
    Conservative: "conservative" => "保守",
    Standard: "standard" => "标准",
    Aggressive: "aggressive" => "积极",
});

choices!(DataPlacement {
    Auto: "auto" => "自动",
    Body: "body" => "正文",
    Cookie: "cookie" => "Cookie",
    Header: "header" => "请求头",
});

fields!(XHttp {
    http: ..,
    download: "下载连接",
    quic: "QUIC",
});

fields!(XHttpOptions {
    host: "主机名",
    path: "路径",
    mode: "模式",
    headers: "请求头",
    padding_size: "填充字节数",
    padding_obfuscation: "填充混淆",
    padding_key: "填充参数名",
    padding_header: "填充请求头",
    padding_placement: "填充位置",
    padding_method: "填充方式",
    upload_method: "上传方法",
    session_placement: "会话标识位置",
    session_key: "会话标识参数名",
    session_alphabet: "会话标识字符集",
    session_length: "会话标识长度",
    sequence_placement: "序号位置",
    sequence_key: "序号参数名",
    data_placement: "上传数据位置",
    data_key: "上传数据参数名",
    chunk_size: "上传数据分块大小",
    grpc_header: "gRPC 请求头",
    sse_header: "SSE 响应头",
    upload_size: "单次上传字节数",
    upload_interval: "上传间隔",
    buffered_uploads: "上传缓存数量",
    stream_keep_alive: "流上传保活间隔",
    header_limit: "请求头大小上限",
    pool: "连接复用",
} groups {
    request: "请求与会话" => [upload_method, session_placement, session_key, session_alphabet, session_length, sequence_placement, sequence_key, data_placement, data_key, chunk_size],
    padding: "填充" => [padding_size, padding_obfuscation, padding_key, padding_header, padding_placement, padding_method],
    upload: "上传" => [upload_size, upload_interval, buffered_uploads, stream_keep_alive],
    protocol: "协议头" => [grpc_header, sse_header, header_limit],
});

fields!(Pool {
    concurrency: "并发流数",
    connections: "连接数",
    reuse_limit: "连接复用次数",
    request_limit: "请求次数",
    lifetime: "连接复用时限",
    keep_alive: "保活间隔",
});

fields!(Download {
    server: "地址",
    port: "端口",
    http: "XHTTP",
    security: "加密",
    network: "网络",
    quic: "QUIC",
});

fields!(Quic {
    congestion: "拥塞算法",
    debug: "调试",
    bbr_profile: "BBR 策略",
    upload_bandwidth: "上传带宽",
    download_bandwidth: "下载带宽",
    loss_compensation: "丢包补偿",
    initial_stream_window: "初始流接收窗口",
    max_stream_window: "最大流接收窗口",
    initial_connection_window: "初始连接接收窗口",
    max_connection_window: "最大连接接收窗口",
    idle_timeout: "空闲超时",
    keep_alive: "保活间隔",
    path_mtu_discovery: "路径 MTU 探测",
    chrome_fingerprint: "Chrome 指纹",
    gso: "分段卸载",
    incoming_streams: "入站流数",
    stateless_reset: "无状态重置",
    initial_packet_size: "初始数据包",
    handshake_timeout: "握手超时",
    udp_mtu: "UDP MTU",
    cwnd: "拥塞窗口",
} groups {
    congestion: "拥塞控制" => [congestion, bbr_profile, upload_bandwidth, download_bandwidth, loss_compensation, cwnd],
    windows: "接收窗口" => [initial_stream_window, max_stream_window, initial_connection_window, max_connection_window, incoming_streams, initial_packet_size],
    connection: "连接参数" => [idle_timeout, keep_alive, path_mtu_discovery, gso, handshake_timeout, udp_mtu],
    protocol: "协议选项" => [debug, chrome_fingerprint, stateless_reset],
});
