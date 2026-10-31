use std::{collections::BTreeMap, rc::Rc};

use base64::{
    Engine, alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use termina::style::StyleExt;
use url::{Host, Url};

use crate::{
    Result,
    form::{self, Value, choices, fields},
    tui::{Action, Item, Menu, Screen},
};

#[derive(Clone, Copy, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Core {
    #[default]
    Auto,
    Xray,
    SingBox,
    Mihomo,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "protocol", rename_all = "kebab-case")]
pub enum Connection {
    Direct(Direct),
    Http(Http),
    Socks(Socks),
}

impl Connection {
    pub fn parse(text: &str) -> Result<Self> {
        let url = Url::parse(text)?;
        if url.query().is_some() {
            return Err("不支持此链接的查询参数".into());
        }
        let server = match Host::parse(url.host_str().ok_or("链接缺少服务器地址")?)? {
            Host::Domain(value) => value,
            Host::Ipv4(value) => value.to_string(),
            Host::Ipv6(value) => value.to_string(),
        };
        let mut proxy = Proxy {
            name: percent_decode_str(url.fragment().unwrap_or_default())
                .decode_utf8()?
                .into_owned(),
            server,
            port: url.port_or_known_default().unwrap_or(1080),
            ..Proxy::default()
        };
        if !url.username().is_empty() || url.password().is_some() {
            let username = percent_decode_str(url.username())
                .decode_utf8()?
                .into_owned();
            if url.scheme() == "socks" && url.password().is_none() {
                let credentials = if username.contains(':') {
                    username
                } else {
                    let engine = GeneralPurpose::new(
                        &alphabet::STANDARD,
                        GeneralPurposeConfig::new()
                            .with_decode_padding_mode(DecodePaddingMode::Indifferent),
                    );
                    String::from_utf8(engine.decode(username.replace('-', "+").replace('_', "/"))?)?
                };
                let (username, password) = credentials
                    .split_once(':')
                    .ok_or("SOCKS 链接的认证信息格式不正确")?;
                proxy.username = Some(username.to_owned());
                proxy.password = Some(password.to_owned());
            } else {
                proxy.username = Some(username);
                proxy.password = url
                    .password()
                    .map(|password| {
                        percent_decode_str(password)
                            .decode_utf8()
                            .map(|value| value.into_owned())
                    })
                    .transpose()?;
            }
        }
        let connection = match url.scheme() {
            "http" | "https" => Self::Http(Http {
                proxy,
                tls: Tls {
                    enabled: url.scheme() == "https",
                    ..Tls::default()
                },
                http: HttpOptions {
                    path: (!url.path().is_empty() && url.path() != "/")
                        .then(|| url.path().to_owned()),
                    ..HttpOptions::default()
                },
                network: Network::default(),
            }),
            "socks" | "socks4" | "socks4a" | "socks5" => {
                if !url.path().is_empty() && url.path() != "/" {
                    return Err("SOCKS 链接中包含路径".into());
                }
                Self::Socks(Socks {
                    proxy,
                    socks: SocksOptions {
                        version: match url.scheme() {
                            "socks4" => SocksVersion::V4,
                            "socks4a" => SocksVersion::V4a,
                            _ => SocksVersion::V5,
                        },
                        ..SocksOptions::default()
                    },
                    tls: Tls::default(),
                    network: Network::default(),
                })
            }
            protocol => return Err(format!("不支持的连接链接：{protocol}").into()),
        };
        Ok(connection)
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Direct(value) => &value.name,
            Self::Http(value) => &value.proxy.name,
            Self::Socks(value) => &value.proxy.name,
        }
    }

    pub fn summary(&self) -> String {
        if !self.name().is_empty() {
            return self.name().to_owned();
        }
        match self {
            Self::Direct(_) => "直连".to_owned(),
            Self::Http(value) => format!("HTTP {}", value.proxy.address()),
            Self::Socks(value) => format!("SOCKS {}", value.proxy.address()),
        }
    }

    pub fn edit(&mut self, screen: &mut Screen, apply: form::Apply<'_, Self>) -> Result<()> {
        self.form(screen, apply, false).map(|_| ())
    }

    fn form(
        &mut self,
        screen: &mut Screen,
        apply: form::Apply<'_, Self>,
        creating: bool,
    ) -> Result<bool> {
        let title = self.summary();
        match self {
            Self::Direct(value) => form::edit(
                screen,
                &title,
                value,
                Rc::new(move |value, screen| apply(&Self::Direct(value.clone()), screen)),
                creating,
            ),
            Self::Http(value) => form::edit(
                screen,
                &title,
                value,
                Rc::new(move |value, screen| apply(&Self::Http(value.clone()), screen)),
                creating,
            ),
            Self::Socks(value) => form::edit(
                screen,
                &title,
                value,
                Rc::new(move |value, screen| apply(&Self::Socks(value.clone()), screen)),
                creating,
            ),
        }
    }

    pub fn validate(&self) -> Result<()> {
        let proxy = match self {
            Self::Direct(_) => return Ok(()),
            Self::Http(value) => &value.proxy,
            Self::Socks(value) => &value.proxy,
        };
        if proxy.server.trim().is_empty() {
            return Err("连接地址不能为空".into());
        }
        if proxy.port == 0 {
            return Err("请填写连接端口".into());
        }
        Ok(())
    }
}

pub fn create(
    screen: &mut Screen,
    apply: form::Apply<'_, Connection>,
) -> Result<Option<Connection>> {
    let items = [
        Item::new("http", "HTTP".stylized()),
        Item::new("socks", "SOCKS".stylized()),
        Item::new("direct", "直连".stylized()),
        Item::new("back", "返回".stylized()),
    ];
    let menu = Menu {
        title: "添加连接",
        heading: "",
        items: &items,
        help: "方向键 选择\n回车键 确定\nEsc 返回",
    };
    let mut selected = 0;
    loop {
        match screen.select(&menu, &mut selected, "")? {
            Action::Back => return Ok(None),
            Action::Select => {
                let mut connection = match selected {
                    0 => Connection::Http(Http::default()),
                    1 => Connection::Socks(Socks::default()),
                    2 => Connection::Direct(Direct::default()),
                    _ => return Ok(None),
                };
                let accepted = connection.form(screen, apply, true)?;
                return Ok(accepted.then_some(connection));
            }
            _ => {}
        }
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Proxy {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub core: Core,
}

impl Proxy {
    pub fn address(&self) -> String {
        if self.server.contains(':') && !self.server.starts_with('[') {
            format!("[{}]:{}", self.server, self.port)
        } else {
            format!("{}:{}", self.server, self.port)
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Http {
    pub proxy: Proxy,
    pub tls: Tls,
    pub http: HttpOptions,
    pub network: Network,
}

impl Default for Http {
    fn default() -> Self {
        Self {
            proxy: Proxy {
                port: 80,
                ..Proxy::default()
            },
            tls: Tls::default(),
            http: HttpOptions::default(),
            network: Network::default(),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Socks {
    pub proxy: Proxy,
    pub tls: Tls,
    pub socks: SocksOptions,
    pub network: Network,
}

impl Default for Socks {
    fn default() -> Self {
        Self {
            proxy: Proxy {
                port: 1080,
                ..Proxy::default()
            },
            tls: Tls::default(),
            socks: SocksOptions::default(),
            network: Network::default(),
        }
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Direct {
    pub name: String,
    pub core: Core,
    pub network: Network,
}

#[derive(Clone, Copy, Default, PartialEq, Deserialize, Serialize)]
pub enum SocksVersion {
    #[serde(rename = "4")]
    V4,
    #[serde(rename = "4a")]
    V4a,
    #[default]
    #[serde(rename = "5")]
    V5,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SocksOptions {
    pub version: SocksVersion,
    pub tcp: Option<bool>,
    pub udp: Option<bool>,
    pub udp_over_tcp: Option<u8>,
    pub user_level: Option<u32>,
    pub user_label: Option<String>,
}

#[derive(Clone, Copy, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HttpVersion {
    #[default]
    Auto,
    Http1,
    Http2,
    Http3,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpOptions {
    pub version: HttpVersion,
    pub fixed_version: bool,
    pub path: Option<String>,
    pub headers: BTreeMap<String, Vec<String>>,
    pub idle_timeout: Option<String>,
    pub keep_alive: Option<String>,
    pub stream_receive_window: Option<u64>,
    pub connection_receive_window: Option<u64>,
    pub max_concurrent_streams: Option<u32>,
    pub initial_packet_size: Option<u16>,
    pub disable_path_mtu_discovery: bool,
    pub user_level: Option<u32>,
    pub user_label: Option<String>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Tls {
    pub enabled: bool,
    pub server_name: Option<String>,
    pub send_sni: Option<bool>,
    pub verify_certificate: Option<bool>,
    pub verify_names: Vec<String>,
    pub alpn: Vec<String>,
    pub min_version: Option<String>,
    pub max_version: Option<String>,
    pub cipher_suites: Vec<String>,
    pub curves: Vec<String>,
    pub fingerprint: Option<String>,
    pub engine: Option<String>,
    pub system_roots: Option<bool>,
    pub certificates: Vec<String>,
    pub certificate_files: Vec<String>,
    pub certificate_sha256: Vec<String>,
    pub public_key_sha256: Vec<String>,
    pub client_certificate: Option<String>,
    pub client_certificate_file: Option<String>,
    pub client_key: Option<String>,
    pub client_key_file: Option<String>,
    pub handshake_timeout: Option<String>,
    pub session_resumption: Option<bool>,
    pub kernel_tx: Option<bool>,
    pub kernel_rx: Option<bool>,
    pub fragment: Option<bool>,
    pub fragment_delay: Option<String>,
    pub record_fragment: Option<bool>,
    pub spoof: Option<String>,
    pub spoof_method: Option<String>,
    pub key_log: Option<String>,
    pub ech: Ech,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ech {
    pub enabled: bool,
    pub config: Option<String>,
    pub config_file: Option<String>,
    pub query_name: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum FastOpen {
    Enabled(bool),
    Queue(u32),
}

impl Default for FastOpen {
    fn default() -> Self {
        Self::Enabled(true)
    }
}

impl Value for FastOpen {
    fn text(&self) -> String {
        match self {
            Self::Enabled(value) => value.text(),
            Self::Queue(value) => value.to_string(),
        }
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
        let mut items = [
            Item::new("on", "开启".stylized()),
            Item::new("off", "关闭".stylized()),
            Item::new("queue", "队列长度".stylized()),
            Item::new("back", "返回".stylized()),
        ];
        let queue = match self {
            Self::Queue(value) => *value,
            _ => 0,
        };
        items[2].value = queue.to_string();
        let menu = Menu {
            title: &title,
            heading: "",
            items: &items,
            help: "方向键 选择\n回车键 确定\nEsc 返回",
        };
        let mut selected = match self {
            Self::Enabled(true) => 0,
            Self::Enabled(false) => 1,
            Self::Queue(_) => 2,
        };
        loop {
            match screen.select(&menu, &mut selected, "")? {
                Action::Back => return Ok(false),
                Action::Select => match selected {
                    0 | 1 => {
                        return form::set(screen, self, Self::Enabled(selected == 0), &apply);
                    }
                    2 => {
                        if let Some(value) =
                            screen.input(&menu, selected, &queue.to_string(), |value, screen| {
                                let value = value
                                    .parse()
                                    .map_err(|error| format!("队列长度格式不正确：{error}"))?;
                                apply(&Self::Queue(value), screen)?;
                                Ok(value)
                            })?
                        {
                            *self = Self::Queue(value);
                            return Ok(true);
                        }
                    }
                    _ => return Ok(false),
                },
                _ => {}
            }
        }
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Network {
    pub interface: Option<String>,
    pub source_ipv4: Option<String>,
    pub source_ipv6: Option<String>,
    pub bind_address_no_port: Option<bool>,
    pub reuse_address: Option<bool>,
    pub routing_mark: Option<u32>,
    pub namespace: Option<String>,
    pub protect_path: Option<String>,
    pub connect_timeout: Option<String>,
    pub address_strategy: Option<AddressStrategy>,
    pub address_port_strategy: Option<String>,
    pub ipv6_only: Option<bool>,
    pub tcp_fast_open: Option<FastOpen>,
    pub tcp_multi_path: Option<bool>,
    pub tcp_keep_alive: Option<bool>,
    pub tcp_keep_alive_idle: Option<String>,
    pub tcp_keep_alive_interval: Option<String>,
    pub tcp_congestion: Option<String>,
    pub tcp_window: Option<u32>,
    pub tcp_max_segment: Option<u32>,
    pub tcp_user_timeout: Option<String>,
    pub udp_fragment: Option<bool>,
    pub happy_eyeballs: HappyEyeballs,
    pub network_strategy: Option<String>,
    pub network_types: Vec<String>,
    pub fallback_network_types: Vec<String>,
    pub fallback_delay: Option<String>,
    pub socket_options: Vec<SocketOption>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HappyEyeballs {
    pub prefer_ipv6: Option<bool>,
    pub delay: Option<String>,
    pub interleave: Option<u32>,
    pub concurrency: Option<u32>,
}

#[derive(Clone, Copy, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AddressStrategy {
    #[default]
    AsIs,
    Resolve,
    Ipv4Only,
    Ipv6Only,
    PreferIpv4,
    PreferIpv6,
    TryIp,
    TryIpv4,
    TryIpv6,
    TryIpv4Ipv6,
    TryIpv6Ipv4,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SocketOption {
    pub system: String,
    pub network: String,
    pub level: String,
    pub option: String,
    pub value: String,
    pub kind: String,
}

choices!(Core {
    Auto: "auto" => "自动",
    Xray: "xray" => "Xray",
    SingBox: "sing-box" => "sing-box",
    Mihomo: "mihomo" => "Mihomo",
});

choices!(SocksVersion {
    V4: "4" => "SOCKS4",
    V4a: "4a" => "SOCKS4a",
    V5: "5" => "SOCKS5",
});

choices!(HttpVersion {
    Auto: "auto" => "自动",
    Http1: "http1" => "HTTP/1.1",
    Http2: "http2" => "HTTP/2",
    Http3: "http3" => "HTTP/3",
});

choices!(AddressStrategy {
    AsIs: "as-is" => "按需解析",
    Resolve: "resolve" => "解析为 IP",
    Ipv4Only: "ipv4-only" => "仅 IPv4",
    Ipv6Only: "ipv6-only" => "仅 IPv6",
    PreferIpv4: "prefer-ipv4" => "优先 IPv4",
    PreferIpv6: "prefer-ipv6" => "优先 IPv6",
    TryIp: "try-ip" => "尝试解析为 IP",
    TryIpv4: "try-ipv4" => "尝试 IPv4",
    TryIpv6: "try-ipv6" => "尝试 IPv6",
    TryIpv4Ipv6: "try-ipv4-ipv6" => "依次尝试 IPv4、IPv6",
    TryIpv6Ipv4: "try-ipv6-ipv4" => "依次尝试 IPv6、IPv4",
});

fields!(Proxy {
    name: "名称",
    server: "地址",
    port: "端口",
    username: "用户名",
    password: "密码",
    core: "核心",
});

fields!(Http {
    proxy: ..,
    tls: "TLS",
    http: "HTTP",
    network: "网络",
});

fields!(Socks {
    proxy: ..,
    tls: "TLS",
    socks: "SOCKS",
    network: "网络",
});

fields!(Direct {
    name: "名称",
    core: "核心",
    network: "网络",
});

fields!(SocksOptions {
    version: "版本",
    tcp: "TCP",
    udp: "UDP",
    udp_over_tcp: "UDP over TCP",
    user_level: "用户等级",
    user_label: "用户标识",
});

fields!(HttpOptions {
    version: "版本",
    fixed_version: "固定版本",
    path: "路径",
    headers: "请求头",
    idle_timeout: "空闲超时",
    keep_alive: "保活间隔",
    stream_receive_window: "流接收窗口",
    connection_receive_window: "连接接收窗口",
    max_concurrent_streams: "并发流数",
    initial_packet_size: "初始数据包大小",
    disable_path_mtu_discovery: "关闭路径 MTU 探测",
    user_level: "用户等级",
    user_label: "用户标识",
});

fields!(Tls {
    enabled: "启用",
    server_name: "服务名",
    send_sni: "发送 SNI",
    verify_certificate: "验证证书",
    verify_names: "证书名称",
    alpn: "ALPN",
    min_version: "最低版本",
    max_version: "最高版本",
    cipher_suites: "密码套件",
    curves: "曲线",
    fingerprint: "指纹",
    engine: "实现",
    system_roots: "系统证书",
    certificates: "信任证书",
    certificate_files: "信任证书文件",
    certificate_sha256: "证书 SHA-256",
    public_key_sha256: "公钥 SHA-256",
    client_certificate: "客户端证书",
    client_certificate_file: "客户端证书文件",
    client_key: "客户端私钥",
    client_key_file: "客户端私钥文件",
    handshake_timeout: "握手超时",
    session_resumption: "会话复用",
    kernel_tx: "内核发送",
    kernel_rx: "内核接收",
    fragment: "握手分片",
    fragment_delay: "分片延迟",
    record_fragment: "记录分片",
    spoof: "伪装内容",
    spoof_method: "伪装方式",
    key_log: "密钥日志文件",
    ech: "ECH",
});

fields!(Ech {
    enabled: "启用",
    config: "配置",
    config_file: "配置文件",
    query_name: "查询名称",
});

fields!(Network {
    interface: "接口",
    source_ipv4: "源 IPv4",
    source_ipv6: "源 IPv6",
    bind_address_no_port: "延后分配端口",
    reuse_address: "复用地址",
    routing_mark: "路由标记",
    namespace: "网络命名空间",
    protect_path: "保护套接字",
    connect_timeout: "连接超时",
    address_strategy: "地址策略",
    address_port_strategy: "地址端口策略",
    ipv6_only: "仅 IPv6",
    tcp_fast_open: "TCP 快速打开",
    tcp_multi_path: "多路径 TCP",
    tcp_keep_alive: "TCP 保活",
    tcp_keep_alive_idle: "TCP 保活起始时间",
    tcp_keep_alive_interval: "TCP 保活间隔",
    tcp_congestion: "TCP 拥塞算法",
    tcp_window: "TCP 接收窗口",
    tcp_max_segment: "TCP 最大分段",
    tcp_user_timeout: "TCP 用户超时",
    udp_fragment: "UDP 分片",
    happy_eyeballs: "双栈连接",
    network_strategy: "接口策略",
    network_types: "接口类型",
    fallback_network_types: "备用接口类型",
    fallback_delay: "备用连接延迟",
    socket_options: "自定义套接字选项",
});

fields!(HappyEyeballs {
    prefer_ipv6: "优先 IPv6",
    delay: "尝试间隔",
    interleave: "交错数量",
    concurrency: "并发尝试数",
});

fields!(SocketOption {
    system: "系统",
    network: "网络",
    level: "级别",
    option: "选项",
    value: "值",
    kind: "类型",
});
