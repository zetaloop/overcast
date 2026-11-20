pub(crate) mod editor;
pub(crate) use editor::client_fields;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
};

use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use termina::style::StyleExt;
use url::Url;

use crate::{
    Result,
    config::Store,
    form::{self, Value, choices, fields},
    transport::Transport,
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
    Vless(crate::vless::Client),
    Vmess(crate::vmess::Client),
    Trojan(crate::trojan::Client),
    Shadowsocks(crate::shadowsocks::Client),
    Hysteria2(crate::hysteria::Client),
    #[serde(rename = "anytls")]
    AnyTls(crate::anytls::Client),
    Warp(crate::warp::Client),
    Forward(crate::forward::Client),
}

impl Connection {
    pub fn core(&self) -> Core {
        match self {
            Self::Direct(value) => value.core,
            Self::Http(value) => value.proxy.core,
            Self::Socks(value) => value.proxy.core,
            Self::Vless(value) => value.core,
            Self::Vmess(value) => value.core,
            Self::Trojan(value) => value.core,
            Self::Shadowsocks(value) => value.core,
            Self::Hysteria2(value) => value.core,
            Self::AnyTls(value) => value.core,
            Self::Warp(value) => value.core,
            Self::Forward(value) => value.core,
        }
    }

    pub fn server(&self) -> Option<(&str, u16)> {
        Some(match self {
            Self::Direct(_) => return None,
            Self::Http(value) => (&value.proxy.server, value.proxy.port),
            Self::Socks(value) => (&value.proxy.server, value.proxy.port),
            Self::Vless(value) => (&value.server, value.port),
            Self::Vmess(value) => (&value.server, value.port),
            Self::Trojan(value) => (&value.server, value.port),
            Self::Shadowsocks(value) => (&value.server, value.port),
            Self::Hysteria2(value) => (&value.server, value.port().ok()?),
            Self::AnyTls(value) => (&value.server, value.port),
            Self::Warp(value) => (value.server(), value.port),
            Self::Forward(value) => (&value.server, value.port),
        })
    }

    pub fn network(&self) -> &Network {
        match self {
            Self::Direct(value) => &value.network,
            Self::Http(value) => &value.network,
            Self::Socks(value) => &value.network,
            Self::Vless(value) => &value.network,
            Self::Vmess(value) => &value.network,
            Self::Trojan(value) => &value.network,
            Self::Shadowsocks(value) => &value.network,
            Self::Hysteria2(value) => &value.network,
            Self::AnyTls(value) => &value.network,
            Self::Warp(value) => &value.network,
            Self::Forward(value) => &value.network,
        }
    }

    pub(crate) fn network_mut(&mut self) -> &mut Network {
        match self {
            Self::Direct(v) => &mut v.network,
            Self::Http(v) => &mut v.network,
            Self::Socks(v) => &mut v.network,
            Self::Vless(v) => &mut v.network,
            Self::Vmess(v) => &mut v.network,
            Self::Trojan(v) => &mut v.network,
            Self::Shadowsocks(v) => &mut v.network,
            Self::Hysteria2(v) => &mut v.network,
            Self::AnyTls(v) => &mut v.network,
            Self::Warp(v) => &mut v.network,
            Self::Forward(v) => &mut v.network,
        }
    }

    pub fn set_server(&mut self, server: &str) {
        if let Self::Warp(value) = self {
            value.server = Some(server.to_owned());
            return;
        }
        let (address, tls) = match self {
            Self::Http(value) => (&mut value.proxy.server, value.security.tls_mut()),
            Self::Socks(value) => (&mut value.proxy.server, value.security.tls_mut()),
            Self::Vless(value) => (&mut value.server, value.security.tls_mut()),
            Self::Vmess(value) => (&mut value.server, value.security.tls_mut()),
            Self::Trojan(value) => (&mut value.server, value.security.tls_mut()),
            Self::Shadowsocks(value) => (&mut value.server, value.security.tls_mut()),
            Self::Hysteria2(value) => (&mut value.server, Some(&mut value.tls)),
            Self::AnyTls(value) => (&mut value.server, value.security.tls_mut()),
            Self::Forward(value) => (&mut value.server, value.security.tls_mut()),
            Self::Direct(_) => return,
            Self::Warp(_) => unreachable!(),
        };
        if let Some(tls) = tls
            && tls.server_name.is_none()
        {
            tls.server_name = Some(address.clone());
        }
        *address = server.to_owned();
    }

    pub fn parse(text: &str) -> Result<Self> {
        if text.split_once("://").is_some_and(|(scheme, _)| {
            scheme.eq_ignore_ascii_case("hysteria2") || scheme.eq_ignore_ascii_case("hy2")
        }) {
            let value = Self::Hysteria2(crate::link::hysteria(text)?);
            value.validate()?;
            return Ok(value);
        }
        if text
            .split_once("://")
            .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("ss"))
        {
            let value = Self::Shadowsocks(crate::link::shadowsocks(text)?);
            value.validate()?;
            return Ok(value);
        }
        if text
            .split_once("://")
            .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("vmess"))
        {
            let value = Self::Vmess(crate::link::vmess(text)?);
            value.validate()?;
            return Ok(value);
        }
        let url = Url::parse(text)?;
        if url.scheme() == "anytls" {
            let value = Self::AnyTls(crate::link::anytls(&url)?);
            value.validate()?;
            return Ok(value);
        }
        if url.scheme() == "vless" {
            let value = Self::Vless(crate::link::vless(&url)?);
            value.validate()?;
            return Ok(value);
        }
        if url.scheme() == "trojan" {
            let value = Self::Trojan(crate::link::trojan(&url)?);
            value.validate()?;
            return Ok(value);
        }
        let mut query: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        let mut proxy = Proxy {
            name: percent_decode_str(url.fragment().unwrap_or_default())
                .decode_utf8()?
                .into_owned(),
            server: crate::link::host(&url)?,
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
                    String::from_utf8(crate::link::decode(&username)?)?
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
            "http" | "https" => {
                let mut http = HttpOptions {
                    path: (!url.path().is_empty() && url.path() != "/")
                        .then(|| url.path().to_owned()),
                    ..HttpOptions::default()
                };
                if !query.contains_key("type")
                    && let Some(path) = query.remove("path")
                {
                    http.path = Some(path);
                }
                if let Some(headers) = query.remove("headers") {
                    let fields: Vec<_> = headers.split(',').collect();
                    let (pairs, tail) = fields.as_chunks::<2>();
                    if !tail.is_empty() {
                        return Err("HTTP 请求头需要成对的名称和值".into());
                    }
                    for &[key, value] in pairs {
                        http.headers
                            .entry(key.to_owned())
                            .or_default()
                            .push(value.to_owned());
                    }
                }
                Self::Http(Http {
                    proxy,
                    http,
                    security: crate::link::security(&mut query, url.scheme() == "https")?,
                    transport: crate::link::transport(&mut query)?,
                    ..Http::default()
                })
            }
            "socks" | "socks4" | "socks4a" | "socks5" | "socks5+tls" => {
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
                        udp_over_tcp: crate::link::uot(&mut query)?,
                        ..SocksOptions::default()
                    },
                    security: crate::link::security(&mut query, url.scheme() == "socks5+tls")?,
                    network: Network::default(),
                    transport: crate::link::transport(&mut query)?,
                    multiplex: None,
                })
            }
            protocol => return Err(format!("不支持的连接链接：{protocol}").into()),
        };
        crate::link::remaining(query.keys(), "链接参数")?;
        connection.validate()?;
        Ok(connection)
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Direct(value) => &value.name,
            Self::Http(value) => &value.proxy.name,
            Self::Socks(value) => &value.proxy.name,
            Self::Vless(value) => &value.name,
            Self::Vmess(value) => &value.name,
            Self::Trojan(value) => &value.name,
            Self::Shadowsocks(value) => &value.name,
            Self::Hysteria2(value) => &value.name,
            Self::AnyTls(value) => &value.name,
            Self::Warp(value) => &value.name,
            Self::Forward(value) => &value.name,
        }
    }

    pub fn transport(&self) -> Option<&Transport> {
        match self {
            Self::Direct(_) | Self::Hysteria2(_) | Self::AnyTls(_) | Self::Warp(_) => None,
            Self::Http(value) => Some(&value.transport),
            Self::Socks(value) => Some(&value.transport),
            Self::Vless(value) => Some(&value.transport),
            Self::Vmess(value) => Some(&value.transport),
            Self::Trojan(value) => Some(&value.transport),
            Self::Shadowsocks(value) => Some(&value.transport),
            Self::Forward(value) => Some(&value.transport),
        }
    }

    pub(crate) fn security_mode(&self) -> usize {
        match self {
            Self::Direct(_) | Self::Warp(_) => 0,
            Self::Hysteria2(_) => 1,
            Self::Http(v) => v.security.index(),
            Self::Socks(v) => v.security.index(),
            Self::Vless(v) => v.security.index(),
            Self::Vmess(v) => v.security.index(),
            Self::Trojan(v) => v.security.index(),
            Self::Shadowsocks(v) => v.security.index(),
            Self::AnyTls(v) => v.security.index(),
            Self::Forward(v) => v.security.index(),
        }
    }

    pub fn multiplex(&self) -> Option<&crate::multiplex::Client> {
        match self {
            Self::Direct(_) | Self::Hysteria2(_) | Self::AnyTls(_) | Self::Warp(_) => None,
            Self::Http(value) => value.multiplex.as_ref(),
            Self::Socks(value) => value.multiplex.as_ref(),
            Self::Vless(value) => value.multiplex.as_ref(),
            Self::Vmess(value) => value.multiplex.as_ref(),
            Self::Trojan(value) => value.multiplex.as_ref(),
            Self::Shadowsocks(value) => value.multiplex.as_ref(),
            Self::Forward(_) => None,
        }
    }

    pub fn packet_encoding(&self) -> Option<PacketEncoding> {
        match self {
            Self::Vless(value) => Some(value.vless.packet_encoding),
            Self::Vmess(value) => Some(value.vmess.packet_encoding),
            _ => None,
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
            Self::Vless(value) => format!("VLESS {}", address(&value.server, value.port)),
            Self::Vmess(value) => format!("VMess {}", address(&value.server, value.port)),
            Self::Trojan(value) => format!("Trojan {}", address(&value.server, value.port)),
            Self::Shadowsocks(value) => {
                format!("Shadowsocks {}", address(&value.server, value.port))
            }
            Self::Hysteria2(value) => format!(
                "Hysteria 2 {}",
                address(
                    &value.server,
                    if value.hysteria.ports.is_empty() {
                        value.port.to_string()
                    } else {
                        value.hysteria.ports.clone()
                    },
                ),
            ),
            Self::Forward(value) => format!("TCP/UDP {}", address(&value.server, value.port)),
            Self::AnyTls(value) => format!("AnyTLS {}", address(&value.server, value.port)),
            Self::Warp(value) => format!("WARP {}", address(value.server(), value.port)),
        }
    }

    pub fn edit(&mut self, screen: &mut Screen, store: &Store) -> Result<()> {
        let title = self.summary();
        form::flat(screen, &title, self, |source| match source {
            Self::Direct(value) => value.controls(store),
            Self::Http(value) => value.controls(store),
            Self::Socks(value) => value.controls(store),
            Self::Vless(value) => value.controls(store),
            Self::Vmess(value) => value.controls(store),
            Self::Trojan(value) => value.controls(store),
            Self::Shadowsocks(value) => value.controls(store),
            Self::Forward(value) => value.controls(store),
            Self::Hysteria2(value) => value.controls(store),
            Self::AnyTls(value) => value.controls(store),
            Self::Warp(value) => value.controls(store),
        })
        .map(|_| ())
    }

    pub fn validate(&self) -> Result<()> {
        self.check_stack()?;
        let (server, port) = match self {
            Self::Direct(_) => return Ok(()),
            Self::Http(value) => (value.proxy.server.as_str(), value.proxy.port),
            Self::Socks(value) => (value.proxy.server.as_str(), value.proxy.port),
            Self::Vless(value) => {
                if value.uuid.is_empty() {
                    return Err("请填写 VLESS 用户标识".into());
                }
                (value.server.as_str(), value.port)
            }
            Self::Vmess(value) => {
                if value.uuid.is_empty() {
                    return Err("请填写 VMess 用户标识".into());
                }
                (value.server.as_str(), value.port)
            }
            Self::Trojan(value) => {
                if value.password.is_empty() {
                    return Err("请填写 Trojan 密码".into());
                }
                (value.server.as_str(), value.port)
            }
            Self::Shadowsocks(value) => {
                if value.shadowsocks.cipher != crate::shadowsocks::Cipher::None
                    && value.password.is_empty()
                {
                    return Err("请填写 Shadowsocks 密码".into());
                }
                value.shadowsocks.cipher.password(&value.password)?;
                (value.server.as_str(), value.port)
            }
            Self::Forward(value) => (value.server.as_str(), value.port),
            Self::Hysteria2(value) => {
                crate::hysteria::password(&value.password)?;
                if let Some(obfs) = &value.hysteria.obfs {
                    obfs.validate()?;
                }
                (value.server.as_str(), value.port()?)
            }
            Self::AnyTls(value) => {
                if value.password.is_empty() {
                    return Err("请填写 AnyTLS 密码".into());
                }
                if matches!(value.security, Security::None) {
                    return Err("AnyTLS 连接需要 TLS 或 REALITY 握手".into());
                }
                (value.server.as_str(), value.port)
            }
            Self::Warp(value) => {
                value.registration.validate()?;
                (value.server(), value.port)
            }
        };
        if server.trim().is_empty() {
            return Err("连接地址不能为空".into());
        }
        if port == 0 {
            return Err("请填写连接端口".into());
        }
        Ok(())
    }
}

pub fn create(screen: &mut Screen, store: &Store) -> Result<Option<Connection>> {
    let items = [
        Item::new("http", "HTTP".stylized()),
        Item::new("socks", "SOCKS".stylized()),
        Item::new("vless", "VLESS".stylized()),
        Item::new("vmess", "VMess".stylized()),
        Item::new("trojan", "Trojan".stylized()),
        Item::new("shadowsocks", "Shadowsocks".stylized()),
        Item::new("hysteria2", "Hysteria 2".stylized()),
        Item::new("anytls", "AnyTLS".stylized()),
        Item::new("warp", "WARP".stylized()),
        Item::new("forward", "TCP/UDP 转发".stylized()),
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
                    2 => Connection::Vless(crate::vless::Client::default()),
                    3 => Connection::Vmess(crate::vmess::Client::default()),
                    4 => Connection::Trojan(crate::trojan::Client::default()),
                    5 => Connection::Shadowsocks(crate::shadowsocks::Client::default()),
                    6 => Connection::Hysteria2(crate::hysteria::Client::default()),
                    7 => Connection::AnyTls(crate::anytls::Client::default()),
                    8 => Connection::Warp(crate::warp::Client::default()),
                    9 => Connection::Forward(crate::forward::Client::default()),
                    10 => Connection::Direct(Direct::default()),
                    _ => return Ok(None),
                };
                connection.edit(screen, store)?;
                return Ok(Some(connection));
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
        address(&self.server, self.port)
    }
}

pub(crate) fn address(server: &str, port: impl Display) -> String {
    if server.contains(':') && !server.starts_with('[') {
        format!("[{server}]:{port}")
    } else {
        format!("{server}:{port}")
    }
}

pub(crate) fn ports(text: &str) -> Result<BTreeSet<u16>> {
    let mut ports = BTreeSet::new();
    for range in text.split(',') {
        let range = range.trim();
        let (first, last) = range.split_once('-').unwrap_or((range, range));
        let first: u16 = first
            .trim()
            .parse()
            .map_err(|error| format!("端口格式不正确：{error}"))?;
        let last: u16 = last
            .trim()
            .parse()
            .map_err(|error| format!("端口格式不正确：{error}"))?;
        if first == 0 || last < first {
            return Err("端口需要在 1～65535 之间，范围按从小到大填写".into());
        }
        ports.extend(first..=last);
    }
    Ok(ports)
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Http {
    pub proxy: Proxy,
    pub security: Security,
    pub http: HttpOptions,
    pub network: Network,
    pub transport: Transport,
    pub multiplex: Option<crate::multiplex::Client>,
}

impl Default for Http {
    fn default() -> Self {
        Self {
            proxy: Proxy {
                port: 80,
                ..Proxy::default()
            },
            security: Security::None,
            http: HttpOptions::default(),
            network: Network::default(),
            transport: Transport::default(),
            multiplex: None,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Socks {
    pub proxy: Proxy,
    pub security: Security,
    pub socks: SocksOptions,
    pub network: Network,
    pub transport: Transport,
    pub multiplex: Option<crate::multiplex::Client>,
}

impl Default for Socks {
    fn default() -> Self {
        Self {
            proxy: Proxy {
                port: 1080,
                ..Proxy::default()
            },
            security: Security::None,
            socks: SocksOptions::default(),
            network: Network::default(),
            transport: Transport::default(),
            multiplex: None,
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

#[derive(Clone, Copy, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PacketEncoding {
    #[default]
    Default,
    Packet,
    PacketAddr,
    Xudp,
}

choices!(PacketEncoding {
    Default: "default" => "默认",
    Packet: "packet" => "原生数据包",
    PacketAddr: "packetaddr" => "PacketAddr",
    Xudp: "xudp" => "XUDP",
});

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
    pub ech: Option<Ech>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ech {
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
    fn alternatives() -> Vec<(&'static str, &'static str, Self)> {
        vec![
            ("on", "开启", Self::Enabled(true)),
            ("off", "关闭", Self::Enabled(false)),
        ]
    }

    fn text(&self) -> String {
        match self {
            Self::Enabled(value) => value.text(),
            Self::Queue(value) => value.to_string(),
        }
    }

    fn edit(&mut self, screen: &mut Screen, parent: &Menu<'_>, field: usize) -> Result<bool> {
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
                        *self = Self::Enabled(selected == 0);
                        return Ok(true);
                    }
                    2 => {
                        if let Some(value) =
                            screen.input(&menu, selected, &queue.to_string(), |value, _| {
                                let value = value
                                    .parse()
                                    .map_err(|error| format!("队列长度格式不正确：{error}"))?;
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

impl Proxy {
    fn fields(&mut self, d: Self, choices: &editor::Choices) -> form::Fields<'_> {
        vec![
            form::field("name", "名称", &mut self.name, d.name),
            form::field("server", "地址", &mut self.server, d.server),
            form::field("port", "端口", &mut self.port, d.port),
            form::field("username", "用户名", &mut self.username, d.username),
            form::field("password", "密码", &mut self.password, d.password),
            choices.core(&mut self.core, d.core),
        ]
    }
}

client_fields!(
    Http,
    Http {
        proxy: ..,
        security: "加密",
        http: "HTTP",
        transport: "传输",
        multiplex: "多路复用",
        network: "网络",
    }
);

client_fields!(
    Socks,
    Socks {
        proxy: ..,
        security: "加密",
        socks: "SOCKS",
        transport: "传输",
        multiplex: "多路复用",
        network: "网络",
    }
);

client_fields!(
    Direct,
    Direct {
        name: "名称",
        core: "核心",
        network: "网络",
    }
);

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
} groups {
    certificates: "证书" => [verify_names, system_roots, certificates, certificate_files, certificate_sha256, public_key_sha256, client_certificate, client_certificate_file, client_key, client_key_file],
    protocol: "版本与密码" => [min_version, max_version, cipher_suites, curves, fingerprint, engine],
    handshake: "握手" => [handshake_timeout, session_resumption, kernel_tx, kernel_rx, fragment, fragment_delay, record_fragment, spoof, spoof_method, key_log],
});

fields!(Ech {
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
} groups {
    binding: "绑定与路由" => [bind_address_no_port, reuse_address, routing_mark, namespace, protect_path, network_strategy, network_types, fallback_network_types, fallback_delay, socket_options],
    tcp: "TCP" => [tcp_fast_open, tcp_multi_path, tcp_keep_alive, tcp_keep_alive_idle, tcp_keep_alive_interval, tcp_congestion, tcp_window, tcp_max_segment, tcp_user_timeout],
    address: "地址选择" => [connect_timeout, address_port_strategy, ipv6_only, happy_eyeballs],
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

pub type Security = crate::security::Security<Tls, crate::reality::Client>;
