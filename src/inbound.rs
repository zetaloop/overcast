use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv6Addr},
    path::Path,
    rc::Rc,
};

use serde::{Deserialize, Serialize};
use termina::{
    event::KeyCode,
    style::{AnsiColor, StyleExt},
};
use uuid::Uuid;

use crate::{
    Result,
    config::Store,
    connection::{FastOpen, SocketOption},
    form::{self, Value, choices, fields},
    transport::Transport,
    tui::{Action, Item, Menu, Screen},
    user,
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Inbound {
    pub uuid: Uuid,
    pub name: String,
    pub address: String,
    pub ports: String,
    pub core: Core,
    pub users: bool,
    pub credentials: Option<Credentials>,
    pub protocol: Protocol,
    #[serde(default)]
    pub transport: Transport,
    pub tls: Tls,
    pub listen: Listen,
}

impl Inbound {
    fn new(kind: Kind) -> Self {
        Self {
            uuid: Uuid::new_v4(),
            name: String::new(),
            address: String::new(),
            ports: match kind {
                Kind::Mixed => "1080",
                Kind::Vless | Kind::Vmess => "443",
            }
            .to_owned(),
            core: kind.core(),
            users: true,
            credentials: None,
            protocol: kind.protocol(),
            transport: Transport::default(),
            tls: Tls {
                enabled: kind != Kind::Mixed,
                ..Tls::default()
            },
            listen: Listen::default(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err("入站名称不能为空".into());
        }
        if self.address.trim().is_empty() {
            return Err("连接地址不能为空".into());
        }
        if !is_ip(&self.address) {
            url::Host::parse(&self.address)
                .map_err(|error| format!("连接地址格式不正确：{error}"))?;
        }
        let address = &self.listen.address;
        if !is_ip(address)
            && address != "localhost"
            && !Path::new(address).is_absolute()
            && !address.starts_with('@')
        {
            return Err("监听地址需要填写 IP、localhost 或套接字路径".into());
        }
        self.ports()?;
        if let Some(credentials) = &self.credentials {
            user::password(&credentials.password)?;
        }
        Ok(())
    }

    pub fn ports(&self) -> Result<BTreeSet<u16>> {
        let mut ports = BTreeSet::new();
        for range in self.ports.split(',') {
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

    pub(crate) fn summary(&self) -> String {
        let address = if self.address.contains(':') && !self.address.starts_with('[') {
            format!("[{}]", self.address)
        } else {
            self.address.clone()
        };
        format!("{} {address}:{}", self.protocol.kind().text(), self.ports)
    }
}

fn is_ip(value: &str) -> bool {
    match value.split_once('%') {
        Some((address, zone)) => !zone.is_empty() && address.parse::<Ipv6Addr>().is_ok(),
        None => value.parse::<IpAddr>().is_ok(),
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Core {
    Xray,
    #[default]
    SingBox,
    Mihomo,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    #[default]
    Mixed,
    Vless,
    Vmess,
}

impl Kind {
    fn core(self) -> Core {
        match self {
            Self::Mixed | Self::Vmess => Core::SingBox,
            Self::Vless => Core::Xray,
        }
    }

    fn protocol(self) -> Protocol {
        match self {
            Self::Mixed => Protocol::Mixed(Mixed::default()),
            Self::Vless => Protocol::Vless(crate::vless::Server::default()),
            Self::Vmess => Protocol::Vmess(crate::vmess::Server::default()),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Protocol {
    Mixed(Mixed),
    Vless(crate::vless::Server),
    Vmess(crate::vmess::Server),
}

impl Protocol {
    fn kind(&self) -> Kind {
        match self {
            Self::Mixed(_) => Kind::Mixed,
            Self::Vless(_) => Kind::Vless,
            Self::Vmess(_) => Kind::Vmess,
        }
    }

    fn edit(&mut self, screen: &mut Screen, apply: form::Apply<'_, Self>) -> Result<()> {
        let title = self.kind().text();
        match self {
            Self::Mixed(value) => form::edit(
                screen,
                &title,
                value,
                Rc::new(move |value, screen| apply(&Self::Mixed(value.clone()), screen)),
                false,
            ),
            Self::Vless(value) => form::edit(
                screen,
                &title,
                value,
                Rc::new(move |value, screen| apply(&Self::Vless(value.clone()), screen)),
                false,
            ),
            Self::Vmess(value) => form::edit(
                screen,
                &title,
                value,
                Rc::new(move |value, screen| apply(&Self::Vmess(value.clone()), screen)),
                false,
            ),
        }
        .map(|_| ())
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Credentials {
    pub uuid: Uuid,
    pub password: String,
}

impl Credentials {
    fn new() -> Result<Self> {
        Ok(Self {
            uuid: Uuid::new_v4(),
            password: user::secret()?,
        })
    }
}

#[derive(Clone, Copy, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HttpVersion {
    #[default]
    Http1,
    Http2,
    Http3,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Mixed {
    pub http: Http,
    pub socks: Socks,
    pub udp: bool,
    pub user_level: Option<u32>,
}

impl Default for Mixed {
    fn default() -> Self {
        Self {
            http: Http::default(),
            socks: Socks::default(),
            udp: true,
            user_level: None,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Http {
    pub enabled: bool,
    pub versions: Vec<HttpVersion>,
    pub transparent: bool,
    pub idle_timeout: Option<String>,
    pub keep_alive: Option<String>,
    pub stream_receive_window: Option<u64>,
    pub connection_receive_window: Option<u64>,
    pub max_concurrent_streams: Option<u32>,
    pub initial_packet_size: Option<u16>,
    pub disable_path_mtu_discovery: bool,
}

impl Default for Http {
    fn default() -> Self {
        Self {
            enabled: true,
            versions: Vec::new(),
            transparent: false,
            idle_timeout: None,
            keep_alive: None,
            stream_receive_window: None,
            connection_receive_window: None,
            max_concurrent_streams: None,
            initial_packet_size: None,
            disable_path_mtu_discovery: false,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Socks {
    pub enabled: bool,
    pub udp_address: Option<String>,
}

impl Default for Socks {
    fn default() -> Self {
        Self {
            enabled: true,
            udp_address: None,
        }
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Tls {
    pub enabled: bool,
    pub server_name: Option<String>,
    pub alpn: Vec<String>,
    pub min_version: Option<String>,
    pub max_version: Option<String>,
    pub cipher_suites: Vec<String>,
    pub curves: Vec<String>,
    pub session_resumption: Option<bool>,
    pub reject_unknown_sni: Option<bool>,
    pub client_auth: ClientAuth,
    pub client_certificates: Vec<String>,
    pub client_certificate_files: Vec<String>,
    pub client_certificate_sha256: Vec<String>,
    pub client_public_key_sha256: Vec<String>,
    pub handshake_timeout: Option<String>,
    pub kernel_tx: Option<bool>,
    pub kernel_rx: Option<bool>,
    pub key_log: Option<String>,
    pub ech: Ech,
    pub reality: crate::reality::Server,
}

#[derive(Clone, Copy, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientAuth {
    #[default]
    None,
    Request,
    RequireAny,
    VerifyIfGiven,
    RequireAndVerify,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ech {
    pub enabled: bool,
    pub keys: Vec<String>,
    pub key_file: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Listen {
    pub address: String,
    pub interface: Option<String>,
    pub routing_mark: Option<u32>,
    pub namespace: Option<String>,
    pub reuse_address: Option<bool>,
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
    pub udp_timeout: Option<String>,
    pub proxy_protocol: bool,
    pub forwarded_sources: Vec<String>,
    pub socket_options: Vec<SocketOption>,
}

impl Default for Listen {
    fn default() -> Self {
        Self {
            address: "::".to_owned(),
            interface: None,
            routing_mark: None,
            namespace: None,
            reuse_address: None,
            ipv6_only: None,
            tcp_fast_open: None,
            tcp_multi_path: None,
            tcp_keep_alive: None,
            tcp_keep_alive_idle: None,
            tcp_keep_alive_interval: None,
            tcp_congestion: None,
            tcp_window: None,
            tcp_max_segment: None,
            tcp_user_timeout: None,
            udp_fragment: None,
            udp_timeout: None,
            proxy_protocol: false,
            forwarded_sources: Vec::new(),
            socket_options: Vec::new(),
        }
    }
}

fn edit(
    screen: &mut Screen,
    store: &Store,
    existing: bool,
    mut inbound: Inbound,
) -> Result<Option<Uuid>> {
    let apply: form::Apply<'_, Inbound> = Rc::new(|edited, screen| {
        if existing {
            screen.work("保存入站", &format!(" -- {}", edited.name), |progress| {
                store.update(progress, |config| {
                    let current = config
                        .inbounds
                        .iter_mut()
                        .find(|current| current.uuid == edited.uuid)
                        .ok_or("入站已被删除")?;
                    *current = edited.clone();
                    Ok(())
                })
            })?;
        }
        Ok(())
    });
    let mut protocols = BTreeMap::new();
    let mut selected = if existing { 0 } else { 3 };
    let mut notice = String::new();
    loop {
        let title = if existing {
            format!("入站 / {}", inbound.name)
        } else {
            "创建入站".to_owned()
        };
        let mut items: Vec<_> = [
            ("name", "名称", inbound.name.clone()),
            ("protocol", "协议", inbound.protocol.kind().text()),
            ("core", "核心", inbound.core.text()),
            ("address", "连接地址", inbound.address.clone()),
            ("ports", "端口", inbound.ports.clone()),
        ]
        .into_iter()
        .map(|(key, label, value)| {
            let mut item = Item::new(key, label.stylized());
            item.value = value;
            item
        })
        .collect();
        let mut users = Item::new("users", "用户支持".stylized());
        users.marker = inbound.users.marker();
        items.push(users);
        if inbound.users {
            items.push(Item::new("new-user", "新增用户".stylized()));
        } else {
            let mut credentials = Item::new("credentials", "入口凭据".stylized());
            credentials.value = inbound.credentials.as_ref().map_or_else(
                || "无".to_owned(),
                |credentials| credentials.uuid.to_string(),
            );
            credentials.detail = "Del 清除凭据".to_owned();
            items.push(credentials);
        }
        let mut tls = Item::new("tls", "TLS".stylized());
        tls.value = inbound.tls.enabled.text();
        let mut transport = Item::new("transport", "传输".stylized());
        transport.value = inbound.transport.text();
        items.extend([
            Item::new("options", "协议参数".stylized()),
            transport,
            tls,
            Item::new("listen", "监听".stylized()),
        ]);
        if existing && crate::keys::Keys::needed(&inbound) {
            items.push(Item::new("handshake", "握手资料".stylized()));
        }
        items.push(if existing {
            Item::new("delete", "删除入站".foreground(AnsiColor::BrightRed))
        } else {
            Item::new("create", "创建".stylized())
        });
        items.push(Item::new("back", "返回".stylized()));
        let menu = Menu {
            title: &title,
            heading: "",
            items: &items,
            help: "方向键 选择\n回车键 编辑\nEsc 返回",
        };
        let action = screen.select(&menu, &mut selected, &notice)?;
        let original = Rc::new(inbound.clone());
        macro_rules! edit {
            ($field:ident) => {
                inbound
                    .$field
                    .edit(
                        screen,
                        &menu,
                        selected,
                        form::map(original, apply.clone(), |inbound, value| {
                            inbound.$field = value
                        }),
                    )
                    .map(|_| ())
            };
        }
        let result = match action {
            Action::Back => return Ok(existing.then_some(inbound.uuid)),
            Action::Key(key)
                if key.code == KeyCode::Delete && items[selected].key == "credentials" =>
            {
                let mut edited = inbound.clone();
                edited.credentials = None;
                form::set(screen, &mut inbound, edited, &apply).map(|_| ())
            }
            Action::Select => match items[selected].key.as_str() {
                "name" => edit!(name),
                "address" => edit!(address),
                "ports" => edit!(ports),
                "core" => edit!(core),
                "users" => edit!(users),
                "new-user" => user::create(screen, store).map(|_| ()),
                "protocol" => {
                    let mut kind = inbound.protocol.kind();
                    protocols.insert(kind, inbound.protocol.clone());
                    let candidate = |kind: Kind| {
                        let mut edited = inbound.clone();
                        if kind != inbound.protocol.kind() {
                            edited.core = kind.core();
                        }
                        edited.protocol = protocols
                            .get(&kind)
                            .cloned()
                            .unwrap_or_else(|| kind.protocol());
                        edited
                    };
                    match kind.edit(
                        screen,
                        &menu,
                        selected,
                        Rc::new(|kind, screen| apply(&candidate(*kind), screen)),
                    ) {
                        Ok(true) => {
                            inbound = candidate(kind);
                            Ok(())
                        }
                        Ok(false) => Ok(()),
                        Err(error) => Err(error),
                    }
                }
                "credentials" => {
                    let creating = inbound.credentials.is_none();
                    let credentials = match &inbound.credentials {
                        Some(credentials) => Ok(credentials.clone()),
                        None => Credentials::new(),
                    };
                    credentials.and_then(|mut credentials| {
                        if form::edit(
                            screen,
                            "入口凭据",
                            &mut credentials,
                            form::map(original, apply.clone(), |inbound, value| {
                                inbound.credentials = Some(value)
                            }),
                            creating,
                        )? {
                            inbound.credentials = Some(credentials);
                        }
                        Ok(())
                    })
                }
                "options" => inbound.protocol.edit(
                    screen,
                    form::map(original, apply.clone(), |inbound, value| {
                        inbound.protocol = value
                    }),
                ),
                "tls" => edit!(tls),
                "transport" => edit!(transport),
                "listen" => edit!(listen),
                "handshake" => store.load().and_then(|config| {
                    let source = config
                        .inbounds
                        .iter()
                        .find(|source| source.uuid == inbound.uuid)
                        .ok_or("入站已被删除")?;
                    let keys = crate::keys::Keys::resolve(source, config.keys.get(&inbound.uuid))?;
                    let keys = if config.keys.get(&inbound.uuid) == Some(&keys) {
                        keys
                    } else {
                        screen.work(
                            "生成握手资料",
                            &format!(" -- {}", inbound.name),
                            |progress| {
                                store.update(progress, |config| {
                                    let source = config
                                        .inbounds
                                        .iter()
                                        .find(|source| source.uuid == inbound.uuid)
                                        .ok_or("入站已被删除")?;
                                    let keys = crate::keys::Keys::resolve(
                                        source,
                                        config.keys.get(&inbound.uuid),
                                    )?;
                                    config.keys.insert(inbound.uuid, keys.clone());
                                    Ok(keys)
                                })
                            },
                        )?
                    };
                    keys.show(source, screen)
                }),
                "create" => {
                    let result = screen.work(
                        "保存入站",
                        &format!(" -- {}", inbound.name),
                        |progress| {
                            store.update(progress, |config| {
                                let mut value = inbound.clone();
                                if value.name.trim().is_empty() {
                                    value.name = value.summary();
                                }
                                config.inbounds.push(value);
                                Ok(())
                            })
                        },
                    );
                    if result.is_ok() {
                        return Ok(Some(inbound.uuid));
                    }
                    result
                }
                "delete" => {
                    let result = screen.work(
                        "删除入站",
                        &format!(" -- {}", inbound.name),
                        |progress| {
                            store.update(progress, |config| {
                                config.inbounds.retain(|value| value.uuid != inbound.uuid);
                                Ok(())
                            })
                        },
                    );
                    if result.is_ok() {
                        return Ok(None);
                    }
                    result
                }
                _ => return Ok(existing.then_some(inbound.uuid)),
            },
            _ => continue,
        };
        notice = result
            .err()
            .map_or_else(String::new, |error| error.to_string());
    }
}

pub fn create(
    screen: &mut Screen,
    store: &Store,
    menu: &Menu<'_>,
    selected: usize,
) -> Result<Option<Uuid>> {
    match Kind::create(screen, menu, selected, Rc::new(|_, _| Ok(())))? {
        Some(kind) => edit(screen, store, false, Inbound::new(kind)),
        None => Ok(None),
    }
}

pub fn run(screen: &mut Screen, store: &Store) -> Result<()> {
    let mut selected = 0;
    let mut notice = String::new();
    loop {
        let config = store.load()?;
        let mut items: Vec<_> = config
            .inbounds
            .iter()
            .map(|inbound| {
                let mut item = Item::new(inbound.uuid.to_string(), inbound.name.clone().stylized());
                item.value = inbound.summary();
                item
            })
            .collect();
        items.extend([
            Item::new("new", "创建入站".stylized()),
            Item::new("back", "返回".stylized()),
        ]);
        let menu = Menu {
            title: "入站",
            heading: "",
            items: &items,
            help: "方向键 选择\n回车键 确定\nEsc 返回",
        };
        let result = match screen.select(&menu, &mut selected, &notice)? {
            Action::Back => return Ok(()),
            Action::Select if selected < config.inbounds.len() => {
                edit(screen, store, true, config.inbounds[selected].clone()).map(|_| ())
            }
            Action::Select if selected == config.inbounds.len() => {
                create(screen, store, &menu, selected).map(|_| ())
            }
            Action::Select => return Ok(()),
            _ => continue,
        };
        notice = result
            .err()
            .map_or_else(String::new, |error| error.to_string());
    }
}

choices!(Core {
    Xray: "xray" => "Xray",
    SingBox: "sing-box" => "sing-box",
    Mihomo: "mihomo" => "Mihomo",
});

choices!(Kind {
    Mixed: "mixed" => "HTTP/SOCKS",
    Vless: "vless" => "VLESS",
    Vmess: "vmess" => "VMess",
});

choices!(HttpVersion {
    Http1: "http1" => "HTTP/1.1",
    Http2: "http2" => "HTTP/2",
    Http3: "http3" => "HTTP/3",
});

choices!(ClientAuth {
    None: "none" => "不要求",
    Request: "request" => "请求证书",
    RequireAny: "require-any" => "要求提供证书",
    VerifyIfGiven: "verify-if-given" => "提供时验证",
    RequireAndVerify: "require-and-verify" => "要求提供并验证",
});

fields!(Credentials {
    uuid: "UUID",
    password: "主密码",
});

fields!(Mixed {
    http: "HTTP",
    socks: "SOCKS",
    udp: "UDP",
    user_level: "用户等级",
});

fields!(Http {
    enabled: "启用",
    versions: "版本",
    transparent: "透明请求",
    idle_timeout: "空闲超时",
    keep_alive: "保活间隔",
    stream_receive_window: "流接收窗口",
    connection_receive_window: "连接接收窗口",
    max_concurrent_streams: "并发流数",
    initial_packet_size: "初始数据包大小",
    disable_path_mtu_discovery: "关闭路径 MTU 探测",
});

fields!(Socks {
    enabled: "启用",
    udp_address: "UDP 公布地址",
});

fields!(Tls {
    enabled: "启用",
    server_name: "服务名",
    alpn: "ALPN",
    min_version: "最低版本",
    max_version: "最高版本",
    cipher_suites: "密码套件",
    curves: "曲线",
    session_resumption: "会话复用",
    reject_unknown_sni: "匹配 SNI",
    client_auth: "客户端证书",
    client_certificates: "客户端信任证书",
    client_certificate_files: "客户端信任证书文件",
    client_certificate_sha256: "客户端证书 SHA-256",
    client_public_key_sha256: "客户端公钥 SHA-256",
    handshake_timeout: "握手超时",
    kernel_tx: "内核发送",
    kernel_rx: "内核接收",
    key_log: "密钥日志文件",
    ech: "ECH",
    reality: "REALITY",
});

fields!(Ech {
    enabled: "启用",
    keys: "密钥",
    key_file: "密钥文件",
});

fields!(Listen {
    address: "地址",
    interface: "接口",
    routing_mark: "路由标记",
    namespace: "网络命名空间",
    reuse_address: "复用地址",
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
    udp_timeout: "UDP 超时",
    proxy_protocol: "PROXY protocol",
    forwarded_sources: "转发来源",
    socket_options: "自定义套接字选项",
});
