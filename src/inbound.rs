use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv6Addr},
    path::Path,
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
    endpoint::Endpoint,
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
    pub core: Core,
    pub users: bool,
    pub credentials: Option<Credentials>,
    pub protocol: Protocol,
    #[serde(default)]
    pub transport: Transport,
    pub security: Security,
    pub listen: Listen,
}

impl Inbound {
    fn new(kind: Kind) -> Self {
        Self {
            uuid: Uuid::new_v4(),
            name: String::new(),
            core: kind.core(),
            users: !matches!(kind, Kind::Forward),
            credentials: None,
            protocol: kind.protocol(),
            transport: Transport::default(),
            security: if matches!(kind, Kind::Mixed | Kind::Shadowsocks | Kind::Forward) {
                Security::None
            } else {
                Security::Tls(Tls::default())
            },
            listen: Listen {
                ports: kind.port().to_string(),
                ..Listen::default()
            },
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err("入站名称不能为空".into());
        }
        if self.listen.enabled && self.listen.host.trim().is_empty() {
            return Err("连接地址不能为空".into());
        }
        if !self.listen.host.is_empty() && !is_ip(&self.listen.host) {
            url::Host::parse(&self.listen.host)
                .map_err(|error| format!("连接地址格式不正确：{error}"))?;
        }
        let address = &self.listen.address;
        if self.listen.enabled
            && !is_ip(address)
            && address != "localhost"
            && !Path::new(address).is_absolute()
            && !address.starts_with('@')
        {
            return Err("监听地址需要填写 IP、localhost 或套接字路径".into());
        }
        self.ports()?;
        let kind = self.protocol.kind();
        if !kind.cores().contains(&self.core) {
            return Err(format!("{} 入站没有 {} 实现", kind.text(), self.core.text()).into());
        }
        if !self.securities().contains(&self.security.index()) {
            return Err(format!("{} 入站不支持 {} 加密", kind.text(), self.security.text()).into());
        }
        if !self.supports_transport(&self.transport) {
            return Err(format!(
                "{} 的 {} 入站不能使用 {} 传输",
                self.core.text(),
                kind.text(),
                self.transport.text()
            )
            .into());
        }
        if let Some(credentials) = &self.credentials {
            user::password(&credentials.password)?;
        }
        Ok(())
    }

    fn securities(&self) -> &'static [usize] {
        match (self.protocol.kind(), self.core) {
            (Kind::Hysteria2, _) => &[1],
            (Kind::AnyTls, Core::Mihomo) => &[0, 1],
            (Kind::Shadowsocks | Kind::Forward, Core::SingBox | Core::Mihomo) => &[0],
            _ => &[0, 1, 2],
        }
    }

    fn transports(&self) -> bool {
        match self.protocol.kind() {
            Kind::Hysteria2 | Kind::AnyTls => false,
            Kind::Mixed | Kind::Shadowsocks | Kind::Forward => self.core == Core::Xray,
            Kind::Vless | Kind::Vmess | Kind::Trojan => true,
        }
    }

    fn supports_transport(&self, transport: &Transport) -> bool {
        if transport.is_default() {
            return true;
        }
        self.transports()
            && match self.core {
                Core::Xray => {
                    !matches!(transport, Transport::Quic)
                        && (self.security.reality().is_none() || transport.xray_reality())
                }
                Core::SingBox => match transport {
                    Transport::Kcp(_) | Transport::XHttp(_) => false,
                    Transport::Quic => matches!(self.security, Security::Tls(_)),
                    _ => true,
                },
                Core::Mihomo => {
                    matches!(transport, Transport::WebSocket(_) | Transport::Grpc(_))
                        || matches!(
                            (&self.protocol, transport),
                            (Protocol::Vless(_), Transport::XHttp(_))
                                | (Protocol::Vmess(_), Transport::Kcp(_))
                        )
                }
            }
    }

    fn effective(&self) -> Self {
        let mut value = self.clone();
        let modes = value.securities();
        if !modes.contains(&value.security.index()) {
            value.security = match modes[0] {
                1 => Security::Tls(Tls::default()),
                _ => Security::None,
            };
        }
        if !value.supports_transport(&value.transport) {
            value.transport = Transport::default();
        }
        value.users &= value.protocol.users();
        if value.users
            || !value.protocol.users()
            || matches!(&value.protocol, Protocol::Shadowsocks(ss) if ss.cipher == crate::shadowsocks::Cipher::None)
        {
            value.credentials = None;
        }
        value
    }

    pub fn quic(&self) -> bool {
        match &self.security {
            Security::Tls(tls) => self.transport.udp(true, &tls.alpn),
            _ => self.transport.udp(false, &[]),
        }
    }

    pub fn ports(&self) -> Result<BTreeSet<u16>> {
        if !self.listen.enabled && self.listen.ports.trim().is_empty() {
            return Ok(BTreeSet::from([self.protocol.kind().port()]));
        }
        crate::connection::ports(&self.listen.ports)
    }

    pub(crate) fn summary(&self) -> String {
        let kind = self.protocol.kind().text();
        match self.listen.text() {
            text if text.is_empty() => kind,
            text => format!("{kind} {text}"),
        }
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
    Trojan,
    Shadowsocks,
    Hysteria2,
    AnyTls,
    Forward,
}

impl Kind {
    fn port(self) -> u16 {
        match self {
            Self::Mixed => 1080,
            Self::Shadowsocks => 8388,
            _ => 443,
        }
    }

    fn core(self) -> Core {
        match self {
            Self::Mixed
            | Self::Vmess
            | Self::Trojan
            | Self::Shadowsocks
            | Self::Hysteria2
            | Self::AnyTls
            | Self::Forward => Core::SingBox,
            Self::Vless => Core::Xray,
        }
    }

    fn cores(self) -> &'static [Core] {
        match self {
            Self::AnyTls => &[Core::SingBox, Core::Mihomo],
            _ => &[Core::Xray, Core::SingBox, Core::Mihomo],
        }
    }

    fn protocol(self) -> Protocol {
        match self {
            Self::Mixed => Protocol::Mixed(Mixed::default()),
            Self::Vless => Protocol::Vless(crate::vless::Server::default()),
            Self::Vmess => Protocol::Vmess(crate::vmess::Server::default()),
            Self::Trojan => Protocol::Trojan(crate::trojan::Server::default()),
            Self::Shadowsocks => Protocol::Shadowsocks(crate::shadowsocks::Server::default()),
            Self::Hysteria2 => Protocol::Hysteria2(Box::default()),
            Self::AnyTls => Protocol::AnyTls(crate::anytls::Server::default()),
            Self::Forward => Protocol::Forward(crate::forward::Server::default()),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Protocol {
    Mixed(Mixed),
    Vless(crate::vless::Server),
    Vmess(crate::vmess::Server),
    Trojan(crate::trojan::Server),
    Shadowsocks(crate::shadowsocks::Server),
    Hysteria2(Box<crate::hysteria::Server>),
    #[serde(rename = "anytls")]
    AnyTls(crate::anytls::Server),
    Forward(crate::forward::Server),
}

impl Protocol {
    pub fn responds(&self) -> bool {
        matches!(self, Self::Hysteria2(value) if value.masquerade.is_some())
    }

    pub fn fallbacks(&self) -> &[Fallback] {
        match self {
            Self::Vless(value) => &value.fallbacks,
            Self::Trojan(value) => &value.fallbacks,
            _ => &[],
        }
    }

    pub fn fallbacks_mut(&mut self) -> Option<&mut Vec<Fallback>> {
        match self {
            Self::Vless(value) => Some(&mut value.fallbacks),
            Self::Trojan(value) => Some(&mut value.fallbacks),
            _ => None,
        }
    }

    pub fn routing(&self) -> bool {
        self.destination().is_none()
    }

    pub fn users(&self) -> bool {
        !matches!(self, Self::Forward(_))
    }

    pub fn needs_credentials(&self) -> bool {
        self.users()
            && !matches!(self, Self::Mixed(_))
            && !matches!(self, Self::Shadowsocks(value) if value.cipher == crate::shadowsocks::Cipher::None)
            && self.fallbacks().is_empty()
            && !self.responds()
    }

    pub fn destination(&self) -> Option<crate::route::Destination> {
        match self {
            Self::Forward(value) => Some(value.outbound),
            _ => None,
        }
    }

    fn kind(&self) -> Kind {
        match self {
            Self::Mixed(_) => Kind::Mixed,
            Self::Vless(_) => Kind::Vless,
            Self::Vmess(_) => Kind::Vmess,
            Self::Trojan(_) => Kind::Trojan,
            Self::Shadowsocks(_) => Kind::Shadowsocks,
            Self::Hysteria2(_) => Kind::Hysteria2,
            Self::AnyTls(_) => Kind::AnyTls,
            Self::Forward(_) => Kind::Forward,
        }
    }

    fn edit(&mut self, screen: &mut Screen) -> Result<()> {
        let title = self.kind().text();
        match self {
            Self::Mixed(value) => form::edit(screen, &title, value),
            Self::Vless(value) => form::edit(screen, &title, value),
            Self::Vmess(value) => form::edit(screen, &title, value),
            Self::Trojan(value) => form::edit(screen, &title, value),
            Self::Shadowsocks(value) => form::edit(screen, &title, value),
            Self::Forward(value) => form::edit(screen, &title, value),
            Self::Hysteria2(value) => form::edit(screen, &title, value.as_mut()),
            Self::AnyTls(value) => form::edit(screen, &title, value),
        }
        .map(|_| ())
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Fallback {
    pub server_name: Option<String>,
    pub alpn: Option<String>,
    pub path: Option<String>,
    pub target: Endpoint,
    pub network: Option<String>,
    pub proxy_protocol: Option<u8>,
}

impl form::Form for Fallback {
    fn fields(&mut self, defaults: Self) -> form::Fields<'_> {
        let address = matches!(self.target, Endpoint::Address(_));
        let mut fields = Vec::new();
        macro_rules! field {
            ($name:ident, $label:literal) => {
                fields.push(form::field(
                    stringify!($name),
                    $label,
                    &mut self.$name,
                    defaults.$name,
                ));
            };
        }
        field!(server_name, "服务名");
        field!(alpn, "ALPN");
        field!(path, "路径");
        field!(target, "目标");
        if address {
            field!(network, "网络类型");
            field!(proxy_protocol, "PROXY protocol 版本");
        }
        fields
    }
}

form::group!(Fallback);

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
    pub ech: Option<Ech>,
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
    pub keys: Vec<String>,
    pub key_file: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Listen {
    pub enabled: bool,
    pub host: String,
    pub ports: String,
    pub address: String,
    pub socket: Socket,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Socket {
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

impl Listen {
    fn text(&self) -> String {
        if !self.enabled || self.host.is_empty() {
            return String::new();
        }
        let host = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.ports.trim().is_empty() {
            return host;
        }
        format!("{host}:{}", self.ports)
    }
}

impl Default for Listen {
    fn default() -> Self {
        Self {
            enabled: true,
            host: String::new(),
            ports: String::new(),
            address: "::".to_owned(),
            socket: Socket::default(),
        }
    }
}

fn edit(
    screen: &mut Screen,
    store: &Store,
    existing: bool,
    mut inbound: Inbound,
) -> Result<Option<Uuid>> {
    let mut protocols = BTreeMap::new();
    let saved = serde_json::to_vec(&inbound)?;
    let initial = serde_json::to_vec(&inbound.effective())?;
    let mut selected = 0;
    let mut opening = !existing;
    let mut notice = String::new();
    loop {
        let mut active = inbound.effective();
        let changed = !existing || serde_json::to_vec(&active)? != initial;
        let title = if existing {
            format!("入站 / {}", inbound.name)
        } else {
            "创建入站".to_owned()
        };
        let mut items: Vec<_> = [
            ("name", "名称", inbound.name.clone()),
            ("protocol", "协议", inbound.protocol.kind().text()),
            ("core", "核心", inbound.core.text()),
        ]
        .into_iter()
        .map(|(key, label, value)| {
            let mut item = Item::new(key, label.stylized());
            item.value = value;
            item
        })
        .collect();
        if let Some(destination) = inbound.protocol.destination() {
            let mut item = Item::new("outbound", "出站".stylized());
            item.value = destination.text();
            items.push(item);
        }
        if inbound.protocol.users() {
            let mut users = Item::new("users", "用户支持".stylized());
            users.marker = inbound.users.marker();
            items.push(users);
            if !inbound.users
                && !matches!(&inbound.protocol, Protocol::Shadowsocks(value) if value.cipher == crate::shadowsocks::Cipher::None)
            {
                let (label, value) = match &inbound.protocol {
                    Protocol::Mixed(_) => (
                        "入口凭据",
                        inbound.credentials.as_ref().map(|c| c.uuid.to_string()),
                    ),
                    Protocol::Vless(_) | Protocol::Vmess(_) => (
                        "入口 UUID",
                        inbound.credentials.as_ref().map(|c| c.uuid.to_string()),
                    ),
                    _ => (
                        "入口密码",
                        inbound.credentials.as_ref().map(|c| c.password.clone()),
                    ),
                };
                let mut credentials = Item::new("credentials", label.stylized());
                credentials.value = value.unwrap_or_else(|| "无".to_owned());
                if inbound.credentials.is_some() && !inbound.protocol.needs_credentials() {
                    credentials.detail = "Del 清除凭据".to_owned();
                }
                items.push(credentials);
            }
        }
        let mut security = Item::new("security", "加密".stylized());
        security.value = active.security.text();
        let mut transport = Item::new("transport", "传输".stylized());
        transport.value = active.transport.text();
        let mut listen = Item::new("listen", "监听".stylized());
        listen.value = match inbound.listen.text() {
            text if text.is_empty() => inbound.listen.enabled.text(),
            text => text,
        };
        if std::mem::take(&mut opening) {
            selected = items.len();
        }
        items.push(listen);
        items.push(Item::new("options", "协议参数".stylized()));
        if inbound.transports() {
            items.push(transport);
        }
        if inbound.securities() != [0] {
            items.push(security);
        }
        let actions = items.len();
        if !changed && inbound.listen.enabled {
            items.push(Item::new("export", "连接资料".stylized()));
        }
        if !changed && crate::keys::Keys::needed(&inbound) {
            items.push(Item::new("handshake", "握手资料".stylized()));
        }
        items.push(if existing && changed {
            Item::new("apply", "确定".stylized())
        } else if existing {
            Item::new("delete", "删除入站".foreground(AnsiColor::BrightRed))
        } else {
            Item::new("create", "创建".stylized())
        });
        items.push(Item::new(
            "back",
            if changed { "取消" } else { "返回" }.stylized(),
        ));
        items[actions].gap = true;
        let menu = Menu {
            title: &title,
            heading: "",
            items: &items,
            help: if changed {
                "方向键 选择\n回车键 编辑\nEsc 取消"
            } else {
                "方向键 选择\n回车键 编辑\nEsc 返回"
            },
        };
        let action = screen.select(&menu, &mut selected, &notice)?;
        if matches!(action, Action::Back)
            || matches!(action, Action::Select) && items[selected].key == "back"
        {
            return Ok(existing.then_some(inbound.uuid));
        }
        macro_rules! edit {
            ($field:ident) => {
                inbound.$field.edit(screen, &menu, selected).map(|_| ())
            };
        }
        let result = match action {
            Action::Back => return Ok(existing.then_some(inbound.uuid)),
            Action::Key(key)
                if key.code == KeyCode::Delete
                    && items[selected].key == "credentials"
                    && !inbound.protocol.needs_credentials() =>
            {
                inbound.credentials = None;
                Ok(())
            }
            Action::Select => match items[selected].key.as_str() {
                "export" => crate::profile::copy(screen, store, Some(inbound.uuid), None),
                "name" => edit!(name),
                "core" => {
                    let kind = inbound.protocol.kind();
                    let choices: Vec<_> = Core::choices()
                        .into_iter()
                        .filter(|(_, _, core)| kind.cores().contains(core))
                        .collect();
                    let current = choices
                        .iter()
                        .position(|(_, _, core)| *core == inbound.core)
                        .unwrap_or_default();
                    let title = format!("{} / 核心", menu.title);
                    form::choose(&mut inbound.core, screen, &title, &choices, current).map(|_| ())
                }
                "users" => {
                    if inbound.users
                        && inbound.credentials.is_none()
                        && inbound.protocol.needs_credentials()
                    {
                        inbound.credentials = Some(Credentials::new()?);
                    }
                    inbound.users = !inbound.users;
                    Ok(())
                }
                "outbound" => {
                    let current = inbound.protocol.destination().unwrap();
                    let progress = crate::progress::Progress::default();
                    crate::route::destination(
                        screen,
                        store,
                        current,
                        false,
                        |config, destination| {
                            crate::native::available(store, config, &active, destination, &progress)
                        },
                    )
                    .map(|selection| {
                        if let Some(destination) = selection
                            && let Protocol::Forward(value) = &mut inbound.protocol
                        {
                            value.outbound = destination;
                        }
                    })
                }
                "protocol" => {
                    let mut kind = inbound.protocol.kind();
                    kind.edit(screen, &menu, selected).map(|edited| {
                        if edited {
                            protocols.insert(
                                inbound.protocol.kind(),
                                (inbound.core, inbound.protocol.clone()),
                            );
                            (inbound.core, inbound.protocol) = protocols
                                .remove(&kind)
                                .unwrap_or_else(|| (kind.core(), kind.protocol()));
                        }
                    })
                }
                "credentials" => {
                    let credentials = match &inbound.credentials {
                        Some(credentials) => Ok(credentials.clone()),
                        None => Credentials::new(),
                    };
                    credentials.and_then(|mut credentials| {
                        let changed = match inbound.protocol {
                            Protocol::Mixed(_) => {
                                form::edit(screen, "入口凭据", &mut credentials)?
                                    || inbound.credentials.is_none()
                            }
                            Protocol::Vless(_) | Protocol::Vmess(_) => {
                                credentials.uuid.edit(screen, &menu, selected)?
                            }
                            _ => credentials.password.edit(screen, &menu, selected)?,
                        };
                        if changed {
                            inbound.credentials = Some(credentials);
                        }
                        Ok(())
                    })
                }
                "options" => inbound.protocol.edit(screen),
                "security" => {
                    let title = format!("{} / 加密", menu.title);
                    active
                        .security
                        .choose(screen, &title, inbound.securities())
                        .map(|edited| {
                            if edited {
                                inbound.security = active.security;
                            }
                        })
                }
                "transport" => {
                    let mut transport = active.transport.clone();
                    transport
                        .choose(screen, &menu, selected, |value| {
                            active.supports_transport(value)
                        })
                        .map(|edited| {
                            if edited {
                                inbound.transport = transport;
                            }
                        })
                }
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
                                store.update(progress, |config, _| {
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
                "create" | "apply" => {
                    let result = screen.work("保存入站", &inbound.name, |progress| {
                        store.update(progress, |config, _| {
                            let mut value = active.clone();
                            if value.name.trim().is_empty() {
                                value.name = value.summary();
                            }
                            if existing {
                                let current = config
                                    .inbounds
                                    .iter_mut()
                                    .find(|current| current.uuid == inbound.uuid)
                                    .ok_or("入站已被删除")?;
                                if serde_json::to_vec(&*current)? != saved {
                                    return Err("入站已在其他编辑中更改，请重新打开".into());
                                }
                                *current = value;
                            } else {
                                config.inbounds.push(value);
                            }
                            Ok(())
                        })
                    });
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
                            store.update(progress, |config, _| {
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

pub fn select(
    screen: &mut Screen,
    store: &Store,
    current: Option<Uuid>,
    filter: impl Fn(&Inbound) -> bool,
) -> Result<Option<Uuid>> {
    loop {
        let config = store.load()?;
        let inbounds: Vec<_> = config
            .inbounds
            .iter()
            .filter(|inbound| filter(inbound))
            .collect();
        let mut items: Vec<_> = inbounds
            .iter()
            .map(|inbound| {
                let mut item = Item::new(inbound.uuid.to_string(), inbound.name.clone().stylized());
                item.value = inbound.summary();
                item
            })
            .collect();
        items.push(Item::new("new", "创建入站".stylized()));
        let selected = inbounds
            .iter()
            .position(|inbound| Some(inbound.uuid) == current)
            .unwrap_or(0);
        let menu = Menu {
            title: "选择入站",
            heading: "",
            items: &items,
            help: "",
        };
        match screen.search(menu.title, &items, selected)? {
            Some(index) if index < inbounds.len() => return Ok(Some(inbounds[index].uuid)),
            Some(index) => {
                if let Some(uuid) = create(screen, store, &menu, index)?
                    && store
                        .load()?
                        .inbounds
                        .iter()
                        .any(|inbound| inbound.uuid == uuid && filter(inbound))
                {
                    return Ok(Some(uuid));
                }
            }
            None => return Ok(None),
        }
    }
}

pub fn create(
    screen: &mut Screen,
    store: &Store,
    menu: &Menu<'_>,
    selected: usize,
) -> Result<Option<Uuid>> {
    match Kind::create(screen, menu, selected)? {
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
    Trojan: "trojan" => "Trojan",
    Shadowsocks: "shadowsocks" => "Shadowsocks",
    Hysteria2: "hysteria2" => "Hysteria 2",
    AnyTls: "anytls" => "AnyTLS",
    Forward: "forward" => "TCP/UDP 转发",
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
} groups {
    certificates: "客户端认证" => [client_auth, client_certificates, client_certificate_files, client_certificate_sha256, client_public_key_sha256],
    protocol: "版本与密码" => [min_version, max_version, cipher_suites, curves],
    handshake: "握手" => [session_resumption, reject_unknown_sni, handshake_timeout, kernel_tx, kernel_rx, key_log],
});

fields!(Ech {
    keys: "密钥",
    key_file: "密钥文件",
});

fields!(Listen {
    host: "连接地址",
    ports: "端口",
    address: "绑定地址",
    enabled: "启用",
    socket: ..,
});

fields!(Socket {
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
} groups {
    tcp: "TCP" => [tcp_fast_open, tcp_multi_path, tcp_keep_alive, tcp_keep_alive_idle, tcp_keep_alive_interval, tcp_congestion, tcp_window, tcp_max_segment, tcp_user_timeout],
    udp: "UDP" => [udp_fragment, udp_timeout],
    binding: "绑定与路由" => [routing_mark, namespace, reuse_address, ipv6_only, socket_options],
    forwarding: "来源信息" => [proxy_protocol, forwarded_sources],
});

pub type Security = crate::security::Security<Tls, crate::reality::Server>;
