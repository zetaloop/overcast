use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    rc::Rc,
};

use serde::Serialize;
use uuid::Uuid;

use crate::{
    Result,
    config::Store,
    graph::{Entry, Graph, Network},
    inbound::{Core, HttpVersion, Inbound, Protocol},
    progress::Progress,
};

use super::{
    binding::{Address, Binding},
    certificate_name,
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Mode {
    Http1,
    Http2,
    Http3,
    Socks,
    SocksUdp,
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    ShadowsocksUdp,
    Forward,
    ForwardUdp,
}

impl Mode {
    fn wire(self) -> Network {
        match self {
            Self::Http3 | Self::SocksUdp | Self::ShadowsocksUdp | Self::ForwardUdp => Network::Udp,
            _ => Network::Tcp,
        }
    }

    fn family(self) -> &'static str {
        match self {
            Self::Http1 | Self::Http2 | Self::Http3 => "HTTP/HTTPS",
            Self::Socks | Self::SocksUdp => "SOCKS",
            Self::Vless => "VLESS",
            Self::Vmess => "VMess",
            Self::Trojan => "Trojan",
            Self::Shadowsocks | Self::ShadowsocksUdp => "Shadowsocks",
            Self::Forward | Self::ForwardUdp => "TCP/UDP 转发",
        }
    }

    fn carries(self, core: Core, network: Network) -> bool {
        match self {
            Self::SocksUdp | Self::ShadowsocksUdp | Self::ForwardUdp => network == Network::Udp,
            Self::Forward => network == Network::Tcp,
            Self::Socks => network == Network::Tcp || core != Core::Mihomo,
            Self::Vless | Self::Vmess | Self::Trojan | Self::Shadowsocks => true,
            _ => network == Network::Tcp || core == Core::SingBox,
        }
    }
}

#[derive(Clone)]
pub struct Member {
    pub entry: usize,
    source: Rc<Inbound>,
    modes: BTreeSet<Mode>,
    pub(super) users: Rc<BTreeMap<Uuid, String>>,
    pub(super) binding: Binding,
}

impl Member {
    pub fn protocol(&self) -> Option<&'static str> {
        if self.source.core != Core::Mihomo || !matches!(self.source.protocol, Protocol::Mixed(_)) {
            return None;
        }
        let families: BTreeSet<_> = self.modes.iter().map(|mode| mode.family()).collect();
        (families.len() == 1).then(|| *families.first().unwrap())
    }

    pub fn carries(&self, network: Network) -> bool {
        self.modes
            .iter()
            .any(|mode| mode.carries(self.source.core, network))
    }

    pub fn internal(&self, port: u16) -> Result<Listener> {
        let mut source = self.source.as_ref().clone();
        source.ports = port.to_string();
        source.listen = crate::inbound::Listen {
            address: "127.0.0.1".to_owned(),
            ..crate::inbound::Listen::default()
        };
        let binding = Binding::local(port, self.binding.networks.clone())?;
        Ok(Listener {
            source,
            members: vec![self.clone()],
            users: self.users.as_ref().clone(),
            binding,
        })
    }
}

pub fn accepts(source: &Inbound, wire: Network, network: Network) -> bool {
    let udp = source.transport.udp(
        source.tls.enabled && !source.tls.reality.enabled,
        &source.tls.alpn,
    );
    modes(source, &[network]).iter().any(|mode| {
        mode.carries(source.core, network)
            && if udp {
                wire == Network::Udp
            } else {
                wire == mode.wire()
            }
    })
}

fn modes(source: &Inbound, networks: &[Network]) -> BTreeSet<Mode> {
    let mut modes = BTreeSet::new();
    match &source.protocol {
        Protocol::Mixed(protocol) => {
            if protocol.http.enabled {
                let versions = if protocol.http.versions.is_empty() {
                    if source.core == Core::SingBox {
                        vec![HttpVersion::Http1, HttpVersion::Http2]
                    } else {
                        vec![HttpVersion::Http1]
                    }
                } else {
                    protocol.http.versions.clone()
                };
                modes.extend(versions.into_iter().map(|version| match version {
                    HttpVersion::Http1 => Mode::Http1,
                    HttpVersion::Http2 => Mode::Http2,
                    HttpVersion::Http3 => Mode::Http3,
                }));
            }
            if protocol.socks.enabled {
                modes.insert(Mode::Socks);
                if source.core == Core::Mihomo && networks.contains(&Network::Udp) {
                    modes.insert(Mode::SocksUdp);
                }
            }
        }
        Protocol::Vless(_) => {
            modes.insert(Mode::Vless);
        }
        Protocol::Vmess(_) => {
            modes.insert(Mode::Vmess);
        }
        Protocol::Trojan(_) => {
            modes.insert(Mode::Trojan);
        }
        Protocol::Shadowsocks(value) => {
            if value.tcp {
                modes.insert(Mode::Shadowsocks);
            }
            if value.udp && networks.contains(&Network::Udp) {
                modes.insert(Mode::ShadowsocksUdp);
            }
        }
        Protocol::Forward(_) => {
            if networks.contains(&Network::Tcp) {
                modes.insert(Mode::Forward);
            }
            if networks.contains(&Network::Udp) {
                modes.insert(Mode::ForwardUdp);
            }
        }
    }
    modes
}

pub struct Listener {
    pub source: Inbound,
    pub members: Vec<Member>,
    pub users: BTreeMap<Uuid, String>,
    pub binding: Binding,
}

pub struct Group<'a> {
    pub entries: BTreeSet<usize>,
    pub listeners: Vec<&'a Listener>,
}

pub fn related<'a>(
    listeners: impl Iterator<Item = &'a Listener>,
    progress: &Progress,
) -> Result<Vec<Group<'a>>> {
    let mut groups: Vec<Group<'a>> = Vec::new();
    for listener in listeners {
        progress.check()?;
        let mut entries: BTreeSet<_> = listener.members.iter().map(|member| member.entry).collect();
        let mut listeners = vec![listener];
        let connected: Vec<_> = groups
            .extract_if(.., |group| !group.entries.is_disjoint(&entries))
            .collect();
        for mut group in connected {
            entries.extend(group.entries);
            listeners.append(&mut group.listeners);
        }
        groups.push(Group { entries, listeners });
    }
    Ok(groups)
}

pub fn build(
    store: &Store,
    graph: &mut Graph<'_>,
    keys: &BTreeMap<Uuid, crate::keys::Keys>,
    progress: &Progress,
) -> Result<Vec<Listener>> {
    let step = progress.activity("分配监听资源");
    let mut groups: BTreeMap<Option<u16>, Vec<Vec<Member>>> = BTreeMap::new();
    for (index, entry) in graph.entries.iter().enumerate() {
        progress.check()?;
        let mut source = entry.inbound.clone();
        if source.tls.enabled && source.tls.reality.enabled {
            if let Some(keys) = keys
                .get(&source.uuid)
                .and_then(|keys| keys.reality.as_ref())
            {
                if source.tls.reality.private_key.is_none() {
                    source.tls.reality.private_key = Some(keys.private_key.clone());
                }
                if source.tls.reality.short_ids.is_empty() {
                    source.tls.reality.short_ids = keys.short_ids.clone();
                }
                if source.tls.reality.signature_seed.is_none() {
                    source.tls.reality.signature_seed = keys.signature_seed.clone();
                }
            }
            source.tls.reality.target = source.tls.reality.address()?;
            source.tls.reality.server_names = source
                .tls
                .reality
                .names(source.tls.server_name.as_deref())?;
            source
                .tls
                .reality
                .short_ids
                .iter_mut()
                .for_each(|value| value.make_ascii_lowercase());
            source.tls.reality.short_ids.sort();
            source.tls.reality.short_ids.dedup();
            if !source.tls.reality.signature {
                source.tls.reality.signature_seed = None;
            }
        } else {
            source.tls.reality = crate::reality::Server::default();
        }
        if let Protocol::Vless(value) = &mut source.protocol
            && let Some(encryption) = &mut value.encryption
            && encryption.private_keys.is_empty()
            && let Some(keys) = keys
                .get(&source.uuid)
                .and_then(|keys| keys.encryption.as_ref())
            && keys.matches(encryption.authentication)
        {
            encryption.private_keys = keys.private_keys.clone();
        }
        if let Protocol::Shadowsocks(value) = &mut source.protocol {
            if value.password.is_none()
                && source.core != Core::Mihomo
                && matches!(
                    value.cipher,
                    crate::shadowsocks::Cipher::Aes128Gcm2022
                        | crate::shadowsocks::Cipher::Aes256Gcm2022
                )
                && let Some(material) = keys
                    .get(&source.uuid)
                    .and_then(|keys| keys.shadowsocks.as_ref())
                && value.cipher.key_size() == material.cipher.key_size()
            {
                value.password = Some(material.password.clone());
            }
            if let Some(password) = &value.password {
                value.password = Some(value.cipher.password(password)?);
            }
        }
        step.detail(&source.name);
        if source.listen.address == "localhost" {
            source.listen.address = "127.0.0.1".to_owned();
        }
        for value in [&mut source.listen.interface, &mut source.listen.namespace] {
            if value.as_deref() == Some("") {
                *value = None;
            }
        }
        if source.listen.ipv6_only == Some(false) {
            source.listen.ipv6_only = None;
        }
        let unix = source.listen.address.starts_with('@')
            || Path::new(&source.listen.address).is_absolute();
        let transport_udp = source.transport.udp(
            source.tls.enabled && !source.tls.reality.enabled,
            &source.tls.alpn,
        );
        let modes = modes(
            &source,
            &entry
                .accounts
                .iter()
                .map(|account| account.network)
                .collect::<Vec<_>>(),
        );
        if unix && source.core != Core::Xray {
            return Err(format!("入站 {} 的核心没有 Unix socket 监听配置", source.name).into());
        }
        if unix && transport_udp {
            return Err(format!("入站 {} 的传输需要 UDP 监听地址", source.name).into());
        }
        if (unix || transport_udp)
            && source.core == Core::Xray
            && matches!(&source.protocol, Protocol::Mixed(protocol) if protocol.socks.enabled)
        {
            return Err(format!(
                "入站 {} 的 Xray SOCKS 处理器需要 TCP 地址，HTTP 可使用当前传输",
                source.name
            )
            .into());
        }
        for (stream, packet, name) in [
            (Mode::Shadowsocks, Mode::ShadowsocksUdp, "Shadowsocks "),
            (Mode::Forward, Mode::ForwardUdp, ""),
        ] {
            if modes.contains(&packet) && (unix || transport_udp && modes.contains(&stream)) {
                return Err(
                    format!("入站 {} 的{name}数据报需要独立 UDP 套接字", source.name).into(),
                );
            }
        }
        let parts =
            if source.core == Core::SingBox && modes.contains(&Mode::Http3) && modes.len() > 1 {
                let mut tcp = modes.clone();
                tcp.remove(&Mode::Http3);
                vec![tcp, BTreeSet::from([Mode::Http3])]
            } else {
                vec![modes]
            };
        let ports: Vec<_> = if unix {
            vec![None]
        } else {
            source.ports()?.into_iter().map(Some).collect()
        };
        let users = Rc::new(credentials(entry));
        for modes in parts {
            let mut source = source.clone();
            if let Protocol::Shadowsocks(protocol) = &mut source.protocol {
                protocol.tcp = modes.contains(&Mode::Shadowsocks);
                protocol.udp = modes.contains(&Mode::ShadowsocksUdp);
            }
            if let Protocol::Forward(protocol) = &mut source.protocol {
                protocol.tcp = modes.contains(&Mode::Forward);
                protocol.udp = modes.contains(&Mode::ForwardUdp);
            }
            if let Protocol::Mixed(protocol) = &mut source.protocol {
                if modes == BTreeSet::from([Mode::Http3]) {
                    protocol.socks.enabled = false;
                }
                protocol.http.versions = versions(&modes);
                if source.core != Core::SingBox {
                    protocol.udp = entry
                        .accounts
                        .iter()
                        .any(|account| account.network == Network::Udp);
                }
            }
            if transport_udp || modes.iter().all(|mode| mode.wire() == Network::Udp) {
                source.listen.tcp_fast_open = None;
                source.listen.tcp_multi_path = None;
                source.listen.tcp_keep_alive = None;
                source.listen.tcp_keep_alive_idle = None;
                source.listen.tcp_keep_alive_interval = None;
                source.listen.tcp_congestion = None;
                source.listen.tcp_window = None;
                source.listen.tcp_max_segment = None;
                source.listen.tcp_user_timeout = None;
            }
            let binding = Binding::new(
                &source,
                ports[0],
                if transport_udp {
                    BTreeSet::from([Network::Udp])
                } else {
                    modes.iter().map(|mode| mode.wire()).collect()
                },
            )?;
            if binding.current_namespace()? {
                source.listen.namespace = None;
            }
            if matches!(binding.address, Address::Ip(std::net::IpAddr::V6(_))) {
                source.listen.ipv6_only = None;
            }
            let source = Rc::new(source);
            for port in &ports {
                progress.check()?;
                let mut binding = binding.clone();
                binding.ports = port.iter().copied().collect();
                let member = Member {
                    entry: index,
                    source: Rc::clone(&source),
                    modes: modes.clone(),
                    users: Rc::clone(&users),
                    binding,
                };
                let groups = groups.entry(*port).or_default();
                let mut combined = Vec::new();
                for group in groups.extract_if(.., |group| {
                    group
                        .iter()
                        .any(|other| other.binding.overlaps(&member.binding))
                }) {
                    combined.extend(group);
                }
                combined.push(member);
                groups.push(combined);
            }
        }
    }
    let mut combined: BTreeMap<Vec<(usize, BTreeSet<Mode>)>, Vec<Member>> = BTreeMap::new();
    for mut members in groups.into_values().flatten() {
        progress.check()?;
        members.sort_by(|left, right| (left.entry, &left.modes).cmp(&(right.entry, &right.modes)));
        let key = members
            .iter()
            .map(|member| (member.entry, member.modes.clone()))
            .collect();
        if let Some(existing) = combined.get_mut(&key) {
            for (existing, member) in existing.iter_mut().zip(members) {
                existing.binding.ports.extend(member.binding.ports);
            }
        } else {
            combined.insert(key, members);
        }
    }
    let mut result = Vec::new();
    for members in combined.into_values() {
        progress.check()?;
        let index = members
            .iter()
            .position(|candidate| {
                members
                    .iter()
                    .all(|member| candidate.binding.contains(&member.binding))
            })
            .ok_or_else(|| conflict(&members, "监听地址与接口的组合无法合并"))?;
        let mut binding = members[index].binding.clone();
        let mut source = (*members[index].source).clone();
        if source.tls.enabled && source.tls.reality.enabled {
            source.tls.reality.private_key = members
                .iter()
                .find_map(|member| member.source.tls.reality.private_key.clone());
            source.tls.reality.signature_seed = members
                .iter()
                .find_map(|member| member.source.tls.reality.signature_seed.clone());
            source.tls.reality.short_ids = members
                .iter()
                .find_map(|member| {
                    (!member.source.tls.reality.short_ids.is_empty())
                        .then(|| member.source.tls.reality.short_ids.clone())
                })
                .unwrap_or_default();
        }
        let modes: BTreeSet<_> = members
            .iter()
            .flat_map(|member| member.modes.iter())
            .copied()
            .collect();
        binding.networks = members
            .iter()
            .flat_map(|member| member.binding.networks.iter().copied())
            .collect();
        let mut users = BTreeMap::new();
        for member in &members {
            if member.source.core != source.core {
                return Err(conflict(&members, "同一监听资源指定了不同核心").into());
            }
            if member.users.is_empty() != members[0].users.is_empty() {
                return Err(conflict(&members, "认证与无凭据连接无法共用原生认证表").into());
            }
            for (&user, password) in member.users.iter() {
                if matches!(source.protocol, Protocol::Mixed(_))
                    && users.get(&user).is_some_and(|other| other != password)
                {
                    return Err(conflict(&members, &format!("凭据 {user} 对应不同密码")).into());
                }
                users.insert(user, password.clone());
            }
            if binding.interface != member.binding.interface {
                return Err(conflict(&members, "监听套接字绑定到不同接口").into());
            }
            same(
                binding.settings.as_ref(),
                member.binding.settings.as_ref(),
                &[],
                "监听",
                &members,
            )?;
            if source.tls.enabled != member.source.tls.enabled {
                return Err(conflict(&members, "TLS 与明文连接使用了同一监听资源").into());
            }
            if source.core == Core::Xray {
                same(
                    &super::transport::xray(&source.transport, true, store, source.tls.enabled)?,
                    &super::transport::xray(
                        &member.source.transport,
                        true,
                        store,
                        member.source.tls.enabled,
                    )?,
                    &[],
                    "传输",
                    &members,
                )?;
            } else if source.core == Core::SingBox {
                same(
                    &super::transport::singbox(
                        &source.transport,
                        true,
                        source.tls.enabled,
                        source.tls.reality.enabled,
                    )?
                    .unwrap_or(serde_json::json!({})),
                    &super::transport::singbox(
                        &member.source.transport,
                        true,
                        member.source.tls.enabled,
                        member.source.tls.reality.enabled,
                    )?
                    .unwrap_or(serde_json::json!({})),
                    &[],
                    "传输",
                    &members,
                )?;
            } else {
                same(
                    &super::transport::mihomo_server(&source.transport)?,
                    &super::transport::mihomo_server(&member.source.transport)?,
                    &[],
                    "传输",
                    &members,
                )?;
            }
            if source.tls.enabled {
                let mut tls = member.source.tls.clone();
                if tls.reality.enabled {
                    if tls.reality.private_key.is_none() {
                        tls.reality.private_key = source.tls.reality.private_key.clone();
                    }
                    if tls.reality.signature_seed.is_none() {
                        tls.reality.signature_seed = source.tls.reality.signature_seed.clone();
                    }
                    if tls.reality.short_ids.is_empty() {
                        tls.reality.short_ids = source.tls.reality.short_ids.clone();
                    }
                }
                same(&source.tls.reality, &tls.reality, &[], "REALITY", &members)?;
                same(
                    &source.tls,
                    &tls,
                    &["server_name", "reality"],
                    "TLS",
                    &members,
                )?;
                if source.core != Core::Xray
                    && !source.tls.reality.enabled
                    && certificate_name(&source) != certificate_name(&member.source)
                {
                    return Err(conflict(&members, "这个核心的监听使用一组证书与私钥").into());
                }
            }
            match (&mut source.protocol, &member.source.protocol) {
                (Protocol::Mixed(current), Protocol::Mixed(other)) => {
                    if current.user_level != other.user_level {
                        return Err(conflict(&members, "用户等级不同").into());
                    }
                    current.udp |= other.udp;
                    if current.http.enabled && other.http.enabled {
                        same(
                            &current.http,
                            &other.http,
                            &["enabled", "versions"],
                            "HTTP",
                            &members,
                        )?;
                    } else if other.http.enabled {
                        current.http = other.http.clone();
                    }
                    if current.socks.enabled && other.socks.enabled {
                        same(
                            &current.socks,
                            &other.socks,
                            &["enabled"],
                            "SOCKS",
                            &members,
                        )?;
                    } else if other.socks.enabled {
                        current.socks = other.socks.clone();
                    }
                }
                (Protocol::Vless(current), Protocol::Vless(other)) => {
                    same(current, other, &["encryption"], "VLESS", &members)?;
                    match (&mut current.encryption, &other.encryption) {
                        (None, None) => {}
                        (Some(current), Some(other)) => {
                            let mut other = other.clone();
                            current.inherit(&other);
                            other.inherit(current);
                            if current.authentication != other.authentication
                                || super::encryption::server(current)?
                                    != super::encryption::server(&other)?
                            {
                                return Err(conflict(&members, "VLESS 加密参数不同").into());
                            }
                        }
                        _ => return Err(conflict(&members, "VLESS 加密参数不同").into()),
                    }
                }
                (Protocol::Vmess(current), Protocol::Vmess(other)) => {
                    same(current, other, &[], "VMess", &members)?
                }
                (Protocol::Trojan(current), Protocol::Trojan(other)) => {
                    same(current, other, &[], "Trojan", &members)?
                }
                (Protocol::Shadowsocks(current), Protocol::Shadowsocks(other)) => {
                    same(
                        current,
                        other,
                        &["tcp", "udp", "password"],
                        "Shadowsocks",
                        &members,
                    )?;
                    if current.password.is_none() {
                        current.password = other.password.clone();
                    } else if other.password.is_some() && current.password != other.password {
                        return Err(conflict(&members, "Shadowsocks 入口共享密钥不同").into());
                    }
                    current.tcp |= other.tcp;
                    current.udp |= other.udp;
                }
                (Protocol::Forward(current), Protocol::Forward(other)) => {
                    same(
                        current,
                        other,
                        &["outbound", "tcp", "udp"],
                        "固定转发",
                        &members,
                    )?;
                    current.tcp |= other.tcp;
                    current.udp |= other.udp;
                }
                _ => return Err(conflict(&members, "协议参数无法合并为同一监听配置").into()),
            }
        }
        if let Protocol::Mixed(protocol) = &mut source.protocol {
            protocol.http.enabled = modes
                .iter()
                .any(|mode| matches!(mode, Mode::Http1 | Mode::Http2 | Mode::Http3));
            protocol.http.versions = versions(&modes);
            protocol.socks.enabled = modes.contains(&Mode::Socks);
            if source.core == Core::Mihomo {
                protocol.udp = modes.contains(&Mode::SocksUdp);
            }
        } else if users.is_empty()
            && !matches!(&source.protocol, Protocol::Shadowsocks(value) if value.cipher == crate::shadowsocks::Cipher::None)
            && source.protocol.users()
        {
            return Err(format!("入站 {} 需要用户或入口凭据", source.name).into());
        }
        let password_identity = matches!(
            source.protocol,
            Protocol::Trojan(_) | Protocol::Shadowsocks(_)
        );
        let credentials: BTreeSet<_> = members
            .iter()
            .flat_map(|member| {
                member
                    .users
                    .iter()
                    .map(|(uuid, password)| (*uuid, password.clone()))
            })
            .collect();
        let mut addresses: BTreeSet<_> = members
            .iter()
            .map(|member| member.binding.address.clone())
            .collect();
        addresses.extend([Address::V4, Address::V6]);
        let mut interfaces: BTreeSet<_> = members
            .iter()
            .map(|member| member.binding.interface)
            .collect();
        interfaces.insert(None);
        for address in &addresses {
            for &interface in &interfaces {
                if !binding.accepts(address, interface) {
                    continue;
                }
                for &mode in &modes {
                    let identities: Vec<_> = if users.is_empty() || mode == Mode::SocksUdp {
                        vec![None]
                    } else {
                        credentials.iter().map(Some).collect()
                    };
                    for identity in identities {
                        progress.check()?;
                        let eligible: Vec<_> = members
                            .iter()
                            .filter(|member| {
                                member.binding.accepts(address, interface)
                                    && member.modes.contains(&mode)
                                    && identity.is_none_or(|(user, password)| {
                                        if password_identity {
                                            member.users.values().any(|value| value == password)
                                        } else {
                                            member.users.contains_key(user)
                                        }
                                    })
                            })
                            .collect();
                        if eligible.is_empty() {
                            return Err(conflict(
                                &members,
                                "合并后的协议与凭据会产生原配置之外的接入资格",
                            )
                            .into());
                        }
                    }
                }
            }
        }
        for (position, left) in members.iter().enumerate() {
            for right in &members[position + 1..] {
                if !source.protocol.users() {
                    continue;
                }
                for network in [Network::Tcp, Network::Udp] {
                    if !left.carries(network) || !right.carries(network) {
                        continue;
                    }
                    if source.core == Core::Mihomo
                        && !left.modes.iter().any(|mode| {
                            mode.carries(source.core, network)
                                && right.modes.iter().any(|other| {
                                    other.family() == mode.family()
                                        && other.carries(source.core, network)
                                })
                        })
                    {
                        continue;
                    }
                    let identities: Vec<_> = if !network.identity(&source) || users.is_empty() {
                        vec![(None, None)]
                    } else if password_identity {
                        left.users
                            .iter()
                            .flat_map(|(left_user, password)| {
                                right
                                    .users
                                    .iter()
                                    .filter(move |(_, other)| *other == password)
                                    .map(move |(right_user, _)| {
                                        (Some(*left_user), Some(*right_user))
                                    })
                            })
                            .collect()
                    } else {
                        left.users
                            .keys()
                            .filter(|user| right.users.contains_key(user))
                            .map(|user| (Some(*user), Some(*user)))
                            .collect()
                    };
                    for (left_identity, right_identity) in identities {
                        if left_identity.is_some() && left.source.users != right.source.users {
                            return Err(conflict(&members, "相同凭据对应不同的系统用户归属").into());
                        }
                        if !graph.equivalent(
                            left.entry,
                            right.entry,
                            network,
                            left_identity,
                            right_identity,
                        )? {
                            return Err(conflict(
                                &members,
                                &format!(
                                    "{} 流量在相同接入身份下具有不同分流结果",
                                    network.name().to_uppercase()
                                ),
                            )
                            .into());
                        }
                    }
                }
            }
        }
        if password_identity && source.protocol.users() {
            let mut identities: BTreeMap<String, (Uuid, bool)> = BTreeMap::new();
            for member in &members {
                for (&uuid, password) in member.users.iter() {
                    identities
                        .entry(password.clone())
                        .and_modify(|(current, system)| {
                            if member.source.users {
                                *current = uuid;
                                *system = true;
                            } else if !*system {
                                *current = (*current).min(uuid);
                            }
                        })
                        .or_insert((uuid, member.source.users));
                }
            }
            users = identities
                .into_iter()
                .map(|(password, (uuid, system))| {
                    (
                        if system {
                            uuid
                        } else {
                            Uuid::new_v5(&uuid, password.as_bytes())
                        },
                        password,
                    )
                })
                .collect();
        }
        result.push(Listener {
            source,
            members,
            users,
            binding,
        });
    }
    step.finish(format!("{} 组监听", result.len()));
    Ok(result)
}

fn credentials(entry: &Entry<'_>) -> BTreeMap<Uuid, String> {
    if !entry.inbound.protocol.users() {
        return BTreeMap::new();
    }
    let mut values: BTreeMap<Uuid, String> = if entry.inbound.users {
        entry
            .users
            .iter()
            .map(|user| (user.uuid, user.password.clone()))
            .collect()
    } else {
        entry
            .inbound
            .credentials
            .iter()
            .map(|value| (value.uuid, value.password.clone()))
            .collect()
    };
    if let Protocol::Shadowsocks(source) = &entry.inbound.protocol {
        if source.cipher == crate::shadowsocks::Cipher::None {
            return BTreeMap::new();
        }
        for password in values.values_mut() {
            *password = source.cipher.credential(password);
        }
    }
    values
}

fn versions(modes: &BTreeSet<Mode>) -> Vec<HttpVersion> {
    modes
        .iter()
        .filter_map(|mode| match mode {
            Mode::Http1 => Some(HttpVersion::Http1),
            Mode::Http2 => Some(HttpVersion::Http2),
            Mode::Http3 => Some(HttpVersion::Http3),
            _ => None,
        })
        .collect()
}

fn same<T: Serialize>(
    left: &T,
    right: &T,
    omitted: &[&str],
    name: &str,
    members: &[Member],
) -> Result<()> {
    let left = serde_json::to_value(left)?;
    let right = serde_json::to_value(right)?;
    let fields: BTreeSet<_> = left
        .as_object()
        .unwrap()
        .keys()
        .chain(right.as_object().unwrap().keys())
        .filter(|key| !omitted.contains(&key.as_str()) && left.get(*key) != right.get(*key))
        .map(String::as_str)
        .collect();
    if fields.is_empty() {
        Ok(())
    } else {
        Err(conflict(
            members,
            &format!(
                "{name} 参数不同：{}",
                fields.into_iter().collect::<Vec<_>>().join("、")
            ),
        )
        .into())
    }
}

fn conflict(members: &[Member], reason: &str) -> String {
    let names: BTreeSet<_> = members
        .iter()
        .map(|member| member.source.name.as_str())
        .collect();
    format!(
        "入站 {} 的监听发生冲突：{reason}",
        names.into_iter().collect::<Vec<_>>().join("、")
    )
}
