use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    rc::Rc,
};

use serde::Serialize;
use uuid::Uuid;

use crate::{
    Result,
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
}

impl Mode {
    fn wire(self) -> Network {
        match self {
            Self::Http3 | Self::SocksUdp => Network::Udp,
            _ => Network::Tcp,
        }
    }

    fn family(self) -> &'static str {
        match self {
            Self::Http1 | Self::Http2 | Self::Http3 => "HTTP/HTTPS",
            Self::Socks | Self::SocksUdp => "SOCKS",
        }
    }

    fn carries(self, core: Core, network: Network) -> bool {
        match self {
            Self::SocksUdp => network == Network::Udp,
            Self::Socks => network == Network::Tcp || core != Core::Mihomo,
            _ => network == Network::Tcp || core == Core::SingBox,
        }
    }
}

pub struct Member {
    pub entry: usize,
    source: Rc<Inbound>,
    modes: BTreeSet<Mode>,
    users: Rc<BTreeMap<Uuid, String>>,
    binding: Binding,
}

impl Member {
    pub fn protocol(&self) -> Option<&'static str> {
        if self.source.core != Core::Mihomo {
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
}

pub struct Listener {
    pub source: Inbound,
    pub members: Vec<Member>,
    pub users: BTreeMap<Uuid, String>,
    pub binding: Binding,
}

pub fn build(graph: &mut Graph<'_>, progress: &Progress) -> Result<Vec<Listener>> {
    let step = progress.activity("分配监听资源");
    let mut groups: BTreeMap<Option<u16>, Vec<Vec<Member>>> = BTreeMap::new();
    for (index, entry) in graph.entries.iter().enumerate() {
        progress.check()?;
        let mut source = entry.inbound.clone();
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
        if unix && source.core != Core::Xray {
            return Err(format!("入站 {} 的核心没有 Unix socket 监听配置", source.name).into());
        }
        let Protocol::Mixed(protocol) = &source.protocol;
        if unix && protocol.socks.enabled {
            return Err(format!(
                "入站 {} 的 Xray SOCKS 处理器需要 TCP 地址，HTTP 可以使用 Unix socket",
                source.name
            )
            .into());
        }
        let mut modes = BTreeSet::new();
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
            if source.core == Core::Mihomo
                && entry
                    .accounts
                    .iter()
                    .any(|account| account.network == Network::Udp)
            {
                modes.insert(Mode::SocksUdp);
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
            let Protocol::Mixed(protocol) = &mut source.protocol;
            if modes == BTreeSet::from([Mode::Http3]) {
                protocol.socks.enabled = false;
            }
            protocol.http.versions = versions(&modes);
            if modes.iter().all(|mode| mode.wire() == Network::Udp) {
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
            if source.core != Core::SingBox {
                protocol.udp = entry
                    .accounts
                    .iter()
                    .any(|account| account.network == Network::Udp);
            }
            let binding = Binding::new(
                &source,
                ports[0],
                modes.iter().map(|mode| mode.wire()).collect(),
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
        let modes: BTreeSet<_> = members
            .iter()
            .flat_map(|member| member.modes.iter())
            .copied()
            .collect();
        binding.networks = modes.iter().map(|mode| mode.wire()).collect();
        let mut users = BTreeMap::new();
        for member in &members {
            if member.source.core != source.core {
                return Err(conflict(&members, "同一监听资源指定了不同核心").into());
            }
            if member.users.is_empty() != members[0].users.is_empty() {
                return Err(conflict(&members, "认证与无凭据连接无法共用原生认证表").into());
            }
            for (&user, password) in member.users.iter() {
                if users.get(&user).is_some_and(|other| other != password) {
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
            if source.tls.enabled {
                same(
                    &source.tls,
                    &member.source.tls,
                    &["server_name"],
                    "TLS",
                    &members,
                )?;
                if source.core != Core::Xray
                    && certificate_name(&source) != certificate_name(&member.source)
                {
                    return Err(conflict(&members, "这个核心的监听使用一组证书与私钥").into());
                }
            }
            let Protocol::Mixed(current) = &mut source.protocol;
            let Protocol::Mixed(other) = &member.source.protocol;
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
        let Protocol::Mixed(protocol) = &mut source.protocol;
        protocol.http.enabled = modes
            .iter()
            .any(|mode| matches!(mode, Mode::Http1 | Mode::Http2 | Mode::Http3));
        protocol.http.versions = versions(&modes);
        protocol.socks.enabled = modes.contains(&Mode::Socks);
        if source.core == Core::Mihomo {
            protocol.udp = modes.contains(&Mode::SocksUdp);
        }
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
                        users.keys().map(|user| Some(*user)).collect()
                    };
                    for identity in identities {
                        progress.check()?;
                        let eligible: Vec<_> = members
                            .iter()
                            .filter(|member| {
                                member.binding.accepts(address, interface)
                                    && member.modes.contains(&mode)
                                    && identity.is_none_or(|user| member.users.contains_key(&user))
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
                if !left.binding.overlaps(&right.binding) {
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
                        vec![None]
                    } else {
                        left.users
                            .keys()
                            .filter(|user| right.users.contains_key(user))
                            .map(|user| Some(*user))
                            .collect()
                    };
                    for identity in identities {
                        if identity.is_some() && left.source.users != right.source.users {
                            return Err(conflict(&members, "相同凭据对应不同的系统用户归属").into());
                        }
                        if !graph.equivalent(left.entry, right.entry, network, identity)? {
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
    if entry.inbound.users {
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
    }
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
