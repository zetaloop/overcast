mod binding;
pub(crate) mod carrier;
pub(crate) mod encryption;
pub(crate) mod forward;
pub(crate) mod hysteria;
pub(crate) mod listener;
mod mihomo;
mod multiplex;
pub(crate) mod options;
mod reality;
mod routing;
pub(crate) mod shadowsocks;
mod singbox;
pub(crate) mod transport;
mod warp;
mod xray;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt, fs,
    io::{ErrorKind, Write},
    net::{TcpListener, UdpSocket},
    path::PathBuf,
    rc::Rc,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Map, Value, json};
use tempfile::TempDir;
use uuid::Uuid;

use crate::{
    Result, certificate,
    component::Component,
    condition::Condition,
    config::{Config, Store},
    connection::{self, Connection},
    endpoint,
    graph::{self, Layer, Payload},
    inbound::{Core, Inbound, Protocol},
    progress::Progress,
    route::Destination,
};

pub struct Prepared {
    pub keys: BTreeMap<Uuid, crate::keys::Keys>,
    pub state: State,
    directory: TempDir,
}

impl Prepared {
    pub fn directory(&self) -> &std::path::Path {
        self.directory.path()
    }

    pub fn keep(self) {
        let _ = self.directory.keep();
    }
}

#[derive(Default)]
pub struct State {
    pub ports: BTreeMap<String, u16>,
    pub instances: Vec<Instance>,
}

pub struct Instance {
    pub component: Component,
    pub file: String,
    pub assets: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub certificates: BTreeSet<String>,
}

struct Service {
    core: Core,
    globals: Map<String, Value>,
    environment: BTreeMap<String, String>,
    listeners: Vec<Value>,
    outbounds: Vec<Value>,
    rules: Vec<routing::Rule>,
    certificates: BTreeSet<String>,
}

#[derive(Clone)]
struct Endpoint {
    service: usize,
    tag: String,
    resolve_udp: bool,
}

#[derive(PartialEq)]
struct Node {
    core: Core,
    globals: Map<String, Value>,
    environment: BTreeMap<String, String>,
    value: Map<String, Value>,
    resolve_udp: bool,
}

#[derive(Clone, PartialEq)]
struct Chain {
    nodes: Vec<Rc<Node>>,
    networks: [bool; 2],
}

impl Chain {
    fn supports(&self, network: graph::Network) -> bool {
        self.networks[network as usize]
    }
}

struct Builder<'a> {
    store: &'a Store,
    config: &'a Config,
    progress: &'a Progress,
    services: Vec<Service>,
    chains: HashMap<(Uuid, Core, Payload), Vec<Chain>>,
    outbounds: HashMap<(Uuid, Core, Payload, usize), Endpoint>,
    bridges: BTreeMap<String, Endpoint>,
    previous: BTreeMap<String, u16>,
    ports: BTreeMap<String, u16>,
    reserved: Vec<binding::Binding>,
    sockets: Vec<(Option<TcpListener>, Option<UdpSocket>)>,
}

impl<'a> Builder<'a> {
    fn new(store: &'a Store, config: &'a Config, progress: &'a Progress) -> Self {
        Self {
            store,
            config,
            progress,
            services: Vec::new(),
            chains: HashMap::new(),
            outbounds: HashMap::new(),
            bridges: BTreeMap::new(),
            previous: BTreeMap::new(),
            ports: BTreeMap::new(),
            reserved: Vec::new(),
            sockets: Vec::new(),
        }
    }
}

pub fn available(
    store: &Store,
    config: &Config,
    source: &Inbound,
    destination: Destination,
    progress: &Progress,
) -> Result<bool> {
    if destination == Destination::Block {
        return Ok(true);
    }
    let modes = listener::modes(source);
    let mut builder = Builder::new(store, config, progress);
    for network in [graph::Network::Tcp, graph::Network::Udp] {
        if modes.iter().any(|mode| mode.carries(source, network))
            && builder.available(
                source.core,
                destination,
                network,
                Payload::from(&source.protocol),
            )?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn prepare(
    store: &Store,
    config: &Config,
    geodata: &mut Option<u64>,
    ports: &BTreeMap<String, u16>,
    progress: &Progress,
) -> Result<(Option<Prepared>, graph::Coverage)> {
    let mut builder = Builder::new(store, config, progress);
    let mut scopes = HashMap::new();
    let graph = builder.graph(geodata, Some(&mut scopes))?;
    let planned: BTreeSet<_> = builder
        .chains
        .keys()
        .filter(|(_, _, payload)| *payload == Payload::Proxy)
        .map(|(uuid, _, _)| *uuid)
        .collect();
    for outbound in &config.outbounds {
        if !planned.contains(&outbound.uuid) {
            builder.plan(outbound, None, Payload::Proxy)?;
        }
    }
    let mut coverage = graph::Coverage::default();
    let mut include = |uuid: Uuid| {
        if let Some(scope) = scopes.remove(&uuid) {
            coverage.reached.extend(scope.reached);
            coverage.remainder |= scope.remainder;
        }
    };
    for inbound in config
        .inbounds
        .iter()
        .filter(|inbound| inbound.listen.enabled)
    {
        include(inbound.uuid);
    }
    let Some(mut graph) = graph else {
        return Ok((None, coverage));
    };
    builder.previous = ports.clone();
    let mut listeners = listener::build(store, &mut graph, &config.keys, progress)?;
    let members: Vec<_> = listeners
        .iter()
        .flat_map(|listener| listener.members.iter().cloned())
        .collect();
    listeners.retain(|listener| listener.source.listen.enabled);
    if listeners.is_empty() {
        return Ok((None, coverage));
    }
    let catalog = crate::geodata::Catalog::ensure(store, geodata, progress)?;
    let data = crate::geodata::Catalog::directory(store, catalog.release);
    builder.reserved = listeners
        .iter()
        .map(|listener| listener.binding.clone())
        .collect();
    let mut http = binding::Binding::local(80, BTreeSet::from([graph::Network::Tcp]))?;
    http.address = binding::Address::Any;
    if members.iter().any(|member| {
        let source = graph.entries[member.entry].inbound;
        matches!(source.security, crate::inbound::Security::Tls(_))
    }) {
        builder.reserved.push(http.clone());
    }
    let mut internal = HashMap::new();
    let mut current = 0;
    while current < listeners.len() {
        progress.check()?;
        let mut targets = BTreeSet::new();
        for member in &listeners[current].members {
            let entry = &graph.entries[member.entry];
            for account in entry
                .accounts
                .iter()
                .filter(|account| member.carries(account.network))
            {
                targets.extend(account.rules.iter().filter_map(|rule| {
                    if let Destination::Inbound(uuid) = rule.destination {
                        Some((uuid, account.network, Layer::Transport))
                    } else {
                        None
                    }
                }));
            }
            targets.extend(
                entry
                    .inbound
                    .protocol
                    .fallbacks()
                    .iter()
                    .filter_map(|fallback| {
                        if let endpoint::Endpoint::Inbound(uuid) = fallback.target {
                            Some((uuid, graph::Network::Tcp, Layer::Protocol))
                        } else {
                            None
                        }
                    }),
            );
        }
        for (uuid, network, layer) in targets {
            if internal.contains_key(&(uuid, network, layer)) {
                continue;
            }
            if layer == Layer::Protocol
                && !graph.reaches(
                    uuid,
                    network,
                    layer,
                    |core, destination, network, payload| {
                        builder.available(core, destination, network, payload)
                    },
                )?
            {
                continue;
            }
            let member = members.iter().find(|member| {
                graph.entries[member.entry].inbound.uuid == uuid
                    && if layer == Layer::Transport {
                        member.binding.networks.contains(&network)
                    } else {
                        member.accepts(network, graph::Network::Tcp, layer)
                    }
            });
            let Some(member) = member else {
                if layer == Layer::Protocol {
                    continue;
                }
                return Err(format!("入站 {uuid} 缺少 {} 接收器", network.name()).into());
            };
            let networks = if layer == Layer::Protocol {
                BTreeSet::from([graph::Network::Tcp])
            } else {
                member.binding.networks.clone()
            };
            let tag = if layer == Layer::Protocol {
                format!("inlet-{uuid}-protocol")
            } else {
                format!(
                    "inlet-{uuid}-{}",
                    member
                        .binding
                        .networks
                        .iter()
                        .map(|network| network.name())
                        .collect::<Vec<_>>()
                        .join("-")
                )
            };
            let port = builder.port(&tag, networks)?;
            let listener = member.internal(port, layer)?;
            include(uuid);
            for &network in &listener.binding.networks {
                internal.insert((uuid, network, layer), listeners.len());
            }
            listeners.push(listener);
        }
        current += 1;
    }
    let mut keys = BTreeMap::new();
    reality::prepare(&listeners, &graph, &mut keys, progress)?;
    encryption::prepare(&listeners, &graph, &mut keys, progress)?;
    shadowsocks::prepare(&listeners, &graph, &mut keys, progress)?;
    let fallback_targets: HashMap<_, _> = internal
        .iter()
        .filter(|((_, _, layer), _)| *layer == Layer::Protocol)
        .map(|(&(uuid, _, _), &index)| {
            (
                uuid,
                (
                    *listeners[index].binding.ports.first().unwrap(),
                    listeners[index].source.listen.socket.proxy_protocol,
                ),
            )
        })
        .collect();
    let step = progress.activity("生成核心配置");
    let mut receivers = Vec::new();
    for (index, listener) in listeners.iter_mut().enumerate() {
        progress.check()?;
        let sender = listener.source.core;
        if let Some(fallbacks) = listener.source.protocol.fallbacks_mut() {
            for fallback in fallbacks {
                let target = match fallback.target {
                    endpoint::Endpoint::Address(_) => continue,
                    endpoint::Endpoint::Block => None,
                    endpoint::Endpoint::Inbound(uuid) => fallback_targets.get(&uuid).copied(),
                };
                let (port, forwarded) = match target {
                    Some(target) => target,
                    None => (builder.reject()?, false),
                };
                fallback.target = endpoint::Endpoint::Address(format!("127.0.0.1:{port}"));
                fallback.network = None;
                fallback.proxy_protocol = (forwarded && sender == Core::Xray).then_some(2);
            }
        }
        if let Some(keys) = keys.get(&listener.source.uuid) {
            keys.apply(&mut listener.source);
        }
        let inbound = &listener.source;
        step.detail(&inbound.name);
        let core = inbound.core;
        let users: Vec<_> = listener
            .users
            .iter()
            .map(|(user, credential)| (user.to_string(), credential.clone()))
            .collect();
        let mut globals = Map::new();
        let target = if matches!(inbound.protocol, Protocol::Forward(_)) {
            Some(builder.forward_target(listener, &graph)?)
        } else {
            None
        };
        let values = match core {
            Core::Xray => xray::listeners(inbound, &users, store, target)?,
            Core::SingBox => singbox::listeners(inbound, &users, store, target)?,
            Core::Mihomo => mihomo::listeners(inbound, &users, store, &mut globals, target)?,
        };
        let values = if core == Core::SingBox {
            let mut expanded = Vec::new();
            for value in values {
                for port in &listener.binding.ports {
                    progress.check()?;
                    let mut value = value.clone();
                    value.insert("listen_port".to_owned(), json!(port));
                    expanded.push(value);
                }
            }
            expanded
        } else {
            values
        };
        let fallback = core == Core::SingBox
            && values.iter().any(|value| {
                value.contains_key("fallback") || value.contains_key("fallback_for_alpn")
            });
        let service = builder.service(core, globals, BTreeMap::new());
        if matches!(inbound.security, crate::inbound::Security::Tls(_)) {
            for member in &listener.members {
                builder.services[service]
                    .certificates
                    .insert(certificate::name(graph.entries[member.entry].inbound)?);
            }
        }
        let mut tags = Vec::new();
        for (part, mut value) in values.into_iter().enumerate() {
            progress.check()?;
            if let Some(reality) = inbound.security.reality()
                && let Some(Destination::Outbound(uuid)) = reality.outbound
            {
                let endpoint = builder.outbound(uuid, core, graph::Network::Tcp, Payload::Proxy)?;
                let parent = builder.bridge(service, &endpoint)?;
                match core {
                    Core::SingBox => {
                        value.get_mut("tls").unwrap()["reality"]["handshake"]["detour"] =
                            json!(parent)
                    }
                    Core::Mihomo => {
                        value.get_mut("reality-config").unwrap()["proxy"] = json!(parent)
                    }
                    Core::Xray => unreachable!(),
                }
            }
            let tag = format!("{}-{index}-{part}", inbound.uuid);
            match core {
                Core::Xray => {
                    value.insert("tag".to_owned(), json!(tag));
                    if listener.binding.ports.is_empty() {
                        value.remove("port");
                    } else {
                        value.insert("port".to_owned(), json!(listener.binding.port_text()));
                    }
                    if matches!(inbound.security, crate::inbound::Security::Tls(_)) {
                        let paths: BTreeSet<_> = listener
                            .members
                            .iter()
                            .map(|member| {
                                certificate_paths(store, graph.entries[member.entry].inbound)
                            })
                            .collect::<Result<_>>()?;
                        value.get_mut("streamSettings").unwrap()["tlsSettings"]["certificates"] = json!(
                            paths
                                .into_iter()
                                .map(|(certificate, key)| json!({
                                    "certificateFile": certificate, "keyFile": key,
                                }))
                                .collect::<Vec<_>>()
                        );
                    }
                }
                Core::SingBox => {
                    value.insert("tag".to_owned(), json!(tag));
                }
                Core::Mihomo => {
                    value.insert("name".to_owned(), json!(tag));
                    value.insert("port".to_owned(), json!(listener.binding.port_text()));
                }
            }
            tags.push(tag);
            builder.services[service].listeners.push(json!(value));
        }
        if fallback {
            builder.services[service].rules.push(routing::Rule {
                inbound: tags.clone(),
                user: Some(String::new()),
                protocol: None,
                network: Some(graph::Network::Tcp),
                condition: Condition::Always,
                outbound: "direct".to_owned(),
                resolve_udp: false,
                target: None,
            });
        }
        receivers.push((service, tags, fallback));
    }
    for (index, listener) in listeners.iter().enumerate() {
        progress.check()?;
        let inbound = &listener.source;
        let payload = Payload::from(&inbound.protocol);
        let (service, tags, fallback) = &receivers[index];
        let service = *service;
        let core = inbound.core;
        let mut detour = None;
        if core == Core::SingBox && !fallback {
            let mut choices = BTreeSet::new();
            let fixed = listener.members.iter().all(|member| {
                graph.entries[member.entry]
                    .accounts
                    .iter()
                    .filter(|account| member.carries(account.network))
                    .all(|account| {
                        if account.network == graph::Network::Tcp
                            && account.rules.len() == 1
                            && account.rules[0].condition == Condition::Always
                            && let Destination::Inbound(uuid) = account.rules[0].destination
                        {
                            choices.insert(uuid);
                            true
                        } else {
                            false
                        }
                    })
            });
            if fixed && choices.len() == 1 {
                let target = internal[&(
                    *choices.first().unwrap(),
                    graph::Network::Tcp,
                    Layer::Transport,
                )];
                let source = &listeners[target].source;
                let (target_service, target_tags, _) = &receivers[target];
                if service == *target_service
                    && target_tags.len() == 1
                    && matches!(source.security, crate::inbound::Security::None)
                    && source.transport.is_default()
                    && matches!(
                        source.protocol,
                        Protocol::Vless(_)
                            | Protocol::Vmess(_)
                            | Protocol::Trojan(_)
                            | Protocol::Shadowsocks(_)
                            | Protocol::AnyTls(_)
                    )
                {
                    detour = Some(target_tags[0].clone());
                }
            }
        }
        if let Some(detour) = detour {
            for value in &mut builder.services[service].listeners {
                if value["tag"]
                    .as_str()
                    .is_some_and(|tag| tags.iter().any(|value| value == tag))
                {
                    value["detour"] = json!(detour);
                }
            }
            continue;
        }
        for member in &listener.members {
            let entry = &graph.entries[member.entry];
            for account in entry
                .accounts
                .iter()
                .filter(|account| member.carries(account.network))
            {
                let user = if payload == Payload::Connection {
                    None
                } else {
                    account
                        .identity(entry.inbound)
                        .filter(|_| {
                            !matches!(inbound.protocol, Protocol::Shadowsocks(_))
                                || core == Core::Xray
                                || shadowsocks::multi(inbound, listener.users.len())
                        })
                        .map(|user| {
                            if inbound.protocol.credential()
                                == Some(crate::inbound::CredentialKind::Password)
                            {
                                listener
                                    .users
                                    .iter()
                                    .find(|(_, credential)| {
                                        credential.identity() == member.users[&user].identity()
                                    })
                                    .unwrap()
                                    .0
                                    .to_string()
                            } else {
                                user.to_string()
                            }
                        })
                };
                for rule in &account.rules {
                    let mut target = if payload == Payload::Connection
                        && let Destination::Outbound(_) = rule.destination
                    {
                        let (server, port) = forward::target(config, rule.destination)
                            .and_then(Connection::server)
                            .ok_or("转交目标缺少后继连接")?;
                        Some((server.to_owned(), port))
                    } else {
                        None
                    };
                    let outbound = match rule.destination {
                        Destination::Block => "block".to_owned(),
                        Destination::Outbound(uuid) => {
                            let endpoint =
                                builder.outbound(uuid, core, account.network, payload)?;
                            builder.bridge(service, &endpoint)?
                        }
                        Destination::Inbound(uuid) => {
                            let index = internal[&(uuid, account.network, Layer::Transport)];
                            let port = *listeners[index].binding.ports.first().unwrap();
                            if core == Core::SingBox {
                                target = Some(("127.0.0.1".to_owned(), port));
                                "direct".to_owned()
                            } else {
                                let sender = if core == Core::Xray {
                                    service
                                } else {
                                    builder.service(Core::Xray, Map::new(), BTreeMap::new())
                                };
                                let tag = format!("inlet-{index}");
                                if !builder.services[sender]
                                    .outbounds
                                    .iter()
                                    .any(|value| value["tag"] == tag)
                                {
                                    let mut value = xray::outbound(
                                        &Connection::Direct(connection::Direct::default()),
                                        store,
                                    )?;
                                    value.insert("tag".to_owned(), json!(tag));
                                    value.get_mut("settings").unwrap()["redirect"] =
                                        json!(format!("127.0.0.1:{port}"));
                                    builder.services[sender].outbounds.push(json!(value));
                                }
                                builder.bridge(
                                    service,
                                    &Endpoint {
                                        service: sender,
                                        tag,
                                        resolve_udp: false,
                                    },
                                )?
                            }
                        }
                    };
                    builder.services[service].rules.push(routing::Rule {
                        inbound: tags.clone(),
                        user: user.clone(),
                        protocol: member.protocol(),
                        network: Some(account.network),
                        condition: rule.condition.clone(),
                        outbound,
                        resolve_udp: false,
                        target,
                    });
                }
            }
        }
    }
    let certificates: BTreeSet<_> = builder
        .services
        .iter()
        .flat_map(|service| service.certificates.iter().cloned())
        .collect();
    let caddy = if certificates.is_empty() {
        None
    } else {
        if certificates.iter().any(|name| certificate::public(name))
            && let Some(listener) = listeners
                .iter()
                .find(|listener| listener.binding.overlaps(&http))
        {
            return Err(format!(
                "入站 {} 的监听与证书 HTTP 验证所需的 TCP 80 端口重叠",
                listener.source.name
            )
            .into());
        }
        Some(builder.port("caddy", BTreeSet::from([graph::Network::Tcp]))?)
    };
    progress.check()?;
    let id = Uuid::new_v4();
    let root = store.directory.join("runtime");
    store.create_dir(&root)?;
    let directory = tempfile::Builder::new()
        .prefix(&id.to_string())
        .rand_bytes(0)
        .tempdir_in(&root)?;
    let mut state = State {
        ports: builder.ports,
        instances: Vec::new(),
    };
    for (index, service) in builder.services.into_iter().enumerate() {
        progress.check()?;
        let mut matchers = routing::Matchers::new(&graph.targets, &catalog);
        let name = format!("{}-{index}", key(service.core));
        let working = directory.path().join(&name);
        store.create_dir(&working)?;
        let file = format!("{name}/config.json");
        let mut output = service.globals;
        let mut environment = service.environment;
        let mut assets = Vec::new();
        match service.core {
            Core::Xray => {
                environment.insert("XRAY_LOCATION_ASSET".to_owned(), ".".to_owned());
                let script = matchers.xray(&service.rules);
                let script_path = working.join("routing.lua");
                store.write(&script_path, |file| {
                    file.write_all(script.as_bytes())?;
                    Ok(())
                })?;
                assets.push("routing.lua".to_owned());
                let mut direct =
                    xray::outbound(&Connection::Direct(connection::Direct::default()), store)?;
                direct.insert("tag".to_owned(), json!("direct"));
                let mut outbounds = vec![
                    json!({"tag": "block", "protocol": "blackhole"}),
                    json!(direct),
                ];
                outbounds.extend(service.outbounds);
                output.insert("inbounds".to_owned(), json!(service.listeners));
                output.insert("outbounds".to_owned(), json!(outbounds));
                output.insert("dns".to_owned(), json!({"servers": ["localhost"]}));
                output.insert(
                    "routing".to_owned(),
                    json!({
                        "script": "routing.lua",
                    }),
                );
            }
            Core::SingBox => {
                let rules = matchers.singbox(&service.rules);
                let mut outbounds = vec![json!({"tag": "direct", "type": "direct"})];
                outbounds.extend(service.outbounds);
                output.insert("inbounds".to_owned(), json!(service.listeners));
                output.insert("outbounds".to_owned(), json!(outbounds));
                output.insert(
                    "dns".to_owned(),
                    json!({
                        "servers": [{"type": "local", "tag": "system"}],
                    }),
                );
                output.insert(
                    "route".to_owned(),
                    json!({
                        "default_domain_resolver": "system",
                        "rules": rules,
                        "rule_set": matchers.rule_sets()?,
                    }),
                );
            }
            Core::Mihomo => {
                environment.insert(
                    "SAFE_PATHS".to_owned(),
                    std::env::join_paths([&store.directory])?
                        .to_string_lossy()
                        .into_owned(),
                );
                let rules = matchers.mihomo(&service.rules);
                let mut proxies = vec![json!({"name": "direct", "type": "direct"})];
                proxies.extend(service.outbounds);
                output.insert("listeners".to_owned(), json!(service.listeners));
                output.insert("proxies".to_owned(), json!(proxies));
                output
                    .entry("rules")
                    .or_insert(json!([]))
                    .as_array_mut()
                    .unwrap()
                    .extend(rules.into_iter().map(Value::String));
                output.insert("ipv6".to_owned(), json!(true));
                output.insert("geodata-mode".to_owned(), json!(true));
                output.insert("geosite-matcher".to_owned(), json!("mph"));
            }
        }
        if service.core != Core::SingBox {
            assets.extend(matchers.write(store, &working, &data, service.core)?);
        }
        store.write(&directory.path().join(&file), |file| {
            serde_json::to_writer_pretty(file, &output)?;
            Ok(())
        })?;
        state.instances.push(Instance {
            component: match service.core {
                Core::Xray => Component::Xray,
                Core::SingBox => Component::SingBox,
                Core::Mihomo => Component::Mihomo,
            },
            file,
            assets,
            environment,
            certificates: service.certificates,
        });
    }
    if let Some(port) = caddy {
        let working = directory.path().join("caddy");
        store.create_dir(&working)?;
        store.write(&working.join("config.json"), |file| {
            serde_json::to_writer_pretty(file, &certificate::config(store, &certificates, port))?;
            Ok(())
        })?;
        state.instances.push(Instance {
            component: Component::Caddy,
            file: "caddy/config.json".to_owned(),
            assets: Vec::new(),
            environment: BTreeMap::new(),
            certificates: BTreeSet::new(),
        });
    }
    progress.check()?;
    step.finish(format!("{} 个服务实例", state.instances.len()));
    Ok((
        Some(Prepared {
            directory,
            keys,
            state,
        }),
        coverage,
    ))
}

pub fn analyze<'a>(
    store: &'a Store,
    config: &'a Config,
    geodata: &mut Option<u64>,
    progress: &'a Progress,
) -> Result<Option<graph::Graph<'a>>> {
    Builder::new(store, config, progress).graph(geodata, None)
}

impl<'a> Builder<'a> {
    fn graph(
        &mut self,
        geodata: &mut Option<u64>,
        coverage: Option<&mut HashMap<Uuid, graph::Coverage>>,
    ) -> Result<Option<graph::Graph<'a>>> {
        graph::build(
            self.store,
            self.config,
            geodata,
            self.progress,
            coverage,
            |core, destination, network, payload| {
                self.available(core, destination, network, payload)
            },
        )
    }

    fn available(
        &mut self,
        core: Core,
        destination: Destination,
        network: graph::Network,
        payload: Payload,
    ) -> Result<bool> {
        Ok(match destination {
            Destination::Block | Destination::Inbound(_) => false,
            Destination::Outbound(uuid) => {
                self.config
                    .outbounds
                    .iter()
                    .any(|outbound| outbound.uuid == uuid)
                    && self
                        .chains(uuid, core, payload)?
                        .iter()
                        .any(|chain| chain.supports(network))
            }
        })
    }

    fn same_path(
        &mut self,
        left: Uuid,
        right: Uuid,
        core: Core,
        network: graph::Network,
        payload: Payload,
    ) -> Result<bool> {
        let left = self
            .chains(left, core, payload)?
            .iter()
            .find(|chain| chain.supports(network))
            .cloned();
        let right = self
            .chains(right, core, payload)?
            .iter()
            .find(|chain| chain.supports(network));
        Ok(left.as_ref() == right)
    }

    fn forward_target<'b>(
        &mut self,
        listener: &listener::Listener,
        graph: &'b graph::Graph<'b>,
    ) -> Result<(&'b str, u16)> {
        let mut target = None;
        for (index, member) in listener.members.iter().enumerate() {
            let source = graph.entries[member.entry].inbound;
            let destination = source.protocol.destination().unwrap();
            let server = forward::target(graph.config(), destination)
                .and_then(Connection::server)
                .ok_or("转发入口缺少后继连接")?;
            if target.is_some_and(|target| target != server) {
                return Err(format!("入站 {} 的同一监听对应不同转发目标", source.name).into());
            }
            for other in &listener.members[..index] {
                let Destination::Outbound(left) = graph.entries[other.entry]
                    .inbound
                    .protocol
                    .destination()
                    .unwrap()
                else {
                    unreachable!()
                };
                let Destination::Outbound(right) = destination else {
                    unreachable!()
                };
                for network in [graph::Network::Tcp, graph::Network::Udp] {
                    if member.carries(network)
                        && other.carries(network)
                        && !self.same_path(
                            left,
                            right,
                            source.core,
                            network,
                            Payload::Connection,
                        )?
                    {
                        return Err(
                            format!("入站 {} 的同一监听对应不同转发路径", source.name).into()
                        );
                    }
                }
            }
            target = Some(server);
        }
        target.ok_or_else(|| "转发入口缺少后继连接".into())
    }

    fn service(
        &mut self,
        core: Core,
        globals: Map<String, Value>,
        environment: BTreeMap<String, String>,
    ) -> usize {
        if let Some(index) = self.services.iter().position(|service| {
            service.core == core
                && globals.iter().all(|(name, value)| {
                    service
                        .globals
                        .get(name)
                        .is_none_or(|current| current == value)
                })
                && environment.iter().all(|(name, value)| {
                    service
                        .environment
                        .get(name)
                        .is_none_or(|current| current == value)
                })
        }) {
            self.services[index].globals.extend(globals);
            self.services[index].environment.extend(environment);
            return index;
        }
        let index = self.services.len();
        self.services.push(Service {
            core,
            globals,
            environment,
            listeners: Vec::new(),
            outbounds: Vec::new(),
            rules: Vec::new(),
            certificates: BTreeSet::new(),
        });
        index
    }

    fn chains(&mut self, uuid: Uuid, preferred: Core, payload: Payload) -> Result<&[Chain]> {
        if self.chains.contains_key(&(uuid, preferred, payload)) {
            return Ok(&self.chains[&(uuid, preferred, payload)]);
        }
        if payload == Payload::Connection
            && forward::target(self.config, Destination::Outbound(uuid)).is_none()
        {
            self.chains.insert((uuid, preferred, payload), Vec::new());
            return Ok(&self.chains[&(uuid, preferred, payload)]);
        }
        let source = self
            .config
            .outbounds
            .iter()
            .find(|outbound| outbound.uuid == uuid)
            .ok_or_else(|| format!("找不到出站：{uuid}"))?;
        let paths = self.plan(source, Some(preferred), payload)?;
        Ok(self
            .chains
            .entry((uuid, preferred, payload))
            .or_insert(paths))
    }

    fn plan(
        &self,
        source: &crate::outbound::Outbound,
        preferred: Option<Core>,
        payload: Payload,
    ) -> Result<Vec<Chain>> {
        let mut chains = vec![Chain {
            nodes: Vec::new(),
            networks: [true, true],
        }];
        for (index, connection) in source.connections.iter().enumerate() {
            self.progress.check()?;
            if chains.is_empty() {
                break;
            }
            let requested = connection.core();
            let candidates = preferred.into_iter().chain(
                [Core::Xray, Core::SingBox, Core::Mihomo]
                    .into_iter()
                    .filter(|core| Some(*core) != preferred),
            );
            let mut nodes = Vec::new();
            let mut errors = Vec::new();
            let forward = payload != Payload::Proxy && index == source.connections.len() - 1;
            for core in candidates {
                if !matches_core(requested, core) {
                    continue;
                }
                if index != 0
                    && core != Core::Xray
                    && (forward || matches!(connection, Connection::Direct(_)))
                {
                    errors.push(format!("{} 直连出站没有前置代理配置", key(core)));
                    continue;
                }
                let mut globals = Map::new();
                let result = if forward {
                    forward::outbound(connection.network(), core, self.store, &mut globals)
                } else {
                    match core {
                        Core::Xray => xray::outbound(connection, self.store),
                        Core::SingBox => singbox::outbound(connection, self.store, &mut globals),
                        Core::Mihomo => mihomo::outbound(connection, self.store, &mut globals),
                    }
                };
                match result {
                    Ok(value) => {
                        let mut environment = BTreeMap::new();
                        if core == Core::Xray
                            && connection.multiplex().is_none_or(|mux| mux.tcp_only)
                            && connection.packet_encoding()
                                == Some(connection::PacketEncoding::Packet)
                        {
                            environment.insert("XRAY_CONE_DISABLED".to_owned(), "true".to_owned());
                        }
                        nodes.push(Rc::new(Node {
                            core,
                            globals,
                            environment,
                            value,
                            resolve_udp: core == Core::SingBox
                                && connection.multiplex().is_none_or(|mux| mux.tcp_only)
                                && connection.packet_encoding()
                                    == Some(connection::PacketEncoding::PacketAddr),
                        }));
                    }
                    Err(error) if error.is::<Unsupported>() => errors.push(error.to_string()),
                    Err(error) => return Err(error),
                }
            }
            if nodes.is_empty() {
                if payload != Payload::Proxy {
                    chains.clear();
                    break;
                }
                return Err(format!(
                    "出站 {} 第 {} 段连接无法生成：{}",
                    source.name,
                    index + 1,
                    errors.join("；")
                )
                .into());
            }
            let carrier = carrier::Carrier::new(connection)?;
            let mut next: Vec<Chain> = Vec::new();
            for chain in &chains {
                for node in &nodes {
                    let available = if forward {
                        let supported = carrier.wires();
                        [
                            chain.networks[0] && supported[0],
                            chain.networks[1] && supported[1],
                        ]
                    } else {
                        carrier.requests(node.core, chain.networks)
                    };
                    if available == [false, false]
                        || next.iter().any(|chain| chain.networks == available)
                    {
                        continue;
                    }
                    let mut path = chain.nodes.clone();
                    path.push(Rc::clone(node));
                    next.push(Chain {
                        nodes: path,
                        networks: available,
                    });
                }
            }
            if next.is_empty()
                && index > 0
                && payload == Payload::Proxy
                && nodes
                    .iter()
                    .any(|node| carrier.requests(node.core, [true, true]) != [false, false])
            {
                let prefix: BTreeSet<_> = chains
                    .iter()
                    .map(|path| match path.networks {
                        [true, true] => "TCP + UDP",
                        [true, false] => "TCP",
                        [false, true] => "UDP",
                        _ => unreachable!(),
                    })
                    .collect();
                return Err(format!(
                    "出站 {} 第 {} 段（{}）之后可用 {}，无法承载第 {} 段（{}）",
                    source.name,
                    index,
                    source.connections[index - 1].summary(),
                    prefix.into_iter().collect::<Vec<_>>().join(" 或 "),
                    index + 1,
                    connection.summary(),
                )
                .into());
            }
            chains = next;
        }
        Ok(chains)
    }

    fn outbound(
        &mut self,
        uuid: Uuid,
        preferred: Core,
        network: graph::Network,
        payload: Payload,
    ) -> Result<Endpoint> {
        let plans = self.chains(uuid, preferred, payload)?;
        let selected = plans
            .iter()
            .position(|chain| chain.supports(network))
            .ok_or("出站无法传递请求的网络类型")?;
        let nodes = plans[selected].nodes.clone();
        if let Some(endpoint) = self.outbounds.get(&(uuid, preferred, payload, selected)) {
            return Ok(endpoint.clone());
        }
        let mut endpoint = None;
        for (index, node) in nodes.into_iter().enumerate() {
            let core = node.core;
            let service = self.service(core, node.globals.clone(), node.environment.clone());
            let mut value = node.value.clone();
            let suffix = match payload {
                Payload::Proxy => "",
                Payload::Connection => "-forward",
            };
            let tag = format!("{uuid}-{}{suffix}-{selected}-{index}", key(preferred));
            value.insert(
                if core == Core::Mihomo { "name" } else { "tag" }.to_owned(),
                json!(tag),
            );
            if let Some(parent) = &endpoint {
                let parent = self.bridge(service, parent)?;
                match core {
                    Core::SingBox => {
                        value.insert("detour".to_owned(), json!(parent));
                    }
                    Core::Mihomo => {
                        value.insert("dialer-proxy".to_owned(), json!(parent));
                    }
                    Core::Xray => {
                        if value
                            .get("protocol")
                            .is_some_and(|protocol| protocol == "freedom")
                            && let Some(Value::Object(settings)) = value.get_mut("settings")
                        {
                            settings.remove("finalRules");
                        }
                        let mut stream = value.entry("streamSettings").or_insert_with(|| json!({}));
                        loop {
                            let socket = stream
                                .as_object_mut()
                                .unwrap()
                                .entry("sockopt")
                                .or_insert_with(|| json!({}));
                            socket
                                .as_object_mut()
                                .unwrap()
                                .insert("dialerProxy".to_owned(), json!(parent));
                            match stream
                                .get_mut("xhttpSettings")
                                .and_then(|http| http.get_mut("downloadSettings"))
                            {
                                Some(download) => stream = download,
                                None => break,
                            }
                        }
                    }
                }
            }
            self.services[service].outbounds.push(json!(value));
            endpoint = Some(Endpoint {
                service,
                tag,
                resolve_udp: node.resolve_udp,
            });
        }
        let endpoint = endpoint.ok_or("出站中没有连接")?;
        self.outbounds
            .insert((uuid, preferred, payload, selected), endpoint.clone());
        Ok(endpoint)
    }

    fn bridge(&mut self, service: usize, target: &Endpoint) -> Result<String> {
        if service == target.service && !target.resolve_udp {
            return Ok(target.tag.clone());
        }
        let tag = format!("relay-{}-{}", target.service, target.tag);
        let client = format!("{service}-{tag}");
        if let Some(endpoint) = self.bridges.get(&client) {
            return Ok(endpoint.tag.clone());
        }
        let port = if let Some(&port) = self.ports.get(&tag) {
            port
        } else {
            let core = self.services[target.service].core;
            let mut networks = BTreeSet::from([graph::Network::Tcp]);
            if core == Core::Mihomo {
                networks.insert(graph::Network::Udp);
            }
            let port = self.port(&tag, networks)?;
            let listener = match core {
                Core::Xray => json!({
                    "tag": tag, "listen": "127.0.0.1", "port": port,
                    "protocol": "socks", "settings": {"auth": "noauth", "udp": true, "ip": "127.0.0.1"},
                }),
                Core::SingBox => json!({
                    "tag": tag, "type": "socks", "listen": "127.0.0.1", "listen_port": port,
                }),
                Core::Mihomo => json!({
                    "name": tag, "type": "socks", "listen": "127.0.0.1",
                    "port": port.to_string(), "udp": true, "users": [],
                }),
            };
            self.services[target.service].listeners.push(listener);
            self.services[target.service].rules.insert(
                0,
                routing::Rule {
                    inbound: vec![tag.clone()],
                    user: None,
                    protocol: None,
                    network: None,
                    condition: Condition::Always,
                    outbound: target.tag.clone(),
                    resolve_udp: target.resolve_udp,
                    target: None,
                },
            );
            port
        };
        let core = self.services[service].core;
        let value = match core {
            Core::Xray => json!({
                "tag": tag, "protocol": "socks", "settings": {"address": "127.0.0.1", "port": port},
            }),
            Core::SingBox => json!({
                "tag": tag, "type": "socks", "server": "127.0.0.1", "server_port": port,
            }),
            Core::Mihomo => json!({
                "name": tag, "type": "socks5", "server": "127.0.0.1", "port": port, "udp": true,
            }),
        };
        self.services[service].outbounds.push(value);
        self.bridges.insert(
            client,
            Endpoint {
                service,
                tag: tag.clone(),
                resolve_udp: false,
            },
        );
        Ok(tag)
    }

    fn reject(&mut self) -> Result<u16> {
        if let Some(&port) = self.ports.get("reject") {
            return Ok(port);
        }
        let port = self.port("reject", BTreeSet::from([graph::Network::Tcp]))?;
        let service = self.service(Core::SingBox, Map::new(), BTreeMap::new());
        self.services[service].listeners.push(json!({
            "type": "direct", "tag": "reject", "listen": "127.0.0.1", "listen_port": port, "network": "tcp",
        }));
        self.services[service].rules.push(routing::Rule {
            inbound: vec!["reject".to_owned()],
            user: None,
            protocol: None,
            network: Some(graph::Network::Tcp),
            condition: Condition::Always,
            outbound: "block".to_owned(),
            resolve_udp: false,
            target: None,
        });
        Ok(port)
    }

    fn port(&mut self, tag: &str, networks: BTreeSet<graph::Network>) -> Result<u16> {
        if let Some(&port) = self.ports.get(tag) {
            return Ok(port);
        }
        let previous = self.previous.get(tag).copied();
        let initial = match previous {
            Some(port) => port,
            None => {
                let mut bytes = [0; 2];
                getrandom::fill(&mut bytes)
                    .map_err(|error| format!("分配核心转交端口失败：{error}"))?;
                u16::from_ne_bytes(bytes)
            }
        };
        let mut binding = binding::Binding::local(initial, networks)?;
        let reserved: BTreeSet<_> = self
            .reserved
            .iter()
            .filter(|reserved| reserved.intersects(&binding))
            .flat_map(|reserved| reserved.ports.iter().copied())
            .collect();
        let mut selected = previous.filter(|port| *port != 0 && !reserved.contains(port));
        if selected.is_none() {
            let mut last_error = None;
            for offset in 0..u32::from(u16::MAX) {
                self.progress.check()?;
                let port = ((u32::from(initial) + offset) % u32::from(u16::MAX) + 1) as u16;
                if reserved.contains(&port) {
                    continue;
                }
                let tcp = if binding.networks.contains(&graph::Network::Tcp) {
                    match TcpListener::bind(("127.0.0.1", port)) {
                        Ok(socket) => Some(socket),
                        Err(error)
                            if matches!(
                                error.kind(),
                                ErrorKind::AddrInUse | ErrorKind::PermissionDenied
                            ) =>
                        {
                            last_error = Some(error);
                            continue;
                        }
                        Err(error) => return Err(error.into()),
                    }
                } else {
                    None
                };
                let udp = if binding.networks.contains(&graph::Network::Udp) {
                    match UdpSocket::bind(("127.0.0.1", port)) {
                        Ok(socket) => Some(socket),
                        Err(error)
                            if matches!(
                                error.kind(),
                                ErrorKind::AddrInUse | ErrorKind::PermissionDenied
                            ) =>
                        {
                            last_error = Some(error);
                            continue;
                        }
                        Err(error) => return Err(error.into()),
                    }
                } else {
                    None
                };
                self.sockets.push((tcp, udp));
                selected = Some(port);
                break;
            }
            if selected.is_none() {
                return Err(format!(
                    "核心转交没有可用的本机端口：{}",
                    last_error.map_or_else(
                        || "端口均被监听配置占用".to_owned(),
                        |error| error.to_string()
                    )
                )
                .into());
            }
        }
        let port = selected.unwrap();
        binding.ports = BTreeSet::from([port]);
        self.reserved.push(binding);
        self.ports.insert(tag.to_owned(), port);
        Ok(port)
    }
}

fn matches_core(requested: connection::Core, core: Core) -> bool {
    matches!(requested, connection::Core::Auto)
        || matches!(
            (requested, core),
            (connection::Core::Xray, Core::Xray)
                | (connection::Core::SingBox, Core::SingBox)
                | (connection::Core::Mihomo, Core::Mihomo)
        )
}

fn key(core: Core) -> &'static str {
    match core {
        Core::Xray => "xray",
        Core::SingBox => "sing-box",
        Core::Mihomo => "mihomo",
    }
}

#[derive(Debug)]
struct Unsupported(String);

impl fmt::Display for Unsupported {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(&self.0)
    }
}

impl std::error::Error for Unsupported {}

fn unsupported<T>(message: impl Into<String>) -> Result<T> {
    Err(Unsupported(message.into()).into())
}

fn path(store: &Store, value: &str) -> PathBuf {
    store.directory.join(value)
}

fn certificate_paths(store: &Store, inbound: &Inbound) -> Result<(PathBuf, PathBuf)> {
    Ok(certificate::paths(store, &certificate::name(inbound)?))
}

fn pem(store: &Store, inline: &[String], files: &[String]) -> Result<Vec<String>> {
    let mut values = inline.to_vec();
    for file in files {
        values.push(fs::read_to_string(path(store, file))?);
    }
    Ok(values)
}

fn digest(value: &str) -> Result<Vec<u8>> {
    let compact = value.replace(':', "");
    let bytes = if compact.len() == 64 && compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        (0..compact.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&compact[index..index + 2], 16))
            .collect::<std::result::Result<Vec<_>, _>>()?
    } else {
        STANDARD.decode(value)?
    };
    if bytes.len() != 32 {
        return Err("SHA-256 固定值需要包含 32 字节".into());
    }
    Ok(bytes)
}

fn hashes(values: &[String]) -> Result<Vec<String>> {
    values
        .iter()
        .map(|value| Ok(STANDARD.encode(digest(value)?)))
        .collect()
}

pub(crate) fn hex_hashes(values: &[String]) -> Result<Vec<String>> {
    values
        .iter()
        .map(|value| {
            Ok(digest(value)?
                .into_iter()
                .map(|byte| format!("{byte:02x}"))
                .collect())
        })
        .collect()
}

fn single_headers(headers: &BTreeMap<String, Vec<String>>) -> Result<BTreeMap<String, String>> {
    headers
        .iter()
        .map(|(name, values)| match values.as_slice() {
            [value] => Ok((name.clone(), value.clone())),
            _ => unsupported(format!("这个核心的 HTTP 请求头每个名称使用一个值：{name}")),
        })
        .collect()
}
