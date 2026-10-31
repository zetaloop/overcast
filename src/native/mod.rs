mod binding;
pub(crate) mod encryption;
mod listener;
mod mihomo;
mod multiplex;
mod options;
mod reality;
mod routing;
mod singbox;
mod transport;
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
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tempfile::TempDir;
use uuid::Uuid;

use crate::{
    Result,
    condition::Condition,
    config::{Config, Store},
    connection::{self, Connection},
    graph,
    inbound::{Core, Protocol},
    progress::Progress,
    route::Destination,
};

pub struct Prepared {
    pub id: Uuid,
    pub keys: BTreeMap<Uuid, crate::keys::Keys>,
    directory: TempDir,
}

impl Prepared {
    pub fn keep(self) {
        let _ = self.directory.keep();
    }
}

#[derive(Default, Deserialize, Serialize)]
pub struct State {
    pub ports: BTreeMap<String, u16>,
    pub instances: Vec<Instance>,
    pub certificates: BTreeSet<String>,
}

#[derive(Deserialize, Serialize)]
pub struct Instance {
    pub core: Core,
    pub file: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub environment: BTreeMap<String, String>,
}

struct Service {
    core: Core,
    globals: Map<String, Value>,
    environment: BTreeMap<String, String>,
    listeners: Vec<Value>,
    outbounds: Vec<Value>,
    rules: Vec<routing::Rule>,
}

#[derive(Clone)]
struct Endpoint {
    service: usize,
    tag: String,
    resolve_udp: bool,
}

struct Node {
    core: Core,
    globals: Map<String, Value>,
    environment: BTreeMap<String, String>,
    value: Map<String, Value>,
    resolve_udp: bool,
}

#[derive(Clone)]
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
    chains: HashMap<(Uuid, Core), Vec<Chain>>,
    outbounds: HashMap<(Uuid, Core, usize), Endpoint>,
    bridges: BTreeMap<String, Endpoint>,
    previous: BTreeMap<String, u16>,
    ports: BTreeMap<String, u16>,
    reserved: Vec<binding::Binding>,
    sockets: Vec<(TcpListener, Option<UdpSocket>)>,
}

pub fn prepare(store: &Store, config: &Config, progress: &Progress) -> Result<Option<Prepared>> {
    let mut builder = Builder {
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
    };
    let Some(mut graph) = graph::build(store, config, progress, |core, destination, network| {
        Ok(match destination {
            Destination::Block => false,
            Destination::Direct => true,
            Destination::Outbound(uuid) => builder
                .chains(uuid, core)?
                .iter()
                .any(|chain| chain.supports(network)),
        })
    })?
    else {
        return Ok(None);
    };
    if let Some(id) = config.runtime {
        let bytes = fs::read(
            store
                .directory
                .join("runtime")
                .join(id.to_string())
                .join("state.json"),
        )?;
        builder.previous = serde_json::from_slice::<State>(&bytes)?.ports;
    }
    let listeners = listener::build(store, &mut graph, &config.keys, progress)?;
    builder.reserved = listeners
        .iter()
        .map(|listener| listener.binding.clone())
        .collect();
    let mut certificates = BTreeSet::new();
    let mut keys = config.keys.clone();
    reality::prepare(&listeners, &graph, &mut keys, progress)?;
    encryption::prepare(&listeners, &graph, &mut keys, progress)?;
    let step = progress.activity("生成核心配置");
    for (index, listener) in listeners.iter().enumerate() {
        progress.check()?;
        let mut source = listener.source.clone();
        if let Some(keys) = keys.get(&source.uuid) {
            keys.apply(&mut source);
        }
        let inbound = &source;
        step.detail(&inbound.name);
        let users: Vec<_> = listener
            .users
            .iter()
            .map(|(user, password)| (user.to_string(), password.clone()))
            .collect();
        let mut globals = Map::new();
        let values = match inbound.core {
            Core::Xray => xray::listeners(inbound, &users, store)?,
            Core::SingBox => singbox::listeners(inbound, &users, store)?,
            Core::Mihomo => mihomo::listeners(inbound, &users, store, &mut globals)?,
        };
        let values = if inbound.core == Core::SingBox {
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
        let fallback = inbound.core == Core::SingBox
            && values.iter().any(|value| {
                value.contains_key("fallback") || value.contains_key("fallback_for_alpn")
            });
        let service = builder.service(inbound.core, globals, BTreeMap::new());
        if inbound.tls.enabled && !inbound.tls.reality.enabled {
            certificates.extend(
                listener
                    .members
                    .iter()
                    .map(|member| certificate_name(graph.entries[member.entry].inbound).to_owned()),
            );
        }
        let mut tags = Vec::new();
        for (part, mut value) in values.into_iter().enumerate() {
            progress.check()?;
            if inbound.tls.enabled
                && inbound.tls.reality.enabled
                && let Destination::Outbound(uuid) = inbound.tls.reality.outbound
            {
                let endpoint = builder.outbound(uuid, inbound.core, graph::Network::Tcp)?;
                let parent = builder.bridge(service, &endpoint)?;
                match inbound.core {
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
            match inbound.core {
                Core::Xray => {
                    value.insert("tag".to_owned(), json!(tag));
                    if listener.binding.ports.is_empty() {
                        value.remove("port");
                    } else {
                        value.insert("port".to_owned(), json!(listener.binding.port_text()));
                    }
                    if inbound.tls.enabled && !inbound.tls.reality.enabled {
                        let paths: BTreeSet<_> = listener
                            .members
                            .iter()
                            .map(|member| {
                                certificate_paths(store, graph.entries[member.entry].inbound)
                            })
                            .collect();
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
            });
        }
        for member in &listener.members {
            let entry = &graph.entries[member.entry];
            for account in entry
                .accounts
                .iter()
                .filter(|account| member.carries(account.network))
            {
                let user = account.identity(entry.inbound).map(|user| {
                    if matches!(inbound.protocol, Protocol::Trojan(_)) {
                        listener
                            .users
                            .iter()
                            .find(|(_, password)| *password == &member.users[&user])
                            .unwrap()
                            .0
                            .to_string()
                    } else {
                        user.to_string()
                    }
                });
                for rule in &account.rules {
                    let outbound = match rule.destination {
                        Destination::Block => "block".to_owned(),
                        Destination::Direct => "direct".to_owned(),
                        Destination::Outbound(uuid) => {
                            let endpoint = builder.outbound(uuid, inbound.core, account.network)?;
                            builder.bridge(service, &endpoint)?
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
                    });
                }
            }
        }
    }
    progress.check()?;
    let id = Uuid::new_v4();
    let root = store.directory.join("runtime");
    store.create_dir(&root)?;
    let directory = tempfile::Builder::new()
        .prefix(&id.to_string())
        .rand_bytes(0)
        .tempdir_in(&root)?;
    store.own(directory.path())?;
    let mut state = State {
        ports: builder.ports,
        instances: Vec::new(),
        certificates,
    };
    let mut all_matchers = routing::Matchers::new(&graph.targets);
    for (index, service) in builder.services.into_iter().enumerate() {
        progress.check()?;
        let mut matchers = routing::Matchers::new(&graph.targets);
        let name = format!("{}-{index}", key(service.core));
        let working = directory.path().join(&name);
        store.create_dir(&working)?;
        let file = format!("{name}/config.json");
        let mut output = service.globals;
        let mut environment = service.environment;
        match service.core {
            Core::Xray => {
                environment.insert(
                    "XRAY_LOCATION_ASSET".to_owned(),
                    working.to_string_lossy().into_owned(),
                );
                let script = matchers.xray(&service.rules);
                let script_path = working.join("routing.lua");
                store.write(&script_path, |file| {
                    file.write_all(script.as_bytes())?;
                    Ok(())
                })?;
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
                        "script": script_path,
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
                output.insert("rules".to_owned(), json!(rules));
                output.insert("ipv6".to_owned(), json!(true));
                output.insert("geodata-mode".to_owned(), json!(true));
                output.insert("geosite-matcher".to_owned(), json!("mph"));
            }
        }
        all_matchers.used.extend(matchers.used);
        store.write(&directory.path().join(&file), |file| {
            serde_json::to_writer_pretty(file, &output)?;
            Ok(())
        })?;
        state.instances.push(Instance {
            core: service.core,
            file,
            environment,
        });
    }
    all_matchers.write(store, directory.path())?;
    for instance in &state.instances {
        let working = directory
            .path()
            .join(&instance.file)
            .parent()
            .unwrap()
            .to_owned();
        for name in ["geoip.dat", "geosite.dat"] {
            fs::hard_link(directory.path().join(name), working.join(name))?;
        }
    }
    store.write(&directory.path().join("state.json"), |file| {
        serde_json::to_writer_pretty(file, &state)?;
        Ok(())
    })?;
    progress.check()?;
    step.finish(format!("{} 个核心实例", state.instances.len()));
    Ok(Some(Prepared {
        id,
        directory,
        keys,
    }))
}

impl Builder<'_> {
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
        });
        index
    }

    fn chains(&mut self, uuid: Uuid, preferred: Core) -> Result<&[Chain]> {
        if self.chains.contains_key(&(uuid, preferred)) {
            return Ok(&self.chains[&(uuid, preferred)]);
        }
        let source = self
            .config
            .outbounds
            .iter()
            .find(|outbound| outbound.uuid == uuid)
            .ok_or_else(|| format!("找不到出站：{uuid}"))?;
        let mut chains = vec![Chain {
            nodes: Vec::new(),
            networks: [true, true],
        }];
        for (index, connection) in source.connections.iter().enumerate() {
            self.progress.check()?;
            if chains.is_empty() {
                break;
            }
            let requested = match connection {
                Connection::Direct(value) => value.core,
                Connection::Http(value) => value.proxy.core,
                Connection::Socks(value) => value.proxy.core,
                Connection::Vless(value) => value.core,
                Connection::Vmess(value) => value.core,
                Connection::Trojan(value) => value.core,
            };
            let mut candidates = vec![preferred];
            candidates.extend(
                [Core::Xray, Core::SingBox, Core::Mihomo]
                    .into_iter()
                    .filter(|core| *core != preferred),
            );
            let mut nodes = Vec::new();
            let mut errors = Vec::new();
            for core in candidates {
                if !matches_core(requested, core) {
                    continue;
                }
                if index != 0 && core != Core::Xray && matches!(connection, Connection::Direct(_)) {
                    errors.push(format!("{} 直连出站没有前置代理配置", key(core)));
                    continue;
                }
                let mut globals = Map::new();
                let result = match core {
                    Core::Xray => xray::outbound(connection, self.store),
                    Core::SingBox => singbox::outbound(connection, self.store, &mut globals),
                    Core::Mihomo => mihomo::outbound(connection, self.store, &mut globals),
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
                return Err(format!(
                    "出站 {} 第 {} 段连接无法生成：{}",
                    source.name,
                    index + 1,
                    errors.join("；")
                )
                .into());
            }
            let mut next: Vec<Chain> = Vec::new();
            for chain in &chains {
                for node in &nodes {
                    let networks = networks(connection, node.core, chain.networks);
                    if networks == [false, false]
                        || next.iter().any(|chain| chain.networks == networks)
                    {
                        continue;
                    }
                    let mut path = chain.nodes.clone();
                    path.push(Rc::clone(node));
                    next.push(Chain {
                        nodes: path,
                        networks,
                    });
                }
            }
            chains = next;
        }
        self.chains.insert((uuid, preferred), chains);
        Ok(&self.chains[&(uuid, preferred)])
    }

    fn outbound(
        &mut self,
        uuid: Uuid,
        preferred: Core,
        network: graph::Network,
    ) -> Result<Endpoint> {
        let plans = self.chains(uuid, preferred)?;
        let selected = plans
            .iter()
            .position(|chain| chain.supports(network))
            .ok_or("出站无法传递请求的网络类型")?;
        let nodes = plans[selected].nodes.clone();
        if let Some(endpoint) = self.outbounds.get(&(uuid, preferred, selected)) {
            return Ok(endpoint.clone());
        }
        let mut endpoint = None;
        for (index, node) in nodes.into_iter().enumerate() {
            let core = node.core;
            let service = self.service(core, node.globals.clone(), node.environment.clone());
            let mut value = node.value.clone();
            let tag = format!("{uuid}-{}-{selected}-{index}", key(preferred));
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
            .insert((uuid, preferred, selected), endpoint.clone());
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
            let previous = self.previous.get(&tag).copied();
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
                    let tcp = match TcpListener::bind(("127.0.0.1", port)) {
                        Ok(socket) => socket,
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
                    };
                    let udp = if core == Core::Mihomo {
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
            self.ports.insert(tag.clone(), port);
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

fn networks(source: &Connection, core: Core, parent: [bool; 2]) -> [bool; 2] {
    let multiplex = source.multiplex().is_some_and(|mux| !mux.tcp_only);
    match source {
        Connection::Direct(_) => parent,
        Connection::Http(value) => {
            let transport =
                if core == Core::SingBox && value.http.version == connection::HttpVersion::Http3 {
                    if value.tls.enabled && value.tls.reality.enabled {
                        !value.http.fixed_version && parent[0]
                    } else {
                        parent[1] || !value.http.fixed_version && parent[0]
                    }
                } else if core == Core::Xray {
                    value.transport.supported(&value.tls, parent)
                } else {
                    parent[0]
                };
            [transport, transport && (core == Core::SingBox || multiplex)]
        }
        Connection::Socks(value) => {
            let transport = if core == Core::Xray {
                value.transport.supported(&value.tls, parent)
            } else {
                parent[0]
            };
            [
                transport && value.socks.tcp.unwrap_or(true),
                transport
                    && (parent[1] || value.socks.udp_over_tcp.is_some() || multiplex)
                    && (value.socks.version == connection::SocksVersion::V5 || multiplex)
                    && value.socks.udp.unwrap_or(true),
            ]
        }
        Connection::Vless(value) => {
            let transport = value.transport.supported(&value.tls, parent);
            [
                transport && value.vless.tcp.unwrap_or(true),
                transport && value.vless.udp.unwrap_or(true),
            ]
        }
        Connection::Vmess(value) => {
            let transport = value.transport.supported(&value.tls, parent);
            [
                transport && value.vmess.tcp.unwrap_or(true),
                transport && value.vmess.udp.unwrap_or(true),
            ]
        }
        Connection::Trojan(value) => {
            let transport = value.transport.supported(&value.tls, parent);
            [
                transport && value.trojan.tcp.unwrap_or(true),
                transport && value.trojan.udp.unwrap_or(true),
            ]
        }
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

fn certificate_paths(store: &Store, inbound: &crate::inbound::Inbound) -> (PathBuf, PathBuf) {
    let name = utf8_percent_encode(certificate_name(inbound), NON_ALPHANUMERIC).to_string();
    let directory = store.directory.join("certificates").join(name);
    (directory.join("certificate.pem"), directory.join("key.pem"))
}

fn certificate_name(inbound: &crate::inbound::Inbound) -> &str {
    inbound
        .tls
        .server_name
        .as_deref()
        .filter(|name| !name.is_empty())
        .unwrap_or(&inbound.address)
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

fn hex_hashes(values: &[String]) -> Result<Vec<String>> {
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
