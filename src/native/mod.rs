mod mihomo;
mod options;
mod routing;
mod singbox;
mod xray;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt, fs,
    io::Write,
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
    inbound::Core,
    progress::Progress,
    route::Destination,
};

pub struct Prepared {
    pub id: Uuid,
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
}

struct Service {
    core: Core,
    globals: Map<String, Value>,
    listeners: Vec<Value>,
    outbounds: Vec<Value>,
    rules: Vec<routing::Rule>,
}

#[derive(Clone)]
struct Endpoint {
    service: usize,
    tag: String,
}

struct Node {
    core: Core,
    globals: Map<String, Value>,
    value: Map<String, Value>,
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
    reserved: BTreeSet<u16>,
    sockets: Vec<(TcpListener, UdpSocket)>,
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
        reserved: BTreeSet::new(),
        sockets: Vec::new(),
    };
    let graph = graph::build(store, config, progress, |core, destination, network| {
        Ok(match destination {
            Destination::Block => false,
            Destination::Direct => true,
            Destination::Outbound(uuid) => builder
                .chains(uuid, core)?
                .iter()
                .any(|chain| chain.supports(network)),
        })
    })?;
    if graph.entries.is_empty() {
        return Ok(None);
    }
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
    for entry in &graph.entries {
        builder.reserved.extend(entry.inbound.ports()?);
    }
    let mut certificates = BTreeSet::new();
    let step = progress.activity("生成核心配置");
    for entry in &graph.entries {
        progress.check()?;
        let inbound = entry.inbound;
        step.detail(&inbound.name);
        let users: Vec<_> = if inbound.users {
            entry
                .users
                .iter()
                .map(|user| (user.uuid.to_string(), user.password.clone()))
                .collect()
        } else {
            inbound
                .credentials
                .iter()
                .map(|credentials| (credentials.uuid.to_string(), credentials.password.clone()))
                .collect()
        };
        let mut globals = Map::new();
        let mut listeners = match inbound.core {
            Core::Xray => xray::listeners(inbound, &users, store)?,
            Core::SingBox => singbox::listeners(inbound, &users, store)?,
            Core::Mihomo => mihomo::listeners(inbound, &users, store, &mut globals)?,
        };
        let crate::inbound::Protocol::Mixed(protocol) = &inbound.protocol;
        if protocol.socks.enabled
            && !entry
                .accounts
                .iter()
                .any(|account| account.network == graph::Network::Udp)
        {
            for listener in &mut listeners {
                match inbound.core {
                    Core::Xray => {
                        listener.get_mut("settings").unwrap()["udp"] = json!(false);
                    }
                    Core::Mihomo => {
                        listener.insert("udp".to_owned(), json!(false));
                    }
                    Core::SingBox => {}
                }
            }
        }
        let service = builder.service(inbound.core, globals);
        if inbound.tls.enabled {
            certificates.insert(certificate_name(inbound).to_owned());
        }
        for port in inbound.ports()? {
            for (part, listener) in listeners.iter().enumerate() {
                let tag = format!("{}-{port}-{part}", inbound.uuid);
                let mut listener = listener.clone();
                match inbound.core {
                    Core::Xray => {
                        listener.insert("tag".to_owned(), json!(tag));
                        listener.insert("port".to_owned(), json!(port));
                    }
                    Core::SingBox => {
                        listener.insert("tag".to_owned(), json!(tag));
                        listener.insert("listen_port".to_owned(), json!(port));
                    }
                    Core::Mihomo => {
                        listener.insert("name".to_owned(), json!(tag));
                        listener.insert("port".to_owned(), json!(port.to_string()));
                    }
                }
                builder.services[service].listeners.push(json!(listener));
                for account in &entry.accounts {
                    let user = account.user.map(|user| user.uuid.to_string()).or_else(|| {
                        account
                            .network
                            .identity(inbound)
                            .then(|| {
                                inbound
                                    .credentials
                                    .as_ref()
                                    .map(|credentials| credentials.uuid.to_string())
                            })
                            .flatten()
                    });
                    for rule in &account.rules {
                        let outbound = match rule.destination {
                            Destination::Block => "block".to_owned(),
                            Destination::Direct => "direct".to_owned(),
                            Destination::Outbound(uuid) => {
                                let endpoint =
                                    builder.outbound(uuid, inbound.core, account.network)?;
                                builder.bridge(service, &endpoint)?
                            }
                        };
                        builder.services[service].rules.push(routing::Rule {
                            inbound: tag.clone(),
                            user: user.clone(),
                            network: Some(account.network),
                            condition: rule.condition.clone(),
                            outbound,
                        });
                    }
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
        let file = format!("{}-{index}.json", key(service.core));
        let mut output = service.globals;
        match service.core {
            Core::Xray => {
                let script = matchers.xray(&service.rules);
                let name = format!("xray-{index}.lua");
                store.write(&directory.path().join(&name), |file| {
                    file.write_all(script.as_bytes())?;
                    Ok(())
                })?;
                let mut outbounds = vec![
                    json!({"tag": "block", "protocol": "blackhole"}),
                    json!({"tag": "direct", "protocol": "freedom"}),
                ];
                outbounds.extend(service.outbounds);
                output.insert("inbounds".to_owned(), json!(service.listeners));
                output.insert("outbounds".to_owned(), json!(outbounds));
                output.insert("dns".to_owned(), json!({"servers": ["localhost"]}));
                output.insert(
                    "routing".to_owned(),
                    json!({
                        "script": directory.path().join(name),
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
        });
    }
    all_matchers.write(store, directory.path())?;
    store.write(&directory.path().join("state.json"), |file| {
        serde_json::to_writer_pretty(file, &state)?;
        Ok(())
    })?;
    progress.check()?;
    step.finish(format!("{} 个核心实例", state.instances.len()));
    Ok(Some(Prepared { id, directory }))
}

impl Builder<'_> {
    fn service(&mut self, core: Core, globals: Map<String, Value>) -> usize {
        if let Some(index) = self
            .services
            .iter()
            .position(|service| service.core == core && service.globals == globals)
        {
            return index;
        }
        let index = self.services.len();
        self.services.push(Service {
            core,
            globals,
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
                if index != 0 && core == Core::Mihomo && matches!(connection, Connection::Direct(_))
                {
                    errors.push("Mihomo 直连出站没有前置代理配置".to_owned());
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
                        nodes.push(Rc::new(Node {
                            core,
                            globals,
                            value,
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
            let service = self.service(core, node.globals.clone());
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
                        let stream = value.entry("streamSettings").or_insert_with(|| json!({}));
                        let socket = stream
                            .as_object_mut()
                            .unwrap()
                            .entry("sockopt")
                            .or_insert_with(|| json!({}));
                        socket
                            .as_object_mut()
                            .unwrap()
                            .insert("dialerProxy".to_owned(), json!(parent));
                    }
                }
            }
            self.services[service].outbounds.push(json!(value));
            endpoint = Some(Endpoint { service, tag });
        }
        let endpoint = endpoint.ok_or("出站中没有连接")?;
        self.outbounds
            .insert((uuid, preferred, selected), endpoint.clone());
        Ok(endpoint)
    }

    fn bridge(&mut self, service: usize, target: &Endpoint) -> Result<String> {
        if service == target.service {
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
            let port = if let Some(&port) = self
                .previous
                .get(&tag)
                .filter(|port| !self.reserved.contains(port))
            {
                port
            } else {
                loop {
                    let tcp = TcpListener::bind(("127.0.0.1", 0))?;
                    let port = tcp.local_addr()?.port();
                    if self.reserved.contains(&port) {
                        continue;
                    }
                    let udp = UdpSocket::bind(("127.0.0.1", port))?;
                    self.sockets.push((tcp, udp));
                    break port;
                }
            };
            self.reserved.insert(port);
            self.ports.insert(tag.clone(), port);
            let core = self.services[target.service].core;
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
                    inbound: tag.clone(),
                    user: None,
                    network: None,
                    condition: Condition::Always,
                    outbound: target.tag.clone(),
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
    match source {
        Connection::Direct(_) => parent,
        Connection::Http(value) => {
            let transport =
                if core == Core::SingBox && value.http.version == connection::HttpVersion::Http3 {
                    parent[1] || !value.http.fixed_version && parent[0]
                } else {
                    parent[0]
                };
            [transport, transport && core == Core::SingBox]
        }
        Connection::Socks(value) => [
            parent[0] && value.socks.tcp.unwrap_or(true),
            parent[0]
                && (parent[1] || value.socks.udp_over_tcp.is_some())
                && value.socks.version == connection::SocksVersion::V5
                && value.socks.udp.unwrap_or(true),
        ],
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
