use std::collections::HashSet;

use uuid::Uuid;

use crate::{
    Result,
    config::{Config, Store},
    connection::{self, Connection},
    graph::{Graph, Network, Payload},
    inbound::{Core, Inbound, Protocol},
    outbound::Selection,
    progress::Progress,
    route::Destination,
    user::User,
};

struct Builder<'a> {
    store: &'a Store,
    config: &'a Config,
    graph: Graph<'a>,
    progress: &'a Progress,
}

pub fn build(
    store: &Store,
    deployment: &crate::service::Deployment,
    inbound: Option<Uuid>,
    user: Option<Uuid>,
    progress: &Progress,
) -> Result<Vec<Selection>> {
    let config = &deployment.config;
    let mut geodata = deployment.geodata;
    let Some(graph) = crate::native::analyze(store, config, &mut geodata, progress)? else {
        return Ok(Vec::new());
    };
    let mut builder = Builder {
        store,
        config,
        graph,
        progress,
    };
    let mut values = Vec::new();
    let mut seen = HashSet::new();
    for index in 0..builder.graph.entries.len() {
        let source = builder.graph.entries[index].inbound;
        if !source.listen.enabled || inbound.is_some_and(|uuid| uuid != source.uuid) {
            continue;
        }
        let users = config
            .users
            .iter()
            .filter(|value| user.is_none_or(|uuid| value.uuid == uuid))
            .map(Some)
            .chain(user.is_none().then_some(None));
        for user in users {
            for (authenticated, connections) in builder.paths(index, user, &mut HashSet::new())? {
                if !seen.insert(serde_json::to_string(&connections)?) {
                    continue;
                }
                let name = if authenticated && let Some(user) = user {
                    format!("{} / {}", user.name, source.name)
                } else {
                    source.name.clone()
                };
                values.push(Selection { name, connections });
            }
        }
    }
    Ok(values)
}

pub fn copy(
    screen: &mut crate::tui::Screen,
    store: &Store,
    inbound: Option<Uuid>,
    user: Option<Uuid>,
) -> Result<()> {
    crate::share::copy(screen, "连接资料", |screen, links| {
        screen.work("生成连接资料", "", |progress| {
            let deployment = crate::service::Deployment::load(store)?;
            let profiles = build(store, &deployment, inbound, user, progress)?;
            if profiles.is_empty() {
                return Err("当前没有可用的接入连接".into());
            }
            if links {
                Ok(profiles
                    .iter()
                    .map(|profile| crate::share::path(&profile.connections, &profile.name, store))
                    .collect::<Result<Vec<_>>>()?
                    .join("\n"))
            } else {
                Ok(serde_json::to_string(&profiles)?)
            }
        })
    })
}

impl Builder<'_> {
    fn paths(
        &mut self,
        index: usize,
        user: Option<&User>,
        visiting: &mut HashSet<usize>,
    ) -> Result<Vec<(bool, Vec<Connection>)>> {
        self.progress.check()?;
        if !visiting.insert(index) {
            return Ok(Vec::new());
        }
        let entry = &self.graph.entries[index];
        let source = entry.inbound;
        let authenticated = source.users && source.protocol.users();
        if authenticated && user.is_none() {
            visiting.remove(&index);
            return Ok(Vec::new());
        }
        let identity = user.filter(|_| authenticated).map(|user| user.uuid);
        let mut routes = Vec::new();
        for account in entry
            .accounts
            .iter()
            .filter(|account| account.user.map(|user| user.uuid) == identity)
        {
            for rule in &account.rules {
                let route = (account.network, rule.destination);
                if rule.destination != Destination::Block && !routes.contains(&route) {
                    routes.push(route);
                }
            }
        }
        if routes.is_empty() {
            visiting.remove(&index);
            return Ok(Vec::new());
        }
        let clients = self.clients(source, user.filter(|_| authenticated))?;
        let payload = Payload::from(&source.protocol);
        let mut result = Vec::new();
        for (network, destination) in routes {
            match destination {
                Destination::Block => {}
                Destination::Outbound(_) if payload == Payload::Proxy => {
                    result.extend(
                        clients
                            .iter()
                            .filter(|client| carries(client, source, network))
                            .map(|client| (authenticated, vec![client.clone()])),
                    );
                }
                Destination::Inbound(uuid) => {
                    let Some(next) = self
                        .graph
                        .entries
                        .iter()
                        .position(|entry| entry.inbound.uuid == uuid)
                    else {
                        continue;
                    };
                    let paths = self.paths(next, user, visiting)?;
                    for (child_user, mut path) in paths {
                        if !crate::native::forward::networks(&path[0])?[network as usize] {
                            continue;
                        }
                        let (server, _) = path[0].server().unwrap();
                        let addresses =
                            self.graph
                                .addresses(index, identity, network, destination, server)?;
                        let receiver = self.graph.entries[next].inbound;
                        if network == Network::Tcp
                            && self.graph.entries[next].accounts.iter().any(|account| {
                                account.network == Network::Udp
                                    && account.user.map(|user| user.uuid)
                                        == user
                                            .filter(|_| receiver.users && receiver.protocol.users())
                                            .map(|user| user.uuid)
                            })
                            && crate::native::listener::accepts(
                                receiver,
                                Network::Tcp,
                                Network::Udp,
                                crate::graph::Layer::Transport,
                            )
                        {
                            stream(&mut path[0], receiver.core);
                        }
                        for address in addresses {
                            path[0].set_server(&address);
                            for client in clients
                                .iter()
                                .filter(|client| carries(client, source, network))
                            {
                                let mut connections = vec![client.clone()];
                                connections.extend(path.clone());
                                result.push((authenticated || child_user, connections));
                            }
                        }
                    }
                }
                Destination::Outbound(uuid) => {
                    let target = self
                        .config
                        .outbounds
                        .iter()
                        .find(|value| value.uuid == uuid)
                        .and_then(|value| value.connections.last())
                        .unwrap();
                    for client in clients
                        .iter()
                        .filter(|client| carries(client, source, network))
                    {
                        result.push((authenticated, vec![client.clone(), self.remote(target)?]));
                    }
                }
            }
        }
        visiting.remove(&index);
        Ok(result)
    }

    fn clients(&self, source: &Inbound, user: Option<&User>) -> Result<Vec<Connection>> {
        let credentials = user
            .map(|user| (user.uuid, user.password.as_str()))
            .or_else(|| {
                source
                    .credentials
                    .as_ref()
                    .map(|value| (value.uuid, value.password.as_str()))
            });
        let uuid = credentials
            .map(|(uuid, _)| uuid.to_string())
            .unwrap_or_default();
        let password = credentials.map_or("", |(_, password)| password);
        let mut source = source.clone();
        if let Some(keys) = self.config.keys.get(&source.uuid) {
            keys.apply(&mut source);
        }
        let mut clients = Vec::new();
        for port in source.ports()? {
            self.progress.check()?;
            for security in self.security(&source)? {
                let server = source.listen.host.clone();
                let transport = source.transport.clone();
                match &source.protocol {
                    Protocol::Mixed(value) => {
                        let proxy = connection::Proxy {
                            server,
                            port,
                            username: credentials.map(|_| uuid.clone()),
                            password: credentials.map(|_| password.to_owned()),
                            ..connection::Proxy::default()
                        };
                        if value.http.enabled {
                            let versions = if value.http.versions.is_empty() {
                                vec![connection::HttpVersion::Auto]
                            } else {
                                value
                                    .http
                                    .versions
                                    .iter()
                                    .map(|version| match version {
                                        crate::inbound::HttpVersion::Http1 => {
                                            connection::HttpVersion::Http1
                                        }
                                        crate::inbound::HttpVersion::Http2 => {
                                            connection::HttpVersion::Http2
                                        }
                                        crate::inbound::HttpVersion::Http3 => {
                                            connection::HttpVersion::Http3
                                        }
                                    })
                                    .collect()
                            };
                            for version in versions {
                                clients.push(Connection::Http(connection::Http {
                                    proxy: proxy.clone(),
                                    security: security.clone(),
                                    transport: transport.clone(),
                                    http: connection::HttpOptions {
                                        version,
                                        ..connection::HttpOptions::default()
                                    },
                                    ..connection::Http::default()
                                }));
                            }
                        }
                        if value.socks.enabled {
                            clients.push(Connection::Socks(connection::Socks {
                                proxy,
                                security,
                                transport,
                                ..connection::Socks::default()
                            }));
                        }
                    }
                    Protocol::Vless(value) => {
                        let encryption = value
                            .encryption
                            .as_ref()
                            .map(|value| -> Result<String> {
                                let keys = self
                                    .config
                                    .keys
                                    .get(&source.uuid)
                                    .and_then(|keys| keys.encryption.as_ref())
                                    .ok_or("缺少已保存的 VLESS 加密材料")?;
                                Ok(crate::native::encryption::client(value, keys))
                            })
                            .transpose()?;
                        clients.push(Connection::Vless(crate::vless::Client {
                            server,
                            port,
                            uuid: uuid.clone(),
                            security,
                            transport,
                            vless: crate::vless::ClientOptions {
                                flow: value.flow,
                                encryption,
                                ..crate::vless::ClientOptions::default()
                            },
                            multiplex: multiplex(value.multiplex.as_ref()),
                            ..crate::vless::Client::default()
                        }));
                    }
                    Protocol::Vmess(value) => {
                        clients.push(Connection::Vmess(crate::vmess::Client {
                            server,
                            port,
                            uuid: uuid.clone(),
                            security,
                            transport,
                            vmess: crate::vmess::ClientOptions {
                                alter_id: value.alter_id,
                                ..crate::vmess::ClientOptions::default()
                            },
                            multiplex: multiplex(value.multiplex.as_ref()),
                            ..crate::vmess::Client::default()
                        }))
                    }
                    Protocol::Trojan(value) => {
                        clients.push(Connection::Trojan(crate::trojan::Client {
                            server,
                            port,
                            password: password.to_owned(),
                            security,
                            transport,
                            multiplex: multiplex(value.multiplex.as_ref()),
                            ..crate::trojan::Client::default()
                        }))
                    }
                    Protocol::Shadowsocks(value) => {
                        let credential = value.cipher.credential(password);
                        let password = if crate::native::shadowsocks::shared(
                            &source,
                            usize::from(credentials.is_some()),
                        ) {
                            format!(
                                "{}:{credential}",
                                value
                                    .password
                                    .as_deref()
                                    .ok_or("缺少已保存的 Shadowsocks 入口密钥")?
                            )
                        } else {
                            credential
                        };
                        clients.push(Connection::Shadowsocks(crate::shadowsocks::Client {
                            server,
                            port,
                            password,
                            security,
                            transport,
                            shadowsocks: crate::shadowsocks::ClientOptions {
                                cipher: value.cipher,
                                tcp: (!value.tcp).then_some(false),
                                udp: (!(value.tcp || value.udp)).then_some(false),
                                ..crate::shadowsocks::ClientOptions::default()
                            },
                            multiplex: multiplex(value.multiplex.as_ref()),
                            ..crate::shadowsocks::Client::default()
                        }));
                    }
                    Protocol::Hysteria2(value) => {
                        let Some((_, password)) = credentials else {
                            continue;
                        };
                        if value.ignore_client_bandwidth {
                            let server = value
                                .quic
                                .download_bandwidth
                                .as_deref()
                                .map(crate::native::transport::mbps)
                                .transpose()?
                                .unwrap_or_default();
                            let client = value
                                .client
                                .download_bandwidth
                                .as_deref()
                                .map(crate::native::transport::mbps)
                                .transpose()?
                                .unwrap_or_default();
                            if server > 0.0 && client == 0.0 {
                                return Err(
                                    "此 HY2 入口要求客户端下载带宽，请填写客户端 QUIC 的下载带宽"
                                        .into(),
                                );
                            }
                        }
                        clients.push(Connection::Hysteria2(crate::hysteria::Client {
                            server,
                            port,
                            password: password.to_owned(),
                            tls: security.tls().cloned().ok_or("Hysteria 2 入口使用 TLS")?,
                            hysteria: crate::hysteria::ClientOptions {
                                obfs: value.obfs.clone(),
                                quic: value.client.clone(),
                                ..crate::hysteria::ClientOptions::default()
                            },
                            ..crate::hysteria::Client::default()
                        }));
                    }
                    Protocol::AnyTls(_) => {
                        let Some((_, password)) = credentials else {
                            continue;
                        };
                        clients.push(Connection::AnyTls(crate::anytls::Client {
                            server,
                            port,
                            password: password.to_owned(),
                            security,
                            ..crate::anytls::Client::default()
                        }));
                    }
                    Protocol::Forward(_) => {
                        clients.push(Connection::Forward(crate::forward::Client {
                            server,
                            port,
                            security,
                            transport,
                            ..crate::forward::Client::default()
                        }))
                    }
                }
            }
        }
        Ok(clients)
    }

    fn security(&self, source: &Inbound) -> Result<Vec<connection::Security>> {
        let Some(server) = source.security.tls() else {
            return Ok(vec![connection::Security::None]);
        };
        let mut tls = connection::Tls {
            alpn: server.alpn.clone(),
            min_version: server.min_version.clone(),
            max_version: server.max_version.clone(),
            cipher_suites: server.cipher_suites.clone(),
            curves: server.curves.clone(),
            ..connection::Tls::default()
        };
        if let Some(ech) = &server.ech {
            tls.ech = Some(connection::Ech {
                config: Some(crate::ech::public(source, ech, self.store)?),
                ..connection::Ech::default()
            });
        }
        let Some(reality) = source.security.reality() else {
            tls.server_name = Some(crate::certificate::name(source)?);
            if !crate::certificate::public(tls.server_name.as_ref().unwrap()) {
                tls.certificates
                    .push(std::fs::read_to_string(crate::certificate::root(
                        self.store,
                    ))?);
            }
            return Ok(vec![connection::Security::Tls(tls)]);
        };
        let keys = self
            .config
            .keys
            .get(&source.uuid)
            .and_then(|keys| keys.reality.as_ref())
            .ok_or("缺少已保存的 REALITY 握手材料")?;
        let client = crate::reality::Client {
            tls,
            public_key: keys.public_key.clone(),
            signature_key: reality
                .signature
                .then(|| keys.signature_key.clone())
                .flatten(),
            ..crate::reality::Client::default()
        };
        let mut values = Vec::new();
        for name in reality.names(server.server_name.as_deref())? {
            for short_id in &keys.short_ids {
                let mut client = client.clone();
                client.tls.server_name = Some(name.clone());
                client.short_id = short_id.clone();
                values.push(connection::Security::Reality(Box::new(client)));
            }
        }
        Ok(values)
    }

    fn remote(&self, target: &Connection) -> Result<Connection> {
        let mut target = target.clone();
        let (core, network, tls) = match &mut target {
            Connection::Http(value) => (
                &mut value.proxy.core,
                &mut value.network,
                value.security.tls_mut(),
            ),
            Connection::Socks(value) => (
                &mut value.proxy.core,
                &mut value.network,
                value.security.tls_mut(),
            ),
            Connection::Vless(value) => (
                &mut value.core,
                &mut value.network,
                value.security.tls_mut(),
            ),
            Connection::Vmess(value) => (
                &mut value.core,
                &mut value.network,
                value.security.tls_mut(),
            ),
            Connection::Trojan(value) => (
                &mut value.core,
                &mut value.network,
                value.security.tls_mut(),
            ),
            Connection::Shadowsocks(value) => (
                &mut value.core,
                &mut value.network,
                value.security.tls_mut(),
            ),
            Connection::Hysteria2(value) => {
                (&mut value.core, &mut value.network, Some(&mut value.tls))
            }
            Connection::AnyTls(value) => (
                &mut value.core,
                &mut value.network,
                value.security.tls_mut(),
            ),
            Connection::Forward(value) => (
                &mut value.core,
                &mut value.network,
                value.security.tls_mut(),
            ),
            Connection::Warp(value) => {
                value.server = Some(value.server().to_owned());
                (&mut value.core, &mut value.network, None)
            }
            Connection::Direct(_) => return Ok(target),
        };
        *core = connection::Core::Auto;
        *network = connection::Network::default();
        let Some(tls) = tls else {
            return Ok(target);
        };
        for file in tls.certificate_files.drain(..) {
            tls.certificates
                .push(std::fs::read_to_string(self.store.directory.join(file))?);
        }
        for (inline, file) in [
            (
                &mut tls.client_certificate,
                &mut tls.client_certificate_file,
            ),
            (&mut tls.client_key, &mut tls.client_key_file),
        ] {
            if let Some(file) = file.take()
                && inline.is_none()
            {
                *inline = Some(std::fs::read_to_string(self.store.directory.join(file))?);
            }
        }
        if let Some(ech) = &mut tls.ech
            && let Some(file) = ech.config_file.take()
            && ech.config.is_none()
        {
            ech.config = Some(std::fs::read_to_string(self.store.directory.join(file))?);
        }
        Ok(target)
    }
}

fn stream(client: &mut Connection, core: Core) {
    let (uot, multiplex) = match client {
        Connection::Socks(value) => (&mut value.socks.udp_over_tcp, &mut value.multiplex),
        Connection::Shadowsocks(value) => {
            (&mut value.shadowsocks.udp_over_tcp, &mut value.multiplex)
        }
        _ => return,
    };
    if multiplex
        .as_ref()
        .is_some_and(|multiplex| !multiplex.tcp_only)
    {
        return;
    }
    if core == Core::Xray {
        *multiplex = Some(crate::multiplex::Client {
            protocol: crate::multiplex::Protocol::MuxCool,
            ..crate::multiplex::Client::default()
        });
    } else {
        *uot = Some(2);
    }
}

fn multiplex(source: Option<&crate::multiplex::Server>) -> Option<crate::multiplex::Client> {
    source.map(|value| crate::multiplex::Client {
        padding: value.padding,
        brutal: value.brutal.as_ref().map(|value| crate::multiplex::Brutal {
            upload: value.download,
            download: value.upload,
        }),
        ..crate::multiplex::Client::default()
    })
}

fn carries(client: &Connection, source: &Inbound, network: Network) -> bool {
    !matches!(client, Connection::Http(_) if network == Network::Udp && source.core != Core::SingBox)
}
