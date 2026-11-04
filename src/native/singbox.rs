use serde_json::{Map, Value, json};

use crate::{
    Result,
    config::Store,
    connection::{self, AddressStrategy, Connection, FastOpen, SocksVersion},
    inbound::{self, Inbound, Protocol},
};

use super::{certificate_paths, hashes, listener::Credential, options::Options, path, unsupported};

pub fn outbound(
    source: &Connection,
    store: &Store,
    globals: &mut Map<String, Value>,
) -> Result<Map<String, Value>> {
    if matches!(source, Connection::Forward(_)) {
        return unsupported("sing-box 固定目标使用路由地址改写");
    }
    if source.multiplex().is_some()
        && !matches!(
            source,
            Connection::Vless(_)
                | Connection::Vmess(_)
                | Connection::Trojan(_)
                | Connection::Shadowsocks(_)
        )
    {
        return unsupported("sing-box HTTP/SOCKS 出站没有流复用配置");
    }
    if !matches!(
        source,
        Connection::Vless(_)
            | Connection::Vmess(_)
            | Connection::Trojan(_)
            | Connection::Shadowsocks(_)
    ) && source
        .transport()
        .is_some_and(|transport| !transport.is_default())
    {
        return unsupported("sing-box 的 HTTP/SOCKS 出站没有传输封装配置");
    }
    let (kind, proxy, network) = match source {
        Connection::Direct(value) => ("direct", None, &value.network),
        Connection::Http(value) => ("http", Some(&value.proxy), &value.network),
        Connection::Socks(value) => ("socks", Some(&value.proxy), &value.network),
        Connection::Vless(value) => ("vless", None, &value.network),
        Connection::Vmess(value) => ("vmess", None, &value.network),
        Connection::Trojan(value) => ("trojan", None, &value.network),
        Connection::Shadowsocks(value) => ("shadowsocks", None, &value.network),
        Connection::Forward(_) => unreachable!(),
    };
    let mut output = Map::from_iter([("type".to_owned(), json!(kind))]);
    dialer(network, &mut output)?;
    if let Some(proxy) = proxy {
        output.insert("server".to_owned(), json!(proxy.server));
        output.insert("server_port".to_owned(), json!(proxy.port));
        if let Some(username) = &proxy.username {
            output.insert("username".to_owned(), json!(username));
        }
        if let Some(password) = &proxy.password {
            output.insert("password".to_owned(), json!(password));
        }
    }
    match source {
        Connection::Direct(_) => {}
        Connection::Forward(_) => unreachable!(),
        Connection::Http(value) => {
            let mut options = Options::new(&value.http)?;
            options.take("version");
            output.insert(
                "version".to_owned(),
                json!(match value.http.version {
                    connection::HttpVersion::Auto => 0,
                    connection::HttpVersion::Http1 => 1,
                    connection::HttpVersion::Http2 => 2,
                    connection::HttpVersion::Http3 => 3,
                }),
            );
            options.rename(
                &mut output,
                &[("fixed_version", "disable_version_fallback")],
            );
            options.copy(&mut output, &["path", "headers"]);
            http(&mut options, &mut output)?;
            options.finish("sing-box HTTP")?;
            if value.tls.enabled {
                output.insert(
                    "tls".to_owned(),
                    client_tls(&value.transport.client_tls(&value.tls), store, globals)?,
                );
            }
        }
        Connection::Socks(value) => {
            if value.tls.enabled {
                return unsupported("sing-box SOCKS 出站没有 TLS 配置");
            }
            let mut options = Options::new(&value.socks)?;
            options.take("version");
            output.insert(
                "version".to_owned(),
                json!(match value.socks.version {
                    SocksVersion::V4 => "4",
                    SocksVersion::V4a => "4a",
                    SocksVersion::V5 => "5",
                }),
            );
            if let Some(version) = options.take("udp_over_tcp") {
                output.insert(
                    "udp_over_tcp".to_owned(),
                    json!({
                        "enabled": true,
                        "version": version,
                    }),
                );
            }
            options.take("tcp");
            options.take("udp");
            let mut network = Vec::new();
            if value.socks.tcp.unwrap_or(true) {
                network.push("tcp");
            }
            if value.socks.udp.unwrap_or(true) && value.socks.version == SocksVersion::V5 {
                network.push("udp");
            }
            output.insert("network".to_owned(), json!(network));
            options.finish("sing-box SOCKS")?;
        }
        Connection::Vless(value) => {
            let mut options = Options::new(&value.vless)?;
            output.insert("server".to_owned(), json!(value.server));
            output.insert("server_port".to_owned(), json!(value.port));
            output.insert("uuid".to_owned(), json!(value.uuid));
            options.take("flow");
            if value.vless.flow == crate::vless::Flow::Vision {
                output.insert("flow".to_owned(), json!("xtls-rprx-vision"));
            }
            if value.vless.encryption.as_deref() == Some("none") {
                options.take("encryption");
            }
            options.take("tcp");
            options.take("udp");
            let mut networks = Vec::new();
            if value.vless.tcp.unwrap_or(true) {
                networks.push("tcp");
            }
            if value.vless.udp.unwrap_or(true) {
                networks.push("udp");
            }
            output.insert("network".to_owned(), json!(networks));
            options.take("packet_encoding");
            if value.multiplex.as_ref().is_some_and(|mux| !mux.tcp_only) {
                options.take("udp_concurrency");
            } else {
                match value.vless.packet_encoding {
                    crate::connection::PacketEncoding::Default => {}
                    encoding => {
                        output.insert(
                            "packet_encoding".to_owned(),
                            json!(match encoding {
                                crate::connection::PacketEncoding::Packet => "",
                                crate::connection::PacketEncoding::PacketAddr => "packetaddr",
                                _ => "xudp",
                            }),
                        );
                    }
                }
            }
            if let Some(multiplex) = &value.multiplex {
                output.insert(
                    "multiplex".to_owned(),
                    super::multiplex::client(multiplex, inbound::Core::SingBox)?,
                );
            }
            options.finish("sing-box VLESS")?;
            if value.tls.enabled {
                output.insert(
                    "tls".to_owned(),
                    client_tls(&value.transport.client_tls(&value.tls), store, globals)?,
                );
            }
            if let Some(transport) = super::transport::singbox(
                &value.transport,
                false,
                value.tls.enabled,
                value.tls.reality.enabled,
            )? {
                output.insert("transport".to_owned(), transport);
            }
        }
        Connection::Vmess(value) => {
            let mut options = Options::new(&value.vmess)?;
            output.insert("server".to_owned(), json!(value.server));
            output.insert("server_port".to_owned(), json!(value.port));
            output.insert("uuid".to_owned(), json!(value.uuid));
            options.take("cipher");
            output.insert(
                "security".to_owned(),
                serde_json::to_value(value.vmess.cipher.resolve())?,
            );
            options.copy(
                &mut output,
                &["alter_id", "global_padding", "authenticated_length"],
            );
            if value.vmess.termination_signal == Some(true) {
                options.take("termination_signal");
            }
            options.take("tcp");
            options.take("udp");
            let mut networks = Vec::new();
            if value.vmess.tcp.unwrap_or(true) {
                networks.push("tcp");
            }
            if value.vmess.udp.unwrap_or(true) {
                networks.push("udp");
            }
            output.insert("network".to_owned(), json!(networks));
            options.take("packet_encoding");
            if value.multiplex.as_ref().is_some_and(|mux| !mux.tcp_only) {
                options.take("udp_concurrency");
            } else if value.vmess.packet_encoding != connection::PacketEncoding::Default {
                output.insert(
                    "packet_encoding".to_owned(),
                    json!(match value.vmess.packet_encoding {
                        connection::PacketEncoding::PacketAddr => "packetaddr",
                        connection::PacketEncoding::Xudp => "xudp",
                        _ => "",
                    }),
                );
            }
            options.finish("sing-box VMess")?;
            if let Some(multiplex) = &value.multiplex {
                output.insert(
                    "multiplex".to_owned(),
                    super::multiplex::client(multiplex, inbound::Core::SingBox)?,
                );
            }
            if value.tls.enabled {
                output.insert(
                    "tls".to_owned(),
                    client_tls(&value.transport.client_tls(&value.tls), store, globals)?,
                );
            }
            if let Some(transport) = super::transport::singbox(
                &value.transport,
                false,
                value.tls.enabled,
                value.tls.reality.enabled,
            )? {
                output.insert("transport".to_owned(), transport);
            }
        }
        Connection::Trojan(value) => {
            let mut options = Options::new(&value.trojan)?;
            output.insert("server".to_owned(), json!(value.server));
            output.insert("server_port".to_owned(), json!(value.port));
            output.insert("password".to_owned(), json!(value.password));
            options.take("tcp");
            options.take("udp");
            let mut networks = Vec::new();
            if value.trojan.tcp.unwrap_or(true) {
                networks.push("tcp");
            }
            if value.trojan.udp.unwrap_or(true) {
                networks.push("udp");
            }
            output.insert("network".to_owned(), json!(networks));
            options.finish("sing-box Trojan")?;
            if let Some(multiplex) = &value.multiplex {
                output.insert(
                    "multiplex".to_owned(),
                    super::multiplex::client(multiplex, inbound::Core::SingBox)?,
                );
            }
            if value.tls.enabled {
                output.insert(
                    "tls".to_owned(),
                    client_tls(&value.transport.client_tls(&value.tls), store, globals)?,
                );
            }
            if let Some(transport) = super::transport::singbox(
                &value.transport,
                false,
                value.tls.enabled,
                value.tls.reality.enabled,
            )? {
                output.insert("transport".to_owned(), transport);
            }
        }
        Connection::Shadowsocks(value) => {
            if value.tls.enabled || !value.transport.is_default() {
                return unsupported("sing-box Shadowsocks 通过 SIP003 插件配置传输封装");
            }
            let mut options = Options::new(&value.shadowsocks)?;
            output.insert("server".to_owned(), json!(value.server));
            output.insert("server_port".to_owned(), json!(value.port));
            output.insert(
                "method".to_owned(),
                super::shadowsocks::cipher(
                    value.shadowsocks.cipher,
                    inbound::Core::SingBox,
                    false,
                )?,
            );
            output.insert(
                "password".to_owned(),
                json!(value.shadowsocks.cipher.password(&value.password)?),
            );
            for name in ["cipher", "tcp", "udp", "plugin", "udp_over_tcp"] {
                options.take(name);
            }
            let mut networks = Vec::new();
            if value.shadowsocks.tcp.unwrap_or(true) {
                networks.push("tcp");
            }
            if value.shadowsocks.udp.unwrap_or(true) {
                networks.push("udp");
            }
            output.insert("network".to_owned(), json!(networks));
            if let Some(version) = value.shadowsocks.udp_over_tcp {
                if version > 2 {
                    return unsupported("UDP over TCP 使用版本 1 或 2");
                }
                if value.multiplex.is_some() {
                    return unsupported("sing-box Shadowsocks 的 UoT 与 S-Mux 分别建立连接");
                }
                output.insert(
                    "udp_over_tcp".to_owned(),
                    json!({"enabled": true, "version": if version == 0 { 2 } else { version }}),
                );
            }
            if let Some(multiplex) = &value.multiplex {
                output.insert(
                    "multiplex".to_owned(),
                    super::multiplex::client(multiplex, inbound::Core::SingBox)?,
                );
            }
            if let Some(plugin) = &value.shadowsocks.plugin {
                output.extend(super::shadowsocks::plugin(
                    plugin,
                    inbound::Core::SingBox,
                    &value.server,
                    store,
                    globals,
                )?);
            }
            options.finish("sing-box Shadowsocks")?;
        }
    }
    Ok(output)
}

pub fn listeners(
    source: &Inbound,
    users: &[(String, Credential)],
    store: &Store,
    target: Option<(&str, u16)>,
) -> Result<Vec<Map<String, Value>>> {
    if matches!(source.protocol, Protocol::Mixed(_)) && !source.transport.is_default() {
        return unsupported("sing-box 的 HTTP/SOCKS 入站没有传输封装配置");
    }
    let mut output = Map::from_iter([
        ("listen".to_owned(), json!(source.listen.address)),
        (
            "users".to_owned(),
            json!(
                users
                    .iter()
                    .map(|(name, credential)| match &source.protocol {
                        Protocol::Mixed(_) =>
                            json!({"username": name, "password": credential.password}),
                        Protocol::Vless(value) => {
                            let mut user = Map::from_iter([
                                ("name".to_owned(), json!(name)),
                                ("uuid".to_owned(), json!(name)),
                            ]);
                            if value.flow == crate::vless::Flow::Vision {
                                user.insert("flow".to_owned(), json!("xtls-rprx-vision"));
                            }
                            json!(user)
                        }
                        Protocol::Vmess(value) => {
                            let mut user = Map::from_iter([
                                ("name".to_owned(), json!(name)),
                                ("uuid".to_owned(), json!(name)),
                            ]);
                            if let Some(alter_id) = value.alter_id {
                                user.insert("alterId".to_owned(), json!(alter_id));
                            }
                            json!(user)
                        }
                        Protocol::Trojan(_) =>
                            json!({"name": name, "password": credential.password}),
                        Protocol::Shadowsocks(_) =>
                            json!({"name": name, "password": credential.password}),
                        Protocol::Forward(_) => unreachable!(),
                    })
                    .collect::<Vec<_>>()
            ),
        ),
    ]);
    let mut options = Options::new(&source.listen)?;
    options.take("address");
    options.rename(
        &mut output,
        &[
            ("interface", "bind_interface"),
            ("reuse_address", "reuse_addr"),
            ("namespace", "netns"),
        ],
    );
    options.copy(
        &mut output,
        &["routing_mark", "tcp_multi_path", "udp_fragment"],
    );
    options.invert(&mut output, "tcp_keep_alive", "disable_tcp_keep_alive");
    options.durations(
        &mut output,
        &[
            ("tcp_keep_alive_idle", "tcp_keep_alive"),
            ("tcp_keep_alive_interval", "tcp_keep_alive_interval"),
            ("udp_timeout", "udp_timeout"),
        ],
        None,
    )?;
    if let Some(value) = &source.listen.tcp_fast_open {
        match value {
            FastOpen::Enabled(value) => {
                output.insert("tcp_fast_open".to_owned(), json!(value));
                options.take("tcp_fast_open");
            }
            FastOpen::Queue(_) => {}
        }
    }
    options.finish("sing-box 监听")?;
    if let Protocol::Vless(value) = &source.protocol {
        if users.is_empty() {
            return unsupported("VLESS 入口需要认证用户");
        }
        let mut options = Options::new(value)?;
        options.take("flow");
        options.take("multiplex");
        if let Some(multiplex) = &value.multiplex {
            output.insert(
                "multiplex".to_owned(),
                super::multiplex::server(multiplex, inbound::Core::SingBox)?,
            );
        }
        options.finish("sing-box VLESS 入站")?;
        output.insert("type".to_owned(), json!("vless"));
        if source.tls.enabled {
            output.insert("tls".to_owned(), server_tls(source, store)?);
        }
        if let Some(transport) = super::transport::singbox(
            &source.transport,
            true,
            source.tls.enabled,
            source.tls.reality.enabled,
        )? {
            output.insert("transport".to_owned(), transport);
        }
        return Ok(vec![output]);
    }
    if let Protocol::Vmess(value) = &source.protocol {
        if users.is_empty() {
            return unsupported("VMess 入口需要认证用户");
        }
        let mut options = Options::new(value)?;
        options.take("alter_id");
        options.take("multiplex");
        options.finish("sing-box VMess 入站")?;
        output.insert("type".to_owned(), json!("vmess"));
        if let Some(multiplex) = &value.multiplex {
            output.insert(
                "multiplex".to_owned(),
                super::multiplex::server(multiplex, inbound::Core::SingBox)?,
            );
        }
        if source.tls.enabled {
            output.insert("tls".to_owned(), server_tls(source, store)?);
        }
        if let Some(transport) = super::transport::singbox(
            &source.transport,
            true,
            source.tls.enabled,
            source.tls.reality.enabled,
        )? {
            output.insert("transport".to_owned(), transport);
        }
        return Ok(vec![output]);
    }
    if let Protocol::Trojan(value) = &source.protocol {
        if users.is_empty() && value.fallbacks.is_empty() {
            return unsupported("Trojan 入口需要认证用户");
        }
        let mut options = Options::new(value)?;
        options.take("fallbacks");
        options.take("multiplex");
        options.finish("sing-box Trojan 入站")?;
        output.insert("type".to_owned(), json!("trojan"));
        if let Some(multiplex) = &value.multiplex {
            output.insert(
                "multiplex".to_owned(),
                super::multiplex::server(multiplex, inbound::Core::SingBox)?,
            );
        }
        if source.tls.enabled {
            output.insert("tls".to_owned(), server_tls(source, store)?);
        }
        if let Some(transport) = super::transport::singbox(
            &source.transport,
            true,
            source.tls.enabled,
            source.tls.reality.enabled,
        )? {
            output.insert("transport".to_owned(), transport);
        }
        fallbacks(source, &value.fallbacks, &mut output)?;
        return Ok(vec![output]);
    }
    if let Protocol::Shadowsocks(value) = &source.protocol {
        if source.tls.enabled || !source.transport.is_default() {
            return unsupported("sing-box Shadowsocks 入站使用原生 TCP/UDP 监听");
        }
        let multi = super::shadowsocks::multi(source, users.len());
        if value.cipher != crate::shadowsocks::Cipher::None
            && (users.is_empty() || !multi && users.len() > 1)
        {
            return unsupported("当前 Shadowsocks 算法的入站需要单个认证密钥");
        }
        let mut options = Options::new(value)?;
        for name in ["cipher", "tcp", "udp", "multiplex"] {
            options.take(name);
        }
        output.insert("type".to_owned(), json!("shadowsocks"));
        output.insert(
            "method".to_owned(),
            super::shadowsocks::cipher(value.cipher, inbound::Core::SingBox, true)?,
        );
        let mut networks = Vec::new();
        if value.tcp {
            networks.push("tcp");
        }
        if value.udp {
            networks.push("udp");
        }
        output.insert("network".to_owned(), json!(networks));
        if multi {
            if value.cipher.key_size().is_some() {
                options.take("password");
                output.insert(
                    "password".to_owned(),
                    json!(
                        value
                            .password
                            .as_ref()
                            .ok_or("缺少 Shadowsocks 入口共享密钥")?
                    ),
                );
            }
        } else {
            output.remove("users");
            if let Some((_, credential)) = users.first() {
                output.insert("password".to_owned(), json!(credential.password));
            }
        }
        if let Some(multiplex) = &value.multiplex {
            output.insert(
                "multiplex".to_owned(),
                super::multiplex::server(multiplex, inbound::Core::SingBox)?,
            );
        }
        options.finish("sing-box Shadowsocks 入站")?;
        return Ok(vec![output]);
    }
    if let Protocol::Forward(value) = &source.protocol {
        if value.user_level.is_some() {
            return unsupported("sing-box 固定转发入口没有用户等级配置");
        }
        if source.tls.enabled || !source.transport.is_default() {
            return unsupported("sing-box 固定转发入口使用原生 TCP/UDP 监听");
        }
        let (server, port) = target.ok_or("转发入口缺少后继连接")?;
        output.insert("type".to_owned(), json!("direct"));
        output.insert("override_address".to_owned(), json!(server));
        output.insert("override_port".to_owned(), json!(port));
        let mut networks = Vec::new();
        if value.tcp {
            networks.push("tcp");
        }
        if value.udp {
            networks.push("udp");
        }
        output.insert("network".to_owned(), json!(networks));
        return Ok(vec![output]);
    }
    let Protocol::Mixed(value) = &source.protocol else {
        unreachable!()
    };
    let mut options = Options::new(value)?;
    options.take("http");
    options.take("socks");
    options.take("udp");
    options.finish("sing-box HTTP/SOCKS")?;
    if value.socks.enabled {
        let mut options = Options::new(&value.socks)?;
        options.take("enabled");
        options.finish("sing-box SOCKS 入站")?;
    }
    if source.tls.enabled {
        if !value.http.enabled {
            return unsupported("sing-box 的 SOCKS TLS 使用 Mixed 入口，需要同时启用 HTTP");
        }
        output.insert("tls".to_owned(), server_tls(source, store)?);
    }
    if !value.http.enabled {
        output.insert("type".to_owned(), json!("socks"));
        return Ok(vec![output]);
    }
    let versions: Vec<_> = if value.http.versions.is_empty() {
        vec![1, 2]
    } else {
        value
            .http
            .versions
            .iter()
            .map(|version| match version {
                inbound::HttpVersion::Http1 => 1,
                inbound::HttpVersion::Http2 => 2,
                inbound::HttpVersion::Http3 => 3,
            })
            .collect()
    };
    let mut options = Options::new(&value.http)?;
    options.take("enabled");
    options.take("versions");
    if value.socks.enabled {
        if !versions.contains(&1) || !versions.contains(&2) {
            return unsupported("sing-box Mixed 的 HTTP/1 与 HTTP/2 共同启用");
        }
        let mut quic = Map::new();
        options.copy(
            &mut quic,
            &["initial_packet_size", "disable_path_mtu_discovery"],
        );
        options.finish("sing-box Mixed 的 HTTP")?;
        output.insert("type".to_owned(), json!("mixed"));
        if versions.contains(&3) {
            let mut packet = output.clone();
            packet.insert("type".to_owned(), json!("http"));
            packet.insert("version".to_owned(), json!([3]));
            packet.extend(quic);
            return Ok(vec![output, packet]);
        }
    } else {
        output.insert("type".to_owned(), json!("http"));
        output.insert("version".to_owned(), json!(versions));
        http(&mut options, &mut output)?;
        options.finish("sing-box HTTP 入站")?;
    }
    Ok(vec![output])
}

fn http(options: &mut Options, output: &mut Map<String, Value>) -> Result<()> {
    options.copy(
        output,
        &[
            "stream_receive_window",
            "connection_receive_window",
            "max_concurrent_streams",
            "initial_packet_size",
            "disable_path_mtu_discovery",
        ],
    );
    options.durations(
        output,
        &[
            ("idle_timeout", "idle_timeout"),
            ("keep_alive", "keep_alive_period"),
        ],
        None,
    )
}

pub fn dialer(source: &connection::Network, output: &mut Map<String, Value>) -> Result<()> {
    let mut options = Options::new(source)?;
    options.rename(
        output,
        &[
            ("interface", "bind_interface"),
            ("source_ipv4", "inet4_bind_address"),
            ("source_ipv6", "inet6_bind_address"),
            ("reuse_address", "reuse_addr"),
            ("namespace", "netns"),
            ("network_types", "network_type"),
            ("fallback_network_types", "fallback_network_type"),
        ],
    );
    options.copy(
        output,
        &[
            "bind_address_no_port",
            "protect_path",
            "routing_mark",
            "tcp_multi_path",
            "udp_fragment",
            "network_strategy",
        ],
    );
    options.invert(output, "tcp_keep_alive", "disable_tcp_keep_alive");
    options.durations(
        output,
        &[
            ("connect_timeout", "connect_timeout"),
            ("tcp_keep_alive_idle", "tcp_keep_alive"),
            ("tcp_keep_alive_interval", "tcp_keep_alive_interval"),
            ("fallback_delay", "fallback_delay"),
        ],
        None,
    )?;
    if let Some(value) = &source.tcp_fast_open {
        match value {
            FastOpen::Enabled(value) => {
                output.insert("tcp_fast_open".to_owned(), json!(value));
                options.take("tcp_fast_open");
            }
            FastOpen::Queue(_) => {}
        }
    }
    if let Some(strategy) = source.address_strategy {
        let value = match strategy {
            AddressStrategy::AsIs => "",
            AddressStrategy::Ipv4Only => "ipv4_only",
            AddressStrategy::Ipv6Only => "ipv6_only",
            AddressStrategy::PreferIpv4 => "prefer_ipv4",
            AddressStrategy::PreferIpv6 => "prefer_ipv6",
            _ => {
                return unsupported(format!(
                    "sing-box 无法表达地址策略：{}",
                    serde_json::to_value(strategy)?
                ));
            }
        };
        options.take("address_strategy");
        output.insert(
            "domain_resolver".to_owned(),
            json!({
                "server": "system",
                "strategy": value,
            }),
        );
    }
    options.finish("sing-box 连接")
}

fn fallbacks(
    source: &Inbound,
    rules: &[inbound::Fallback],
    output: &mut Map<String, Value>,
) -> Result<()> {
    let mut default = None;
    let mut protocols = Map::new();
    for rule in rules {
        let mut options = Options::new(rule)?;
        options.take("target");
        options.take("alpn");
        if rule.network.as_deref() == Some("tcp") {
            options.take("network");
        }
        if rule.proxy_protocol == Some(0) {
            options.take("proxy_protocol");
        }
        if rule.server_name.as_deref() == Some("") {
            options.take("server_name");
        }
        if rule.path.as_deref() == Some("") {
            options.take("path");
        }
        options.finish("sing-box 协议回落")?;
        let (host, port) = if let Ok(port) = rule.target.address().parse::<u16>() {
            ("localhost".to_owned(), port)
        } else {
            let address = url::Url::parse(&format!("tcp://{}", rule.target.address()))?;
            if address.path() != "" && address.path() != "/" {
                return unsupported("sing-box 回落使用 TCP 地址");
            }
            (
                crate::link::host(&address)?,
                address.port().ok_or("回落目标缺少端口")?,
            )
        };
        if port == 0 {
            return Err("请填写回落目标端口".into());
        }
        let target = json!({"server": host, "server_port": port});
        if let Some(alpn) = rule.alpn.as_ref().filter(|value| !value.is_empty()) {
            if source.tls.enabled {
                if source.tls.reality.enabled {
                    return unsupported("sing-box REALITY 不提供 ALPN 协商结果");
                }
                protocols.insert(alpn.clone(), target);
            }
        } else {
            default = Some(target);
        }
    }
    if let Some(default) = &default
        && !protocols.is_empty()
    {
        let mut alpn = source.tls.alpn.clone();
        match &source.transport {
            crate::transport::Transport::Http(_) => {
                if alpn.is_empty() {
                    alpn.push("http/1.1".to_owned());
                }
                alpn.push("h2".to_owned());
            }
            crate::transport::Transport::Grpc(_) => alpn.push("h2".to_owned()),
            crate::transport::Transport::HttpUpgrade(_) if alpn.is_empty() => {
                alpn.push("http/1.1".to_owned())
            }
            crate::transport::Transport::Quic if alpn.is_empty() => alpn.push("h3".to_owned()),
            _ => {}
        }
        for alpn in alpn {
            protocols.entry(alpn).or_insert_with(|| default.clone());
        }
    }
    if let Some(default) = default {
        output.insert("fallback".to_owned(), default);
    }
    if !protocols.is_empty() {
        output.insert("fallback_for_alpn".to_owned(), json!(protocols));
    }
    Ok(())
}

fn client_tls(
    source: &connection::Tls,
    store: &Store,
    globals: &mut Map<String, Value>,
) -> Result<Value> {
    if source.reality.enabled {
        return super::reality::singbox(source, store);
    }
    let mut options = Options::new(source)?;
    options.take("reality");
    let mut output = Map::new();
    options.copy(
        &mut output,
        &[
            "enabled",
            "server_name",
            "engine",
            "alpn",
            "min_version",
            "max_version",
            "cipher_suites",
            "client_certificate",
            "client_key",
            "kernel_tx",
            "kernel_rx",
            "fragment",
            "record_fragment",
            "spoof",
            "spoof_method",
        ],
    );
    options.rename(&mut output, &[("curves", "curve_preferences")]);
    options.invert(&mut output, "send_sni", "disable_sni");
    options.invert(&mut output, "verify_certificate", "insecure");
    options.durations(
        &mut output,
        &[
            ("handshake_timeout", "handshake_timeout"),
            ("fragment_delay", "fragment_fallback_delay"),
        ],
        None,
    )?;
    if let Some(value) = options.take("fingerprint") {
        output.insert(
            "utls".to_owned(),
            json!({"enabled": true, "fingerprint": value}),
        );
    }
    for (name, destination) in [
        ("client_certificate_file", "client_certificate_path"),
        ("client_key_file", "client_key_path"),
    ] {
        if let Some(value) = options.take(name) {
            output.insert(
                destination.to_owned(),
                json!(path(store, value.as_str().unwrap())),
            );
        }
    }
    for (name, destination, values) in [
        (
            "certificate_sha256",
            "certificate_sha256",
            &source.certificate_sha256,
        ),
        (
            "public_key_sha256",
            "certificate_public_key_sha256",
            &source.public_key_sha256,
        ),
    ] {
        if options.take(name).is_some() {
            output.insert(destination.to_owned(), json!(hashes(values)?));
        }
    }
    options.take("system_roots");
    options.take("certificates");
    options.take("certificate_files");
    if source.system_roots.is_some()
        || !source.certificates.is_empty()
        || !source.certificate_files.is_empty()
    {
        globals.insert("certificate".to_owned(), json!({
            "store": if source.system_roots == Some(true) { "system" } else { "none" },
            "certificate": source.certificates,
            "certificate_path": source.certificate_files.iter().map(|value| path(store, value)).collect::<Vec<_>>(),
        }));
    }
    options.take("ech");
    if source.ech.enabled {
        let mut ech = Map::from_iter([("enabled".to_owned(), json!(true))]);
        if let Some(value) = &source.ech.config {
            ech.insert("config".to_owned(), json!(crate::ech::pem(value)?));
        }
        if let Some(value) = &source.ech.config_file {
            ech.insert("config_path".to_owned(), json!(path(store, value)));
        }
        if let Some(value) = &source.ech.query_name {
            ech.insert("query_server_name".to_owned(), json!(value));
        }
        output.insert("ech".to_owned(), json!(ech));
    }
    options.finish("sing-box TLS")?;
    Ok(json!(output))
}

fn server_tls(source: &Inbound, store: &Store) -> Result<Value> {
    if source.tls.reality.enabled {
        if let Protocol::Mixed(protocol) = &source.protocol
            && protocol
                .http
                .versions
                .contains(&inbound::HttpVersion::Http3)
        {
            return unsupported("REALITY 握手使用 TCP，无法提供 HTTP/3 监听");
        }
        return super::reality::server(source);
    }
    let mut options = Options::new(&source.tls)?;
    options.take("reality");
    let (certificate, key) = certificate_paths(store, source)?;
    let mut output = Map::from_iter([
        ("certificate_path".to_owned(), json!(certificate)),
        ("key_path".to_owned(), json!(key)),
    ]);
    options.copy(
        &mut output,
        &[
            "enabled",
            "server_name",
            "alpn",
            "min_version",
            "max_version",
            "cipher_suites",
            "kernel_tx",
            "kernel_rx",
        ],
    );
    options.rename(
        &mut output,
        &[
            ("curves", "curve_preferences"),
            ("client_auth", "client_authentication"),
            ("client_certificates", "client_certificate"),
        ],
    );
    options.durations(
        &mut output,
        &[("handshake_timeout", "handshake_timeout")],
        None,
    )?;
    if options.take("client_certificate_files").is_some() {
        output.insert(
            "client_certificate_path".to_owned(),
            json!(
                source
                    .tls
                    .client_certificate_files
                    .iter()
                    .map(|value| path(store, value))
                    .collect::<Vec<_>>()
            ),
        );
    }
    for (name, destination, values) in [
        (
            "client_certificate_sha256",
            "client_certificate_sha256",
            &source.tls.client_certificate_sha256,
        ),
        (
            "client_public_key_sha256",
            "client_certificate_public_key_sha256",
            &source.tls.client_public_key_sha256,
        ),
    ] {
        if options.take(name).is_some() {
            output.insert(destination.to_owned(), json!(hashes(values)?));
        }
    }
    options.take("ech");
    if source.tls.ech.enabled {
        let mut ech = Map::from_iter([("enabled".to_owned(), json!(true))]);
        if !source.tls.ech.keys.is_empty() {
            ech.insert("key".to_owned(), json!(source.tls.ech.keys));
        }
        if let Some(value) = &source.tls.ech.key_file {
            ech.insert("key_path".to_owned(), json!(path(store, value)));
        }
        output.insert("ech".to_owned(), json!(ech));
    }
    options.finish("sing-box 服务端 TLS")?;
    Ok(json!(output))
}
