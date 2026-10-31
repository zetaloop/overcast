use serde_json::{Map, Value, json};

use crate::{
    Result,
    config::Store,
    connection::{self, AddressStrategy, Connection, FastOpen, SocksVersion},
    inbound::{self, Inbound, Protocol},
};

use super::{certificate_paths, hashes, options::Options, path, unsupported};

pub fn outbound(
    source: &Connection,
    store: &Store,
    globals: &mut Map<String, Value>,
) -> Result<Map<String, Value>> {
    let (kind, proxy, network) = match source {
        Connection::Direct(value) => ("direct", None, &value.network),
        Connection::Http(value) => ("http", Some(&value.proxy), &value.network),
        Connection::Socks(value) => ("socks", Some(&value.proxy), &value.network),
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
                output.insert("tls".to_owned(), client_tls(&value.tls, store, globals)?);
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
    }
    Ok(output)
}

pub fn listeners(
    source: &Inbound,
    users: &[(String, String)],
    store: &Store,
) -> Result<Vec<Map<String, Value>>> {
    let mut output = Map::from_iter([
        ("listen".to_owned(), json!(source.listen.address)),
        (
            "users".to_owned(),
            json!(
                users
                    .iter()
                    .map(|(name, password)| { json!({"username": name, "password": password}) })
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
    let Protocol::Mixed(value) = &source.protocol;
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

fn dialer(source: &connection::Network, output: &mut Map<String, Value>) -> Result<()> {
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

fn client_tls(
    source: &connection::Tls,
    store: &Store,
    globals: &mut Map<String, Value>,
) -> Result<Value> {
    let mut options = Options::new(source)?;
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
            ech.insert("config".to_owned(), json!(value));
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
    let mut options = Options::new(&source.tls)?;
    let (certificate, key) = certificate_paths(store, source);
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
