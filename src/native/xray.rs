use std::time::Duration;

use serde_json::{Map, Value, json};

use crate::{
    Result,
    config::Store,
    connection::{self, AddressStrategy, Connection, SocksVersion},
    inbound::{self, Inbound, Protocol},
};

use super::{
    certificate_paths, hex_hashes, options::Options, path, single_headers, transport, unsupported,
};

pub fn outbound(source: &Connection, store: &Store) -> Result<Map<String, Value>> {
    let (kind, proxy, network) = match source {
        Connection::Direct(value) => ("freedom", None, &value.network),
        Connection::Http(value) => ("http", Some(&value.proxy), &value.network),
        Connection::Socks(value) => ("socks", Some(&value.proxy), &value.network),
        Connection::Vless(value) => ("vless", None, &value.network),
    };
    let mut output = Map::from_iter([("protocol".to_owned(), json!(kind))]);
    if let Some(multiplex) = source.multiplex() {
        output.insert(
            "mux".to_owned(),
            super::multiplex::client(multiplex, inbound::Core::Xray)?,
        );
    }
    let mut settings = Map::new();
    let mut stream = Map::new();
    let mut options = Options::new(network)?;
    if network.source_ipv4.is_some() && network.source_ipv6.is_some() {
        return unsupported("Xray 每个出站的 sendThrough 使用一个源地址");
    }
    if let Some(value) = options
        .take("source_ipv4")
        .or_else(|| options.take("source_ipv6"))
    {
        output.insert("sendThrough".to_owned(), value);
    }
    let sockopt = dialer(network, &mut options)?;
    options.finish("Xray 连接")?;
    if !sockopt.is_empty() {
        stream.insert("sockopt".to_owned(), json!(sockopt));
    }
    if let Some(proxy) = proxy {
        settings.insert("address".to_owned(), json!(proxy.server));
        settings.insert("port".to_owned(), json!(proxy.port));
        if let Some(value) = &proxy.username {
            settings.insert("user".to_owned(), json!(value));
        }
        if let Some(value) = &proxy.password {
            settings.insert("pass".to_owned(), json!(value));
        }
    }
    let tls = match source {
        Connection::Direct(_) => {
            settings.insert("finalRules".to_owned(), json!([{"action": "allow"}]));
            None
        }
        Connection::Http(value) => {
            let mut options = Options::new(&value.http)?;
            if matches!(
                value.http.version,
                connection::HttpVersion::Auto | connection::HttpVersion::Http1
            ) {
                options.take("version");
                options.take("fixed_version");
            }
            options.rename(
                &mut settings,
                &[("user_level", "level"), ("user_label", "email")],
            );
            if options.take("headers").is_some() {
                settings.insert(
                    "headers".to_owned(),
                    json!(single_headers(&value.http.headers)?),
                );
            }
            options.finish("Xray HTTP")?;
            Some(&value.tls)
        }
        Connection::Socks(value) => {
            let mut options = Options::new(&value.socks)?;
            if value.socks.version != SocksVersion::V5 {
                return unsupported("Xray SOCKS 出站使用 SOCKS5");
            }
            options.rename(
                &mut settings,
                &[("user_level", "level"), ("user_label", "email")],
            );
            options.take("tcp");
            options.take("udp");
            if source.multiplex().is_some_and(|mux| !mux.tcp_only) {
                options.take("udp_over_tcp");
            }
            options.finish("Xray SOCKS")?;
            Some(&value.tls)
        }
        Connection::Vless(value) => {
            if value.multiplex.is_some() && value.vless.flow == crate::vless::Flow::Vision {
                return unsupported("Vision 与 Mux.Cool TCP 流复用无法同时使用");
            }
            let mut options = Options::new(&value.vless)?;
            settings.insert("address".to_owned(), json!(value.server));
            settings.insert("port".to_owned(), json!(value.port));
            settings.insert("id".to_owned(), json!(value.uuid));
            settings.insert(
                "encryption".to_owned(),
                json!(value.vless.encryption.as_deref().unwrap_or("none")),
            );
            options.take("encryption");
            options.take("flow");
            if value.vless.flow == crate::vless::Flow::Vision {
                settings.insert("flow".to_owned(), json!("xtls-rprx-vision-udp443"));
            }
            options.rename(
                &mut settings,
                &[
                    ("user_level", "level"),
                    ("user_label", "email"),
                    ("preconnect", "testpre"),
                    ("padding", "testseed"),
                ],
            );
            options.take("tcp");
            options.take("udp");
            options.take("packet_encoding");
            options.take("udp_concurrency");
            if value.multiplex.as_ref().is_none_or(|mux| mux.tcp_only) {
                if let Some(concurrency) = value.vless.udp_concurrency {
                    i16::try_from(concurrency).map_err(|_| "Xray UDP 并发流数超过支持范围")?;
                    if concurrency == 0
                        && value.vless.packet_encoding == crate::vless::PacketEncoding::Xudp
                    {
                        return Err("XUDP 并发流数需要大于零".into());
                    }
                }
                match value.vless.packet_encoding {
                    crate::vless::PacketEncoding::PacketAddr => {
                        return unsupported("Xray VLESS 没有 PacketAddr 编码配置");
                    }
                    crate::vless::PacketEncoding::Packet
                        if value.vless.udp_concurrency.is_some()
                            || value.vless.flow == crate::vless::Flow::Vision =>
                    {
                        return unsupported(
                            "原生 VLESS 数据包与 Vision、XUDP 并发设置无法同时使用",
                        );
                    }
                    crate::vless::PacketEncoding::Xudp | crate::vless::PacketEncoding::Default
                        if value.vless.packet_encoding == crate::vless::PacketEncoding::Xudp
                            || value.vless.udp_concurrency.is_some() =>
                    {
                        let mux = output.entry("mux").or_insert_with(|| json!({"enabled": true, "concurrency": -1, "xudpProxyUDP443": "allow"}));
                        if mux["xudpConcurrency"] == -1 {
                            return unsupported("仅 TCP 流复用与 XUDP 并发配置无法同时使用");
                        }
                        mux["xudpConcurrency"] = json!(value.vless.udp_concurrency.unwrap_or(8));
                    }
                    _ => {}
                }
            }
            options.finish("Xray VLESS")?;
            Some(&value.tls)
        }
    };
    if let Some(tls) = tls.filter(|tls| tls.enabled) {
        if tls.reality.enabled {
            reality_transport(source.transport().unwrap())?;
        }
        stream.extend(security(tls, store)?);
    }
    if let Some(transport) = source.transport() {
        stream.extend(transport::xray(transport, false, store)?);
    }
    output.insert("settings".to_owned(), json!(settings));
    if !stream.is_empty() {
        output.insert("streamSettings".to_owned(), json!(stream));
    }
    Ok(output)
}

pub fn listeners(
    source: &Inbound,
    users: &[(String, String)],
    store: &Store,
) -> Result<Vec<Map<String, Value>>> {
    if source.transport.udp(
        source.tls.enabled && !source.tls.reality.enabled,
        &source.tls.alpn,
    ) && source.listen.proxy_protocol
    {
        return unsupported("XHTTP/3 的 UDP 监听没有 PROXY protocol 支持");
    }
    let mut output = Map::from_iter([
        ("listen".to_owned(), json!(source.listen.address)),
        ("port".to_owned(), json!(source.ports)),
    ]);
    let mut settings = Map::new();
    let mut stream = Map::new();
    if matches!(source.protocol, Protocol::Mixed(_)) && !users.is_empty() {
        settings.insert(
            "accounts".to_owned(),
            json!(
                users
                    .iter()
                    .map(|(name, password)| { json!({"user": name, "pass": password}) })
                    .collect::<Vec<_>>()
            ),
        );
    }
    match &source.protocol {
        Protocol::Mixed(value) => {
            let mut options = Options::new(value)?;
            options.take("http");
            options.take("socks");
            options.take("udp");
            options.rename(&mut settings, &[("user_level", "userLevel")]);
            options.finish("Xray HTTP/SOCKS")?;
            if !value.http.enabled && value.socks.enabled {
                return unsupported("Xray 的 SOCKS 入口同时接收 HTTP 请求");
            }
            let mut options = Options::new(&value.http)?;
            options.take("enabled");
            if value
                .http
                .versions
                .iter()
                .all(|version| *version == inbound::HttpVersion::Http1)
            {
                options.take("versions");
            }
            if value.socks.enabled {
                options.finish("Xray HTTP/SOCKS 的 HTTP")?;
                output.insert("protocol".to_owned(), json!("socks"));
                settings.insert(
                    "auth".to_owned(),
                    json!(if users.is_empty() {
                        "noauth"
                    } else {
                        "password"
                    }),
                );
                settings.insert("udp".to_owned(), json!(value.udp));
                let mut options = Options::new(&value.socks)?;
                options.take("enabled");
                options.rename(&mut settings, &[("udp_address", "ip")]);
                options.finish("Xray SOCKS 入站")?;
            } else {
                output.insert("protocol".to_owned(), json!("http"));
                options.rename(&mut settings, &[("transparent", "allowTransparent")]);
                options.finish("Xray HTTP 入站")?;
            }
        }
        Protocol::Vless(value) => {
            if users.is_empty() {
                return unsupported("VLESS 入口需要认证用户");
            }
            output.insert("protocol".to_owned(), json!("vless"));
            let mut options = Options::new(value)?;
            options.take("flow");
            options.take("encryption");
            options.take("user_level");
            options.take("multiplex");
            if let Some(multiplex) = &value.multiplex {
                super::multiplex::server(multiplex, inbound::Core::Xray)?;
            }
            settings.insert(
                "decryption".to_owned(),
                json!(
                    value
                        .encryption
                        .as_ref()
                        .map(super::encryption::server)
                        .transpose()?
                        .unwrap_or_else(|| "none".to_owned())
                ),
            );
            settings.insert(
                "clients".to_owned(),
                json!(
                    users
                        .iter()
                        .map(|(name, _)| {
                            let mut user = Map::from_iter([
                                ("id".to_owned(), json!(name)),
                                ("email".to_owned(), json!(name)),
                            ]);
                            if value.flow == crate::vless::Flow::Vision {
                                user.insert("flow".to_owned(), json!("xtls-rprx-vision"));
                            }
                            if let Some(level) = value.user_level {
                                user.insert("level".to_owned(), json!(level));
                            }
                            user
                        })
                        .collect::<Vec<_>>()
                ),
            );
            options.rename(&mut settings, &[("padding", "testseed")]);
            options.take("fallbacks");
            if !value.fallbacks.is_empty() {
                if value.encryption.is_some() {
                    return unsupported("VLESS Encryption 与协议回落无法同时使用");
                }
                let mut fallbacks = Vec::new();
                for fallback in &value.fallbacks {
                    if fallback.target.is_empty() {
                        return Err("请填写 VLESS 回落目标".into());
                    }
                    let mut options = Options::new(fallback)?;
                    let mut output = Map::new();
                    options.copy(&mut output, &["alpn", "path"]);
                    options.rename(
                        &mut output,
                        &[
                            ("server_name", "name"),
                            ("target", "dest"),
                            ("network", "type"),
                            ("proxy_protocol", "xver"),
                        ],
                    );
                    options.finish("Xray VLESS 回落")?;
                    fallbacks.push(output);
                }
                settings.insert("fallbacks".to_owned(), json!(fallbacks));
            }
            options.finish("Xray VLESS 入站")?;
        }
    }
    let mut options = Options::new(&source.listen)?;
    options.take("address");
    options.take("interface");
    let mut sockopt = socket(&mut options)?;
    let mut custom = Vec::new();
    if source.listen.tcp_keep_alive == Some(true)
        && !["tcpKeepAliveIdle", "tcpKeepAliveInterval"]
            .iter()
            .any(|name| {
                sockopt
                    .get(*name)
                    .and_then(Value::as_u64)
                    .is_some_and(|value| value > 0)
            })
    {
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            windows
        ))]
        {
            #[cfg(unix)]
            use nix::libc::{SO_KEEPALIVE, SOL_SOCKET};
            #[cfg(windows)]
            use windows_sys::Win32::Networking::WinSock::{SO_KEEPALIVE, SOL_SOCKET};
            custom.push(json!({
                "network": "tcp", "level": SOL_SOCKET.to_string(),
                "opt": SO_KEEPALIVE.to_string(), "type": "int", "value": "1",
            }));
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            windows
        )))]
        return unsupported("Xray 在此平台需要通过保活时间参数启用 TCP 保活");
    }
    if let Some(interface) = source
        .listen
        .interface
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use nix::libc::{SO_BINDTODEVICE, SOL_SOCKET};
            custom.push(json!({
                "level": SOL_SOCKET.to_string(),
                "opt": SO_BINDTODEVICE.to_string(), "type": "str", "value": interface,
            }));
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        return unsupported(format!("Xray 在此平台无法绑定入站接口：{interface}"));
    }
    if !custom.is_empty() {
        if let Some(Value::Array(values)) = sockopt.remove("customSockopt") {
            custom.extend(values);
        }
        sockopt.insert("customSockopt".to_owned(), json!(custom));
    }
    options.rename(
        &mut sockopt,
        &[
            ("proxy_protocol", "acceptProxyProtocol"),
            ("forwarded_sources", "trustedXForwardedFor"),
        ],
    );
    options.finish("Xray 监听")?;
    if !sockopt.is_empty() {
        stream.insert("sockopt".to_owned(), json!(sockopt));
    }
    if source.tls.enabled {
        if source.tls.reality.enabled {
            reality_transport(&source.transport)?;
            stream.insert("security".to_owned(), json!("reality"));
            stream.insert(
                "realitySettings".to_owned(),
                super::reality::server(source)?,
            );
        } else {
            stream.insert("security".to_owned(), json!("tls"));
            stream.insert("tlsSettings".to_owned(), server_tls(source, store)?);
        }
    }
    stream.extend(transport::xray(&source.transport, true, store)?);
    output.insert("settings".to_owned(), json!(settings));
    if !stream.is_empty() {
        output.insert("streamSettings".to_owned(), json!(stream));
    }
    Ok(vec![output])
}

pub fn dialer(source: &connection::Network, options: &mut Options) -> Result<Map<String, Value>> {
    let mut output = socket(options)?;
    if let Some(strategy) = source.address_strategy {
        options.take("address_strategy");
        let value = match strategy {
            AddressStrategy::AsIs => "AsIs",
            AddressStrategy::Resolve => "ForceIP",
            AddressStrategy::Ipv4Only => "ForceIPv4",
            AddressStrategy::Ipv6Only => "ForceIPv6",
            AddressStrategy::PreferIpv4 => "ForceIPv4v6",
            AddressStrategy::PreferIpv6 => "ForceIPv6v4",
            AddressStrategy::TryIp => "UseIP",
            AddressStrategy::TryIpv4 => "UseIPv4",
            AddressStrategy::TryIpv6 => "UseIPv6",
            AddressStrategy::TryIpv4Ipv6 => "UseIPv4v6",
            AddressStrategy::TryIpv6Ipv4 => "UseIPv6v4",
        };
        output.insert("domainStrategy".to_owned(), json!(value));
    }
    Ok(output)
}

fn socket(options: &mut Options) -> Result<Map<String, Value>> {
    let mut output = Map::new();
    options.rename(
        &mut output,
        &[
            ("routing_mark", "mark"),
            ("tcp_fast_open", "tcpFastOpen"),
            ("tcp_multi_path", "tcpMptcp"),
            ("tcp_congestion", "tcpCongestion"),
            ("tcp_window", "tcpWindowClamp"),
            ("tcp_max_segment", "tcpMaxSeg"),
            ("ipv6_only", "v6only"),
            ("address_port_strategy", "addressPortStrategy"),
        ],
    );
    options.copy(&mut output, &["interface"]);
    match options
        .take("tcp_keep_alive")
        .and_then(|value| value.as_bool())
    {
        Some(false) => {
            options.take("tcp_keep_alive_idle");
            options.take("tcp_keep_alive_interval");
            output.insert("tcpKeepAliveIdle".to_owned(), json!(-1));
        }
        _ => options.durations(
            &mut output,
            &[
                ("tcp_keep_alive_idle", "tcpKeepAliveIdle"),
                ("tcp_keep_alive_interval", "tcpKeepAliveInterval"),
            ],
            Some(Duration::from_secs(1)),
        )?,
    }
    options.durations(
        &mut output,
        &[("tcp_user_timeout", "tcpUserTimeout")],
        Some(Duration::from_millis(1)),
    )?;
    if let Some(Value::Object(mut values)) = options.take("happy_eyeballs") {
        let mut output_values = Map::new();
        for (source, destination) in [
            ("prefer_ipv6", "prioritizeIPv6"),
            ("interleave", "interleave"),
            ("concurrency", "maxConcurrentTry"),
        ] {
            if let Some(value) = values.remove(source).filter(|value| !value.is_null()) {
                output_values.insert(destination.to_owned(), value);
            }
        }
        if let Some(value) = values.remove("delay").filter(|value| !value.is_null()) {
            let duration = humantime::parse_duration(value.as_str().unwrap())?;
            if duration.as_nanos() % 1_000_000 != 0 {
                return unsupported("Xray 双栈尝试间隔使用整数毫秒");
            }
            output_values.insert(
                "tryDelayMs".to_owned(),
                json!(u64::try_from(duration.as_millis())?),
            );
        }
        output.insert("happyEyeballs".to_owned(), json!(output_values));
    }
    if let Some(Value::Array(values)) = options.take("socket_options") {
        let values: Vec<_> = values
            .into_iter()
            .map(|mut value| {
                let object = value.as_object_mut().unwrap();
                let option = object.remove("option").unwrap();
                let kind = object.remove("kind").unwrap();
                object.insert("opt".to_owned(), option);
                object.insert("type".to_owned(), kind);
                value
            })
            .collect();
        output.insert("customSockopt".to_owned(), json!(values));
    }
    Ok(output)
}

pub fn security(source: &connection::Tls, store: &Store) -> Result<Map<String, Value>> {
    let (kind, name, value) = if source.reality.enabled {
        ("reality", "realitySettings", super::reality::xray(source)?)
    } else {
        ("tls", "tlsSettings", client_tls(source, store)?)
    };
    Ok(Map::from_iter([
        ("security".to_owned(), json!(kind)),
        (name.to_owned(), value),
    ]))
}

fn reality_transport(source: &crate::transport::Transport) -> Result<()> {
    match source {
        crate::transport::Transport::Default
        | crate::transport::Transport::Grpc(_)
        | crate::transport::Transport::XHttp(_) => Ok(()),
        _ => unsupported("Xray REALITY 可用于原生 TCP、XHTTP 和 gRPC 传输"),
    }
}

fn client_tls(source: &connection::Tls, store: &Store) -> Result<Value> {
    let mut options = Options::new(source)?;
    options.take("enabled");
    options.take("reality");
    let mut output = Map::new();
    options.copy(&mut output, &["alpn", "fingerprint"]);
    options.rename(
        &mut output,
        &[
            ("server_name", "serverName"),
            ("min_version", "minVersion"),
            ("max_version", "maxVersion"),
            ("curves", "curvePreferences"),
            ("session_resumption", "enableSessionResumption"),
            ("key_log", "masterKeyLog"),
        ],
    );
    if source.send_sni == Some(true) {
        options.take("send_sni");
    }
    if source.verify_certificate == Some(true) {
        options.take("verify_certificate");
    }
    if options.take("cipher_suites").is_some() {
        output.insert(
            "cipherSuites".to_owned(),
            json!(source.cipher_suites.join(":")),
        );
    }
    if options.take("verify_names").is_some() {
        output.insert(
            "verifyPeerCertByName".to_owned(),
            json!(source.verify_names.join(",")),
        );
    }
    if options.take("certificate_sha256").is_some() {
        output.insert(
            "pinnedPeerCertSha256".to_owned(),
            json!(hex_hashes(&source.certificate_sha256)?.join(",")),
        );
    }
    if let Some(enabled) = source.system_roots {
        options.take("system_roots");
        output.insert(
            if enabled {
                "useSystemCA"
            } else {
                "disableSystemRoot"
            }
            .to_owned(),
            json!(true),
        );
    }
    let mut certificates = Vec::new();
    options.take("certificates");
    options.take("certificate_files");
    if !source.certificates.is_empty() {
        certificates.push(json!({"usage": "verify", "certificate": source.certificates}));
    }
    for value in &source.certificate_files {
        certificates.push(json!({"usage": "verify", "certificateFile": path(store, value)}));
    }
    let mut client = Map::new();
    for (name, destination) in [("client_certificate", "certificate"), ("client_key", "key")] {
        if let Some(value) = options.take(name) {
            client.insert(destination.to_owned(), json!([value]));
        }
    }
    for (name, destination) in [
        ("client_certificate_file", "certificateFile"),
        ("client_key_file", "keyFile"),
    ] {
        if let Some(value) = options.take(name) {
            client.insert(
                destination.to_owned(),
                json!(path(store, value.as_str().unwrap())),
            );
        }
    }
    if !client.is_empty() {
        certificates.push(json!(client));
    }
    if !certificates.is_empty() {
        output.insert("certificates".to_owned(), json!(certificates));
    }
    options.take("ech");
    if source.ech.enabled {
        if let Some(config) = &source.ech.config {
            output.insert("echConfigList".to_owned(), json!(config));
        } else if let Some(file) = &source.ech.config_file {
            output.insert(
                "echConfigList".to_owned(),
                json!(std::fs::read_to_string(path(store, file))?.trim()),
            );
        } else if let Some(name) = &source.ech.query_name {
            output.insert("echConfigList".to_owned(), json!(name));
        }
    }
    options.finish("Xray TLS")?;
    Ok(json!(output))
}

fn server_tls(source: &Inbound, store: &Store) -> Result<Value> {
    let mut options = Options::new(&source.tls)?;
    options.take("reality");
    options.take("enabled");
    let (certificate, key) = certificate_paths(store, source);
    let mut output = Map::from_iter([(
        "certificates".to_owned(),
        json!([{
            "certificateFile": certificate,
            "keyFile": key,
        }]),
    )]);
    options.copy(&mut output, &["alpn"]);
    options.rename(
        &mut output,
        &[
            ("server_name", "serverName"),
            ("min_version", "minVersion"),
            ("max_version", "maxVersion"),
            ("curves", "curvePreferences"),
            ("session_resumption", "enableSessionResumption"),
            ("reject_unknown_sni", "rejectUnknownSni"),
            ("key_log", "masterKeyLog"),
        ],
    );
    if options.take("cipher_suites").is_some() {
        output.insert(
            "cipherSuites".to_owned(),
            json!(source.tls.cipher_suites.join(":")),
        );
    }
    options.take("ech");
    if source.tls.ech.enabled {
        if let Some(file) = &source.tls.ech.key_file {
            output.insert(
                "echServerKeys".to_owned(),
                json!(std::fs::read_to_string(path(store, file))?.trim()),
            );
        } else if let [key] = source.tls.ech.keys.as_slice() {
            output.insert("echServerKeys".to_owned(), json!(key));
        } else {
            return unsupported("Xray ECH 使用一份服务端密钥");
        }
    }
    options.finish("Xray 服务端 TLS")?;
    Ok(json!(output))
}
