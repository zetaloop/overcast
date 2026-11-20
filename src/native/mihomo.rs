use std::borrow::Cow;
use std::time::Duration;

use serde_json::{Map, Value, json};

use crate::{
    Result,
    config::Store,
    connection::{self, AddressStrategy, Connection, FastOpen, Security, SocksVersion},
    inbound::{self, Inbound, Protocol},
};

use super::{
    certificate_paths, hex_hashes, listener::Credential, options::Options, single_headers,
    unsupported,
};

pub fn outbound(
    source: &Connection,
    input: super::parameters::Input<'_>,
    globals: &mut Map<String, Value>,
) -> Result<Map<String, Value>> {
    let (kind, proxy, network) = match source {
        Connection::Direct(value) => ("direct", None, &value.network),
        Connection::Http(value) => ("http", Some(&value.proxy), &value.network),
        Connection::Socks(value) => ("socks5", Some(&value.proxy), &value.network),
        Connection::Vless(value) => ("vless", None, &value.network),
        Connection::Vmess(value) => ("vmess", None, &value.network),
        Connection::Trojan(value) => ("trojan", None, &value.network),
        Connection::Shadowsocks(value) => ("ss", None, &value.network),
        Connection::Hysteria2(value) => ("hysteria2", None, &value.network),
        Connection::AnyTls(value) => ("anytls", None, &value.network),
        Connection::Warp(value) => ("masque", None, &value.network),
        Connection::Forward(_) => unreachable!(),
    };
    let mut output = Map::from_iter([("type".to_owned(), json!(kind))]);
    let mut options = Options::new(network)?;
    dial_options(network, &mut options, &mut output, globals)?;
    options.finish("Mihomo 连接")?;
    if let Some(proxy) = proxy {
        output.insert("server".to_owned(), json!(proxy.server));
        output.insert("port".to_owned(), json!(proxy.port));
        if let Some(value) = &proxy.username {
            output.insert("username".to_owned(), json!(value));
        }
        if let Some(value) = &proxy.password {
            output.insert("password".to_owned(), json!(value));
        }
    }
    let tls = match source {
        Connection::Forward(_) => unreachable!(),
        Connection::Warp(value) => {
            output.extend(super::warp::mihomo(value, input)?);
            output.insert("server".to_owned(), json!(value.server()));
            output.insert("port".to_owned(), json!(value.port));
            None
        }
        Connection::AnyTls(value) => {
            let mut options = Options::new(&value.anytls)?;
            options.take("tcp");
            options.take("udp");
            options.rename(
                &mut output,
                &[
                    ("min_idle_session", "min-idle-session"),
                    ("client_metadata", "client-metadata"),
                ],
            );
            options.invert(&mut output, "reuse", "disable-reuse");
            options.durations(
                &mut output,
                &[
                    ("idle_session_check_interval", "idle-session-check-interval"),
                    ("idle_session_timeout", "idle-session-timeout"),
                ],
                Some(Duration::from_secs(1)),
            )?;
            options.finish("Mihomo AnyTLS")?;
            output.insert("server".to_owned(), json!(value.server));
            output.insert("port".to_owned(), json!(value.port));
            output.insert("password".to_owned(), json!(value.password));
            output.insert("udp".to_owned(), json!(value.anytls.udp.unwrap_or(true)));
            Some(Cow::Borrowed(&value.security))
        }
        Connection::Hysteria2(value) => {
            output.extend(super::hysteria::client(value, inbound::Core::Mihomo)?);
            output.insert("server".to_owned(), json!(value.server));
            output.insert("port".to_owned(), json!(value.port()?));
            output.insert("password".to_owned(), json!(value.password));
            Some(Cow::Owned(Security::Tls(value.tls.clone())))
        }
        Connection::Shadowsocks(value) => {
            let mut options = Options::new(&value.shadowsocks)?;
            output.insert("server".to_owned(), json!(value.server));
            output.insert("port".to_owned(), json!(value.port));
            output.insert(
                "cipher".to_owned(),
                super::shadowsocks::cipher(value.shadowsocks.cipher, inbound::Core::Mihomo, false)?,
            );
            if let Some(password) =
                input.material(|| value.shadowsocks.cipher.password(&value.password))?
            {
                output.insert("password".to_owned(), json!(password));
            }
            output.insert(
                "udp".to_owned(),
                json!(value.shadowsocks.udp.unwrap_or(true)),
            );
            for name in ["cipher", "tcp", "udp", "plugin", "udp_over_tcp"] {
                options.take(name);
            }
            if let Some(version) = value.shadowsocks.udp_over_tcp {
                if version > 2 {
                    return unsupported("UDP over TCP 使用版本 1 或 2");
                }
                output.insert("udp-over-tcp".to_owned(), json!(true));
                output.insert(
                    "udp-over-tcp-version".to_owned(),
                    json!(if version == 0 { 2 } else { version }),
                );
            }
            if let Some(plugin) = &value.shadowsocks.plugin {
                output.extend(super::shadowsocks::plugin(
                    plugin,
                    inbound::Core::Mihomo,
                    &value.server,
                    input.directory,
                    globals,
                )?);
                if plugin.name == "kcptun" && value.shadowsocks.udp_over_tcp.is_none() {
                    output.insert("udp-over-tcp-version".to_owned(), json!(2));
                }
            }
            options.finish("Mihomo Shadowsocks")?;
            None
        }
        Connection::Trojan(value) => {
            let mut options = Options::new(&value.trojan)?;
            output.insert("server".to_owned(), json!(value.server));
            output.insert("port".to_owned(), json!(value.port));
            output.insert("password".to_owned(), json!(value.password));
            output.insert("udp".to_owned(), json!(value.trojan.udp.unwrap_or(true)));
            options.take("tcp");
            options.take("udp");
            options.finish("Mihomo Trojan")?;
            output.extend(super::transport::mihomo_client(
                &value.transport,
                &value.network,
                !matches!(value.security, Security::None),
                input,
                globals,
            )?);
            Some(Cow::Borrowed(&value.security))
        }
        Connection::Direct(_) => None,
        Connection::Http(value) => {
            let mut options = Options::new(&value.http)?;
            if matches!(
                value.http.version,
                connection::HttpVersion::Auto | connection::HttpVersion::Http1
            ) {
                options.take("version");
                options.take("fixed_version");
            }
            if options.take("headers").is_some() {
                output.insert(
                    "headers".to_owned(),
                    json!(single_headers(&value.http.headers)?),
                );
            }
            options.finish("Mihomo HTTP")?;
            Some(Cow::Borrowed(&value.security))
        }
        Connection::Vmess(value) => {
            let mut options = Options::new(&value.vmess)?;
            output.insert("server".to_owned(), json!(value.server));
            output.insert("port".to_owned(), json!(value.port));
            output.insert("uuid".to_owned(), json!(value.uuid));
            output.insert(
                "cipher".to_owned(),
                serde_json::to_value(value.vmess.cipher.resolve())?,
            );
            options.take("cipher");
            options.rename(
                &mut output,
                &[
                    ("alter_id", "alterId"),
                    ("global_padding", "global-padding"),
                    ("authenticated_length", "authenticated-length"),
                ],
            );
            if value.vmess.termination_signal == Some(true) {
                options.take("termination_signal");
            }
            options.take("tcp");
            options.take("udp");
            output.insert("udp".to_owned(), json!(value.vmess.udp.unwrap_or(true)));
            options.take("packet_encoding");
            if value.multiplex.as_ref().is_some_and(|mux| !mux.tcp_only) {
                options.take("udp_concurrency");
            } else if value.vmess.packet_encoding != connection::PacketEncoding::Default {
                output.insert(
                    "packet-encoding".to_owned(),
                    json!(match value.vmess.packet_encoding {
                        connection::PacketEncoding::PacketAddr => "packetaddr",
                        connection::PacketEncoding::Xudp => "xudp",
                        _ => "",
                    }),
                );
            }
            options.finish("Mihomo VMess")?;
            output.extend(super::transport::mihomo_client(
                &value.transport,
                &value.network,
                !matches!(value.security, Security::None),
                input,
                globals,
            )?);
            Some(Cow::Borrowed(&value.security))
        }
        Connection::Socks(value) => {
            if value.socks.version != SocksVersion::V5 {
                return unsupported("Mihomo SOCKS 出站使用 SOCKS5");
            }
            if value
                .security
                .tls()
                .and_then(|tls| tls.server_name.as_ref())
                .is_some_and(|name| {
                    !name.is_empty() && !name.eq_ignore_ascii_case(&value.proxy.server)
                })
            {
                return unsupported("Mihomo 的 SOCKS TLS 使用服务器地址作为 SNI");
            }
            let mut options = Options::new(&value.socks)?;
            options.take("udp");
            output.insert("udp".to_owned(), json!(value.socks.udp.unwrap_or(true)));
            options.take("tcp");
            if source.multiplex().is_some_and(|mux| !mux.tcp_only) {
                options.take("udp_over_tcp");
            }
            options.finish("Mihomo SOCKS")?;
            Some(Cow::Borrowed(&value.security))
        }
        Connection::Vless(value) => {
            if value
                .security
                .reality()
                .is_some_and(|reality| reality.tls.alpn == ["h3"])
                && matches!(value.transport, crate::transport::Transport::XHttp(_))
            {
                return unsupported("Mihomo XHTTP/3 不支持 REALITY 握手");
            }
            let mut options = input.vless(&value.vless, inbound::Core::Mihomo)?;
            output.insert("server".to_owned(), json!(value.server));
            output.insert("port".to_owned(), json!(value.port));
            output.insert("uuid".to_owned(), json!(value.uuid));
            output.insert("udp".to_owned(), json!(value.vless.udp.unwrap_or(true)));
            options.take("flow");
            if value.vless.flow == crate::vless::Flow::Vision {
                output.insert("flow".to_owned(), json!("xtls-rprx-vision"));
            }
            options.copy(&mut output, &["encryption"]);
            options.take("tcp");
            options.take("udp");
            options.take("packet_encoding");
            if value.multiplex.as_ref().is_some_and(|mux| !mux.tcp_only) {
                options.take("udp_concurrency");
            } else {
                match value.vless.packet_encoding {
                    crate::connection::PacketEncoding::Default => {}
                    crate::connection::PacketEncoding::Packet => {
                        return unsupported("Mihomo VLESS 的 UDP 编码使用 XUDP 或 PacketAddr");
                    }
                    crate::connection::PacketEncoding::PacketAddr => {
                        output.insert("packet-encoding".to_owned(), json!("packetaddr"));
                    }
                    crate::connection::PacketEncoding::Xudp => {
                        output.insert("packet-encoding".to_owned(), json!("xudp"));
                    }
                }
            }
            options.finish("Mihomo VLESS")?;
            output.extend(super::transport::mihomo_client(
                &value.transport,
                &value.network,
                !matches!(value.security, Security::None),
                input,
                globals,
            )?);
            Some(Cow::Borrowed(&value.security))
        }
    };
    if let Some(tls) = tls.filter(|tls| !matches!(tls.as_ref(), Security::None)) {
        let tls = source
            .transport()
            .map_or(Cow::Borrowed(tls.as_ref()), |transport| {
                transport.client_tls(&tls)
            });
        client_tls(&tls, input, &mut output, globals, kind)?;
        if matches!(source, Connection::Socks(_)) {
            output.remove("sni");
        }
    }
    if let Some(multiplex) = source.multiplex() {
        output.insert(
            "smux".to_owned(),
            super::multiplex::client(multiplex, inbound::Core::Mihomo)?,
        );
    }
    Ok(output)
}

pub fn listeners(
    source: &Inbound,
    users: &[(String, Credential)],
    store: &Store,
    globals: &mut Map<String, Value>,
    target: Option<(&str, u16)>,
) -> Result<Vec<Map<String, Value>>> {
    let mut output = Map::from_iter([
        ("listen".to_owned(), json!(source.listen.address)),
        ("port".to_owned(), json!(source.listen.ports)),
        (
            "users".to_owned(),
            if matches!(
                source.protocol,
                Protocol::Hysteria2(_) | Protocol::AnyTls(_) | Protocol::Shadowsocks(_)
            ) {
                json!(
                    users
                        .iter()
                        .map(|(name, credential)| (name.clone(), json!(credential.password)))
                        .collect::<Map<_, _>>()
                )
            } else {
                json!(
                    users
                        .iter()
                        .map(|(name, credential)| match &source.protocol {
                            Protocol::Mixed(_) =>
                                json!({"username": name, "password": credential.password}),
                            Protocol::Vless(value) => {
                                let mut user = Map::from_iter([
                                    ("username".to_owned(), json!(name)),
                                    ("uuid".to_owned(), json!(name)),
                                ]);
                                if value.flow == crate::vless::Flow::Vision {
                                    user.insert("flow".to_owned(), json!("xtls-rprx-vision"));
                                }
                                json!(user)
                            }
                            Protocol::Vmess(value) => {
                                let mut user = Map::from_iter([
                                    ("username".to_owned(), json!(name)),
                                    ("uuid".to_owned(), json!(name)),
                                ]);
                                if let Some(alter_id) = value.alter_id {
                                    user.insert("alterId".to_owned(), json!(alter_id));
                                }
                                json!(user)
                            }
                            Protocol::Trojan(_) =>
                                json!({"username": name, "password": credential.password}),
                            Protocol::Hysteria2(_)
                            | Protocol::AnyTls(_)
                            | Protocol::Shadowsocks(_)
                            | Protocol::Forward(_) => unreachable!(),
                        })
                        .collect::<Vec<_>>()
                )
            },
        ),
    ]);
    let mut options = Options::new(&source.listen.socket)?;
    options.rename(&mut output, &[("routing_mark", "routing-mark")]);
    if let Some(FastOpen::Enabled(value)) = &source.listen.socket.tcp_fast_open {
        options.take("tcp_fast_open");
        globals.insert("inbound-tfo".to_owned(), json!(value));
    }
    options.rename(globals, &[("tcp_multi_path", "inbound-mptcp")]);
    keep_alive(&mut options, globals)?;
    options.finish("Mihomo 监听")?;
    if let Protocol::AnyTls(value) = &source.protocol {
        let mut options = Options::new(value)?;
        options.take("padding_scheme");
        options.finish("Mihomo AnyTLS 入站")?;
        if !value.padding_scheme.is_empty() {
            output.insert(
                "padding-scheme".to_owned(),
                json!(value.padding_scheme.join("\n")),
            );
        }
        output.insert("type".to_owned(), json!("anytls"));
        if !matches!(source.security, inbound::Security::None) {
            server_tls(source, store, &mut output)?;
        } else {
            output.insert("allow-insecure".to_owned(), json!(true));
        }
        return Ok(vec![output]);
    }
    if let Protocol::Hysteria2(value) = &source.protocol {
        if value
            .masquerade
            .as_ref()
            .is_some_and(|value| value.kind == crate::hysteria::MasqueradeKind::Proxy)
        {
            globals.insert("rules".to_owned(), json!(["IN-TYPE,INNER,direct"]));
        }
        output.insert("type".to_owned(), json!("hysteria2"));
        output.extend(super::hysteria::server(
            value,
            inbound::Core::Mihomo,
            store,
        )?);
        server_tls(source, store, &mut output)?;
        return Ok(vec![output]);
    }
    if let Protocol::Vless(value) = &source.protocol {
        if users.is_empty() {
            return unsupported("VLESS 入口需要认证用户");
        }
        let mut options = Options::new(value)?;
        options.take("flow");
        options.take("multiplex");
        if let Some(multiplex) = &value.multiplex {
            output.insert(
                "mux-option".to_owned(),
                super::multiplex::server(multiplex, inbound::Core::Mihomo)?,
            );
        }
        options.take("encryption");
        if let Some(encryption) = &value.encryption {
            output.insert(
                "decryption".to_owned(),
                json!(super::encryption::server(encryption)?),
            );
        }
        options.finish("Mihomo VLESS 入站")?;
        output.insert("type".to_owned(), json!("vless"));
        if !matches!(source.security, inbound::Security::None) {
            server_tls(source, store, &mut output)?;
        } else if value.encryption.is_none() {
            output.insert("allow-insecure".to_owned(), json!(true));
        }
        output.extend(super::transport::mihomo_server(&source.transport)?);
        return Ok(vec![output]);
    }
    if let Protocol::Vmess(value) = &source.protocol {
        if users.is_empty() {
            return unsupported("VMess 入口需要认证用户");
        }
        let mut options = Options::new(value)?;
        options.take("alter_id");
        options.take("multiplex");
        options.finish("Mihomo VMess 入站")?;
        output.insert("type".to_owned(), json!("vmess"));
        if let Some(multiplex) = &value.multiplex {
            output.insert(
                "mux-option".to_owned(),
                super::multiplex::server(multiplex, inbound::Core::Mihomo)?,
            );
        }
        server_tls(source, store, &mut output)?;
        output.extend(super::transport::mihomo_server(&source.transport)?);
        return Ok(vec![output]);
    }
    if let Protocol::Trojan(value) = &source.protocol {
        if users.is_empty() {
            return unsupported("Trojan 入口需要认证用户");
        }
        let mut options = Options::new(value)?;
        options.take("multiplex");
        options.finish("Mihomo Trojan 入站")?;
        output.insert("type".to_owned(), json!("trojan"));
        if let Some(multiplex) = &value.multiplex {
            output.insert(
                "mux-option".to_owned(),
                super::multiplex::server(multiplex, inbound::Core::Mihomo)?,
            );
        }
        if !matches!(source.security, inbound::Security::None) {
            server_tls(source, store, &mut output)?;
        } else {
            output.insert("allow-insecure".to_owned(), json!(true));
        }
        output.extend(super::transport::mihomo_server(&source.transport)?);
        return Ok(vec![output]);
    }
    if let Protocol::Shadowsocks(value) = &source.protocol {
        if !value.tcp {
            return unsupported("Mihomo Shadowsocks 入站启用 TCP 监听");
        }
        let mut options = Options::new(value)?;
        for name in ["cipher", "tcp", "udp", "multiplex"] {
            options.take(name);
        }
        output.insert("type".to_owned(), json!("shadowsocks"));
        output.insert(
            "cipher".to_owned(),
            super::shadowsocks::cipher(value.cipher, inbound::Core::Mihomo, true)?,
        );
        output.insert("udp".to_owned(), json!(value.udp));
        super::shadowsocks::authentication(source, users, &mut options, &mut output)?;
        if value.cipher == crate::shadowsocks::Cipher::None {
            // Named listeners require a password field even though the none service ignores it.
            output.insert("password".to_owned(), json!("unused"));
        }
        if let Some(multiplex) = &value.multiplex {
            output.insert(
                "mux-option".to_owned(),
                super::multiplex::server(multiplex, inbound::Core::Mihomo)?,
            );
        }
        options.finish("Mihomo Shadowsocks 入站")?;
        return Ok(vec![output]);
    }
    if let Protocol::Forward(value) = &source.protocol {
        if value.user_level.is_some() {
            return unsupported("Mihomo 固定转发入口没有用户等级配置");
        }
        let (server, port) = target.ok_or("转发入口缺少后继连接")?;
        output.insert("type".to_owned(), json!("tunnel"));
        output.insert(
            "target".to_owned(),
            json!(crate::connection::address(server, port)),
        );
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
    options.finish("Mihomo HTTP/SOCKS")?;
    output.insert(
        "type".to_owned(),
        json!(if value.http.enabled && value.socks.enabled {
            "mixed"
        } else if value.http.enabled {
            "http"
        } else {
            "socks"
        }),
    );
    if value.http.enabled {
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
        options.finish("Mihomo HTTP 入站")?;
    }
    if value.socks.enabled {
        output.insert("udp".to_owned(), json!(value.udp));
        let mut options = Options::new(&value.socks)?;
        options.take("enabled");
        options.finish("Mihomo SOCKS 入站")?;
    }
    server_tls(source, store, &mut output)?;
    Ok(vec![output])
}

pub(super) fn dial_options(
    network: &connection::Network,
    options: &mut Options,
    output: &mut Map<String, Value>,
    globals: &mut Map<String, Value>,
) -> Result<()> {
    options.rename(
        output,
        &[
            ("interface", "interface-name"),
            ("routing_mark", "routing-mark"),
            ("tcp_multi_path", "mptcp"),
        ],
    );
    if let Some(value) = options.take("tcp_fast_open") {
        if !value.is_boolean() {
            return unsupported("Mihomo 的 TCP 快速打开使用开关");
        }
        output.insert("tfo".to_owned(), value);
    }
    if options.take("address_strategy").is_some()
        && let Some(strategy) = network.address_strategy
    {
        let value = match strategy {
            AddressStrategy::AsIs => "dual",
            AddressStrategy::Ipv4Only => "ipv4",
            AddressStrategy::Ipv6Only => "ipv6",
            AddressStrategy::PreferIpv4 => "ipv4-prefer",
            AddressStrategy::PreferIpv6 => "ipv6-prefer",
            _ => {
                return unsupported(format!(
                    "Mihomo 无法表达地址策略：{}",
                    serde_json::to_value(strategy)?
                ));
            }
        };
        output.insert("ip-version".to_owned(), json!(value));
    }
    keep_alive(options, globals)
}

fn keep_alive(options: &mut Options, globals: &mut Map<String, Value>) -> Result<()> {
    options.invert(globals, "tcp_keep_alive", "disable-keep-alive");
    options.durations(
        globals,
        &[
            ("tcp_keep_alive_idle", "keep-alive-idle"),
            ("tcp_keep_alive_interval", "keep-alive-interval"),
        ],
        Some(Duration::from_secs(1)),
    )
}

pub fn client_tls(
    security: &Security,
    input: super::parameters::Input<'_>,
    output: &mut Map<String, Value>,
    globals: &mut Map<String, Value>,
    kind: &str,
) -> Result<()> {
    let v2ray = matches!(kind, "vless" | "vmess" | "trojan");
    let (source, reality) = match security {
        Security::None => return Ok(()),
        Security::Tls(tls) => (tls, None),
        Security::Reality(reality) => (&reality.tls, Some(reality.as_ref())),
    };
    if reality.is_some() && !v2ray {
        return unsupported(format!("Mihomo {kind} 出站没有 REALITY 配置"));
    }
    let mut options = Options::new(source)?;
    if !matches!(kind, "trojan" | "hysteria2" | "anytls") {
        output.insert("tls".to_owned(), json!(true));
    }
    options.rename(
        output,
        &[(
            "server_name",
            if matches!(kind, "vless" | "vmess") {
                "servername"
            } else {
                "sni"
            },
        )],
    );
    if v2ray || matches!(kind, "hysteria2" | "anytls") {
        options.copy(output, &["alpn"]);
    }
    if v2ray || kind == "anytls" {
        options.rename(output, &[("fingerprint", "client-fingerprint")]);
        if let Some(reality) = reality {
            let mut options = input.reality(reality)?;
            options.take("tls");
            let mut reality = Map::new();
            options.rename(
                &mut reality,
                &[
                    ("public_key", "public-key"),
                    ("short_id", "short-id"),
                    ("hybrid_key_exchange", "support-x25519mlkem768"),
                ],
            );
            options.finish("Mihomo REALITY")?;
            output.insert("reality-opts".to_owned(), json!(reality));
        }
    }
    options.invert(output, "verify_certificate", "skip-cert-verify");
    if source.send_sni == Some(true) {
        options.take("send_sni");
    }
    if source.system_roots == Some(true) {
        options.take("system_roots");
    }
    if let [name] = source.verify_names.as_slice() {
        options.take("verify_names");
        output.insert("name-cert-verify".to_owned(), json!(name));
    }
    if let [hash] = source.certificate_sha256.as_slice() {
        options.take("certificate_sha256");
        output.insert(
            "fingerprint".to_owned(),
            json!(hex_hashes(std::slice::from_ref(hash))?.remove(0)),
        );
    }
    inbound::Core::Mihomo.identity(source)?;
    for (name, value, destination) in [
        (
            "client_certificate",
            &source.client_certificate,
            "certificate",
        ),
        ("client_key", &source.client_key, "private-key"),
    ] {
        options.take(name);
        if let Some(v) = value {
            output.insert(destination.into(), v.native(input.directory));
        }
    }
    options.take("certificates");
    if !source.certificates.is_empty() {
        let Some(trust) = source
            .certificates
            .iter()
            .map(crate::security::Material::inline)
            .collect::<Option<Vec<_>>>()
        else {
            return unsupported("Mihomo 的出站信任库使用证书正文，不支持文件路径");
        };
        let value = json!({"custom-certifactes": trust});
        if globals.get("tls").is_some_and(|current| current != &value) {
            return unsupported("Mihomo 同一连接的上传与下载使用共同的证书信任库");
        }
        globals.insert("tls".to_owned(), value);
    }
    options.take("ech");
    if let Some(value) = &source.ech {
        if !v2ray && !matches!(kind, "hysteria2" | "anytls") {
            return unsupported(format!("Mihomo {kind} 出站没有 ECH 配置"));
        }
        let mut ech = Map::from_iter([("enable".to_owned(), json!(true))]);
        if let Some(config) = &value.config {
            let Some(text) = config.inline() else {
                return unsupported("Mihomo 的 ECH 公共参数使用正文，不支持文件路径");
            };
            ech.insert("config".to_owned(), json!(crate::ech::base64(text)?));
        }
        if let Some(value) = &value.query_name {
            ech.insert("query-server-name".to_owned(), json!(value));
        }
        output.insert("ech-opts".to_owned(), json!(ech));
    }
    options.finish("Mihomo TLS")
}

fn server_tls(source: &Inbound, store: &Store, output: &mut Map<String, Value>) -> Result<()> {
    let tls = match &source.security {
        inbound::Security::None => return Ok(()),
        inbound::Security::Tls(tls) => tls,
        inbound::Security::Reality(reality) => {
            output.insert(
                "reality-config".to_owned(),
                super::reality::server(source, reality)?,
            );
            return Ok(());
        }
    };
    let mut options = Options::new(tls)?;
    options.take("server_name");
    if matches!(source.protocol, Protocol::Hysteria2(_)) {
        options.copy(output, &["alpn"]);
    }
    let (certificate, key) = certificate_paths(store, source)?;
    output.insert("certificate".to_owned(), json!(certificate));
    output.insert("private-key".to_owned(), json!(key));
    options.rename(output, &[("client_auth", "client-auth-type")]);
    options.take("client_certificates");
    if let [v] = tls.client_certificates.as_slice() {
        output.insert("client-auth-cert".into(), v.native(&store.directory));
    } else if !tls.client_certificates.is_empty() {
        let Some(trust) = tls
            .client_certificates
            .iter()
            .map(crate::security::Material::inline)
            .collect::<Option<Vec<_>>>()
        else {
            return unsupported("Mihomo 的入站信任库可用多张证书正文或一条文件路径");
        };
        output.insert("client-auth-cert".into(), json!(trust.join("\n")));
    }
    options.take("ech");
    if let Some(ech) = &tls.ech {
        output.insert(
            "ech-key".into(),
            crate::ech::server_key(ech, &store.directory)?,
        );
    }
    options.finish("Mihomo 服务端 TLS")
}
