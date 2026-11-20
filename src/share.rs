use std::{collections::BTreeMap, net::IpAddr};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Map, Value, json};
use termina::style::StyleExt;
use url::Host;

use crate::{
    Result,
    config::Store,
    connection::{self, Connection, HttpVersion, Security, SocksVersion},
    native::options::Options,
    transport::{Header, Transport},
    tui::{Action, Item, Menu, Screen},
};

const COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

pub fn copy(
    screen: &mut Screen,
    title: &str,
    generate: impl Fn(&mut Screen, bool) -> Result<String>,
) -> Result<()> {
    let items = [
        Item::new("links", "分享链接".stylized()),
        Item::new("config", "复制 Overcast 配置".stylized()),
        Item::new("back", "返回".stylized()),
    ];
    let menu = Menu {
        title,
        heading: "",
        items: &items,
        help: "方向键 选择\n回车键 复制\nEsc 返回",
    };
    let mut selected = 0;
    let mut notice = String::new();
    loop {
        match screen.select(&menu, &mut selected, &notice)? {
            Action::Back => return Ok(()),
            Action::Select if selected == 2 => return Ok(()),
            Action::Select => {
                notice = match generate(screen, selected == 0).and_then(|text| screen.copy(&text)) {
                    Ok(()) => String::new(),
                    Err(error) => error.to_string(),
                };
            }
            _ => {}
        }
    }
}

pub fn path(connections: &[Connection], name: &str, store: &Store) -> Result<String> {
    let mut values = connections
        .iter()
        .rev()
        .filter(|c| !matches!(c, Connection::Direct(_)));
    let mut inner = values.next().ok_or("直连没有远端分享链接")?.clone();
    for outer in values {
        let Connection::Forward(value) = outer else {
            return Err("多段代理连接使用连接路径 JSON 分享".into());
        };
        inner.set_server(&value.server);
        let (port, security, transport) = match &mut inner {
            Connection::Http(value) => (
                &mut value.proxy.port,
                Some(&mut value.security),
                Some(&mut value.transport),
            ),
            Connection::Socks(value) => (
                &mut value.proxy.port,
                Some(&mut value.security),
                Some(&mut value.transport),
            ),
            Connection::Vless(value) => (
                &mut value.port,
                Some(&mut value.security),
                Some(&mut value.transport),
            ),
            Connection::Vmess(value) => (
                &mut value.port,
                Some(&mut value.security),
                Some(&mut value.transport),
            ),
            Connection::Trojan(value) => (
                &mut value.port,
                Some(&mut value.security),
                Some(&mut value.transport),
            ),
            Connection::Shadowsocks(value) => (
                &mut value.port,
                Some(&mut value.security),
                Some(&mut value.transport),
            ),
            Connection::Forward(value) => (
                &mut value.port,
                Some(&mut value.security),
                Some(&mut value.transport),
            ),
            Connection::Direct(_) => unreachable!(),
            Connection::Warp(_) => {
                return Err("WARP 连接使用连接路径 JSON 分享".into());
            }
            Connection::Hysteria2(value) => {
                // The forwarded client dials the outer port, not the backend's hopping ports.
                value.hysteria.ports.clear();
                value.hysteria.hop_interval = None;
                value.hysteria.hop_interval_max = None;
                (&mut value.port, None, None)
            }
            Connection::AnyTls(value) => (&mut value.port, Some(&mut value.security), None),
        };
        let secure = security
            .as_deref()
            .is_none_or(|security| !matches!(security, Security::None));
        if !matches!(value.security, Security::None) && secure {
            return Err("嵌套 TLS 连接使用连接路径 JSON 分享".into());
        }
        if !value.transport.is_default() && secure {
            return Err("传输内部的 TLS 连接使用连接路径 JSON 分享".into());
        }
        if let Some(security) = security
            && !matches!(value.security, Security::None)
        {
            *security = value.security.clone();
        }
        if !value.transport.is_default() {
            let Some(transport) = transport.filter(|transport| transport.is_default()) else {
                return Err("嵌套传输连接使用连接路径 JSON 分享".into());
            };
            *transport = value.transport.clone();
        }
        *port = value.port;
    }
    link(&inner, name, store)
}

pub fn link(source: &Connection, name: &str, store: &Store) -> Result<String> {
    let (server, port) = source.server().ok_or("直连没有远端分享链接")?;
    let server = match server.parse::<IpAddr>() {
        Ok(server) => server.to_string(),
        Err(_) => Host::parse(server)?.to_string(),
    };
    let mut query = Map::new();
    let (scheme, user) = match source {
        Connection::Direct(_) => unreachable!(),
        Connection::Warp(_) => return Err("WARP 连接使用连接路径 JSON 分享".into()),
        Connection::Forward(_) => {
            return Err("此连接使用连接路径 JSON 分享".into());
        }
        Connection::Http(value) => {
            tls(&value.security, &mut query, store)?;
            transport(&value.transport, &value.security, &mut query, store)?;
            if matches!(value.security, Security::Tls(_)) {
                query.remove("security");
                if value.http.fixed_version && !query.contains_key("alpn") {
                    let alpn = match value.http.version {
                        HttpVersion::Auto => None,
                        HttpVersion::Http1 => Some("http/1.1"),
                        HttpVersion::Http2 => Some("h2"),
                        HttpVersion::Http3 => Some("h3"),
                    };
                    if let Some(alpn) = alpn {
                        query.insert("alpn".to_owned(), json!(alpn));
                    }
                }
            }
            if let Some(path) = &value.http.path {
                query.entry("path").or_insert(json!(path));
            }
            let headers: Vec<_> = value
                .http
                .headers
                .iter()
                .flat_map(|(key, values)| {
                    values
                        .iter()
                        .filter(|v| !v.contains(',') && !key.contains(','))
                        .flat_map(|value| [key.as_str(), value.as_str()])
                })
                .collect();
            if !headers.is_empty() {
                query.insert("headers".to_owned(), json!(headers.join(",")));
            }
            if let Some(insecure) = query.remove("allowInsecure") {
                query.insert("insecure".to_owned(), insecure);
            }
            let user = credentials(
                value.proxy.username.as_deref(),
                value.proxy.password.as_deref(),
            );
            (
                if matches!(value.security, Security::None) {
                    "http"
                } else {
                    "https"
                },
                user,
            )
        }
        Connection::Socks(value) => {
            tls(&value.security, &mut query, store)?;
            transport(&value.transport, &value.security, &mut query, store)?;
            let socks_tls = value.socks.version == SocksVersion::V5
                && matches!(value.security, Security::Tls(_));
            if socks_tls {
                query.remove("security");
            }
            uot(&mut query, value.socks.udp_over_tcp)?;
            let user = if value.socks.version == SocksVersion::V5
                && !socks_tls
                && (value.proxy.username.is_some() || value.proxy.password.is_some())
            {
                format!(
                    "{}@",
                    URL_SAFE_NO_PAD.encode(format!(
                        "{}:{}",
                        value.proxy.username.as_deref().unwrap_or_default(),
                        value.proxy.password.as_deref().unwrap_or_default()
                    ))
                )
            } else {
                credentials(
                    value.proxy.username.as_deref(),
                    value.proxy.password.as_deref(),
                )
            };
            (
                match value.socks.version {
                    SocksVersion::V4 => "socks4",
                    SocksVersion::V4a => "socks4a",
                    SocksVersion::V5 if socks_tls => "socks5+tls",
                    SocksVersion::V5 => "socks",
                },
                user,
            )
        }
        Connection::Vless(value) => {
            if value.vless.flow == crate::vless::Flow::Vision {
                query.insert("flow".to_owned(), json!("xtls-rprx-vision"));
            }
            query.insert(
                "encryption".to_owned(),
                json!(value.vless.encryption.as_deref().unwrap_or("none")),
            );
            tls(&value.security, &mut query, store)?;
            transport(&value.transport, &value.security, &mut query, store)?;
            (
                "vless",
                format!("{}@", utf8_percent_encode(&value.uuid, COMPONENT)),
            )
        }
        Connection::Vmess(value) => {
            tls(&value.security, &mut query, store)?;
            transport(&value.transport, &value.security, &mut query, store)?;
            if value.vmess.alter_id.is_some_and(|id| id != 0)
                || query.keys().all(|key| {
                    matches!(
                        key.as_str(),
                        "type"
                            | "host"
                            | "path"
                            | "headerType"
                            | "seed"
                            | "serviceName"
                            | "authority"
                            | "mode"
                            | "security"
                            | "sni"
                            | "alpn"
                            | "fp"
                            | "allowInsecure"
                            | "vcn"
                            | "pcs"
                    )
                })
            {
                let network = query.remove("type").unwrap_or(json!("tcp"));
                let header = if network == "grpc" || network == "xhttp" {
                    query.remove("mode")
                } else {
                    query.remove("headerType")
                };
                let host = if network == "grpc" {
                    query.remove("authority")
                } else {
                    query.remove("host")
                };
                let path = if network == "grpc" {
                    query.remove("serviceName")
                } else if network == "kcp" {
                    query.remove("seed")
                } else {
                    query.remove("path")
                };
                let mut values = Map::from_iter([
                    ("v".to_owned(), json!(2)),
                    ("ps".to_owned(), json!(name)),
                    ("add".to_owned(), json!(server)),
                    ("port".to_owned(), json!(port)),
                    ("id".to_owned(), json!(value.uuid)),
                    ("aid".to_owned(), json!(value.vmess.alter_id.unwrap_or(0))),
                    ("scy".to_owned(), json!(value.vmess.cipher)),
                    ("net".to_owned(), network),
                ]);
                for (key, value) in [("type", header), ("host", host), ("path", path)] {
                    if let Some(value) = value {
                        values.insert(key.to_owned(), value);
                    }
                }
                if let Some(value) = query.remove("security") {
                    values.insert("tls".to_owned(), value);
                }
                if let Some(value) = query.remove("allowInsecure") {
                    values.insert("insecure".to_owned(), json!(value.to_string()));
                }
                values.extend(query);
                return Ok(format!(
                    "vmess://{}",
                    STANDARD.encode(serde_json::to_vec(&values)?)
                ));
            }
            if value.vmess.cipher != crate::vmess::Cipher::Auto {
                query.insert("encryption".to_owned(), json!(value.vmess.cipher));
            }
            (
                "vmess",
                format!("{}@", utf8_percent_encode(&value.uuid, COMPONENT)),
            )
        }
        Connection::Trojan(value) => {
            tls(&value.security, &mut query, store)?;
            transport(&value.transport, &value.security, &mut query, store)?;
            match value.security {
                Security::None => {
                    query.insert("security".to_owned(), json!("none"));
                }
                Security::Tls(_) => {
                    query.remove("security");
                }
                Security::Reality(_) => {}
            }
            (
                "trojan",
                format!("{}@", utf8_percent_encode(&value.password, COMPONENT)),
            )
        }
        Connection::AnyTls(value) => {
            Options::new(&value.anytls)?.copy(
                &mut query,
                &[
                    "idle_session_check_interval",
                    "idle_session_timeout",
                    "min_idle_session",
                ],
            );
            match value.security {
                Security::None => return Err("AnyTLS 分享链接使用 TLS".into()),
                Security::Tls(_) => {
                    tls(&value.security, &mut query, store)?;
                    query.remove("security");
                }
                Security::Reality(_) => tls(&value.security, &mut query, store)?,
            }
            if let Some(value) = query.remove("allowInsecure") {
                query.insert("insecure".to_owned(), value);
            }
            (
                "anytls",
                format!("{}@", utf8_percent_encode(&value.password, COMPONENT)),
            )
        }
        Connection::Hysteria2(value) => {
            tls(&Security::Tls(value.tls.clone()), &mut query, store)?;
            query.remove("security");
            if let Some(value) = query.remove("allowInsecure") {
                query.insert("insecure".to_owned(), value);
            }
            if let Some(pins) = query.remove("pcs") {
                let pins = pins.as_str().unwrap();
                if let Some((first, _)) = pins.split_once(',') {
                    query.insert("pcs".to_owned(), json!(pins));
                    query.insert("pinSHA256".to_owned(), json!(first));
                } else {
                    query.insert("pinSHA256".to_owned(), json!(pins));
                }
            }
            let options = &value.hysteria;
            if let Some(obfs) = &options.obfs {
                query.insert("obfs".to_owned(), json!(obfs.kind));
                query.insert("obfs-password".to_owned(), json!(obfs.password));
                if obfs.kind == crate::hysteria::ObfsKind::Gecko {
                    let (min, max) = obfs.packet_sizes();
                    for (field, alias, size, explicit) in [
                        (
                            "minPacketSize",
                            "min_packet_size",
                            min,
                            obfs.min_packet_size,
                        ),
                        (
                            "maxPacketSize",
                            "max_packet_size",
                            max,
                            obfs.max_packet_size,
                        ),
                    ] {
                        if explicit.is_some_and(|size| size != 0) {
                            query.insert(field.to_owned(), json!(size));
                            query.insert(alias.to_owned(), json!(size));
                        }
                    }
                }
            }
            if !options.ports.is_empty() {
                query.insert("mport".to_owned(), json!(options.ports));
                Options::new(options)?.copy(&mut query, &["hop_interval", "hop_interval_max"]);
            }
            for (key, bandwidth) in [
                ("up", &options.quic.upload_bandwidth),
                ("down", &options.quic.download_bandwidth),
            ] {
                if let Some(bandwidth) = bandwidth {
                    query.insert(key.to_owned(), json!(bandwidth));
                }
            }
            let mask = crate::native::hysteria::share_mask(options)?;
            if !mask.is_empty() {
                query.insert("fm".to_owned(), json!(mask));
            }
            (
                "hysteria2",
                format!("{}@", utf8_percent_encode(&value.password, COMPONENT)),
            )
        }
        Connection::Shadowsocks(value) => {
            tls(&value.security, &mut query, store)?;
            transport(&value.transport, &value.security, &mut query, store)?;
            uot(&mut query, value.shadowsocks.udp_over_tcp)?;
            let cipher = serde_json::to_value(value.shadowsocks.cipher)?;
            let cipher = cipher.as_str().unwrap();
            let password = value.shadowsocks.cipher.password(&value.password)?;
            if let Some(plugin) = &value.shadowsocks.plugin {
                query.insert(
                    "plugin".to_owned(),
                    json!(if plugin.options.is_empty() {
                        plugin.name.clone()
                    } else {
                        format!("{};{}", plugin.name, plugin.options)
                    }),
                );
            }
            let user = if value.shadowsocks.cipher.key_size().is_some() {
                format!("{cipher}:{}@", utf8_percent_encode(&password, COMPONENT))
            } else {
                format!(
                    "{}@",
                    URL_SAFE_NO_PAD.encode(format!("{cipher}:{password}"))
                )
            };
            ("ss", user)
        }
    };
    let address = connection::address(&server, port);
    let mut value = format!("{scheme}://{user}{address}");
    if matches!(scheme, "http" | "https") {
        value.push('/');
    }
    if !query.is_empty() {
        if scheme == "ss" && !value.ends_with('/') {
            value.push('/');
        }
        value.push('?');
        value.push_str(
            &query
                .into_iter()
                .map(|(key, value)| {
                    let value = value
                        .as_str()
                        .map_or_else(|| value.to_string(), str::to_owned);
                    format!(
                        "{}={}",
                        utf8_percent_encode(&key, COMPONENT),
                        utf8_percent_encode(&value, COMPONENT)
                    )
                })
                .collect::<Vec<_>>()
                .join("&"),
        );
    }
    if !name.is_empty() {
        value.push('#');
        value.push_str(&utf8_percent_encode(name, COMPONENT).to_string());
    }
    Ok(value)
}

fn uot(query: &mut Map<String, Value>, version: Option<u8>) -> Result<()> {
    let field = match version {
        None => return Ok(()),
        Some(0 | 2) => "uot",
        Some(1) => "udp-over-tcp",
        Some(_) => return Err("UDP over TCP 使用版本 1 或 2".into()),
    };
    query.insert(field.to_owned(), json!(true));
    Ok(())
}

fn credentials(username: Option<&str>, password: Option<&str>) -> String {
    if username.is_none() && password.is_none() {
        return String::new();
    }
    let mut value = utf8_percent_encode(username.unwrap_or_default(), COMPONENT).to_string();
    if let Some(password) = password {
        value.push(':');
        value.push_str(&utf8_percent_encode(password, COMPONENT).to_string());
    }
    value.push('@');
    value
}

fn tls(security: &Security, query: &mut Map<String, Value>, store: &Store) -> Result<()> {
    let (source, reality) = match security {
        Security::None => return Ok(()),
        Security::Tls(tls) => (tls, None),
        Security::Reality(reality) => (&reality.tls, Some(reality.as_ref())),
    };
    query.insert(
        "security".to_owned(),
        json!(if reality.is_some() { "reality" } else { "tls" }),
    );
    let mut options = Options::new(source)?;
    options.rename(
        query,
        &[
            ("server_name", "sni"),
            ("fingerprint", "fp"),
            ("min_version", "tls_min_version"),
            ("max_version", "tls_max_version"),
            ("fragment", "tls_fragment"),
            ("fragment_delay", "tls_fragment_fallback_delay"),
            ("record_fragment", "tls_record_fragment"),
            ("client_certificate", "tls_client_certificate"),
            ("client_key", "tls_client_key"),
        ],
    );
    for (destination, separator, values) in [
        ("alpn", ",", &source.alpn),
        ("vcn", ",", &source.verify_names),
        ("cs", ":", &source.cipher_suites),
        ("tls_curve_preferences", ",", &source.curves),
        ("tls_certificate", ",", &source.certificates),
        (
            "tls_certificate_public_key_sha256",
            ",",
            &source.public_key_sha256,
        ),
    ] {
        if !values.is_empty() {
            query.insert(destination.to_owned(), json!(values.join(separator)));
        }
    }
    if !source.certificate_sha256.is_empty() {
        query.insert(
            "pcs".to_owned(),
            json!(crate::native::hex_hashes(&source.certificate_sha256)?.join(",")),
        );
    }
    if source.verify_certificate == Some(false) {
        query.insert("allowInsecure".to_owned(), json!(1));
    }
    if source.send_sni == Some(false) {
        query.insert("disable_sni".to_owned(), json!(true));
    }
    if let Some(reality) = reality {
        let mut options = Options::new(reality)?;
        options.rename(
            query,
            &[
                ("public_key", "pbk"),
                ("short_id", "sid"),
                ("spider_path", "spx"),
                ("signature_key", "pqv"),
            ],
        );
        query.entry("fp").or_insert(json!("chrome"));
    }
    if let Some(ech) = &source.ech {
        let value = if let Some(value) = &ech.config {
            value.clone()
        } else if let Some(file) = &ech.config_file {
            std::fs::read_to_string(store.directory.join(file))?
                .trim()
                .to_owned()
        } else {
            ech.query_name.clone().unwrap_or_default()
        };
        query.insert("ech".to_owned(), json!(value));
    }
    Ok(())
}

fn transport(
    source: &Transport,
    security: &Security,
    query: &mut Map<String, Value>,
    store: &Store,
) -> Result<()> {
    let secure = !matches!(security, Security::None);
    match source {
        Transport::Default => {}
        Transport::WebSocket(value) => {
            query.insert("type".to_owned(), json!("ws"));
            host(&value.headers, value.host.as_deref(), query);
            let mut path = value.path.clone().unwrap_or_else(|| "/".to_owned());
            if let Some(size) = value.early_data {
                if let Some(header) = &value.early_data_header {
                    query.insert("early_data_header_name".to_owned(), json!(header));
                }
                path = crate::native::transport::early_data(&path, size);
            }
            query.insert("path".to_owned(), json!(path));
        }
        Transport::HttpUpgrade(value) => {
            query.insert("type".to_owned(), json!("httpupgrade"));
            host(&value.headers, value.host.as_deref(), query);
            let mut path = value.path.clone().unwrap_or_else(|| "/".to_owned());
            if let Some(enabled) = value.early_data {
                path = crate::native::transport::early_data(&path, u32::from(enabled));
            }
            query.insert("path".to_owned(), json!(path));
        }
        Transport::Grpc(value) => {
            query.insert("type".to_owned(), json!("grpc"));
            if let Some(value) = &value.service_name {
                query.insert("serviceName".to_owned(), json!(value));
            }
            if let Some(value) = &value.authority {
                query.insert("authority".to_owned(), json!(value));
            }
            if value.multi_mode {
                query.insert("mode".to_owned(), json!("multi"));
            }
        }
        Transport::Http(value) => {
            match value.version(secure) {
                HttpVersion::Http1 => {
                    query.insert("type".to_owned(), json!("tcp"));
                    query.insert("headerType".to_owned(), json!("http"));
                }
                HttpVersion::Http2 | HttpVersion::Http3 => {
                    query.insert("type".to_owned(), json!("http"));
                    if secure && value.version(true) == HttpVersion::Http3 {
                        query.entry("alpn").or_insert(json!("h3"));
                    }
                }
                HttpVersion::Auto => unreachable!(),
            }
            host(&value.headers, None, query);
            if !value.host.is_empty() {
                query.insert("host".to_owned(), json!(value.host.join(",")));
            }
            if let Some(value) = &value.path {
                query.insert("path".to_owned(), json!(value));
            }
        }
        Transport::Kcp(value) => {
            query.insert("type".to_owned(), json!("kcp"));
            if let Some(value) = value.mtu {
                query.insert("mtu".to_owned(), json!(value));
            }
            if let Some(value) = &value.interval {
                let duration = humantime::parse_duration(value)?;
                if duration.subsec_nanos() % 1_000_000 == 0 {
                    query.insert("tti".to_owned(), json!(duration.as_millis()));
                }
            }
            if value.header != Header::None {
                query.insert("headerType".to_owned(), json!(value.header));
            }
            if let Some(value) = &value.seed {
                query.insert("seed".to_owned(), json!(value));
            }
            if let Some(value) = &value.domain {
                query.insert("host".to_owned(), json!(value));
            }
            if !value.checksum || value.header == Header::Dns && value.domain.is_some() {
                query.insert(
                    "fm".to_owned(),
                    json!({"udp": crate::native::transport::kcp_masks(value)?}),
                );
            }
        }
        Transport::Quic => {
            query.insert("type".to_owned(), json!("quic"));
        }
        Transport::XHttp(value) => {
            let mut value = value.clone();
            if let Some(download) = &mut value.download {
                download.network = connection::Network::default();
                if let Some(tls) = download.security.tls_mut() {
                    for file in std::mem::take(&mut tls.certificate_files) {
                        tls.certificates
                            .push(std::fs::read_to_string(store.directory.join(file))?);
                    }
                    if let Some(file) = tls.client_certificate_file.take() {
                        tls.client_certificate =
                            Some(std::fs::read_to_string(store.directory.join(file))?);
                    }
                    if let Some(file) = tls.client_key_file.take() {
                        tls.client_key = Some(std::fs::read_to_string(store.directory.join(file))?);
                    }
                }
            }
            let mut native = crate::native::transport::xray(
                &Transport::XHttp(value),
                false,
                store.into(),
                secure,
            )?;
            query.insert("type".to_owned(), json!("xhttp"));
            let mut extra = native
                .remove("xhttpSettings")
                .unwrap()
                .as_object()
                .unwrap()
                .clone();
            for name in ["host", "path", "mode"] {
                if let Some(value) = extra.remove(name) {
                    query.insert(name.to_owned(), value);
                }
            }
            if !extra.is_empty() {
                query.insert("extra".to_owned(), json!(extra));
            }
            if let Some(value) = native.remove("finalmask") {
                query.insert("fm".to_owned(), value);
            }
        }
    }
    Ok(())
}

fn host(
    values: &BTreeMap<String, Vec<String>>,
    host: Option<&str>,
    query: &mut Map<String, Value>,
) {
    if let Some(host) = host.or_else(|| {
        values
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("host"))
            .and_then(|(_, hosts)| hosts.first())
            .map(String::as_str)
    }) {
        query.insert("host".to_owned(), json!(host));
    }
}
