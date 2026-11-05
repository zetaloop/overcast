use std::{collections::BTreeMap, net::IpAddr};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Map, Value, json};
use url::{Host, Url};

use crate::{
    Result,
    config::Store,
    connection::{self, Connection, HttpVersion, SocksVersion, Tls},
    native::options::Options,
    transport::{Header, Transport},
};

const COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

pub fn path(connections: &[Connection], name: &str, store: &Store) -> Result<String> {
    let mut values = Vec::new();
    for connection in connections {
        if let Connection::Direct(value) = connection {
            Options::new(&value.network)?.finish("分享链接")?;
        } else {
            values.push(connection.clone());
        }
    }
    let mut inner = values.pop().ok_or("直连没有远端分享链接")?;
    while let Some(outer) = values.pop() {
        Options::new(outer.network())?.finish("分享链接")?;
        match outer {
            Connection::Forward(value) => {
                let (server, port, tls, transport) = match &mut inner {
                    Connection::Http(value) => (
                        &mut value.proxy.server,
                        &mut value.proxy.port,
                        &mut value.tls,
                        Some(&mut value.transport),
                    ),
                    Connection::Socks(value) => (
                        &mut value.proxy.server,
                        &mut value.proxy.port,
                        &mut value.tls,
                        Some(&mut value.transport),
                    ),
                    Connection::Vless(value) => (
                        &mut value.server,
                        &mut value.port,
                        &mut value.tls,
                        Some(&mut value.transport),
                    ),
                    Connection::Vmess(value) => (
                        &mut value.server,
                        &mut value.port,
                        &mut value.tls,
                        Some(&mut value.transport),
                    ),
                    Connection::Trojan(value) => (
                        &mut value.server,
                        &mut value.port,
                        &mut value.tls,
                        Some(&mut value.transport),
                    ),
                    Connection::Shadowsocks(value) => (
                        &mut value.server,
                        &mut value.port,
                        &mut value.tls,
                        Some(&mut value.transport),
                    ),
                    Connection::Forward(value) => (
                        &mut value.server,
                        &mut value.port,
                        &mut value.tls,
                        Some(&mut value.transport),
                    ),
                    Connection::Direct(_) => unreachable!(),
                    Connection::Hysteria2(value) => {
                        if !value.hysteria.ports.is_empty() {
                            return Err("多段跳跃端口连接使用连接路径 JSON 分享".into());
                        }
                        (&mut value.server, &mut value.port, &mut value.tls, None)
                    }
                    Connection::AnyTls(value) => {
                        (&mut value.server, &mut value.port, &mut value.tls, None)
                    }
                };
                if value.tls.enabled && tls.enabled {
                    return Err("嵌套 TLS 连接使用连接路径 JSON 分享".into());
                }
                if !value.transport.is_default() && tls.enabled {
                    return Err("传输内部的 TLS 连接使用连接路径 JSON 分享".into());
                }
                if tls.enabled && tls.server_name.is_none() {
                    tls.server_name = Some(server.clone());
                }
                if value.tls.enabled {
                    *tls = value.tls;
                }
                if !value.transport.is_default() {
                    let Some(transport) = transport.filter(|transport| transport.is_default())
                    else {
                        return Err("嵌套传输连接使用连接路径 JSON 分享".into());
                    };
                    *transport = value.transport;
                }
                *server = value.server;
                *port = value.port;
            }
            _ => return Err("多段代理连接使用连接路径 JSON 分享".into()),
        }
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
        Connection::Forward(_) => {
            return Err("此连接使用连接路径 JSON 分享".into());
        }
        Connection::Http(value) => {
            if !value.transport.is_default()
                || !matches!(value.http.version, HttpVersion::Auto | HttpVersion::Http1)
            {
                return Err("HTTP 分享链接使用标准 HTTP/HTTPS 代理连接".into());
            }
            if value.tls.enabled {
                let mut tls = value.tls.clone();
                tls.enabled = false;
                if tls.server_name.as_deref() == Some(value.proxy.server.as_str()) {
                    tls.server_name = None;
                }
                Options::new(&tls)?.finish("HTTP 分享链接")?;
            }
            if !value.http.headers.is_empty() {
                return Err("HTTP 代理分享链接没有自定义请求头字段".into());
            }
            let user = credentials(
                value.proxy.username.as_deref(),
                value.proxy.password.as_deref(),
            );
            (if value.tls.enabled { "https" } else { "http" }, user)
        }
        Connection::Socks(value) => {
            if value.tls.enabled || !value.transport.is_default() {
                return Err("SOCKS 分享链接使用原生 SOCKS 连接".into());
            }
            let user = if value.socks.version == SocksVersion::V5
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
                    SocksVersion::V5 => "socks",
                },
                user,
            )
        }
        Connection::Vless(value) => {
            if value.vless.flow == crate::vless::Flow::Vision {
                query.insert("flow".to_owned(), json!("xtls-rprx-vision"));
            }
            if let Some(value) = value
                .vless
                .encryption
                .as_ref()
                .filter(|value| value.as_str() != "none")
            {
                query.insert("encryption".to_owned(), json!(value));
            }
            tls(&value.tls, &mut query, store)?;
            transport(&value.transport, &value.tls, &mut query, store)?;
            (
                "vless",
                format!("{}@", utf8_percent_encode(&value.uuid, COMPONENT)),
            )
        }
        Connection::Vmess(value) => {
            tls(&value.tls, &mut query, store)?;
            transport(&value.transport, &value.tls, &mut query, store)?;
            if query.keys().all(|key| {
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
            }) {
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
            if value.vmess.alter_id.is_some_and(|value| value != 0) {
                return Err("此传输参数使用 VMess AEAD 分享链接".into());
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
            tls(&value.tls, &mut query, store)?;
            transport(&value.transport, &value.tls, &mut query, store)?;
            if !value.tls.enabled {
                query.insert("security".to_owned(), json!("none"));
            } else if !value.tls.reality.enabled {
                query.remove("security");
            }
            (
                "trojan",
                format!("{}@", utf8_percent_encode(&value.password, COMPONENT)),
            )
        }
        Connection::AnyTls(value) => {
            let mut options = Options::new(&value.anytls)?;
            if value.anytls.tcp == Some(true) {
                options.take("tcp");
            }
            if value.anytls.udp == Some(true) {
                options.take("udp");
            }
            if value.anytls.reuse == Some(true) {
                options.take("reuse");
            }
            options.finish("AnyTLS 分享链接")?;
            if !value.tls.enabled {
                return Err("AnyTLS 分享链接使用 TLS".into());
            }
            tls(&value.tls, &mut query, store)?;
            if !value.tls.reality.enabled {
                query.remove("security");
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
            let mut options = Options::new(&value.hysteria)?;
            options.take("obfs");
            options.take("ports");
            if value.hysteria.tcp == Some(true) {
                options.take("tcp");
            }
            if value.hysteria.udp == Some(true) {
                options.take("udp");
            }
            options.finish("Hysteria 2 分享链接")?;
            tls(&value.tls, &mut query, store)?;
            if !value.tls.enabled || value.tls.reality.enabled {
                return Err("Hysteria 2 分享链接使用 TLS".into());
            }
            query.remove("security");
            if let Some(value) = query.remove("allowInsecure") {
                query.insert("insecure".to_owned(), value);
            }
            if let Some(value) = query.remove("pcs") {
                if value.as_str().unwrap().contains(',') {
                    return Err("Hysteria 2 分享链接使用一个证书指纹".into());
                }
                query.insert("pinSHA256".to_owned(), value);
            }
            if let Some(obfs) = &value.hysteria.obfs {
                let mut options = Options::new(obfs)?;
                options.take("kind");
                options.take("password");
                options.finish("Hysteria 2 混淆分享链接")?;
                query.insert("obfs".to_owned(), json!(obfs.kind));
                query.insert("obfs-password".to_owned(), json!(obfs.password));
            }
            (
                "hysteria2",
                format!("{}@", utf8_percent_encode(&value.password, COMPONENT)),
            )
        }
        Connection::Shadowsocks(value) => {
            if value.tls.enabled || !value.transport.is_default() {
                return Err("Shadowsocks 分享链接通过 SIP003 插件描述传输封装".into());
            }
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
    let mut url = Url::parse(&format!(
        "{scheme}://{user}{}",
        connection::address(&server, port)
    ))?;
    if let Connection::Http(value) = source
        && let Some(path) = &value.http.path
    {
        url.set_path(path);
    }
    let mut value = if let Connection::Hysteria2(source) = source
        && !source.hysteria.ports.is_empty()
    {
        crate::connection::ports(&source.hysteria.ports)?;
        format!(
            "{scheme}://{user}{}",
            connection::address(&server, &source.hysteria.ports)
        )
    } else {
        url.to_string()
    };
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

fn tls(source: &Tls, query: &mut Map<String, Value>, store: &Store) -> Result<()> {
    if !source.enabled {
        return Ok(());
    }
    query.insert(
        "security".to_owned(),
        json!(if source.reality.enabled {
            "reality"
        } else {
            "tls"
        }),
    );
    let mut options = Options::new(source)?;
    for name in [
        "enabled",
        "reality",
        "ech",
        "key_log",
        "handshake_timeout",
        "session_resumption",
        "kernel_tx",
        "kernel_rx",
    ] {
        options.take(name);
    }
    options.rename(query, &[("server_name", "sni"), ("fingerprint", "fp")]);
    for (name, destination, values) in [
        ("alpn", "alpn", &source.alpn),
        ("verify_names", "vcn", &source.verify_names),
    ] {
        options.take(name);
        if !values.is_empty() {
            query.insert(destination.to_owned(), json!(values.join(",")));
        }
    }
    options.take("certificate_sha256");
    if !source.certificate_sha256.is_empty() {
        query.insert(
            "pcs".to_owned(),
            json!(crate::native::hex_hashes(&source.certificate_sha256)?.join(",")),
        );
    }
    options.take("verify_certificate");
    if source.verify_certificate == Some(false) {
        query.insert("allowInsecure".to_owned(), json!(1));
    }
    if source.send_sni == Some(true) {
        options.take("send_sni");
    }
    if source.system_roots == Some(true) {
        options.take("system_roots");
    }
    options.finish("TLS 分享链接")?;
    if source.reality.enabled {
        let mut options = Options::new(&source.reality)?;
        options.take("enabled");
        options.take("debug");
        options.rename(
            query,
            &[
                ("public_key", "pbk"),
                ("short_id", "sid"),
                ("spider_path", "spx"),
                ("signature_key", "pqv"),
            ],
        );
        options.finish("REALITY 分享链接")?;
        query.entry("fp").or_insert(json!("chrome"));
    }
    if source.ech.enabled {
        let value = if let Some(value) = &source.ech.config {
            value.clone()
        } else if let Some(file) = &source.ech.config_file {
            std::fs::read_to_string(store.directory.join(file))?
                .trim()
                .to_owned()
        } else {
            source.ech.query_name.clone().unwrap_or_default()
        };
        query.insert("ech".to_owned(), json!(value));
    }
    Ok(())
}

fn transport(
    source: &Transport,
    security: &Tls,
    query: &mut Map<String, Value>,
    store: &Store,
) -> Result<()> {
    match source {
        Transport::Default => {}
        Transport::WebSocket(value) => {
            query.insert("type".to_owned(), json!("ws"));
            headers(&value.headers, value.host.as_deref(), query)?;
            let mut path = value.path.clone().unwrap_or_else(|| "/".to_owned());
            if let Some(size) = value.early_data {
                if value
                    .early_data_header
                    .as_deref()
                    .is_some_and(|header| !header.eq_ignore_ascii_case("Sec-WebSocket-Protocol"))
                {
                    return Err("WebSocket 分享链接的握手数据使用 Sec-WebSocket-Protocol".into());
                }
                path = crate::native::transport::early_data(&path, size);
            }
            query.insert("path".to_owned(), json!(path));
        }
        Transport::HttpUpgrade(value) => {
            query.insert("type".to_owned(), json!("httpupgrade"));
            headers(&value.headers, value.host.as_deref(), query)?;
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
            match value.version(security.enabled) {
                HttpVersion::Http1 => {
                    query.insert("type".to_owned(), json!("tcp"));
                    query.insert("headerType".to_owned(), json!("http"));
                }
                HttpVersion::Http2 => {
                    query.insert("type".to_owned(), json!("http"));
                }
                _ => return Err("当前 HTTP 传输没有对应的分享链接形式".into()),
            }
            headers(&value.headers, None, query)?;
            if !value.host.is_empty() {
                query.insert("host".to_owned(), json!(value.host.join(",")));
            }
            if let Some(value) = &value.path {
                query.insert("path".to_owned(), json!(value));
            }
            if value
                .method
                .as_deref()
                .is_some_and(|method| method != "GET")
            {
                return Err("HTTP 传输分享链接使用默认请求方法".into());
            }
        }
        Transport::Kcp(value) => {
            query.insert("type".to_owned(), json!("kcp"));
            if let Some(value) = value.mtu {
                query.insert("mtu".to_owned(), json!(value));
            }
            if let Some(value) = &value.interval {
                let duration = humantime::parse_duration(value)?;
                if duration.subsec_nanos() % 1_000_000 != 0 {
                    return Err("KCP 分享链接的时间间隔使用整数毫秒".into());
                }
                query.insert("tti".to_owned(), json!(duration.as_millis()));
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
                let native =
                    crate::native::transport::xray(source, false, store, security.enabled)?;
                query.insert(
                    "fm".to_owned(),
                    native
                        .get("finalmask")
                        .cloned()
                        .unwrap_or_else(|| json!({"udp": []})),
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
                if download.tls.enabled {
                    for file in std::mem::take(&mut download.tls.certificate_files) {
                        download
                            .tls
                            .certificates
                            .push(std::fs::read_to_string(store.directory.join(file))?);
                    }
                    if let Some(file) = download.tls.client_certificate_file.take() {
                        download.tls.client_certificate =
                            Some(std::fs::read_to_string(store.directory.join(file))?);
                    }
                    if let Some(file) = download.tls.client_key_file.take() {
                        download.tls.client_key =
                            Some(std::fs::read_to_string(store.directory.join(file))?);
                    }
                }
            }
            let mut native = crate::native::transport::xray(
                &Transport::XHttp(value),
                false,
                store,
                security.enabled,
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

fn headers(
    values: &BTreeMap<String, Vec<String>>,
    host: Option<&str>,
    query: &mut Map<String, Value>,
) -> Result<()> {
    for (name, values) in values {
        if !name.eq_ignore_ascii_case("host") || values.len() != 1 {
            return Err(format!("分享链接没有自定义请求头 {name} 的通用表达方式").into());
        }
        if host.is_none() {
            if query
                .get("host")
                .is_some_and(|value| value != &json!(values[0]))
            {
                return Err("分享链接使用单个 Host 请求头".into());
            }
            query.insert("host".to_owned(), json!(values[0]));
        }
    }
    if let Some(host) = host {
        query.insert("host".to_owned(), json!(host));
    }
    Ok(())
}
