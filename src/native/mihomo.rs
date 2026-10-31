use std::time::Duration;

use serde_json::{Map, Value, json};

use crate::{
    Result,
    config::Store,
    connection::{self, AddressStrategy, Connection, FastOpen, SocksVersion},
    inbound::{self, Inbound, Protocol},
};

use super::{
    certificate_paths, hex_hashes, options::Options, path, pem, single_headers, unsupported,
};

pub fn outbound(
    source: &Connection,
    store: &Store,
    globals: &mut Map<String, Value>,
) -> Result<Map<String, Value>> {
    if source
        .transport()
        .is_some_and(|transport| !transport.is_default())
    {
        return unsupported("Mihomo 的 HTTP/SOCKS 出站没有传输封装配置");
    }
    let (kind, proxy, network) = match source {
        Connection::Direct(value) => ("direct", None, &value.network),
        Connection::Http(value) => ("http", Some(&value.proxy), &value.network),
        Connection::Socks(value) => ("socks5", Some(&value.proxy), &value.network),
    };
    let mut output = Map::from_iter([("type".to_owned(), json!(kind))]);
    let mut options = Options::new(network)?;
    options.rename(
        &mut output,
        &[
            ("interface", "interface-name"),
            ("routing_mark", "routing-mark"),
            ("tcp_multi_path", "mptcp"),
        ],
    );
    if let Some(value) = &network.tcp_fast_open
        && let FastOpen::Enabled(value) = value
    {
        options.take("tcp_fast_open");
        output.insert("tfo".to_owned(), json!(value));
    }
    if let Some(strategy) = network.address_strategy {
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
        options.take("address_strategy");
        output.insert("ip-version".to_owned(), json!(value));
    }
    keep_alive(&mut options, globals)?;
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
            Some(&value.tls)
        }
        Connection::Socks(value) => {
            if value.socks.version != SocksVersion::V5 {
                return unsupported("Mihomo SOCKS 出站使用 SOCKS5");
            }
            if value.tls.enabled
                && value.tls.server_name.as_ref().is_some_and(|name| {
                    !name.is_empty() && !name.eq_ignore_ascii_case(&value.proxy.server)
                })
            {
                return unsupported("Mihomo 的 SOCKS TLS 使用服务器地址作为 SNI");
            }
            let mut options = Options::new(&value.socks)?;
            options.take("udp");
            output.insert("udp".to_owned(), json!(value.socks.udp.unwrap_or(true)));
            options.take("tcp");
            options.finish("Mihomo SOCKS")?;
            Some(&value.tls)
        }
    };
    if let Some(tls) = tls.filter(|tls| tls.enabled) {
        client_tls(tls, store, &mut output, globals)?;
        if matches!(source, Connection::Socks(_)) {
            output.remove("sni");
        }
    }
    Ok(output)
}

pub fn listeners(
    source: &Inbound,
    users: &[(String, String)],
    store: &Store,
    globals: &mut Map<String, Value>,
) -> Result<Vec<Map<String, Value>>> {
    if !source.transport.is_default() {
        return unsupported("Mihomo 的 HTTP/SOCKS 入站没有传输封装配置");
    }
    let mut output = Map::from_iter([
        ("listen".to_owned(), json!(source.listen.address)),
        ("port".to_owned(), json!(source.ports)),
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
    options.rename(&mut output, &[("routing_mark", "routing-mark")]);
    if let Some(FastOpen::Enabled(value)) = &source.listen.tcp_fast_open {
        options.take("tcp_fast_open");
        globals.insert("inbound-tfo".to_owned(), json!(value));
    }
    options.rename(globals, &[("tcp_multi_path", "inbound-mptcp")]);
    keep_alive(&mut options, globals)?;
    options.finish("Mihomo 监听")?;
    let Protocol::Mixed(value) = &source.protocol;
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
    if source.tls.enabled {
        server_tls(source, store, &mut output)?;
    }
    Ok(vec![output])
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

fn client_tls(
    source: &connection::Tls,
    store: &Store,
    output: &mut Map<String, Value>,
    globals: &mut Map<String, Value>,
) -> Result<()> {
    let mut options = Options::new(source)?;
    options.rename(output, &[("enabled", "tls"), ("server_name", "sni")]);
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
    for (inline, file, destination) in [
        (
            "client_certificate",
            "client_certificate_file",
            "certificate",
        ),
        ("client_key", "client_key_file", "private-key"),
    ] {
        let text = options.take(inline);
        let file = options.take(file);
        if let Some(file) = file {
            output.insert(
                destination.to_owned(),
                json!(path(store, file.as_str().unwrap())),
            );
        } else if let Some(text) = text {
            output.insert(destination.to_owned(), text);
        }
    }
    options.take("certificates");
    options.take("certificate_files");
    let trust = pem(store, &source.certificates, &source.certificate_files)?;
    if !trust.is_empty() {
        globals.insert("tls".to_owned(), json!({"custom-certifactes": trust}));
    }
    options.take("ech");
    if source.ech.enabled {
        return unsupported("Mihomo HTTP/SOCKS 出站没有 ECH 配置");
    }
    options.finish("Mihomo TLS")
}

fn server_tls(source: &Inbound, store: &Store, output: &mut Map<String, Value>) -> Result<()> {
    let mut options = Options::new(&source.tls)?;
    options.take("enabled");
    options.take("server_name");
    let (certificate, key) = certificate_paths(store, source);
    output.insert("certificate".to_owned(), json!(certificate));
    output.insert("private-key".to_owned(), json!(key));
    options.rename(output, &[("client_auth", "client-auth-type")]);
    options.take("client_certificates");
    options.take("client_certificate_files");
    let trust = pem(
        store,
        &source.tls.client_certificates,
        &source.tls.client_certificate_files,
    )?;
    if !trust.is_empty() {
        output.insert("client-auth-cert".to_owned(), json!(trust.join("\n")));
    }
    options.take("ech");
    if source.tls.ech.enabled {
        if let Some(file) = &source.tls.ech.key_file {
            output.insert("ech-key".to_owned(), json!(path(store, file)));
        } else if let [key] = source.tls.ech.keys.as_slice() {
            output.insert("ech-key".to_owned(), json!(key));
        } else {
            return unsupported("Mihomo ECH 使用一份服务端密钥");
        }
    }
    options.finish("Mihomo 服务端 TLS")
}
