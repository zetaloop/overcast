use std::collections::BTreeMap;

use base64::{
    Engine, alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use percent_encoding::percent_decode_str;
use serde_json::{Map, Value, json};
use url::{Host, Url};

use crate::{
    Result,
    connection::{Ech, HttpVersion, Security, Tls},
    transport::{
        Download, Grpc, Header, Http, HttpUpgrade, Kcp, Pool, Quic, Transport, WebSocket, XHttp,
        XHttpOptions,
    },
    vless::{Client, Flow},
};

pub fn decode(value: &str) -> Result<Vec<u8>> {
    let engine = GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    Ok(engine.decode(value.replace('-', "+").replace('_', "/"))?)
}

pub fn vmess(text: &str) -> Result<crate::vmess::Client> {
    let mut client = crate::vmess::Client::default();
    let mut query;
    if text.contains('@') {
        let url = Url::parse(text)?;
        client.name = percent_decode_str(url.fragment().unwrap_or_default())
            .decode_utf8()?
            .into_owned();
        client.server = host(&url)?;
        client.port = url.port().ok_or("VMess 链接缺少端口")?;
        client.uuid = percent_decode_str(url.username())
            .decode_utf8()?
            .into_owned();
        if let Some(password) = url.password() {
            client.uuid.push(':');
            client
                .uuid
                .push_str(&percent_decode_str(password).decode_utf8()?);
        }
        query = url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<BTreeMap<_, _>>();
        if let Some(cipher) = query.remove("encryption") {
            client.vmess.cipher = serde_json::from_value(json!(cipher))?;
        }
    } else {
        let encoded = text.split_once("://").ok_or("链接缺少协议")?.1;
        let values: Map<String, Value> = serde_json::from_slice(&decode(encoded)?)?;
        query = BTreeMap::new();
        for (key, value) in values {
            let value = match value {
                Value::String(value) => value,
                Value::Null => continue,
                value => value.to_string(),
            };
            if !value.is_empty() {
                query.insert(key, value);
            }
        }
        query.remove("v");
        client.name = query.remove("ps").unwrap_or_default();
        client.server = query.remove("add").ok_or("VMess 链接缺少服务器地址")?;
        client.port = query.remove("port").ok_or("VMess 链接缺少端口")?.parse()?;
        client.uuid = query.remove("id").ok_or("VMess 链接缺少用户标识")?;
        if let Some(value) = query.remove("aid") {
            client.vmess.alter_id = Some(value.parse()?);
        }
        if let Some(value) = query.remove("scy") {
            client.vmess.cipher = serde_json::from_value(json!(value))?;
        }
        let network = query.remove("net").unwrap_or_else(|| "tcp".to_owned());
        let header = query.remove("type");
        let host = query.remove("host");
        let path = query.remove("path");
        match network.as_str() {
            "grpc" => {
                if let Some(host) = host {
                    query.insert("authority".to_owned(), host);
                }
                if let Some(path) = path {
                    query.insert("serviceName".to_owned(), path);
                }
                if let Some(mode) = header.filter(|value| value != "none") {
                    query.insert("mode".to_owned(), mode);
                }
            }
            "kcp" => {
                if let Some(header) = header {
                    query.insert("headerType".to_owned(), header);
                }
                if let Some(path) = path {
                    query.insert("seed".to_owned(), path);
                }
            }
            _ => {
                if let Some(host) = host {
                    query.insert("host".to_owned(), host);
                }
                if let Some(path) = path {
                    query.insert("path".to_owned(), path);
                }
                if let Some(header) = header {
                    if network == "xhttp" {
                        query.insert("mode".to_owned(), header);
                    } else if matches!(network.as_str(), "raw" | "tcp") {
                        query.insert("headerType".to_owned(), header);
                    }
                }
            }
        }
        query.insert("type".to_owned(), network);
        if let Some(security) = query.remove("tls") {
            query.insert("security".to_owned(), security);
        }
    }
    client.security = security(&mut query, false)?;
    client.transport = transport(&mut query)?;
    remaining(query.keys(), "链接参数")?;
    Ok(client)
}

pub fn vless(url: &Url) -> Result<Client> {
    let mut query: BTreeMap<_, _> = url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    let mut client = Client {
        name: percent_decode_str(url.fragment().unwrap_or_default())
            .decode_utf8()?
            .into_owned(),
        server: host(url)?,
        port: url.port().ok_or("VLESS 链接缺少端口")?,
        uuid: percent_decode_str(url.username())
            .decode_utf8()?
            .into_owned(),
        ..Client::default()
    };
    if let Some(password) = url.password() {
        client.uuid.push(':');
        client
            .uuid
            .push_str(&percent_decode_str(password).decode_utf8()?);
    }
    client.vless.flow = match query.remove("flow").as_deref() {
        None | Some("") => Flow::None,
        Some("xtls-rprx-vision" | "xtls-rprx-vision-udp443") => Flow::Vision,
        Some(value) => return Err(format!("无法识别 VLESS 流模式：{value}").into()),
    };
    client.vless.encryption = query.remove("encryption");
    client.security = security(&mut query, false)?;
    client.transport = transport(&mut query)?;
    remaining(query.keys(), "链接参数")?;
    Ok(client)
}

pub fn trojan(url: &Url) -> Result<crate::trojan::Client> {
    let mut query = url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<BTreeMap<_, _>>();
    let client = crate::trojan::Client {
        name: percent_decode_str(url.fragment().unwrap_or_default())
            .decode_utf8()?
            .into_owned(),
        server: host(url)?,
        port: url.port().unwrap_or(443),
        password: credentials(url)?,
        security: security(&mut query, true)?,
        transport: transport(&mut query)?,
        ..crate::trojan::Client::default()
    };
    remaining(query.keys(), "链接参数")?;
    Ok(client)
}

pub fn anytls(url: &Url) -> Result<crate::anytls::Client> {
    if !url.path().is_empty() && url.path() != "/" {
        return Err("AnyTLS 链接中包含路径".into());
    }
    let mut query: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
    let client = crate::anytls::Client {
        name: percent_decode_str(url.fragment().unwrap_or_default())
            .decode_utf8()?
            .into_owned(),
        server: host(url)?,
        port: url.port().unwrap_or(443),
        password: credentials(url)?,
        security: security(&mut query, true)?,
        anytls: crate::anytls::ClientOptions {
            idle_session_check_interval: query.remove("idle_session_check_interval"),
            idle_session_timeout: query.remove("idle_session_timeout"),
            min_idle_session: query
                .remove("min_idle_session")
                .map(|v| v.parse())
                .transpose()?,
            ..Default::default()
        },
        ..crate::anytls::Client::default()
    };
    remaining(query.keys(), "链接参数")?;
    Ok(client)
}

pub fn hysteria(text: &str) -> Result<crate::hysteria::Client> {
    use crate::hysteria::{Obfs, ObfsKind};

    let source = text.split_once("://").ok_or("链接缺少协议")?.1;
    let end = source.find(['/', '?', '#']).unwrap_or(source.len());
    let (authority, suffix) = source.split_at(end);
    let (auth, endpoint) = authority.rsplit_once('@').unwrap_or(("", authority));
    let (address, ports) = if endpoint.starts_with('[') {
        let end = endpoint.find(']').ok_or("IPv6 地址缺少右括号")? + 1;
        let (address, ports) = endpoint.split_at(end);
        (
            address,
            if ports.is_empty() {
                "443"
            } else {
                ports.strip_prefix(':').ok_or("连接端口格式不正确")?
            },
        )
    } else {
        endpoint.rsplit_once(':').unwrap_or((endpoint, "443"))
    };
    let port = *crate::connection::ports(ports)?.first().unwrap();
    let auth = if auth.is_empty() {
        String::new()
    } else {
        format!("{auth}@")
    };
    let url = Url::parse(&format!("hysteria2://{auth}{address}:{port}{suffix}"))?;
    if !url.path().is_empty() && url.path() != "/" {
        return Err("Hysteria 2 链接中包含路径".into());
    }
    let mut query: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
    let pin = query.remove("pinSHA256");
    let Security::Tls(mut tls) = security(&mut query, true)? else {
        return Err("Hysteria 2 连接使用 TLS".into());
    };
    if let Some(pin) = pin {
        if tls.certificate_sha256.is_empty() {
            tls.certificate_sha256.push(pin);
        } else if !crate::native::hex_hashes(&tls.certificate_sha256)?
            .contains(&crate::native::hex_hashes(&[pin])?[0])
        {
            return Err("链接中的证书指纹参数相互冲突".into());
        }
    }
    let mut hysteria = crate::hysteria::ClientOptions {
        ports: query.remove("mport").unwrap_or_default().replace(':', "-"),
        hop_interval: query.remove("hop_interval"),
        hop_interval_max: query.remove("hop_interval_max"),
        ..Default::default()
    };
    if ports.contains([',', '-']) {
        merge_ports(&mut hysteria.ports, ports)?;
    }
    let size = |query: &mut BTreeMap<String, String>, key, alias| -> Result<Option<u16>> {
        let a = query.remove(key).map(|s| s.parse()).transpose()?;
        let b = query.remove(alias).map(|s| s.parse()).transpose()?;
        if a.is_some() && b.is_some() && a != b {
            return Err(format!("Gecko 链接中的 {key} 与 {alias} 不一致").into());
        }
        Ok(a.or(b))
    };
    let min = size(&mut query, "minPacketSize", "min_packet_size")?;
    let max = size(&mut query, "maxPacketSize", "max_packet_size")?;
    let password = query.remove("obfs-password").unwrap_or_default();
    let kind = match query.remove("obfs").as_deref() {
        Some("none" | "plain") => None,
        None | Some("") if min.is_some() || max.is_some() => Some(ObfsKind::Gecko),
        None | Some("") => (!password.is_empty()).then_some(ObfsKind::Salamander),
        Some(kind) => Some(serde_json::from_value(json!(kind))?),
    };
    if (min.is_some() || max.is_some()) && kind != Some(ObfsKind::Gecko) {
        return Err("数据包大小需要使用 Gecko 混淆".into());
    }
    hysteria.obfs = kind.map(|kind| Obfs {
        kind,
        password,
        min_packet_size: min,
        max_packet_size: max,
    });
    if let Some(mask) = query.remove("fm") {
        hysteria_mask(&mut hysteria, serde_json::from_str(&mask)?)?;
    }
    for (key, bandwidth) in [
        ("up", &mut hysteria.quic.upload_bandwidth),
        ("down", &mut hysteria.quic.download_bandwidth),
    ] {
        if let Some(value) = query.remove(key) {
            bandwidth.get_or_insert(value);
        }
    }
    remaining(query.keys(), "链接参数")?;
    Ok(crate::hysteria::Client {
        name: percent_decode_str(url.fragment().unwrap_or_default())
            .decode_utf8()?
            .into_owned(),
        server: host(&url)?,
        port,
        password: credentials(&url)?,
        tls,
        hysteria,
        ..crate::hysteria::Client::default()
    })
}

fn merge_ports(current: &mut String, ports: &str) -> Result<()> {
    if current.is_empty() {
        *current = ports.to_owned();
    } else if current != ports
        && crate::connection::ports(current)? != crate::connection::ports(ports)?
    {
        return Err("链接中的跳跃端口不一致".into());
    }
    Ok(())
}

fn hysteria_mask(
    options: &mut crate::hysteria::ClientOptions,
    mut mask: Map<String, Value>,
) -> Result<()> {
    use crate::hysteria::{Obfs, ObfsKind};

    if let Some(params) = mask.remove("quicParams") {
        options.quic = quic(serde_json::from_value(params)?)?;
    }
    if let Some(udp) = mask.remove("udp") {
        let mut have_obfs = false;
        let mut have_hop = false;
        for mut item in serde_json::from_value::<Vec<Map<String, Value>>>(udp)? {
            let mut settings: Map<String, Value> =
                serde_json::from_value(item.remove("settings").unwrap_or(json!({})))?;
            match item.remove("type").as_ref().and_then(Value::as_str) {
                Some("salamander") if !have_obfs => {
                    have_obfs = true;
                    let mut obfs = Obfs {
                        password: serde_json::from_value(
                            settings.remove("password").ok_or("混淆参数缺少密码")?,
                        )?,
                        ..Default::default()
                    };
                    if let Some(size) = settings.remove("packetSize") {
                        let size = range(size, "")?;
                        let (min, max) = size.split_once('-').unwrap_or((&size, &size));
                        let (min, max) = (min.parse::<u16>()?, max.parse::<u16>()?);
                        if max > 0 {
                            if min == 0 {
                                return Err("Gecko FinalMask 的最小数据包大小必须大于零".into());
                            }
                            obfs.kind = ObfsKind::Gecko;
                            obfs.min_packet_size = Some(min);
                            obfs.max_packet_size = Some(max);
                        }
                    }
                    if let Some(fields) = &options.obfs {
                        let (min, max) = fields.packet_sizes();
                        let sizes = obfs.packet_sizes();
                        if fields.kind != obfs.kind
                            || !fields.password.is_empty() && fields.password != obfs.password
                            || fields.min_packet_size.is_some() && min != sizes.0
                            || fields.max_packet_size.is_some() && max != sizes.1
                        {
                            return Err("链接与 FinalMask 中的 Hysteria 2 混淆参数不一致".into());
                        }
                    }
                    options.obfs = Some(obfs);
                }
                Some("udphop")
                    if !have_hop
                        && settings
                            .remove("mode")
                            .as_ref()
                            .and_then(Value::as_str)
                            .is_some_and(|mode| mode.eq_ignore_ascii_case("intervalRemote")) =>
                {
                    have_hop = true;
                    let ports: String = serde_json::from_value(
                        settings.remove("remotePorts").ok_or("跳跃端口不能为空")?,
                    )?;
                    merge_ports(&mut options.ports, &ports)?;
                    if let Some(value) = settings.remove("interval") {
                        let seconds = range(value, "")?;
                        let (min, max) = seconds.split_once('-').unwrap_or((&seconds, &seconds));
                        let (min, max) = (min.parse::<u32>()?, max.parse::<u32>()?);
                        options
                            .hop_interval
                            .get_or_insert_with(|| format!("{min}s"));
                        if min != max {
                            options
                                .hop_interval_max
                                .get_or_insert_with(|| format!("{max}s"));
                        }
                    }
                }
                _ => return Err("此 FinalMask 无法转换为 Hysteria 2 连接".into()),
            }
            remaining(settings.keys(), "Hysteria 2 FinalMask")?;
            remaining(item.keys(), "Hysteria 2 FinalMask")?;
        }
    }
    remaining(mask.keys(), "Hysteria 2 FinalMask")
}

pub fn shadowsocks(text: &str) -> Result<crate::shadowsocks::Client> {
    let source = text.split_once("://").ok_or("链接缺少协议")?.1;
    let (source, tag) = source.split_once('#').unwrap_or((source, ""));
    let (source, query) = source.split_once('?').unwrap_or((source, ""));
    let (url, credentials) = if source.contains('@') {
        let url = Url::parse(&format!("ss://{source}"))?;
        let username = percent_decode_str(url.username())
            .decode_utf8()?
            .into_owned();
        let credentials = if let Some(password) = url.password() {
            format!("{username}:{}", percent_decode_str(password).decode_utf8()?)
        } else if username.contains(':') {
            username
        } else {
            String::from_utf8(decode(&username)?)?
        };
        (url, credentials)
    } else {
        let decoded = String::from_utf8(decode(source.trim_end_matches('/'))?)?;
        let (credentials, address) = decoded
            .rsplit_once('@')
            .ok_or("Shadowsocks 链接缺少服务器地址")?;
        (
            Url::parse(&format!("ss://{address}"))?,
            credentials.to_owned(),
        )
    };
    if !url.path().is_empty() && url.path() != "/" {
        return Err("Shadowsocks 链接中包含路径".into());
    }
    let (cipher, password) = credentials
        .split_once(':')
        .ok_or("Shadowsocks 链接缺少算法或密码")?;
    let cipher = cipher.to_ascii_lowercase();
    let cipher = cipher
        .strip_prefix("aead_")
        .unwrap_or(&cipher)
        .replace('_', "-");
    let mut query: BTreeMap<_, _> = url::form_urlencoded::parse(query.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    let plugin = query.remove("plugin").map(|value| {
        let (name, options) = value.split_once(';').unwrap_or((&value, ""));
        crate::shadowsocks::Plugin {
            name: if name == "simple-obfs" {
                "obfs-local"
            } else {
                name
            }
            .to_owned(),
            options: options.to_owned(),
        }
    });
    let client = crate::shadowsocks::Client {
        name: percent_decode_str(tag).decode_utf8()?.into_owned(),
        server: host(&url)?,
        port: url.port().ok_or("Shadowsocks 链接缺少端口")?,
        password: password.to_owned(),
        shadowsocks: crate::shadowsocks::ClientOptions {
            cipher: serde_json::from_value(json!(cipher))?,
            udp_over_tcp: uot(&mut query)?,
            plugin,
            ..crate::shadowsocks::ClientOptions::default()
        },
        security: security(&mut query, false)?,
        transport: transport(&mut query)?,
        ..crate::shadowsocks::Client::default()
    };
    remaining(query.keys(), "链接参数")?;
    Ok(client)
}

pub fn uot(query: &mut BTreeMap<String, String>) -> Result<Option<u8>> {
    let legacy = query.remove("udp-over-tcp");
    let enabled = query.remove("uot");
    match (enabled.as_deref(), legacy.as_deref()) {
        (None | Some("false" | "0"), None | Some("false" | "0")) => Ok(None),
        (None, Some("true")) => Ok(Some(1)),
        (Some("true"), None) => Ok(Some(2)),
        (Some("1"), _) => Err(
            "uot=1 只表示启用；Mihomo 默认使用 v1，Throne 默认使用 v2。请在连接参数中指定版本"
                .into(),
        ),
        _ => Err("无法确定链接中的 UDP over TCP 版本".into()),
    }
}

fn credentials(url: &Url) -> Result<String> {
    let mut value = percent_decode_str(url.username())
        .decode_utf8()?
        .into_owned();
    if let Some(password) = url.password() {
        value.push(':');
        value.push_str(&percent_decode_str(password).decode_utf8()?);
    }
    Ok(value)
}

pub fn host(url: &Url) -> Result<String> {
    Ok(
        match Host::parse(url.host_str().ok_or("链接缺少服务器地址")?)? {
            Host::Domain(value) => value,
            Host::Ipv4(value) => value.to_string(),
            Host::Ipv6(value) => value.to_string(),
        },
    )
}

pub fn security(query: &mut BTreeMap<String, String>, default: bool) -> Result<Security> {
    let security = query
        .remove("security")
        .unwrap_or_else(|| if default { "tls" } else { "none" }.to_owned());
    if !matches!(security.as_str(), "none" | "" | "tls" | "reality") {
        return Err(format!("无法识别握手类型：{security}").into());
    }
    let mut tls = Tls {
        server_name: query.remove("sni"),
        fingerprint: query.remove("fp"),
        min_version: query.remove("tls_min_version"),
        max_version: query.remove("tls_max_version"),
        client_certificate: query.remove("tls_client_certificate"),
        client_key: query.remove("tls_client_key"),
        fragment_delay: query.remove("tls_fragment_fallback_delay"),
        ..Tls::default()
    };
    for (key, separator, target) in [
        ("alpn", ',', &mut tls.alpn),
        ("vcn", ',', &mut tls.verify_names),
        ("pcs", ',', &mut tls.certificate_sha256),
        ("cs", ':', &mut tls.cipher_suites),
        ("tls_curve_preferences", ',', &mut tls.curves),
        ("tls_certificate", ',', &mut tls.certificates),
        (
            "tls_certificate_public_key_sha256",
            ',',
            &mut tls.public_key_sha256,
        ),
    ] {
        if let Some(value) = query.remove(key) {
            *target = value
                .split(separator)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
        }
    }
    for (key, target) in [
        ("tls_fragment", &mut tls.fragment),
        ("tls_record_fragment", &mut tls.record_fragment),
    ] {
        if let Some(value) = query.remove(key) {
            *target = Some(value.parse()?);
        }
    }
    if let Some(value) = query.remove("disable_sni") {
        tls.send_sni = Some(!value.parse::<bool>()?);
    }
    for key in ["allowInsecure", "insecure"] {
        if let Some(value) = query.remove(key) {
            let verify = match value.as_str() {
                "1" | "true" => false,
                "0" | "false" => true,
                _ => return Err(format!("{key} 需要使用布尔值").into()),
            };
            if tls.verify_certificate.is_some_and(|value| value != verify) {
                return Err("链接中的证书验证参数相互冲突".into());
            }
            tls.verify_certificate = Some(verify);
        }
    }
    if let Some(value) = query.remove("ech") {
        tls.ech = Some(Ech {
            config: Some(value),
            ..Ech::default()
        });
    }
    let reality = crate::reality::Client {
        public_key: query.remove("pbk").unwrap_or_default(),
        short_id: query.remove("sid").unwrap_or_default(),
        spider_path: query.remove("spx"),
        signature_key: query.remove("pqv"),
        ..crate::reality::Client::default()
    };
    Ok(match security.as_str() {
        "tls" => Security::Tls(tls),
        "reality" => Security::Reality(Box::new(crate::reality::Client { tls, ..reality })),
        _ => Security::None,
    })
}

pub fn transport(query: &mut BTreeMap<String, String>) -> Result<Transport> {
    let mask = query
        .remove("fm")
        .map(|value| serde_json::from_str::<Map<String, Value>>(&value))
        .transpose()?;
    let kind = query.remove("type").unwrap_or_else(|| "tcp".to_owned());
    let value: Result<Transport> = match kind.as_str() {
        "tcp" | "raw" => {
            if query.get("headerType").is_some_and(|value| value == "http") {
                query.remove("headerType");
                Ok(Transport::Http(Http {
                    version: HttpVersion::Http1,
                    host: query.remove("host").map_or_else(Vec::new, |value| {
                        value.split(',').map(str::to_owned).collect()
                    }),
                    path: query.remove("path"),
                    ..Http::default()
                }))
            } else {
                if query
                    .get("headerType")
                    .is_none_or(|value| value == "none" || value.is_empty())
                {
                    query.remove("headerType");
                    query.remove("host");
                    query.remove("path");
                }
                Ok(Transport::Default)
            }
        }
        "http" | "h2" => Ok(Transport::Http(Http {
            version: HttpVersion::Http2,
            host: query.remove("host").map_or_else(Vec::new, |value| {
                value.split(',').map(str::to_owned).collect()
            }),
            path: query.remove("path"),
            ..Http::default()
        })),
        "kcp" | "mkcp" => {
            let header = match query.remove("headerType").as_deref() {
                None | Some("" | "none") => Header::None,
                Some("wechat") => Header::WechatVideo,
                Some(value) => serde_json::from_value(json!(value))?,
            };
            Ok(Transport::Kcp(Kcp {
                mtu: query.remove("mtu").map(|value| value.parse()).transpose()?,
                interval: query
                    .remove("tti")
                    .map(|value| value.parse::<u32>().map(|value| format!("{value}ms")))
                    .transpose()?,
                seed: query.remove("seed"),
                domain: query.remove("host"),
                header,
                ..Kcp::default()
            }))
        }
        "quic" => {
            for key in ["headerType", "quicSecurity", "key"] {
                if query
                    .get(key)
                    .is_some_and(|value| value.is_empty() || value == "none")
                {
                    query.remove(key);
                }
            }
            Ok(Transport::Quic)
        }
        "ws" => {
            let mut value = WebSocket {
                host: query.remove("host"),
                path: query.remove("path"),
                early_data_header: query.remove("early_data_header_name"),
                ..WebSocket::default()
            };
            value.early_data = early_data(&mut value.path)?;
            Ok(Transport::WebSocket(value))
        }
        "httpupgrade" => {
            let mut value = HttpUpgrade {
                host: query.remove("host"),
                path: query.remove("path"),
                ..HttpUpgrade::default()
            };
            value.early_data = early_data(&mut value.path)?.map(|value| value != 0);
            Ok(Transport::HttpUpgrade(value))
        }
        "grpc" => {
            let multi_mode = match query.remove("mode").as_deref() {
                None | Some("" | "gun") => false,
                Some("multi") => true,
                Some(value) => return Err(format!("无法识别 gRPC 模式：{value}").into()),
            };
            Ok(Transport::Grpc(Grpc {
                service_name: query.remove("serviceName"),
                authority: query.remove("authority"),
                multi_mode,
                ..Grpc::default()
            }))
        }
        "xhttp" => {
            let mut value = XHttp::default();
            if let Some(extra) = query.remove("extra") {
                value = xhttp(serde_json::from_str(&extra)?)?;
            }
            if let Some(host) = query.remove("host") {
                value.http.host = Some(host);
            }
            if let Some(path) = query.remove("path") {
                value.http.path = Some(path);
            }
            if let Some(mode) = query.remove("mode")
                && !mode.is_empty()
            {
                value.http.mode = serde_json::from_value(json!(mode))?;
            }
            Ok(Transport::XHttp(Box::new(value)))
        }
        _ => Err(format!("无法识别传输类型：{kind}").into()),
    };
    let mut value = value?;
    if let Some(mask) = mask {
        finalmask(&mut value, mask)?;
    }
    Ok(value)
}

fn early_data(path: &mut Option<String>) -> Result<Option<u32>> {
    let Some(value) = path.as_deref() else {
        return Ok(None);
    };
    let (value, fragment) = value
        .split_once('#')
        .map_or((value, None), |(value, fragment)| (value, Some(fragment)));
    let Some((prefix, query)) = value.split_once('?') else {
        return Ok(None);
    };
    let pairs: Vec<_> = url::form_urlencoded::parse(query.as_bytes()).collect();
    let Some((_, size)) = pairs.iter().find(|(key, _)| key == "ed") else {
        return Ok(None);
    };
    let size = size.parse()?;
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(
            pairs
                .iter()
                .filter(|(key, _)| key != "ed")
                .map(|(key, value)| (key.as_ref(), value.as_ref())),
        )
        .finish();
    let mut value = if query.is_empty() {
        prefix.to_owned()
    } else {
        format!("{prefix}?{query}")
    };
    if let Some(fragment) = fragment {
        value.push('#');
        value.push_str(fragment);
    }
    *path = Some(value);
    Ok(Some(size))
}

fn finalmask(transport: &mut Transport, mut values: Map<String, Value>) -> Result<()> {
    if let Transport::XHttp(value) = transport
        && let Some(params) = values.remove("quicParams")
    {
        value.quic = quic(serde_json::from_value(params)?)?;
    }
    if let Transport::Kcp(value) = transport
        && let Some(masks) = values.remove("udp")
    {
        value.checksum = false;
        value.seed = None;
        value.header = Header::None;
        value.domain = None;
        for mut mask in serde_json::from_value::<Vec<Map<String, Value>>>(masks)? {
            if mask.remove("type").as_ref() != Some(&json!("mkcp-legacy")) {
                return Err("当前 KCP 参数无法表达此 Finalmask".into());
            }
            let mut settings: Map<String, Value> = mask
                .remove("settings")
                .map(serde_json::from_value)
                .transpose()?
                .unwrap_or_default();
            if let Some(header) = settings.remove("header") {
                if value.header != Header::None {
                    return Err("当前 KCP 参数使用单个数据包头".into());
                }
                value.header = if header == "wechat" {
                    Header::WechatVideo
                } else {
                    serde_json::from_value(header)?
                };
                value.domain = settings
                    .remove("value")
                    .map(serde_json::from_value)
                    .transpose()?;
            } else if let Some(seed) = settings.remove("value") {
                if value.seed.is_some() {
                    return Err("当前 KCP 参数使用单个种子".into());
                }
                value.seed = Some(serde_json::from_value(seed)?);
            } else {
                if value.checksum {
                    return Err("当前 KCP 参数使用单个校验层".into());
                }
                value.checksum = true;
            }
            remaining(mask.keys(), "Finalmask")?;
            remaining(settings.keys(), "KCP Finalmask")?;
        }
    }
    remaining(values.keys(), "Finalmask")
}

fn quic(mut values: Map<String, Value>) -> Result<Quic> {
    let mut output = Map::new();
    rename(
        &mut values,
        &mut output,
        &[
            ("congestion", "congestion"),
            ("debug", "debug"),
            ("bbrProfile", "bbr_profile"),
            ("brutalUp", "upload_bandwidth"),
            ("brutalDown", "download_bandwidth"),
            ("initStreamReceiveWindow", "initial_stream_window"),
            ("maxStreamReceiveWindow", "max_stream_window"),
            ("initConnectionReceiveWindow", "initial_connection_window"),
            ("maxConnectionReceiveWindow", "max_connection_window"),
            ("maxIncomingStreams", "incoming_streams"),
        ],
    );
    for (native, source) in [
        ("brutalDisableLossCompensation", "loss_compensation"),
        ("disablePathMTUDiscovery", "path_mtu_discovery"),
        ("disableGSO", "gso"),
        ("disableChromeParrot", "chrome_fingerprint"),
        ("disableStatelessReset", "stateless_reset"),
    ] {
        if let Some(value) = values.remove(native) {
            output.insert(
                source.to_owned(),
                json!(!serde_json::from_value::<bool>(value)?),
            );
        }
    }
    for (native, source) in [
        ("keepAlivePeriod", "keep_alive"),
        ("maxIdleTimeout", "idle_timeout"),
    ] {
        if let Some(value) = values.remove(native) {
            output.insert(source.to_owned(), json!(range(value, "s")?));
        }
    }
    remaining(values.keys(), "QUIC 参数")?;
    Ok(serde_json::from_value(json!(output))?)
}

fn xhttp(mut extra: Map<String, Value>) -> Result<XHttp> {
    let mut value = XHttp::default();
    if let Some(download) = extra.remove("downloadSettings") {
        let mut stream: Map<String, Value> = serde_json::from_value(download)?;
        let mut download = Download::default();
        if let Some(address) = stream.remove("address") {
            download.server = serde_json::from_value(address)?;
        }
        if let Some(port) = stream.remove("port") {
            download.port = serde_json::from_value(port)?;
        }
        if let Some(network) = stream.remove("network")
            && network != "xhttp"
            && network != "splithttp"
        {
            return Err("XHTTP 下载连接需要使用 XHTTP 传输".into());
        }
        if let Some(settings) = stream.remove("xhttpSettings") {
            download.http = http(serde_json::from_value(settings)?)?;
        }
        let security = stream.remove("security").unwrap_or(json!("none"));
        let settings = if security == "reality" {
            "realitySettings"
        } else {
            "tlsSettings"
        };
        download.security = match stream.remove(settings) {
            Some(settings) => {
                security_options(serde_json::from_value(settings)?, security == "reality")?
            }
            None if security == "tls" => Security::Tls(Tls::default()),
            None if security == "none" => Security::None,
            None => return Err(format!("XHTTP 下载连接缺少 {security} 参数").into()),
        };
        if let Some(mask) = stream.remove("finalmask") {
            let mut mask: Map<String, Value> = serde_json::from_value(mask)?;
            if let Some(params) = mask.remove("quicParams") {
                download.quic = quic(serde_json::from_value(params)?)?;
            }
            remaining(mask.keys(), "XHTTP 下载 Finalmask")?;
        }
        if security != "tls" && security != "reality" && security != "none" {
            return Err("无法识别 XHTTP 下载握手类型".into());
        }
        remaining(stream.keys(), "XHTTP 下载连接")?;
        value.download = Some(download);
    }
    value.http = http(extra)?;
    Ok(value)
}

fn security_options(mut values: Map<String, Value>, reality: bool) -> Result<Security> {
    let mut output = Map::new();
    let mut options = Map::new();
    rename(
        &mut values,
        &mut output,
        &[
            ("serverName", "server_name"),
            ("fingerprint", "fingerprint"),
            ("alpn", "alpn"),
            ("masterKeyLog", "key_log"),
            ("minVersion", "min_version"),
            ("maxVersion", "max_version"),
            ("curvePreferences", "curves"),
            ("enableSessionResumption", "session_resumption"),
        ],
    );
    if reality {
        rename(
            &mut values,
            &mut options,
            &[
                ("publicKey", "public_key"),
                ("password", "public_key"),
                ("shortId", "short_id"),
                ("spiderX", "spider_path"),
                ("mldsa65Verify", "signature_key"),
                ("show", "debug"),
            ],
        );
    } else {
        if let Some(insecure) = values.remove("allowInsecure") {
            output.insert(
                "verify_certificate".to_owned(),
                json!(!serde_json::from_value::<bool>(insecure)?),
            );
        }
        for (native, source, separator) in [
            ("cipherSuites", "cipher_suites", ':'),
            ("verifyPeerCertByName", "verify_names", ','),
            ("pinnedPeerCertSha256", "certificate_sha256", ','),
        ] {
            if let Some(value) = values.remove(native) {
                let value: String = serde_json::from_value(value)?;
                output.insert(
                    source.to_owned(),
                    json!(
                        value
                            .split(separator)
                            .map(str::to_owned)
                            .collect::<Vec<_>>()
                    ),
                );
            }
        }
        if let Some(value) = values.remove("disableSystemRoot") {
            output.insert(
                "system_roots".to_owned(),
                json!(!serde_json::from_value::<bool>(value)?),
            );
        }
        if let Some(value) = values.remove("useSystemCA") {
            output.insert("system_roots".to_owned(), value);
        }
        if let Some(value) = values.remove("echConfigList") {
            output.insert("ech".to_owned(), json!({"config": value}));
        }
        if let Some(certificates) = values.remove("certificates") {
            let mut trust = Vec::new();
            for mut certificate in serde_json::from_value::<Vec<Map<String, Value>>>(certificates)?
            {
                let usage = certificate.remove("usage");
                let text = certificate
                    .remove("certificate")
                    .map(serde_json::from_value::<Vec<String>>)
                    .transpose()?
                    .unwrap_or_default();
                if usage.as_ref() == Some(&json!("verify")) {
                    trust.extend(text);
                } else if usage.is_none() || usage.as_ref() == Some(&json!("encipherment")) {
                    if output.contains_key("client_certificate") {
                        return Err("XHTTP 下载连接使用一组客户端证书".into());
                    }
                    if !text.is_empty() {
                        output.insert("client_certificate".to_owned(), json!(text.join("\n")));
                    }
                    if let Some(key) = certificate.remove("key") {
                        output.insert(
                            "client_key".to_owned(),
                            json!(serde_json::from_value::<Vec<String>>(key)?.join("\n")),
                        );
                    }
                } else {
                    return Err("无法识别 XHTTP 下载证书用途".into());
                }
                remaining(certificate.keys(), "XHTTP 下载证书")?;
            }
            if !trust.is_empty() {
                output.insert("certificates".to_owned(), json!(trust));
            }
        }
    }
    remaining(values.keys(), "XHTTP 下载握手")?;
    let tls = serde_json::from_value(json!(output))?;
    Ok(if reality {
        options.insert("tls".to_owned(), json!(tls));
        Security::Reality(Box::new(serde_json::from_value(json!(options))?))
    } else {
        Security::Tls(tls)
    })
}

fn http(mut values: Map<String, Value>) -> Result<XHttpOptions> {
    let mut output = Map::new();
    rename(
        &mut values,
        &mut output,
        &[
            ("host", "host"),
            ("path", "path"),
            ("mode", "mode"),
            ("xPaddingObfsMode", "padding_obfuscation"),
            ("xPaddingKey", "padding_key"),
            ("xPaddingHeader", "padding_header"),
            ("xPaddingMethod", "padding_method"),
            ("uplinkHTTPMethod", "upload_method"),
            ("sessionIDPlacement", "session_placement"),
            ("sessionIDKey", "session_key"),
            ("sessionIDTable", "session_alphabet"),
            ("seqPlacement", "sequence_placement"),
            ("seqKey", "sequence_key"),
            ("uplinkDataPlacement", "data_placement"),
            ("uplinkDataKey", "data_key"),
            ("scMaxBufferedPosts", "buffered_uploads"),
            ("serverMaxHeaderBytes", "header_limit"),
        ],
    );
    if let Some(headers) = values.remove("headers") {
        let headers: BTreeMap<String, String> = serde_json::from_value(headers)?;
        output.insert(
            "headers".to_owned(),
            json!(
                headers
                    .into_iter()
                    .map(|(key, value)| (key, vec![value]))
                    .collect::<BTreeMap<_, _>>()
            ),
        );
    }
    if let Some(placement) = values.remove("xPaddingPlacement") {
        output.insert(
            "padding_placement".to_owned(),
            if placement == "queryInHeader" {
                json!("query-in-header")
            } else {
                placement
            },
        );
    }
    for (native, source) in [
        ("noGRPCHeader", "grpc_header"),
        ("noSSEHeader", "sse_header"),
    ] {
        if let Some(value) = values.remove(native) {
            output.insert(
                source.to_owned(),
                json!(!serde_json::from_value::<bool>(value)?),
            );
        }
    }
    for (native, source, unit) in [
        ("xPaddingBytes", "padding_size", ""),
        ("sessionIDLength", "session_length", ""),
        ("uplinkChunkSize", "chunk_size", ""),
        ("scMaxEachPostBytes", "upload_size", ""),
        ("scMinPostsIntervalMs", "upload_interval", "ms"),
        ("scStreamUpServerSecs", "stream_keep_alive", "s"),
    ] {
        if let Some(value) = values.remove(native) {
            output.insert(source.to_owned(), json!(range(value, unit)?));
        }
    }
    if let Some(pool) = values.remove("xmux") {
        output.insert(
            "pool".to_owned(),
            json!(pool_options(serde_json::from_value(pool)?)?),
        );
    }
    remaining(values.keys(), "XHTTP 参数")?;
    Ok(serde_json::from_value(json!(output))?)
}

fn pool_options(mut values: Map<String, Value>) -> Result<Pool> {
    let mut output = Map::new();
    for (native, source, unit) in [
        ("maxConcurrency", "concurrency", ""),
        ("maxConnections", "connections", ""),
        ("cMaxReuseTimes", "reuse_limit", ""),
        ("hMaxRequestTimes", "request_limit", ""),
        ("hMaxReusableSecs", "lifetime", "s"),
        ("hKeepAlivePeriod", "keep_alive", "s"),
    ] {
        if let Some(value) = values.remove(native) {
            output.insert(source.to_owned(), json!(range(value, unit)?));
        }
    }
    remaining(values.keys(), "XHTTP 连接复用")?;
    Ok(serde_json::from_value(json!(output))?)
}

fn range(value: Value, unit: &str) -> Result<String> {
    let text = match value {
        Value::String(value) => value,
        Value::Number(value) => value.to_string(),
        _ => return Err("整数区间需要使用数字或区间字符串".into()),
    };
    if unit.is_empty() {
        return Ok(text);
    }
    match text
        .char_indices()
        .skip(1)
        .find(|(_, character)| *character == '-')
    {
        Some((index, _)) => Ok(format!(
            "{}{unit}-{}{unit}",
            &text[..index],
            &text[index + 1..]
        )),
        None => Ok(format!("{text}{unit}")),
    }
}

fn rename(
    source: &mut Map<String, Value>,
    output: &mut Map<String, Value>,
    names: &[(&str, &str)],
) {
    for &(name, destination) in names {
        if let Some(value) = source.remove(name) {
            output.insert(destination.to_owned(), value);
        }
    }
}

pub fn remaining<'a>(keys: impl Iterator<Item = &'a String>, context: &str) -> Result<()> {
    let fields: Vec<_> = keys.map(String::as_str).collect();
    if fields.is_empty() {
        Ok(())
    } else {
        Err(format!("{context} 包含无法转换的字段：{}", fields.join("、")).into())
    }
}
