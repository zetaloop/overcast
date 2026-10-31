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
    connection::{HttpVersion, Tls},
    transport::{
        Download, Grpc, Header, Http, HttpUpgrade, Kcp, Pool, Transport, WebSocket, XHttp,
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
    client.tls = tls(&mut query, false)?;
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
    client.tls = tls(&mut query, false)?;
    client.transport = transport(&mut query)?;
    remaining(query.keys(), "链接参数")?;
    Ok(client)
}

pub fn trojan(url: &Url) -> Result<crate::trojan::Client> {
    let mut query = url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<BTreeMap<_, _>>();
    let mut password = percent_decode_str(url.username())
        .decode_utf8()?
        .into_owned();
    if let Some(value) = url.password() {
        password.push(':');
        password.push_str(&percent_decode_str(value).decode_utf8()?);
    }
    let client = crate::trojan::Client {
        name: percent_decode_str(url.fragment().unwrap_or_default())
            .decode_utf8()?
            .into_owned(),
        server: host(url)?,
        port: url.port().unwrap_or(443),
        password,
        tls: tls(&mut query, true)?,
        transport: transport(&mut query)?,
        ..crate::trojan::Client::default()
    };
    remaining(query.keys(), "链接参数")?;
    Ok(client)
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

pub fn tls(query: &mut BTreeMap<String, String>, default: bool) -> Result<Tls> {
    let security = query
        .remove("security")
        .unwrap_or_else(|| if default { "tls" } else { "none" }.to_owned());
    if !matches!(security.as_str(), "none" | "" | "tls" | "reality") {
        return Err(format!("无法识别握手类型：{security}").into());
    }
    let mut tls = Tls {
        enabled: matches!(security.as_str(), "tls" | "reality"),
        server_name: query.remove("sni"),
        fingerprint: query.remove("fp"),
        ..Tls::default()
    };
    if let Some(value) = query.remove("alpn") {
        tls.alpn = value
            .split(',')
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect();
    }
    if let Some(value) = query.remove("vcn") {
        tls.verify_names = value.split(',').map(str::to_owned).collect();
    }
    if let Some(value) = query.remove("pcs") {
        tls.certificate_sha256 = value.split(',').map(str::to_owned).collect();
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
        tls.ech.enabled = true;
        tls.ech.config = Some(value);
    }
    tls.reality.enabled = security == "reality";
    tls.reality.public_key = query.remove("pbk").unwrap_or_default();
    tls.reality.short_id = query.remove("sid").unwrap_or_default();
    tls.reality.spider_path = query.remove("spx");
    tls.reality.signature_key = query.remove("pqv");
    Ok(tls)
}

pub fn transport(query: &mut BTreeMap<String, String>) -> Result<Transport> {
    let kind = query.remove("type").unwrap_or_else(|| "tcp".to_owned());
    match kind.as_str() {
        "tcp" | "raw" => {
            if query.get("headerType").is_some_and(|value| value == "http") {
                query.remove("headerType");
                return Ok(Transport::Http(Http {
                    version: HttpVersion::Http1,
                    host: query.remove("host").map_or_else(Vec::new, |value| {
                        value.split(',').map(str::to_owned).collect()
                    }),
                    path: query.remove("path"),
                    ..Http::default()
                }));
            }
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
        "http" | "h2" => Ok(Transport::Http(Http {
            version: if kind == "h2" {
                HttpVersion::Http2
            } else {
                HttpVersion::Auto
            },
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
                ..WebSocket::default()
            };
            if let Some(path) = &value.path
                && let Some((prefix, query)) = path.split_once('?')
            {
                let pairs: Vec<_> = url::form_urlencoded::parse(query.as_bytes()).collect();
                if let Some((_, size)) = pairs.iter().find(|(key, _)| key == "ed") {
                    value.early_data = Some(size.parse()?);
                    let query = url::form_urlencoded::Serializer::new(String::new())
                        .extend_pairs(
                            pairs
                                .iter()
                                .filter(|(key, _)| key != "ed")
                                .map(|(key, value)| (key.as_ref(), value.as_ref())),
                        )
                        .finish();
                    value.path = Some(if query.is_empty() {
                        prefix.to_owned()
                    } else {
                        format!("{prefix}?{query}")
                    });
                }
            }
            Ok(Transport::WebSocket(value))
        }
        "httpupgrade" => Ok(Transport::HttpUpgrade(HttpUpgrade {
            host: query.remove("host"),
            path: query.remove("path"),
            ..HttpUpgrade::default()
        })),
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
    }
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
        if let Some(settings) = stream.remove(settings) {
            download.tls =
                security_options(serde_json::from_value(settings)?, security == "reality")?;
        }
        download.tls.enabled = security == "tls" || security == "reality";
        if security != "tls" && security != "reality" && security != "none" {
            return Err("无法识别 XHTTP 下载握手类型".into());
        }
        remaining(stream.keys(), "XHTTP 下载连接")?;
        value.download = Some(download);
    }
    value.http = http(extra)?;
    Ok(value)
}

fn security_options(mut values: Map<String, Value>, reality: bool) -> Result<Tls> {
    let mut output = Map::from_iter([("enabled".to_owned(), json!(true))]);
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
        ],
    );
    if reality {
        let mut options = Map::from_iter([("enabled".to_owned(), json!(true))]);
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
        output.insert("reality".to_owned(), json!(options));
    } else if let Some(insecure) = values.remove("allowInsecure") {
        output.insert(
            "verify_certificate".to_owned(),
            json!(!serde_json::from_value::<bool>(insecure)?),
        );
    }
    remaining(values.keys(), "XHTTP 下载握手")?;
    Ok(serde_json::from_value(json!(output))?)
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

fn remaining<'a>(keys: impl Iterator<Item = &'a String>, context: &str) -> Result<()> {
    let fields: Vec<_> = keys.map(String::as_str).collect();
    if fields.is_empty() {
        Ok(())
    } else {
        Err(format!("{context} 包含无法转换的字段：{}", fields.join("、")).into())
    }
}
