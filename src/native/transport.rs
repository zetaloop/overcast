use crate::language::{message, text as tr};
use std::{collections::BTreeMap, time::Duration};

use percent_encoding::percent_decode_str;
use serde_json::{Map, Value, json};
use url::form_urlencoded;

use crate::{
    Result,
    connection::{HttpVersion, Network, Security},
    inbound::Core,
    transport::{Mode, PaddingPlacement, Placement, Pool, Quic, Transport, XHttp, XHttpOptions},
};

use super::{options::Options, single_headers, unsupported};

pub(super) fn grpc(core: Core, inbound: bool, options: &mut Options) -> Result<Map<String, Value>> {
    let mut output = Map::new();
    let (service, idle, ping, unit) = match core {
        Core::Xray => (
            "serviceName",
            "idle_timeout",
            "health_check_timeout",
            Some(Duration::from_secs(1)),
        ),
        Core::SingBox => ("service_name", "idle_timeout", "ping_timeout", None),
        Core::Mihomo => (
            "grpc-service-name",
            "ping-interval",
            "",
            Some(Duration::from_secs(1)),
        ),
    };
    options.rename(&mut output, &[("service_name", service)]);
    if core != Core::Mihomo || !inbound {
        options.durations(&mut output, &[("keep_alive", idle)], unit)?;
    }
    if core != Core::Mihomo {
        options.durations(&mut output, &[("ping_timeout", ping)], unit)?;
    }
    if inbound {
        for key in [
            "authority",
            "permit_without_stream",
            "receive_window",
            "user_agent",
            "connections",
            "min_streams",
            "max_streams",
        ] {
            options.take(key);
        }
        if core == Core::Xray {
            options.take("multi_mode");
        }
    } else {
        match core {
            Core::Xray => {
                options.copy(
                    &mut output,
                    &["authority", "permit_without_stream", "user_agent"],
                );
                options.rename(
                    &mut output,
                    &[
                        ("multi_mode", "multiMode"),
                        ("receive_window", "initial_windows_size"),
                    ],
                );
            }
            Core::SingBox => options.copy(&mut output, &["permit_without_stream"]),
            Core::Mihomo => options.rename(
                &mut output,
                &[
                    ("user_agent", "grpc-user-agent"),
                    ("connections", "max-connections"),
                    ("min_streams", "min-streams"),
                    ("max_streams", "max-streams"),
                ],
            ),
        }
    }
    Ok(output)
}

pub fn xray(
    source: &Transport,
    inbound: bool,
    input: super::parameters::Input<'_>,
    tls: bool,
) -> Result<Map<String, Value>> {
    let mut output = Map::new();
    let (network, name, mut options) = match source {
        Transport::Default => return Ok(output),
        Transport::WebSocket(value) => ("websocket", "wsSettings", Options::new(value)?),
        Transport::HttpUpgrade(value) => {
            ("httpupgrade", "httpupgradeSettings", Options::new(value)?)
        }
        Transport::Grpc(value) => ("grpc", "grpcSettings", Options::new(value)?),
        Transport::XHttp(value) => return xhttp(value, inbound, input),
        Transport::Http(value) => ("raw", "rawSettings", Options::new(value)?),
        Transport::Kcp(value) => ("kcp", "kcpSettings", Options::new(value)?),
        Transport::Quic => {
            return unsupported(tr(
                "Xray does not support standalone QUIC transport",
                "Xray 没有独立 QUIC 传输配置",
            ));
        }
    };
    let mut settings = Map::new();
    match source {
        Transport::Default | Transport::XHttp(_) | Transport::Quic => unreachable!(),
        Transport::Http(value) => {
            if value.version(tls) != HttpVersion::Http1 {
                return unsupported(tr(
                    "Xray HTTP camouflage requires HTTP/1",
                    "Xray 的 HTTP 伪装使用 HTTP/1",
                ));
            }
            options.take("version");
            options.take("random_headers");
            if !value.random_headers && value.headers.values().any(|values| values.len() > 1) {
                return unsupported(tr(
                    "Xray HTTP camouflage selects randomly among header values",
                    "Xray HTTP 伪装从多个标头值中随机选择",
                ));
            }
            let mut request = Map::new();
            let mut response = Map::new();
            if let Some(path) = options.take("path") {
                let mut path = if inbound {
                    request_path(path.as_str().unwrap())?.0
                } else {
                    path.as_str().unwrap().split('#').next().unwrap().to_owned()
                };
                if !path.starts_with('/') {
                    path.insert(0, '/');
                }
                request.insert("path".to_owned(), json!([path]));
            }
            options.take("headers");
            if inbound {
                if !value.headers.is_empty() {
                    response.insert("headers".to_owned(), json!(value.headers));
                }
            } else {
                options.copy(&mut request, &["method"]);
                options.take("host");
                let mut headers = value.headers.clone();
                if !value.host.is_empty() {
                    host(&mut headers, value.host.clone());
                }
                if !headers.is_empty() {
                    request.insert("headers".to_owned(), json!(headers));
                }
            }
            settings.insert(
                "header".to_owned(),
                json!({"type": "http", "request": request, "response": response}),
            );
        }
        Transport::Kcp(value) => {
            options.copy(&mut settings, &["mtu"]);
            options.rename(
                &mut settings,
                &[
                    ("upload", "uplinkCapacity"),
                    ("download", "downlinkCapacity"),
                    ("window_multiplier", "cwndMultiplier"),
                    ("write_buffer", "maxSendingWindow"),
                ],
            );
            options.durations(
                &mut settings,
                &[("interval", "tti")],
                Some(Duration::from_millis(1)),
            )?;
            for field in ["checksum", "seed", "header", "domain"] {
                options.take(field);
            }
            let masks = kcp_masks(value)?;
            if !masks.is_empty() {
                output.insert("finalmask".to_owned(), json!({"udp": masks}));
            }
        }
        Transport::WebSocket(value) => {
            options.copy(&mut settings, &["host", "path"]);
            options.take("headers");
            if !inbound && !value.headers.is_empty() {
                settings.insert("headers".to_owned(), json!(single_headers(&value.headers)?));
            }
            if value
                .early_data_header
                .as_deref()
                .is_some_and(|header| !header.eq_ignore_ascii_case("Sec-WebSocket-Protocol"))
            {
                return unsupported(tr(
                    "Xray WebSocket early data uses the Sec-WebSocket-Protocol header",
                    "Xray 的 WebSocket 握手数据使用 Sec-WebSocket-Protocol 请求头",
                ));
            }
            options.take("early_data_header");
            if let Some(size) = options.take("early_data")
                && !inbound
            {
                let path = settings.get("path").and_then(Value::as_str).unwrap_or("/");
                settings.insert(
                    "path".to_owned(),
                    json!(early_data(path, size.as_u64().unwrap() as u32)),
                );
            }
            options.durations(
                &mut settings,
                &[("heartbeat", "heartbeatPeriod")],
                Some(Duration::from_secs(1)),
            )?;
        }
        Transport::HttpUpgrade(value) => {
            options.copy(&mut settings, &["host", "path"]);
            options.take("headers");
            if !inbound && !value.headers.is_empty() {
                settings.insert("headers".to_owned(), json!(single_headers(&value.headers)?));
            }
            if let Some(enabled) = options.take("early_data")
                && !inbound
            {
                let path = settings.get("path").and_then(Value::as_str).unwrap_or("/");
                settings.insert(
                    "path".to_owned(),
                    json!(early_data(path, u32::from(enabled.as_bool().unwrap()))),
                );
            }
        }
        Transport::Grpc(_) => settings = grpc(Core::Xray, inbound, &mut options)?,
    }
    options.finish(tr("Xray transport", "Xray 传输"))?;
    if let Some(Value::String(path)) = settings.get_mut("path") {
        if !path.starts_with('/') {
            path.insert(0, '/');
        }
        if path == "/" {
            settings.remove("path");
        }
    }
    if inbound && let Some(Value::String(host)) = settings.get_mut("host") {
        *host = host
            .chars()
            .map(|character| character.to_lowercase().next().unwrap())
            .collect();
    }
    settings.retain(|_, value| match value {
        Value::String(value) => !value.is_empty(),
        Value::Number(value) if !matches!(source, Transport::Kcp(_)) => value.as_u64() != Some(0),
        Value::Object(value) => !value.is_empty(),
        _ => true,
    });
    output.insert("network".to_owned(), json!(network));
    if !settings.is_empty() {
        output.insert(name.to_owned(), json!(settings));
    }
    Ok(output)
}

pub(crate) fn kcp_masks(value: &crate::transport::Kcp) -> Result<Vec<Value>> {
    use crate::transport::Header;

    let mut masks = Vec::new();
    if value.header != Header::None {
        let header = if value.header == Header::WechatVideo {
            json!("wechat")
        } else {
            serde_json::to_value(value.header)?
        };
        let mut settings = Map::from_iter([("header".to_owned(), header)]);
        if value.header == Header::Dns
            && let Some(domain) = &value.domain
        {
            settings.insert("value".to_owned(), json!(domain));
        }
        masks.push(json!({"type": "mkcp-legacy", "settings": settings}));
    }
    if let Some(seed) = value.seed.as_ref().filter(|seed| !seed.is_empty()) {
        masks.push(json!({"type": "mkcp-legacy", "settings": {"value": seed}}));
    } else if value.checksum {
        masks.push(json!({"type": "mkcp-legacy"}));
    }
    Ok(masks)
}

pub fn singbox(
    source: &Transport,
    inbound: bool,
    tls: bool,
    reality: bool,
) -> Result<Option<Value>> {
    let mut output = Map::new();
    match source {
        Transport::Default => return Ok(None),
        Transport::Http(value) => {
            let version = value.version(tls);
            if version == HttpVersion::Http3 {
                return unsupported(tr(
                    "sing-box HTTP transport requires HTTP/1 or HTTP/2",
                    "sing-box HTTP 传输使用 HTTP/1 或 HTTP/2",
                ));
            }
            if !inbound && (version == HttpVersion::Http2) != tls {
                return unsupported(tr(
                    "sing-box HTTP clients use TLS for HTTP/2 and plaintext for HTTP/1",
                    "sing-box HTTP 客户端通过 TLS 选择 HTTP/2，明文使用 HTTP/1",
                ));
            }
            let mut options = Options::new(value)?;
            options.take("version");
            options.take("random_headers");
            if value.random_headers && value.headers.values().any(|values| values.len() > 1) {
                return unsupported(tr(
                    "sing-box HTTP transport sends all header values",
                    "sing-box HTTP 传输发送全部标头值",
                ));
            }
            options.copy(&mut output, &["host", "path", "method", "headers"]);
            if inbound && let Some(Value::String(path)) = output.get_mut("path") {
                *path = request_path(path)?.0;
            }
            options.durations(
                &mut output,
                &[
                    ("idle_timeout", "idle_timeout"),
                    ("ping_timeout", "ping_timeout"),
                ],
                None,
            )?;
            options.finish(tr("sing-box HTTP transport", "sing-box HTTP 传输"))?;
            output.insert("type".to_owned(), json!("http"));
        }
        Transport::Kcp(_) => {
            return unsupported(tr(
                "sing-box does not support KCP transport",
                "sing-box 没有 KCP 传输配置",
            ));
        }
        Transport::Quic => {
            if !tls || reality {
                return unsupported(tr("QUIC transport requires TLS", "QUIC 传输需要 TLS 握手"));
            }
            output.insert("type".to_owned(), json!("quic"));
        }
        Transport::WebSocket(value) => {
            let mut options = Options::new(value)?;
            output.insert("type".to_owned(), json!("ws"));
            options.copy(&mut output, &["path"]);
            options.rename(&mut output, &[("early_data", "max_early_data")]);
            options.take("early_data_header");
            output.insert(
                "early_data_header_name".to_owned(),
                json!(
                    value
                        .early_data_header
                        .as_deref()
                        .unwrap_or("Sec-WebSocket-Protocol")
                ),
            );
            options.take("headers");
            if !inbound {
                options.take("host");
                let mut headers = value.headers.clone();
                if let Some(host) = &value.host {
                    self::host(&mut headers, vec![host.clone()]);
                }
                if !headers.is_empty() {
                    output.insert("headers".to_owned(), json!(headers));
                }
            } else if let Some(Value::String(path)) = output.get_mut("path") {
                *path = path.split('?').next().unwrap().to_owned();
            }
            options.finish("sing-box WebSocket")?;
        }
        Transport::HttpUpgrade(value) => {
            let mut options = Options::new(value)?;
            output.insert("type".to_owned(), json!("httpupgrade"));
            options.copy(&mut output, &["host", "path"]);
            if inbound {
                options.take("headers");
                options.take("early_data");
            } else {
                options.copy(&mut output, &["headers"]);
                if value.early_data == Some(false) {
                    options.take("early_data");
                }
            }
            options.finish("sing-box HTTPUpgrade")?;
        }
        Transport::Grpc(value) => {
            let mut options = Options::new(value)?;
            output.insert("type".to_owned(), json!("grpc"));
            output.extend(grpc(Core::SingBox, inbound, &mut options)?);
            options.finish("sing-box gRPC")?;
        }
        Transport::XHttp(_) => {
            return unsupported(tr(
                "sing-box does not support XHTTP transport",
                "sing-box 没有 XHTTP 传输配置",
            ));
        }
    }
    Ok(Some(json!(output)))
}

pub fn mihomo_client(
    source: &Transport,
    network: &Network,
    tls: bool,
    input: super::parameters::Input<'_>,
    globals: &mut Map<String, Value>,
) -> Result<Map<String, Value>> {
    let mut output = Map::new();
    match source {
        Transport::Default => {}
        Transport::Http(value) => {
            let mut options = Options::new(value)?;
            options.take("version");
            options.take("random_headers");
            let mut settings = Map::new();
            let path = if let Some(path) = options.take("path") {
                let (path, query) = request_path(path.as_str().unwrap())?;
                if !query.is_empty() {
                    return unsupported(tr(
                        "Mihomo HTTP transport paths do not support query parameters",
                        "Mihomo HTTP 传输路径没有查询参数配置",
                    ));
                }
                Some(path)
            } else {
                None
            };
            match value.version(tls) {
                HttpVersion::Http1 => {
                    if !value.random_headers
                        && value.headers.values().any(|values| values.len() > 1)
                    {
                        return unsupported(tr(
                            "Mihomo HTTP camouflage selects randomly among header values",
                            "Mihomo HTTP 伪装从多个标头值中随机选择",
                        ));
                    }
                    options.copy(&mut settings, &["method"]);
                    if let Some(path) = path {
                        settings.insert("path".to_owned(), json!([path]));
                    }
                    options.take("headers");
                    options.take("host");
                    let mut headers = value.headers.clone();
                    if !value.host.is_empty() {
                        host(&mut headers, value.host.clone());
                    }
                    if !headers.is_empty() {
                        settings.insert("headers".to_owned(), json!(headers));
                    }
                    output.insert("network".to_owned(), json!("http"));
                    output.insert("http-opts".to_owned(), json!(settings));
                }
                HttpVersion::Http2 => {
                    options.copy(&mut settings, &["host"]);
                    if let Some(path) = path {
                        settings.insert("path".to_owned(), json!(path));
                    }
                    if value.method.as_deref() == Some("PUT") {
                        options.take("method");
                    }
                    output.insert("network".to_owned(), json!("h2"));
                    output.insert("h2-opts".to_owned(), json!(settings));
                }
                _ => {
                    return unsupported(tr(
                        "Mihomo HTTP transport requires HTTP/1 or HTTP/2",
                        "Mihomo HTTP 传输使用 HTTP/1 或 HTTP/2",
                    ));
                }
            }
            options.finish(tr("Mihomo HTTP transport", "Mihomo HTTP 传输"))?;
        }
        Transport::Kcp(value) => {
            output.insert("network".to_owned(), json!("kcp"));
            output.insert("mkcp-opts".to_owned(), json!(mihomo_kcp(value)?));
        }
        Transport::Quic => {
            return unsupported(tr(
                "Mihomo does not support standalone QUIC transport",
                "Mihomo 没有独立 QUIC 传输配置",
            ));
        }
        Transport::WebSocket(value) => {
            let mut options = Options::new(value)?;
            let mut ws = Map::new();
            options.copy(&mut ws, &["path"]);
            options.rename(&mut ws, &[("early_data", "max-early-data")]);
            options.take("early_data_header");
            ws.insert(
                "early-data-header-name".to_owned(),
                json!(
                    value
                        .early_data_header
                        .as_deref()
                        .unwrap_or("Sec-WebSocket-Protocol")
                ),
            );
            options.take("host");
            options.take("headers");
            let mut headers = single_headers(&value.headers)?;
            if let Some(host) = &value.host {
                self::host(&mut headers, host.clone());
            }
            if !headers.is_empty() {
                ws.insert("headers".to_owned(), json!(headers));
            }
            options.finish("Mihomo WebSocket")?;
            output.insert("network".to_owned(), json!("ws"));
            output.insert("ws-opts".to_owned(), json!(ws));
        }
        Transport::HttpUpgrade(value) => {
            let mut options = Options::new(value)?;
            let mut ws = Map::from_iter([("v2ray-http-upgrade".to_owned(), json!(true))]);
            options.copy(&mut ws, &["path"]);
            options.rename(&mut ws, &[("early_data", "v2ray-http-upgrade-fast-open")]);
            options.take("host");
            options.take("headers");
            let mut headers = single_headers(&value.headers)?;
            if let Some(host) = &value.host {
                self::host(&mut headers, host.clone());
            }
            if !headers.is_empty() {
                ws.insert("headers".to_owned(), json!(headers));
            }
            options.finish("Mihomo HTTPUpgrade")?;
            output.insert("network".to_owned(), json!("ws"));
            output.insert("ws-opts".to_owned(), json!(ws));
        }
        Transport::Grpc(value) => {
            let mut options = Options::new(value)?;
            let grpc = grpc(Core::Mihomo, false, &mut options)?;
            options.finish("Mihomo gRPC")?;
            output.insert("network".to_owned(), json!("grpc"));
            output.insert("grpc-opts".to_owned(), json!(grpc));
        }
        Transport::XHttp(value) => {
            Options::new(&value.quic)?.finish("Mihomo XHTTP QUIC")?;
            let mut http = mihomo_http(&value.http, false)?;
            if let Some(download) = &value.download {
                if download
                    .security
                    .reality()
                    .is_some_and(|reality| reality.tls.alpn == ["h3"])
                {
                    return unsupported(tr(
                        "Mihomo XHTTP/3 does not support REALITY",
                        "Mihomo XHTTP/3 不支持 REALITY 握手",
                    ));
                }
                if value.http.mode == Mode::StreamOne {
                    return unsupported(tr(
                        "Single-stream XHTTP cannot use a separate download connection",
                        "XHTTP 单流模式与独立下载连接无法同时使用",
                    ));
                }
                if input.pending.is_none() && (download.server.is_empty() || download.port == 0) {
                    return Err(tr(
                        "Enter a server address and port for XHTTP download",
                        "请填写 XHTTP 下载连接的地址与端口",
                    )
                    .into());
                }
                if serde_json::to_value(&download.network)? != serde_json::to_value(network)? {
                    Options::new(&download.network)?.finish(tr(
                        "Mihomo XHTTP download connection",
                        "Mihomo XHTTP 下载连接",
                    ))?;
                }
                Options::new(&download.quic)?
                    .finish(tr("Mihomo XHTTP download QUIC", "Mihomo XHTTP 下载 QUIC"))?;
                let mut options = Options::new(&download.http)?;
                let mut settings = Map::from_iter([
                    ("server".to_owned(), json!(download.server)),
                    ("port".to_owned(), json!(download.port)),
                    (
                        "tls".to_owned(),
                        json!(!matches!(download.security, Security::None)),
                    ),
                    ("alpn".to_owned(), json!([])),
                    ("servername".to_owned(), json!("")),
                    ("skip-cert-verify".to_owned(), json!(false)),
                    ("name-cert-verify".to_owned(), json!("")),
                    ("fingerprint".to_owned(), json!("")),
                    ("certificate".to_owned(), json!("")),
                    ("private-key".to_owned(), json!("")),
                    ("client-fingerprint".to_owned(), json!("")),
                    ("reality-opts".to_owned(), json!({})),
                    ("ech-opts".to_owned(), json!({})),
                ]);
                options.copy(&mut settings, &["host", "path"]);
                if options.take("headers").is_some() {
                    settings.insert(
                        "headers".to_owned(),
                        json!(single_headers(&download.http.headers)?),
                    );
                }
                options.take("pool");
                let pool = mihomo_pool(&download.http.pool)?;
                if !pool.is_empty() {
                    settings.insert("reuse-settings".to_owned(), json!(pool));
                }
                let parent = serde_json::to_value(&value.http)?;
                let child = serde_json::to_value(&download.http)?;
                for (name, value) in child.as_object().unwrap() {
                    if parent.get(name) == Some(value) {
                        options.take(name);
                    }
                }
                options.finish(tr(
                    "Mihomo XHTTP download settings",
                    "Mihomo XHTTP 下载参数",
                ))?;
                if !matches!(download.security, Security::None) {
                    super::mihomo::client_tls(
                        &download.security,
                        input.download(),
                        &mut settings,
                        globals,
                        "vless",
                    )?;
                }
                http.insert("download-settings".to_owned(), json!(settings));
            }
            output.insert("network".to_owned(), json!("xhttp"));
            output.insert("xhttp-opts".to_owned(), json!(http));
        }
    }
    Ok(output)
}

pub fn mihomo_server(source: &Transport) -> Result<Map<String, Value>> {
    let mut output = Map::new();
    match source {
        Transport::Default => {}
        Transport::Http(_) => {
            return unsupported(tr(
                "Mihomo does not support server-side HTTP transport",
                "Mihomo 没有 HTTP 服务端传输配置",
            ));
        }
        Transport::Kcp(value) => {
            let mut settings = mihomo_kcp(value)?;
            settings.insert("enable".to_owned(), json!(true));
            output.insert("mkcp-config".to_owned(), json!(settings));
        }
        Transport::Quic => {
            return unsupported(tr(
                "Mihomo does not support standalone QUIC transport",
                "Mihomo 没有独立 QUIC 传输配置",
            ));
        }
        Transport::WebSocket(value) => {
            let mut options = Options::new(value)?;
            options.take("path");
            output.insert(
                "ws-path".to_owned(),
                json!(
                    value
                        .path
                        .as_deref()
                        .filter(|path| !path.is_empty())
                        .unwrap_or("/")
                        .split('?')
                        .next()
                        .unwrap()
                ),
            );
            options.take("headers");
            options.take("early_data");
            if value
                .early_data_header
                .as_deref()
                .is_none_or(|header| header.eq_ignore_ascii_case("Sec-WebSocket-Protocol"))
            {
                options.take("early_data_header");
            }
            options.finish(tr("Mihomo WebSocket inbound", "Mihomo WebSocket 入站"))?;
        }
        Transport::HttpUpgrade(_) => {
            return unsupported(tr(
                "Mihomo does not support server-side HTTPUpgrade",
                "Mihomo 没有 HTTPUpgrade 服务端传输配置",
            ));
        }
        Transport::Grpc(value) => {
            let mut options = Options::new(value)?;
            if value.service_name.as_deref().is_none_or(str::is_empty) {
                return unsupported(tr(
                    "Mihomo gRPC inbounds require a nonempty service name",
                    "Mihomo gRPC 入站通过非空服务名启用",
                ));
            }
            output.extend(grpc(Core::Mihomo, true, &mut options)?);
            options.finish(tr("Mihomo gRPC inbound", "Mihomo gRPC 入站"))?;
        }
        Transport::XHttp(value) => {
            Options::new(&value.quic)?
                .finish(tr("Mihomo XHTTP inbound QUIC", "Mihomo XHTTP 入站 QUIC"))?;
            let mut http = mihomo_http(&value.http, true)?;
            http.entry("mode").or_insert(json!("auto"));
            output.insert("xhttp-config".to_owned(), json!(http));
        }
    }
    Ok(output)
}

fn host<T>(headers: &mut BTreeMap<String, T>, value: T) {
    headers.retain(|name, _| !name.eq_ignore_ascii_case("Host"));
    headers.insert("Host".to_owned(), value);
}

fn request_path(value: &str) -> Result<(String, &str)> {
    let value = value.split('#').next().unwrap();
    let (path, query) = value.split_once('?').unwrap_or((value, ""));
    let Ok(path) = percent_decode_str(path).decode_utf8() else {
        return unsupported(tr(
            "Request path is not valid UTF-8",
            "请求路径无法表示为 UTF-8",
        ));
    };
    let mut path = path.into_owned();
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    Ok((path, query))
}

fn mihomo_kcp(source: &crate::transport::Kcp) -> Result<Map<String, Value>> {
    if !source.checksum && source.seed.as_ref().is_none_or(String::is_empty) {
        return unsupported(tr(
            "Mihomo KCP requires a frame checksum or an encryption seed",
            "Mihomo KCP 使用帧校验或加密种子",
        ));
    }
    if source.header == crate::transport::Header::Dns {
        return unsupported(tr(
            "Mihomo KCP does not support DNS packet camouflage",
            "Mihomo KCP 没有 DNS 数据包伪装",
        ));
    }
    let mut options = Options::new(source)?;
    let mut output = Map::new();
    options.copy(&mut output, &["mtu", "congestion", "seed", "header"]);
    options.rename(
        &mut output,
        &[
            ("upload", "uplink-capacity"),
            ("download", "downlink-capacity"),
            ("write_buffer", "write-buffer"),
            ("read_buffer", "read-buffer"),
        ],
    );
    options.durations(
        &mut output,
        &[("interval", "tti")],
        Some(Duration::from_millis(1)),
    )?;
    options.take("checksum");
    options.take("domain");
    options.finish("Mihomo KCP")?;
    Ok(output)
}

fn mihomo_http(source: &XHttpOptions, inbound: bool) -> Result<Map<String, Value>> {
    let mut options = Options::new(source)?;
    let mut output = Map::new();
    options.copy(&mut output, &["host", "path", "mode"]);
    options.take("headers");
    if !inbound && !source.headers.is_empty() {
        output.insert(
            "headers".to_owned(),
            json!(single_headers(&source.headers)?),
        );
    }
    options.rename(
        &mut output,
        &[
            ("padding_obfuscation", "x-padding-obfs-mode"),
            ("padding_key", "x-padding-key"),
            ("padding_header", "x-padding-header"),
            ("padding_method", "x-padding-method"),
            ("upload_method", "uplink-http-method"),
            ("session_placement", "session-placement"),
            ("session_key", "session-key"),
            ("sequence_placement", "seq-placement"),
            ("sequence_key", "seq-key"),
            ("data_placement", "uplink-data-placement"),
            ("data_key", "uplink-data-key"),
        ],
    );
    if options.take("padding_placement").is_some() {
        output.insert(
            "x-padding-placement".to_owned(),
            json!(match source.padding_placement {
                PaddingPlacement::QueryInHeader => "queryInHeader",
                PaddingPlacement::Cookie => "cookie",
                PaddingPlacement::Header => "header",
                PaddingPlacement::Query => "query",
            }),
        );
    }
    ranges(
        &mut options,
        &mut output,
        &[
            ("padding_size", "x-padding-bytes"),
            ("upload_size", "sc-max-each-post-bytes"),
            ("chunk_size", "uplink-chunk-size"),
        ],
        None,
    )?;
    options.take("pool");
    if inbound {
        for field in [
            "session_alphabet",
            "session_length",
            "grpc_header",
            "upload_interval",
        ] {
            options.take(field);
        }
        options.invert(&mut output, "sse_header", "no-sse-header");
        options.rename(
            &mut output,
            &[("buffered_uploads", "sc-max-buffered-posts")],
        );
        ranges(
            &mut options,
            &mut output,
            &[("stream_keep_alive", "sc-stream-up-server-secs")],
            Some(Duration::from_secs(1)),
        )?;
    } else {
        for field in [
            "sse_header",
            "stream_keep_alive",
            "header_limit",
            "buffered_uploads",
        ] {
            options.take(field);
        }
        options.invert(&mut output, "grpc_header", "no-grpc-header");
        options.rename(&mut output, &[("session_alphabet", "session-table")]);
        ranges(
            &mut options,
            &mut output,
            &[("session_length", "session-length")],
            None,
        )?;
        ranges(
            &mut options,
            &mut output,
            &[("upload_interval", "sc-min-posts-interval-ms")],
            Some(Duration::from_millis(1)),
        )?;
        let pool = mihomo_pool(&source.pool)?;
        if !pool.is_empty() {
            output.insert("reuse-settings".to_owned(), json!(pool));
        }
    }
    options.finish("Mihomo XHTTP")?;
    for value in output.values_mut() {
        if value.is_number() {
            *value = json!(value.to_string());
        }
    }
    Ok(output)
}

fn mihomo_pool(source: &Pool) -> Result<Map<String, Value>> {
    let mut options = Options::new(source)?;
    let mut output = Map::new();
    ranges(
        &mut options,
        &mut output,
        &[
            ("concurrency", "max-concurrency"),
            ("connections", "max-connections"),
            ("reuse_limit", "c-max-reuse-times"),
            ("request_limit", "h-max-request-times"),
        ],
        None,
    )?;
    ranges(
        &mut options,
        &mut output,
        &[("lifetime", "h-max-reusable-secs")],
        Some(Duration::from_secs(1)),
    )?;
    for value in output.values_mut() {
        if value.is_number() {
            *value = json!(value.to_string());
        }
    }
    if let Some(value) = options.take("keep_alive") {
        output.insert(
            "h-keep-alive-period".to_owned(),
            json!(duration(value.as_str().unwrap(), Duration::from_secs(1))?),
        );
    }
    options.finish(tr("Mihomo XHTTP connection reuse", "Mihomo XHTTP 连接复用"))?;
    Ok(output)
}

fn xhttp(
    source: &XHttp,
    inbound: bool,
    input: super::parameters::Input<'_>,
) -> Result<Map<String, Value>> {
    let mut settings = xhttp_options(&source.http, inbound)?;
    if !inbound && let Some(download) = &source.download {
        if source.http.mode == Mode::StreamOne {
            return unsupported(tr(
                "Single-stream XHTTP cannot use a separate download connection",
                "XHTTP 单流模式与独立下载连接无法同时使用",
            ));
        }
        if input.pending.is_none() && (download.server.is_empty() || download.port == 0) {
            return Err(tr(
                "Enter a server address and port for XHTTP download",
                "请填写 XHTTP 下载连接的地址与端口",
            )
            .into());
        }
        let server = match download.server.parse::<std::net::IpAddr>() {
            Ok(address) => address.to_string(),
            Err(_) if download.server.is_empty() => String::new(),
            Err(_) => match url::Host::parse(&download.server)? {
                url::Host::Domain(value) => value,
                url::Host::Ipv4(value) => value.to_string(),
                url::Host::Ipv6(value) => value.to_string(),
            },
        };
        let mut stream = Map::from_iter([
            ("address".to_owned(), json!(server)),
            ("port".to_owned(), json!(download.port)),
            ("network".to_owned(), json!("xhttp")),
            (
                "xhttpSettings".to_owned(),
                json!(xhttp_options(&download.http, false)?),
            ),
        ]);
        let mut options = Options::new(&download.network)?;
        let socket = super::xray::dialer(&download.network, &mut options)?;
        options.finish(tr("Xray download connection", "Xray 下载连接"))?;
        if !socket.is_empty() {
            stream.insert("sockopt".to_owned(), json!(socket));
        }
        stream.extend(super::xray::security(&download.security, input.download())?);
        let params = quic(&download.quic, false)?;
        if !params.is_empty() {
            stream.insert("finalmask".to_owned(), json!({"quicParams": params}));
        }
        settings.insert("downloadSettings".to_owned(), json!(stream));
    }
    let mut output = Map::from_iter([
        ("network".to_owned(), json!("xhttp")),
        ("xhttpSettings".to_owned(), json!(settings)),
    ]);
    let params = quic(&source.quic, inbound)?;
    if !params.is_empty() {
        output.insert("finalmask".to_owned(), json!({"quicParams": params}));
    }
    Ok(output)
}

fn xhttp_options(source: &XHttpOptions, inbound: bool) -> Result<Map<String, Value>> {
    let mut options = Options::new(source)?;
    let mut output = Map::new();
    options.copy(&mut output, &["host", "mode"]);
    options.take("path");
    if let Some(path) = &source.path {
        let (path, query) = path.split_once('?').unwrap_or((path, ""));
        let mut path = if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        };
        if (source.session_placement == Placement::Path
            || source.sequence_placement == Placement::Path)
            && !path.ends_with('/')
        {
            path.push('/');
        }
        if !inbound && !query.is_empty() {
            path.push('?');
            path.push_str(query);
        }
        if path != "/" {
            output.insert("path".to_owned(), json!(path));
        }
    }
    if inbound {
        if let Some(Value::String(host)) = output.get_mut("host") {
            *host = host
                .chars()
                .map(|character| character.to_lowercase().next().unwrap())
                .collect();
        }
        for field in [
            "headers",
            "upload_method",
            "session_alphabet",
            "session_length",
            "chunk_size",
            "grpc_header",
            "upload_interval",
            "pool",
        ] {
            options.take(field);
        }
    } else {
        options.take("headers");
        if !source.headers.is_empty() {
            output.insert(
                "headers".to_owned(),
                json!(single_headers(&source.headers)?),
            );
        }
        options.rename(
            &mut output,
            &[
                ("upload_method", "uplinkHTTPMethod"),
                ("session_alphabet", "sessionIDTable"),
            ],
        );
        ranges(
            &mut options,
            &mut output,
            &[
                ("session_length", "sessionIDLength"),
                ("chunk_size", "uplinkChunkSize"),
            ],
            None,
        )?;
        ranges(
            &mut options,
            &mut output,
            &[("upload_interval", "scMinPostsIntervalMs")],
            Some(Duration::from_millis(1)),
        )?;
        options.invert(&mut output, "grpc_header", "noGRPCHeader");
        options.take("pool");
        let pool = pool(&source.pool)?;
        if !pool.is_empty() {
            output.insert("xmux".to_owned(), json!(pool));
        }
    }
    options.rename(
        &mut output,
        &[
            ("padding_obfuscation", "xPaddingObfsMode"),
            ("padding_key", "xPaddingKey"),
            ("padding_header", "xPaddingHeader"),
            ("padding_method", "xPaddingMethod"),
            ("session_placement", "sessionIDPlacement"),
            ("session_key", "sessionIDKey"),
            ("sequence_placement", "seqPlacement"),
            ("sequence_key", "seqKey"),
            ("data_placement", "uplinkDataPlacement"),
            ("data_key", "uplinkDataKey"),
            ("buffered_uploads", "scMaxBufferedPosts"),
            ("header_limit", "serverMaxHeaderBytes"),
        ],
    );
    if options.take("padding_placement").is_some() {
        output.insert(
            "xPaddingPlacement".to_owned(),
            json!(match source.padding_placement {
                PaddingPlacement::QueryInHeader => "queryInHeader",
                PaddingPlacement::Cookie => "cookie",
                PaddingPlacement::Header => "header",
                PaddingPlacement::Query => "query",
            }),
        );
    }
    options.invert(&mut output, "sse_header", "noSSEHeader");
    ranges(
        &mut options,
        &mut output,
        &[
            ("padding_size", "xPaddingBytes"),
            ("upload_size", "scMaxEachPostBytes"),
        ],
        None,
    )?;
    ranges(
        &mut options,
        &mut output,
        &[("stream_keep_alive", "scStreamUpServerSecs")],
        Some(Duration::from_secs(1)),
    )?;
    options.finish("XHTTP")?;
    Ok(output)
}

fn pool(source: &Pool) -> Result<Map<String, Value>> {
    let mut options = Options::new(source)?;
    let mut output = Map::new();
    ranges(
        &mut options,
        &mut output,
        &[
            ("concurrency", "maxConcurrency"),
            ("connections", "maxConnections"),
            ("reuse_limit", "cMaxReuseTimes"),
            ("request_limit", "hMaxRequestTimes"),
        ],
        None,
    )?;
    ranges(
        &mut options,
        &mut output,
        &[("lifetime", "hMaxReusableSecs")],
        Some(Duration::from_secs(1)),
    )?;
    if let Some(value) = options.take("keep_alive") {
        output.insert(
            "hKeepAlivePeriod".to_owned(),
            json!(duration(value.as_str().unwrap(), Duration::from_secs(1))?),
        );
    }
    options.finish(tr("XHTTP connection reuse", "XHTTP 连接复用"))?;
    Ok(output)
}

pub(super) fn quic(source: &Quic, inbound: bool) -> Result<Map<String, Value>> {
    let mut options = Options::new(source)?;
    if source.congestion == crate::transport::Congestion::Cubic {
        return unsupported(tr(
            "Xray QUIC requires BBR, Brutal or Reno",
            "Xray QUIC 使用 BBR、Brutal 或 Reno",
        ));
    }
    let output = quic_params(source, inbound, &mut options);
    options.finish("QUIC")?;
    Ok(output)
}

pub(super) fn quic_params(
    source: &Quic,
    inbound: bool,
    options: &mut Options,
) -> Map<String, Value> {
    let mut output = Map::new();
    if source.congestion != crate::transport::Congestion::Cubic {
        options.copy(&mut output, &["congestion"]);
    }
    options.copy(&mut output, &["debug"]);
    options.rename(
        &mut output,
        &[
            ("bbr_profile", "bbrProfile"),
            ("upload_bandwidth", "brutalUp"),
            ("download_bandwidth", "brutalDown"),
            ("initial_stream_window", "initStreamReceiveWindow"),
            ("max_stream_window", "maxStreamReceiveWindow"),
            ("initial_connection_window", "initConnectionReceiveWindow"),
            ("max_connection_window", "maxConnectionReceiveWindow"),
            ("incoming_streams", "maxIncomingStreams"),
        ],
    );
    options.invert(
        &mut output,
        "loss_compensation",
        "brutalDisableLossCompensation",
    );
    options.invert(&mut output, "path_mtu_discovery", "disablePathMTUDiscovery");
    options.invert(&mut output, "gso", "disableGSO");
    if inbound {
        options.take("keep_alive");
        options.take("chrome_fingerprint");
        options.invert(&mut output, "stateless_reset", "disableStatelessReset");
    } else {
        options.take("stateless_reset");
        options.invert(&mut output, "chrome_fingerprint", "disableChromeParrot");
        if let Some(seconds) = options.seconds("keep_alive") {
            output.insert("keepAlivePeriod".to_owned(), json!(seconds));
        }
    }
    if let Some(seconds) = options.seconds("idle_timeout") {
        output.insert("maxIdleTimeout".to_owned(), json!(seconds));
    }
    output
}

fn ranges(
    options: &mut Options,
    output: &mut Map<String, Value>,
    names: &[(&str, &str)],
    unit: Option<Duration>,
) -> Result<()> {
    for &(source, destination) in names {
        if let Some(value) = options.take(source) {
            output.insert(
                destination.to_owned(),
                range(value.as_str().unwrap(), unit)?,
            );
        }
    }
    Ok(())
}

pub(super) fn range(text: &str, unit: Option<Duration>) -> Result<Value> {
    let text = text.trim();
    let (first, last) = text
        .char_indices()
        .skip(1)
        .find(|(_, character)| *character == '-')
        .map_or((text, text), |(index, _)| {
            (&text[..index], &text[index + 1..])
        });
    let parse = |value: &str| -> Result<i32> {
        match unit {
            Some(unit) => Ok(i32::try_from(duration(value, unit)?)?),
            None => Ok(value.trim().parse()?),
        }
    };
    let (first, last) = (parse(first)?, parse(last)?);
    if first == last {
        Ok(json!(first))
    } else {
        Ok(json!(format!("{}-{}", first.min(last), first.max(last))))
    }
}

pub(super) fn duration(text: &str, unit: Duration) -> Result<i64> {
    let text = text.trim();
    let (negative, value) = text
        .strip_prefix('-')
        .map_or((false, text), |value| (true, value));
    let value = humantime::parse_duration(value)?;
    if value.as_nanos() % unit.as_nanos() != 0 {
        return unsupported(message!(
            "Expected a multiple of {}: {text}",
            "时间精度需要为 {}：{text}",
            humantime::format_duration(unit)
        ));
    }
    let value = i128::try_from(value.as_nanos() / unit.as_nanos())?;
    Ok(i64::try_from(if negative { -value } else { value })?)
}

pub(crate) fn mbps(text: &str) -> Result<f64> {
    let text = text.trim().to_ascii_lowercase();
    if text.is_empty() {
        return Ok(0.0);
    }
    let end = text
        .find(|value: char| !value.is_ascii_digit() && value != '.')
        .unwrap_or(text.len());
    let (amount, unit) = text.split_at(end);
    let amount: f64 = amount
        .parse()
        .map_err(|error| message!("Invalid bandwidth: {error}", "带宽格式不正确：{error}"))?;
    let scale = match unit.trim() {
        "" | "b" | "bps" => 0.000001,
        "k" | "kb" | "kbps" => 0.001,
        "m" | "mb" | "mbps" => 1.0,
        "g" | "gb" | "gbps" => 1000.0,
        "t" | "tb" | "tbps" => 1000000.0,
        unit => {
            return Err(
                message!("Unknown bandwidth unit: {unit}", "无法识别带宽单位：{unit}").into(),
            );
        }
    };
    let rate = amount * scale;
    if !rate.is_finite() {
        return Err(tr(
            "Bandwidth exceeds the supported range",
            "带宽数值超出支持范围",
        )
        .into());
    }
    Ok(rate)
}

pub(crate) fn early_data(path: &str, size: u32) -> String {
    let (path, fragment) = path
        .split_once('#')
        .map_or((path, None), |(path, fragment)| (path, Some(fragment)));
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let mut encoded = form_urlencoded::Serializer::new(String::new());
    encoded.extend_pairs(form_urlencoded::parse(query.as_bytes()).filter(|(key, _)| key != "ed"));
    encoded.append_pair("ed", &size.to_string());
    let mut path = format!("{path}?{}", encoded.finish());
    if let Some(fragment) = fragment {
        path.push('#');
        path.push_str(fragment);
    }
    path
}
