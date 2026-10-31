use std::time::Duration;

use serde_json::{Map, Value, json};
use url::form_urlencoded;

use crate::{
    Result,
    config::Store,
    connection::Network,
    transport::{Mode, PaddingPlacement, Placement, Pool, Quic, Transport, XHttp, XHttpOptions},
};

use super::{options::Options, single_headers, unsupported};

pub fn xray(source: &Transport, inbound: bool, store: &Store) -> Result<Map<String, Value>> {
    let mut output = Map::new();
    let (network, name, mut options) = match source {
        Transport::Default => return Ok(output),
        Transport::WebSocket(value) => ("websocket", "wsSettings", Options::new(value)?),
        Transport::HttpUpgrade(value) => {
            ("httpupgrade", "httpupgradeSettings", Options::new(value)?)
        }
        Transport::Grpc(value) => ("grpc", "grpcSettings", Options::new(value)?),
        Transport::XHttp(value) => return xhttp(value, inbound, store),
    };
    let mut settings = Map::new();
    match source {
        Transport::Default | Transport::XHttp(_) => unreachable!(),
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
                return unsupported("Xray 的 WebSocket 握手数据使用 Sec-WebSocket-Protocol 请求头");
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
        Transport::Grpc(_) => {
            options.rename(&mut settings, &[("service_name", "serviceName")]);
            if inbound {
                for field in [
                    "authority",
                    "multi_mode",
                    "permit_without_stream",
                    "receive_window",
                    "user_agent",
                    "connections",
                    "min_streams",
                    "max_streams",
                ] {
                    options.take(field);
                }
            } else {
                options.copy(
                    &mut settings,
                    &["authority", "permit_without_stream", "user_agent"],
                );
                options.rename(
                    &mut settings,
                    &[
                        ("multi_mode", "multiMode"),
                        ("receive_window", "initial_windows_size"),
                    ],
                );
            }
            options.durations(
                &mut settings,
                &[
                    ("keep_alive", "idle_timeout"),
                    ("ping_timeout", "health_check_timeout"),
                ],
                Some(Duration::from_secs(1)),
            )?;
        }
    }
    options.finish("Xray 传输")?;
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
        Value::Number(value) => value.as_u64() != Some(0),
        Value::Object(value) => !value.is_empty(),
        _ => true,
    });
    output.insert("network".to_owned(), json!(network));
    if !settings.is_empty() {
        output.insert(name.to_owned(), json!(settings));
    }
    Ok(output)
}

pub fn singbox(source: &Transport, inbound: bool) -> Result<Option<Value>> {
    let mut output = Map::new();
    match source {
        Transport::Default => return Ok(None),
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
                    headers.insert("Host".to_owned(), vec![host.clone()]);
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
            options.copy(&mut output, &["service_name"]);
            if inbound {
                for field in [
                    "authority",
                    "user_agent",
                    "receive_window",
                    "permit_without_stream",
                    "connections",
                    "min_streams",
                    "max_streams",
                ] {
                    options.take(field);
                }
            } else {
                options.copy(&mut output, &["permit_without_stream"]);
            }
            options.durations(
                &mut output,
                &[
                    ("keep_alive", "idle_timeout"),
                    ("ping_timeout", "ping_timeout"),
                ],
                None,
            )?;
            options.finish("sing-box gRPC")?;
        }
        Transport::XHttp(_) => return unsupported("sing-box 没有 XHTTP 传输配置"),
    }
    Ok(Some(json!(output)))
}

pub fn mihomo_client(
    source: &Transport,
    network: &Network,
    store: &Store,
    globals: &mut Map<String, Value>,
) -> Result<Map<String, Value>> {
    let mut output = Map::new();
    match source {
        Transport::Default => {}
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
                headers.insert("Host".to_owned(), host.clone());
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
                headers.insert("Host".to_owned(), host.clone());
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
            let mut grpc = Map::new();
            options.rename(
                &mut grpc,
                &[
                    ("service_name", "grpc-service-name"),
                    ("user_agent", "grpc-user-agent"),
                    ("connections", "max-connections"),
                    ("min_streams", "min-streams"),
                    ("max_streams", "max-streams"),
                ],
            );
            options.durations(
                &mut grpc,
                &[("keep_alive", "ping-interval")],
                Some(Duration::from_secs(1)),
            )?;
            options.finish("Mihomo gRPC")?;
            output.insert("network".to_owned(), json!("grpc"));
            output.insert("grpc-opts".to_owned(), json!(grpc));
        }
        Transport::XHttp(value) => {
            Options::new(&value.quic)?.finish("Mihomo XHTTP QUIC")?;
            let mut http = mihomo_http(&value.http, false)?;
            if let Some(download) = &value.download {
                if download.tls.enabled
                    && download.tls.reality.enabled
                    && download.tls.alpn == ["h3"]
                {
                    return unsupported("Mihomo XHTTP/3 不支持 REALITY 握手");
                }
                if value.http.mode == Mode::StreamOne {
                    return unsupported("XHTTP 单流模式与独立下载连接无法同时使用");
                }
                if download.server.is_empty() || download.port == 0 {
                    return Err("请填写 XHTTP 下载连接的地址与端口".into());
                }
                if serde_json::to_value(&download.network)? != serde_json::to_value(network)? {
                    Options::new(&download.network)?.finish("Mihomo XHTTP 下载连接")?;
                }
                Options::new(&download.quic)?.finish("Mihomo XHTTP 下载 QUIC")?;
                let mut options = Options::new(&download.http)?;
                let mut settings = Map::from_iter([
                    ("server".to_owned(), json!(download.server)),
                    ("port".to_owned(), json!(download.port)),
                    ("tls".to_owned(), json!(download.tls.enabled)),
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
                options.finish("Mihomo XHTTP 下载参数")?;
                if download.tls.enabled {
                    super::mihomo::client_tls(
                        &download.tls,
                        store,
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
            options.finish("Mihomo WebSocket 入站")?;
        }
        Transport::HttpUpgrade(_) => {
            return unsupported("Mihomo VLESS 入站没有 HTTPUpgrade 接收器");
        }
        Transport::Grpc(value) => {
            let mut options = Options::new(value)?;
            if value.service_name.as_deref().is_none_or(str::is_empty) {
                return unsupported("Mihomo gRPC 入站通过非空服务名启用");
            }
            options.rename(&mut output, &[("service_name", "grpc-service-name")]);
            for field in [
                "authority",
                "user_agent",
                "receive_window",
                "permit_without_stream",
                "connections",
                "min_streams",
                "max_streams",
            ] {
                options.take(field);
            }
            options.finish("Mihomo gRPC 入站")?;
        }
        Transport::XHttp(value) => {
            Options::new(&value.quic)?.finish("Mihomo XHTTP 入站 QUIC")?;
            let mut http = mihomo_http(&value.http, true)?;
            http.entry("mode").or_insert(json!("auto"));
            output.insert("xhttp-config".to_owned(), json!(http));
        }
    }
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
    options.finish("Mihomo XHTTP 连接复用")?;
    Ok(output)
}

fn xhttp(source: &XHttp, inbound: bool, store: &Store) -> Result<Map<String, Value>> {
    let mut settings = xhttp_options(&source.http, inbound)?;
    if !inbound && let Some(download) = &source.download {
        if source.http.mode == Mode::StreamOne {
            return unsupported("XHTTP 单流模式与独立下载连接无法同时使用");
        }
        if download.server.is_empty() || download.port == 0 {
            return Err("请填写 XHTTP 下载连接的地址与端口".into());
        }
        let server = match download.server.parse::<std::net::IpAddr>() {
            Ok(address) => address.to_string(),
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
        options.finish("Xray 下载连接")?;
        if !socket.is_empty() {
            stream.insert("sockopt".to_owned(), json!(socket));
        }
        if download.tls.enabled {
            stream.extend(super::xray::security(&download.tls, store)?);
        }
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
    options.finish("XHTTP 连接复用")?;
    Ok(output)
}

fn quic(source: &Quic, inbound: bool) -> Result<Map<String, Value>> {
    let mut options = Options::new(source)?;
    let mut output = Map::new();
    options.copy(&mut output, &["congestion", "debug"]);
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
        options.durations(
            &mut output,
            &[("keep_alive", "keepAlivePeriod")],
            Some(Duration::from_secs(1)),
        )?;
    }
    options.durations(
        &mut output,
        &[("idle_timeout", "maxIdleTimeout")],
        Some(Duration::from_secs(1)),
    )?;
    options.finish("QUIC")?;
    Ok(output)
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

fn range(text: &str, unit: Option<Duration>) -> Result<Value> {
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

fn duration(text: &str, unit: Duration) -> Result<i64> {
    let text = text.trim();
    let (negative, value) = text
        .strip_prefix('-')
        .map_or((false, text), |value| (true, value));
    let value = humantime::parse_duration(value)?;
    if value.as_nanos() % unit.as_nanos() != 0 {
        return unsupported(format!(
            "时间精度需要为 {}：{text}",
            humantime::format_duration(unit)
        ));
    }
    let value = i128::try_from(value.as_nanos() / unit.as_nanos())?;
    Ok(i64::try_from(if negative { -value } else { value })?)
}

fn early_data(path: &str, size: u32) -> String {
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
