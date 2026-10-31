use std::time::Duration;

use serde_json::{Map, Value, json};
use url::form_urlencoded;

use crate::{Result, transport::Transport};

use super::{options::Options, single_headers, unsupported};

pub fn xray(source: &Transport, inbound: bool) -> Result<Map<String, Value>> {
    let mut output = Map::new();
    let (network, name, mut options) = match source {
        Transport::Default => return Ok(output),
        Transport::WebSocket(value) => ("websocket", "wsSettings", Options::new(value)?),
        Transport::HttpUpgrade(value) => {
            ("httpupgrade", "httpupgradeSettings", Options::new(value)?)
        }
        Transport::Grpc(value) => ("grpc", "grpcSettings", Options::new(value)?),
    };
    let mut settings = Map::new();
    match source {
        Transport::Default => unreachable!(),
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
