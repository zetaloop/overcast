use crate::language::{message, text as tr};
use std::time::Duration;

use serde_json::{Map, Value, json};
use url::Url;

use crate::{
    Result,
    config::Store,
    hysteria::{Client, ClientOptions, Masquerade, MasqueradeKind, Obfs, ObfsKind, Server},
    inbound::Core,
    transport::{Congestion, Quic},
};

use super::{options::Options, path, single_headers, unsupported};

fn obfs_mask(source: &Obfs) -> Value {
    let mut settings = json!({"password": source.password});
    if source.kind == ObfsKind::Gecko {
        let (min, max) = source.packet_sizes();
        settings["packetSize"] = json!(format!("{min}-{max}"));
    }
    json!({"type": "salamander", "settings": settings})
}

fn port_mask(ports: &str, interval: Option<(u64, u64)>) -> Value {
    let mut settings = json!({"mode": "intervalRemote", "remotePorts": ports});
    if let Some((min, max)) = interval {
        settings["interval"] = json!(format!("{min}-{max}"));
    }
    json!({"type": "udphop", "settings": settings})
}

pub fn share_mask(value: &ClientOptions) -> Result<Map<String, Value>> {
    let params = super::transport::quic_params(&value.quic, false, &mut Options::new(&value.quic)?);
    let mut mask = Map::new();
    if !params.is_empty() {
        mask.insert("quicParams".to_owned(), json!(params));
    }
    if mask.is_empty()
        && value.ports.is_empty()
        && !value
            .obfs
            .as_ref()
            .is_some_and(|o| o.kind == ObfsKind::Gecko)
    {
        return Ok(mask);
    }
    let mut udp: Vec<_> = value.obfs.iter().map(obfs_mask).collect();
    if !value.ports.is_empty() {
        let mut options = Options::new(value)?;
        let min = options.seconds("hop_interval");
        let max = options.seconds("hop_interval_max");
        let interval = match (min, max) {
            (None, None) => None,
            (None, _) if value.hop_interval.is_some() => None,
            (_, None) if value.hop_interval_max.is_some() => None,
            _ => {
                let min = min.unwrap_or(30);
                let max = max.unwrap_or(min);
                (5..=i32::MAX as u64)
                    .contains(&min)
                    .then_some((min, max))
                    .filter(|(_, max)| (min..=i32::MAX as u64).contains(max))
            }
        };
        udp.push(port_mask(&value.ports, interval));
    }
    if !udp.is_empty() {
        mask.insert("udp".to_owned(), json!(udp));
    }
    Ok(mask)
}

pub fn client(source: &Client, core: Core) -> Result<Map<String, Value>> {
    let value = &source.hysteria;
    if value.ports.is_empty() && (value.hop_interval.is_some() || value.hop_interval_max.is_some())
    {
        return Err(tr(
            "Hop interval requires hopping ports",
            "跳跃间隔需要同时配置跳跃端口",
        )
        .into());
    }
    let mut output = parameters(&value.quic, value.obfs.as_ref(), core, false)?;
    let mut options = Options::new(value)?;
    for name in ["tcp", "udp", "quic", "obfs", "ports"] {
        options.take(name);
    }
    if !value.ports.is_empty() {
        crate::connection::ports(&value.ports)?;
    }
    match core {
        Core::SingBox => {
            if !value.ports.is_empty() {
                output.insert(
                    "server_ports".to_owned(),
                    json!(
                        value
                            .ports
                            .split(',')
                            .map(|value| value.trim().replace('-', ":"))
                            .collect::<Vec<_>>()
                    ),
                );
            }
            options.durations(
                &mut output,
                &[
                    ("hop_interval", "hop_interval"),
                    ("hop_interval_max", "hop_interval_max"),
                ],
                None,
            )?;
            let mut networks = Vec::new();
            if value.tcp.unwrap_or(true) {
                networks.push("tcp");
            }
            if value.udp.unwrap_or(true) {
                networks.push("udp");
            }
            output.insert("network".to_owned(), json!(networks));
        }
        Core::Mihomo | Core::Xray => {
            let mut interval = Map::new();
            options.durations(
                &mut interval,
                &[("hop_interval", "min"), ("hop_interval_max", "max")],
                Some(Duration::from_secs(1)),
            )?;
            let min = interval.get("min").and_then(Value::as_u64).unwrap_or(30);
            let max = interval.get("max").and_then(Value::as_u64).unwrap_or(min);
            if max < min {
                return Err(tr(
                    "Maximum hop interval must be at least the hop interval",
                    "最大跳跃间隔需要大于或等于跳跃间隔",
                )
                .into());
            }
            if core == Core::Mihomo {
                if !value.ports.is_empty() {
                    output.insert("ports".to_owned(), json!(value.ports));
                }
                if !interval.is_empty() {
                    output.insert("hop-interval".to_owned(), json!(format!("{min}-{max}")));
                }
            } else {
                output["hysteriaSettings"]["auth"] = json!(source.password);
                if !value.ports.is_empty() {
                    let mask = output.entry("finalmask").or_insert(json!({}));
                    let masks = mask
                        .as_object_mut()
                        .unwrap()
                        .entry("udp")
                        .or_insert(json!([]))
                        .as_array_mut()
                        .unwrap();
                    masks.push(port_mask(&value.ports, Some((min, max))));
                }
            }
        }
    }
    options.finish(tr("Hysteria 2 outbound", "Hysteria 2 出站"))?;
    Ok(output)
}

pub fn server(source: &Server, core: Core, store: &Store) -> Result<Map<String, Value>> {
    let mut output = parameters(&source.quic, source.obfs.as_ref(), core, true)?;
    let mut options = Options::new(source)?;
    for name in ["quic", "client", "obfs", "masquerade"] {
        options.take(name);
    }
    match core {
        Core::Xray => {
            options.take("user_level");
        }
        Core::SingBox => options.copy(&mut output, &["ignore_client_bandwidth"]),
        Core::Mihomo => options.rename(
            &mut output,
            &[("ignore_client_bandwidth", "ignore-client-bandwidth")],
        ),
    }
    if let Some(value) = &source.masquerade {
        let value = masquerade(value, core, store)?;
        if core == Core::Xray {
            output["hysteriaSettings"]["masquerade"] = value;
        } else {
            output.insert("masquerade".to_owned(), value);
        }
    }
    options.finish(tr("Hysteria 2 inbound", "Hysteria 2 入站"))?;
    Ok(output)
}

fn parameters(
    source: &Quic,
    obfs: Option<&Obfs>,
    core: Core,
    server: bool,
) -> Result<Map<String, Value>> {
    let mut output = if core == Core::Xray {
        let params = super::transport::quic(source, server)?;
        let mut stream = Map::from_iter([
            ("network".to_owned(), json!("hysteria")),
            ("hysteriaSettings".to_owned(), json!({"version": 2})),
        ]);
        if !params.is_empty() {
            stream.insert("finalmask".to_owned(), json!({"quicParams": params}));
        }
        stream
    } else {
        let mut options = Options::new(source)?;
        let mut output = Map::new();
        if core == Core::SingBox {
            options.copy(&mut output, &["bbr_profile", "initial_packet_size"]);
            options.rename(
                &mut output,
                &[
                    ("max_stream_window", "stream_receive_window"),
                    ("max_connection_window", "connection_receive_window"),
                    ("incoming_streams", "max_concurrent_streams"),
                    ("debug", "brutal_debug"),
                ],
            );
            options.invert(
                &mut output,
                "path_mtu_discovery",
                "disable_path_mtu_discovery",
            );
            for (name, key) in [
                ("upload_bandwidth", "up_mbps"),
                ("download_bandwidth", "down_mbps"),
            ] {
                if let Some(value) = options.take(name) {
                    let rate = super::transport::mbps(value.as_str().unwrap())?;
                    if rate.fract() != 0.0 || rate >= i64::MAX as f64 {
                        return unsupported(tr(
                            "sing-box requires whole Mbps for HY2 bandwidth",
                            "sing-box HY2 使用整数 Mbps 带宽",
                        ));
                    }
                    output.insert(key.to_owned(), json!(rate as u64));
                }
            }
            options.durations(
                &mut output,
                &[
                    ("idle_timeout", "idle_timeout"),
                    ("keep_alive", "keep_alive_period"),
                ],
                None,
            )?;
            if !server {
                options.invert(&mut output, "chrome_fingerprint", "disable_chrome_parrot");
            }
        } else {
            options.rename(
                &mut output,
                &[
                    ("bbr_profile", "bbr-profile"),
                    ("initial_stream_window", "initial-stream-receive-window"),
                    ("max_stream_window", "max-stream-receive-window"),
                    (
                        "initial_connection_window",
                        "initial-connection-receive-window",
                    ),
                    ("max_connection_window", "max-connection-receive-window"),
                    ("upload_bandwidth", "up"),
                    ("download_bandwidth", "down"),
                    ("udp_mtu", "udp-mtu"),
                    ("cwnd", "cwnd"),
                ],
            );
            if !server {
                options.durations(
                    &mut output,
                    &[("handshake_timeout", "handshake-timeout")],
                    Some(Duration::from_secs(1)),
                )?;
            }
        }
        if source.congestion == Congestion::Brutal {
            options.take("congestion");
        }
        options.finish(&format!("{} Hysteria 2 QUIC", super::key(core)))?;
        output
    };
    if let Some(source) = obfs {
        let mut options = Options::new(source)?;
        options.take("kind");
        options.take("password");
        let mut value = Map::from_iter([("password".to_owned(), json!(source.password))]);
        if source.kind == ObfsKind::Gecko {
            if core == Core::Xray {
                options.take("min_packet_size");
                options.take("max_packet_size");
            } else {
                options.copy(&mut value, &["min_packet_size", "max_packet_size"]);
            }
        }
        options.finish(tr("HY2 obfuscation", "HY2 混淆"))?;
        match core {
            Core::SingBox => {
                value.insert("type".to_owned(), json!(source.kind));
                output.insert("obfs".to_owned(), json!(value));
            }
            Core::Mihomo => {
                output.insert("obfs".to_owned(), json!(source.kind));
                for (name, value) in value {
                    output.insert(format!("obfs-{}", name.replace('_', "-")), value);
                }
            }
            Core::Xray => {
                let mask = output.entry("finalmask").or_insert(json!({}));
                mask["udp"] = json!([obfs_mask(source)]);
            }
        }
    }
    Ok(output)
}

fn masquerade(source: &Masquerade, core: Core, store: &Store) -> Result<Value> {
    let mut options = Options::new(source)?;
    options.take("kind");
    let mut output = Map::from_iter([("type".to_owned(), json!(source.kind))]);
    let url = match source.kind {
        MasqueradeKind::File => {
            if source.directory.is_empty() {
                return Err(tr(
                    "Enter a directory for HY2 file masquerading",
                    "请填写 HY2 伪装文件目录",
                )
                .into());
            }
            options.take("directory");
            let directory = path(store, &source.directory);
            output.insert(
                if core == Core::Xray {
                    "dir"
                } else {
                    "directory"
                }
                .to_owned(),
                json!(directory),
            );
            let mut url = Url::from_directory_path(&directory).map_err(|_| {
                tr(
                    "HY2 masquerade requires an absolute directory path",
                    "HY2 伪装文件目录需要使用绝对路径",
                )
            })?;
            // Mihomo opens the URL path as a native filesystem path.
            if cfg!(windows) && core == Core::Mihomo {
                let mut directory = directory
                    .to_str()
                    .ok_or(tr(
                        "Invalid character in HY2 masquerade directory",
                        "HY2 伪装目录包含无效字符",
                    ))?
                    .replace('\\', "/");
                if !directory.starts_with("//") {
                    directory = format!("//?/{directory}");
                }
                url.set_host(None)?;
                url.set_path(&directory);
            }
            url.to_string()
        }
        MasqueradeKind::Proxy => {
            let url = Url::parse(&source.url).map_err(|error| {
                message!(
                    "Invalid HY2 masquerade target: {error}",
                    "HY2 伪装目标地址格式不正确：{error}"
                )
            })?;
            if !matches!(url.scheme(), "http" | "https")
                && !(core == Core::Xray && url.scheme() == "unix")
            {
                return unsupported(tr(
                    "HY2 reverse proxy requires an HTTP or HTTPS upstream",
                    "HY2 伪装反代需要 HTTP 或 HTTPS 目标",
                ));
            }
            options.copy(&mut output, &["url"]);
            match core {
                Core::Xray => {
                    options.rename(
                        &mut output,
                        &[("rewrite_host", "rewriteHost"), ("forwarded", "xForwarded")],
                    );
                    options.invert(&mut output, "verify_certificate", "insecure");
                }
                Core::SingBox => {
                    options.copy(&mut output, &["rewrite_host"]);
                    if source.verify_certificate == Some(true) {
                        options.take("verify_certificate");
                    }
                }
                Core::Mihomo => {
                    if source.verify_certificate == Some(false) {
                        options.take("verify_certificate");
                    }
                }
            }
            url.to_string()
        }
        MasqueradeKind::String => {
            if core == Core::Mihomo {
                return unsupported(tr(
                    "Mihomo HY2 masquerade supports files or an HTTP reverse proxy",
                    "Mihomo HY2 伪装响应使用文件或 HTTP 反代",
                ));
            }
            if let Some(code) = source.status_code {
                ureq::http::StatusCode::from_u16(code)?;
            }
            options.copy(&mut output, &["content"]);
            options.take("headers");
            if core == Core::Xray {
                options.rename(&mut output, &[("status_code", "statusCode")]);
                output.insert(
                    "headers".to_owned(),
                    json!(single_headers(&source.headers)?),
                );
            } else {
                options.copy(&mut output, &["status_code"]);
                output.insert("headers".to_owned(), json!(source.headers));
            }
            String::new()
        }
    };
    options.finish(tr("HY2 masquerade response", "HY2 伪装响应"))?;
    Ok(if core == Core::Mihomo {
        json!(url)
    } else {
        json!(output)
    })
}
