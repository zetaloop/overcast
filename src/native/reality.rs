use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::{
    Result,
    config::Store,
    graph::Graph,
    inbound::{Core, Inbound},
    progress::Progress,
    reality::{Client, Keys, Limit, Server},
};

use super::{
    listener::{self, Listener},
    options::Options,
    unsupported,
};

pub fn prepare(
    listeners: &[Listener],
    graph: &Graph<'_>,
    keys: &mut BTreeMap<Uuid, crate::keys::Keys>,
    progress: &Progress,
) -> Result<()> {
    let active = listeners
        .iter()
        .filter(|listener| listener.source.security.reality().is_some());
    for group in listener::related(active, progress)? {
        progress.check()?;
        let sources: Vec<_> = group
            .listeners
            .iter()
            .filter_map(|listener| listener.source.security.reality())
            .collect();
        let private: BTreeSet<_> = sources
            .iter()
            .filter_map(|source| source.private_key.clone())
            .collect();
        let short_ids: BTreeSet<_> = sources
            .iter()
            .filter(|source| !source.short_ids.is_empty())
            .map(|source| source.short_ids.clone())
            .collect();
        let seeds: BTreeSet<_> = sources
            .iter()
            .filter_map(|source| source.signature_seed.clone())
            .collect();
        if private.len() > 1 || short_ids.len() > 1 || seeds.len() > 1 {
            let names: Vec<_> = group
                .entries
                .iter()
                .map(|entry| graph.entries[*entry].inbound.name.as_str())
                .collect();
            return Err(format!(
                "入站 {} 关联的 REALITY 监听要求不同的握手材料",
                names.join("、")
            )
            .into());
        }
        let mut source = sources[0].clone();
        source.private_key = private.into_iter().next();
        source.short_ids = short_ids.into_iter().next().unwrap_or_default();
        source.signature_seed = seeds.into_iter().next();
        let cached = group.entries.iter().find_map(|entry| {
            keys.get(&graph.entries[*entry].inbound.uuid)
                .and_then(|keys| keys.reality.as_ref())
        });
        let material = Keys::resolve(&source, cached)?;
        for entry in group.entries {
            let uuid = graph.entries[entry].inbound.uuid;
            let mut material = material.clone();
            if !source.signature {
                material.signature_seed = keys
                    .get(&uuid)
                    .and_then(|keys| keys.reality.as_ref())
                    .and_then(|keys| keys.signature_seed.clone());
                material.signature_key = keys
                    .get(&uuid)
                    .and_then(|keys| keys.reality.as_ref())
                    .and_then(|keys| keys.signature_key.clone());
            }
            keys.entry(uuid).or_default().reality = Some(material);
        }
    }
    Ok(())
}

pub fn xray(source: &Client) -> Result<Value> {
    source.validate()?;
    let mut tls = Options::new(&source.tls)?;
    let mut output = Map::new();
    tls.rename(
        &mut output,
        &[("server_name", "serverName"), ("key_log", "masterKeyLog")],
    );
    tls.copy(&mut output, &["fingerprint"]);
    tls.finish("Xray REALITY")?;
    let mut options = Options::new(source)?;
    options.take("tls");
    options.rename(
        &mut output,
        &[
            ("public_key", "password"),
            ("short_id", "shortId"),
            ("signature_key", "mldsa65Verify"),
            ("spider_path", "spiderX"),
            ("debug", "show"),
        ],
    );
    options.finish("Xray REALITY 客户端")?;
    Ok(json!(output))
}

pub fn singbox(reality: &Client, store: &Store) -> Result<Value> {
    reality.validate()?;
    let source = &reality.tls;
    let mut options = Options::new(source)?;
    if source.verify_certificate == Some(true) {
        options.take("verify_certificate");
    }
    if source.send_sni == Some(true) {
        options.take("send_sni");
    }
    if source.system_roots == Some(true) {
        options.take("system_roots");
    }
    if source.engine.as_deref() == Some("go") {
        options.take("engine");
    }
    let mut output = Map::from_iter([("enabled".to_owned(), json!(true))]);
    options.copy(
        &mut output,
        &[
            "server_name",
            "alpn",
            "min_version",
            "max_version",
            "cipher_suites",
            "client_certificate",
            "client_key",
            "kernel_tx",
            "kernel_rx",
        ],
    );
    options.durations(
        &mut output,
        &[("handshake_timeout", "handshake_timeout")],
        None,
    )?;
    let mut utls = Map::from_iter([("enabled".to_owned(), json!(true))]);
    options.copy(&mut utls, &["fingerprint"]);
    output.insert("utls".to_owned(), json!(utls));
    for (name, destination) in [
        ("client_certificate_file", "client_certificate_path"),
        ("client_key_file", "client_key_path"),
    ] {
        if let Some(value) = options.take(name) {
            output.insert(
                destination.to_owned(),
                json!(super::path(store, value.as_str().unwrap())),
            );
        }
    }
    options.finish("sing-box REALITY")?;
    let mut options = Options::new(reality)?;
    options.take("tls");
    if reality.hybrid_key_exchange == Some(false) {
        options.take("hybrid_key_exchange");
    }
    let mut reality = Map::from_iter([("enabled".to_owned(), json!(true))]);
    options.copy(&mut reality, &["public_key", "short_id"]);
    options.finish("sing-box REALITY 客户端")?;
    output.insert("reality".to_owned(), json!(reality));
    Ok(json!(output))
}

pub fn server(source: &Inbound, value: &Server) -> Result<Value> {
    let mut tls = Options::new(&value.tls)?;
    tls.take("server_name");
    let mut output = Map::new();
    match source.core {
        Core::Xray => tls.rename(&mut output, &[("key_log", "masterKeyLog")]),
        Core::SingBox => {
            tls.copy(
                &mut output,
                &[
                    "alpn",
                    "min_version",
                    "max_version",
                    "cipher_suites",
                    "kernel_tx",
                    "kernel_rx",
                ],
            );
            tls.durations(
                &mut output,
                &[("handshake_timeout", "handshake_timeout")],
                None,
            )?;
            if value.tls.session_resumption == Some(false) {
                tls.take("session_resumption");
            }
        }
        Core::Mihomo => {}
    }
    tls.finish("REALITY 握手")?;
    let names = value.names(value.tls.server_name.as_deref())?;
    let mut options = Options::new(value)?;
    for name in [
        "tls",
        "target",
        "server_names",
        "private_key",
        "short_ids",
        "signature",
    ] {
        options.take(name);
    }
    if !value.signature {
        options.take("signature_seed");
    }
    match source.core {
        Core::Xray => {
            output.insert("target".to_owned(), json!(value.address()?));
            if value.endpoint()?.is_none() {
                output.insert("type".to_owned(), json!("unix"));
            }
            output.insert("serverNames".to_owned(), json!(names));
            output.insert(
                "privateKey".to_owned(),
                json!(value.private_key.as_ref().ok_or("REALITY 私钥尚未生成")?),
            );
            output.insert("shortIds".to_owned(), json!(value.short_ids));
            options.rename(
                &mut output,
                &[
                    ("target_network", "type"),
                    ("proxy_protocol", "xver"),
                    ("min_client_version", "minClientVer"),
                    ("max_client_version", "maxClientVer"),
                    ("signature_seed", "mldsa65Seed"),
                    ("debug", "show"),
                ],
            );
            options.durations(
                &mut output,
                &[("max_time_difference", "maxTimeDiff")],
                Some(Duration::from_millis(1)),
            )?;
            for (field, name, limit) in [
                ("upload", "limitFallbackUpload", &value.upload),
                ("download", "limitFallbackDownload", &value.download),
            ] {
                options.take(field);
                let limit = limits(limit, source.core)?;
                if !limit.is_empty() {
                    output.insert(name.to_owned(), json!(limit));
                }
            }
        }
        Core::SingBox => {
            if value.signature {
                return unsupported("sing-box REALITY 没有 ML-DSA-65 签名配置");
            }
            let [name] = names.as_slice() else {
                return unsupported("sing-box REALITY 使用一个服务名");
            };
            output.insert("enabled".to_owned(), json!(true));
            output.insert("server_name".to_owned(), json!(name));
            let (server, port) = value
                .endpoint()?
                .ok_or("sing-box REALITY 握手目标使用 TCP 地址")?;
            let mut handshake = Map::from_iter([
                ("server".to_owned(), json!(server)),
                ("server_port".to_owned(), json!(port)),
            ]);
            options.take("network");
            super::singbox::dialer(&value.network, &mut handshake)?;
            options.take("outbound");
            if value.target_network.as_deref() == Some("tcp") {
                options.take("target_network");
            }
            let mut reality = Map::from_iter([
                ("enabled".to_owned(), json!(true)),
                ("handshake".to_owned(), json!(handshake)),
                (
                    "private_key".to_owned(),
                    json!(value.private_key.as_ref().ok_or("REALITY 私钥尚未生成")?),
                ),
                ("short_id".to_owned(), json!(value.short_ids)),
            ]);
            options.durations(
                &mut reality,
                &[("max_time_difference", "max_time_difference")],
                None,
            )?;
            output.insert("reality".to_owned(), json!(reality));
        }
        Core::Mihomo => {
            if value.signature {
                return unsupported("Mihomo REALITY 没有 ML-DSA-65 签名配置");
            }
            value
                .endpoint()?
                .ok_or("Mihomo REALITY 握手目标使用 TCP 地址")?;
            if value.target_network.as_deref() == Some("tcp") {
                options.take("target_network");
            }
            options.take("outbound");
            output.insert("proxy".to_owned(), json!("DIRECT"));
            output.insert("dest".to_owned(), json!(value.address()?));
            output.insert("server-names".to_owned(), json!(names));
            output.insert(
                "private-key".to_owned(),
                json!(value.private_key.as_ref().ok_or("REALITY 私钥尚未生成")?),
            );
            output.insert("short-id".to_owned(), json!(value.short_ids));
            options.durations(
                &mut output,
                &[("max_time_difference", "max-time-difference")],
                Some(Duration::from_micros(1)),
            )?;
            for (field, name, limit) in [
                ("upload", "limit-fallback-upload", &value.upload),
                ("download", "limit-fallback-download", &value.download),
            ] {
                options.take(field);
                let limit = limits(limit, source.core)?;
                if !limit.is_empty() {
                    output.insert(name.to_owned(), json!(limit));
                }
            }
        }
    }
    options.finish("REALITY 服务端")?;
    Ok(json!(output))
}

fn limits(source: &Limit, core: Core) -> Result<Map<String, Value>> {
    let mut options = Options::new(source)?;
    let mut output = Map::new();
    options.rename(
        &mut output,
        match core {
            Core::Xray => &[
                ("after_bytes", "afterBytes"),
                ("bytes_per_second", "bytesPerSec"),
                ("burst_bytes_per_second", "burstBytesPerSec"),
            ],
            _ => &[
                ("after_bytes", "after-bytes"),
                ("bytes_per_second", "bytes-per-sec"),
                ("burst_bytes_per_second", "burst-bytes-per-sec"),
            ],
        },
    );
    options.finish("REALITY 回落速率")?;
    Ok(output)
}
