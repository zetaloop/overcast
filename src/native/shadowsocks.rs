use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::{
    Result,
    config::Store,
    graph::Graph,
    inbound::{Core, Inbound, Protocol},
    progress::Progress,
    shadowsocks::{Cipher, Keys, Plugin},
};

use super::{
    listener::{self, Listener},
    unsupported,
};

pub fn cipher(value: Cipher, core: Core, inbound: bool) -> Result<Value> {
    let standard = value.aead() || value.key_size().is_some() || value == Cipher::None;
    let stream = matches!(
        value,
        Cipher::Aes128Ctr
            | Cipher::Aes192Ctr
            | Cipher::Aes256Ctr
            | Cipher::Aes128Cfb
            | Cipher::Aes192Cfb
            | Cipher::Aes256Cfb
            | Cipher::Rc4Md5
            | Cipher::Chacha20Ietf
            | Cipher::Xchacha20
    );
    let supported = match core {
        Core::Xray => standard && !matches!(value, Cipher::None | Cipher::Aes192Gcm),
        Core::SingBox => standard || !inbound && stream,
        Core::Mihomo => true,
    };
    if !supported {
        return unsupported(format!(
            "当前核心的 Shadowsocks {}不支持算法 {}",
            if inbound { "入站" } else { "出站" },
            serde_json::to_value(value)?
        ));
    }
    Ok(serde_json::to_value(value)?)
}

pub fn multi(source: &Inbound, users: usize) -> bool {
    let Protocol::Shadowsocks(value) = &source.protocol else {
        return false;
    };
    source.core != Core::Mihomo
        && (value.cipher.aead()
            || matches!(value.cipher, Cipher::Aes128Gcm2022 | Cipher::Aes256Gcm2022)
                && (source.users || users > 1 || value.password.is_some()))
}

pub fn shared(source: &Inbound, users: usize) -> bool {
    matches!(&source.protocol, Protocol::Shadowsocks(value) if value.cipher.key_size().is_some() && multi(source, users))
}

pub fn prepare(
    listeners: &[Listener],
    graph: &Graph<'_>,
    keys: &mut BTreeMap<Uuid, crate::keys::Keys>,
    progress: &Progress,
) -> Result<()> {
    for group in listener::related(
        listeners
            .iter()
            .filter(|listener| shared(&listener.source, listener.users.len())),
        progress,
    )? {
        let sources: Vec<_> = group
            .listeners
            .iter()
            .filter_map(|listener| {
                if let Protocol::Shadowsocks(value) = &listener.source.protocol {
                    Some(value)
                } else {
                    None
                }
            })
            .collect();
        let passwords: BTreeSet<_> = sources
            .iter()
            .filter_map(|source| source.password.clone())
            .collect();
        if passwords.len() > 1 {
            return Err(format!(
                "入站 {} 关联的 Shadowsocks 监听要求不同的入口密钥",
                group
                    .entries
                    .iter()
                    .map(|entry| graph.entries[*entry].inbound.name.as_str())
                    .collect::<Vec<_>>()
                    .join("、")
            )
            .into());
        }
        let mut source = sources[0].clone();
        source.password = passwords.into_iter().next();
        let previous = group.entries.iter().find_map(|entry| {
            keys.get(&graph.entries[*entry].inbound.uuid)
                .and_then(|keys| keys.shadowsocks.as_ref())
        });
        let material = Keys::resolve(&source, previous)?;
        for entry in group.entries {
            keys.entry(graph.entries[entry].inbound.uuid)
                .or_default()
                .shadowsocks = Some(material.clone());
        }
    }
    Ok(())
}

pub(super) fn arguments(text: &str) -> Result<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    let mut name = None;
    let mut part = String::new();
    let mut insert = |name: &mut Option<String>, part: &mut String| -> Result<()> {
        let (key, value) = match name.take() {
            Some(name) => (name, std::mem::take(part)),
            None => (std::mem::take(part), "1".to_owned()),
        };
        if key.is_empty() {
            return Err("插件参数名称不能为空".into());
        }
        values.entry(key).or_insert(value);
        Ok(())
    };
    let mut chars = text.chars();
    while let Some(value) = chars.next() {
        match value {
            '\\' => part.push(chars.next().ok_or("插件参数的转义符后缺少字符")?),
            '=' if name.is_none() => name = Some(std::mem::take(&mut part)),
            ';' => insert(&mut name, &mut part)?,
            value => part.push(value),
        }
    }
    if name.is_some() || !part.is_empty() {
        insert(&mut name, &mut part)?;
    }
    Ok(values)
}

pub fn plugin(
    source: &Plugin,
    core: Core,
    server: &str,
    store: &Store,
    globals: &mut Map<String, Value>,
) -> Result<Map<String, Value>> {
    let mut values = arguments(&source.options)?;
    let mut original = values.clone();
    let mut output = Map::new();
    let mut options = Map::new();
    let (name, allowed): (&str, &[&str]) = match source.name.as_str() {
        "obfs-local" | "simple-obfs" | "obfs" => {
            let mode = values.remove("obfs").unwrap_or_else(|| "http".to_owned());
            if !matches!(mode.as_str(), "http" | "tls") {
                return Err("Simple Obfs 模式需要使用 http 或 tls".into());
            }
            options.insert("mode".to_owned(), json!(mode));
            options.insert(
                "host".to_owned(),
                json!(values.remove("obfs-host").unwrap_or_default()),
            );
            ("obfs", &[])
        }
        "v2ray-plugin" => {
            let mode = values
                .remove("mode")
                .unwrap_or_else(|| "websocket".to_owned());
            if !matches!(mode.as_str(), "websocket" | "quic") {
                return Err("v2ray-plugin 模式需要使用 websocket 或 quic".into());
            }
            if core == Core::Mihomo && mode != "websocket" {
                return unsupported("Mihomo v2ray-plugin 使用 WebSocket");
            }
            options.insert("mode".to_owned(), json!(mode));
            let host = values.remove("host");
            options.insert(
                "host".to_owned(),
                json!(host.as_deref().unwrap_or("cloudfront.com")),
            );
            options.insert(
                "path".to_owned(),
                json!(values.remove("path").unwrap_or_else(|| "/".to_owned())),
            );
            let tls = values.remove("tls").is_some();
            if mode == "quic" && !tls {
                return unsupported("QUIC 插件需要 TLS");
            }
            if tls && core == Core::Mihomo && host.is_none() {
                options.insert("host".to_owned(), json!(server));
                options.insert("headers".to_owned(), json!({"Host": "cloudfront.com"}));
            }
            options.insert("tls".to_owned(), json!(tls));
            let mux = values
                .remove("mux")
                .map(|value| value.parse::<i32>())
                .transpose()?
                .unwrap_or(1);
            options.insert("mux".to_owned(), json!(mux > 0));
            let cert = values.remove("cert");
            let raw = values.remove("certRaw").map(|value| {
                format!("-----BEGIN CERTIFICATE-----\n{value}\n-----END CERTIFICATE-----")
            });
            if core == Core::Mihomo && tls {
                let trust = super::pem(
                    store,
                    &raw.into_iter().collect::<Vec<_>>(),
                    &cert.into_iter().collect::<Vec<_>>(),
                )?;
                if !trust.is_empty() {
                    globals.insert("tls".to_owned(), json!({"custom-certifactes": trust}));
                }
            }
            (
                "v2ray-plugin",
                &[
                    "headers",
                    "ech-opts",
                    "fingerprint",
                    "certificate",
                    "private-key",
                    "skip-cert-verify",
                    "name-cert-verify",
                    "v2ray-http-upgrade",
                    "v2ray-http-upgrade-fast-open",
                ],
            )
        }
        "gost-plugin" => (
            "gost-plugin",
            &[
                "mode",
                "host",
                "path",
                "tls",
                "headers",
                "ech-opts",
                "fingerprint",
                "certificate",
                "private-key",
                "skip-cert-verify",
                "name-cert-verify",
                "mux",
            ],
        ),
        "restls" => (
            "restls",
            &[
                "password",
                "host",
                "version-hint",
                "restls-script",
                "fingerprint",
                "skip-cert-verify",
                "name-cert-verify",
                "force-tls12",
            ],
        ),
        "kcptun" => (
            "kcptun",
            &[
                "key",
                "crypt",
                "mode",
                "conn",
                "autoexpire",
                "scavengettl",
                "mtu",
                "ratelimit",
                "sndwnd",
                "rcvwnd",
                "datashard",
                "parityshard",
                "dscp",
                "nocomp",
                "acknodelay",
                "nodelay",
                "interval",
                "resend",
                "nc",
                "sockbuf",
                "smuxver",
                "smuxbuf",
                "framesize",
                "streambuf",
                "keepalive",
            ],
        ),
        _ => return unsupported(format!("当前核心没有 SIP003 插件 {}", source.name)),
    };
    if core == Core::SingBox {
        if !matches!(name, "obfs" | "v2ray-plugin") {
            return unsupported(format!("sing-box 没有 SIP003 插件 {name}"));
        }
        if !values.is_empty() {
            return unsupported(format!(
                "sing-box 插件未使用参数：{}",
                values.keys().cloned().collect::<Vec<_>>().join("、")
            ));
        }
        if let Some(path) = original.get_mut("cert") {
            *path = super::path(store, path).to_string_lossy().into_owned();
        }
        let escape = |value: &str| {
            value
                .replace('\\', "\\\\")
                .replace(';', "\\;")
                .replace('=', "\\=")
        };
        let text = original
            .into_iter()
            .map(|(key, value)| format!("{}={}", escape(&key), escape(&value)))
            .collect::<Vec<_>>()
            .join(";");
        output.insert(
            "plugin".to_owned(),
            json!(if name == "obfs" { "obfs-local" } else { name }),
        );
        output.insert("plugin_opts".to_owned(), json!(text));
    } else if core == Core::Mihomo {
        if let Some(fingerprint) = values.remove("client-fingerprint") {
            if name != "restls" {
                return unsupported("当前插件没有客户端握手指纹配置");
            }
            output.insert("client-fingerprint".to_owned(), json!(fingerprint));
        }
        for (key, value) in values {
            if !allowed.contains(&key.as_str()) {
                return unsupported(format!("Mihomo 插件未使用参数：{key}"));
            }
            let value = if key == "headers" {
                let headers: Map<String, Value> = serde_json::from_str(&value)?;
                let mut combined = options
                    .remove("headers")
                    .and_then(|value| value.as_object().cloned())
                    .unwrap_or_default();
                if headers.keys().any(|name| name.eq_ignore_ascii_case("host")) {
                    combined.remove("Host");
                }
                combined.extend(headers);
                json!(combined)
            } else if key == "ech-opts" {
                serde_json::from_str(&value)?
            } else if matches!(key.as_str(), "certificate" | "private-key")
                && !value.contains("-----BEGIN")
            {
                json!(super::path(store, &value))
            } else {
                json!(value)
            };
            options.insert(key, value);
        }
        output.insert("plugin".to_owned(), json!(name));
        output.insert("plugin-opts".to_owned(), json!(options));
    } else {
        return unsupported("Xray Shadowsocks 使用传输设置配置封装");
    }
    Ok(output)
}
