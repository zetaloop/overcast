use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::{
    Result,
    graph::Graph,
    inbound::{Core, Inbound, Protocol},
    progress::Progress,
    shadowsocks::{Authentication, Cipher, Keys, Plugin},
};

use super::{
    listener::{self, Credential, Listener},
    options::Options,
    unsupported,
};

pub fn cipher(value: Cipher, core: Core, inbound: bool) -> Result<Value> {
    if !value.supported(core, inbound) {
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
    value
        .authentication(source.core, source.system_users(), users)
        .named()
}

pub fn authentication(
    source: &Inbound,
    users: &[(String, Credential)],
    options: &mut Options,
    output: &mut Map<String, Value>,
) -> Result<()> {
    let Protocol::Shadowsocks(ss) = &source.protocol else {
        unreachable!()
    };
    match ss.authentication(source.core, source.system_users(), users.len()) {
        Authentication::IdentityKey => {
            output.insert(
                "password".to_owned(),
                options
                    .take("password")
                    .ok_or("缺少 Shadowsocks 入口共享密钥")?,
            );
        }
        Authentication::Users => {}
        Authentication::None => {
            output.remove("users");
        }
        Authentication::Single => {
            output.remove("users");
            let [(_, credential)] = users else {
                return unsupported("当前 Shadowsocks 算法的入站需要单个认证密钥");
            };
            output.insert("password".to_owned(), json!(credential.password));
        }
    }
    Ok(())
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
            .filter(|listener| matches!(&listener.source.protocol, Protocol::Shadowsocks(v) if v.cipher.identity_key(listener.source.core))),
        progress,
    )? {
        if !group.listeners.iter().any(|l| multi(&l.source, l.users.len())) {
            continue;
        }
        let sources: Vec<_> = group
            .entries
            .iter()
            .map(|index| {
                let inbound = graph.entries[*index].inbound;
                let Protocol::Shadowsocks(value) = &inbound.protocol else { unreachable!() };
                let cached = graph.config().keys.get(&inbound.uuid).and_then(|keys| keys.shadowsocks.as_ref())
                    .filter(|keys| keys.cipher.key_size() == value.cipher.key_size());
                (value, value.password.as_ref().or_else(|| cached.map(|keys| &keys.password)))
            })
            .collect();
        let passwords: BTreeSet<_> = sources
            .iter()
            .filter_map(|(source, key)| key.map(|password| source.cipher.password(password)))
            .collect::<Result<_>>()?;
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
        let mut source = sources[0].0.clone();
        source.password = passwords.into_iter().next();
        let material = Keys::resolve(&source)?;
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
    directory: &std::path::Path,
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
            if cert.is_some() && raw.is_some() {
                return Err("v2ray-plugin 的同一份证书请选择 cert 路径或 certRaw 正文".into());
            }
            if core == Core::Mihomo && tls {
                if cert.is_some() {
                    return unsupported(
                        "Mihomo v2ray-plugin 的信任证书使用 certRaw 正文，不支持 cert 路径",
                    );
                }
                if let Some(raw) = raw {
                    globals.insert("tls".to_owned(), json!({"custom-certifactes": [raw]}));
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
            *path = directory.join(&*path).to_string_lossy().into_owned();
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
                json!(directory.join(&value))
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
