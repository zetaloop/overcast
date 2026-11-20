use std::{net::IpAddr, time::Duration};

use serde_json::{Map, Value, json};

use crate::{
    Result,
    connection::FastOpen,
    transport::Congestion,
    warp::{Client, Mode},
};

use super::{options::Options, single_headers, unsupported};

pub fn xray(source: &Client, input: super::parameters::Input<'_>) -> Result<Map<String, Value>> {
    let value = &source.warp;
    let mut options = Options::new(value)?;
    for name in ["mode", "tcp", "udp", "remote_dns", "quic"] {
        options.take(name);
    }
    if value
        .remote_dns
        .iter()
        .any(|server| server.parse::<IpAddr>().is_err())
    {
        return unsupported("Xray WARP 的远端 DNS 使用 IP 地址");
    }
    let mut tls = Map::from_iter([
        (
            "alpn".to_owned(),
            json!([if value.mode == Mode::Http2 {
                "h2"
            } else {
                "h3"
            }]),
        ),
        (
            "serverName".to_owned(),
            options
                .take("server_name")
                .unwrap_or(json!("consumer-masque.cloudflareclient.com")),
        ),
    ]);
    options.invert(&mut tls, "verify_certificate", "allowInsecure");
    if value.mode == Mode::Http2 {
        options.copy(&mut tls, &["fingerprint"]);
    }
    let mut masque = Map::new();
    if let Some(registration) = input.material(|| {
        Ok(json!({
            "privateKey": source.registration.private_key,
            "publicKey": source.registration.public_key()?,
            "address": source.registration.addresses()?,
        }))
    })? {
        masque.insert("warp".to_owned(), registration);
    }
    options.copy(&mut masque, &["host", "path"]);
    if options.take("headers").is_some() {
        masque.insert("headers".to_owned(), json!(single_headers(&value.headers)?));
    }
    let mut pool = Map::new();
    if let Some(value) = options.take("keep_alive") {
        pool.insert(
            "hKeepAlivePeriod".to_owned(),
            json!(super::transport::duration(
                value.as_str().unwrap(),
                Duration::from_secs(1)
            )?),
        );
    }
    if !pool.is_empty() {
        masque.insert("xmux".to_owned(), json!(pool));
    }
    options.finish("Xray WARP")?;
    let mut output = Map::from_iter([
        ("network".to_owned(), json!("masque")),
        ("security".to_owned(), json!("tls")),
        ("tlsSettings".to_owned(), json!(tls)),
        ("masqueSettings".to_owned(), json!(masque)),
    ]);
    let mut options = Options::new(&value.quic)?;
    let quic = if value.mode == Mode::Http3 {
        for name in [
            "download_bandwidth",
            "chrome_fingerprint",
            "incoming_streams",
            "stateless_reset",
        ] {
            if options.take(name).is_some() {
                return unsupported(format!("Xray WARP QUIC 无法表达参数：{name}"));
            }
        }
        super::transport::quic(&value.quic, false)?
    } else {
        options.finish("Xray WARP QUIC")?;
        Map::new()
    };
    if !quic.is_empty() {
        output.insert("finalmask".to_owned(), json!({"quicParams": quic}));
    }
    Ok(output)
}

pub fn mihomo(source: &Client, input: super::parameters::Input<'_>) -> Result<Map<String, Value>> {
    let value = &source.warp;
    if value.mode == Mode::Http2
        && (matches!(source.network.tcp_fast_open, Some(FastOpen::Enabled(true)))
            || source.network.tcp_multi_path == Some(true))
    {
        return unsupported("Mihomo WARP 没有 TCP Fast Open 和 MPTCP 配置");
    }
    let mut options = Options::new(value)?;
    for name in ["mode", "tcp", "udp", "remote_dns", "quic", "stack"] {
        options.take(name);
    }
    let mut output = Map::from_iter([("udp".to_owned(), json!(value.udp.unwrap_or(true)))]);
    if let Some(public) = input.material(|| source.registration.public_key())? {
        output.insert("public-key".to_owned(), json!(public));
        output.insert(
            "private-key".to_owned(),
            json!(source.registration.private_key),
        );
    }
    if !source.registration.ipv4.is_empty() {
        output.insert("ip".to_owned(), json!(source.registration.ipv4));
    }
    if !source.registration.ipv6.is_empty() {
        output.insert("ipv6".to_owned(), json!(source.registration.ipv6));
    }
    if value.mode == Mode::Http2 {
        output.insert("network".to_owned(), json!("h2"));
    }
    options.rename(&mut output, &[("server_name", "sni"), ("mtu", "mtu")]);
    options.invert(&mut output, "verify_certificate", "skip-cert-verify");
    options.durations(
        &mut output,
        &[("handshake_timeout", "handshake-timeout")],
        Some(Duration::from_secs(1)),
    )?;
    options.take("host");
    options.take("path");
    if value.host.is_some() || value.path.is_some() {
        output.insert(
            "uri".to_owned(),
            json!(format!(
                "https://{}{}",
                value.host.as_deref().unwrap_or("cloudflareaccess.com"),
                value.path.as_deref().unwrap_or("/")
            )),
        );
    }
    if !value.remote_dns.is_empty() {
        output.insert("remote-dns-resolve".to_owned(), json!(true));
        output.insert("dns".to_owned(), json!(value.remote_dns));
    }
    options.finish("Mihomo WARP")?;
    let mut options = Options::new(&value.stack)?;
    let mut stack = Map::new();
    options.copy(&mut stack, &["mode"]);
    options.rename(&mut stack, &[("congestion", "congestion-controller")]);
    options.finish("Mihomo IP 协议栈")?;
    if !stack.is_empty() {
        output.insert("ip-stack".to_owned(), json!(stack));
    }
    let mut options = Options::new(&value.quic)?;
    if value.mode == Mode::Http3 {
        if options.take("congestion").is_some() {
            let congestion = value.quic.congestion;
            let name = match congestion {
                Congestion::Bbr => "bbr",
                Congestion::Reno => "new_reno",
                Congestion::Cubic => "cubic",
                _ => return unsupported("Mihomo WARP 使用 BBR、Reno 或 Cubic"),
            };
            output.insert("congestion-controller".to_owned(), json!(name));
        }
        options.rename(
            &mut output,
            &[("bbr_profile", "bbr-profile"), ("cwnd", "cwnd")],
        );
    }
    options.finish("Mihomo WARP QUIC")?;
    Ok(output)
}
