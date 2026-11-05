use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    Result,
    connection::{self, Core, Network, Tls},
    form::{choices, fields},
    transport::Quic,
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Client {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub core: Core,
    pub hysteria: ClientOptions,
    pub tls: Tls,
    pub network: Network,
}

impl Default for Client {
    fn default() -> Self {
        Self {
            name: String::new(),
            server: String::new(),
            port: 443,
            password: String::new(),
            core: Core::default(),
            hysteria: ClientOptions::default(),
            tls: Tls {
                enabled: true,
                ..Tls::default()
            },
            network: Network::default(),
        }
    }
}

impl Client {
    pub fn port(&self) -> Result<u16> {
        if self.hysteria.ports.is_empty() {
            Ok(self.port)
        } else {
            Ok(*connection::ports(&self.hysteria.ports)?.first().unwrap())
        }
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClientOptions {
    pub tcp: Option<bool>,
    pub udp: Option<bool>,
    pub obfs: Option<Obfs>,
    pub ports: String,
    pub hop_interval: Option<String>,
    pub hop_interval_max: Option<String>,
    pub quic: Quic,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Server {
    pub obfs: Option<Obfs>,
    pub quic: Quic,
    pub client: Quic,
    pub ignore_client_bandwidth: bool,
    pub masquerade: Option<Masquerade>,
    pub user_level: Option<u32>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Obfs {
    pub kind: ObfsKind,
    pub password: String,
    pub min_packet_size: Option<u16>,
    pub max_packet_size: Option<u16>,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObfsKind {
    #[default]
    Salamander,
    Gecko,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Masquerade {
    pub kind: MasqueradeKind,
    pub directory: String,
    pub url: String,
    pub rewrite_host: bool,
    pub forwarded: bool,
    pub verify_certificate: Option<bool>,
    pub status_code: Option<u16>,
    pub headers: BTreeMap<String, Vec<String>>,
    pub content: String,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MasqueradeKind {
    File,
    #[default]
    Proxy,
    String,
}

pub fn password(value: &str) -> Result<()> {
    if value.is_empty() {
        return Err("请填写 Hysteria 2 认证密码".into());
    }
    if value
        .bytes()
        .any(|value| value < 32 && value != b'\t' || value == 127)
    {
        return Err("Hysteria 2 认证密码需要符合 HTTP 字段值格式".into());
    }
    Ok(())
}

fields!(Client {
    name: "名称",
    server: "地址",
    port: "端口",
    password: "密码",
    core: "核心",
    hysteria: "Hysteria 2",
    tls: "TLS",
    network: "网络",
});

fields!(ClientOptions {
    tcp: "TCP",
    udp: "UDP",
    obfs: "混淆",
    ports: "跳跃端口",
    hop_interval: "跳跃间隔",
    hop_interval_max: "最大跳跃间隔",
    quic: "QUIC",
});

fields!(Server {
    obfs: "混淆",
    quic: "QUIC",
    client: "客户端 QUIC",
    ignore_client_bandwidth: "忽略客户端带宽",
    masquerade: "伪装响应",
    user_level: "用户等级",
});

fields!(Obfs {
    kind: "类型",
    password: "密码",
    min_packet_size: "最小数据包",
    max_packet_size: "最大数据包",
});

fields!(Masquerade {
    kind: "类型",
    directory: "文件目录",
    url: "反代目标",
    rewrite_host: "改写主机名",
    forwarded: "转发来源信息",
    verify_certificate: "验证上游证书",
    status_code: "响应状态",
    headers: "响应头",
    content: "响应内容",
});

choices!(ObfsKind {
    Salamander: "salamander" => "Salamander",
    Gecko: "gecko" => "Gecko",
});

choices!(MasqueradeKind {
    File: "file" => "文件",
    Proxy: "proxy" => "HTTP 反代",
    String: "string" => "固定响应",
});
