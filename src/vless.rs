use serde::{Deserialize, Serialize};

use crate::{
    connection::{Core, Network, PacketEncoding, Security, Tls},
    form::{choices, fields},
    inbound::Fallback,
    transport::Transport,
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Client {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub core: Core,
    pub vless: ClientOptions,
    pub security: Security,
    pub transport: Transport,
    pub multiplex: Option<crate::multiplex::Client>,
    pub network: Network,
}

impl Default for Client {
    fn default() -> Self {
        Self {
            name: String::new(),
            server: String::new(),
            port: 443,
            uuid: String::new(),
            core: Core::default(),
            vless: ClientOptions::default(),
            security: Security::Tls(Tls::default()),
            transport: Transport::default(),
            multiplex: None,
            network: Network::default(),
        }
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClientOptions {
    pub flow: Flow,
    pub encryption: Option<String>,
    pub packet_encoding: PacketEncoding,
    pub udp_concurrency: Option<u16>,
    pub tcp: Option<bool>,
    pub udp: Option<bool>,
    pub user_level: Option<u32>,
    pub user_label: Option<String>,
    pub preconnect: Option<u32>,
    pub padding: Vec<u32>,
}

impl ClientOptions {
    pub(crate) fn encrypted(&self) -> bool {
        self.encryption
            .as_deref()
            .is_some_and(|v| !v.is_empty() && v != "none")
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Server {
    pub flow: Flow,
    pub encryption: Option<crate::encryption::Server>,
    pub user_level: Option<u32>,
    pub padding: Vec<u32>,
    pub fallbacks: Vec<Fallback>,
    pub multiplex: Option<crate::multiplex::Server>,
}

#[derive(Clone, Copy, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Flow {
    #[default]
    None,
    Vision,
}

choices!(Flow {
    None: "none" => ("Default", "默认"),
    Vision: "vision" => "Vision",
});

crate::connection::client_fields!(
    Vless,
    Client {
        name: ("Name", "名称"),
        server: ("Address", "地址"),
        port: ("Port", "端口"),
        uuid: "UUID",
        core: ("Core", "核心"),
        vless: "VLESS",
        security: ("Encryption", "加密"),
        transport: ("Transport", "传输"),
        multiplex: ("Multiplexing", "多路复用"),
        network: ("Network", "网络"),
    }
);

fields!(ClientOptions {
    flow: ("Flow", "流模式"),
    encryption: ("Encryption", "加密"),
    packet_encoding: ("UDP packet encoding", "UDP 封装"),
    udp_concurrency: ("UDP concurrency", "UDP 并发流数"),
    tcp: "TCP",
    udp: "UDP",
    user_level: ("User level", "用户等级"),
    user_label: ("User ID", "用户标识"),
    preconnect: ("Preconnections", "预连接数量"),
    padding: ("Vision padding parameters", "Vision 填充参数"),
});

fields!(Server {
    flow: ("Flow", "流模式"),
    encryption: ("Encryption", "加密"),
    user_level: ("User level", "用户等级"),
    padding: ("Vision padding parameters", "Vision 填充参数"),
    fallbacks: ("Fallbacks", "回落"),
    multiplex: "S-Mux",
});
