use serde::{Deserialize, Serialize};

use crate::{
    connection::{Core, Network, Security, Tls},
    form::fields,
    inbound::Fallback,
    transport::Transport,
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Client {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub core: Core,
    pub trojan: ClientOptions,
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
            password: String::new(),
            core: Core::default(),
            trojan: ClientOptions::default(),
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
    pub tcp: Option<bool>,
    pub udp: Option<bool>,
    pub user_level: Option<u8>,
    pub user_label: Option<String>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Server {
    pub user_level: Option<u8>,
    pub fallbacks: Vec<Fallback>,
    pub multiplex: Option<crate::multiplex::Server>,
}

crate::connection::client_fields!(
    Trojan,
    Client {
        name: ("Name", "名称"),
        server: ("Address", "地址"),
        port: ("Port", "端口"),
        password: ("Password", "密码"),
        core: ("Core", "核心"),
        trojan: "Trojan",
        security: ("Encryption", "加密"),
        transport: ("Transport", "传输"),
        multiplex: ("Multiplexing", "多路复用"),
        network: ("Network", "网络"),
    }
);

fields!(ClientOptions {
    tcp: "TCP",
    udp: "UDP",
    user_level: ("User level", "用户等级"),
    user_label: ("User ID", "用户标识"),
});

fields!(Server {
    user_level: ("User level", "用户等级"),
    fallbacks: ("Fallbacks", "回落"),
    multiplex: "S-Mux",
});
