use serde::{Deserialize, Serialize};

use crate::{
    connection::{Core, Network, Security},
    form::fields,
    route::Destination,
    transport::Transport,
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Client {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub core: Core,
    pub security: Security,
    pub transport: Transport,
    pub network: Network,
}

impl Default for Client {
    fn default() -> Self {
        Self {
            name: String::new(),
            server: String::new(),
            port: 443,
            core: Core::default(),
            security: Security::None,
            transport: Transport::default(),
            network: Network::default(),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Server {
    pub outbound: Destination,
    pub tcp: bool,
    pub udp: bool,
    pub user_level: Option<u32>,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            outbound: Destination::Block,
            tcp: true,
            udp: true,
            user_level: None,
        }
    }
}

crate::connection::client_fields!(
    Forward,
    Client {
        name: ("Name", "名称"),
        server: ("Address", "地址"),
        port: ("Port", "端口"),
        core: ("Core", "核心"),
        security: ("Encryption", "加密"),
        transport: ("Transport", "传输"),
        network: ("Network", "网络"),
    }
);

fields!(Server {
    tcp: ("Accept TCP", "TCP 接收"),
    udp: ("Accept UDP", "UDP 接收"),
    user_level: ("User level", "用户等级"),
});
