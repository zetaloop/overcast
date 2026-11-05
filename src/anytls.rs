use serde::{Deserialize, Serialize};

use crate::{
    connection::{Core, Network, Tls},
    form::fields,
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Client {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub core: Core,
    pub anytls: ClientOptions,
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
            anytls: ClientOptions::default(),
            tls: Tls {
                enabled: true,
                ..Tls::default()
            },
            network: Network::default(),
        }
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClientOptions {
    pub tcp: Option<bool>,
    pub udp: Option<bool>,
    pub idle_session_check_interval: Option<String>,
    pub idle_session_timeout: Option<String>,
    pub min_idle_session: Option<u32>,
    pub reuse: Option<bool>,
    pub client_metadata: Option<String>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Server {
    pub padding_scheme: Vec<String>,
}

fields!(Client {
    name: "名称",
    server: "地址",
    port: "端口",
    password: "密码",
    core: "核心",
    anytls: "AnyTLS",
    tls: "TLS",
    network: "网络",
});

fields!(ClientOptions {
    tcp: "TCP",
    udp: "UDP",
    idle_session_check_interval: "空闲会话检查间隔",
    idle_session_timeout: "空闲会话超时",
    min_idle_session: "保留空闲会话数",
    reuse: "复用连接",
    client_metadata: "客户端标识",
});

fields!(Server {
    padding_scheme: "填充方案",
});
