use serde::{Deserialize, Serialize};

use crate::{
    connection::{Core, Network, PacketEncoding, Security, Tls},
    form::{choices, fields},
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
    pub vmess: ClientOptions,
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
            vmess: ClientOptions::default(),
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
    pub cipher: Cipher,
    pub alter_id: Option<u32>,
    pub global_padding: Option<bool>,
    pub authenticated_length: Option<bool>,
    pub termination_signal: Option<bool>,
    pub packet_encoding: PacketEncoding,
    pub udp_concurrency: Option<u16>,
    pub tcp: Option<bool>,
    pub udp: Option<bool>,
    pub user_level: Option<u32>,
    pub user_label: Option<String>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Server {
    pub alter_id: Option<u32>,
    pub user_level: Option<u32>,
    pub default_user_level: Option<u8>,
    pub multiplex: Option<crate::multiplex::Server>,
}

#[derive(Clone, Copy, Default, PartialEq, Deserialize, Serialize)]
pub enum Cipher {
    #[default]
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[serde(rename = "chacha20-poly1305")]
    Chacha20Poly1305,
    #[serde(rename = "aes-128-cfb")]
    Aes128Cfb,
    #[serde(rename = "none")]
    None,
    #[serde(rename = "zero")]
    Zero,
}

impl Cipher {
    pub fn resolve(self) -> Self {
        if self != Self::Auto {
            return self;
        }
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("pclmulqdq") {
            return Self::Aes128Gcm;
        }
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("aes")
            && std::arch::is_aarch64_feature_detected!("pmull")
        {
            return Self::Aes128Gcm;
        }
        Self::Chacha20Poly1305
    }
}

choices!(Cipher {
    Auto: "auto" => "自动",
    Aes128Gcm: "aes-128-gcm" => "AES-128-GCM",
    Chacha20Poly1305: "chacha20-poly1305" => "ChaCha20-Poly1305",
    Aes128Cfb: "aes-128-cfb" => "AES-128-CFB",
    None: "none" => "明文",
    Zero: "zero" => "明文透传",
});

crate::connection::client_fields!(
    Vmess,
    Client {
        name: "名称",
        server: "地址",
        port: "端口",
        uuid: "UUID",
        core: "核心",
        vmess: "VMess",
        security: "加密",
        transport: "传输",
        multiplex: "多路复用",
        network: "网络",
    }
);

fields!(ClientOptions {
    cipher: "加密算法",
    alter_id: "额外标识数量",
    global_padding: "全局填充",
    authenticated_length: "长度认证",
    termination_signal: "终止信号",
    packet_encoding: "UDP 封装",
    udp_concurrency: "UDP 并发流数",
    tcp: "TCP",
    udp: "UDP",
    user_level: "用户等级",
    user_label: "用户标识",
});

fields!(Server {
    alter_id: "额外标识数量",
    user_level: "用户等级",
    default_user_level: "动态用户等级",
    multiplex: "S-Mux",
});
