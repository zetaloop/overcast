use serde::{Deserialize, Serialize};

use crate::{
    connection::{Core, Network, Security, Tls},
    form::{self, Value, fields},
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
    pub security: Security,
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
            security: Security::Tls(Tls::default()),
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

impl Client {
    pub fn security(&self) -> Security {
        match &self.security {
            Security::Reality(_) if self.core == Core::Mihomo => Security::Tls(Tls::default()),
            value => value.clone(),
        }
    }
}

impl form::Form for Client {
    fn fields(&mut self, d: Self) -> form::Fields<'_> {
        let modes: &[usize] = if self.core == Core::Mihomo {
            &[1]
        } else {
            &[1, 2]
        };
        let mut active = self.security();
        vec![
            form::field("name", "名称", &mut self.name, d.name),
            form::field("server", "地址", &mut self.server, d.server),
            form::field("port", "端口", &mut self.port, d.port),
            form::field("password", "密码", &mut self.password, d.password),
            form::choice_field("core", "核心", &mut self.core, d.core, |core| {
                *core != Core::Xray
            }),
            form::control(
                "security",
                "握手",
                &mut self.security,
                d.security,
                Some(active.text()),
                move |value, screen, menu, _| {
                    let changed = active.choose(
                        screen,
                        &format!("{} / 握手", menu.title),
                        modes,
                        form::edit,
                    )?;
                    if changed {
                        *value = active.clone();
                    }
                    Ok(changed)
                },
            ),
            form::field("anytls", "会话参数", &mut self.anytls, d.anytls),
            form::field("network", "网络", &mut self.network, d.network),
        ]
    }
}

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
