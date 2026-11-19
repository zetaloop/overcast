use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    Result,
    connection::{Core, Network, Security},
    form::{self, Form, Value, choices, fields},
    inbound::Core as ServerCore,
    transport::Transport,
    tui::Screen,
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Client {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub core: Core,
    pub shadowsocks: ClientOptions,
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
            port: 8388,
            password: String::new(),
            core: Core::default(),
            shadowsocks: ClientOptions::default(),
            security: Security::None,
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
    pub tcp: Option<bool>,
    pub udp: Option<bool>,
    pub udp_over_tcp: Option<u8>,
    pub plugin: Option<Plugin>,
    pub user_level: Option<u8>,
    pub user_label: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Server {
    pub cipher: Cipher,
    pub tcp: bool,
    pub udp: bool,
    pub password: Option<String>,
    pub user_level: Option<u8>,
    pub multiplex: Option<crate::multiplex::Server>,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            cipher: Cipher::default(),
            tcp: true,
            udp: true,
            password: None,
            user_level: None,
            multiplex: None,
        }
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Plugin {
    pub name: String,
    pub options: String,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum Cipher {
    #[default]
    #[serde(rename = "2022-blake3-aes-128-gcm")]
    Aes128Gcm2022,
    #[serde(rename = "2022-blake3-aes-256-gcm")]
    Aes256Gcm2022,
    #[serde(rename = "2022-blake3-aes-128-ccm")]
    Aes128Ccm2022,
    #[serde(rename = "2022-blake3-aes-256-ccm")]
    Aes256Ccm2022,
    #[serde(rename = "2022-blake3-chacha20-poly1305")]
    Chacha20Poly13052022,
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[serde(rename = "aes-192-gcm")]
    Aes192Gcm,
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[serde(rename = "chacha20-ietf-poly1305", alias = "chacha20-poly1305")]
    Chacha20Poly1305,
    #[serde(rename = "xchacha20-ietf-poly1305", alias = "xchacha20-poly1305")]
    Xchacha20Poly1305,
    #[serde(rename = "chacha8-ietf-poly1305", alias = "chacha8-poly1305")]
    Chacha8Poly1305,
    #[serde(rename = "xchacha8-ietf-poly1305", alias = "xchacha8-poly1305")]
    Xchacha8Poly1305,
    #[serde(rename = "rabbit128-poly1305")]
    Rabbit128Poly1305,
    #[serde(rename = "aes-128-ccm")]
    Aes128Ccm,
    #[serde(rename = "aes-192-ccm")]
    Aes192Ccm,
    #[serde(rename = "aes-256-ccm")]
    Aes256Ccm,
    #[serde(rename = "aes-128-gcm-siv")]
    Aes128GcmSiv,
    #[serde(rename = "aes-256-gcm-siv")]
    Aes256GcmSiv,
    #[serde(rename = "aegis-128l")]
    Aegis128l,
    #[serde(rename = "aegis-256")]
    Aegis256,
    #[serde(rename = "aez-384")]
    Aez384,
    #[serde(rename = "deoxys-ii-256-128")]
    DeoxysII256128,
    #[serde(rename = "lea-128-gcm")]
    Lea128Gcm,
    #[serde(rename = "lea-192-gcm")]
    Lea192Gcm,
    #[serde(rename = "lea-256-gcm")]
    Lea256Gcm,
    #[serde(rename = "ascon128")]
    Ascon128,
    #[serde(rename = "ascon128a")]
    Ascon128a,
    #[serde(rename = "aes-128-ctr")]
    Aes128Ctr,
    #[serde(rename = "aes-192-ctr")]
    Aes192Ctr,
    #[serde(rename = "aes-256-ctr")]
    Aes256Ctr,
    #[serde(rename = "aes-128-cfb")]
    Aes128Cfb,
    #[serde(rename = "aes-192-cfb")]
    Aes192Cfb,
    #[serde(rename = "aes-256-cfb")]
    Aes256Cfb,
    #[serde(rename = "rc4-md5")]
    Rc4Md5,
    #[serde(rename = "chacha20")]
    Chacha20,
    #[serde(rename = "chacha20-ietf")]
    Chacha20Ietf,
    #[serde(rename = "xchacha20")]
    Xchacha20,
    #[serde(rename = "none", alias = "dummy")]
    None,
}

impl Cipher {
    pub fn supported(self, core: ServerCore, inbound: bool) -> bool {
        let aead = self.aead(core) || self.identity_key(core) || self == Self::Chacha20Poly13052022;
        match core {
            ServerCore::Xray => aead,
            ServerCore::SingBox => {
                aead || self == Self::None
                    || !inbound
                        && matches!(
                            self,
                            Self::Aes128Ctr
                                | Self::Aes192Ctr
                                | Self::Aes256Ctr
                                | Self::Aes128Cfb
                                | Self::Aes192Cfb
                                | Self::Aes256Cfb
                                | Self::Rc4Md5
                                | Self::Chacha20Ietf
                                | Self::Xchacha20
                        )
            }
            ServerCore::Mihomo => true,
        }
    }

    pub fn key_size(self) -> Option<usize> {
        match self {
            Self::Aes128Gcm2022 | Self::Aes128Ccm2022 => Some(16),
            Self::Aes256Gcm2022 | Self::Aes256Ccm2022 | Self::Chacha20Poly13052022 => Some(32),
            _ => None,
        }
    }

    pub fn identity_key(self, core: ServerCore) -> bool {
        match self {
            Self::Aes128Gcm2022 | Self::Aes256Gcm2022 => true,
            Self::Aes128Ccm2022 | Self::Aes256Ccm2022 => core == ServerCore::Mihomo,
            _ => false,
        }
    }

    pub fn authentication(self, core: ServerCore) -> Authentication {
        if self == Self::None {
            Authentication::None
        } else if self.identity_key(core) {
            Authentication::IdentityKey
        } else if self.aead(core) {
            Authentication::Users
        } else {
            Authentication::Single
        }
    }

    pub fn aead(self, core: ServerCore) -> bool {
        match self {
            Self::Aes192Gcm => core != ServerCore::Xray,
            Self::Aes128Gcm
            | Self::Aes256Gcm
            | Self::Chacha20Poly1305
            | Self::Xchacha20Poly1305 => true,
            Self::Chacha8Poly1305
            | Self::Xchacha8Poly1305
            | Self::Rabbit128Poly1305
            | Self::Aes128Ccm
            | Self::Aes192Ccm
            | Self::Aes256Ccm
            | Self::Aes128GcmSiv
            | Self::Aes256GcmSiv
            | Self::Aegis128l
            | Self::Aegis256
            | Self::Aez384
            | Self::DeoxysII256128
            | Self::Lea128Gcm
            | Self::Lea192Gcm
            | Self::Lea256Gcm
            | Self::Ascon128
            | Self::Ascon128a => core == ServerCore::Mihomo,
            _ => false,
        }
    }

    pub fn credential(self, password: &str) -> String {
        if let Some(size) = self.key_size() {
            STANDARD.encode(&Sha256::digest(password.as_bytes())[..size])
        } else if self == Self::None {
            String::new()
        } else {
            password.to_owned()
        }
    }

    pub fn password(self, value: &str) -> Result<String> {
        let Some(size) = self.key_size() else {
            return Ok(value.to_owned());
        };
        let mut keys = Vec::new();
        for value in value.split(':') {
            let mut key = match crate::link::decode(value) {
                Ok(key) => key,
                Err(_) if value.len() == size => value.as_bytes().to_vec(),
                Err(error) => return Err(format!("Shadowsocks 密钥编码不正确：{error}").into()),
            };
            if key.len() < size {
                return Err(format!(
                    "Shadowsocks 密钥需要 {size} 字节，当前为 {} 字节",
                    key.len()
                )
                .into());
            }
            if key.len() > size {
                key = Sha256::digest(&key)[..size].to_vec();
            }
            keys.push(STANDARD.encode(key));
        }
        if self == Self::Chacha20Poly13052022 && keys.len() > 1 {
            return Err("Shadowsocks 2022 ChaCha20-Poly1305 使用单个密钥".into());
        }
        Ok(keys.join(":"))
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Keys {
    pub cipher: Cipher,
    pub password: String,
}

impl Keys {
    pub fn apply(&self, source: &mut Server, core: ServerCore) {
        if source.cipher.identity_key(core) && source.cipher.key_size() == self.cipher.key_size() {
            source.password = Some(self.password.clone());
        }
    }

    pub fn resolve(source: &Server) -> Result<Self> {
        let size = source.cipher.key_size().ok_or("当前算法使用用户密码")?;
        let password = if let Some(password) = &source.password {
            source.cipher.password(password)?
        } else {
            let mut bytes = vec![0; size];
            getrandom::fill(&mut bytes)
                .map_err(|error| format!("生成 Shadowsocks 入口密钥失败：{error}"))?;
            STANDARD.encode(bytes)
        };
        if password.contains(':') {
            return Err("Shadowsocks 入口共享密钥需要单个密钥".into());
        }
        Ok(Self {
            cipher: source.cipher,
            password,
        })
    }
}

fields!(Client {
    name: "名称",
    server: "地址",
    port: "端口",
    password: "密码",
    core: "核心",
    shadowsocks: "Shadowsocks",
    security: "加密",
    transport: "传输",
    multiplex: "多路复用",
    network: "网络",
});

fields!(ClientOptions {
    cipher: "算法",
    tcp: "TCP",
    udp: "UDP",
    udp_over_tcp: "UDP over TCP",
    plugin: "SIP003 插件",
    user_level: "用户等级",
    user_label: "用户标识",
});

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Authentication {
    None,
    Single,
    Users,
    IdentityKey,
}

impl Authentication {
    pub fn named(self) -> bool {
        matches!(self, Self::Users | Self::IdentityKey)
    }
}

impl Server {
    pub fn authentication(
        &self,
        core: ServerCore,
        system_users: bool,
        accounts: usize,
    ) -> Authentication {
        let mode = self.cipher.authentication(core);
        match mode {
            Authentication::IdentityKey if self.password.is_some() => mode,
            _ if mode.named() && !system_users && accounts <= 1 => Authentication::Single,
            _ => mode,
        }
    }

    fn fields_for(&self, core: ServerCore) -> impl Fn(&str) -> bool + use<> {
        let cipher = if self.cipher.supported(core, true) {
            self.cipher
        } else {
            Cipher::default()
        };
        move |key| match key {
            "tcp" => core != ServerCore::Mihomo,
            "password" => cipher.identity_key(core),
            "user_level" => core == ServerCore::Xray,
            "multiplex" => core != ServerCore::Xray,
            _ => true,
        }
    }

    fn fields(&mut self, core: ServerCore) -> form::Fields<'_> {
        let d = Self::default();
        vec![
            form::choice_field("cipher", "算法", &mut self.cipher, d.cipher, move |v| {
                v.supported(core, true)
            }),
            form::field("tcp", "TCP 接收", &mut self.tcp, d.tcp),
            form::field("udp", "UDP 接收", &mut self.udp, d.udp),
            form::field("password", "入口共享密钥", &mut self.password, d.password),
            form::field("user_level", "用户等级", &mut self.user_level, d.user_level),
            form::field("multiplex", "S-Mux", &mut self.multiplex, d.multiplex),
        ]
    }

    pub fn fit(&mut self, core: ServerCore) {
        if !self.cipher.supported(core, true) {
            self.cipher = Cipher::default();
        }
        let allowed = self.fields_for(core);
        for mut field in self.fields(core) {
            if !allowed(field.key()) {
                field.reset();
            }
        }
    }

    pub fn validate(&self, core: ServerCore) -> Result<()> {
        if !self.cipher.supported(core, true) {
            return Err(format!(
                "{} 的 Shadowsocks 入站不支持 {}",
                core.text(),
                self.cipher.text()
            )
            .into());
        }
        let allowed = self.fields_for(core);
        for (key, label, set) in [
            ("tcp", "关闭 TCP 接收", !self.tcp),
            ("password", "入口共享密钥", self.password.is_some()),
            ("user_level", "用户等级", self.user_level.is_some()),
            ("multiplex", "S-Mux", self.multiplex.is_some()),
        ] {
            if set && !allowed(key) {
                return Err(format!(
                    "{} 的 {} 入站不支持{label}",
                    core.text(),
                    self.cipher.text()
                )
                .into());
            }
        }
        if let Some(password) = &self.password {
            let key = self.cipher.password(password)?;
            if key.contains(':') {
                return Err("Shadowsocks 入口共享密钥需要单个密钥".into());
            }
        }
        Ok(())
    }

    pub fn edit(&mut self, screen: &mut Screen, title: &str, core: ServerCore) -> Result<bool> {
        let mut page = (std::mem::take(self), core);
        let result = form::edit(screen, title, &mut page);
        *self = page.0;
        result
    }
}

impl Form for (Server, ServerCore) {
    fn fields(&mut self, _: Self) -> form::Fields<'_> {
        let allowed = self.0.fields_for(self.1);
        self.0
            .fields(self.1)
            .into_iter()
            .filter(|field| allowed(field.key()))
            .collect()
    }
}

fields!(Plugin {
    name: "名称",
    options: "参数",
});

choices!(Cipher {
    Aes128Gcm2022: "2022-blake3-aes-128-gcm" => "2022-blake3-aes-128-gcm",
    Aes256Gcm2022: "2022-blake3-aes-256-gcm" => "2022-blake3-aes-256-gcm",
    Aes128Ccm2022: "2022-blake3-aes-128-ccm" => "2022-blake3-aes-128-ccm",
    Aes256Ccm2022: "2022-blake3-aes-256-ccm" => "2022-blake3-aes-256-ccm",
    Chacha20Poly13052022: "2022-blake3-chacha20-poly1305" => "2022-blake3-chacha20-poly1305",
    Aes128Gcm: "aes-128-gcm" => "aes-128-gcm",
    Aes192Gcm: "aes-192-gcm" => "aes-192-gcm",
    Aes256Gcm: "aes-256-gcm" => "aes-256-gcm",
    Chacha20Poly1305: "chacha20-ietf-poly1305" => "chacha20-ietf-poly1305",
    Xchacha20Poly1305: "xchacha20-ietf-poly1305" => "xchacha20-ietf-poly1305",
    Chacha8Poly1305: "chacha8-ietf-poly1305" => "chacha8-ietf-poly1305",
    Xchacha8Poly1305: "xchacha8-ietf-poly1305" => "xchacha8-ietf-poly1305",
    Rabbit128Poly1305: "rabbit128-poly1305" => "rabbit128-poly1305",
    Aes128Ccm: "aes-128-ccm" => "aes-128-ccm",
    Aes192Ccm: "aes-192-ccm" => "aes-192-ccm",
    Aes256Ccm: "aes-256-ccm" => "aes-256-ccm",
    Aes128GcmSiv: "aes-128-gcm-siv" => "aes-128-gcm-siv",
    Aes256GcmSiv: "aes-256-gcm-siv" => "aes-256-gcm-siv",
    Aegis128l: "aegis-128l" => "aegis-128l",
    Aegis256: "aegis-256" => "aegis-256",
    Aez384: "aez-384" => "aez-384",
    DeoxysII256128: "deoxys-ii-256-128" => "deoxys-ii-256-128",
    Lea128Gcm: "lea-128-gcm" => "lea-128-gcm",
    Lea192Gcm: "lea-192-gcm" => "lea-192-gcm",
    Lea256Gcm: "lea-256-gcm" => "lea-256-gcm",
    Ascon128: "ascon128" => "ascon128",
    Ascon128a: "ascon128a" => "ascon128a",
    Aes128Ctr: "aes-128-ctr" => "aes-128-ctr",
    Aes192Ctr: "aes-192-ctr" => "aes-192-ctr",
    Aes256Ctr: "aes-256-ctr" => "aes-256-ctr",
    Aes128Cfb: "aes-128-cfb" => "aes-128-cfb",
    Aes192Cfb: "aes-192-cfb" => "aes-192-cfb",
    Aes256Cfb: "aes-256-cfb" => "aes-256-cfb",
    Rc4Md5: "rc4-md5" => "rc4-md5",
    Chacha20: "chacha20" => "chacha20",
    Chacha20Ietf: "chacha20-ietf" => "chacha20-ietf",
    Xchacha20: "xchacha20" => "xchacha20",
    None: "none" => "无",
});
