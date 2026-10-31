use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ml_kem::KeyExport;
use serde::{Deserialize, Serialize};

use crate::{
    Result,
    form::{choices, fields},
};

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Server {
    pub authentication: Option<Authentication>,
    pub mode: Mode,
    pub session: Option<String>,
    pub padding: Option<String>,
    pub private_keys: Vec<String>,
}

impl Server {
    pub fn inherit(&mut self, other: &Self) {
        self.authentication = self.authentication.or(other.authentication);
        if self.session.is_none() {
            self.session = other.session.clone();
        }
        if self.padding.is_none() {
            self.padding = other.padding.clone();
        }
        if self.private_keys.is_empty() {
            self.private_keys = other.private_keys.clone();
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum Authentication {
    #[serde(rename = "x25519")]
    X25519,
    #[default]
    #[serde(rename = "ml-kem-768")]
    MlKem768,
}

impl Authentication {
    fn size(self) -> usize {
        match self {
            Self::X25519 => 32,
            Self::MlKem768 => 64,
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Native,
    Xorpub,
    Random,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Xorpub => "xorpub",
            Self::Random => "random",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Keys {
    pub private_keys: Vec<String>,
    pub public_keys: Vec<String>,
}

impl Keys {
    pub fn matches(&self, authentication: Option<Authentication>) -> bool {
        !self.private_keys.is_empty()
            && authentication.is_none_or(|authentication| {
                self.private_keys.iter().all(|key| {
                    URL_SAFE_NO_PAD
                        .decode(key)
                        .is_ok_and(|key| key.len() == authentication.size())
                })
            })
    }

    pub fn resolve(source: &Server, previous: Option<&Self>) -> Result<Self> {
        let private_keys = if !source.private_keys.is_empty() {
            source.private_keys.clone()
        } else if let Some(previous) = previous.filter(|keys| keys.matches(source.authentication)) {
            previous.private_keys.clone()
        } else {
            let mut bytes = vec![0; source.authentication.unwrap_or_default().size()];
            getrandom::fill(&mut bytes).map_err(|error| format!("生成加密材料失败：{error}"))?;
            vec![URL_SAFE_NO_PAD.encode(bytes)]
        };
        let mut public_keys = Vec::new();
        for private in &private_keys {
            let bytes = URL_SAFE_NO_PAD.decode(private)?;
            if source
                .authentication
                .is_some_and(|authentication| bytes.len() != authentication.size())
            {
                return Err("私钥与认证算法不相符".into());
            }
            public_keys.push(match bytes.len() {
                32 => URL_SAFE_NO_PAD.encode(x25519_dalek::x25519(
                    bytes.try_into().unwrap(),
                    x25519_dalek::X25519_BASEPOINT_BYTES,
                )),
                64 => {
                    let seed: [u8; 64] = bytes.try_into().unwrap();
                    let key = ml_kem::DecapsulationKey::<ml_kem::MlKem768>::from_seed(seed.into());
                    URL_SAFE_NO_PAD.encode(key.encapsulation_key().to_bytes())
                }
                _ => return Err("VLESS 加密私钥需要包含 32 或 64 字节".into()),
            });
        }
        Ok(Self {
            private_keys,
            public_keys,
        })
    }
}

choices!(Authentication {
    X25519: "x25519" => "X25519",
    MlKem768: "ml-kem-768" => "ML-KEM-768",
});

choices!(Mode {
    Native: "native" => "原生",
    Xorpub: "xorpub" => "公钥混淆",
    Random: "random" => "完全混淆",
});

fields!(Server {
    authentication: "认证算法",
    mode: "模式",
    session: "会话时长",
    padding: "填充参数",
    private_keys: "私钥",
});
