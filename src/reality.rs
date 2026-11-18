use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::{Result, connection::Network, form::fields, route::Destination};

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Client {
    pub tls: crate::connection::Tls,
    pub public_key: String,
    pub short_id: String,
    pub signature_key: Option<String>,
    pub spider_path: Option<String>,
    pub hybrid_key_exchange: Option<bool>,
    pub debug: bool,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Server {
    pub tls: crate::inbound::Tls,
    pub target: String,
    pub target_network: Option<String>,
    pub network: Network,
    pub outbound: Option<Destination>,
    pub server_names: Vec<String>,
    pub private_key: Option<String>,
    pub short_ids: Vec<String>,
    pub max_time_difference: Option<String>,
    pub proxy_protocol: Option<u8>,
    pub min_client_version: Option<String>,
    pub max_client_version: Option<String>,
    pub signature: bool,
    pub signature_seed: Option<String>,
    pub upload: Limit,
    pub download: Limit,
    pub debug: bool,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limit {
    pub after_bytes: Option<u64>,
    pub bytes_per_second: Option<u64>,
    pub burst_bytes_per_second: Option<u64>,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Keys {
    pub private_key: String,
    pub public_key: String,
    pub short_ids: Vec<String>,
    pub signature_seed: Option<String>,
    pub signature_key: Option<String>,
}

impl Keys {
    pub fn values(&self) -> Vec<(&'static str, &'static str, String)> {
        let mut values = vec![
            ("public-key", "公钥", self.public_key.clone()),
            ("short-ids", "短标识", self.short_ids.join(",")),
            ("private-key", "私钥", self.private_key.clone()),
        ];
        if let Some(value) = &self.signature_key {
            values.push(("signature-key", "ML-DSA-65 公钥", value.clone()));
        }
        if let Some(value) = &self.signature_seed {
            values.push(("signature-seed", "签名种子", value.clone()));
        }
        values
    }

    pub fn resolve(source: &Server, previous: Option<&Self>) -> Result<Self> {
        let private_key = match source
            .private_key
            .as_ref()
            .or_else(|| previous.map(|keys| &keys.private_key))
        {
            Some(value) => value.clone(),
            None => URL_SAFE_NO_PAD.encode(random::<32>()?),
        };
        let bytes = key(&private_key)?;
        let public_key = URL_SAFE_NO_PAD.encode(x25519_dalek::x25519(
            bytes,
            x25519_dalek::X25519_BASEPOINT_BYTES,
        ));
        let short_ids = if !source.short_ids.is_empty() {
            source.short_ids.clone()
        } else if let Some(previous) = previous {
            previous.short_ids.clone()
        } else {
            vec![
                random::<8>()?
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
            ]
        };
        for value in &short_ids {
            short_id(value)?;
        }
        let mut signature_seed = previous.and_then(|keys| keys.signature_seed.clone());
        let mut signature_key = previous.and_then(|keys| keys.signature_key.clone());
        if source.signature {
            let seed = match source.signature_seed.as_ref().or(signature_seed.as_ref()) {
                Some(value) => value.clone(),
                None => URL_SAFE_NO_PAD.encode(random::<32>()?),
            };
            if seed == private_key {
                return Err("REALITY 签名种子与握手私钥需要使用不同的值".into());
            }
            let signing = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&key(&seed)?.into());
            let verifying: &ml_dsa::VerifyingKey<ml_dsa::MlDsa65> = signing.as_ref();
            signature_key = Some(URL_SAFE_NO_PAD.encode(verifying.encode()));
            signature_seed = Some(seed);
        }
        Ok(Self {
            private_key,
            public_key,
            short_ids,
            signature_seed,
            signature_key,
        })
    }

    pub fn apply(&self, source: &mut Server) {
        source.private_key = Some(self.private_key.clone());
        source.short_ids = self.short_ids.clone();
        if source.signature {
            source.signature_seed = self.signature_seed.clone();
        }
    }
}

impl Client {
    pub fn validate(&self) -> Result<()> {
        key(&self.public_key)?;
        short_id(&self.short_id)?;
        if let Some(value) = &self.signature_key
            && URL_SAFE_NO_PAD.decode(value)?.len() != 1952
        {
            return Err("ML-DSA-65 公钥需要包含 1952 字节".into());
        }
        Ok(())
    }
}

impl Server {
    pub fn use_names(&mut self) {
        if let Some(name) = self.tls.server_name.take()
            && self.server_names.is_empty()
        {
            self.server_names.push(name);
        }
    }

    pub fn fields_for(&self, core: crate::inbound::Core) -> impl Fn(&str) -> bool + use<> {
        use crate::inbound::Core;
        let blocked = self.outbound == Some(Destination::Block);
        move |field| match field {
            "target" | "server_names" | "private_key" | "short_ids" | "max_time_difference" => true,
            "outbound" => core != Core::Xray || blocked,
            "network" | "alpn" | "min_version" | "max_version" | "cipher_suites"
            | "handshake_timeout" | "kernel_tx" | "kernel_rx" => core == Core::SingBox,
            "upload" | "download" => core != Core::SingBox,
            "key_log" | "target_network" | "proxy_protocol" | "min_client_version"
            | "max_client_version" | "signature" | "signature_seed" | "debug" => core == Core::Xray,
            _ => false,
        }
    }

    pub fn endpoint(&self) -> Result<Option<(String, u16)>> {
        if self.target.is_empty() {
            return Err("请填写 REALITY 握手目标".into());
        }
        if self.target.starts_with('@') || std::path::Path::new(&self.target).is_absolute() {
            return Ok(None);
        }
        if let Ok(port) = self.target.parse::<u16>() {
            if port == 0 {
                return Err("REALITY 握手目标端口不能为零".into());
            }
            return Ok(Some(("127.0.0.1".to_owned(), port)));
        }
        if let Ok(address) = self.target.parse::<std::net::IpAddr>() {
            return Ok(Some((address.to_string(), 443)));
        }
        let url = url::Url::parse(&format!("tcp://{}", self.target))?;
        if !url.username().is_empty()
            || url.password().is_some()
            || !url.path().is_empty()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("REALITY 握手目标需要填写主机与端口".into());
        }
        let host = match url.host().ok_or("REALITY 握手目标缺少主机名")? {
            url::Host::Domain(value) => value.to_owned(),
            url::Host::Ipv4(value) => value.to_string(),
            url::Host::Ipv6(value) => value.to_string(),
        };
        let port = url.port().unwrap_or(443);
        if port == 0 {
            return Err("REALITY 握手目标端口不能为零".into());
        }
        Ok(Some((host, port)))
    }

    pub fn names(&self, name: Option<&str>) -> Result<Vec<String>> {
        let mut names = if self.server_names.is_empty() {
            vec![match name {
                Some(name) => name.to_owned(),
                None => {
                    self.endpoint()?
                        .ok_or("Unix 握手目标需要指定 REALITY 服务名")?
                        .0
                }
            }]
        } else {
            self.server_names.clone()
        };
        names.sort();
        names.dedup();
        Ok(names)
    }

    pub fn address(&self) -> Result<String> {
        Ok(match self.endpoint()? {
            Some((host, port)) if host.contains(':') => format!("[{host}]:{port}"),
            Some((host, port)) => format!("{host}:{port}"),
            None => self.target.clone(),
        })
    }
}

fn key(value: &str) -> Result<[u8; 32]> {
    URL_SAFE_NO_PAD
        .decode(value)?
        .try_into()
        .map_err(|_| "X25519 私钥、公钥及 ML-DSA 种子需要包含 32 字节".into())
}

fn short_id(value: &str) -> Result<()> {
    if value.len() > 16
        || !value.len().is_multiple_of(2)
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("REALITY 短标识需要填写不超过 8 字节的十六进制字符串".into());
    }
    Ok(())
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|error| format!("生成握手材料失败：{error}"))?;
    Ok(bytes)
}

fields!(Client {
    tls: "TLS",
    public_key: "公钥",
    short_id: "短标识",
    signature_key: "ML-DSA-65 公钥",
    spider_path: "探测路径",
    hybrid_key_exchange: "混合密钥交换",
    debug: "调试",
});

fields!(Server {
    tls: ..,
    target: "握手目标",
    target_network: "目标网络类型",
    network: "目标连接参数",
    outbound: "经出站连接",
    server_names: "服务名",
    private_key: "私钥",
    short_ids: "短标识",
    max_time_difference: "时间偏差",
    proxy_protocol: "PROXY protocol 版本",
    min_client_version: "最低客户端版本",
    max_client_version: "最高客户端版本",
    signature: "ML-DSA-65 签名",
    signature_seed: "签名种子",
    upload: "回落上传",
    download: "回落下载",
    debug: "调试",
} groups {
    authentication: "认证材料" => [private_key, short_ids, signature, signature_seed],
    target_options: "目标连接" => [target_network, network, outbound, proxy_protocol],
    clients: "客户端限制" => [min_client_version, max_client_version, max_time_difference],
    fallback: "回落限速" => [upload, download],
});

fields!(Limit {
    after_bytes: "起始字节数",
    bytes_per_second: "每秒字节数",
    burst_bytes_per_second: "突发每秒字节数",
});

impl crate::security::Handshake<crate::connection::Tls> for Client {
    fn tls(&self) -> &crate::connection::Tls {
        &self.tls
    }

    fn tls_mut(&mut self) -> &mut crate::connection::Tls {
        &mut self.tls
    }
}

impl crate::security::Handshake<crate::inbound::Tls> for Server {
    fn tls(&self) -> &crate::inbound::Tls {
        &self.tls
    }

    fn tls_mut(&mut self) -> &mut crate::inbound::Tls {
        &mut self.tls
    }
}
