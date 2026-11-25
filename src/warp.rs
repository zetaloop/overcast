use crate::language::{message, text as tr};
use std::{
    collections::BTreeMap,
    fs::File,
    net::{Ipv4Addr, Ipv6Addr},
    process::Command,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use termina::style::StyleExt;
use x509_cert::{
    der::{DecodePem, Encode},
    spki::SubjectPublicKeyInfoOwned,
};

use crate::{
    Result,
    component::Component,
    config::Store,
    connection::{AddressStrategy, Core, Network},
    form::{self, choices, fields},
    progress::Progress,
    transport::Quic,
    tui::{Action, Item, Menu, Screen},
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Client {
    pub name: String,
    pub registration: Registration,
    pub server: Option<String>,
    pub port: u16,
    pub core: Core,
    pub warp: ClientOptions,
    pub network: Network,
}

impl Default for Client {
    fn default() -> Self {
        Self {
            name: String::new(),
            registration: Registration::default(),
            server: None,
            port: 443,
            core: Core::default(),
            warp: ClientOptions::default(),
            network: Network::default(),
        }
    }
}

impl Client {
    pub fn server(&self) -> &str {
        if let Some(server) = &self.server {
            return server;
        }
        let ipv6 = self.network.ipv6_only == Some(true)
            || matches!(
                self.network.address_strategy,
                Some(
                    AddressStrategy::Ipv6Only
                        | AddressStrategy::PreferIpv6
                        | AddressStrategy::TryIpv6
                        | AddressStrategy::TryIpv6Ipv4
                )
            );
        match (self.warp.mode, ipv6) {
            (Mode::Http3, false) => &self.registration.endpoint_v4,
            (Mode::Http3, true) => &self.registration.endpoint_v6,
            (Mode::Http2, false) => &self.registration.endpoint_h2_v4,
            (Mode::Http2, true) => &self.registration.endpoint_h2_v6,
        }
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClientOptions {
    pub mode: Mode,
    pub tcp: Option<bool>,
    pub udp: Option<bool>,
    pub server_name: Option<String>,
    pub verify_certificate: Option<bool>,
    pub fingerprint: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub headers: BTreeMap<String, Vec<String>>,
    pub mtu: Option<u32>,
    pub handshake_timeout: Option<String>,
    pub keep_alive: Option<String>,
    pub remote_dns: Vec<String>,
    pub quic: Quic,
    pub stack: Stack,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    #[default]
    Http3,
    Http2,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Stack {
    pub mode: StackMode,
    pub congestion: Option<StackCongestion>,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StackMode {
    #[default]
    Auto,
    Mips,
    Gvisor,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StackCongestion {
    #[default]
    Cubic,
    Reno,
    Bbr,
    Bbr3,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Registration {
    pub private_key: String,
    pub endpoint_v4: String,
    pub endpoint_v6: String,
    pub endpoint_h2_v4: String,
    pub endpoint_h2_v6: String,
    pub endpoint_pub_key: String,
    pub id: String,
    pub access_token: String,
    pub ipv4: String,
    pub ipv6: String,
}

impl Registration {
    pub fn public_key(&self) -> Result<String> {
        let key = SubjectPublicKeyInfoOwned::from_pem(&self.endpoint_pub_key).map_err(|error| {
            message!(
                "Invalid WARP peer public key: {error}",
                "WARP 对端公钥格式不正确：{error}"
            )
        })?;
        Ok(STANDARD.encode(key.to_der()?))
    }

    pub fn addresses(&self) -> Result<Vec<String>> {
        let mut addresses = Vec::new();
        if !self.ipv4.is_empty() {
            let address = self.ipv4.parse::<Ipv4Addr>().map_err(|error| {
                message!(
                    "Invalid WARP IPv4 address: {error}",
                    "WARP IPv4 地址格式不正确：{error}"
                )
            })?;
            addresses.push(format!("{address}/32"));
        }
        if !self.ipv6.is_empty() {
            let address = self.ipv6.parse::<Ipv6Addr>().map_err(|error| {
                message!(
                    "Invalid WARP IPv6 address: {error}",
                    "WARP IPv6 地址格式不正确：{error}"
                )
            })?;
            addresses.push(format!("{address}/128"));
        }
        if addresses.is_empty() {
            return Err(tr(
                "No assigned address in WARP registration",
                "WARP 资料缺少分配地址",
            )
            .into());
        }
        Ok(addresses)
    }

    pub fn validate(&self) -> Result<()> {
        if self.private_key.is_empty() {
            return Err(tr(
                "Register or import WARP credentials",
                "请注册或导入 WARP 资料",
            )
            .into());
        }
        STANDARD.decode(&self.private_key).map_err(|error| {
            message!(
                "Invalid WARP private key: {error}",
                "WARP 私钥格式不正确：{error}"
            )
        })?;
        self.public_key()?;
        self.addresses()?;
        Ok(())
    }
}

fn register(store: &Store, progress: &Progress) -> Result<Registration> {
    let resources = crate::resource::Resources::load(store)?;
    let program = resources
        .components
        .get(&Component::Usque)
        .map(|installed| Component::Usque.program(store, installed))
        .transpose()?;
    let program = match program {
        Some(program) if program.try_exists()? => program,
        _ => store.update(progress, |config, resources| {
            let preview = config.preview(Component::Usque);
            Component::Usque.ensure(store, preview, resources, progress)?;
            Component::Usque.program(store, &resources.components[&Component::Usque])
        })?,
    };
    progress.check()?;
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("config.json");
    let step = progress.activity(tr("Registering with WARP", "登记 WARP"));
    let output = Command::new(program)
        .arg("--config")
        .arg(&file)
        .args(["register", "--accept-tos"])
        .output()?;
    if !output.status.success() {
        return Err(message!(
            "WARP registration failed: {}{}",
            "WARP 登记失败：{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
        .into());
    }
    let registration: Registration = serde_json::from_reader(File::open(&file)?)?;
    registration.validate()?;
    step.finish(&registration.id);
    progress.check()?;
    Ok(registration)
}

impl form::Value for Registration {
    fn text(&self) -> String {
        if self.private_key.is_empty() {
            tr("Not configured", "未配置").to_owned()
        } else if self.id.is_empty() {
            tr("Configured", "已配置").to_owned()
        } else {
            self.id.clone()
        }
    }

    fn edit(&mut self, screen: &mut Screen, menu: &Menu<'_>, selected: usize) -> Result<bool> {
        let title = format!("{} / {}", menu.title, menu.items[selected].label.content);
        let mut items = vec![
            Item::new("register", tr("Register with WARP", "注册 WARP").stylized()),
            Item::new("import", tr("Import registration", "导入资料").stylized()),
        ];
        if !self.private_key.is_empty() {
            items.push(Item::new(
                "copy",
                tr("Copy registration", "复制资料").stylized(),
            ));
        }
        items.push(Item::new("back", tr("Back", "返回").stylized()));
        let menu = Menu {
            title: &title,
            heading: "",
            items: &items,
            help: tr(
                "Arrow keys to select\nEnter to confirm\nEsc to go back",
                "方向键 选择\n回车键 确定\nEsc 返回",
            ),
        };
        let mut selected = 0;
        loop {
            match screen.select(&menu, &mut selected, "")? {
                Action::Back => return Ok(false),
                Action::Select => match items[selected].key.as_str() {
                    "register" => {
                        let store = Store::open()?;
                        let edited = screen.work(
                            tr("Register with WARP", "注册 WARP"),
                            "",
                            |progress| register(&store, progress),
                        )?;
                        *self = edited;
                        return Ok(true);
                    }
                    "import" => {
                        let current = if self.private_key.is_empty() {
                            String::new()
                        } else {
                            serde_json::to_string_pretty(self)?
                        };
                        let edited = screen.input(&menu, selected, &current, |text, _| {
                            let registration: Registration =
                                serde_json::from_str(text).map_err(|error| {
                                    message!(
                                        "Invalid WARP registration: {error}",
                                        "WARP 资料格式不正确：{error}"
                                    )
                                })?;
                            registration.validate()?;
                            Ok(registration)
                        })?;
                        if let Some(edited) = edited {
                            *self = edited;
                            return Ok(true);
                        }
                    }
                    "copy" => screen.copy(&serde_json::to_string_pretty(self)?)?,
                    _ => return Ok(false),
                },
                _ => {}
            }
        }
    }
}

crate::connection::client_fields!(
    Warp,
    Client {
        name: ("Name", "名称"),
        registration: ("Registration", "登记资料"),
        server: ("Address", "地址"),
        port: ("Port", "端口"),
        core: ("Core", "核心"),
        warp: "MASQUE",
        network: ("Network", "网络"),
    }
);

fields!(ClientOptions {
    mode: ("Carrier", "承载"),
    tcp: "TCP",
    udp: "UDP",
    server_name: ("Server name", "服务器名称"),
    verify_certificate: ("Verify peer public key", "验证对端公钥"),
    fingerprint: ("TLS fingerprint", "TLS 指纹"),
    host: ("HTTP host", "HTTP 主机名"),
    path: ("HTTP path", "HTTP 路径"),
    headers: ("Request headers", "请求头"),
    mtu: "MTU",
    handshake_timeout: ("Handshake timeout", "握手超时"),
    keep_alive: ("Keepalive interval", "保活间隔"),
    remote_dns: ("Remote DNS", "远端 DNS"),
    quic: "QUIC",
    stack: ("IP stack", "IP 协议栈"),
});

fields!(Stack {
    mode: ("Implementation", "实现"),
    congestion: ("TCP congestion control", "TCP 拥塞控制"),
});

choices!(Mode {
    Http3: "http3" => "HTTP/3",
    Http2: "http2" => "HTTP/2",
});

choices!(StackMode {
    Auto: "auto" => ("Automatic", "自动"),
    Mips: "mips" => "MIPS",
    Gvisor: "gvisor" => "gVisor",
});

choices!(StackCongestion {
    Cubic: "cubic" => "Cubic",
    Reno: "reno" => "Reno",
    Bbr: "bbr" => "BBR",
    Bbr3: "bbr3" => "BBRv3",
});
