use crate::language::{message, text as tr};
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    Result,
    connection::{self, Core, Network, Tls},
    form::{self, Form, Value, choices, fields},
    inbound::Core as ServerCore,
    transport::Quic,
    tui::{Menu, Screen},
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Client {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub core: Core,
    pub hysteria: ClientOptions,
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
            hysteria: ClientOptions::default(),
            tls: Tls::default(),
            network: Network::default(),
        }
    }
}

impl Client {
    pub fn port(&self) -> Result<u16> {
        if self.hysteria.ports.is_empty() {
            Ok(self.port)
        } else {
            Ok(*connection::ports(&self.hysteria.ports)?.first().unwrap())
        }
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClientOptions {
    pub tcp: Option<bool>,
    pub udp: Option<bool>,
    pub obfs: Option<Obfs>,
    pub ports: String,
    pub hop_interval: Option<String>,
    pub hop_interval_max: Option<String>,
    pub quic: Quic,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Server {
    pub obfs: Option<Obfs>,
    pub quic: Quic,
    pub client: Quic,
    pub ignore_client_bandwidth: bool,
    pub masquerade: Option<Masquerade>,
    pub user_level: Option<u32>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Obfs {
    pub kind: ObfsKind,
    pub password: String,
    pub min_packet_size: Option<u16>,
    pub max_packet_size: Option<u16>,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObfsKind {
    #[default]
    Salamander,
    Gecko,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Masquerade {
    pub kind: MasqueradeKind,
    pub directory: String,
    pub url: String,
    pub rewrite_host: bool,
    pub forwarded: bool,
    pub verify_certificate: Option<bool>,
    pub status_code: Option<u16>,
    pub headers: BTreeMap<String, Vec<String>>,
    pub content: String,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MasqueradeKind {
    File,
    #[default]
    Proxy,
    String,
}

pub fn password(value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(tr("Enter a Hysteria 2 password", "请填写 Hysteria 2 认证密码").into());
    }
    if value
        .bytes()
        .any(|value| value < 32 && value != b'\t' || value == 127)
    {
        return Err(tr(
            "The Hysteria 2 password must be a valid HTTP field value",
            "Hysteria 2 认证密码需要符合 HTTP 字段值格式",
        )
        .into());
    }
    Ok(())
}

crate::connection::client_fields!(
    Hysteria2,
    Client {
        name: ("Name", "名称"),
        server: ("Address", "地址"),
        port: ("Port", "端口"),
        password: ("Password", "密码"),
        core: ("Core", "核心"),
        hysteria: "Hysteria 2",
        tls: "TLS",
        network: ("Network", "网络"),
    }
);

fn mode<T: Form, K: Value + Copy + PartialEq>(
    value: &mut Option<T>,
    screen: &mut Screen,
    title: &str,
    kinds: Vec<(&'static str, &'static str, K)>,
    kind: fn(&mut T) -> &mut K,
    edit: impl FnOnce(&mut T, &mut Screen, &str) -> Result<bool>,
) -> Result<bool> {
    let previous = value.as_mut().map(|v| *kind(v));
    let choices: Vec<_> = std::iter::once(("none", tr("None", "无"), None))
        .chain(kinds.into_iter().map(|(key, name, k)| (key, name, Some(k))))
        .collect();
    let mut selected = previous.filter(|k| choices.iter().any(|(_, _, v)| *v == Some(*k)));
    let current = choices.iter().position(|(_, _, v)| *v == selected).unwrap();
    if !form::choose(&mut selected, screen, title, &choices, current)? {
        return Ok(false);
    }
    if let Some(selected) = selected {
        let value = value.get_or_insert_with(T::default);
        *kind(value) = selected;
        Ok(
            edit(value, screen, &format!("{title} / {}", selected.text()))?
                || Some(selected) != previous,
        )
    } else {
        Ok(value.take().is_some())
    }
}

impl Obfs {
    pub fn validate(&self) -> Result<()> {
        if self.password.len() < 4 {
            return Err(tr(
                "The HY2 obfuscation password must be at least 4 UTF-8 bytes",
                "HY2 混淆密码至少需要 4 个 UTF-8 字节",
            )
            .into());
        }
        if self.kind == ObfsKind::Gecko {
            let (min, max) = self.packet_sizes();
            if min > max || max > 2048 {
                return Err(message!("Invalid Gecko packet sizes {min}–{max}: the minimum must not exceed the maximum and both must be between 1 and 2048 bytes", "Gecko 数据包范围 {min}–{max} 无效：需要 1 ≤ 最小值 ≤ 最大值 ≤ 2048 字节"
                )
                .into());
            }
        }
        Ok(())
    }

    pub fn packet_sizes(&self) -> (u16, u16) {
        (
            self.min_packet_size.filter(|&v| v != 0).unwrap_or(512),
            self.max_packet_size.filter(|&v| v != 0).unwrap_or(1200),
        )
    }

    fn field(slot: &mut Option<Self>) -> Box<dyn form::Field + '_> {
        let text = slot
            .as_ref()
            .map_or_else(|| tr("None", "无").to_owned(), |v| v.kind.text());
        form::control(
            "obfs",
            tr("Obfuscation", "混淆"),
            slot,
            None,
            Some(text),
            |value, screen, _, _| {
                mode(
                    value,
                    screen,
                    tr("Obfuscation", "混淆"),
                    ObfsKind::choices(),
                    |obfs| &mut obfs.kind,
                    |obfs, screen, title| {
                        let gecko = obfs.kind == ObfsKind::Gecko;
                        if gecko {
                            form::subset(screen, title, obfs, |key| key != "kind")
                        } else {
                            let items = [crate::tui::Item::new(
                                "password",
                                termina::style::StyleExt::stylized(tr("Password", "密码")),
                            )];
                            obfs.password.edit(
                                screen,
                                &Menu {
                                    title,
                                    heading: "",
                                    items: &items,
                                    help: "",
                                },
                                0,
                            )
                        }
                    },
                )
            },
        )
    }

    pub fn fit(&mut self) {
        if self.kind == ObfsKind::Salamander {
            self.min_packet_size = None;
            self.max_packet_size = None;
        }
    }
}

impl MasqueradeKind {
    fn field(self, core: ServerCore, key: &str) -> bool {
        match self {
            Self::File => key == "directory",
            Self::Proxy => match key {
                "url" => true,
                "rewrite_host" => core != ServerCore::Mihomo,
                "forwarded" | "verify_certificate" => core == ServerCore::Xray,
                _ => false,
            },
            Self::String => matches!(key, "content" | "status_code" | "headers"),
        }
    }
}

impl Server {
    pub fn fit(&mut self, core: ServerCore) {
        if let Some(obfs) = &mut self.obfs {
            obfs.fit();
        }
        if let Some(mask) = &mut self.masquerade {
            let kind = mask.kind;
            if core == ServerCore::Mihomo && kind == MasqueradeKind::String {
                self.masquerade = None;
            } else {
                form::retain(mask, |key| key == "kind" || kind.field(core, key));
            }
        }
    }

    pub fn edit(&mut self, screen: &mut Screen, title: &str, core: ServerCore) -> Result<bool> {
        let mut page = ServerPage {
            core,
            options: std::mem::take(self),
        };
        let result = form::edit(screen, title, &mut page);
        *self = page.options;
        result
    }
}

#[derive(Clone, Default)]
struct ServerPage {
    core: ServerCore,
    options: Server,
}

impl Form for ServerPage {
    fn fields(&mut self, d: Self) -> form::Fields<'_> {
        let core = self.core;
        let v = &mut self.options;
        let d = d.options;
        let text = v
            .masquerade
            .as_ref()
            .filter(|mask| mask.kind != MasqueradeKind::String || core != ServerCore::Mihomo)
            .map_or_else(|| tr("None", "无").to_owned(), |mask| mask.kind.text());
        vec![
            Obfs::field(&mut v.obfs),
            form::control(
                "masquerade",
                tr("Masquerade response", "伪装响应"),
                &mut v.masquerade,
                None,
                Some(text),
                move |slot, screen, _, _| {
                    let kinds = MasqueradeKind::choices()
                        .into_iter()
                        .filter(|(_, _, m)| {
                            *m != MasqueradeKind::String || core != ServerCore::Mihomo
                        })
                        .collect();
                    mode(
                        slot,
                        screen,
                        tr("Masquerade response", "伪装响应"),
                        kinds,
                        |v| &mut v.kind,
                        |mask, screen, title| {
                            let kind = mask.kind;
                            form::subset(screen, title, mask, |key| kind.field(core, key))
                        },
                    )
                },
            ),
            form::field(
                "quic",
                tr("Server QUIC", "服务端 QUIC"),
                &mut v.quic,
                d.quic,
            ),
            form::field(
                "client",
                tr("Client QUIC", "客户端 QUIC"),
                &mut v.client,
                d.client,
            ),
            form::field(
                "ignore_client_bandwidth",
                tr("Ignore client bandwidth", "忽略客户端带宽"),
                &mut v.ignore_client_bandwidth,
                d.ignore_client_bandwidth,
            ),
            form::field(
                "user_level",
                tr("User level", "用户等级"),
                &mut v.user_level,
                d.user_level,
            ),
        ]
    }
}

impl Form for ClientOptions {
    fn fields(&mut self, d: Self) -> form::Fields<'_> {
        vec![
            Obfs::field(&mut self.obfs),
            form::field(
                "ports",
                tr("Hopping ports", "跳跃端口"),
                &mut self.ports,
                d.ports,
            ),
            form::field(
                "hop_interval",
                tr("Hop interval", "跳跃间隔"),
                &mut self.hop_interval,
                d.hop_interval,
            ),
            form::field(
                "hop_interval_max",
                tr("Maximum hop interval", "最大跳跃间隔"),
                &mut self.hop_interval_max,
                d.hop_interval_max,
            ),
            form::field("tcp", "TCP", &mut self.tcp, d.tcp),
            form::field("udp", "UDP", &mut self.udp, d.udp),
            form::field("quic", "QUIC", &mut self.quic, d.quic),
        ]
    }
}
form::group!(ClientOptions);

fields!(Obfs {
    kind: ("Type", "类型"),
    password: ("Password", "密码"),
    min_packet_size: ("Minimum packet size", "最小数据包"),
    max_packet_size: ("Maximum packet size", "最大数据包"),
});

fields!(Masquerade {
    kind: ("Type", "类型"),
    directory: ("Directory", "文件目录"),
    url: ("Reverse proxy upstream", "反代目标"),
    rewrite_host: ("Rewrite host", "改写主机名"),
    forwarded: ("Forward client information", "转发来源信息"),
    verify_certificate: ("Verify upstream certificate", "验证上游证书"),
    status_code: ("Response status", "响应状态"),
    headers: ("Response headers", "响应头"),
    content: ("Response body", "响应内容"),
});

choices!(ObfsKind {
    Salamander: "salamander" => "Salamander",
    Gecko: "gecko" => "Gecko",
});

choices!(MasqueradeKind {
    File: "file" => ("File", "文件"),
    Proxy: "proxy" => ("HTTP reverse proxy", "HTTP 反代"),
    String: "string" => ("Static response", "固定响应"),
});
