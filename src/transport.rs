use std::{collections::BTreeMap, rc::Rc};

use serde::{Deserialize, Serialize};
use termina::style::StyleExt;

use crate::{
    Result,
    form::{self, Value, fields},
    tui::{Action, Item, Menu, Screen},
};

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum Transport {
    #[default]
    Default,
    WebSocket(WebSocket),
    HttpUpgrade(HttpUpgrade),
    Grpc(Grpc),
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebSocket {
    pub host: Option<String>,
    pub path: Option<String>,
    pub headers: BTreeMap<String, Vec<String>>,
    pub early_data: Option<u32>,
    pub early_data_header: Option<String>,
    pub heartbeat: Option<String>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpUpgrade {
    pub host: Option<String>,
    pub path: Option<String>,
    pub headers: BTreeMap<String, Vec<String>>,
    pub early_data: Option<bool>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Grpc {
    pub authority: Option<String>,
    pub service_name: Option<String>,
    pub multi_mode: bool,
    pub keep_alive: Option<String>,
    pub ping_timeout: Option<String>,
    pub permit_without_stream: bool,
    pub receive_window: Option<u32>,
    pub user_agent: Option<String>,
}

impl Transport {
    pub fn is_default(&self) -> bool {
        matches!(self, Self::Default)
    }

    fn index(&self) -> usize {
        match self {
            Self::Default => 0,
            Self::WebSocket(_) => 1,
            Self::HttpUpgrade(_) => 2,
            Self::Grpc(_) => 3,
        }
    }
}

impl Value for Transport {
    fn text(&self) -> String {
        match self {
            Self::Default => "默认",
            Self::WebSocket(_) => "WebSocket",
            Self::HttpUpgrade(_) => "HTTPUpgrade",
            Self::Grpc(_) => "gRPC",
        }
        .to_owned()
    }

    fn run(
        &mut self,
        screen: &mut Screen,
        parent: &Menu<'_>,
        field: usize,
        apply: form::Apply<'_, Self>,
        _: bool,
    ) -> Result<bool> {
        let title = format!("{} / {}", parent.title, parent.items[field].label.content);
        let mut saved = BTreeMap::new();
        let mut selected = self.index();
        let mut changed = false;
        let mut notice = String::new();
        loop {
            let mut items: Vec<_> = [
                ("default", "默认"),
                ("websocket", "WebSocket"),
                ("httpupgrade", "HTTPUpgrade"),
                ("grpc", "gRPC"),
                ("back", "返回"),
            ]
            .into_iter()
            .map(|(key, label)| Item::new(key, label.stylized()))
            .collect();
            items[self.index()].marker = "■";
            let menu = Menu {
                title: &title,
                heading: "",
                items: &items,
                help: "方向键 选择\n回车键 编辑\nEsc 返回",
            };
            match screen.select(&menu, &mut selected, &notice)? {
                Action::Back => return Ok(changed),
                Action::Select if selected == items.len() - 1 => return Ok(changed),
                Action::Select => {
                    saved.insert(self.index(), self.clone());
                    let mut candidate =
                        saved
                            .get(&selected)
                            .cloned()
                            .unwrap_or_else(|| match selected {
                                1 => Self::WebSocket(WebSocket::default()),
                                2 => Self::HttpUpgrade(HttpUpgrade::default()),
                                3 => Self::Grpc(Grpc::default()),
                                _ => Self::Default,
                            });
                    let creating = selected != self.index();
                    let result = match &mut candidate {
                        Self::Default => form::set(screen, self, Self::Default, &apply),
                        Self::WebSocket(value) => {
                            let apply = apply.clone();
                            form::edit(
                                screen,
                                &format!("{title} / WebSocket"),
                                value,
                                Rc::new(move |value, screen| {
                                    apply(&Self::WebSocket(value.clone()), screen)
                                }),
                                creating,
                            )
                        }
                        Self::HttpUpgrade(value) => {
                            let apply = apply.clone();
                            form::edit(
                                screen,
                                &format!("{title} / HTTPUpgrade"),
                                value,
                                Rc::new(move |value, screen| {
                                    apply(&Self::HttpUpgrade(value.clone()), screen)
                                }),
                                creating,
                            )
                        }
                        Self::Grpc(value) => {
                            let apply = apply.clone();
                            form::edit(
                                screen,
                                &format!("{title} / gRPC"),
                                value,
                                Rc::new(move |value, screen| {
                                    apply(&Self::Grpc(value.clone()), screen)
                                }),
                                creating,
                            )
                        }
                    };
                    match result {
                        Ok(accepted) => {
                            if accepted {
                                *self = candidate;
                                changed = true;
                            }
                            notice.clear();
                        }
                        Err(error) => notice = error.to_string(),
                    }
                }
                _ => {}
            }
        }
    }
}

fields!(WebSocket {
    host: "主机名",
    path: "路径",
    headers: "请求头",
    early_data: "握手数据上限",
    early_data_header: "握手数据请求头",
    heartbeat: "心跳间隔",
});

fields!(HttpUpgrade {
    host: "主机名",
    path: "路径",
    headers: "请求头",
    early_data: "提前发送",
});

fields!(Grpc {
    authority: "主机名",
    service_name: "服务名",
    multi_mode: "多流模式",
    keep_alive: "保活间隔",
    ping_timeout: "保活响应超时",
    permit_without_stream: "空闲连接保活",
    receive_window: "接收窗口",
    user_agent: "用户代理",
});
