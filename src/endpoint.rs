use crate::language::text as tr;
use serde::{Deserialize, Serialize};
use termina::style::StyleExt;
use uuid::Uuid;

use crate::{
    Result,
    config::Store,
    form::Value,
    inbound,
    route::Destination,
    tui::{Action, Item, Menu, Screen},
};

#[derive(Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "kebab-case")]
pub enum Endpoint {
    #[default]
    Block,
    Inbound(Uuid),
    #[serde(untagged)]
    Address(String),
}

impl Endpoint {
    pub fn address(&self) -> &str {
        let Self::Address(value) = self else {
            unreachable!("unresolved endpoint")
        };
        value
    }
}

impl Value for Endpoint {
    fn text(&self) -> String {
        match self {
            Self::Block => Destination::Block.text(),
            Self::Inbound(uuid) => Destination::Inbound(*uuid).text(),
            Self::Address(value) => value.clone(),
        }
    }

    fn edit(&mut self, screen: &mut Screen, parent: &Menu<'_>, field: usize) -> Result<bool> {
        let title = format!("{} / {}", parent.title, parent.items[field].label.content);
        let mut selected = match self {
            Self::Block => 0,
            Self::Address(_) => 1,
            Self::Inbound(_) => 2,
        };
        let mut notice = String::new();
        loop {
            let items = vec![
                Item::new("block", tr("Blackhole", "黑洞").stylized()),
                Item::new("address", tr("Address", "地址").stylized()),
                Item::new("inbound", tr("Inbound", "入口").stylized()),
                Item::new("back", tr("Back", "返回").stylized()),
            ];
            let menu = Menu {
                title: &title,
                heading: "",
                items: &items,
                help: tr(
                    "Arrow keys to select\nEnter to edit\nEsc to go back",
                    "方向键 选择\n回车键 编辑\nEsc 返回",
                ),
            };
            let result = match screen.select(&menu, &mut selected, &notice)? {
                Action::Back => return Ok(false),
                Action::Select => match items[selected].key.as_str() {
                    "block" => {
                        *self = Self::Block;
                        Ok(true)
                    }
                    "address" => {
                        let mut address = match self {
                            Self::Address(value) => value.clone(),
                            _ => String::new(),
                        };
                        address.edit(screen, &menu, selected).inspect(|&changed| {
                            if changed {
                                *self = Self::Address(address);
                            }
                        })
                    }
                    "inbound" => {
                        let current = match self {
                            Self::Inbound(uuid) => Some(*uuid),
                            _ => None,
                        };
                        match inbound::select(screen, &Store::open(None)?, current, |_| true)? {
                            Some(uuid) => {
                                *self = Self::Inbound(uuid);
                                Ok(true)
                            }
                            None => Ok(false),
                        }
                    }
                    _ => return Ok(false),
                },
                _ => continue,
            };
            match result {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(error) => notice = error.to_string(),
            }
        }
    }
}
