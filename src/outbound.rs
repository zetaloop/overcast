use crate::language::{message, text as tr};
use serde::{Deserialize, Serialize};
use termina::{
    event::{KeyCode, Modifiers},
    style::{AnsiColor, StyleExt},
};
use uuid::Uuid;

use crate::{
    Result,
    config::Store,
    connection::{self, Connection},
    form::Value,
    progress::Progress,
    tui::{Action, Item, Menu, Screen},
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Outbound {
    pub uuid: Uuid,
    pub name: String,
    pub connections: Vec<Connection>,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Selection {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    pub connections: Vec<Connection>,
}

impl Outbound {
    pub(crate) fn default_direct() -> Self {
        Self {
            uuid: Uuid::new_v5(
                &Uuid::NAMESPACE_URL,
                b"https://github.com/zetaloop/overcast/direct",
            ),
            name: tr("Direct", "直连").to_owned(),
            connections: vec![Connection::Direct(connection::Direct::default())],
        }
    }

    fn new() -> Self {
        Self {
            uuid: Uuid::new_v4(),
            name: String::new(),
            connections: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(tr("Enter an outbound name", "出站名称不能为空").into());
        }
        if self.connections.is_empty() {
            return Err(tr("Outbound has no connections", "出站中没有连接").into());
        }
        for (index, connection) in self.connections.iter().enumerate() {
            connection.validate().map_err(|error| {
                message!("Connection {}: {error}", "第 {} 段连接：{error}", index + 1)
            })?;
        }
        Ok(())
    }

    pub(crate) fn summary(&self) -> String {
        self.connections
            .iter()
            .map(Connection::summary)
            .collect::<Vec<_>>()
            .join(" → ")
    }

    fn selection(&self) -> Selection {
        Selection {
            name: self.name.clone(),
            connections: self.connections.clone(),
        }
    }

    fn effective(&self) -> Self {
        let mut value = self.clone();
        for connection in &mut value.connections {
            connection.fit();
        }
        value
    }
}

impl Selection {
    fn parse(text: &str) -> Result<Vec<Self>> {
        let text = text.trim();
        let selections = if text.starts_with('{') || text.starts_with('[') {
            let value: serde_json::Value = serde_json::from_str(text)?;
            let values = match value {
                serde_json::Value::Array(values) => values,
                value => vec![value],
            };
            values
                .into_iter()
                .map(|mut value| {
                    if value.get("connections").is_some() {
                        value
                            .as_object_mut()
                            .ok_or(tr("Invalid outbound configuration", "出站配置的格式不正确"))?
                            .remove("uuid");
                        Ok(serde_json::from_value(value)?)
                    } else {
                        Ok(Self::from(serde_json::from_value::<Connection>(value)?))
                    }
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            text.lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| Connection::parse(line.trim()).map(Self::from))
                .collect::<Result<Vec<_>>>()?
        };
        if selections.is_empty()
            || selections
                .iter()
                .any(|selection| selection.connections.is_empty())
        {
            return Err(tr("No connections in pasted text", "粘贴内容中没有连接").into());
        }
        for selection in &selections {
            for (index, connection) in selection.connections.iter().enumerate() {
                connection.check_stack().map_err(|error| {
                    message!("Connection {}: {error}", "第 {} 段连接：{error}", index + 1)
                })?;
            }
        }
        Ok(selections)
    }

    fn copy(&self, screen: &mut Screen) -> Result<()> {
        screen.copy(&serde_json::to_string(self)?)
    }
}

impl From<Connection> for Selection {
    fn from(connection: Connection) -> Self {
        Self {
            name: String::new(),
            connections: vec![connection],
        }
    }
}

fn paste(store: &Store, selections: Vec<Selection>, progress: &Progress) -> Result<usize> {
    let mut index = 0;
    store.update(progress, |config, _| {
        index = config.outbounds.len();
        for selection in selections {
            let mut outbound = Outbound {
                uuid: Uuid::new_v4(),
                name: selection.name,
                connections: selection.connections,
            };
            if outbound.name.trim().is_empty() {
                outbound.name = outbound.summary();
            }
            let name = outbound.name.clone();
            let mut suffix = 1;
            while config
                .outbounds
                .iter()
                .any(|other| other.name == outbound.name)
            {
                outbound.name = format!("{name} ({suffix})");
                suffix += 1;
            }
            config.outbounds.push(outbound);
        }
        Ok(())
    })?;
    Ok(index)
}

fn copy_connections(screen: &mut Screen, outbound: &Outbound) -> Result<()> {
    let mut included = vec![false; outbound.connections.len()];
    let mut selected = 0;
    let mut notice = String::new();
    loop {
        let mut items: Vec<_> = outbound
            .connections
            .iter()
            .enumerate()
            .map(|(index, connection)| {
                let mut item = Item::new((index + 1).to_string(), connection.summary().stylized());
                item.marker = if included[index] { "■" } else { "□" };
                item
            })
            .collect();
        items.extend([
            Item::new("all", tr("Select all", "全选").stylized()),
            Item::new("copy", tr("Copy selected", "复制所选").stylized()),
            Item::new("back", tr("Back", "返回").stylized()),
        ]);
        let menu = Menu {
            title: tr("Copy connections", "复制连接"),
            heading: &outbound.name,
            items: &items,
            help: tr(
                "Arrow keys to select\nEnter to confirm\nEsc to go back",
                "方向键 选择\n回车键 确定\nEsc 返回",
            ),
        };
        match screen.select(&menu, &mut selected, &notice)? {
            Action::Back => return Ok(()),
            Action::Select if selected < included.len() => included[selected] = !included[selected],
            Action::Select => match items[selected].key.as_str() {
                "all" => {
                    let value = !included.iter().all(|included| *included);
                    included.fill(value);
                }
                "copy" => {
                    let selection = Selection {
                        name: if included.iter().all(|included| *included) {
                            outbound.name.clone()
                        } else {
                            String::new()
                        },
                        connections: outbound
                            .connections
                            .iter()
                            .zip(&included)
                            .filter(|(_, included)| **included)
                            .map(|(connection, _)| connection.clone())
                            .collect(),
                    };
                    if selection.connections.is_empty() {
                        notice = tr("Select at least one connection", "请选择连接").to_owned();
                    } else {
                        selection.copy(screen)?;
                        return Ok(());
                    }
                }
                _ => return Ok(()),
            },
            _ => {}
        }
    }
}

fn edit(
    screen: &mut Screen,
    store: &Store,
    existing: bool,
    mut outbound: Outbound,
) -> Result<Option<Uuid>> {
    let saved = serde_json::to_vec(&outbound)?;
    let initial = serde_json::to_vec(&outbound.effective())?;
    let mut selected = if existing { 0 } else { 1 };
    let mut notice = String::new();
    loop {
        let active = outbound.effective();
        let changed = !existing || serde_json::to_vec(&active)? != initial;
        let title = if existing {
            message!("Outbound / {}", "出站 / {}", outbound.name)
        } else {
            tr("Create outbound", "创建出站").to_owned()
        };
        let mut items = vec![Item::new("name", tr("Name", "名称").stylized())];
        items[0].value = outbound.name.clone();
        items.extend(
            outbound
                .connections
                .iter()
                .enumerate()
                .map(|(index, connection)| {
                    let mut item =
                        Item::new((index + 1).to_string(), connection.summary().stylized());
                    if index > 0 {
                        item.marker = "↓";
                    } else {
                        item.gap = true;
                    }
                    item
                }),
        );
        items.push(Item::new(
            "add",
            tr("Add connection", "添加连接").stylized(),
        ));
        let actions = items.len();
        if changed {
            items.push(if existing {
                Item::new("apply", tr("Confirm", "确定").stylized())
            } else {
                Item::new("create", tr("Create", "创建").stylized())
            });
        } else {
            items.push(Item::new(
                "export",
                tr("Connection details", "连接资料").stylized(),
            ));
            if outbound.connections.len() > 1 {
                items.push(Item::new(
                    "select",
                    tr("Copy part of path", "复制部分连接").stylized(),
                ));
            }
            items.push(Item::new(
                "delete",
                tr("Delete outbound", "删除出站").foreground(AnsiColor::BrightRed),
            ));
        }
        items.push(Item::new(
            "back",
            if changed {
                tr("Cancel", "取消")
            } else {
                tr("Back", "返回")
            }
            .stylized(),
        ));
        items[actions].gap = true;
        let menu = Menu {
            title: &title,
            heading: "",
            items: &items,
            help: if changed {
                tr(
                    "Arrow keys to select\nEnter to edit\nEsc to cancel",
                    "方向键 选择\n回车键 编辑\nEsc 取消",
                )
            } else {
                tr(
                    "Arrow keys to select\nEnter to edit\nEsc to go back",
                    "方向键 选择\n回车键 编辑\nEsc 返回",
                )
            },
        };
        let action = screen.select(&menu, &mut selected, &notice)?;
        let connection = selected
            .checked_sub(1)
            .filter(|index| *index < outbound.connections.len());
        let result = match (action, connection) {
            (Action::Back, _) => return Ok(existing.then_some(outbound.uuid)),
            (Action::Paste(text), connection) => Selection::parse(&text).map(|selections| {
                let position = connection.map_or(
                    if selected == 0 {
                        0
                    } else {
                        outbound.connections.len()
                    },
                    |index| index + 1,
                );
                let connections: Vec<_> = selections
                    .into_iter()
                    .flat_map(|selection| selection.connections)
                    .collect();
                let count = connections.len();
                outbound.connections.splice(position..position, connections);
                selected = position + count;
            }),
            (Action::Key(key), connection) if matches!(key.code, KeyCode::Char('c' | 'C')) => {
                if let Some(index) = connection {
                    Selection {
                        name: String::new(),
                        connections: vec![active.connections[index].clone()],
                    }
                    .copy(screen)
                } else {
                    active.selection().copy(screen)
                }
            }
            (Action::Key(key), Some(index)) if matches!(key.code, KeyCode::Char('l' | 'L')) => {
                let connection = &active.connections[index];
                crate::share::link(connection, &connection.summary())
                    .and_then(|text| screen.copy(&text))
            }
            (Action::Key(key), Some(index)) if key.code == KeyCode::Delete => {
                outbound.connections.remove(index);
                Ok(())
            }
            (Action::Key(key), Some(index))
                if key.modifiers.contains(Modifiers::ALT)
                    && matches!(key.code, KeyCode::Up | KeyCode::Down) =>
            {
                let destination = if key.code == KeyCode::Up {
                    index.saturating_sub(1)
                } else {
                    (index + 1).min(outbound.connections.len() - 1)
                };
                outbound.connections.swap(index, destination);
                selected = destination + 1;
                Ok(())
            }
            (Action::Select, Some(index)) => outbound.connections[index].edit(screen, store),
            (Action::Select, None) => match items[selected].key.as_str() {
                "name" => outbound.name.edit(screen, &menu, selected).map(|_| ()),
                "add" => {
                    if let Some(value) = connection::create(screen, store)? {
                        outbound.connections.push(value);
                        selected = outbound.connections.len();
                    }
                    Ok(())
                }
                "export" => crate::share::copy(
                    screen,
                    tr("Connection details", "连接资料"),
                    |_, links| {
                        if links {
                            crate::share::path(&active.connections, &active.name)
                        } else {
                            Ok(serde_json::to_string(&active.selection())?)
                        }
                    },
                ),
                "select" => copy_connections(screen, &active),
                "create" | "apply" => {
                    let result = screen.work(
                        tr("Saving outbound", "保存出站"),
                        &format!(" -- {}", outbound.name),
                        |progress| {
                            store.update(progress, |config, _| {
                                let mut value = active.clone();
                                if value.name.trim().is_empty() {
                                    value.name = value.summary();
                                }
                                if existing {
                                    let current = config
                                        .outbounds
                                        .iter_mut()
                                        .find(|current| current.uuid == outbound.uuid)
                                        .ok_or(tr("The outbound has been deleted", "出站已被删除"))?;
                                    if serde_json::to_vec(&*current)? != saved {
                                        return Err(tr("The outbound was modified elsewhere. Reopen it to edit.", "出站已在其他编辑中更改，请重新打开").into());
                                    }
                                    *current = value;
                                } else {
                                    config.outbounds.push(value);
                                }
                                Ok(())
                            })
                        },
                    );
                    if result.is_ok() {
                        return Ok(Some(outbound.uuid));
                    }
                    result
                }
                "delete" => {
                    screen.work(
                        tr("Delete outbound", "删除出站"),
                        &format!(" -- {}", outbound.name),
                        |progress| {
                            store.update(progress, |config, _| {
                                config
                                    .outbounds
                                    .retain(|current| current.uuid != outbound.uuid);
                                Ok(())
                            })
                        },
                    )?;
                    return Ok(None);
                }
                _ => return Ok(existing.then_some(outbound.uuid)),
            },
            _ => continue,
        };
        notice = result
            .err()
            .map_or_else(String::new, |error| error.to_string());
    }
}

pub fn create(screen: &mut Screen, store: &Store) -> Result<Option<Uuid>> {
    edit(screen, store, false, Outbound::new())
}

pub fn run(screen: &mut Screen, store: &Store) -> Result<()> {
    let mut selected = 0;
    let mut notice = String::new();
    loop {
        let config = store.load()?;
        let mut items: Vec<_> = config
            .outbounds
            .iter()
            .map(|outbound| {
                let mut item =
                    Item::new(outbound.uuid.to_string(), outbound.name.clone().stylized());
                item.value = outbound.summary();
                item
            })
            .collect();
        items.extend([
            Item::new("new", tr("Create outbound", "创建出站").stylized()),
            Item::new("back", tr("Back", "返回").stylized()),
        ]);
        let menu = Menu {
            title: tr("Outbound", "出站"),
            heading: "",
            items: &items,
            help: tr(
                "Arrow keys to select\nEnter to confirm\nEsc to go back",
                "方向键 选择\n回车键 确定\nEsc 返回",
            ),
        };
        let result = match screen.select(&menu, &mut selected, &notice)? {
            Action::Back => return Ok(()),
            Action::Paste(text) => Selection::parse(&text)
                .and_then(|selection| {
                    screen.work(tr("Saving outbound", "保存出站"), "", |progress| {
                        paste(store, selection, progress)
                    })
                })
                .map(|index| {
                    selected = index;
                }),
            Action::Key(key)
                if matches!(key.code, KeyCode::Char('c' | 'C'))
                    && selected < config.outbounds.len() =>
            {
                config.outbounds[selected].selection().copy(screen)
            }
            Action::Select if selected < config.outbounds.len() => {
                edit(screen, store, true, config.outbounds[selected].clone()).map(|_| ())
            }
            Action::Select if selected == config.outbounds.len() => {
                create(screen, store).map(|_| ())
            }
            Action::Select => return Ok(()),
            _ => continue,
        };
        notice = result
            .err()
            .map_or_else(String::new, |error| error.to_string());
    }
}
