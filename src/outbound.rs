use std::rc::Rc;

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
    form,
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
struct Selection {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    name: String,
    connections: Vec<Connection>,
}

impl Outbound {
    fn new() -> Self {
        Self {
            uuid: Uuid::new_v4(),
            name: String::new(),
            connections: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err("出站名称不能为空".into());
        }
        if self.connections.is_empty() {
            return Err("出站中没有连接".into());
        }
        for (index, connection) in self.connections.iter().enumerate() {
            connection
                .validate()
                .map_err(|error| format!("第 {} 段连接：{error}", index + 1))?;
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
                            .ok_or("出站配置的格式不正确")?
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
            return Err("粘贴内容中没有连接".into());
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
    store.update(progress, |config| {
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
            Item::new("all", "全选".stylized()),
            Item::new("copy", "复制所选".stylized()),
            Item::new("back", "返回".stylized()),
        ]);
        let menu = Menu {
            title: "复制连接",
            heading: &outbound.name,
            items: &items,
            help: "方向键 选择\n回车键 确定\nEsc 返回",
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
                        notice = "请选择连接".to_owned();
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
    let apply: form::Apply<'_, Outbound> = Rc::new(|edited, screen| {
        if existing {
            screen.work("保存出站", &format!(" -- {}", edited.name), |progress| {
                store.update(progress, |config| {
                    let current = config
                        .outbounds
                        .iter_mut()
                        .find(|current| current.uuid == edited.uuid)
                        .ok_or("出站已被删除")?;
                    *current = edited.clone();
                    Ok(())
                })
            })?;
        }
        Ok(())
    });
    let mut selected = if existing { 0 } else { 1 };
    let mut notice = String::new();
    loop {
        let title = if existing {
            format!("出站 / {}", outbound.name)
        } else {
            "创建出站".to_owned()
        };
        let mut items = vec![Item::new("name", "名称".stylized())];
        items[0].value = outbound.name.clone();
        items.extend(
            outbound
                .connections
                .iter()
                .enumerate()
                .map(|(index, connection)| {
                    Item::new((index + 1).to_string(), connection.summary().stylized())
                }),
        );
        items.push(Item::new("add", "添加连接".stylized()));
        if !existing {
            items.push(Item::new("create", "创建".stylized()));
        }
        items.extend([
            Item::new("copy", "复制出站".stylized()),
            Item::new("select", "复制连接".stylized()),
        ]);
        if existing {
            items.push(Item::new(
                "delete",
                "删除出站".foreground(AnsiColor::BrightRed),
            ));
        }
        items.push(Item::new("back", "返回".stylized()));
        let menu = Menu {
            title: &title,
            heading: "",
            items: &items,
            help: "方向键 选择\n回车键 编辑\nC 复制连接\nL 分享链接\nDel 删除连接\nAlt+↑↓ 移动\nEsc 返回",
        };
        let action = screen.select(&menu, &mut selected, &notice)?;
        let connection = selected
            .checked_sub(1)
            .filter(|index| *index < outbound.connections.len());
        let result = match (action, connection) {
            (Action::Back, _) => return Ok(existing.then_some(outbound.uuid)),
            (Action::Paste(text), connection) => Selection::parse(&text).and_then(|selections| {
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
                let mut edited = outbound.clone();
                edited.connections.splice(position..position, connections);
                form::set(screen, &mut outbound, edited, &apply).map(|_| {
                    selected = position + count;
                })
            }),
            (Action::Key(key), connection) if matches!(key.code, KeyCode::Char('c' | 'C')) => {
                if let Some(index) = connection {
                    Selection {
                        name: String::new(),
                        connections: vec![outbound.connections[index].clone()],
                    }
                    .copy(screen)
                } else {
                    outbound.selection().copy(screen)
                }
            }
            (Action::Key(key), Some(index)) if matches!(key.code, KeyCode::Char('l' | 'L')) => {
                let connection = &outbound.connections[index];
                screen.copy(&crate::share::link(
                    connection,
                    &connection.summary(),
                    store,
                )?)
            }
            (Action::Key(key), Some(index)) if key.code == KeyCode::Delete => {
                let mut edited = outbound.clone();
                edited.connections.remove(index);
                form::set(screen, &mut outbound, edited, &apply).map(|_| ())
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
                let mut edited = outbound.clone();
                edited.connections.swap(index, destination);
                form::set(screen, &mut outbound, edited, &apply).map(|_| {
                    selected = destination + 1;
                })
            }
            (Action::Select, Some(index)) => {
                let apply = form::map(
                    Rc::new(outbound.clone()),
                    apply.clone(),
                    move |outbound, connection| {
                        outbound.connections[index] = connection;
                    },
                );
                outbound.connections[index].edit(screen, apply)
            }
            (Action::Select, None) => match items[selected].key.as_str() {
                "name" => {
                    if let Some(value) =
                        screen.input(&menu, selected, &outbound.name, |value, screen| {
                            let edited = Outbound {
                                name: value.to_owned(),
                                ..outbound.clone()
                            };
                            apply(&edited, screen)?;
                            Ok(edited.name)
                        })?
                    {
                        outbound.name = value;
                    }
                    Ok(())
                }
                "add" => {
                    let apply = form::map(
                        Rc::new(outbound.clone()),
                        apply.clone(),
                        |outbound, connection| outbound.connections.push(connection),
                    );
                    if let Some(value) = connection::create(screen, apply)? {
                        outbound.connections.push(value);
                        selected = outbound.connections.len();
                    }
                    Ok(())
                }
                "copy" => outbound.selection().copy(screen),
                "select" => copy_connections(screen, &outbound),
                "create" => {
                    let result = screen.work(
                        "保存出站",
                        &format!(" -- {}", outbound.name),
                        |progress| {
                            store.update(progress, |config| {
                                let mut value = outbound.clone();
                                if value.name.trim().is_empty() {
                                    value.name = value.summary();
                                }
                                config.outbounds.push(value);
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
                        "删除出站",
                        &format!(" -- {}", outbound.name),
                        |progress| {
                            store.update(progress, |config| {
                                config
                                    .outbounds
                                    .retain(|current| current.uuid != outbound.uuid);
                                for rule in &mut config.rules {
                                    rule.remove_destination(crate::route::Destination::Outbound(
                                        outbound.uuid,
                                    ));
                                }
                                for inbound in &mut config.inbounds {
                                    if let crate::inbound::Protocol::Forward(value) =
                                        &mut inbound.protocol
                                        && value.outbound
                                            == crate::route::Destination::Outbound(outbound.uuid)
                                    {
                                        value.outbound = crate::route::Destination::Block;
                                    }
                                }
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
            Item::new("new", "创建出站".stylized()),
            Item::new("back", "返回".stylized()),
        ]);
        let menu = Menu {
            title: "出站",
            heading: "",
            items: &items,
            help: "方向键 选择\n回车键 确定\nC 复制出站\nEsc 返回",
        };
        let result = match screen.select(&menu, &mut selected, &notice)? {
            Action::Back => return Ok(()),
            Action::Paste(text) => Selection::parse(&text)
                .and_then(|selection| {
                    screen.work("保存出站", "", |progress| {
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
