use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use termina::{
    Event,
    event::KeyCode,
    style::{AnsiColor, StyleExt},
};
use uuid::Uuid;

use crate::{
    Result,
    condition::Condition,
    config::{Config, Store},
    form::{self, Value},
    geodata::Catalog,
    inbound,
    input::Editor,
    outbound,
    tui::{Action, Item, Menu, Screen},
    user,
};

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Rule {
    pub condition: Condition,
    pub destination: Destination,
    pub children: Vec<Self>,
}

impl Rule {
    pub fn validate(&self) -> Result<()> {
        self.condition.validate()?;
        for child in &self.children {
            child.validate()?;
        }
        Ok(())
    }

    pub fn replace_user(&mut self, previous: Uuid, current: Uuid) {
        self.condition.replace_user(previous, current);
        for child in &mut self.children {
            child.replace_user(previous, current);
        }
    }

    pub fn remove_outbound(&mut self, uuid: Uuid) {
        if self.destination == Destination::Outbound(uuid) {
            self.destination = Destination::Block;
        }
        for child in &mut self.children {
            child.remove_outbound(uuid);
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "kebab-case")]
pub enum Destination {
    Direct,
    #[default]
    Block,
    Outbound(Uuid),
}

impl Destination {
    fn name(self, config: &Config) -> String {
        match self {
            Self::Direct => "直连".to_owned(),
            Self::Block => "黑洞".to_owned(),
            Self::Outbound(uuid) => config
                .outbounds
                .iter()
                .find(|outbound| outbound.uuid == uuid)
                .map_or_else(|| uuid.to_string(), |outbound| outbound.name.clone()),
        }
    }

    fn key(self) -> String {
        match self {
            Self::Direct => "direct".to_owned(),
            Self::Block => "block".to_owned(),
            Self::Outbound(uuid) => uuid.to_string(),
        }
    }
}

impl Value for Destination {
    fn text(&self) -> String {
        match Store::open().and_then(|store| store.load()) {
            Ok(config) => self.name(&config),
            Err(error) => error.to_string(),
        }
    }

    fn run(
        &mut self,
        screen: &mut Screen,
        _: &Menu<'_>,
        _: usize,
        apply: form::Apply<'_, Self>,
        _: bool,
    ) -> Result<bool> {
        match destination(screen, &Store::open()?, *self)? {
            Some(value) => form::set(screen, self, value, &apply),
            None => Ok(false),
        }
    }
}

fn get<'a>(rules: &'a [Rule], path: &[usize]) -> Result<&'a Rule> {
    let (index, rest) = path.split_first().ok_or("找不到规则")?;
    let rule = rules.get(*index).ok_or("找不到规则")?;
    if rest.is_empty() {
        Ok(rule)
    } else {
        get(&rule.children, rest)
    }
}

fn get_mut<'a>(rules: &'a mut [Rule], path: &[usize]) -> Result<&'a mut Rule> {
    let (index, rest) = path.split_first().ok_or("找不到规则")?;
    let rule = rules.get_mut(*index).ok_or("找不到规则")?;
    if rest.is_empty() {
        Ok(rule)
    } else {
        get_mut(&mut rule.children, rest)
    }
}

fn children<'a>(rules: &'a mut Vec<Rule>, path: &[usize]) -> Result<&'a mut Vec<Rule>> {
    if path.is_empty() {
        Ok(rules)
    } else {
        Ok(&mut get_mut(rules, path)?.children)
    }
}

fn rows(rules: &[Rule], config: &Config) -> (Vec<Vec<usize>>, Vec<Item>) {
    fn append(
        rules: &[Rule],
        config: &Config,
        path: &mut Vec<usize>,
        rows: &mut Vec<(Vec<usize>, Item)>,
    ) {
        for (index, rule) in rules.iter().enumerate() {
            path.push(index);
            let key = path
                .iter()
                .map(|index| (index + 1).to_string())
                .collect::<Vec<_>>()
                .join(".");
            let label = format!(
                "{}{} → {}",
                "  ".repeat(path.len() - 1),
                rule.condition.text(config),
                rule.destination.name(config),
            );
            rows.push((path.clone(), Item::new(key, label.stylized())));
            append(&rule.children, config, path, rows);
            path.pop();
        }
    }
    let mut rows = Vec::new();
    append(rules, config, &mut Vec::new(), &mut rows);
    rows.into_iter().unzip()
}

fn select_user(screen: &mut Screen, store: &Store) -> Result<Option<Condition>> {
    loop {
        let config = store.load()?;
        let mut items: Vec<_> = config
            .users
            .iter()
            .map(|user| {
                let mut item = Item::new(user.uuid.to_string(), user.name.clone().stylized());
                item.value = user.uuid.to_string();
                item
            })
            .collect();
        items.push(Item::new("new", "新增用户".stylized()));
        match screen.search("选择用户", &items, 0)? {
            Some(index) if index < config.users.len() => {
                return Ok(Some(Condition::User(config.users[index].uuid)));
            }
            Some(_) => {
                if let Some(uuid) = user::create(screen, store)? {
                    return Ok(Some(Condition::User(uuid)));
                }
            }
            None => return Ok(None),
        }
    }
}

fn select_inbound(screen: &mut Screen, store: &Store) -> Result<Option<Condition>> {
    loop {
        let config = store.load()?;
        let mut items: Vec<_> = config
            .inbounds
            .iter()
            .map(|inbound| {
                let mut item = Item::new(inbound.uuid.to_string(), inbound.name.clone().stylized());
                item.value = inbound.summary();
                item
            })
            .collect();
        items.push(Item::new("new", "创建入站".stylized()));
        let menu = Menu {
            title: "选择入站",
            heading: "",
            items: &items,
            help: "",
        };
        match screen.search(menu.title, &items, 0)? {
            Some(index) if index < config.inbounds.len() => {
                return Ok(Some(Condition::Inbound(config.inbounds[index].uuid)));
            }
            Some(index) => {
                if let Some(uuid) = inbound::create(screen, store, &menu, index)? {
                    return Ok(Some(Condition::Inbound(uuid)));
                }
            }
            None => return Ok(None),
        }
    }
}

fn select_target(
    screen: &mut Screen,
    config: &Config,
    catalog: &Catalog,
) -> Result<Option<Condition>> {
    let literals = [
        ("domain", "域名"),
        ("suffix", "域名及子域"),
        ("keyword", "域名关键词"),
        ("regex", "域名正则"),
        ("ip", "IP 地址或网段"),
    ];
    let sets = catalog
        .sites
        .iter()
        .map(|name| (Condition::Site(name.clone()), String::new()))
        .chain(
            catalog
                .ips
                .iter()
                .map(|name| (Condition::Geoip(name.clone()), String::new())),
        )
        .chain(
            catalog
                .asns
                .iter()
                .map(|(number, name)| (Condition::Asn(*number), name.clone())),
        )
        .map(|(condition, name)| {
            let text = condition.text(config);
            let mut item = Item::new(text.clone(), text.stylized());
            item.value = name;
            (item, Some(condition))
        });
    let (items, values): (Vec<_>, Vec<_>) = literals
        .iter()
        .map(|(key, label)| (Item::new(*key, label.stylized()), None))
        .chain(sets)
        .unzip();
    let mut selected = 0;
    loop {
        let Some(index) = screen.search("选择目标", &items, selected)? else {
            return Ok(None);
        };
        selected = index;
        if let Some(condition) = &values[index] {
            return Ok(Some(condition.clone()));
        }
        let (kind, label) = literals[index];
        let fields = [Item::new(kind, label.stylized())];
        let menu = Menu {
            title: "目标条件",
            heading: "",
            items: &fields,
            help: "",
        };
        if let Some(condition) = screen.input(&menu, 0, "", |value, _| {
            Condition::parse(
                &format!("{kind}:{}", serde_json::to_string(value)?),
                config,
                catalog,
                &BTreeMap::new(),
            )
        })? {
            return Ok(Some(condition));
        }
    }
}

fn destination(
    screen: &mut Screen,
    store: &Store,
    current: Destination,
) -> Result<Option<Destination>> {
    loop {
        let config = store.load()?;
        let mut values = vec![Destination::Direct, Destination::Block];
        values.extend(
            config
                .outbounds
                .iter()
                .map(|outbound| Destination::Outbound(outbound.uuid)),
        );
        if !values.contains(&current) {
            values.push(current);
        }
        let selected = values.iter().position(|value| *value == current).unwrap();
        let mut items: Vec<_> = values
            .iter()
            .map(|value| {
                let mut item = Item::new(value.key(), value.name(&config).stylized());
                if let Destination::Outbound(uuid) = value
                    && let Some(outbound) = config
                        .outbounds
                        .iter()
                        .find(|outbound| outbound.uuid == *uuid)
                {
                    item.value = outbound.summary();
                }
                item
            })
            .collect();
        items.push(Item::new("new", "创建出站".stylized()));
        match screen.search("选择出站", &items, selected)? {
            Some(index) if index < values.len() => return Ok(Some(values[index])),
            Some(_) => {
                if let Some(uuid) = outbound::create(screen, store)? {
                    return Ok(Some(Destination::Outbound(uuid)));
                }
            }
            None => return Ok(None),
        }
    }
}

fn condition(screen: &mut Screen, store: &Store, path: &[usize]) -> Result<()> {
    let catalog = match Catalog::load(store)? {
        Some(catalog) => catalog,
        None => screen.work("准备规则数据", "", |progress| {
            Catalog::update(store, progress)
        })?,
    };
    let config = store.load()?;
    let condition = &get(&config.rules, path)?.condition;
    let bindings = condition.bindings(&config);
    let mut editor = Editor::new(condition.text(&config));
    editor.move_to(editor.text().len(), false);
    let mut selected: usize = 0;
    let mut notice = String::new();
    let items: Vec<_> = [
        ("user", "用户"),
        ("inbound", "入站"),
        ("target", "目标"),
        ("block", "黑洞"),
    ]
    .into_iter()
    .map(|(key, label)| {
        let mut item = Item::new(key, label.stylized());
        item.marker = "+";
        item
    })
    .collect();
    let apply = |text: &str, screen: &mut Screen| {
        screen.work("编辑条件", text, |progress| {
            store.update(progress, |config| {
                let condition = Condition::parse(text, config, &catalog, &bindings)?;
                get_mut(&mut config.rules, path)?.condition = condition;
                Ok(())
            })
        })
    };
    if let Some(argument) = screen.arguments.pop_front() {
        if argument != "-" {
            editor = Editor::new(argument);
        }
        match apply(editor.text(), screen) {
            Ok(()) => return Ok(()),
            Err(error) => {
                notice = error.to_string();
                screen.arguments.clear();
            }
        }
    }
    while !screen.exiting {
        screen.prompt(
            "编辑条件",
            &mut editor,
            items.iter(),
            selected.checked_sub(1),
            &notice,
            "↑↓ 选择\n回车键 确定\nEsc 取消\nCtrl+A 全选\nCtrl+C 复制 / Ctrl+X 剪切",
        )?;
        let Some(event) = screen.event(false)? else {
            continue;
        };
        if let Event::Key(key) = event {
            match key.code {
                KeyCode::Escape => return Ok(()),
                KeyCode::Up => {
                    selected = (selected + items.len()) % (items.len() + 1);
                    continue;
                }
                KeyCode::Down => {
                    selected = (selected + 1) % (items.len() + 1);
                    continue;
                }
                KeyCode::Enter if selected == 0 => {
                    match apply(editor.text(), screen) {
                        Ok(()) => return Ok(()),
                        Err(error) => notice = error.to_string(),
                    }
                    continue;
                }
                KeyCode::Enter => {
                    let result = match items[selected - 1].key.as_str() {
                        "user" => select_user(screen, store),
                        "inbound" => select_inbound(screen, store),
                        "target" => store
                            .load()
                            .and_then(|config| select_target(screen, &config, &catalog)),
                        _ => Ok(Some(Condition::Never)),
                    };
                    match result {
                        Ok(Some(condition)) => match store.load() {
                            Ok(config) => {
                                editor.insert(&condition.text(&config));
                                selected = 0;
                                notice.clear();
                            }
                            Err(error) => notice = error.to_string(),
                        },
                        Ok(None) => {}
                        Err(error) => notice = error.to_string(),
                    }
                    continue;
                }
                _ => {}
            }
        }
        screen.edit(&mut editor, event)?;
        selected = 0;
    }
    Ok(())
}

fn relocate(rules: &mut Vec<Rule>, path: &mut Vec<usize>, direction: KeyCode) -> Result<()> {
    let (&index, parent) = path.split_last().ok_or("找不到规则")?;
    match direction {
        KeyCode::Up | KeyCode::Down => {
            let siblings = children(rules, parent)?;
            let destination = if direction == KeyCode::Up {
                index.saturating_sub(1)
            } else {
                (index + 1).min(siblings.len() - 1)
            };
            siblings.swap(index, destination);
            *path.last_mut().unwrap() = destination;
        }
        KeyCode::Right if index > 0 => {
            let siblings = children(rules, parent)?;
            let rule = siblings.remove(index);
            let sibling = &mut siblings[index - 1];
            let child = sibling.children.len();
            sibling.children.push(rule);
            path.pop();
            path.extend([index - 1, child]);
        }
        KeyCode::Left if !parent.is_empty() => {
            let rule = children(rules, parent)?.remove(index);
            let (&index, ancestor) = parent.split_last().unwrap();
            children(rules, ancestor)?.insert(index + 1, rule);
            *path = ancestor.to_vec();
            path.push(index + 1);
        }
        _ => {}
    }
    Ok(())
}

fn move_rule(
    screen: &mut Screen,
    store: &Store,
    mut path: Vec<usize>,
) -> Result<Option<Vec<usize>>> {
    let config = store.load()?;
    let mut rules = config.rules.clone();
    let mut notice = String::new();
    while !screen.exiting {
        let (paths, items) = rows(&rules, &config);
        let selected = paths
            .iter()
            .position(|current| *current == path)
            .ok_or("找不到规则")?;
        let menu = Menu {
            title: "移动规则",
            heading: "",
            items: &items,
            help: "↑↓ 调整顺序\n←→ 调整层级\n回车键 确定\nEsc 取消",
        };
        screen.menu(&menu, selected, &notice, None)?;
        let key = if let Some(argument) = screen.arguments.pop_front() {
            match argument.as_str() {
                "up" => KeyCode::Up,
                "down" => KeyCode::Down,
                "left" => KeyCode::Left,
                "right" => KeyCode::Right,
                "-" => KeyCode::Enter,
                "back" => KeyCode::Escape,
                _ => {
                    notice = format!("找不到移动操作：{argument}");
                    screen.arguments.clear();
                    continue;
                }
            }
        } else {
            match screen.event(true)? {
                Some(Event::Key(key)) => key.code,
                _ => continue,
            }
        };
        let result = match key {
            KeyCode::Escape => return Ok(None),
            KeyCode::Enter => {
                let result = screen.work(menu.title, "", |progress| {
                    store.update(progress, |config| {
                        config.rules = rules.clone();
                        Ok(())
                    })
                });
                if result.is_ok() {
                    return Ok(Some(path));
                }
                screen.arguments.clear();
                result
            }
            direction => relocate(&mut rules, &mut path, direction),
        };
        notice = result
            .err()
            .map_or_else(String::new, |error| error.to_string());
    }
    Ok(None)
}

fn edit(screen: &mut Screen, store: &Store, mut path: Vec<usize>) -> Result<Option<Vec<usize>>> {
    let mut selected = 0;
    let mut notice = String::new();
    loop {
        let config = store.load()?;
        let rule = get(&config.rules, &path)?;
        let mut items = vec![
            Item::new("condition", "条件".stylized()),
            Item::new("destination", "出站".stylized()),
            Item::new("new", "新增子规则".stylized()),
            Item::new("move", "移动规则".stylized()),
            Item::new("delete", "删除规则".foreground(AnsiColor::BrightRed)),
            Item::new("back", "返回".stylized()),
        ];
        items[0].value = rule.condition.text(&config);
        items[1].value = rule.destination.name(&config);
        let menu = Menu {
            title: "编辑规则",
            heading: "",
            items: &items,
            help: "方向键 选择\n回车键 编辑\nEsc 返回",
        };
        let result = match screen.select(&menu, &mut selected, &notice)? {
            Action::Back => return Ok(Some(path)),
            Action::Select => match items[selected].key.as_str() {
                "condition" => condition(screen, store, &path),
                "destination" => {
                    destination(screen, store, rule.destination).and_then(|destination| {
                        match destination {
                            Some(destination) => screen.work(menu.title, "", |progress| {
                                store.update(progress, |config| {
                                    get_mut(&mut config.rules, &path)?.destination = destination;
                                    Ok(())
                                })
                            }),
                            None => Ok(()),
                        }
                    })
                }
                "new" => {
                    let index = screen.work(menu.title, "", |progress| {
                        store.update(progress, |config| {
                            let rule = get_mut(&mut config.rules, &path)?;
                            let index = rule.children.len();
                            rule.children.push(Rule {
                                destination: rule.destination,
                                ..Rule::default()
                            });
                            Ok(index)
                        })
                    });
                    index.map(|index| {
                        path.push(index);
                        selected = 0;
                    })
                }
                "move" => move_rule(screen, store, path.clone()).map(|moved| {
                    if let Some(moved) = moved {
                        path = moved;
                    }
                }),
                "delete" => {
                    let result = screen.work(menu.title, "", |progress| {
                        store.update(progress, |config| {
                            let (&index, parent) = path.split_last().ok_or("找不到规则")?;
                            let siblings = children(&mut config.rules, parent)?;
                            if index >= siblings.len() {
                                return Err("找不到规则".into());
                            }
                            siblings.remove(index);
                            Ok(())
                        })
                    });
                    if result.is_ok() {
                        return Ok(None);
                    }
                    result
                }
                _ => return Ok(Some(path)),
            },
            _ => continue,
        };
        notice = result
            .err()
            .map_or_else(String::new, |error| error.to_string());
    }
}

pub fn run(screen: &mut Screen, store: &Store) -> Result<()> {
    let mut selected = 0;
    let mut focus = None;
    let mut notice = String::new();
    loop {
        let config = store.load()?;
        let (paths, mut items) = rows(&config.rules, &config);
        if let Some(path) = focus.take()
            && let Some(index) = paths.iter().position(|current| *current == path)
        {
            selected = index;
        }
        items.extend([
            Item::new("new", "创建规则".stylized()),
            Item::new("update", "更新规则数据".stylized()),
            Item::new("back", "返回".stylized()),
        ]);
        let menu = Menu {
            title: "分流",
            heading: "",
            items: &items,
            help: "方向键 选择\n回车键 编辑\nM 移动规则\nEsc 返回",
        };
        let result = match screen.select(&menu, &mut selected, &notice)? {
            Action::Back => return Ok(()),
            Action::Key(key)
                if matches!(key.code, KeyCode::Char('m' | 'M')) && selected < paths.len() =>
            {
                move_rule(screen, store, paths[selected].clone()).map(|path| focus = path)
            }
            Action::Select if selected < paths.len() => {
                edit(screen, store, paths[selected].clone()).map(|path| focus = path)
            }
            Action::Select => match items[selected].key.as_str() {
                "new" => {
                    let index = screen.work(menu.title, "", |progress| {
                        store.update(progress, |config| {
                            let index = config.rules.len();
                            config.rules.push(Rule::default());
                            Ok(index)
                        })
                    });
                    match index {
                        Ok(index) => edit(screen, store, vec![index]).map(|path| focus = path),
                        Err(error) => Err(error),
                    }
                }
                "update" => screen
                    .work("更新规则数据", "", |progress| {
                        Catalog::update(store, progress)
                    })
                    .map(|_| ()),
                _ => return Ok(()),
            },
            _ => continue,
        };
        notice = result
            .err()
            .map_or_else(String::new, |error| error.to_string());
    }
}
