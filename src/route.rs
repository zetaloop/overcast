use crate::language::{message, text as tr};
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
    config::{Config, Reference, Store},
    form::Value,
    geodata::Catalog,
    graph::Coverage,
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

    pub fn prune(&mut self, keep: &impl Fn(Reference) -> Result<bool>) -> Result<()> {
        self.condition.prune(keep)?;
        self.destination.prune(keep)?;
        for (index, child) in self.children.iter_mut().enumerate() {
            child
                .prune(keep)
                .map_err(|e| message!("Child rule {}: {e}", "子规则 {}：{e}", index + 1))?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "kebab-case")]
pub enum Destination {
    #[default]
    Block,
    Outbound(Uuid),
    Inbound(Uuid),
}

impl Destination {
    pub fn prune(&mut self, keep: &impl Fn(Reference) -> Result<bool>) -> Result<()> {
        let object = match *self {
            Self::Block => return Ok(()),
            Self::Outbound(uuid) => Reference::Outbound(uuid),
            Self::Inbound(uuid) => Reference::Inbound(uuid),
        };
        if !keep(object)? {
            *self = Self::Block;
        }
        Ok(())
    }

    fn name(self, config: &Config) -> String {
        match self {
            Self::Block => tr("Blackhole", "黑洞").to_owned(),
            Self::Outbound(uuid) => config
                .outbounds
                .iter()
                .find(|outbound| outbound.uuid == uuid)
                .map_or_else(|| uuid.to_string(), |outbound| outbound.name.clone()),
            Self::Inbound(uuid) => message!(
                "Inbound / {}",
                "入口 / {}",
                config
                    .inbounds
                    .iter()
                    .find(|inbound| inbound.uuid == uuid)
                    .map_or_else(|| uuid.to_string(), |inbound| inbound.name.clone())
            ),
        }
    }

    fn key(self) -> String {
        match self {
            Self::Block => "block".to_owned(),
            Self::Outbound(uuid) => uuid.to_string(),
            Self::Inbound(uuid) => format!("inbound:{uuid}"),
        }
    }
}

impl Value for Destination {
    fn text(&self) -> String {
        match Store::open(None).and_then(|store| store.load()) {
            Ok(config) => self.name(&config),
            Err(error) => error.to_string(),
        }
    }

    fn edit(&mut self, screen: &mut Screen, _: &Menu<'_>, _: usize) -> Result<bool> {
        match destination(screen, &Store::open(None)?, *self, false, |_, _| Ok(true))? {
            Some(value) => {
                *self = value;
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

fn get<'a>(rules: &'a [Rule], path: &[usize]) -> Result<&'a Rule> {
    let (index, rest) = path
        .split_first()
        .ok_or(tr("Rule not found", "找不到规则"))?;
    let rule = rules
        .get(*index)
        .ok_or(tr("Rule not found", "找不到规则"))?;
    if rest.is_empty() {
        Ok(rule)
    } else {
        get(&rule.children, rest)
    }
}

fn get_mut<'a>(rules: &'a mut [Rule], path: &[usize]) -> Result<&'a mut Rule> {
    let (index, rest) = path
        .split_first()
        .ok_or(tr("Rule not found", "找不到规则"))?;
    let rule = rules
        .get_mut(*index)
        .ok_or(tr("Rule not found", "找不到规则"))?;
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

fn rows(
    rules: &[Rule],
    config: &Config,
    coverage: Option<&Coverage>,
) -> (Vec<Vec<usize>>, Vec<Item>) {
    fn append(
        rules: &[Rule],
        config: &Config,
        coverage: Option<&Coverage>,
        path: &mut Vec<usize>,
        prefix: &str,
        rows: &mut Vec<(Vec<usize>, Item)>,
    ) {
        for (index, rule) in rules.iter().enumerate() {
            path.push(index);
            let key = path
                .iter()
                .map(|index| (index + 1).to_string())
                .collect::<Vec<_>>()
                .join(".");
            let label = match &rule.condition {
                Condition::Always => tr("All", "全部").to_owned(),
                condition => condition.text(config),
            };
            let last = index + 1 == rules.len();
            let root = path.len() == 1;
            let reached = coverage.is_none_or(|coverage| {
                coverage
                    .reached
                    .iter()
                    .any(|reached| reached.starts_with(path))
            });
            let mut item = Item::new(
                key,
                if reached {
                    label.stylized()
                } else {
                    label.foreground(AnsiColor::BrightBlack)
                },
            );
            item.branch = Some(match (root, last) {
                (true, _) => String::new(),
                (false, true) => format!("{prefix}└─ "),
                (false, false) => format!("{prefix}├─ "),
            });
            item.value = rule.destination.name(config);
            rows.push((path.clone(), item));
            let prefix = match (root, last) {
                (true, _) => String::new(),
                (false, true) => format!("{prefix}   "),
                (false, false) => format!("{prefix}│  "),
            };
            append(&rule.children, config, coverage, path, &prefix, rows);
            path.pop();
        }
    }
    let mut rows = Vec::new();
    append(rules, config, coverage, &mut Vec::new(), "", &mut rows);
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
        items.push(Item::new("new", tr("Add user", "新增用户").stylized()));
        match screen.search(tr("Select user", "选择用户"), &items, 0)? {
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
    Ok(
        inbound::select(screen, store, None, |inbound| inbound.protocol.routing())?
            .map(Condition::Inbound),
    )
}

fn select_target(screen: &mut Screen, store: &Store) -> Result<Option<Condition>> {
    let targets = [
        ("domain", tr("Domain", "域名")),
        ("suffix", tr("Domain and subdomains", "域名及子域")),
        ("keyword", tr("Domain keyword", "域名关键词")),
        ("regex", tr("Domain regex", "域名正则")),
        ("ip", tr("IP address or subnet", "IP 地址或网段")),
        ("site", "GeoSite"),
        ("geoip", "GeoIP"),
        ("asn", "ASN"),
        ("back", tr("Back", "返回")),
    ];
    let mut items: Vec<_> = targets
        .iter()
        .map(|&(key, label)| Item::new(key, label.stylized()))
        .collect();
    items[5].gap = true;
    let menu = Menu {
        title: tr("Select target", "选择目标"),
        heading: "",
        items: &items,
        help: tr(
            "Arrow keys to select\nEnter to confirm\nEsc to go back",
            "方向键 选择\n回车键 确定\nEsc 返回",
        ),
    };
    let mut selected = 0;
    let mut catalog = None;
    loop {
        match screen.select(&menu, &mut selected, "")? {
            Action::Back => return Ok(None),
            Action::Select => {}
            _ => continue,
        }
        let (kind, label) = targets[selected];
        if kind == "back" {
            return Ok(None);
        }
        if matches!(kind, "site" | "geoip" | "asn") {
            let catalog = match &catalog {
                Some(value) => value,
                None => catalog.insert(screen.work(
                    tr("Reading routing data", "读取规则数据"),
                    "",
                    |progress| {
                        let mut release = crate::resource::Resources::load(store)?.geodata;
                        Catalog::ensure(store, &mut release, progress)
                    },
                )?),
            };
            let choices: Vec<_> = match kind {
                "asn" => catalog
                    .asns
                    .iter()
                    .map(|(number, org)| {
                        let mut item =
                            Item::new(number.to_string(), format!("AS{number}").stylized());
                        item.value = org.clone();
                        item
                    })
                    .collect(),
                _ => (if kind == "site" {
                    &catalog.sites
                } else {
                    &catalog.ips
                })
                .iter()
                .map(|name| Item::new(name, name.clone().stylized()))
                .collect(),
            };
            if let Some(index) = screen.search(label, &choices, 0)? {
                let name = &choices[index].key;
                return Ok(Some(match kind {
                    "site" => Condition::Site(name.clone()),
                    "geoip" => Condition::Geoip(name.clone()),
                    _ => Condition::Asn(name.parse()?),
                }));
            }
        } else if let Some(condition) = screen.input(&menu, selected, "", |value, _| {
            Condition::literal(kind, value)
        })? {
            return Ok(Some(condition));
        }
    }
}

pub(crate) fn destination(
    screen: &mut Screen,
    store: &Store,
    current: Destination,
    routing: bool,
    available: impl Fn(&Config, Destination) -> Result<bool>,
) -> Result<Option<Destination>> {
    loop {
        let config = store.load()?;
        let mut values = vec![Destination::Block];
        values.extend(
            config
                .outbounds
                .iter()
                .map(|outbound| Destination::Outbound(outbound.uuid)),
        );
        if routing {
            values.extend(
                config
                    .inbounds
                    .iter()
                    .map(|inbound| Destination::Inbound(inbound.uuid)),
            );
        }
        let mut candidates = Vec::new();
        for value in values {
            if available(&config, value)? {
                candidates.push(value);
            }
        }
        let mut values = candidates;
        if !values.contains(&current) && available(&config, current)? {
            values.push(current);
        }
        let selected = values
            .iter()
            .position(|value| *value == current)
            .unwrap_or(0);
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
                if let Destination::Inbound(uuid) = value
                    && let Some(inbound) =
                        config.inbounds.iter().find(|inbound| inbound.uuid == *uuid)
                {
                    item.value = inbound.summary();
                }
                item
            })
            .collect();
        items.push(Item::new(
            "new",
            tr("Create outbound", "创建出站").stylized(),
        ));
        if routing {
            items.push(Item::new(
                "inbound",
                tr("Create inbound", "创建入站").stylized(),
            ));
        }
        let menu = Menu {
            title: if routing {
                tr("Select destination", "选择去向")
            } else {
                tr("Select outbound", "选择出站")
            },
            heading: "",
            items: &items,
            help: "",
        };
        match screen.search(menu.title, &items, selected)? {
            Some(index) if index < values.len() => return Ok(Some(values[index])),
            Some(index) if items[index].key == "inbound" => {
                if let Some(uuid) = inbound::create(screen, store, &menu, index)? {
                    return Ok(Some(Destination::Inbound(uuid)));
                }
            }
            Some(_) => {
                if let Some(uuid) = outbound::create(screen, store)? {
                    let value = Destination::Outbound(uuid);
                    if available(&store.load()?, value)? {
                        return Ok(Some(value));
                    }
                }
            }
            None => return Ok(None),
        }
    }
}

fn condition(screen: &mut Screen, store: &Store, path: &[usize]) -> Result<()> {
    let config = store.load()?;
    let condition = &get(&config.rules, path)?.condition;
    let bindings = condition.bindings(&config);
    let mut editor = Editor::new(condition.text(&config));
    editor.move_to(editor.text().len(), false);
    let mut selected: usize = 0;
    let mut notice = String::new();
    let items: Vec<_> = [
        ("user", tr("User", "用户")),
        ("inbound", tr("Inbound", "入站")),
        ("target", tr("Target", "目标")),
        ("block", tr("Blackhole", "黑洞")),
    ]
    .into_iter()
    .map(|(key, label)| {
        let mut item = Item::new(key, label.stylized());
        item.marker = "+";
        item
    })
    .collect();
    let apply = |text: &str, screen: &mut Screen| {
        screen.work(tr("Edit condition", "编辑条件"), text, |progress| {
            store.update(progress, |config, resources| {
                let condition = Condition::parse(
                    text,
                    config,
                    || Catalog::ensure(store, &mut resources.geodata, progress),
                    &bindings,
                )?;
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
            tr("Edit condition", "编辑条件"),
            &mut editor,
            items.iter(),
            selected.checked_sub(1),
            &notice,
            tr("↑↓ to select\nEnter to confirm\nEsc to cancel\nCtrl+A to select all\nCtrl+C to copy / Ctrl+X to cut", "↑↓ 选择\n回车键 确定\nEsc 取消\nCtrl+A 全选\nCtrl+C 复制 / Ctrl+X 剪切"),
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
                        "target" => select_target(screen, store),
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
    let (&index, parent) = path
        .split_last()
        .ok_or(tr("Rule not found", "找不到规则"))?;
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
        let (paths, items) = rows(&rules, &config, None);
        let selected = paths
            .iter()
            .position(|current| *current == path)
            .ok_or(tr("Rule not found", "找不到规则"))?;
        let menu = Menu {
            title: tr("Move rule", "移动规则"),
            heading: "",
            items: &items,
            help: tr(
                "Arrow keys to move\nEnter to confirm\nEsc to cancel",
                "方向键 移动\n回车键 确定\nEsc 取消",
            ),
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
                    notice = message!(
                        "Unknown move command: {argument}",
                        "找不到移动操作：{argument}"
                    );
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
                    store.update(progress, |config, _| {
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
            Item::new("condition", tr("Condition", "条件").stylized()),
            Item::new("destination", tr("Destination", "去向").stylized()),
            Item::new("new", tr("Add child rule", "新增子规则").stylized()),
            Item::new("move", tr("Move rule", "移动规则").stylized()),
            Item::new(
                "delete",
                tr("Delete rule", "删除规则").foreground(AnsiColor::BrightRed),
            ),
            Item::new("back", tr("Back", "返回").stylized()),
        ];
        items[0].value = if rule.condition == Condition::Always {
            tr("All", "全部").to_owned()
        } else {
            rule.condition.text(&config)
        };
        items[1].value = rule.destination.name(&config);
        items[0].show_value = true;
        items[1].show_value = true;
        items[2].gap = true;
        let menu = Menu {
            title: tr("Edit rule", "编辑规则"),
            heading: "",
            items: &items,
            help: tr(
                "Arrow keys to select\nEnter to edit\nEsc to go back",
                "方向键 选择\n回车键 编辑\nEsc 返回",
            ),
        };
        let result = match screen.select(&menu, &mut selected, &notice)? {
            Action::Back => return Ok(Some(path)),
            Action::Select => match items[selected].key.as_str() {
                "condition" => condition(screen, store, &path),
                "destination" => {
                    destination(screen, store, rule.destination, true, |_, _| Ok(true)).and_then(
                        |destination| match destination {
                            Some(destination) => screen.work(menu.title, "", |progress| {
                                store.update(progress, |config, _| {
                                    get_mut(&mut config.rules, &path)?.destination = destination;
                                    Ok(())
                                })
                            }),
                            None => Ok(()),
                        },
                    )
                }
                "new" => {
                    let index = screen.work(menu.title, "", |progress| {
                        store.update(progress, |config, _| {
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
                        store.update(progress, |config, _| {
                            let (&index, parent) = path
                                .split_last()
                                .ok_or(tr("Rule not found", "找不到规则"))?;
                            let siblings = children(&mut config.rules, parent)?;
                            if index >= siblings.len() {
                                return Err(tr("Rule not found", "找不到规则").into());
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
        let deployment = crate::service::Deployment::confirmed(store)?;
        let config = &deployment.config;
        let (paths, mut items) = rows(&config.rules, config, Some(&deployment.coverage));
        if deployment.coverage.remainder {
            let mut item = Item::new("", tr("Remaining traffic", "其余流量").stylized());
            item.branch = Some(String::new());
            item.value = Destination::Block.name(config);
            item.inert = true;
            items.push(item);
        }
        let mut create = Item::new("new", tr("Create rule", "创建规则").stylized());
        create.gap = true;
        if let Some(path) = focus.take()
            && let Some(index) = paths.iter().position(|current| *current == path)
        {
            selected = index;
        }
        items.extend([create, Item::new("back", tr("Back", "返回").stylized())]);
        let menu = Menu {
            title: tr("Routing", "分流"),
            heading: "",
            items: &items,
            help: tr(
                "Arrow keys to select\nEnter to edit\nEsc to go back",
                "方向键 选择\n回车键 编辑\nEsc 返回",
            ),
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
                        store.update(progress, |config, _| {
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
                _ => return Ok(()),
            },
            _ => continue,
        };
        notice = result
            .err()
            .map_or_else(String::new, |error| error.to_string());
    }
}
