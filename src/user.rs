use serde::{Deserialize, Serialize};
use termina::style::{AnsiColor, StyleExt};
use uuid::Uuid;

use crate::{
    Result,
    config::Store,
    tui::{Action, Item, Menu, Screen},
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub name: String,
    pub uuid: Uuid,
    pub password: String,
}

impl User {
    fn new() -> Result<Self> {
        Ok(Self {
            name: String::new(),
            uuid: Uuid::new_v4(),
            password: secret()?,
        })
    }

    pub fn validate(&self) -> Result<()> {
        name(&self.name)?;
        password(&self.password)
    }
}

fn name(value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err("用户名称不能为空".into());
    }
    Ok(())
}

pub fn secret() -> Result<String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|error| format!("生成主密码失败：{error}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub fn password(value: &str) -> Result<()> {
    if value.is_empty() {
        return Err("主密码不能为空".into());
    }
    if value.len() > 64 {
        return Err("主密码最多 64 个 UTF-8 字节".into());
    }
    Ok(())
}

fn edit(
    screen: &mut Screen,
    store: &Store,
    mut original: Option<Uuid>,
    mut user: User,
) -> Result<Option<Uuid>> {
    let mut selected = 0;
    let mut notice = String::new();
    loop {
        let title = if original.is_some() {
            format!("用户 / {}", user.name)
        } else {
            "新增用户".to_owned()
        };
        let mut items = vec![
            Item::new("name", "名称".stylized()),
            Item::new("uuid", "UUID".stylized()),
            Item::new("password", "主密码".stylized()),
        ];
        items[0].value = user.name.clone();
        items[1].value = user.uuid.to_string();
        items[2].value = user.password.clone();
        if original.is_some() {
            items.push(Item::new(
                "delete",
                "删除用户".foreground(AnsiColor::BrightRed),
            ));
        } else {
            items.push(Item::new("create", "创建".stylized()));
        }
        items.push(Item::new("back", "返回".stylized()));
        let menu = Menu {
            title: &title,
            heading: "",
            items: &items,
            help: "方向键 选择\n回车键 确定\nEsc 返回",
        };
        match screen.select(&menu, &mut selected, &notice)? {
            Action::Select => {}
            Action::Back => return Ok(original),
            _ => continue,
        }
        notice.clear();
        let apply = |edited: User, screen: &mut Screen| {
            if let Some(uuid) = original {
                screen.work("保存用户", &format!(" -- {}", edited.name), |progress| {
                    store.update(progress, |config| {
                        let current = config
                            .users
                            .iter_mut()
                            .find(|user| user.uuid == uuid)
                            .ok_or("用户已被删除")?;
                        *current = edited.clone();
                        if uuid != edited.uuid {
                            for rule in &mut config.rules {
                                rule.replace_user(uuid, edited.uuid);
                            }
                        }
                        Ok(())
                    })
                })?;
            }
            Ok(edited)
        };
        let edited = match items[selected].key.as_str() {
            "name" => screen.input(&menu, selected, &user.name, |value, screen| {
                name(value)?;
                apply(
                    User {
                        name: value.to_owned(),
                        ..user.clone()
                    },
                    screen,
                )
            })?,
            "uuid" => screen.input(&menu, selected, &user.uuid.to_string(), |value, screen| {
                apply(
                    User {
                        uuid: value
                            .parse()
                            .map_err(|error| format!("UUID 格式不正确：{error}"))?,
                        ..user.clone()
                    },
                    screen,
                )
            })?,
            "password" => screen.input(&menu, selected, &user.password, |value, screen| {
                password(value)?;
                apply(
                    User {
                        password: value.to_owned(),
                        ..user.clone()
                    },
                    screen,
                )
            })?,
            "create" => {
                let result =
                    screen.work("保存用户", &format!(" -- {}", user.name), |progress| {
                        store.update(progress, |config| {
                            config.users.push(user.clone());
                            Ok(())
                        })
                    });
                match result {
                    Ok(()) => return Ok(Some(user.uuid)),
                    Err(error) => notice = error.to_string(),
                }
                None
            }
            "delete" => {
                let result =
                    screen.work("删除用户", &format!(" -- {}", user.name), |progress| {
                        store.update(progress, |config| {
                            config.users.retain(|user| Some(user.uuid) != original);
                            Ok(())
                        })
                    });
                match result {
                    Ok(()) => return Ok(None),
                    Err(error) => notice = error.to_string(),
                }
                None
            }
            _ => return Ok(original),
        };
        if let Some(edited) = edited {
            original = original.map(|_| edited.uuid);
            user = edited;
        }
    }
}

pub fn create(screen: &mut Screen, store: &Store) -> Result<Option<Uuid>> {
    edit(screen, store, None, User::new()?)
}

pub fn run(screen: &mut Screen, store: &Store) -> Result<()> {
    let mut selected = 0;
    let mut notice = String::new();
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
        items.extend([
            Item::new("new", "新增用户".stylized()),
            Item::new("back", "返回".stylized()),
        ]);
        let menu = Menu {
            title: "用户",
            heading: "",
            items: &items,
            help: "方向键 选择\n回车键 确定\nEsc 返回",
        };
        match screen.select(&menu, &mut selected, &notice)? {
            Action::Select => {}
            Action::Back => return Ok(()),
            _ => continue,
        }
        if selected == config.users.len() + 1 {
            return Ok(());
        }
        let result = if let Some(user) = config.users.get(selected) {
            edit(screen, store, Some(user.uuid), user.clone())
        } else {
            create(screen, store)
        };
        notice = result
            .err()
            .map_or_else(String::new, |error| error.to_string());
    }
}
