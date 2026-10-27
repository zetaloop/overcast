use std::{collections::BTreeMap, fmt::Display, str::FromStr};

use termina::{
    event::{KeyCode, Modifiers},
    style::StyleExt,
};

use crate::{
    Result,
    tui::{Action, Item, Menu, Screen},
};

pub trait Value: Clone + Default {
    fn text(&self) -> String {
        String::new()
    }

    fn marker(&self) -> &'static str {
        ">"
    }

    fn edit(&mut self, screen: &mut Screen, menu: &Menu<'_>, selected: usize) -> Result<bool>;
}

pub trait Field {
    fn item(&self) -> Item;
    fn edit(&mut self, screen: &mut Screen, menu: &Menu<'_>, selected: usize) -> Result<bool>;
    fn reset(&mut self);
}

pub type Fields<'a> = Vec<Box<dyn Field + 'a>>;

pub trait Form: Default {
    fn fields(&mut self, defaults: Self) -> Fields<'_>;
}

struct Binding<'a, T> {
    key: &'static str,
    label: &'static str,
    value: &'a mut T,
    default: T,
}

pub fn field<'a, T: Value>(
    key: &'static str,
    label: &'static str,
    value: &'a mut T,
    default: T,
) -> Box<dyn Field + 'a> {
    Box::new(Binding {
        key,
        label,
        value,
        default,
    })
}

impl<T: Value> Field for Binding<'_, T> {
    fn item(&self) -> Item {
        let mut item = Item::new(self.key, self.label.stylized());
        item.value = self.value.text();
        item.marker = self.value.marker();
        item
    }

    fn edit(&mut self, screen: &mut Screen, menu: &Menu<'_>, selected: usize) -> Result<bool> {
        self.value.edit(screen, menu, selected)
    }

    fn reset(&mut self) {
        *self.value = self.default.clone();
    }
}

pub fn edit<T: Form>(screen: &mut Screen, title: &str, value: &mut T) -> Result<bool> {
    let mut fields = value.fields(T::default());
    let mut selected = 0;
    let mut notice = String::new();
    let mut changed = false;
    loop {
        let mut items: Vec<_> = fields.iter().map(|field| field.item()).collect();
        items.push(Item::new("back", "返回".stylized()));
        let menu = Menu {
            title,
            heading: "",
            items: &items,
            help: "方向键 选择\n回车键 编辑\nDel 恢复默认\nEsc 返回",
        };
        let result = match screen.select(&menu, &mut selected, &notice)? {
            Action::Back => return Ok(changed),
            Action::Select if selected == fields.len() => return Ok(changed),
            Action::Select => fields[selected].edit(screen, &menu, selected),
            Action::Key(key) if key.code == KeyCode::Delete && selected < fields.len() => {
                fields[selected].reset();
                Ok(true)
            }
            _ => continue,
        };
        match result {
            Ok(edited) => {
                changed |= edited;
                notice.clear();
            }
            Err(error) => notice = error.to_string(),
        }
    }
}

fn input<T: Display + FromStr>(
    value: &mut T,
    screen: &mut Screen,
    menu: &Menu<'_>,
    selected: usize,
) -> Result<bool>
where
    T::Err: Display,
{
    let Some(edited) = screen.input(menu, selected, &value.to_string(), |text| {
        text.parse()
            .map_err(|error| format!("格式不正确：{error}").into())
    })?
    else {
        return Ok(false);
    };
    *value = edited;
    Ok(true)
}

macro_rules! scalar {
    ($($ty:ty),* $(,)?) => {
        $(impl Value for $ty {
            fn text(&self) -> String { self.to_string() }
            fn edit(&mut self, screen: &mut Screen, menu: &Menu<'_>, selected: usize) -> Result<bool> {
                input(self, screen, menu, selected)
            }
        })*
    };
}

scalar!(String, u8, u16, u32, u64);

impl Value for bool {
    fn text(&self) -> String {
        if *self { "开启" } else { "关闭" }.to_owned()
    }

    fn marker(&self) -> &'static str {
        if *self { "■" } else { "□" }
    }

    fn edit(&mut self, _: &mut Screen, _: &Menu<'_>, _: usize) -> Result<bool> {
        *self = !*self;
        Ok(true)
    }
}

impl<T: Value> Value for Option<T> {
    fn text(&self) -> String {
        self.as_ref().map_or_else(|| "默认".to_owned(), Value::text)
    }

    fn marker(&self) -> &'static str {
        self.as_ref().map_or(">", Value::marker)
    }

    fn edit(&mut self, screen: &mut Screen, menu: &Menu<'_>, selected: usize) -> Result<bool> {
        let mut value = self.clone().unwrap_or_default();
        if value.edit(screen, menu, selected)? {
            *self = Some(value);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl<T: Value> Value for Vec<T> {
    fn edit(&mut self, screen: &mut Screen, parent: &Menu<'_>, field: usize) -> Result<bool> {
        let title = format!("{} / {}", parent.title, parent.items[field].label.content);
        let mut selected = 0;
        let mut notice = String::new();
        let mut changed = false;
        loop {
            let mut items: Vec<_> = self
                .iter()
                .enumerate()
                .map(|(index, value)| {
                    let mut item = Item::new(index.to_string(), (index + 1).to_string().stylized());
                    item.value = value.text();
                    item.marker = value.marker();
                    item
                })
                .collect();
            items.extend([
                Item::new("add", "添加".stylized()),
                Item::new("back", "返回".stylized()),
            ]);
            let menu = Menu {
                title: &title,
                heading: "",
                items: &items,
                help: "方向键 选择\n回车键 编辑\nDel 删除\nAlt+↑↓ 移动\nEsc 返回",
            };
            let result = match screen.select(&menu, &mut selected, &notice)? {
                Action::Back => return Ok(changed),
                Action::Select if selected == self.len() + 1 => return Ok(changed),
                Action::Select if selected == self.len() => {
                    let mut value = T::default();
                    match value.edit(screen, &menu, selected) {
                        Ok(true) => {
                            self.push(value);
                            Ok(true)
                        }
                        other => other,
                    }
                }
                Action::Select => self[selected].edit(screen, &menu, selected),
                Action::Key(key) if key.code == KeyCode::Delete && selected < self.len() => {
                    self.remove(selected);
                    Ok(true)
                }
                Action::Key(key)
                    if key.modifiers.contains(Modifiers::ALT)
                        && matches!(key.code, KeyCode::Up | KeyCode::Down)
                        && selected < self.len() =>
                {
                    let destination = if key.code == KeyCode::Up {
                        selected.saturating_sub(1)
                    } else {
                        (selected + 1).min(self.len() - 1)
                    };
                    self.swap(selected, destination);
                    selected = destination;
                    Ok(true)
                }
                _ => continue,
            };
            match result {
                Ok(edited) => {
                    changed |= edited;
                    notice.clear();
                }
                Err(error) => notice = error.to_string(),
            }
        }
    }
}

impl<T: Value> Value for BTreeMap<String, T> {
    fn edit(&mut self, screen: &mut Screen, parent: &Menu<'_>, field: usize) -> Result<bool> {
        let title = format!("{} / {}", parent.title, parent.items[field].label.content);
        let mut selected = 0;
        let mut notice = String::new();
        let mut changed = false;
        loop {
            let keys: Vec<_> = self.keys().cloned().collect();
            let mut items: Vec<_> = self
                .iter()
                .map(|(key, value)| {
                    let mut item = Item::new(key.clone(), key.clone().stylized());
                    item.value = value.text();
                    item.marker = value.marker();
                    item
                })
                .collect();
            items.extend([
                Item::new("add", "添加".stylized()),
                Item::new("back", "返回".stylized()),
            ]);
            let menu = Menu {
                title: &title,
                heading: "",
                items: &items,
                help: "方向键 选择\n回车键 编辑\nDel 删除\nEsc 返回",
            };
            let result = match screen.select(&menu, &mut selected, &notice)? {
                Action::Back => return Ok(changed),
                Action::Select if selected == self.len() + 1 => return Ok(changed),
                Action::Select if selected == self.len() => {
                    let Some(key) = screen.input(&menu, selected, "", |key| {
                        if self.contains_key(key) {
                            return Err("这个名称已经存在".into());
                        }
                        Ok(key.to_owned())
                    })?
                    else {
                        continue;
                    };
                    let mut value = T::default();
                    let items = [Item::new(key.clone(), key.clone().stylized())];
                    let entry = Menu {
                        items: &items,
                        ..menu
                    };
                    match value.edit(screen, &entry, 0) {
                        Ok(true) => {
                            self.insert(key.clone(), value);
                            selected = self.keys().position(|name| name == &key).unwrap_or(0);
                            Ok(true)
                        }
                        other => other,
                    }
                }
                Action::Select => self
                    .get_mut(&keys[selected])
                    .ok_or("项目已被删除")?
                    .edit(screen, &menu, selected),
                Action::Key(key) if key.code == KeyCode::Delete && selected < keys.len() => {
                    self.remove(&keys[selected]);
                    Ok(true)
                }
                _ => continue,
            };
            match result {
                Ok(edited) => {
                    changed |= edited;
                    notice.clear();
                }
                Err(error) => notice = error.to_string(),
            }
        }
    }
}

pub fn choose<T: PartialEq + Clone>(
    value: &mut T,
    screen: &mut Screen,
    parent: &Menu<'_>,
    field: usize,
    choices: &[(&str, &str, T)],
) -> Result<bool> {
    let title = format!("{} / {}", parent.title, parent.items[field].label.content);
    let mut items: Vec<_> = choices
        .iter()
        .map(|(key, label, _)| Item::new(*key, (*label).to_owned().stylized()))
        .collect();
    items.push(Item::new("back", "返回".stylized()));
    let menu = Menu {
        title: &title,
        heading: "",
        items: &items,
        help: "方向键 选择\n回车键 确定\nEsc 返回",
    };
    let mut selected = choices
        .iter()
        .position(|(_, _, choice)| choice == value)
        .unwrap_or(0);
    loop {
        match screen.select(&menu, &mut selected, "")? {
            Action::Back => return Ok(false),
            Action::Select if selected == choices.len() => return Ok(false),
            Action::Select => {
                *value = choices[selected].2.clone();
                return Ok(true);
            }
            _ => {}
        }
    }
}

macro_rules! fields {
    ($ty:ty { $($field:ident: $label:tt),* $(,)? }) => {
        impl $crate::form::Form for $ty {
            fn fields(&mut self, defaults: Self) -> $crate::form::Fields<'_> {
                let Self { $($field),* } = self;
                let mut fields = Vec::new();
                $($crate::form::fields!(@push fields, $field, defaults.$field, $label);)*
                fields
            }
        }
        $crate::form::group!($ty);
    };
    (@push $fields:ident, $field:ident, $default:expr, ..) => {
        $fields.extend($crate::form::Form::fields($field, $default));
    };
    (@push $fields:ident, $field:ident, $default:expr, $label:literal) => {
        $fields.push($crate::form::field(stringify!($field), $label, $field, $default));
    };
}

macro_rules! group {
    ($ty:ty) => {
        impl $crate::form::Value for $ty {
            fn edit(
                &mut self,
                screen: &mut $crate::tui::Screen,
                menu: &$crate::tui::Menu<'_>,
                selected: usize,
            ) -> $crate::Result<bool> {
                let title = format!("{} / {}", menu.title, menu.items[selected].label.content);
                $crate::form::edit(screen, &title, self)
            }
        }
    };
}

macro_rules! choices {
    ($ty:ty { $($variant:ident: $key:literal => $label:literal),* $(,)? }) => {
        impl $crate::form::Value for $ty {
            fn text(&self) -> String {
                match self { $(Self::$variant => $label.to_owned()),* }
            }

            fn edit(&mut self, screen: &mut $crate::tui::Screen, menu: &$crate::tui::Menu<'_>, selected: usize) -> $crate::Result<bool> {
                $crate::form::choose(self, screen, menu, selected, &[$(($key, $label, Self::$variant)),*])
            }
        }
    };
}

pub(crate) use {choices, fields, group};
