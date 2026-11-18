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

    fn choices() -> Vec<(&'static str, &'static str, Self)> {
        Vec::new()
    }

    fn edit(&mut self, screen: &mut Screen, menu: &Menu<'_>, selected: usize) -> Result<bool>;

    fn create(screen: &mut Screen, menu: &Menu<'_>, selected: usize) -> Result<Option<Self>> {
        let mut value = Self::default();
        let accepted = value.edit(screen, menu, selected)?;
        Ok(accepted.then_some(value))
    }

    fn optional(
        value: &mut Option<Self>,
        screen: &mut Screen,
        menu: &Menu<'_>,
        selected: usize,
    ) -> Result<bool> {
        if let Some(value) = value {
            return value.edit(screen, menu, selected);
        }
        *value = Self::create(screen, menu, selected)?;
        Ok(value.is_some())
    }
}

pub trait Field {
    fn key(&self) -> &'static str;
    fn item(&self) -> Item;
    fn edit(&mut self, screen: &mut Screen, menu: &Menu<'_>, selected: usize) -> Result<bool>;
    fn reset(&mut self);
}

pub type Fields<'a> = Vec<Box<dyn Field + 'a>>;

pub struct Group {
    pub key: &'static str,
    pub label: &'static str,
    pub fields: &'static [&'static str],
}

pub trait Form: Clone + Default {
    fn fields(&mut self, defaults: Self) -> Fields<'_>;

    fn groups(&self) -> Vec<Group> {
        Vec::new()
    }
}

struct Binding<'a, T, E> {
    key: &'static str,
    label: &'static str,
    value: &'a mut T,
    default: T,
    preview: Option<String>,
    edit: E,
}

pub fn field<'a, T: Value>(
    key: &'static str,
    label: &'static str,
    value: &'a mut T,
    default: T,
) -> Box<dyn Field + 'a> {
    control(key, label, value, default, None, T::edit)
}

pub fn control<'a, T: Value>(
    key: &'static str,
    label: &'static str,
    value: &'a mut T,
    default: T,
    preview: Option<String>,
    edit: impl FnMut(&mut T, &mut Screen, &Menu<'_>, usize) -> Result<bool> + 'a,
) -> Box<dyn Field + 'a> {
    Box::new(Binding {
        key,
        label,
        value,
        default,
        preview,
        edit,
    })
}

impl<T: Value, E: FnMut(&mut T, &mut Screen, &Menu<'_>, usize) -> Result<bool>> Field
    for Binding<'_, T, E>
{
    fn key(&self) -> &'static str {
        self.key
    }
    fn item(&self) -> Item {
        let mut item = Item::new(self.key, self.label.stylized());
        item.value = self.preview.clone().unwrap_or_else(|| self.value.text());
        item.marker = self.value.marker();
        item
    }

    fn edit(&mut self, screen: &mut Screen, menu: &Menu<'_>, selected: usize) -> Result<bool> {
        (self.edit)(self.value, screen, menu, selected)
    }

    fn reset(&mut self) {
        *self.value = self.default.clone();
    }
}

pub fn choice_field<'a, T: Value + PartialEq>(
    key: &'static str,
    label: &'static str,
    value: &'a mut T,
    default: T,
    allowed: impl Fn(&T) -> bool + 'a,
) -> Box<dyn Field + 'a> {
    control(
        key,
        label,
        value,
        default,
        None,
        move |value, screen, menu, _| {
            let choices: Vec<_> = T::choices()
                .into_iter()
                .filter(|(_, _, v)| allowed(v))
                .collect();
            let current = choices.iter().position(|(_, _, v)| v == value).unwrap_or(0);
            choose(
                value,
                screen,
                &format!("{} / {label}", menu.title),
                &choices,
                current,
            )
        },
    )
}

pub fn edit<T: Form>(screen: &mut Screen, title: &str, value: &mut T) -> Result<bool> {
    subset(screen, title, value, |_| true)
}

pub fn subset<T: Form>(
    screen: &mut Screen,
    title: &str,
    value: &mut T,
    allowed: impl Fn(&str) -> bool,
) -> Result<bool> {
    edit_group(screen, title, value, None, None, None, &allowed)
}

pub fn retain<T: Form>(value: &mut T, allowed: impl Fn(&str) -> bool) {
    for mut field in value.fields(T::default()) {
        if !allowed(field.key()) {
            field.reset();
        }
    }
}

type Submit<'a, T> = dyn Fn(&T, &mut Screen) -> Result<()> + 'a;
type Confirm<'a, T> = (&'a dyn Fn(&T) -> bool, &'a Submit<'a, T>);

pub fn page<T: Form + PartialEq>(
    screen: &mut Screen,
    title: &str,
    value: &T,
    save: impl Fn(&T, &mut Screen) -> Result<()>,
) -> Result<()> {
    edit_group(
        screen,
        title,
        &mut value.clone(),
        None,
        Some((&|draft| draft != value, &save)),
        None,
        &|_| true,
    )
    .map(|_| ())
}

pub fn optional<T: Form>(
    slot: &mut Option<T>,
    screen: &mut Screen,
    menu: &Menu<'_>,
    selected: usize,
) -> Result<bool> {
    let mut enabled = slot.is_some();
    let mut value = slot.clone().unwrap_or_default();
    let title = format!("{} / {}", menu.title, menu.items[selected].label.content);
    let changed = edit_group(
        screen,
        &title,
        &mut value,
        None,
        None,
        Some(&mut enabled),
        &|_| true,
    )?;
    if changed {
        *slot = enabled.then_some(value);
    }
    Ok(changed)
}

fn edit_group<T: Form>(
    screen: &mut Screen,
    title: &str,
    value: &mut T,
    group: Option<&Group>,
    submit: Option<Confirm<'_, T>>,
    mut enabled: Option<&mut bool>,
    allowed: &dyn Fn(&str) -> bool,
) -> Result<bool> {
    let mut selected = 0;
    let mut notice = String::new();
    let mut changed = false;
    loop {
        let pending = submit.is_some_and(|(dirty, _)| dirty(value));
        let active = enabled.as_deref().copied().unwrap_or(true);
        let mut groups = if active && group.is_none() {
            value.groups()
        } else {
            Vec::new()
        };
        let mut fields = if active {
            value.fields(T::default())
        } else {
            Vec::new()
        };
        fields.retain(|field| allowed(field.key()));
        groups.retain(|group| {
            fields
                .iter()
                .any(|field| group.fields.contains(&field.key()))
        });
        fields.retain(|field| match group {
            Some(group) => group.fields.contains(&field.key()),
            None => !groups
                .iter()
                .any(|group| group.fields.contains(&field.key())),
        });
        if let Some(flag) = enabled.as_deref_mut() {
            fields.insert(0, field("use", "启用", flag, false));
        }
        let mut items: Vec<_> = fields.iter().map(|field| field.item()).collect();
        items.extend(
            groups
                .iter()
                .map(|group| Item::new(group.key, group.label.stylized())),
        );
        let editing = pending;
        if editing {
            let mut save = Item::new("apply", "确定".stylized());
            save.gap = true;
            items.push(save);
        }
        items.push(Item::new(
            "back",
            if editing { "取消" } else { "返回" }.stylized(),
        ));
        let menu = Menu {
            title,
            heading: "",
            items: &items,
            help: if editing {
                "方向键 选择\n回车键 编辑\nDel 恢复默认\nEsc 取消"
            } else {
                "方向键 选择\n回车键 编辑\nDel 恢复默认\nEsc 返回"
            },
        };
        let result = match screen.select(&menu, &mut selected, &notice)? {
            Action::Back => return Ok(!editing && changed),
            Action::Select if selected == items.len() - 1 => return Ok(!editing && changed),
            Action::Select if editing && selected == fields.len() + groups.len() => {
                drop(fields);
                match (submit.unwrap().1)(value, screen) {
                    Ok(()) => return Ok(true),
                    Err(error) => Err(error),
                }
            }
            Action::Select if selected >= fields.len() => {
                let group = &groups[selected - fields.len()];
                drop(fields);
                edit_group(
                    screen,
                    &format!("{title} / {}", group.label),
                    value,
                    Some(group),
                    None,
                    None,
                    allowed,
                )
            }
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
    let Some(edited) = screen.input(menu, selected, &value.to_string(), |text, _| {
        let edited = text
            .parse()
            .map_err(|error| format!("格式不正确：{error}"))?;
        Ok(edited)
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

scalar!(String, u8, u16, u32, u64, i32, i64, uuid::Uuid);

impl Value for bool {
    fn text(&self) -> String {
        if *self { "开启" } else { "关闭" }.to_owned()
    }

    fn marker(&self) -> &'static str {
        if *self { "■" } else { "□" }
    }

    fn choices() -> Vec<(&'static str, &'static str, Self)> {
        vec![("on", "开启", true), ("off", "关闭", false)]
    }

    fn edit(&mut self, _: &mut Screen, _: &Menu<'_>, _: usize) -> Result<bool> {
        *self = !*self;
        Ok(true)
    }
}

impl<T: Value> Value for Option<T> {
    fn text(&self) -> String {
        self.as_ref().map_or_else(
            || "默认".to_owned(),
            |value| match value.text() {
                text if text.is_empty() => "已设置".to_owned(),
                text => text,
            },
        )
    }

    fn marker(&self) -> &'static str {
        self.as_ref().map_or(">", Value::marker)
    }

    fn edit(&mut self, screen: &mut Screen, menu: &Menu<'_>, selected: usize) -> Result<bool> {
        let choices = T::choices();
        if !choices.is_empty() {
            let choices: Vec<_> = std::iter::once(("default", "默认", None))
                .chain(
                    choices
                        .into_iter()
                        .map(|(key, label, value)| (key, label, Some(value))),
                )
                .collect();
            let current = match self.as_ref() {
                None => 0,
                Some(value) => choices
                    .iter()
                    .position(|(_, _, choice)| {
                        choice
                            .as_ref()
                            .is_some_and(|choice| choice.text() == value.text())
                    })
                    .unwrap(),
            };
            let title = format!("{} / {}", menu.title, menu.items[selected].label.content);
            return choose(self, screen, &title, &choices, current);
        }
        T::optional(self, screen, menu, selected)
    }
}

impl<T: Value> Value for Vec<T> {
    fn text(&self) -> String {
        if self.is_empty() {
            return "空".to_owned();
        }
        let values: Vec<_> = self.iter().map(Value::text).collect();
        if values.iter().any(String::is_empty) {
            format!("{} 项", self.len())
        } else {
            values.join("、")
        }
    }

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
                    let mut item =
                        Item::new((index + 1).to_string(), (index + 1).to_string().stylized());
                    item.value = value.text();
                    item.marker = value.marker();
                    item.show_value = true;
                    item
                })
                .collect();
            let mut add = Item::new("add", "添加".stylized());
            add.gap = !items.is_empty();
            items.push(add);
            items.push(Item::new("back", "返回".stylized()));
            let menu = Menu {
                title: &title,
                heading: "",
                items: &items,
                help: "方向键 选择\n回车键 编辑\nDel 删除\nAlt+↑↓ 移动\nEsc 返回",
            };
            let result = match screen.select(&menu, &mut selected, &notice)? {
                Action::Back => return Ok(changed),
                Action::Select if selected == items.len() - 1 => return Ok(changed),
                Action::Select if selected == self.len() => {
                    T::create(screen, &menu, selected).map(|value| {
                        if let Some(value) = value {
                            self.push(value);
                            true
                        } else {
                            false
                        }
                    })
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
    fn text(&self) -> String {
        if self.is_empty() {
            "空".to_owned()
        } else {
            self.keys().cloned().collect::<Vec<_>>().join("、")
        }
    }

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
                    item.show_value = true;
                    item
                })
                .collect();
            let mut add = Item::new("add", "添加".stylized());
            add.gap = !items.is_empty();
            items.push(add);
            items.push(Item::new("back", "返回".stylized()));
            let menu = Menu {
                title: &title,
                heading: "",
                items: &items,
                help: "方向键 选择\n回车键 编辑\nDel 删除\nEsc 返回",
            };
            let result = match screen.select(&menu, &mut selected, &notice)? {
                Action::Back => return Ok(changed),
                Action::Select if selected == items.len() - 1 => return Ok(changed),
                Action::Select if selected == self.len() => {
                    let Some(key) = screen.input(&menu, selected, "", |key, _| {
                        if self.contains_key(key) {
                            return Err("这个名称已经存在".into());
                        }
                        Ok(key.to_owned())
                    })?
                    else {
                        continue;
                    };
                    let items = [Item::new(key.clone(), key.clone().stylized())];
                    let entry = Menu {
                        items: &items,
                        ..menu
                    };
                    T::create(screen, &entry, 0).map(|value| {
                        if let Some(value) = value {
                            self.insert(key.clone(), value);
                            selected = self.keys().position(|name| name == &key).unwrap_or(0);
                            true
                        } else {
                            false
                        }
                    })
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

pub fn choose<T: Clone>(
    value: &mut T,
    screen: &mut Screen,
    title: &str,
    choices: &[(&str, &str, T)],
    current: usize,
) -> Result<bool> {
    let mut items: Vec<_> = choices
        .iter()
        .map(|(key, label, _)| Item::new(*key, (*label).to_owned().stylized()))
        .collect();
    items[current].marker = "■";
    items.push(Item::new("back", "返回".stylized()));
    let menu = Menu {
        title,
        heading: "",
        items: &items,
        help: "方向键 选择\n回车键 确定\nEsc 返回",
    };
    let mut selected = current;
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
    ($ty:ty { $($field:ident: $label:tt),* $(,)? } $(groups { $($key:ident: $group:literal => [$($member:ident),* $(,)?]),* $(,)? })?) => {
        impl $crate::form::Form for $ty {
            fn fields(&mut self, defaults: Self) -> $crate::form::Fields<'_> {
                let Self { $($field,)* .. } = self;
                let mut fields = Vec::new();
                $({
                    $crate::form::fields!(@push fields, $field, defaults.$field, $label);
                })*
                fields
            }

            fn groups(&self) -> Vec<$crate::form::Group> {
                [$($crate::form::fields!(@groups &self.$field, $label)),*]
                    .into_iter()
                    .flatten()
                    .chain([$($($crate::form::Group {
                        key: stringify!($key),
                        label: $group,
                        fields: &[$(stringify!($member)),*],
                    }),*)?])
                    .collect()
            }
        }
        $crate::form::group!($ty);
    };
    (@groups $field:expr, ..) => {
        $crate::form::Form::groups($field)
    };
    (@groups $field:expr, $label:literal) => { Vec::<$crate::form::Group>::new() };
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
            fn optional(
                value: &mut Option<Self>,
                screen: &mut $crate::tui::Screen,
                menu: &$crate::tui::Menu<'_>,
                selected: usize,
            ) -> $crate::Result<bool> {
                $crate::form::optional(value, screen, menu, selected)
            }
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

            fn choices() -> Vec<(&'static str, &'static str, Self)> {
                vec![$(($key, $label, Self::$variant)),*]
            }

            fn edit(&mut self, screen: &mut $crate::tui::Screen, menu: &$crate::tui::Menu<'_>, selected: usize) -> $crate::Result<bool> {
                let choices = Self::choices();
                let current = choices.iter().position(|(_, _, value)| value == self).unwrap();
                let title = format!("{} / {}", menu.title, menu.items[selected].label.content);
                $crate::form::choose(self, screen, &title, &choices, current)
            }
        }
    };
}

pub(crate) use {choices, fields, group};
