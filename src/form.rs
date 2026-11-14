use std::{collections::BTreeMap, fmt::Display, rc::Rc, str::FromStr};

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

    fn edit(
        &mut self,
        screen: &mut Screen,
        menu: &Menu<'_>,
        selected: usize,
        apply: Apply<'_, Self>,
    ) -> Result<bool> {
        self.run(screen, menu, selected, apply, false)
    }

    fn create(
        screen: &mut Screen,
        menu: &Menu<'_>,
        selected: usize,
        apply: Apply<'_, Self>,
    ) -> Result<Option<Self>> {
        let mut value = Self::default();
        let accepted = value.run(screen, menu, selected, apply, true)?;
        Ok(accepted.then_some(value))
    }

    fn run(
        &mut self,
        screen: &mut Screen,
        menu: &Menu<'_>,
        selected: usize,
        apply: Apply<'_, Self>,
        creating: bool,
    ) -> Result<bool>;
}

pub type Apply<'a, T> = Rc<dyn Fn(&T, &mut Screen) -> Result<()> + 'a>;

pub fn map<'a, T: Clone + 'a, U: Clone + 'a>(
    value: Rc<T>,
    apply: Apply<'a, T>,
    replace: impl Fn(&mut T, U) + 'a,
) -> Apply<'a, U> {
    Rc::new(move |edited, screen| {
        let mut value = (*value).clone();
        replace(&mut value, edited.clone());
        apply(&value, screen)
    })
}

pub fn set<T>(screen: &mut Screen, value: &mut T, edited: T, apply: &Apply<'_, T>) -> Result<bool> {
    apply(&edited, screen)?;
    *value = edited;
    Ok(true)
}

pub trait Field {
    fn item(&self) -> Item;
    fn edit(&mut self, screen: &mut Screen, menu: &Menu<'_>, selected: usize) -> Result<bool>;
    fn reset(&mut self, screen: &mut Screen) -> Result<bool>;
}

pub type Fields<'a> = Vec<Box<dyn Field + 'a>>;

pub struct Group {
    pub key: &'static str,
    pub label: &'static str,
    pub fields: &'static [&'static str],
}

pub trait Form: Clone + Default {
    fn fields<'a>(&'a mut self, defaults: Self, apply: Apply<'a, Self>) -> Fields<'a>;

    fn groups(&self) -> Vec<Group> {
        Vec::new()
    }
}

struct Binding<'a, T> {
    key: &'static str,
    label: &'static str,
    value: &'a mut T,
    default: T,
    apply: Apply<'a, T>,
}

pub fn field<'a, T: Value>(
    key: &'static str,
    label: &'static str,
    value: &'a mut T,
    default: T,
    apply: Apply<'a, T>,
) -> Box<dyn Field + 'a> {
    Box::new(Binding {
        key,
        label,
        value,
        default,
        apply,
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
        self.value.edit(screen, menu, selected, self.apply.clone())
    }

    fn reset(&mut self, screen: &mut Screen) -> Result<bool> {
        set(screen, self.value, self.default.clone(), &self.apply)
    }
}

pub fn edit<T: Form>(
    screen: &mut Screen,
    title: &str,
    value: &mut T,
    apply: Apply<'_, T>,
    creating: bool,
) -> Result<bool> {
    edit_group(screen, title, value, apply, creating, None)
}

fn edit_group<T: Form>(
    screen: &mut Screen,
    title: &str,
    value: &mut T,
    apply: Apply<'_, T>,
    creating: bool,
    group: Option<&Group>,
) -> Result<bool> {
    let update: Apply<'_, T> = if creating {
        Rc::new(|_, _| Ok(()))
    } else {
        apply.clone()
    };
    let mut selected = 0;
    let mut notice = String::new();
    let mut changed = false;
    loop {
        let groups = if group.is_none() {
            value.groups()
        } else {
            Vec::new()
        };
        let mut fields = value.fields(T::default(), update.clone());
        fields.retain(|field| {
            let item = field.item();
            match group {
                Some(group) => group.fields.contains(&item.key.as_str()),
                None => !groups
                    .iter()
                    .any(|group| group.fields.contains(&item.key.as_str())),
            }
        });
        let mut items: Vec<_> = fields.iter().map(|field| field.item()).collect();
        items.extend(
            groups
                .iter()
                .map(|group| Item::new(group.key, group.label.stylized())),
        );
        if creating {
            items.push(Item::new("create", "确定".stylized()));
        }
        items.push(Item::new(
            "back",
            if creating { "取消" } else { "返回" }.stylized(),
        ));
        let menu = Menu {
            title,
            heading: "",
            items: &items,
            help: if creating {
                "方向键 选择\n回车键 编辑\nDel 恢复默认\nEsc 取消"
            } else {
                "方向键 选择\n回车键 编辑\nDel 恢复默认\nEsc 返回"
            },
        };
        let result = match screen.select(&menu, &mut selected, &notice)? {
            Action::Back => return Ok(!creating && changed),
            Action::Select if selected == items.len() - 1 => return Ok(!creating && changed),
            Action::Select if creating && items[selected].key == "create" => {
                drop(fields);
                match apply(value, screen) {
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
                    update.clone(),
                    false,
                    Some(group),
                )
            }
            Action::Select => fields[selected].edit(screen, &menu, selected),
            Action::Key(key) if key.code == KeyCode::Delete && selected < fields.len() => {
                fields[selected].reset(screen)
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
    apply: Apply<'_, T>,
) -> Result<bool>
where
    T::Err: Display,
{
    let Some(edited) = screen.input(menu, selected, &value.to_string(), |text, screen| {
        let edited = text
            .parse()
            .map_err(|error| format!("格式不正确：{error}"))?;
        apply(&edited, screen)?;
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
            fn run(&mut self, screen: &mut Screen, menu: &Menu<'_>, selected: usize, apply: Apply<'_, Self>, _: bool) -> Result<bool> {
                input(self, screen, menu, selected, apply)
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

    fn run(
        &mut self,
        screen: &mut Screen,
        _: &Menu<'_>,
        _: usize,
        apply: Apply<'_, Self>,
        _: bool,
    ) -> Result<bool> {
        set(screen, self, !*self, &apply)
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

    fn run(
        &mut self,
        screen: &mut Screen,
        menu: &Menu<'_>,
        selected: usize,
        apply: Apply<'_, Self>,
        creating: bool,
    ) -> Result<bool> {
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
            return choose(self, screen, &title, &choices, current, apply, creating);
        }
        let creating = creating || self.is_none();
        let mut value = self.clone().unwrap_or_default();
        let apply = map(Rc::new(self.clone()), apply, |option, value| {
            *option = Some(value)
        });
        if value.run(screen, menu, selected, apply, creating)? {
            *self = Some(value);
            Ok(true)
        } else {
            Ok(false)
        }
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

    fn run(
        &mut self,
        screen: &mut Screen,
        parent: &Menu<'_>,
        field: usize,
        apply: Apply<'_, Self>,
        creating: bool,
    ) -> Result<bool> {
        let update: Apply<'_, Self> = if creating {
            Rc::new(|_, _| Ok(()))
        } else {
            apply.clone()
        };
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
                    item
                })
                .collect();
            items.push(Item::new("add", "添加".stylized()));
            if creating {
                items.push(Item::new("create", "确定".stylized()));
            }
            items.push(Item::new(
                "back",
                if creating { "取消" } else { "返回" }.stylized(),
            ));
            let menu = Menu {
                title: &title,
                heading: "",
                items: &items,
                help: if creating {
                    "方向键 选择\n回车键 编辑\nDel 删除\nAlt+↑↓ 移动\nEsc 取消"
                } else {
                    "方向键 选择\n回车键 编辑\nDel 删除\nAlt+↑↓ 移动\nEsc 返回"
                },
            };
            let result = match screen.select(&menu, &mut selected, &notice)? {
                Action::Back => return Ok(!creating && changed),
                Action::Select if selected == items.len() - 1 => return Ok(!creating && changed),
                Action::Select if creating && selected == self.len() + 1 => {
                    match apply(self, screen) {
                        Ok(()) => return Ok(true),
                        Err(error) => Err(error),
                    }
                }
                Action::Select if selected == self.len() => {
                    let apply = map(Rc::new(self.clone()), update.clone(), |values, value| {
                        values.push(value);
                    });
                    T::create(screen, &menu, selected, apply).map(|value| {
                        if let Some(value) = value {
                            self.push(value);
                            true
                        } else {
                            false
                        }
                    })
                }
                Action::Select => {
                    let apply = map(
                        Rc::new(self.clone()),
                        update.clone(),
                        move |values, value| values[selected] = value,
                    );
                    self[selected].edit(screen, &menu, selected, apply)
                }
                Action::Key(key) if key.code == KeyCode::Delete && selected < self.len() => {
                    let mut edited = self.clone();
                    edited.remove(selected);
                    set(screen, self, edited, &update)
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
                    let mut edited = self.clone();
                    edited.swap(selected, destination);
                    set(screen, self, edited, &update).inspect(|_| {
                        selected = destination;
                    })
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

    fn run(
        &mut self,
        screen: &mut Screen,
        parent: &Menu<'_>,
        field: usize,
        apply: Apply<'_, Self>,
        creating: bool,
    ) -> Result<bool> {
        let update: Apply<'_, Self> = if creating {
            Rc::new(|_, _| Ok(()))
        } else {
            apply.clone()
        };
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
            items.push(Item::new("add", "添加".stylized()));
            if creating {
                items.push(Item::new("create", "确定".stylized()));
            }
            items.push(Item::new(
                "back",
                if creating { "取消" } else { "返回" }.stylized(),
            ));
            let menu = Menu {
                title: &title,
                heading: "",
                items: &items,
                help: if creating {
                    "方向键 选择\n回车键 编辑\nDel 删除\nEsc 取消"
                } else {
                    "方向键 选择\n回车键 编辑\nDel 删除\nEsc 返回"
                },
            };
            let result = match screen.select(&menu, &mut selected, &notice)? {
                Action::Back => return Ok(!creating && changed),
                Action::Select if selected == items.len() - 1 => return Ok(!creating && changed),
                Action::Select if creating && selected == self.len() + 1 => {
                    match apply(self, screen) {
                        Ok(()) => return Ok(true),
                        Err(error) => Err(error),
                    }
                }
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
                    let name = key.clone();
                    let apply = map(
                        Rc::new(self.clone()),
                        update.clone(),
                        move |values, value| {
                            values.insert(name.clone(), value);
                        },
                    );
                    T::create(screen, &entry, 0, apply).map(|value| {
                        if let Some(value) = value {
                            self.insert(key.clone(), value);
                            selected = self.keys().position(|name| name == &key).unwrap_or(0);
                            true
                        } else {
                            false
                        }
                    })
                }
                Action::Select => {
                    let key = keys[selected].clone();
                    let apply = map(
                        Rc::new(self.clone()),
                        update.clone(),
                        move |values, value| {
                            values.insert(key.clone(), value);
                        },
                    );
                    self.get_mut(&keys[selected])
                        .ok_or("项目已被删除")?
                        .edit(screen, &menu, selected, apply)
                }
                Action::Key(key) if key.code == KeyCode::Delete && selected < keys.len() => {
                    let mut edited = self.clone();
                    edited.remove(&keys[selected]);
                    set(screen, self, edited, &update)
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
    apply: Apply<'_, T>,
    creating: bool,
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
    let mut notice = String::new();
    loop {
        match screen.select(&menu, &mut selected, &notice)? {
            Action::Back => return Ok(false),
            Action::Select if selected == choices.len() => return Ok(false),
            Action::Select if !creating && selected == current => return Ok(false),
            Action::Select => match set(screen, value, choices[selected].2.clone(), &apply) {
                Ok(changed) => return Ok(changed),
                Err(error) => notice = error.to_string(),
            },
            _ => {}
        }
    }
}

macro_rules! fields {
    ($ty:ty { $($field:ident: $label:tt),* $(,)? } $(groups { $($key:ident: $group:literal => [$($member:ident),* $(,)?]),* $(,)? })?) => {
        impl $crate::form::Form for $ty {
            fn fields<'a>(&'a mut self, defaults: Self, apply: $crate::form::Apply<'a, Self>) -> $crate::form::Fields<'a> {
                let original = std::rc::Rc::new(self.clone());
                let Self { $($field,)* .. } = self;
                let mut fields = Vec::new();
                $({
                    let apply = $crate::form::map(original.clone(), apply.clone(), |value, edited| value.$field = edited);
                    $crate::form::fields!(@push fields, $field, defaults.$field, $label, apply);
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
    (@push $fields:ident, $field:ident, $default:expr, .., $apply:ident) => {
        $fields.extend($crate::form::Form::fields($field, $default, $apply));
    };
    (@push $fields:ident, $field:ident, $default:expr, $label:literal, $apply:ident) => {
        $fields.push($crate::form::field(stringify!($field), $label, $field, $default, $apply));
    };
}

macro_rules! group {
    ($ty:ty) => {
        impl $crate::form::Value for $ty {
            fn run(
                &mut self,
                screen: &mut $crate::tui::Screen,
                menu: &$crate::tui::Menu<'_>,
                selected: usize,
                apply: $crate::form::Apply<'_, Self>,
                creating: bool,
            ) -> $crate::Result<bool> {
                let title = format!("{} / {}", menu.title, menu.items[selected].label.content);
                $crate::form::edit(screen, &title, self, apply, creating)
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

            fn run(&mut self, screen: &mut $crate::tui::Screen, menu: &$crate::tui::Menu<'_>, selected: usize, apply: $crate::form::Apply<'_, Self>, creating: bool) -> $crate::Result<bool> {
                let choices = Self::choices();
                let current = choices.iter().position(|(_, _, value)| value == self).unwrap();
                let title = format!("{} / {}", menu.title, menu.items[selected].label.content);
                $crate::form::choose(self, screen, &title, &choices, current, apply, creating)
            }
        }
    };
}

pub(crate) use {choices, fields, group};
