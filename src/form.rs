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

pub type Apply<'a, T> = Rc<dyn Fn(&T) -> Result<()> + 'a>;

pub fn map<'a, T: Clone + 'a, U: Clone + 'a>(
    value: Rc<T>,
    apply: Apply<'a, T>,
    replace: impl Fn(&mut T, U) + 'a,
) -> Apply<'a, U> {
    Rc::new(move |edited| {
        let mut value = (*value).clone();
        replace(&mut value, edited.clone());
        apply(&value)
    })
}

pub fn set<T>(value: &mut T, edited: T, apply: &Apply<'_, T>) -> Result<bool> {
    apply(&edited)?;
    *value = edited;
    Ok(true)
}

pub trait Field {
    fn item(&self) -> Item;
    fn edit(&mut self, screen: &mut Screen, menu: &Menu<'_>, selected: usize) -> Result<bool>;
    fn reset(&mut self) -> Result<bool>;
}

pub type Fields<'a> = Vec<Box<dyn Field + 'a>>;

pub trait Form: Clone + Default {
    fn fields<'a>(&'a mut self, defaults: Self, apply: Apply<'a, Self>) -> Fields<'a>;
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

    fn reset(&mut self) -> Result<bool> {
        set(self.value, self.default.clone(), &self.apply)
    }
}

pub fn edit<T: Form>(
    screen: &mut Screen,
    title: &str,
    value: &mut T,
    apply: Apply<'_, T>,
    creating: bool,
) -> Result<bool> {
    let update: Apply<'_, T> = if creating {
        Rc::new(|_| Ok(()))
    } else {
        apply.clone()
    };
    let mut selected = 0;
    let mut notice = String::new();
    let mut changed = false;
    loop {
        let mut fields = value.fields(T::default(), update.clone());
        let mut items: Vec<_> = fields.iter().map(|field| field.item()).collect();
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
            Action::Select if selected == fields.len() => {
                drop(fields);
                match apply(value) {
                    Ok(()) => return Ok(true),
                    Err(error) => Err(error),
                }
            }
            Action::Select => fields[selected].edit(screen, &menu, selected),
            Action::Key(key) if key.code == KeyCode::Delete && selected < fields.len() => {
                fields[selected].reset()
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
    let Some(edited) = screen.input(menu, selected, &value.to_string(), |text| {
        let edited = text
            .parse()
            .map_err(|error| format!("格式不正确：{error}"))?;
        apply(&edited)?;
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

scalar!(String, u8, u16, u32, u64);

impl Value for bool {
    fn text(&self) -> String {
        if *self { "开启" } else { "关闭" }.to_owned()
    }

    fn marker(&self) -> &'static str {
        if *self { "■" } else { "□" }
    }

    fn run(
        &mut self,
        _: &mut Screen,
        _: &Menu<'_>,
        _: usize,
        apply: Apply<'_, Self>,
        _: bool,
    ) -> Result<bool> {
        set(self, !*self, &apply)
    }
}

impl<T: Value> Value for Option<T> {
    fn text(&self) -> String {
        self.as_ref().map_or_else(|| "默认".to_owned(), Value::text)
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
    fn run(
        &mut self,
        screen: &mut Screen,
        parent: &Menu<'_>,
        field: usize,
        apply: Apply<'_, Self>,
        creating: bool,
    ) -> Result<bool> {
        let update: Apply<'_, Self> = if creating {
            Rc::new(|_| Ok(()))
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
                    let mut item = Item::new(index.to_string(), (index + 1).to_string().stylized());
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
                Action::Select if creating && selected == self.len() + 1 => match apply(self) {
                    Ok(()) => return Ok(true),
                    Err(error) => Err(error),
                },
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
                    set(self, edited, &update)
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
                    set(self, edited, &update).inspect(|_| {
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
    fn run(
        &mut self,
        screen: &mut Screen,
        parent: &Menu<'_>,
        field: usize,
        apply: Apply<'_, Self>,
        creating: bool,
    ) -> Result<bool> {
        let update: Apply<'_, Self> = if creating {
            Rc::new(|_| Ok(()))
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
                Action::Select if creating && selected == self.len() + 1 => match apply(self) {
                    Ok(()) => return Ok(true),
                    Err(error) => Err(error),
                },
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
                    set(self, edited, &update)
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
    apply: Apply<'_, T>,
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
                return set(value, choices[selected].2.clone(), &apply);
            }
            _ => {}
        }
    }
}

macro_rules! fields {
    ($ty:ty { $($field:ident: $label:tt),* $(,)? }) => {
        impl $crate::form::Form for $ty {
            fn fields<'a>(&'a mut self, defaults: Self, apply: $crate::form::Apply<'a, Self>) -> $crate::form::Fields<'a> {
                let original = std::rc::Rc::new(self.clone());
                let Self { $($field),* } = self;
                let mut fields = Vec::new();
                $({
                    let apply = $crate::form::map(original.clone(), apply.clone(), |value, edited| value.$field = edited);
                    $crate::form::fields!(@push fields, $field, defaults.$field, $label, apply);
                })*
                fields
            }
        }
        $crate::form::group!($ty);
    };
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

            fn run(&mut self, screen: &mut $crate::tui::Screen, menu: &$crate::tui::Menu<'_>, selected: usize, apply: $crate::form::Apply<'_, Self>, _: bool) -> $crate::Result<bool> {
                $crate::form::choose(self, screen, menu, selected, &[$(($key, $label, Self::$variant)),*], apply)
            }
        }
    };
}

pub(crate) use {choices, fields, group};
