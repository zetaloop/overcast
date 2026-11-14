use std::rc::Rc;

use serde::{Deserialize, Serialize};
use termina::style::StyleExt;

use crate::{
    Result,
    form::{self, Form, Value},
    tui::{Action, Item, Menu, Screen},
};

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Security<T, R> {
    #[default]
    None,
    Tls(T),
    Reality(Box<R>),
}

pub trait Handshake<T> {
    fn tls(&self) -> &T;
    fn tls_mut(&mut self) -> &mut T;
}

impl<T, R: Handshake<T>> Security<T, R> {
    pub fn tls(&self) -> Option<&T> {
        match self {
            Self::None => None,
            Self::Tls(value) => Some(value),
            Self::Reality(value) => Some(value.tls()),
        }
    }

    pub fn tls_mut(&mut self) -> Option<&mut T> {
        match self {
            Self::None => None,
            Self::Tls(value) => Some(value),
            Self::Reality(value) => Some(value.tls_mut()),
        }
    }

    pub fn reality(&self) -> Option<&R> {
        match self {
            Self::Reality(value) => Some(value),
            _ => None,
        }
    }

    fn index(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Tls(_) => 1,
            Self::Reality(_) => 2,
        }
    }
}

impl<T: Form, R: Form + Handshake<T>> Security<T, R> {
    pub fn choose(
        &mut self,
        screen: &mut Screen,
        title: &str,
        modes: &[usize],
        apply: form::Apply<'_, Self>,
    ) -> Result<bool> {
        let labels = ["无", "TLS", "REALITY"];
        let mut items: Vec<_> = modes
            .iter()
            .map(|&mode| Item::new(["none", "tls", "reality"][mode], labels[mode].stylized()))
            .collect();
        if let Some(current) = modes.iter().position(|&mode| mode == self.index()) {
            items[current].marker = "■";
        }
        items.push(Item::new("back", "返回".stylized()));
        let menu = Menu {
            title,
            heading: "",
            items: &items,
            help: "方向键 选择\n回车键 编辑\nEsc 返回",
        };
        let mut selected = modes
            .iter()
            .position(|&mode| mode == self.index())
            .unwrap_or_default();
        let mut notice = String::new();
        loop {
            match screen.select(&menu, &mut selected, &notice)? {
                Action::Back => return Ok(false),
                Action::Select if selected == modes.len() => return Ok(false),
                Action::Select => {
                    let mode = modes[selected];
                    let creating = mode != self.index();
                    let mut candidate = if creating {
                        match mode {
                            1 => Self::Tls(T::default()),
                            2 => Self::Reality(Box::default()),
                            _ => Self::None,
                        }
                    } else {
                        self.clone()
                    };
                    let title = format!("{title} / {}", labels[mode]);
                    let result = match &mut candidate {
                        Self::None if !creating => return Ok(false),
                        Self::None => form::set(screen, self, Self::None, &apply),
                        Self::Tls(value) => {
                            let apply = apply.clone();
                            form::edit(
                                screen,
                                &title,
                                value,
                                Rc::new(move |value, screen| {
                                    apply(&Self::Tls(value.clone()), screen)
                                }),
                                creating,
                            )
                        }
                        Self::Reality(value) => {
                            let apply = apply.clone();
                            form::edit(
                                screen,
                                &title,
                                value.as_mut(),
                                Rc::new(move |value, screen| {
                                    apply(&Self::Reality(Box::new(value.clone())), screen)
                                }),
                                creating,
                            )
                        }
                    };
                    match result {
                        Ok(changed) if changed || !creating => {
                            if changed && !matches!(candidate, Self::None) {
                                *self = candidate;
                            }
                            return Ok(changed);
                        }
                        Ok(_) => notice.clear(),
                        Err(error) => notice = error.to_string(),
                    }
                }
                _ => {}
            }
        }
    }
}

impl<T: Form, R: Form + Handshake<T>> Value for Security<T, R> {
    fn text(&self) -> String {
        ["无", "TLS", "REALITY"][self.index()].to_owned()
    }

    fn run(
        &mut self,
        screen: &mut Screen,
        parent: &Menu<'_>,
        field: usize,
        apply: form::Apply<'_, Self>,
        _: bool,
    ) -> Result<bool> {
        let title = format!("{} / {}", parent.title, parent.items[field].label.content);
        self.choose(screen, &title, &[0, 1, 2], apply)
    }
}
