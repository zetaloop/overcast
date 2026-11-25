use std::{
    fs,
    io::{ErrorKind, Write},
    sync::atomic::{AtomicBool, Ordering},
};

use termina::style::StyleExt;

use crate::{
    Result,
    config::Store,
    tui::{Action, Item, Menu, Screen},
};

static CHINESE: AtomicBool = AtomicBool::new(false);

pub fn text<'a>(english: &'a str, chinese: &'a str) -> &'a str {
    if CHINESE.load(Ordering::Relaxed) {
        chinese
    } else {
        english
    }
}

pub fn chinese() -> bool {
    CHINESE.load(Ordering::Relaxed)
}

macro_rules! message {
    ($en:literal, $zh:literal $(, $($args:tt)+)?) => {
        if $crate::language::chinese() {
            format!($zh $(, $($args)+)?)
        } else {
            format!($en $(, $($args)+)?)
        }
    };
}
pub(crate) use message;

macro_rules! label {
    (($en:literal, $zh:literal)) => {
        $crate::language::text($en, $zh)
    };
    ($label:literal) => {
        $label
    };
}
pub(crate) use label;

pub fn load(store: &Store) -> Result<bool> {
    let path = store.directory.join("language");
    let code = match fs::read_to_string(&path) {
        Ok(code) => code,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("{}: {error}", path.display()).into()),
    };
    let chinese = match code.trim() {
        "en" => false,
        "zh-CN" => true,
        code => return Err(format!("{}: unknown language {code}", path.display()).into()),
    };
    CHINESE.store(chinese, Ordering::Relaxed);
    Ok(true)
}

pub fn choose(screen: &mut Screen, store: &Store) -> Result<bool> {
    let items = [
        Item::new("en", "English".stylized()),
        Item::new("zh-CN", "简体中文".stylized()),
    ];
    let menu = Menu {
        title: "Language / 语言",
        heading: "",
        items: &items,
        help: "↑↓   Enter   Esc",
    };
    let mut selected = usize::from(CHINESE.load(Ordering::Relaxed));
    loop {
        match screen.select(&menu, &mut selected, "")? {
            Action::Select => {
                store.create_dir(&store.directory)?;
                store.write(&store.directory.join("language"), |file| {
                    Ok(writeln!(file, "{}", items[selected].key)?)
                })?;
                CHINESE.store(selected == 1, Ordering::Relaxed);
                return Ok(true);
            }
            Action::Back => return Ok(false),
            _ => {}
        }
    }
}
