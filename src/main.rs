mod component;
mod condition;
mod config;
mod connection;
mod form;
mod geodata;
mod inbound;
pub mod input;
mod outbound;
mod pattern;
pub mod progress;
mod resource;
mod route;
pub mod tui;
mod user;

use std::{error::Error, process::ExitCode};

use config::Store;
use termina::style::{AnsiColor, StyleExt};
use tui::{Action, Item, Menu, Screen};

pub type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

fn run() -> Result<()> {
    let store = Store::open()?;
    let mut screen = Screen::open(std::env::args().skip(1))?;
    screen.aliases(&[
        ("help", &["about"]),
        ("version", &["about"]),
        ("add-user", &["users", "new", "name"]),
    ]);
    let mut selected = 0;
    let mut notice = String::new();
    let items = [
        Item::new("inbounds", "入站".stylized()),
        Item::new("outbounds", "出站".stylized()),
        Item::new("users", "用户".stylized()),
        Item::new("rules", "分流".stylized()),
        Item::new("components", "组件".stylized()),
        Item::new("about", "关于".stylized()),
        Item::new("exit", "退出".foreground(AnsiColor::BrightRed)),
    ];
    let menu = Menu {
        title: "主菜单",
        heading: "",
        items: &items,
        help: "方向键 选择\n回车键 确定\nEsc 退出",
    };
    loop {
        match screen.select(&menu, &mut selected, &notice)? {
            Action::Select => {}
            Action::Back => break,
            _ => continue,
        }
        let result = match selected {
            0 => inbound::run(&mut screen, &store),
            1 => outbound::run(&mut screen, &store),
            2 => user::run(&mut screen, &store),
            3 => route::run(&mut screen, &store),
            4 => component::run(&mut screen, &store),
            5 => screen.about(),
            _ => break,
        };
        notice = result
            .err()
            .map_or_else(String::new, |error| error.to_string());
    }
    screen.finish()
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
