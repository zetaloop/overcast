mod anytls;
mod certificate;
mod component;
mod condition;
mod config;
mod connection;
mod ech;
mod encryption;
mod endpoint;
mod form;
mod forward;
mod geodata;
mod graph;
mod hysteria;
mod inbound;
pub mod input;
mod keys;
mod link;
mod maintenance;
mod multiplex;
mod native;
mod outbound;
mod pattern;
mod profile;
pub mod progress;
mod reality;
mod resource;
mod route;
mod security;
mod service;
mod shadowsocks;
mod share;
mod target;
mod transport;
mod trojan;
pub mod tui;
mod update;
mod user;
mod vless;
mod vmess;
mod warp;

use std::{error::Error, process::ExitCode};

use config::Store;
use termina::style::{AnsiColor, StyleExt};
use tui::{Action, Item, Menu, Screen};

pub type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

fn run() -> Result<()> {
    #[cfg(windows)]
    update::cleanup()?;
    let mut args = std::env::args().skip(1).peekable();
    match args.peek().map(String::as_str) {
        Some("--run") => {
            args.next();
            return service::run(Store::open(args.next().map(Into::into))?);
        }
        Some("--update") => {
            args.next();
            let store = Store::open(args.next().map(Into::into))?;
            let progress = progress::Progress::default();
            if let Some(update) = maintenance::update(&store, &progress)? {
                println!("Overcast 已更新至 {}", update.activate(&store, &progress)?);
            }
            return Ok(());
        }
        _ => {}
    }
    let store = Store::open(None)?;
    let mut screen = Screen::open(args)?;
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
        Item::new("maintenance", "维护".stylized()),
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
            4 => match maintenance::run(&mut screen, &store) {
                Ok(Some(update)) => {
                    let version = screen.work("应用更新", "", |progress| {
                        update.activate(&store, progress)
                    });
                    drop(screen);
                    println!("Overcast 已更新至 {}", version?);
                    return Ok(());
                }
                result => result.map(|_| ()),
            },
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
