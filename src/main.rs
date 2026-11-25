mod anytls;
mod certificate;
mod component;
mod condition;
mod config;
mod connection;
mod core;
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
mod language;
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
use language::text;
use termina::style::{AnsiColor, StyleExt};
use tui::{Action, Item, Menu, Screen};

pub type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

fn run() -> Result<()> {
    #[cfg(windows)]
    update::cleanup()?;
    let mut args = std::env::args().skip(1).peekable();
    let store = Store::open()?;
    let configured = language::load(&store)?;
    if matches!(args.peek().map(String::as_str), Some("--run" | "--update")) {
        let run = args.next().as_deref() == Some("--run");
        if let Some(argument) = args.next() {
            return Err(language::message!(
                "Unexpected argument: {argument}",
                "多余的参数：{argument}"
            )
            .into());
        }
        if run {
            return service::run(store);
        }
        let progress = progress::Progress::default();
        if let Some(update) = maintenance::update(&store, &progress)? {
            println!(
                "{} {}",
                language::text("Updated Overcast to", "Overcast 已更新至"),
                update.activate(&store, &progress)?
            );
        }
        return Ok(());
    }
    let mut screen = Screen::open([])?;
    if !configured && !language::choose(&mut screen, &store)? {
        return screen.finish();
    }
    screen.arguments.extend(args);
    screen.aliases(&[
        ("help", &["settings", "about"]),
        ("version", &["settings", "about"]),
        ("add-user", &["users", "new", "name"]),
    ]);
    let mut selected = 0;
    let mut notice = String::new();
    loop {
        let mut items = [
            Item::new("inbounds", text("Inbounds", "入站").stylized()),
            Item::new("outbounds", text("Outbounds", "出站").stylized()),
            Item::new("users", text("Users", "用户").stylized()),
            Item::new("rules", text("Routing", "分流").stylized()),
            Item::new("settings", text("Settings", "设置").stylized()),
            Item::new(
                "exit",
                text("Quit", "退出").foreground(AnsiColor::BrightRed),
            ),
        ];
        items[4].gap = true;
        let menu = Menu {
            title: text("Main menu", "主菜单"),
            heading: "",
            items: &items,
            help: text(
                "Arrow keys to select\nEnter to open\nEsc to quit",
                "方向键 选择\n回车键 确定\nEsc 退出",
            ),
        };
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
            4 => match settings(&mut screen, &store) {
                Ok(Some(update)) => {
                    let version =
                        screen.work(text("Applying update", "应用更新"), "", |progress| {
                            update.activate(&store, progress)
                        });
                    drop(screen);
                    println!(
                        "{} {}",
                        text("Updated Overcast to", "Overcast 已更新至"),
                        version?
                    );
                    return Ok(());
                }
                result => result.map(|_| ()),
            },
            _ => break,
        };
        notice = result
            .err()
            .map_or_else(String::new, |error| error.to_string());
    }
    screen.finish()
}

fn settings(screen: &mut Screen, store: &Store) -> Result<Option<update::Installed>> {
    let mut selected = 0;
    let mut notice = String::new();
    loop {
        let mut running = Item::new("running", text("Run service", "总开关").stylized());
        let active = service::running();
        match &active {
            Ok(true) => running.marker = "■",
            Ok(false) => running.marker = "□",
            Err(error) => running.value = error.to_string(),
        }
        let mut language = Item::new("language", "Language / 语言".stylized());
        language.value = text("English", "简体中文").into();
        language.gap = true;
        let items = [
            running,
            Item::new("logs", text("Logs", "日志").stylized()),
            Item::new("updates", text("Updates", "更新").stylized()),
            language,
            Item::new("about", text("About", "关于").stylized()),
            Item::new("back", text("Back", "返回").stylized()),
        ];
        let menu = Menu {
            title: text("Settings", "设置"),
            heading: "",
            items: &items,
            help: text(
                "Arrow keys to select\nEnter to confirm\nEsc to go back",
                "方向键 选择\n回车键 确定\nEsc 返回",
            ),
        };
        match screen.select(&menu, &mut selected, &notice)? {
            Action::Back => return Ok(None),
            Action::Select => {}
            _ => continue,
        }
        let result = match items[selected].key.as_str() {
            "running" => active.and_then(|running| {
                screen.work(
                    if running {
                        text("Stopping service", "停止服务")
                    } else {
                        text("Starting service", "启动服务")
                    },
                    "",
                    |progress| service::set_running(store, !running, progress),
                )
            }),
            "logs" => service::logs(screen, store),
            "updates" => match maintenance::run(screen, store) {
                Ok(Some(update)) => return Ok(Some(update)),
                result => result.map(|_| ()),
            },
            "language" => language::choose(screen, store).map(|_| ()),
            "about" => screen.about(),
            _ => return Ok(None),
        };
        notice = result
            .err()
            .map_or_else(String::new, |error| error.to_string());
    }
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
