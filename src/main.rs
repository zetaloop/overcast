pub mod input;
pub mod progress;
pub mod tui;

use std::{error::Error, process::ExitCode};

use crossterm::style::{Stylize, style};
use tui::{Item, Screen};

pub type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

fn run() -> Result<()> {
    let mut screen = Screen::open(std::env::args().skip(1))?;
    screen.aliases(&[("help", &["about"]), ("version", &["about"])]);
    let mut selected = 0;
    let items = [
        Item::new("about", style("关于")),
        Item::new("exit", "退出".red()),
    ];
    while screen.select("主菜单", "", &items, &mut selected, "")? {
        if selected == 1 {
            break;
        }
        let heading = format!("Overcast {}\n代理服务安装与管理", env!("CARGO_PKG_VERSION"));
        screen.select(
            "关于",
            &heading,
            &[Item::new("back", style("返回"))],
            &mut 0,
            "",
        )?;
    }
    Ok(())
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
