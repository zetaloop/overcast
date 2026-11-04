use std::{fs, process::Command};

use serde_json::json;

use super::execute;
use crate::{Result, config::Store};

const LABEL: &str = "build.loop.overcast";
const TARGET: &str = "system/build.loop.overcast";
const PLIST: &str = "/Library/LaunchDaemons/build.loop.overcast.plist";
const NOT_FOUND: i32 = 113;

fn loaded() -> Result<bool> {
    let output = Command::new("launchctl").args(["print", TARGET]).output()?;
    if output.status.code() == Some(NOT_FOUND) {
        return Ok(false);
    }
    if !output.status.success() {
        return Err(format!(
            "读取服务状态失败：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    Ok(true)
}

fn unload() -> Result<()> {
    if loaded()? {
        execute(Command::new("launchctl").args(["bootout", "--wait", TARGET]))?;
    }
    Ok(())
}

pub(super) fn install(store: &Store) -> Result<()> {
    let logs = store.directory.join("logs");
    store.create_dir(&logs)?;
    let output = logs.join("overcast.log");
    let definition = json!({
        "Label": LABEL,
        "ProgramArguments": [std::env::current_exe()?, "--run", store.directory],
        "RunAtLoad": true,
        "KeepAlive": {"SuccessfulExit": false},
        "StandardOutPath": output,
        "StandardErrorPath": output,
    });
    unload()?;
    fs::write(PLIST, serde_json::to_vec(&definition)?)?;
    execute(Command::new("plutil").args(["-convert", "xml1", PLIST]))?;
    execute(Command::new("launchctl").args(["bootstrap", "system", PLIST]))?;
    Ok(())
}

pub(super) fn reload() -> Result<()> {
    execute(Command::new("launchctl").args(["kill", "SIGHUP", TARGET]))?;
    Ok(())
}

pub(super) fn remove() -> Result<()> {
    unload()?;
    match fs::remove_file(PLIST) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
