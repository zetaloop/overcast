use crate::language::text as tr;
use std::{fs, path::Path, process::Command};

use super::execute;
use crate::{Result, config::Store};

const UNIT: &str = "/etc/systemd/system/overcast.service";

fn quote(value: &Path) -> Result<String> {
    Ok(format!(
        "\"{}\"",
        value
            .to_str()
            .ok_or(tr("Invalid character in path", "路径包含无效字符"))?
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$")
    ))
}

fn external() -> Result<bool> {
    let path = execute(Command::new("systemctl").args([
        "show",
        "--property=FragmentPath",
        "--value",
        "overcast.service",
    ]))?;
    let path = path.trim();
    Ok(!path.is_empty() && fs::canonicalize(path)? != Path::new(UNIT))
}

pub(crate) fn running() -> Result<bool> {
    let state = execute(Command::new("systemctl").args([
        "show",
        "--property=ActiveState",
        "--value",
        "overcast.service",
    ]))?;
    Ok(matches!(
        state.trim(),
        "active" | "reloading" | "refreshing"
    ))
}

pub(super) fn install(_: &Store) -> Result<()> {
    if !external()? {
        let unit = format!(
            "[Unit]\nDescription=Overcast\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=exec\nExecStart={} --run\nExecReload=/bin/kill -HUP $MAINPID\nKillMode=mixed\nRestart=on-failure\n\n[Install]\nWantedBy=multi-user.target\n",
            quote(&crate::update::service_program()?)?,
        );
        fs::write(UNIT, unit)?;
        execute(Command::new("systemctl").arg("daemon-reload"))?;
        execute(Command::new("systemctl").args(["enable", "overcast.service"]))?;
    }
    execute(Command::new("systemctl").args(["start", "overcast.service"]))?;
    if !running()? {
        return Err(tr(
            "systemd finished the start job without activating overcast.service",
            "systemd 已完成启动操作，但 overcast.service 未运行",
        )
        .into());
    }
    Ok(())
}

pub(super) fn reload() -> Result<()> {
    execute(Command::new("systemctl").args(["reload", "overcast.service"]))?;
    Ok(())
}

pub(super) fn restart() -> Result<()> {
    execute(Command::new("systemctl").args([
        "kill",
        "--kill-whom=main",
        "--signal=USR1",
        "overcast.service",
    ]))?;
    Ok(())
}

pub(super) fn remove() -> Result<()> {
    if external()? {
        execute(Command::new("systemctl").args(["stop", "overcast.service"]))?;
        return Ok(());
    }
    execute(Command::new("systemctl").args(["disable", "--now", "overcast.service"]))?;
    match fs::remove_file(UNIT) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    execute(Command::new("systemctl").arg("daemon-reload"))?;
    Ok(())
}
