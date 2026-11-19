use std::{env, fmt::Write as _, fs, io, path::PathBuf};

use semver::Version;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use ureq::Agent;

use crate::{Result, config::Store, progress::Progress, resource::Asset, service};

fn program() -> io::Result<PathBuf> {
    env::current_exe()?.canonicalize()
}

pub fn channel() -> Result<Option<String>> {
    match fs::read_to_string(program()?.with_extension("channel")) {
        Ok(text) if !text.trim().is_empty() => Ok(Some(text.trim().to_owned())),
        Ok(_) => Err("安装渠道标记为空".into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn digest(mut file: impl io::Read) -> Result<String> {
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    let mut text = String::from("sha256:");
    for byte in hash.finalize() {
        write!(text, "{byte:02x}")?;
    }
    Ok(text)
}

pub struct Update {
    target: PathBuf,
    download: NamedTempFile,
    version: String,
}

pub struct Installed {
    pub version: String,
    running: Option<uuid::Uuid>,
    _lock: fs::File,
}

impl Installed {
    pub fn activate(self, store: &Store, progress: &Progress) -> Result<String> {
        if let Some(id) = self.running {
            service::restart(store, id, progress)
                .map_err(|error| format!("Overcast {} 已安装；{error}", self.version))?;
        }
        Ok(self.version)
    }
}

impl Update {
    pub fn prepare(
        client: &Agent,
        asset: &Asset,
        tag: &str,
        specific: bool,
        progress: &Progress,
    ) -> Result<Option<Self>> {
        let candidate = Version::parse(
            tag.strip_prefix('v')
                .ok_or("Overcast 发布标签缺少 v 前缀")?,
        )?;
        let current = Version::parse(env!("CARGO_PKG_VERSION"))?;
        if !specific && candidate.cmp_precedence(&current).is_lt() {
            return Ok(None);
        }
        let expected = asset
            .digest
            .as_deref()
            .filter(|s| s.starts_with("sha256:"))
            .ok_or("发布文件缺少 SHA-256 摘要")?;
        let target = program()?;
        if candidate == current && digest(fs::File::open(&target)?)? == expected {
            progress.record("当前版本", tag);
            return Ok(None);
        }
        let mut download = NamedTempFile::new_in(target.parent().unwrap())?;
        asset.download(client, download.as_file_mut(), progress)?;
        if digest(download.as_file())? != expected {
            return Err(format!("{} 的内容与发布文件摘要不符", asset.name).into());
        }
        #[cfg(unix)]
        download
            .as_file()
            .set_permissions(fs::metadata(&target)?.permissions())?;
        download.as_file().sync_all()?;
        Ok(Some(Self {
            target,
            download,
            version: tag.to_owned(),
        }))
    }

    pub fn install(self, store: &Store, progress: &Progress) -> Result<Installed> {
        let lock = store.lock()?;
        let deployment = service::Deployment::load(store)?;
        progress.check()?;
        let step = progress.activity("更新 Overcast");
        let candidate = self.download.into_temp_path();
        #[cfg(unix)]
        fs::rename(&candidate, &self.target)?;
        #[cfg(windows)]
        {
            let retired = self.target.with_added_extension("replaced");
            fs::rename(&self.target, &retired)?;
            if let Err(error) = fs::rename(&candidate, &self.target) {
                fs::rename(&retired, &self.target).map_err(|restore| {
                    format!(
                        "安装新版失败：{error}；旧程序位于 {}：{restore}",
                        retired.display()
                    )
                })?;
                return Err(error.into());
            }
        }
        step.finish(&self.version);
        Ok(Installed {
            version: self.version,
            running: deployment.config.running.then_some(deployment.id),
            _lock: lock,
        })
    }
}

#[cfg(windows)]
pub fn cleanup() -> io::Result<()> {
    match fs::remove_file(program()?.with_added_extension("replaced")) {
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                || matches!(error.raw_os_error(), Some(5 | 32)) =>
        {
            Ok(())
        }
        result => result,
    }
}
