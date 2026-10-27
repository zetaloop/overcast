use std::{
    collections::{HashMap, HashSet},
    env,
    fs::{self, File, OpenOptions},
    io::{BufReader, ErrorKind, Write},
    path::{Path, PathBuf, absolute},
};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::{Result, outbound::Outbound, user::User};

#[derive(Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub users: Vec<User>,
    pub outbounds: Vec<Outbound>,
}

impl Config {
    fn validate(&self) -> Result<()> {
        let mut identifiers = HashSet::new();
        let mut passwords = HashMap::new();
        for user in &self.users {
            user.validate()?;
            if !identifiers.insert(user.uuid) {
                return Err(format!("用户 UUID 重复：{}", user.uuid).into());
            }
            if let Some(name) = passwords.insert(&user.password, &user.name) {
                return Err(format!("{name} 与 {} 的主密码相同", user.name).into());
            }
        }
        identifiers.clear();
        for outbound in &self.outbounds {
            outbound.validate()?;
            if !identifiers.insert(outbound.uuid) {
                return Err(format!("出站 UUID 重复：{}", outbound.uuid).into());
            }
        }
        Ok(())
    }
}

pub struct Store {
    pub directory: PathBuf,
    #[cfg(unix)]
    owner: Option<(u32, u32)>,
}

impl Store {
    pub fn open() -> Result<Self> {
        #[cfg(unix)]
        let account = match env::var("SUDO_UID") {
            Ok(uid) => {
                let uid = nix::unistd::Uid::from_raw(
                    uid.parse()
                        .map_err(|error| format!("无法解析 SUDO_UID：{error}"))?,
                );
                Some(
                    nix::unistd::User::from_uid(uid)?
                        .ok_or_else(|| format!("找不到发起操作的账号：{uid}"))?,
                )
            }
            Err(env::VarError::NotPresent) => None,
            Err(error) => return Err(error.into()),
        };
        #[cfg(unix)]
        let home = match &account {
            Some(account) => Some(account.dir.clone()),
            None => env::home_dir(),
        };
        #[cfg(not(unix))]
        let home = env::home_dir();

        let directory = absolute(match env::var_os("OVERCAST_HOME") {
            Some(directory) => PathBuf::from(directory),
            None => home.ok_or("无法确定账号的主目录")?.join(".overcast"),
        })?;
        #[cfg(unix)]
        let owner = if nix::unistd::geteuid().is_root() {
            let (uid, gid) = match fs::metadata(&directory) {
                Ok(metadata) => (metadata.uid(), metadata.gid()),
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    account.as_ref().map_or((0, 0), |account| {
                        (account.uid.as_raw(), account.gid.as_raw())
                    })
                }
                Err(error) => return Err(error.into()),
            };
            (uid != 0).then_some((uid, gid))
        } else {
            None
        };
        Ok(Self {
            directory,
            #[cfg(unix)]
            owner,
        })
    }

    pub fn load(&self) -> Result<Config> {
        let path = self.directory.join("config.json");
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Config::default()),
            Err(error) => {
                return Err(format!("无法读取 {}：{error}", path.display()).into());
            }
        };
        let config: Config = serde_json::from_reader(BufReader::new(file))
            .map_err(|error| format!("无法解析 {}：{error}", path.display()))?;
        config
            .validate()
            .map_err(|error| format!("{}：{error}", path.display()))?;
        Ok(config)
    }

    pub fn update(&self, change: impl FnOnce(&mut Config) -> Result<()>) -> Result<()> {
        if let Some(parent) = self.directory.parent() {
            fs::create_dir_all(parent)?;
        }
        let builder = &mut fs::DirBuilder::new();
        #[cfg(unix)]
        builder.mode(0o700);
        match builder.create(&self.directory) {
            Ok(()) => self.own(&self.directory)?,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        let path = self.directory.join("config.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let lock = match options.create_new(true).open(&path) {
            Ok(file) => {
                self.own(&path)?;
                file
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                options.create_new(false).open(&path)?
            }
            Err(error) => return Err(error.into()),
        };
        lock.lock()?;
        let mut config = self.load()?;
        change(&mut config)?;
        config.validate()?;
        let path = self.directory.join("config.json");
        let mut file = NamedTempFile::new_in(&self.directory)?;
        serde_json::to_writer_pretty(&mut file, &config)?;
        file.write_all(b"\n")?;
        self.own(file.path())?;
        file.as_file().sync_all()?;
        file.persist(&path)
            .map_err(|error| format!("无法保存 {}：{}", path.display(), error.error))?;
        Ok(())
    }

    fn own(&self, path: &Path) -> Result<()> {
        #[cfg(unix)]
        if let Some((uid, gid)) = self.owner {
            std::os::unix::fs::chown(path, Some(uid), Some(gid))?;
        }
        #[cfg(not(unix))]
        let _ = path;
        Ok(())
    }
}
