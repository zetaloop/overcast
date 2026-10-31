use std::{
    collections::{BTreeMap, HashMap, HashSet},
    env,
    fs::{self, File, OpenOptions},
    io::{BufReader, ErrorKind, Write},
    path::{Path, PathBuf, absolute},
};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use uuid::Uuid;

use crate::{
    Result,
    component::{Component, Settings},
    inbound::Inbound,
    native,
    outbound::Outbound,
    progress::Progress,
    route::Rule,
    user::User,
};

#[derive(Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<Uuid>,
    pub users: Vec<User>,
    pub inbounds: Vec<Inbound>,
    pub outbounds: Vec<Outbound>,
    pub rules: Vec<Rule>,
    pub components: BTreeMap<Component, Settings>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub keys: BTreeMap<Uuid, crate::reality::Keys>,
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
        for inbound in &self.inbounds {
            inbound.validate()?;
            if !identifiers.insert(inbound.uuid) {
                return Err(format!("入站 UUID 重复：{}", inbound.uuid).into());
            }
        }
        identifiers.clear();
        for outbound in &self.outbounds {
            outbound.validate()?;
            if !identifiers.insert(outbound.uuid) {
                return Err(format!("出站 UUID 重复：{}", outbound.uuid).into());
            }
        }
        for rule in &self.rules {
            rule.validate()?;
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

    pub fn update<T>(
        &self,
        progress: &Progress,
        change: impl FnOnce(&mut Config) -> Result<T>,
    ) -> Result<T> {
        self.create_dir(&self.directory)?;
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
        progress.check()?;
        let mut config = self.load()?;
        let previous = config.runtime;
        let result = change(&mut config)?;
        config.validate()?;
        config
            .keys
            .retain(|uuid, _| config.inbounds.iter().any(|inbound| inbound.uuid == *uuid));
        let prepared = native::prepare(self, &config, progress)?;
        if let Some(prepared) = &prepared {
            config.keys = prepared.keys.clone();
        }
        config.runtime = prepared.as_ref().map(|prepared| prepared.id);
        progress.check()?;
        let path = self.directory.join("config.json");
        self.write(&path, |file| {
            serde_json::to_writer_pretty(&mut *file, &config)?;
            file.write_all(b"\n")?;
            Ok(())
        })?;
        if let Some(prepared) = prepared {
            prepared.keep();
        }
        if let Some(previous) = previous.filter(|previous| Some(*previous) != config.runtime) {
            let directory = self.directory.join("runtime").join(previous.to_string());
            if let Err(error) = fs::remove_dir_all(&directory)
                && error.kind() != ErrorKind::NotFound
            {
                progress.record(
                    "清理旧配置失败",
                    &format!("{}：{error}", directory.display()),
                );
            }
        }
        Ok(result)
    }

    pub fn write(&self, path: &Path, write: impl FnOnce(&mut File) -> Result<()>) -> Result<()> {
        let directory = path.parent().ok_or("文件路径缺少目录")?;
        let mut file = NamedTempFile::new_in(directory)?;
        write(file.as_file_mut())?;
        self.own(file.path())?;
        file.as_file().sync_all()?;
        file.persist(path)
            .map_err(|error| format!("无法保存 {}：{}", path.display(), error.error))?;
        Ok(())
    }

    pub fn create_dir(&self, directory: &Path) -> Result<()> {
        let mut missing = Vec::new();
        for path in directory.ancestors() {
            if path.try_exists()? {
                break;
            }
            missing.push(path);
        }
        for path in missing.into_iter().rev() {
            let builder = &mut fs::DirBuilder::new();
            #[cfg(unix)]
            builder.mode(0o700);
            match builder.create(path) {
                Ok(()) => self.own(path)?,
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    pub fn own(&self, path: &Path) -> Result<()> {
        #[cfg(unix)]
        if let Some((uid, gid)) = self.owner {
            std::os::unix::fs::lchown(path, Some(uid), Some(gid))?;
        }
        #[cfg(not(unix))]
        let _ = path;
        Ok(())
    }
}
