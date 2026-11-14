use std::{
    collections::{BTreeMap, HashMap, HashSet},
    env,
    fs::{self, File, OpenOptions},
    io::{BufReader, ErrorKind, Write},
    path::{Path, PathBuf, absolute},
};

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
    resource::Resources,
    route::Rule,
    service,
    user::User,
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub users: Vec<User>,
    pub inbounds: Vec<Inbound>,
    pub outbounds: Vec<Outbound>,
    pub rules: Vec<Rule>,
    pub components: BTreeMap<Component, Settings>,
    pub maintenance: crate::maintenance::Schedule,
    pub running: bool,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub keys: BTreeMap<Uuid, crate::keys::Keys>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            users: Vec::new(),
            inbounds: Vec::new(),
            outbounds: vec![Outbound::default_direct()],
            rules: Vec::new(),
            components: BTreeMap::new(),
            maintenance: Default::default(),
            running: false,
            keys: BTreeMap::new(),
        }
    }
}

impl Config {
    pub(crate) fn runtime(&self) -> Result<serde_json::Value> {
        let mut value = serde_json::to_value(self)?;
        let fields = value.as_object_mut().unwrap();
        for field in ["components", "maintenance", "running"] {
            fields.remove(field);
        }
        for field in ["users", "inbounds", "outbounds"] {
            for object in fields[field].as_array_mut().unwrap() {
                let object = object.as_object_mut().unwrap();
                object.remove("name");
                if let Some(connections) = object.get_mut("connections") {
                    for connection in connections.as_array_mut().unwrap() {
                        let connection = connection.as_object_mut().unwrap();
                        if let Some(proxy) = connection.get_mut("proxy") {
                            proxy.as_object_mut().unwrap().remove("name");
                        } else {
                            connection.remove("name");
                        }
                    }
                }
            }
        }
        Ok(value)
    }

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

#[derive(Clone)]
pub struct Store {
    pub directory: PathBuf,
}

fn default_directory() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    return Ok("/var/lib/overcast".into());
    #[cfg(target_os = "macos")]
    return Ok("/Library/Application Support/Overcast".into());
    #[cfg(windows)]
    {
        use std::{ffi::OsString, os::windows::ffi::OsStringExt, ptr};
        use windows_sys::Win32::{
            System::Com::CoTaskMemFree,
            UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath},
        };

        let mut path = ptr::null_mut();
        let result =
            unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, ptr::null_mut(), &mut path) };
        if result < 0 {
            unsafe { CoTaskMemFree(path.cast()) };
            return Err(format!("无法获取应用数据目录：HRESULT {result:#010x}").into());
        }
        let directory = unsafe {
            let mut length = 0;
            while *path.add(length) != 0 {
                length += 1;
            }
            let directory = PathBuf::from(OsString::from_wide(std::slice::from_raw_parts(
                path, length,
            )));
            CoTaskMemFree(path.cast());
            directory
        };
        Ok(directory.join("Overcast"))
    }
}

impl Store {
    pub fn open(directory: Option<PathBuf>) -> Result<Self> {
        let directory = absolute(
            match directory.or_else(|| env::var_os("OVERCAST_HOME").map(PathBuf::from)) {
                Some(directory) => directory,
                None => default_directory()?,
            },
        )?;
        Ok(Self { directory })
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

    pub fn lock(&self) -> Result<File> {
        self.create_dir(&self.directory)?;
        let path = self.directory.join("config.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        let lock = match options.create_new(true).open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                options.create_new(false).open(&path)?
            }
            Err(error) => return Err(error.into()),
        };
        lock.lock()?;
        Ok(lock)
    }

    pub fn update<T>(
        &self,
        progress: &Progress,
        change: impl FnOnce(&mut Config, &mut Resources) -> Result<T>,
    ) -> Result<T> {
        let _lock = self.lock()?;
        progress.check()?;
        let previous = service::Deployment::load(self)?;
        let mut config = self.load()?;
        let mut resources = Resources::load(self)?;
        let planned = (|| -> Result<_> {
            let result = change(&mut config, &mut resources)?;
            config.validate()?;
            config.maintenance.next()?;
            config
                .keys
                .retain(|uuid, _| config.inbounds.iter().any(|inbound| inbound.uuid == *uuid));
            if let Some(target) = previous.reuse(self, &config, &resources)? {
                return Ok((result, None, target));
            }
            let prepared = native::prepare(
                self,
                &config,
                &mut resources.geodata,
                &previous.ports,
                progress,
            )?;
            if let Some(prepared) = &prepared {
                config.keys = prepared.keys.clone();
            }
            let target = service::Deployment::prepare(
                self,
                &config,
                &mut resources,
                prepared.as_ref(),
                &previous,
                progress,
            )?;
            Ok((result, prepared, target))
        })();
        resources.save(self)?;
        let (result, mut prepared, target) = planned?;
        progress.check()?;
        let path = self.directory.join("config.json");
        let mut directories = previous.directories();
        if let Some(prepared) = &prepared {
            directories.extend(prepared.state.instances.iter().map(|instance| {
                prepared
                    .directory()
                    .join(&instance.file)
                    .parent()
                    .unwrap()
                    .to_owned()
            }));
        }
        let used = target.directories();
        if prepared.as_ref().is_some_and(|prepared| {
            used.iter()
                .any(|directory| directory.starts_with(prepared.directory()))
        }) {
            prepared.take().unwrap().keep();
        }
        service::apply(self, &previous, &target, progress)?;
        if let Err(error) = self.write(&path, |file| {
            serde_json::to_writer_pretty(&mut *file, &config)?;
            file.write_all(b"\n")?;
            Ok(())
        }) {
            let step = progress.activity("恢复部署");
            match service::restore(self, &target, &previous, &Progress::default()) {
                Ok(()) => step.finish("已恢复此前部署"),
                Err(recovery) => return Err(format!("{error}；恢复部署失败：{recovery}").into()),
            }
            return Err(format!("{error}\n已恢复此前部署").into());
        }
        for directory in directories.difference(&used) {
            if let Err(error) = fs::remove_dir_all(directory)
                && error.kind() != ErrorKind::NotFound
            {
                progress.warn(
                    "清理旧配置失败",
                    &format!("{}：{error}", directory.display()),
                );
            }
            if let Some(parent) = directory.parent()
                && let Err(error) = fs::remove_dir(parent)
                && !matches!(
                    error.kind(),
                    ErrorKind::NotFound | ErrorKind::DirectoryNotEmpty
                )
            {
                progress.warn("清理旧配置失败", &format!("{}：{error}", parent.display()));
            }
        }
        Ok(result)
    }

    pub fn write(&self, path: &Path, write: impl FnOnce(&mut File) -> Result<()>) -> Result<()> {
        let directory = path.parent().ok_or("文件路径缺少目录")?;
        let mut file = NamedTempFile::new_in(directory)?;
        write(file.as_file_mut())?;
        file.as_file().sync_all()?;
        file.persist(path)
            .map_err(|error| format!("无法保存 {}：{}", path.display(), error.error))?;
        Ok(())
    }

    pub fn create_dir(&self, directory: &Path) -> Result<()> {
        fs::create_dir_all(directory)?;
        Ok(())
    }
}
