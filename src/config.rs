use crate::language::{message, text as tr};
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
    endpoint::Endpoint,
    inbound::{Inbound, Protocol, Security},
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

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reference {
    User(Uuid),
    Inbound(Uuid),
    Outbound(Uuid),
}

impl Config {
    fn objects(&self) -> HashSet<Reference> {
        self.users
            .iter()
            .map(|value| Reference::User(value.uuid))
            .chain(
                self.inbounds
                    .iter()
                    .map(|value| Reference::Inbound(value.uuid)),
            )
            .chain(
                self.outbounds
                    .iter()
                    .map(|value| Reference::Outbound(value.uuid)),
            )
            .collect()
    }

    fn prune(&mut self, previous: &HashSet<Reference>) -> Result<()> {
        let current = self.objects();
        let keep = |object: Reference| -> Result<bool> {
            if current.contains(&object) {
                return Ok(true);
            }
            if previous.contains(&object) {
                return Ok(false);
            }
            let (kind, uuid) = match object {
                Reference::User(uuid) => (tr("User", "用户"), uuid),
                Reference::Inbound(uuid) => (tr("Inbound", "入站"), uuid),
                Reference::Outbound(uuid) => (tr("Outbound", "出站"), uuid),
            };
            Err(message!("Unknown {kind}: {uuid}", "找不到{kind}：{uuid}").into())
        };
        for (index, rule) in self.rules.iter_mut().enumerate() {
            rule.prune(&keep)
                .map_err(|e| message!("Routing rule {}: {e}", "分流规则 {}：{e}", index + 1))?;
        }
        for inbound in &mut self.inbounds {
            let keep = |object| {
                keep(object)
                    .map_err(|e| message!("Inbound {}: {e}", "入站 {}：{e}", inbound.name).into())
            };
            if let Some(fallbacks) = inbound.protocol.fallbacks_mut() {
                for fallback in fallbacks {
                    if let Endpoint::Inbound(uuid) = fallback.target
                        && !keep(Reference::Inbound(uuid))?
                    {
                        fallback.target = Endpoint::Block;
                    }
                }
            }
            if let Protocol::Forward(value) = &mut inbound.protocol {
                value.outbound.prune(&keep)?;
            }
            if let Security::Reality(reality) = &mut inbound.security
                && let Some(destination) = &mut reality.outbound
            {
                destination.prune(&keep)?;
            }
        }
        for uuid in self.keys.keys() {
            keep(Reference::Inbound(*uuid))
                .map_err(|e| message!("Handshake details: {e}", "握手资料：{e}"))?;
        }
        self.keys
            .retain(|uuid, _| current.contains(&Reference::Inbound(*uuid)));
        Ok(())
    }

    pub(crate) fn runtime(&self) -> Result<serde_json::Value> {
        let mut value = serde_json::to_value(self)?;
        let fields = value.as_object_mut().unwrap();
        for field in ["components", "maintenance", "running", "keys"] {
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
                return Err(
                    message!("Duplicate user UUID: {}", "用户 UUID 重复：{}", user.uuid).into(),
                );
            }
            if let Some(name) = passwords.insert(&user.password, &user.name) {
                return Err(message!(
                    "{name} and {} have the same master password",
                    "{name} 与 {} 的主密码相同",
                    user.name
                )
                .into());
            }
        }
        identifiers.clear();
        for inbound in &self.inbounds {
            inbound.validate()?;
            if !identifiers.insert(inbound.uuid) {
                return Err(message!(
                    "Duplicate inbound UUID: {}",
                    "入站 UUID 重复：{}",
                    inbound.uuid
                )
                .into());
            }
        }
        identifiers.clear();
        for outbound in &self.outbounds {
            outbound.validate()?;
            if !identifiers.insert(outbound.uuid) {
                return Err(message!(
                    "Duplicate outbound UUID: {}",
                    "出站 UUID 重复：{}",
                    outbound.uuid
                )
                .into());
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
            return Err(message!(
                "Could not locate the application data directory: HRESULT {result:#010x}",
                "无法获取应用数据目录：HRESULT {result:#010x}"
            )
            .into());
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
                return Err(message!(
                    "Could not read {}: {error}",
                    "无法读取 {}：{error}",
                    path.display()
                )
                .into());
            }
        };
        let config: Config = serde_json::from_reader(BufReader::new(file)).map_err(|error| {
            message!(
                "Could not parse {}: {error}",
                "无法解析 {}：{error}",
                path.display()
            )
        })?;
        config
            .validate()
            .map_err(|error| message!("{}: {error}", "{}：{error}", path.display()))?;
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
        let selected = Resources::load(self)?;
        let mut resources = selected.clone();
        let objects = config.objects();
        let result = change(&mut config, &mut resources)?;
        config.prune(&objects)?;
        config.validate()?;
        config.maintenance.next()?;
        let (prepared, target) = if let Some(target) = previous.reuse(self, &config, &resources)? {
            (None, target)
        } else {
            let (prepared, coverage) = native::prepare(
                self,
                &config,
                &mut resources.geodata,
                &previous.ports,
                progress,
            )?;
            let target = service::Deployment::prepare(
                self,
                &config,
                &mut resources,
                prepared.as_ref(),
                coverage,
                &previous,
                progress,
            )?;
            for (&uuid, used) in &target.config.keys {
                let cached = config.keys.entry(uuid).or_default();
                *cached = used.with_cache(cached);
            }
            (prepared, target)
        };
        service::check(&previous, &target, progress)?;
        let path = self.directory.join("config.json");
        let mut directories = previous.directories();
        let used = target.directories();
        target.save(self)?;
        let mut selection_saved = false;
        let applied = (|| -> Result<()> {
            service::switch(self, &previous, &target, progress)?;
            if resources != selected {
                resources.save(self)?;
                selection_saved = true;
            }
            self.write(&path, |file| {
                serde_json::to_writer_pretty(&mut *file, &config)?;
                file.write_all(b"\n")?;
                Ok(())
            })?;
            Ok(())
        })();
        if let Err(error) = applied {
            let step = progress.activity(tr("Restoring deployment", "恢复部署"));
            let recovery = previous
                .save(self)
                .and_then(|()| service::switch(self, &target, &previous, &Progress::default()));
            if recovery.is_err()
                && let Some(prepared) = prepared
            {
                prepared.keep();
            }
            let selection = if selection_saved {
                selected.save(self)
            } else {
                Ok(())
            };
            let mut errors = Vec::new();
            for outcome in [recovery, selection] {
                if let Err(cause) = outcome {
                    errors.push(cause.to_string());
                }
            }
            if !errors.is_empty() {
                let recovery = errors.join("; ");
                return Err(message!(
                    "{error}; could not restore the previous deployment: {recovery}",
                    "{error}；恢复部署失败：{recovery}"
                )
                .into());
            }
            step.finish(tr("Previous deployment restored", "已恢复此前部署"));
            return Err(message!(
                "{error}\nPrevious deployment restored",
                "{error}\n已恢复此前部署"
            )
            .into());
        }
        if let Some(prepared) = prepared
            && used
                .iter()
                .any(|path| path.starts_with(prepared.directory()))
        {
            directories.extend(prepared.state.instances.iter().map(|instance| {
                prepared
                    .directory()
                    .join(&instance.file)
                    .parent()
                    .unwrap()
                    .to_owned()
            }));
            prepared.keep();
        }
        for directory in directories.difference(&used) {
            if let Err(error) = fs::remove_dir_all(directory)
                && error.kind() != ErrorKind::NotFound
            {
                progress.warn(
                    tr("Could not remove the old configuration", "清理旧配置失败"),
                    &message!("{}: {error}", "{}：{error}", directory.display()),
                );
            }
            if let Some(parent) = directory.parent()
                && let Err(error) = fs::remove_dir(parent)
                && !matches!(
                    error.kind(),
                    ErrorKind::NotFound | ErrorKind::DirectoryNotEmpty
                )
            {
                progress.warn(
                    tr("Could not remove the old configuration", "清理旧配置失败"),
                    &message!("{}: {error}", "{}：{error}", parent.display()),
                );
            }
        }
        Ok(result)
    }

    pub fn write(&self, path: &Path, write: impl FnOnce(&mut File) -> Result<()>) -> Result<()> {
        let directory = path
            .parent()
            .ok_or(tr("File path has no parent directory", "文件路径缺少目录"))?;
        let mut file = NamedTempFile::new_in(directory)?;
        write(file.as_file_mut())?;
        file.as_file().sync_all()?;
        file.persist(path).map_err(|error| {
            message!(
                "Could not save {}: {}",
                "无法保存 {}：{}",
                path.display(),
                error.error
            )
        })?;
        Ok(())
    }

    pub fn create_dir(&self, directory: &Path) -> Result<()> {
        fs::create_dir_all(directory)?;
        Ok(())
    }
}
