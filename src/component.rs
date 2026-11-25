use crate::language::{message, text as tr};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::BufReader,
    path::{Path, PathBuf},
    thread,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use tempfile::{NamedTempFile, tempdir_in};
use termina::style::StyleExt;
use ureq::Agent;

use crate::{
    Result,
    config::Store,
    progress::{Progress, Step},
    resource::{self, Asset, Release, Resources},
    tui::{Action, Item, Menu, Screen},
};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Component {
    Overcast,
    Xray,
    SingBox,
    Mihomo,
    Caddy,
    Usque,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub preview: bool,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Installed {
    pub tag: String,
    pub version: String,
    pub asset: u64,
    pub path: PathBuf,
}

struct Package<'a> {
    asset: &'a Asset,
    member: String,
    version: String,
}

enum Prepared {
    Program(Installed),
    Overcast(Option<crate::update::Update>),
}

impl Component {
    pub const ALL: [Self; 6] = [
        Self::Overcast,
        Self::Xray,
        Self::SingBox,
        Self::Mihomo,
        Self::Caddy,
        Self::Usque,
    ];

    pub fn key(self) -> &'static str {
        match self {
            Self::Overcast => "overcast",
            Self::Xray => "xray",
            Self::SingBox => "sing-box",
            Self::Mihomo => "mihomo",
            Self::Caddy => "caddy",
            Self::Usque => "usque",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Overcast => "Overcast",
            Self::Xray => "Xray",
            Self::SingBox => "sing-box",
            Self::Mihomo => "Mihomo",
            Self::Caddy => "Caddy",
            Self::Usque => "usque",
        }
    }

    fn repository(self) -> &'static str {
        match self {
            Self::Overcast => "zetaloop/overcast",
            Self::Xray => "XTLS/Xray-core",
            Self::SingBox => "SagerNet/sing-box",
            Self::Mihomo => "MetaCubeX/mihomo",
            Self::Caddy => "caddyserver/caddy",
            Self::Usque => "Diniboy1123/usque",
        }
    }

    fn binary(self) -> String {
        format!("{}{}", self.key(), env::consts::EXE_SUFFIX)
    }

    pub fn version(self, resources: &Resources) -> Option<&str> {
        match self {
            Self::Overcast => Some(env!("CARGO_PKG_VERSION")),
            _ => resources.components.get(&self).map(|v| v.version.as_str()),
        }
    }

    pub fn program(self, store: &Store, installed: &Installed) -> Result<PathBuf> {
        Ok(self
            .directory(store, &installed.tag)?
            .join(installed.asset.to_string())
            .join(&installed.path))
    }

    pub fn ensure(
        self,
        store: &Store,
        preview: bool,
        resources: &mut Resources,
        progress: &Progress,
    ) -> Result<()> {
        if let Some(installed) = resources.components.get(&self)
            && self.program(store, installed)?.try_exists()?
        {
            return Ok(());
        }
        let client = resource::client();
        let release = self.release(
            &client,
            resources
                .components
                .get(&self)
                .map(|value| value.tag.as_str()),
            preview,
            progress,
        )?;
        resources
            .components
            .insert(self, self.install(store, &client, &release, progress)?);
        Ok(())
    }

    fn directory(self, store: &Store, version: &str) -> Result<PathBuf> {
        if version.is_empty()
            || Path::new(version)
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err(tr(
                "The component version is not a valid release tag",
                "组件版本不是有效的发布标签",
            )
            .into());
        }
        Ok(store
            .directory
            .join("components")
            .join(self.key())
            .join(version))
    }

    fn release(
        self,
        client: &Agent,
        version: Option<&str>,
        preview: bool,
        progress: &Progress,
    ) -> Result<Release> {
        let step = progress.activity(tr("Checking releases", "查询版本"));
        let url = url::Url::parse(&format!(
            "https://api.github.com/repos/{}/releases",
            self.repository()
        ))?;
        let release = if let Some(version) = version {
            let mut url = url.clone();
            url.path_segments_mut()
                .map_err(|_| tr("Invalid release URL", "版本地址格式不正确"))?
                .extend(["tags", version]);
            resource::json(client, url.as_str(), progress, &step)?
        } else if preview {
            let mut releases: Vec<Release> = resource::json(client, url.as_str(), progress, &step)?;
            if self == Self::Mihomo
                && !releases
                    .iter()
                    .any(|release| release.tag_name == "Prerelease-Alpha")
            {
                let mut url = url.clone();
                url.path_segments_mut()
                    .map_err(|_| tr("Invalid release URL", "版本地址格式不正确"))?
                    .extend(["tags", "Prerelease-Alpha"]);
                releases.push(resource::json(client, url.as_str(), progress, &step)?);
            }
            releases
                .into_iter()
                .filter(|release| !release.draft)
                .map(|release| {
                    let published = release.published_at.as_deref().unwrap_or_default();
                    let date = self
                        .package(&release)
                        .map_or(published, |p| p.asset.updated_at.as_str().max(published))
                        .to_owned();
                    (date, release)
                })
                .max_by(|(left, _), (right, _)| left.cmp(right))
                .map(|(_, release)| release)
                .ok_or(tr("No releases found", "发布列表中没有已发布版本"))?
        } else {
            let mut url = url;
            url.path_segments_mut()
                .map_err(|_| tr("Invalid release URL", "版本地址格式不正确"))?
                .push("latest");
            resource::json(client, url.as_str(), progress, &step)?
        };
        step.finish(self.package(&release)?.version);
        Ok(release)
    }

    fn package(self, release: &Release) -> Result<Package<'_>> {
        let architecture = match env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            "x86" => "386",
            "loongarch64" => "loong64",
            "powerpc64" if cfg!(target_endian = "little") => "ppc64le",
            "powerpc64" => "ppc64",
            architecture => architecture,
        };
        let system = env::consts::OS;
        let version = release.tag_name.trim_start_matches('v');
        let extension = if cfg!(windows) { "zip" } else { "tar.gz" };
        let (name, member) = match self {
            Self::Overcast => {
                let platform = match system {
                    "windows" => "pc-windows-msvc",
                    "linux" => "unknown-linux-musl",
                    "macos" => "apple-darwin",
                    _ => {
                        return Err(message!(
                            "No Overcast binary for {system}",
                            "没有提供 {system} 版 Overcast"
                        )
                        .into());
                    }
                };
                (
                    format!(
                        "overcast-{}-{platform}{}",
                        env::consts::ARCH,
                        env::consts::EXE_SUFFIX
                    ),
                    self.binary(),
                )
            }
            Self::Xray => {
                let architecture = match architecture {
                    "amd64" => "64",
                    "arm64" => "arm64-v8a",
                    "386" => "32",
                    architecture => architecture,
                };
                (format!("Xray-{system}-{architecture}.zip"), self.binary())
            }
            Self::SingBox => {
                let system = if system == "macos" { "darwin" } else { system };
                (
                    format!("sing-box-{version}-{system}-{architecture}.{extension}"),
                    self.binary(),
                )
            }
            Self::Mihomo => {
                let system = if system == "macos" { "darwin" } else { system };
                #[cfg(target_arch = "x86_64")]
                let architecture = amd64();
                let extension = if cfg!(windows) { "zip" } else { "gz" };
                let member = format!("mihomo-{system}-{architecture}{}", env::consts::EXE_SUFFIX);
                if release.tag_name == "Prerelease-Alpha" {
                    let prefix = format!("mihomo-{system}-{architecture}-");
                    let suffix = format!(".{extension}");
                    let (asset, version) = release
                        .assets
                        .iter()
                        .filter_map(|asset| {
                            let version =
                                asset.name.strip_prefix(&prefix)?.strip_suffix(&suffix)?;
                            version.starts_with("alpha-").then_some((asset, version))
                        })
                        .max_by_key(|(asset, _)| &asset.updated_at)
                        .ok_or_else(|| {
                            message!(
                                "No Mihomo Alpha binary for {system}/{architecture}",
                                "Mihomo Alpha 没有提供 {system}/{architecture} 程序"
                            )
                        })?;
                    return Ok(Package {
                        asset,
                        member,
                        version: version.to_owned(),
                    });
                }
                (
                    format!(
                        "mihomo-{system}-{architecture}-{}.{extension}",
                        release.tag_name
                    ),
                    member,
                )
            }
            Self::Caddy => {
                let system = if system == "macos" { "mac" } else { system };
                (
                    format!("caddy_{version}_{system}_{architecture}.{extension}"),
                    self.binary(),
                )
            }
            Self::Usque => {
                let system = if system == "macos" { "darwin" } else { system };
                (
                    format!("usque_{version}_{system}_{architecture}.zip"),
                    self.binary(),
                )
            }
        };
        let asset = release
            .assets
            .iter()
            .find(|asset| asset.name == name)
            .ok_or_else(|| {
                message!(
                    "{} {} does not include {name}",
                    "{} {} 没有提供 {name}",
                    self.name(),
                    release.tag_name
                )
            })?;
        Ok(Package {
            asset,
            member,
            version: release.tag_name.clone(),
        })
    }

    fn prepare(
        self,
        store: &Store,
        client: &Agent,
        release: &Release,
        specific: bool,
        progress: &Progress,
    ) -> Result<Prepared> {
        match self {
            Self::Overcast => Ok(Prepared::Overcast(crate::update::Update::prepare(
                client,
                self.package(release)?.asset,
                &release.tag_name,
                specific,
                progress,
            )?)),
            _ => Ok(Prepared::Program(
                self.install(store, client, release, progress)?,
            )),
        }
    }

    fn install(
        self,
        store: &Store,
        client: &Agent,
        release: &Release,
        progress: &Progress,
    ) -> Result<Installed> {
        let Package {
            asset,
            member,
            version,
        } = self.package(release)?;
        let parent = self.directory(store, &release.tag_name)?;
        let directory = parent.join(asset.id.to_string());
        let path = if !directory.try_exists()? {
            store.create_dir(&parent)?;
            let mut download = NamedTempFile::new_in(&parent)?;
            asset.download(client, download.as_file_mut(), progress)?;
            let unpacked = tempdir_in(&parent)?;
            let step = progress.activity(tr("Extracting binary", "展开程序"));
            unpack(
                download.as_file_mut(),
                &asset.name,
                &member,
                unpacked.path(),
                progress,
                &step,
            )?;
            progress.check()?;
            let paths = files(unpacked.path())?;
            let binary = paths
                .iter()
                .find(|path| {
                    path.file_name().is_some_and(|name| name == member.as_str()) && path.is_file()
                })
                .ok_or_else(|| {
                    message!(
                        "{} does not contain {member}",
                        "{} 中没有找到 {member}",
                        asset.name
                    )
                })?;
            let path = binary.strip_prefix(unpacked.path())?.to_owned();
            #[cfg(unix)]
            fs::set_permissions(binary, fs::Permissions::from_mode(0o700))?;
            for path in &paths {
                progress.check()?;
                if path.symlink_metadata()?.is_file() {
                    OpenOptions::new().write(true).open(path)?.sync_all()?;
                }
            }
            match fs::rename(unpacked.path(), &directory) {
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::DirectoryNotEmpty
                    ) && directory.is_dir() => {}
                Err(error) => return Err(error.into()),
            }
            step.finish(&version);
            path
        } else {
            let binary = files(&directory)?
                .into_iter()
                .find(|path| {
                    path.file_name().is_some_and(|name| name == member.as_str()) && path.is_file()
                })
                .ok_or_else(|| {
                    message!(
                        "{} does not contain {member}",
                        "{} 中没有找到 {member}",
                        directory.display()
                    )
                })?;
            binary.strip_prefix(&directory)?.to_owned()
        };
        let installed = Installed {
            tag: release.tag_name.clone(),
            version,
            asset: asset.id,
            path,
        };
        progress.check()?;
        let detail = format!("{} {}", self.name(), installed.version);
        progress.record(tr("Ready", "准备完成"), &detail);
        Ok(installed)
    }
}

fn unpack(
    source: &mut File,
    name: &str,
    member: &str,
    destination: &Path,
    progress: &Progress,
    step: &Step,
) -> Result<()> {
    let source = resource::Reader { source, progress };
    if name.ends_with(".zip") {
        let mut archive = zip::ZipArchive::new(source)?;
        archive.extract(destination)?;
    } else if name.ends_with(".tar.gz") {
        let mut archive = tar::Archive::new(GzDecoder::new(BufReader::new(source)));
        archive.unpack(destination)?;
        std::io::copy(&mut archive.into_inner(), &mut std::io::sink())?;
    } else if name.ends_with(".gz") {
        resource::copy(
            &mut GzDecoder::new(BufReader::new(source)),
            &mut File::create(destination.join(member))?,
            progress,
            step,
        )?;
    } else {
        return Err(message!(
            "Unsupported package format: {name}",
            "不支持的程序包格式：{name}"
        )
        .into());
    }
    progress.check()
}

fn files(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut directories = vec![directory.to_owned()];
    let mut paths = Vec::new();
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                directories.push(path.clone());
            }
            paths.push(path);
        }
    }
    Ok(paths)
}

#[cfg(target_arch = "x86_64")]
fn amd64() -> &'static str {
    let v2 = std::is_x86_feature_detected!("cmpxchg16b")
        && std::is_x86_feature_detected!("popcnt")
        && std::is_x86_feature_detected!("sse3")
        && std::is_x86_feature_detected!("ssse3")
        && std::is_x86_feature_detected!("sse4.1")
        && std::is_x86_feature_detected!("sse4.2")
        && std::arch::x86_64::__cpuid(0x8000_0001).ecx & 1 != 0;
    if !v2 {
        return "amd64-v1";
    }
    if std::is_x86_feature_detected!("avx")
        && std::is_x86_feature_detected!("avx2")
        && std::is_x86_feature_detected!("bmi1")
        && std::is_x86_feature_detected!("bmi2")
        && std::is_x86_feature_detected!("f16c")
        && std::is_x86_feature_detected!("fma")
        && std::is_x86_feature_detected!("lzcnt")
        && std::is_x86_feature_detected!("movbe")
    {
        "amd64-v3"
    } else {
        "amd64-v2"
    }
}

pub fn edit(
    screen: &mut Screen,
    store: &Store,
    client: &Agent,
    component: Component,
) -> Result<Option<crate::update::Installed>> {
    let mut selected = 0;
    let mut notice = String::new();
    let mut latest: Option<Release> = None;
    loop {
        let config = store.load()?;
        let resources = Resources::load(store)?;
        let settings = config.components.get(&component);
        let preview = settings.is_some_and(|settings| settings.preview);
        let installed = resources.components.get(&component);
        let own = component == Component::Overcast;
        let version = component
            .version(&resources)
            .unwrap_or(tr("Not installed", "未安装"));
        let channel = if own { crate::update::channel()? } else { None };
        let mut heading = message!("Current version: {version}", "当前版本：{version}");
        if let Some(channel) = channel.as_ref().map(|c| &c.name) {
            heading.push_str(&message!(
                " (installed via {channel})",
                "（{channel} 安装）"
            ));
        }
        let mut items = [
            Item::new(
                "install",
                tr("Install latest version", "安装最新版").stylized(),
            ),
            Item::new("version", tr("Choose version", "指定版本").stylized()),
            Item::new("check", tr("Check for updates", "检查更新").stylized()),
            Item::new(
                "preview",
                tr("Include prereleases", "包含预览版").stylized(),
            ),
            Item::new("back", tr("Back", "返回").stylized()),
        ];
        items[1].value = if own {
            format!("v{version}")
        } else {
            installed.map_or_else(String::new, |v| v.tag.clone())
        };
        items[1].detail = tr("Release tag", "发布标签").to_owned();
        items[3].marker = if preview { "■" } else { "□" };
        if let Some(release) = &latest {
            items[0].value = component.package(release)?.version;
        }
        let menu = Menu {
            title: component.name(),
            heading: &heading,
            items: &items,
            help: tr(
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
            "check" => screen
                .work(
                    tr("Checking releases", "查询版本"),
                    component.name(),
                    |progress| component.release(client, None, preview, progress),
                )
                .map(|release| {
                    latest = Some(release);
                }),
            "install" | "version" => {
                if let Some(channel) = channel.as_ref().map(|c| &c.name) {
                    let mut selected = 0;
                    let choices = [
                        Item::new("back", tr("Back", "返回").stylized()),
                        Item::new("replace", tr("Update anyway", "仍然更新").stylized()),
                    ];
                    let heading = message!(
                        "This will replace the executable installed by {channel}.",
                        "当前程序由 {channel} 安装，此操作会替换它。"
                    );
                    let menu = Menu {
                        title: tr("Update Overcast", "更新 Overcast"),
                        heading: &heading,
                        items: &choices,
                        help: menu.help,
                    };
                    if !matches!(screen.select(&menu, &mut selected, "")?, Action::Select)
                        || selected == 0
                    {
                        continue;
                    }
                }
                let version = if items[selected].key == "version" {
                    let Some(version) =
                        screen.input(&menu, selected, &items[selected].value, |value, _| {
                            let version = value.trim();
                            if version.is_empty() {
                                return Err(tr("Enter a release tag", "请填写发布标签").into());
                            }
                            component.directory(store, version)?;
                            Ok(version.to_owned())
                        })?
                    else {
                        continue;
                    };
                    Some(version)
                } else {
                    None
                };
                let result = screen.work(
                    tr("Installing component", "安装组件"),
                    component.name(),
                    |progress| {
                        let release =
                            component.release(client, version.as_deref(), preview, progress)?;
                        let updated = match component.prepare(
                            store,
                            client,
                            &release,
                            version.is_some(),
                            progress,
                        )? {
                            Prepared::Overcast(update) => {
                                update.map(|v| v.install(store, progress)).transpose()?
                            }
                            Prepared::Program(installed) => {
                                store.update(progress, |_, resources| {
                                    resources.components.insert(component, installed);
                                    Ok(())
                                })?;
                                None
                            }
                        };
                        Ok((release, updated))
                    },
                );
                match result {
                    Ok((_, Some(update))) => return Ok(Some(update)),
                    Ok((release, None)) => {
                        if version.is_none() {
                            latest = Some(release);
                        }
                        Ok(())
                    }
                    Err(error) => Err(error),
                }
            }
            "preview" => screen
                .work(component.name(), "", |progress| {
                    store.update(progress, |config, _| {
                        config.components.entry(component).or_default().preview = !preview;
                        Ok(())
                    })
                })
                .map(|()| {
                    latest = None;
                }),
            _ => return Ok(None),
        };
        notice = result
            .err()
            .map_or_else(String::new, |error| error.to_string());
    }
}

pub fn update(
    store: &Store,
    config: &crate::config::Config,
    resources: &mut Resources,
    progress: &Progress,
) -> Result<Option<crate::update::Update>> {
    let client = resource::client();
    let standalone = crate::update::channel()?.is_none();
    let prepared = thread::scope(|scope| {
        let tasks: Vec<_> = Component::ALL
            .into_iter()
            .filter(|component| match component {
                Component::Overcast => standalone,
                _ => resources.components.contains_key(component),
            })
            .map(|component| {
                let progress = progress.group(component.name());
                let client = &client;
                let preview = config
                    .components
                    .get(&component)
                    .is_some_and(|settings| settings.preview);
                scope.spawn(move || {
                    let result = component
                        .release(client, None, preview, &progress)
                        .and_then(|release| {
                            component.prepare(store, client, &release, false, &progress)
                        });
                    if let Err(error) = &result {
                        progress.fail(&error.to_string());
                    }
                    result.map(|value| (component, value))
                })
            })
            .collect();
        tasks
            .into_iter()
            .map(|task| {
                task.join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            })
            .collect::<Result<Vec<_>>>()
    })?;
    let mut update = None;
    for (component, value) in prepared {
        match value {
            Prepared::Program(installed) => {
                resources.components.insert(component, installed);
            }
            Prepared::Overcast(program) => update = program,
        }
    }
    Ok(update)
}
