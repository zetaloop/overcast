use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{BufReader, Seek, SeekFrom},
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
    resource::{self, Asset, Release},
    tui::{Action, Item, Menu, Screen},
};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Component {
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
    pub installed: Option<Installed>,
}

#[derive(Clone, Deserialize, Serialize)]
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

impl Component {
    const ALL: [Self; 5] = [
        Self::Xray,
        Self::SingBox,
        Self::Mihomo,
        Self::Caddy,
        Self::Usque,
    ];

    pub fn key(self) -> &'static str {
        match self {
            Self::Xray => "xray",
            Self::SingBox => "sing-box",
            Self::Mihomo => "mihomo",
            Self::Caddy => "caddy",
            Self::Usque => "usque",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Xray => "Xray",
            Self::SingBox => "sing-box",
            Self::Mihomo => "Mihomo",
            Self::Caddy => "Caddy",
            Self::Usque => "usque",
        }
    }

    fn repository(self) -> &'static str {
        match self {
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

    pub fn program(self, store: &Store, settings: &Settings) -> Result<PathBuf> {
        let installed = settings
            .installed
            .as_ref()
            .ok_or_else(|| format!("{} 尚未安装", self.name()))?;
        Ok(self
            .directory(store, &installed.tag)?
            .join(installed.asset.to_string())
            .join(&installed.path))
    }

    pub fn ensure(self, store: &Store, settings: &mut Settings, progress: &Progress) -> Result<()> {
        if settings.installed.is_some() && self.program(store, settings)?.try_exists()? {
            return Ok(());
        }
        let client = resource::client();
        let release = self.release(
            &client,
            settings.installed.as_ref().map(|value| value.tag.as_str()),
            settings.preview,
            progress,
        )?;
        settings.installed = Some(self.install(store, &client, &release, progress)?);
        Ok(())
    }

    fn directory(self, store: &Store, version: &str) -> Result<PathBuf> {
        if version.is_empty()
            || Path::new(version)
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err("组件版本不是有效的发布标签".into());
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
        let step = progress.activity("查询版本");
        let url = url::Url::parse(&format!(
            "https://api.github.com/repos/{}/releases",
            self.repository()
        ))?;
        let release = if let Some(version) = version {
            let mut url = url.clone();
            url.path_segments_mut()
                .map_err(|_| "版本地址格式不正确")?
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
                    .map_err(|_| "版本地址格式不正确")?
                    .extend(["tags", "Prerelease-Alpha"]);
                releases.push(resource::json(client, url.as_str(), progress, &step)?);
            }
            releases
                .into_iter()
                .filter(|release| !release.draft)
                .map(|release| {
                    let date = self.package(&release).map_or_else(
                        |_| release.published_at.clone(),
                        |package| {
                            package
                                .asset
                                .updated_at
                                .clone()
                                .max(release.published_at.clone())
                        },
                    );
                    (date, release)
                })
                .max_by(|(left, _), (right, _)| left.cmp(right))
                .map(|(_, release)| release)
                .ok_or("发布列表中没有已发布版本")?
        } else {
            let mut url = url;
            url.path_segments_mut()
                .map_err(|_| "版本地址格式不正确")?
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
                            format!("Mihomo Alpha 没有提供 {system}/{architecture} 程序")
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
            .ok_or_else(|| format!("{} {} 没有提供 {name}", self.name(), release.tag_name))?;
        Ok(Package {
            asset,
            member,
            version: release.tag_name.clone(),
        })
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
            store.own(download.path())?;
            let step = progress.start("下载程序", asset.size, "字节");
            resource::retry(progress, &step, || {
                step.set(0);
                step.detail(&asset.name);
                download.as_file_mut().set_len(0)?;
                download.seek(SeekFrom::Start(0))?;
                let mut response = resource::request(client, &asset.browser_download_url)?;
                resource::copy(
                    &mut response.body_mut().as_reader(),
                    download.as_file_mut(),
                    progress,
                    &step,
                )
            })?;
            step.finish(&asset.name);
            download.seek(SeekFrom::Start(0))?;
            let unpacked = tempdir_in(&parent)?;
            store.own(unpacked.path())?;
            let step = progress.activity("展开程序");
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
                .ok_or_else(|| format!("{} 中没有找到 {member}", asset.name))?;
            let path = binary.strip_prefix(unpacked.path())?.to_owned();
            #[cfg(unix)]
            fs::set_permissions(binary, fs::Permissions::from_mode(0o700))?;
            for path in &paths {
                progress.check()?;
                store.own(path)?;
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
                .ok_or_else(|| format!("{} 中没有找到 {member}", directory.display()))?;
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
        progress.record("准备完成", &detail);
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
        return Err(format!("不支持的程序包格式：{name}").into());
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

fn edit(screen: &mut Screen, store: &Store, client: &Agent, component: Component) -> Result<()> {
    let mut selected = 0;
    let mut notice = String::new();
    let mut latest: Option<Release> = None;
    loop {
        let config = store.load()?;
        let settings = config.components.get(&component);
        let preview = settings.is_some_and(|settings| settings.preview);
        let installed = settings.and_then(|settings| settings.installed.as_ref());
        let heading = format!(
            "当前版本：{}",
            installed.map_or("未安装", |installed| installed.version.as_str())
        );
        let mut items = [
            Item::new("install", "安装最新版".stylized()),
            Item::new("version", "指定版本".stylized()),
            Item::new("check", "检查更新".stylized()),
            Item::new("preview", "包含预览版".stylized()),
            Item::new("back", "返回".stylized()),
        ];
        items[1].value = installed.map_or_else(String::new, |installed| installed.tag.clone());
        items[1].detail = "发布标签".to_owned();
        items[3].marker = if preview { "■" } else { "□" };
        if let Some(release) = &latest {
            items[0].value = component.package(release)?.version;
        }
        let menu = Menu {
            title: component.name(),
            heading: &heading,
            items: &items,
            help: "方向键 选择\n回车键 确定\nEsc 返回",
        };
        match screen.select(&menu, &mut selected, &notice)? {
            Action::Back => return Ok(()),
            Action::Select => {}
            _ => continue,
        }
        let result = match items[selected].key.as_str() {
            "check" => screen
                .work("查询版本", component.name(), |progress| {
                    component.release(client, None, preview, progress)
                })
                .map(|release| {
                    latest = Some(release);
                }),
            "install" | "version" => {
                let version = if items[selected].key == "version" {
                    let Some(version) =
                        screen.input(&menu, selected, &items[selected].value, |value, _| {
                            let version = value.trim();
                            if version.is_empty() {
                                return Err("请填写发布标签".into());
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
                screen
                    .work("安装组件", component.name(), |progress| {
                        let release =
                            component.release(client, version.as_deref(), preview, progress)?;
                        let installed = component.install(store, client, &release, progress)?;
                        store.update(progress, |config| {
                            config.components.entry(component).or_default().installed =
                                Some(installed);
                            Ok(())
                        })?;
                        Ok(release)
                    })
                    .map(|release| {
                        if version.is_none() {
                            latest = Some(release);
                        }
                    })
            }
            "preview" => screen
                .work(component.name(), "", |progress| {
                    store.update(progress, |config| {
                        config.components.entry(component).or_default().preview = !preview;
                        Ok(())
                    })
                })
                .map(|()| {
                    latest = None;
                }),
            _ => return Ok(()),
        };
        notice = result
            .err()
            .map_or_else(String::new, |error| error.to_string());
    }
}

pub fn run(screen: &mut Screen, store: &Store) -> Result<()> {
    let client = resource::client();
    let mut selected = 0;
    let mut notice = String::new();
    loop {
        let config = store.load()?;
        let mut items: Vec<_> = Component::ALL
            .iter()
            .map(|component| {
                let mut item = Item::new(component.key(), component.name().stylized());
                item.value = config
                    .components
                    .get(component)
                    .and_then(|settings| settings.installed.as_ref())
                    .map_or_else(
                        || "未安装".to_owned(),
                        |installed| installed.version.clone(),
                    );
                item
            })
            .collect();
        let mut running = Item::new("running", "运行服务".stylized());
        running.marker = if config.running { "■" } else { "□" };
        items.extend([
            running,
            Item::new("update", "更新已安装组件".stylized()),
            Item::new("back", "返回".stylized()),
        ]);
        let menu = Menu {
            title: "组件",
            heading: "",
            items: &items,
            help: "方向键 选择\n回车键 确定\nEsc 返回",
        };
        match screen.select(&menu, &mut selected, &notice)? {
            Action::Back => return Ok(()),
            Action::Select => {}
            _ => continue,
        }
        let result = if let Some(component) = Component::ALL.get(selected) {
            edit(screen, store, &client, *component)
        } else if items[selected].key == "running" {
            screen.work(
                if config.running {
                    "停止服务"
                } else {
                    "启动服务"
                },
                "",
                |progress| {
                    store.update(progress, |config| {
                        config.running = !config.running;
                        Ok(())
                    })
                },
            )
        } else if items[selected].key == "update" {
            screen.work("更新组件", "", |progress| {
                let installed = thread::scope(|scope| {
                    let tasks: Vec<_> = config
                        .components
                        .iter()
                        .filter(|(_, settings)| settings.installed.is_some())
                        .map(|(component, settings)| {
                            let progress = progress.group(component.name());
                            let client = &client;
                            scope.spawn(move || {
                                let result = component
                                    .release(client, None, settings.preview, &progress)
                                    .and_then(|release| {
                                        component.install(store, client, &release, &progress)
                                    });
                                if let Err(error) = &result {
                                    progress.fail(&error.to_string());
                                }
                                result.map(|installed| (*component, installed))
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
                if !installed.is_empty() {
                    store.update(progress, |config| {
                        for (component, installed) in installed {
                            config.components.entry(component).or_default().installed =
                                Some(installed);
                        }
                        Ok(())
                    })?;
                }
                Ok(())
            })
        } else {
            return Ok(());
        };
        notice = result
            .err()
            .map_or_else(String::new, |error| error.to_string());
    }
}
