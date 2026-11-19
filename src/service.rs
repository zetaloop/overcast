#[cfg(target_os = "macos")]
mod macos;
mod startup;
#[cfg(all(unix, not(target_os = "macos")))]
mod systemd;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "macos")]
use macos as platform;
#[cfg(all(unix, not(target_os = "macos")))]
use systemd as platform;
#[cfg(windows)]
use windows as platform;

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    path::PathBuf,
    process::Command,
    sync::mpsc::{self, Receiver, RecvTimeoutError, Sender},
    thread,
    time::{Duration, Instant},
};

use notify::{RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use termina::style::StyleExt;
use uuid::Uuid;

use crate::{
    Result, certificate,
    component::Component,
    config::{Config, Store},
    maintenance,
    native::{Instance, Prepared},
    progress::{Progress, Step},
    resource::Resources,
    tui::{Action, Item, Menu, Screen},
};

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Deployment {
    pub id: Uuid,
    pub config: Config,
    pub geodata: Option<u64>,
    pub ports: BTreeMap<String, u16>,
    pub coverage: crate::graph::Coverage,
    units: Vec<Unit>,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
struct Unit {
    component: Component,
    name: String,
    program: PathBuf,
    config: PathBuf,
    assets: Vec<String>,
    environment: BTreeMap<String, String>,
    certificates: BTreeSet<String>,
}

#[derive(Default, Deserialize, Serialize)]
struct Status {
    id: Uuid,
    activity: Option<String>,
    error: Option<String>,
}

enum Event {
    Reload,
    Stop,
    Exited(String, u64),
    Maintained(Result<()>),
}

impl Deployment {
    pub fn load(store: &Store) -> Result<Self> {
        match fs::read(store.directory.join("deployment.json")) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error.into()),
        }
    }

    pub fn reuse(
        &self,
        store: &Store,
        config: &Config,
        resources: &Resources,
    ) -> Result<Option<Self>> {
        if self.config.runtime()? != config.runtime()? || self.geodata != resources.geodata {
            return Ok(None);
        }
        for unit in &self.units {
            let Some(installed) = resources.components.get(&unit.component) else {
                return Ok(None);
            };
            if unit.component.program(store, installed)? != unit.program {
                return Ok(None);
            }
        }
        Ok(Some(Self {
            id: Uuid::new_v4(),
            config: config.clone(),
            ..self.clone()
        }))
    }

    pub fn prepare(
        store: &Store,
        config: &Config,
        resources: &mut Resources,
        prepared: Option<&Prepared>,
        coverage: crate::graph::Coverage,
        previous: &Self,
        progress: &Progress,
    ) -> Result<Self> {
        let mut deployment = Self {
            id: Uuid::new_v4(),
            config: config.clone(),
            geodata: resources.geodata,
            coverage,
            ..Self::default()
        };
        let Some(prepared) = prepared else {
            return Ok(deployment);
        };
        let state = &prepared.state;
        for Instance {
            component,
            file,
            assets,
            environment,
            certificates,
        } in &state.instances
        {
            component.ensure(
                store,
                config
                    .components
                    .get(component)
                    .is_some_and(|settings| settings.preview),
                resources,
                &progress.group(component.name()),
            )?;
            let config_file = prepared.directory().join(file);
            let stem = config_file
                .parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy();
            let name = stem.into_owned();
            let installed = resources
                .components
                .get(component)
                .ok_or_else(|| format!("缺少 {} 程序", component.name()))?;
            let mut unit = Unit {
                component: *component,
                name,
                program: component.program(store, installed)?,
                config: config_file,
                assets: assets.clone(),
                environment: environment.clone(),
                certificates: certificates.clone(),
            };
            if let Some(old) = previous.units.iter().find(|old| old.name == unit.name)
                && unit.equivalent(old)?
            {
                unit = old.clone();
            }
            deployment.units.push(unit);
        }
        deployment.ports = state.ports.clone();
        Ok(deployment)
    }

    pub fn directories(&self) -> BTreeSet<PathBuf> {
        self.units
            .iter()
            .map(|unit| unit.config.parent().unwrap().to_owned())
            .collect()
    }

    fn certificates(&self) -> BTreeSet<String> {
        self.units
            .iter()
            .flat_map(|unit| unit.certificates.iter().cloned())
            .collect()
    }

    fn save(&self, store: &Store) -> Result<()> {
        store.write(&store.directory.join("deployment.json"), |file| {
            serde_json::to_writer_pretty(file, self)?;
            Ok(())
        })
    }

    fn caddy(&self) -> Option<&Unit> {
        self.units
            .iter()
            .find(|unit| unit.component == Component::Caddy)
    }
}

impl Unit {
    fn equivalent(&self, other: &Self) -> Result<bool> {
        if self.component != other.component
            || self.program != other.program
            || self.environment != other.environment
            || self.certificates != other.certificates
            || self.assets != other.assets
        {
            return Ok(false);
        }
        for (file, previous) in std::iter::once((self.config.clone(), other.config.clone())).chain(
            self.assets.iter().map(|name| {
                (
                    self.config.parent().unwrap().join(name),
                    other.config.parent().unwrap().join(name),
                )
            }),
        ) {
            let previous = match fs::read(previous) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
                Err(error) => return Err(error.into()),
            };
            if fs::read(file)? != previous {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn arguments(&self, check: bool) -> Vec<OsString> {
        let directory = self.config.parent().unwrap();
        match self.component {
            Component::Usque => unreachable!("registration tool in deployment"),
            Component::Xray => {
                let mut args = vec![
                    "run".into(),
                    "-config".into(),
                    self.config.as_os_str().to_owned(),
                ];
                if check {
                    args.push("-test".into());
                }
                args
            }
            Component::SingBox => vec![
                if check { "check" } else { "run" }.into(),
                "--disable-color".into(),
                "-c".into(),
                self.config.as_os_str().to_owned(),
                "-D".into(),
                directory.as_os_str().to_owned(),
            ],
            Component::Mihomo => {
                let mut args = vec![
                    "-f".into(),
                    self.config.as_os_str().to_owned(),
                    "-d".into(),
                    directory.as_os_str().to_owned(),
                ];
                if check {
                    args.push("-t".into());
                }
                args
            }
            Component::Caddy => vec![
                if check { "validate" } else { "run" }.into(),
                "--config".into(),
                self.config.as_os_str().to_owned(),
            ],
        }
    }

    fn check(&self, progress: &Progress) -> Result<()> {
        progress.check()?;
        let step = progress.activity(format!("读取 {} 配置", self.component.name()));
        execute(&mut self.command(true))?;
        step.finish(&self.name);
        Ok(())
    }

    fn command(&self, check: bool) -> Command {
        let mut command = Command::new(&self.program);
        command
            .args(self.arguments(check))
            .envs(&self.environment)
            .current_dir(self.config.parent().unwrap());
        command
    }
}

pub fn logs(screen: &mut Screen, store: &Store) -> Result<()> {
    let directory = store.directory.join("logs");
    let mut paths = Vec::new();
    match fs::read_dir(&directory) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry?;
                let path = entry.path();
                if entry.file_type()?.is_file()
                    && path.extension().is_some_and(|extension| extension == "log")
                {
                    paths.push(path);
                }
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    paths.sort();
    if paths.is_empty() {
        return screen.view("运行日志", "尚无运行日志");
    }
    let mut selected = 0;
    let mut notice = String::new();
    loop {
        let items: Vec<_> = paths
            .iter()
            .map(|path| {
                let name = path.file_name().unwrap().to_string_lossy();
                Item::new(name.clone().into_owned(), name.into_owned().stylized())
            })
            .chain(std::iter::once(Item::new("back", "返回".stylized())))
            .collect();
        let menu = Menu {
            title: "运行日志",
            heading: "",
            items: &items,
            help: "方向键 选择\n回车键 查看\nEsc 返回",
        };
        match screen.select(&menu, &mut selected, &notice)? {
            Action::Back => return Ok(()),
            Action::Select if selected == paths.len() => return Ok(()),
            Action::Select => {
                let bytes = match fs::read(&paths[selected]) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        notice = error.to_string();
                        continue;
                    }
                };
                let text = String::from_utf8_lossy(&bytes);
                let title = paths[selected].file_name().unwrap().to_string_lossy();
                screen.view(&title, &text)?;
                notice.clear();
            }
            _ => {}
        }
    }
}

pub fn apply(
    store: &Store,
    previous: &Deployment,
    target: &Deployment,
    progress: &Progress,
) -> Result<()> {
    for unit in target
        .units
        .iter()
        .filter(|unit| unit.certificates.is_empty() && !previous.units.contains(unit))
    {
        unit.check(progress)?;
    }
    progress.check()?;
    target.save(store)?;
    if let Err(error) = switch(store, previous, target, progress) {
        let step = progress.activity("恢复部署");
        match restore(store, target, previous, &Progress::default()) {
            Ok(()) => step.finish("已恢复此前部署"),
            Err(recovery) => return Err(format!("{error}；恢复部署失败：{recovery}").into()),
        }
        return Err(format!("{error}\n已恢复此前部署").into());
    }
    Ok(())
}

pub fn restore(
    store: &Store,
    current: &Deployment,
    previous: &Deployment,
    progress: &Progress,
) -> Result<()> {
    previous.save(store)?;
    switch(store, current, previous, progress)
}

fn switch(
    store: &Store,
    previous: &Deployment,
    target: &Deployment,
    progress: &Progress,
) -> Result<()> {
    match (previous.config.running, target.config.running) {
        (false, false) => {}
        (true, false) => {
            let step = progress.activity("停止服务");
            platform::remove()?;
            step.finish("已停止");
        }
        (false, true) => {
            let step = progress.activity("启动服务");
            report(store, target.id, Some("启动编排器".to_owned()), None)?;
            platform::install(store)?;
            wait(store, target.id, progress, &step)?;
            step.finish("已启动");
        }
        (true, true)
            if previous.units == target.units
                && previous.config.maintenance == target.config.maintenance => {}
        (true, true) => {
            let step = progress.activity("应用服务");
            report(store, target.id, Some("载入配置".to_owned()), None)?;
            platform::reload()?;
            wait(store, target.id, progress, &step)?;
            step.finish("已应用");
        }
    }
    Ok(())
}

fn wait(store: &Store, id: Uuid, progress: &Progress, step: &Step) -> Result<()> {
    let path = store.directory.join("status.json");
    let changed = progress.clone();
    let mut watcher =
        notify::recommended_watcher(move |_: notify::Result<notify::Event>| changed.notify())?;
    watcher.watch(&store.directory, RecursiveMode::NonRecursive)?;
    let mut result = Ok(());
    progress.until(|| {
        let status: Status = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        if status.id != id {
            return Ok(false);
        }
        if let Some(activity) = status.activity {
            step.detail(activity);
            return Ok(false);
        }
        if let Some(error) = status.error {
            result = Err(error.into());
        }
        Ok(true)
    })?;
    result
}

pub fn run(store: Store) -> Result<()> {
    #[cfg(unix)]
    {
        use nix::sys::signal::{SigSet, Signal};

        let mut signals = SigSet::empty();
        for signal in [Signal::SIGHUP, Signal::SIGTERM, Signal::SIGINT] {
            signals.add(signal);
        }
        signals.thread_block()?;
        let (sender, events) = mpsc::channel();
        let progress = Progress::default();
        let (notify, cancel) = (sender.clone(), progress.clone());
        thread::spawn(move || {
            while let Ok(signal) = signals.wait() {
                if signal != Signal::SIGHUP {
                    cancel.cancel();
                    let _ = notify.send(Event::Stop);
                    return;
                }
                if notify.send(Event::Reload).is_err() {
                    return;
                }
                cancel.notify();
            }
        });
        finish(&store, orchestrate(&store, sender, events, &progress))
    }
    #[cfg(windows)]
    {
        windows::serve(store)
    }
}

struct Process {
    unit: Unit,
    pid: u32,
    generation: u64,
    started: Instant,
    done: Receiver<String>,
    exit: Option<String>,
}

struct Orchestrator<'a> {
    store: &'a Store,
    sender: Sender<Event>,
    progress: &'a Progress,
    running: BTreeMap<String, Process>,
    generation: u64,
}

const RESTART: Duration = Duration::from_secs(1);
const BACKOFF: Duration = Duration::from_secs(60);

fn orchestrate(
    store: &Store,
    sender: Sender<Event>,
    events: Receiver<Event>,
    progress: &Progress,
) -> Result<()> {
    let mut orchestrator = Orchestrator {
        store,
        sender,
        progress,
        running: BTreeMap::new(),
        generation: 0,
    };
    let mut deployment = Deployment::default();
    let mut retries: BTreeMap<String, Instant> = BTreeMap::new();
    let mut delays: BTreeMap<String, Duration> = BTreeMap::new();
    let mut maintenance = None;
    let mut pending = true;
    loop {
        if pending {
            pending = false;
            let target = Deployment::load(store)?;
            let result = orchestrator.transition(&deployment, &target);
            retries.clear();
            if let Err(error) = &result {
                log(store, &format!("应用部署失败：{error}"));
            }
            report(
                store,
                target.id,
                None,
                result.err().map(|error| error.to_string()),
            )?;
            if maintenance.is_none() || deployment.config.maintenance != target.config.maintenance {
                maintenance = target
                    .config
                    .maintenance
                    .next()?
                    .map(|delay| Instant::now() + delay);
            }
            deployment = target;
        }
        let deadline = retries.values().copied().chain(maintenance).min();
        let event = match deadline {
            Some(deadline) => {
                events.recv_timeout(deadline.saturating_duration_since(Instant::now()))
            }
            None => events.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        match event {
            Ok(Event::Reload) => pending = true,
            Ok(Event::Stop) | Err(RecvTimeoutError::Disconnected) => break,
            Ok(Event::Exited(name, generation)) => {
                if orchestrator
                    .running
                    .get(&name)
                    .is_some_and(|process| process.generation == generation)
                {
                    let mut process = orchestrator.running.remove(&name).unwrap();
                    let delay = if process.started.elapsed() > BACKOFF {
                        RESTART
                    } else {
                        delays
                            .get(&name)
                            .map_or(RESTART, |delay| (*delay * 2).min(BACKOFF))
                    };
                    log(
                        store,
                        &format!(
                            "{name} 退出：{}",
                            process.status().expect("missing exit status")
                        ),
                    );
                    delays.insert(name.clone(), delay);
                    retries.insert(name, Instant::now() + delay);
                }
            }
            Ok(Event::Maintained(result)) => {
                if let Err(error) = result {
                    log(store, &format!("定时维护失败：{error}"));
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                let now = Instant::now();
                let due: Vec<_> = retries
                    .iter()
                    .filter(|(_, at)| **at <= now)
                    .map(|(name, _)| name.clone())
                    .collect();
                for name in due {
                    retries.remove(&name);
                    let Some(unit) = deployment.units.iter().find(|unit| unit.name == name) else {
                        continue;
                    };
                    if let Err(error) = orchestrator.start(unit) {
                        log(store, &format!("{name} 启动失败：{error}"));
                        let delay = (delays[&name] * 2).min(BACKOFF);
                        delays.insert(name.clone(), delay);
                        retries.insert(name, now + delay);
                    }
                }
                if maintenance.is_some_and(|at| at <= now) {
                    let store = store.clone();
                    let sender = orchestrator.sender.clone();
                    thread::spawn(move || {
                        let result = maintenance::update(&store, &Progress::default());
                        let _ = sender.send(Event::Maintained(result));
                    });
                    maintenance = deployment
                        .config
                        .maintenance
                        .next()?
                        .map(|delay| now + delay);
                }
            }
        }
    }
    let names: Vec<_> = orchestrator
        .running
        .values()
        .filter(|process| process.unit.component != Component::Caddy)
        .map(|process| process.unit.name.clone())
        .chain(
            deployment
                .caddy()
                .map(|unit| unit.name.clone())
                .filter(|name| orchestrator.running.contains_key(name)),
        )
        .collect();
    for name in names {
        orchestrator.stop(&name);
    }
    Ok(())
}

impl Orchestrator<'_> {
    fn transition(&mut self, previous: &Deployment, target: &Deployment) -> Result<()> {
        let changed: BTreeSet<_> = target
            .units
            .iter()
            .filter(|unit| {
                self.running
                    .get_mut(&unit.name)
                    .is_none_or(|process| process.unit != **unit || process.status().is_some())
            })
            .map(|unit| unit.name.clone())
            .collect();
        let caddy = self
            .running
            .values()
            .find(|process| process.unit.component == Component::Caddy)
            .map(|process| process.unit.name.clone());
        if let Some(unit) = target.caddy().filter(|unit| changed.contains(&unit.name)) {
            report(self.store, target.id, Some("准备 Caddy".to_owned()), None)?;
            unit.check(self.progress)?;
            match caddy
                .as_ref()
                .and_then(|name| self.running.get_mut(name))
                .and_then(|process| process.status().is_none().then_some(process))
                .filter(|process| process.unit.program == unit.program)
            {
                Some(process) => {
                    let port = previous
                        .ports
                        .get("caddy")
                        .copied()
                        .unwrap_or(target.ports["caddy"]);
                    reload(unit, port)?;
                    process.unit = unit.clone();
                }
                None => {
                    if let Some(name) = &caddy {
                        self.stop(name);
                    }
                    self.start(unit)?;
                }
            }
            let certificates = target.certificates();
            report(
                self.store,
                target.id,
                Some(format!(
                    "准备证书：{}",
                    certificates.iter().cloned().collect::<Vec<_>>().join("、")
                )),
                None,
            )?;
            let process = self.running.get_mut(&unit.name).unwrap();
            certificate::wait(self.store, &certificates, self.progress, || {
                process.check()?;
                Ok(Deployment::load(self.store)?.id == target.id)
            })?;
        } else if target.caddy().is_none()
            && let Some(name) = &caddy
        {
            self.stop(name);
        }
        for unit in target
            .units
            .iter()
            .filter(|unit| unit.component != Component::Caddy && changed.contains(&unit.name))
        {
            report(
                self.store,
                target.id,
                Some(format!("检查 {} 配置", unit.component.name())),
                None,
            )?;
            unit.check(self.progress)?;
        }
        let obsolete: Vec<_> = self
            .running
            .values()
            .filter(|process| {
                process.unit.component != Component::Caddy
                    && (changed.contains(&process.unit.name)
                        || !target
                            .units
                            .iter()
                            .any(|unit| unit.name == process.unit.name))
            })
            .map(|process| process.unit.name.clone())
            .collect();
        for name in obsolete {
            report(self.store, target.id, Some(format!("停止 {name}")), None)?;
            self.stop(&name);
        }
        for unit in target
            .units
            .iter()
            .filter(|unit| unit.component != Component::Caddy && changed.contains(&unit.name))
        {
            self.progress.check()?;
            report(
                self.store,
                target.id,
                Some(format!("启动 {}", unit.component.name())),
                None,
            )?;
            self.start(unit)?;
        }
        for process in self.running.values_mut() {
            process.check()?;
        }
        Ok(())
    }

    fn start(&mut self, unit: &Unit) -> Result<()> {
        let logs = self.store.directory.join("logs");
        self.store.create_dir(&logs)?;
        let mut command = unit.command(false);
        let startup = startup::Startup::prepare(
            unit,
            &mut command,
            logs.join(format!("{}.log", unit.name)),
            self.progress,
        )?;
        isolate(&mut command);
        let mut child = command
            .spawn()
            .map_err(|error| format!("启动 {} 失败：{error}", unit.component.name()))?;
        drop(command);
        self.generation += 1;
        let (finished, done) = mpsc::sync_channel(1);
        let (sender, name, generation) = (self.sender.clone(), unit.name.clone(), self.generation);
        let notify = self.progress.clone();
        let pid = child.id();
        thread::spawn(move || {
            let status = child.wait();
            let _ = finished.send(
                status
                    .as_ref()
                    .map_or_else(ToString::to_string, ToString::to_string),
            );
            notify.notify();
            let _ = sender.send(Event::Exited(name, generation));
        });
        let mut process = Process {
            unit: unit.clone(),
            pid,
            generation,
            started: Instant::now(),
            done,
            exit: None,
        };
        if let Err(error) = self.progress.until(|| {
            let desired = Deployment::load(self.store)?;
            if !desired.config.running || !desired.units.contains(unit) {
                return Err(std::io::Error::new(ErrorKind::Interrupted, "部署已被替换").into());
            }
            startup.ready(process.status())
        }) {
            process.stop();
            return Err(format!("启动 {} 失败：{error}", unit.name).into());
        }
        self.running.insert(unit.name.clone(), process);
        Ok(())
    }

    fn stop(&mut self, name: &str) {
        if let Some(process) = self.running.remove(name) {
            process.stop();
        }
    }
}

impl Process {
    fn status(&mut self) -> Option<&str> {
        if self.exit.is_none() {
            self.exit = self.done.try_recv().ok();
        }
        self.exit.as_deref()
    }

    fn check(&mut self) -> Result<()> {
        if let Some(status) = self.status().map(str::to_owned) {
            return Err(format!("{} 已退出：{status}", self.unit.name).into());
        }
        Ok(())
    }

    fn stop(mut self) {
        if self.status().is_none() {
            terminate(self.pid);
            if let Err(RecvTimeoutError::Timeout) = self.done.recv_timeout(Duration::from_secs(10))
            {
                kill(self.pid);
                let _ = self.done.recv();
            }
        }
    }
}

#[cfg(unix)]
fn isolate(command: &mut Command) {
    use nix::sys::signal::SigSet;
    use std::os::unix::process::CommandExt;

    unsafe {
        command.pre_exec(|| {
            SigSet::all().thread_unblock()?;
            #[cfg(target_os = "linux")]
            nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGTERM)?;
            Ok(())
        });
    }
}

#[cfg(windows)]
fn isolate(command: &mut Command) {
    windows::isolate(command);
}

#[cfg(unix)]
fn terminate(pid: u32) {
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid as i32),
        nix::sys::signal::Signal::SIGTERM,
    );
}

#[cfg(windows)]
fn terminate(pid: u32) {
    windows::terminate(pid);
}

#[cfg(unix)]
fn kill(pid: u32) {
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid as i32),
        nix::sys::signal::Signal::SIGKILL,
    );
}

#[cfg(windows)]
fn kill(pid: u32) {
    windows::kill(pid);
}

fn report(store: &Store, id: Uuid, activity: Option<String>, error: Option<String>) -> Result<()> {
    store.write(&store.directory.join("status.json"), |file| {
        serde_json::to_writer(
            file,
            &Status {
                id,
                activity,
                error,
            },
        )?;
        Ok(())
    })
}

// Waiting clients learn from the status file when the service stops before applying their deployment.
fn finish(store: &Store, result: Result<()>) -> Result<()> {
    let error = match &result {
        Ok(()) => "服务已停止".to_owned(),
        Err(error) => format!("服务已停止：{error}"),
    };
    let id = Deployment::load(store).map_or_else(|_| Uuid::nil(), |deployment| deployment.id);
    let _ = report(store, id, None, Some(error));
    result
}

fn log(store: &Store, message: &str) {
    let logs = store.directory.join("logs");
    if store.create_dir(&logs).is_ok()
        && let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(logs.join("overcast.log"))
    {
        let _ = writeln!(
            file,
            "{} {message}",
            humantime::format_rfc3339_seconds(std::time::SystemTime::now())
        );
    }
}

fn reload(unit: &Unit, port: u16) -> Result<()> {
    execute(
        Command::new(&unit.program)
            .args(["reload", "--config"])
            .arg(&unit.config)
            .args(["--address", &format!("127.0.0.1:{port}")]),
    )?;
    Ok(())
}

fn execute(command: &mut Command) -> Result<String> {
    let output = command.output().map_err(|error| {
        format!(
            "执行 {} 失败：{error}",
            command.get_program().to_string_lossy()
        )
    })?;
    if !output.status.success() {
        let detail = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return Err(format!(
            "{} 执行失败：{}",
            command.get_program().to_string_lossy(),
            detail.trim()
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}
