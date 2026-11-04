#[cfg(target_os = "macos")]
mod macos;
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
    process::{Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver, RecvTimeoutError, Sender},
    thread,
    time::{Duration, Instant},
};

use notify::{RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    Result, certificate,
    component::Component,
    config::{Config, Store},
    native::{Instance, State},
    progress::Progress,
};

#[derive(Default, Deserialize, Serialize)]
struct Deployment {
    id: Uuid,
    ports: BTreeMap<String, u16>,
    units: Vec<Unit>,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
struct Unit {
    component: Component,
    name: String,
    program: PathBuf,
    config: PathBuf,
    environment: BTreeMap<String, String>,
    certificates: BTreeSet<String>,
}

#[derive(Default, Deserialize, Serialize)]
struct Status {
    id: Uuid,
    error: Option<String>,
}

enum Event {
    Reload,
    Stop,
    Exited(String, u64, std::io::Result<ExitStatus>),
}

impl Deployment {
    fn load(store: &Store, config: &Config) -> Result<Self> {
        let Some(id) = config.runtime else {
            return Ok(Self::default());
        };
        let directory = store.directory.join("runtime").join(id.to_string());
        let state: State = serde_json::from_slice(&fs::read(directory.join("state.json"))?)?;
        let mut units = Vec::new();
        for Instance {
            component,
            file,
            environment,
        } in &state.instances
        {
            let config_file = directory.join(file);
            let stem = config_file
                .parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy();
            let name = stem.into_owned();
            let settings = config
                .components
                .get(component)
                .ok_or_else(|| format!("{} 尚未安装", component.name()))?;
            units.push(Unit {
                component: *component,
                name,
                program: component.program(store, settings)?,
                config: config_file,
                environment: environment.clone(),
                certificates: if *component == Component::Caddy {
                    BTreeSet::new()
                } else {
                    state.certificates.clone()
                },
            });
        }
        Ok(Self {
            id: Uuid::new_v4(),
            ports: state.ports,
            units,
        })
    }

    fn saved(store: &Store) -> Result<Self> {
        match fs::read(store.directory.join("services.json")) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error.into()),
        }
    }

    fn save(&self, store: &Store) -> Result<()> {
        store.write(&store.directory.join("services.json"), |file| {
            serde_json::to_writer_pretty(file, self)?;
            Ok(())
        })
    }

    fn certificates(&self) -> BTreeSet<String> {
        self.units
            .iter()
            .flat_map(|unit| unit.certificates.iter().cloned())
            .collect()
    }

    fn caddy(&self) -> Option<&Unit> {
        self.units
            .iter()
            .find(|unit| unit.component == Component::Caddy)
    }
}

impl Unit {
    fn arguments(&self, check: bool) -> Vec<OsString> {
        let directory = self.config.parent().unwrap();
        match self.component {
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

pub fn prepare(store: &Store, config: &mut Config, progress: &Progress) -> Result<()> {
    let Some(id) = config.runtime else {
        return Ok(());
    };
    let state: State = serde_json::from_slice(&fs::read(
        store
            .directory
            .join("runtime")
            .join(id.to_string())
            .join("state.json"),
    )?)?;
    let components: BTreeSet<_> = state
        .instances
        .iter()
        .map(|instance| instance.component)
        .collect();
    for component in components {
        component.ensure(
            store,
            config.components.entry(component).or_default(),
            &progress.group(component.name()),
        )?;
    }
    Ok(())
}

pub fn apply(store: &Store, previous: &Config, target: &Config, progress: &Progress) -> Result<()> {
    let deployment = Deployment::load(store, target)?;
    for unit in &deployment.units {
        unit.check(progress)?;
    }
    progress.check()?;
    deployment.save(store)?;
    if let Err(error) = switch(
        store,
        previous.running,
        target.running,
        &deployment,
        progress,
    ) {
        let step = progress.activity("恢复部署");
        match restore(store, target, previous, &Progress::default()) {
            Ok(()) => step.finish("已恢复此前部署"),
            Err(recovery) => return Err(format!("{error}；恢复部署失败：{recovery}").into()),
        }
        return Err(error);
    }
    Ok(())
}

pub fn restore(
    store: &Store,
    current: &Config,
    previous: &Config,
    progress: &Progress,
) -> Result<()> {
    let deployment = Deployment::load(store, previous)?;
    deployment.save(store)?;
    switch(
        store,
        current.running,
        previous.running,
        &deployment,
        progress,
    )
}

fn switch(
    store: &Store,
    previous: bool,
    running: bool,
    target: &Deployment,
    progress: &Progress,
) -> Result<()> {
    match (previous, running) {
        (false, false) => {}
        (true, false) => {
            let step = progress.activity("停止服务");
            platform::remove()?;
            step.finish("已停止");
        }
        (false, true) => {
            let step = progress.activity("启动服务");
            platform::install(store)?;
            wait(store, target.id, progress)?;
            step.finish(format!("{} 个核心", target.units.len()));
        }
        (true, true) => {
            let step = progress.activity("应用服务");
            platform::reload()?;
            wait(store, target.id, progress)?;
            step.finish(format!("{} 个核心", target.units.len()));
        }
    }
    Ok(())
}

fn wait(store: &Store, id: Uuid, progress: &Progress) -> Result<()> {
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
            }
        });
        orchestrate(&store, sender, events, &progress)
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
    done: Receiver<()>,
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
    let mut pending = true;
    loop {
        if pending {
            pending = false;
            let target = Deployment::saved(store)?;
            let result = orchestrator.transition(&deployment, &target);
            retries.clear();
            if let Err(error) = &result {
                log(store, &format!("应用部署失败：{error}"));
            }
            store.write(&store.directory.join("status.json"), |file| {
                serde_json::to_writer(
                    file,
                    &Status {
                        id: target.id,
                        error: result.err().map(|error| error.to_string()),
                    },
                )?;
                Ok(())
            })?;
            deployment = target;
        }
        let deadline = retries.values().copied().min();
        let event = match deadline {
            Some(deadline) => {
                events.recv_timeout(deadline.saturating_duration_since(Instant::now()))
            }
            None => events.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        match event {
            Ok(Event::Reload) => pending = true,
            Ok(Event::Stop) | Err(RecvTimeoutError::Disconnected) => break,
            Ok(Event::Exited(name, generation, status)) => {
                if orchestrator
                    .running
                    .get(&name)
                    .is_some_and(|process| process.generation == generation)
                {
                    let process = orchestrator.running.remove(&name).unwrap();
                    let delay = if process.started.elapsed() > BACKOFF {
                        RESTART
                    } else {
                        delays
                            .get(&name)
                            .map_or(RESTART, |delay| (*delay * 2).min(BACKOFF))
                    };
                    match status {
                        Ok(status) => log(store, &format!("{name} 退出：{status}")),
                        Err(error) => log(store, &format!("{name} 退出：{error}")),
                    }
                    delays.insert(name.clone(), delay);
                    retries.insert(name, Instant::now() + delay);
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
                    .get(&unit.name)
                    .is_none_or(|process| process.unit != **unit)
            })
            .map(|unit| unit.name.clone())
            .collect();
        let caddy = self
            .running
            .values()
            .find(|process| process.unit.component == Component::Caddy)
            .map(|process| process.unit.name.clone());
        if let Some(unit) = target.caddy().filter(|unit| changed.contains(&unit.name)) {
            unit.check(self.progress)?;
            match caddy
                .as_ref()
                .and_then(|name| self.running.get_mut(name))
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
            certificate::wait(self.store, &target.certificates(), self.progress)?;
        } else if target.caddy().is_none()
            && let Some(name) = &caddy
        {
            self.stop(name);
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
            self.stop(&name);
        }
        for unit in target
            .units
            .iter()
            .filter(|unit| unit.component != Component::Caddy && changed.contains(&unit.name))
        {
            self.progress.check()?;
            self.start(unit)?;
        }
        Ok(())
    }

    fn start(&mut self, unit: &Unit) -> Result<()> {
        let logs = self.store.directory.join("logs");
        self.store.create_dir(&logs)?;
        let output = OpenOptions::new()
            .create(true)
            .append(true)
            .open(logs.join(format!("{}.log", unit.name)))?;
        let mut command = unit.command(false);
        command
            .stdin(Stdio::null())
            .stdout(output.try_clone()?)
            .stderr(output);
        isolate(&mut command);
        let mut child = command
            .spawn()
            .map_err(|error| format!("启动 {} 失败：{error}", unit.component.name()))?;
        self.generation += 1;
        let (finished, done) = mpsc::sync_channel(1);
        let (sender, name, generation) = (self.sender.clone(), unit.name.clone(), self.generation);
        let pid = child.id();
        thread::spawn(move || {
            let status = child.wait();
            let _ = finished.send(());
            let _ = sender.send(Event::Exited(name, generation, status));
        });
        self.running.insert(
            unit.name.clone(),
            Process {
                unit: unit.clone(),
                pid,
                generation,
                started: Instant::now(),
                done,
            },
        );
        Ok(())
    }

    fn stop(&mut self, name: &str) {
        let Some(process) = self.running.remove(name) else {
            return;
        };
        terminate(process.pid);
        if process.done.recv_timeout(Duration::from_secs(10)).is_err() {
            kill(process.pid);
            let _ = process.done.recv();
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
