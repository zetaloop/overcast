use crate::language::{message, text as tr};
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, TryRecvError},
    },
    thread,
    time::Duration,
};

use notify::{RecursiveMode, Watcher};
use serde::Deserialize;
use tempfile::TempPath;

use super::Unit;
use crate::{Result, component::Component, progress::Progress};

pub(super) struct Startup {
    signal: Signal,
    log: PathBuf,
    offset: u64,
}

enum Signal {
    Message(Receiver<Result<()>>),
    Caddy {
        received: Receiver<Result<()>>,
        _pingback: Pingback,
    },
    Mihomo {
        receipt: TempPath,
        _watch: notify::RecommendedWatcher,
        errors: Receiver<notify::Error>,
        names: BTreeSet<String>,
    },
}

impl Startup {
    pub fn prepare(
        unit: &Unit,
        command: &mut Command,
        log: PathBuf,
        progress: &Progress,
    ) -> Result<Self> {
        let output = OpenOptions::new().create(true).append(true).open(&log)?;
        let offset = output.metadata()?.len();
        command.stdin(Stdio::null());
        let (send, received) = mpsc::channel();
        let changed = progress.clone();
        let report = move |result| {
            let _ = send.send(result);
            changed.notify();
        };
        let signal = match unit.component {
            Component::Xray | Component::SingBox => {
                let component = unit.component;
                let (reader, writer) = io::pipe()?;
                command.stdout(writer.try_clone()?).stderr(writer);
                thread::Builder::new().spawn(move || {
                    let mut reader = BufReader::new(reader);
                    let mut output = output;
                    report(message(component, &mut reader, &mut output));
                    let _ = io::copy(&mut reader, &mut output);
                })?;
                Signal::Message(received)
            }
            Component::Caddy => {
                command.stdout(output.try_clone()?).stderr(output);
                let pingback = Pingback::listen(command, report)?;
                Signal::Caddy {
                    received,
                    _pingback: pingback,
                }
            }
            Component::Mihomo => {
                #[derive(Deserialize)]
                struct Listeners {
                    listeners: Vec<Listener>,
                }
                #[derive(Deserialize)]
                struct Listener {
                    name: String,
                }
                let config: Listeners =
                    serde_json::from_reader(BufReader::new(File::open(&unit.config)?))?;
                let directory = unit.config.parent().unwrap();
                let receipt = tempfile::NamedTempFile::new_in(directory)?.into_temp_path();
                let filename = receipt.file_name().unwrap().to_str().unwrap();
                command
                    .arg("-post-up")
                    .arg(format!("echo ready > {filename}"))
                    .stdout(output.try_clone()?)
                    .stderr(output);
                let (send, errors) = mpsc::channel();
                let changed = progress.clone();
                let path = receipt.to_path_buf();
                let mut watch =
                    notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
                        match event {
                            Ok(event) if !event.kind.is_access() && event.paths.contains(&path) => {
                            }
                            Err(error) => {
                                let _ = send.send(error);
                            }
                            _ => return,
                        }
                        changed.notify();
                    })?;
                watch.watch(directory, RecursiveMode::NonRecursive)?;
                Signal::Mihomo {
                    receipt,
                    _watch: watch,
                    errors,
                    names: config
                        .listeners
                        .into_iter()
                        .map(|entry| entry.name)
                        .collect(),
                }
            }
            Component::Usque | Component::Overcast => {
                unreachable!("maintenance program in deployment")
            }
        };
        Ok(Self {
            signal,
            log,
            offset,
        })
    }

    fn output(&self) -> Result<impl BufRead> {
        let mut file = File::open(&self.log)?;
        let length = file.metadata()?.len().saturating_sub(self.offset);
        file.seek(SeekFrom::Start(self.offset))?;
        Ok(BufReader::new(file.take(length)))
    }

    pub fn ready(&self, exited: Option<&str>) -> Result<bool> {
        match &self.signal {
            Signal::Message(received) | Signal::Caddy { received, .. } => {
                match received.try_recv() {
                    Ok(result) => {
                        result?;
                        if exited.is_none() {
                            return Ok(true);
                        }
                    }
                    Err(TryRecvError::Disconnected) => {
                        return Err(
                            tr("Startup status channel closed", "启动结果通道已关闭").into()
                        );
                    }
                    // The reader delivers the complete diagnostic at EOF, including the final line.
                    Err(TryRecvError::Empty) if matches!(self.signal, Signal::Message(_)) => {
                        return Ok(false);
                    }
                    Err(TryRecvError::Empty) => {}
                }
            }
            Signal::Mihomo {
                receipt,
                errors,
                names,
                ..
            } => {
                if let Ok(error) = errors.try_recv() {
                    return Err(error.into());
                }
                if exited.is_none() && receipt.metadata()?.len() > 0 {
                    return listeners(names, self.output()?).map(|()| true);
                }
            }
        }
        if let Some(status) = exited {
            let reason = self
                .output()?
                .lines()
                .last()
                .transpose()?
                .filter(|line| !line.is_empty())
                .map_or_else(
                    || status.to_owned(),
                    |line| message!("{status}: {line}", "{status}：{line}"),
                );
            return Err(message!(
                "Process exited during startup: {reason}",
                "进程在启动时退出：{reason}"
            )
            .into());
        }
        Ok(false)
    }
}

fn message(component: Component, reader: &mut impl BufRead, output: &mut File) -> Result<()> {
    let mut line = Vec::new();
    let mut last = String::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            return Err(if last.is_empty() {
                tr(
                    "Process closed its output before reporting startup",
                    "进程在发出启动结果前关闭了输出",
                )
                .into()
            } else {
                last.into()
            });
        }
        output.write_all(&line)?;
        let text = String::from_utf8_lossy(&line);
        let text = text.trim_end();
        let ready = match component {
            Component::Xray => text.rsplit_once("core: Xray ").is_some_and(|(_, tail)| {
                tail.strip_suffix(" started")
                    .is_some_and(|v| !v.is_empty() && !v.contains(char::is_whitespace))
            }),
            Component::SingBox => text.contains("sing-box started (") && text.ends_with("s)"),
            _ => unreachable!(),
        };
        if ready {
            return Ok(());
        }
        if !text.is_empty() {
            last.clear();
            last.push_str(text);
        }
    }
}

fn listeners(expected: &BTreeSet<String>, output: impl BufRead) -> Result<()> {
    let mut missing = expected.clone();
    for line in output.lines() {
        let line = line?;
        let message = line
            .split_once("msg=")
            .map_or(line.as_str(), |(_, text)| text.trim_matches('"'));
        if let Some(text) = message.strip_prefix("Listener ")
            && let Some((name, _)) = text.split_once(" listen err: ")
            && expected.contains(name)
        {
            return Err(message.to_owned().into());
        }
        if let Some((prefix, _)) = message.split_once("proxy listening at: ")
            && let Some((_, name)) = prefix.split_once('[')
            && let Some((name, _)) = name.split_once(']')
        {
            missing.remove(name);
        }
    }
    if !missing.is_empty() {
        return Err(message!(
            "No startup status for listeners: {}",
            "以下监听没有返回启动结果：{}",
            missing.into_iter().collect::<Vec<_>>().join(tr(", ", "、"))
        )
        .into());
    }
    Ok(())
}

struct Pingback {
    address: SocketAddr,
    finished: Arc<AtomicBool>,
}

impl Pingback {
    fn listen(
        command: &mut Command,
        report: impl FnOnce(Result<()>) + Send + 'static,
    ) -> Result<Self> {
        let listener = TcpListener::bind(
            &[
                SocketAddr::from(([127, 0, 0, 1], 0)),
                SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 0)),
            ][..],
        )?;
        let address = listener.local_addr()?;
        let mut token = [0; 32];
        getrandom::fill(&mut token).map_err(|error| {
            message!(
                "Could not generate Caddy startup acknowledgement: {error}",
                "生成 Caddy 启动回执失败：{error}"
            )
        })?;
        let (input, mut writer) = io::pipe()?;
        writer.write_all(&token)?;
        command
            .arg("--pingback")
            .arg(address.to_string())
            .stdin(input);
        let finished = Arc::new(AtomicBool::new(false));
        let closed = finished.clone();
        thread::Builder::new().spawn(move || {
            let result = (|| -> Result<()> {
                loop {
                    let (mut peer, _) = listener.accept()?;
                    if closed.load(Ordering::Acquire) {
                        return Ok(());
                    }
                    peer.set_read_timeout(Some(Duration::from_secs(1)))?;
                    let mut bytes = [0; 32];
                    if peer.read_exact(&mut bytes).is_ok() && bytes == token {
                        return Ok(());
                    }
                }
            })();
            closed.store(true, Ordering::Release);
            report(result);
        })?;
        Ok(Self { address, finished })
    }
}

impl Drop for Pingback {
    fn drop(&mut self) {
        if !self.finished.swap(true, Ordering::AcqRel) {
            let _ = TcpStream::connect(self.address);
        }
    }
}
