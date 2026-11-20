use crate::language::{message, text as tr};
use std::{fs, path::Path};

use crate::{
    Result,
    config::Store,
    form::{self, Form, Value},
    security::Material,
    transport::Transport,
    tui::Screen,
};

pub(crate) trait Draft: Clone {
    type Core: Value + Copy + PartialEq;
    fn core(&self) -> Self::Core;
    fn supports(&self, core: Self::Core) -> bool;
    fn set_core(&mut self, core: Self::Core);
    fn projected(&self) -> Self;
    fn changes(&self, next: &Self, changes: &mut Changes);
    fn materials(&mut self, active: &Self, changes: &mut Changes);

    fn preview(&self, target: Self::Core) -> (Self, String) {
        let mut draft = self.clone();
        draft.set_core(target);
        let active = draft.projected();
        let mut changes = Changes::default();
        if target != self.core() {
            self.projected().changes(&active, &mut changes);
            draft.materials(&active, &mut changes);
        }
        (active, changes.lines.join("\n"))
    }

    fn select(&mut self, active: &Self, directory: &Path) -> Vec<String> {
        self.set_core(active.core());
        let mut changes = Changes {
            directory: Some(directory),
            ..Default::default()
        };
        self.materials(active, &mut changes);
        changes.errors
    }
}

pub(crate) fn choose<T: Draft>(
    value: &mut T,
    screen: &mut Screen,
    title: &str,
    store: &Store,
) -> Result<bool> {
    let current = value.core();
    let choices: Vec<_> = T::Core::choices()
        .into_iter()
        .filter(|(_, _, core)| value.supports(*core))
        .map(|(key, name, core)| (key, name, value.preview(core)))
        .collect();
    let current_index = choices.iter().position(|(_, _, v)| v.0.core() == current);
    let Some(index) = form::pick(screen, title, &choices, current_index, |v| v.1.clone())? else {
        return Ok(false);
    };
    if Some(index) == current_index {
        return Ok(false);
    }
    let errors = value.select(&choices[index].2.0, &store.directory);
    if !errors.is_empty() {
        screen.warn(errors.join("\n"));
    }
    Ok(true)
}

#[derive(Default)]
pub(crate) struct Changes<'a> {
    pub lines: Vec<String>,
    directory: Option<&'a Path>,
    errors: Vec<String>,
}

impl Changes<'_> {
    pub fn client_tls(
        &mut self,
        tls: &mut crate::connection::Tls,
        core: crate::inbound::Core,
        ech: bool,
        prefix: &str,
    ) {
        if ech
            && !core.ech_file(false)
            && let Some(material) = tls.ech.as_mut().and_then(|v| v.config.as_mut())
        {
            self.inline(
                &message!("{prefix}ECH public configuration", "{prefix}ECH 公共参数"),
                material,
            );
        }
        if core.inline_trust(false, &tls.certificates) {
            for material in &mut tls.certificates {
                self.inline(
                    &message!("{prefix}trusted certificates", "{prefix}信任证书"),
                    material,
                );
            }
        }
        if core.paired_identity()
            && let (Some(cert), Some(key)) = (&mut tls.client_certificate, &mut tls.client_key)
            && cert.inline().is_some() != key.inline().is_some()
        {
            self.inline(
                &message!("{prefix}client certificate", "{prefix}客户端证书"),
                cert,
            );
            self.inline(
                &message!("{prefix}client private key", "{prefix}客户端私钥"),
                key,
            );
        }
    }

    pub fn flag(&mut self, name: &str, old: bool, new: bool) {
        if old != new {
            let space = if name.starts_with(|c: char| c.is_ascii_alphanumeric()) {
                " "
            } else {
                ""
            };
            self.lines.push(if new {
                message!("Enable {name}", "开启{space}{name}")
            } else {
                message!("Disable {name}", "关闭{space}{name}")
            });
        }
    }

    pub fn mode<T: Value>(&mut self, name: &str, old: &T, new: &T) {
        if old.text() != new.text() {
            self.lines.push(message!(
                "Change {name} from {} to {}",
                "{name}从 {} 改为 {}",
                old.text(),
                new.text()
            ));
        }
    }

    pub fn fields<T: Form + serde::Serialize>(&mut self, prefix: &str, old: &T, new: &T) {
        let old = serde_json::to_value(old).expect("form fields serialize");
        let next = serde_json::to_value(new).expect("form fields serialize");
        if old == next {
            return;
        }
        let defaults = serde_json::to_value(T::default()).expect("form defaults serialize");
        for field in new.clone().fields(T::default()) {
            let key = field.key();
            if let (Some(a), Some(b)) = (old.get(key), next.get(key))
                && a != b
            {
                let item = field.item();
                let name = format!("{prefix}{}", item.label.content);
                if let (Some(a), Some(b)) = (a.as_bool(), b.as_bool()) {
                    self.flag(&name, a, b);
                } else if b.is_null() || b.as_array().is_some_and(Vec::is_empty) {
                    self.lines.push(message!("Clear {name}", "清除{name}"));
                } else if a.is_null() || a.as_array().is_some_and(Vec::is_empty) {
                    self.lines.push(message!("Restore {name}", "恢复{name}"));
                } else if defaults.get(key) == Some(b) {
                    self.lines
                        .push(message!("Reset {name} to default", "{name}恢复默认"));
                } else if a.is_object() || b.is_object() {
                    self.lines
                        .push(message!("Restore {name} settings", "恢复{name}设置"));
                } else {
                    self.lines
                        .push(message!("Set {name} to {}", "{name}改为{}", item.value));
                }
            }
        }
    }

    pub fn transport(&mut self, old: &Transport, new: &Transport) {
        if let (Transport::Grpc(a), Transport::Grpc(b)) = (old, new) {
            self.fields("gRPC ", a, b);
        } else {
            self.mode(tr("Transport", "传输"), old, new);
        }
    }

    pub fn inline(&mut self, name: &str, value: &mut Material) {
        let Material::File(file) = value else { return };
        let Some(directory) = self.directory else {
            let text = message!(
                "Use inline {name} instead of a file",
                "{name}从文件路径改为正文"
            );
            if !self.lines.contains(&text) {
                self.lines.push(text);
            }
            return;
        };
        let path = directory.join(&*file);
        *value = Material::Inline(match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) => {
                self.errors.push(message!(
                    "Could not read {}: {error}",
                    "无法读取 {}：{error}",
                    path.display()
                ));
                String::new()
            }
        });
    }
}
