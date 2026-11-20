use crate::language::{message, text as tr};
use std::{collections::BTreeSet, time::Duration};

use serde::Serialize;
use serde_json::{Map, Value, json};

use super::unsupported;
use crate::Result;

pub struct Options {
    values: Map<String, Value>,
    fields: Option<BTreeSet<String>>,
}

impl Options {
    pub fn new<T: Default + Serialize>(value: &T) -> Result<Self> {
        let Value::Object(mut values) = serde_json::to_value(value)? else {
            unreachable!()
        };
        let defaults = serde_json::to_value(T::default())?;
        values.retain(|key, value| defaults.get(key) != Some(value));
        Ok(Self {
            values,
            fields: None,
        })
    }

    pub fn fields(write: impl FnOnce(&mut Self) -> Result<()>) -> BTreeSet<String> {
        let mut options = Self {
            values: Map::new(),
            fields: Some(BTreeSet::new()),
        };
        write(&mut options).expect("default parameters must be representable");
        options.fields.unwrap()
    }

    pub fn take(&mut self, name: &str) -> Option<Value> {
        if let Some(fields) = &mut self.fields {
            fields.insert(name.to_owned());
        }
        self.values.remove(name)
    }

    pub(crate) fn keys(&self) -> impl Iterator<Item = &str> {
        self.values.keys().map(String::as_str)
    }

    pub(super) fn require(&mut self, key: &str) {
        self.values.entry(key).or_insert(Value::Null);
    }

    pub fn seconds(&mut self, name: &str) -> Option<u64> {
        let duration = humantime::parse_duration(self.values.get(name)?.as_str()?).ok()?;
        if duration.subsec_nanos() != 0 {
            return None;
        }
        self.take(name);
        Some(duration.as_secs())
    }

    pub fn copy(&mut self, output: &mut Map<String, Value>, names: &[&str]) {
        for &name in names {
            if let Some(value) = self.take(name) {
                output.insert(name.to_owned(), value);
            }
        }
    }

    pub fn rename(&mut self, output: &mut Map<String, Value>, names: &[(&str, &str)]) {
        for &(source, destination) in names {
            if let Some(value) = self.take(source) {
                output.insert(destination.to_owned(), value);
            }
        }
    }

    pub fn invert(&mut self, output: &mut Map<String, Value>, source: &str, destination: &str) {
        if let Some(value) = self.take(source) {
            output.insert(destination.to_owned(), json!(!value.as_bool().unwrap()));
        }
    }

    pub fn durations(
        &mut self,
        output: &mut Map<String, Value>,
        names: &[(&str, &str)],
        unit: Option<Duration>,
    ) -> Result<()> {
        for &(source, destination) in names {
            if let Some(value) = self.take(source) {
                let text = value.as_str().unwrap();
                let duration = humantime::parse_duration(text).map_err(|error| {
                    message!(
                        "Invalid duration {text}: {error}",
                        "时间格式不正确 {text}：{error}"
                    )
                })?;
                let value = match unit {
                    Some(unit) => {
                        if duration.as_nanos() % unit.as_nanos() != 0 {
                            return unsupported(message!(
                                "{source} cannot express {text} in units of {}",
                                "{source} 的精度无法用 {} 表达：{text}",
                                humantime::format_duration(unit),
                            ));
                        }
                        json!(u64::try_from(duration.as_nanos() / unit.as_nanos())?)
                    }
                    None => json!(format!("{}ns", duration.as_nanos())),
                };
                output.insert(destination.to_owned(), value);
            }
        }
        Ok(())
    }

    pub fn finish(self, name: &str) -> Result<()> {
        if self.values.is_empty() {
            Ok(())
        } else {
            unsupported(message!(
                "Unsupported {name} parameters: {}",
                "{name} 无法表达参数：{}",
                self.values
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(tr(", ", "、")),
            ))
        }
    }
}
