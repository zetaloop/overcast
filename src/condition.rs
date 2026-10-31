use std::collections::BTreeMap;

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Result, config::Config, geodata::Catalog, pattern};

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "kebab-case")]
pub enum Condition {
    #[default]
    Always,
    Never,
    And(Vec<Self>),
    Or(Vec<Self>),
    User(Uuid),
    Inbound(Uuid),
    Domain(String),
    Suffix(String),
    Keyword(String),
    Regex(String),
    Ip(IpNetwork),
    Site(String),
    Geoip(String),
    Asn(u32),
}

impl Condition {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Regex(text) => {
                pattern::parse(text)?;
            }
            Self::And(children) | Self::Or(children) => {
                for child in children {
                    child.validate()?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub fn text(&self, config: &Config) -> String {
        self.format(config, 0)
    }

    fn format(&self, config: &Config, parent: u8) -> String {
        let (children, operator, precedence) = match self {
            Self::Always => return if parent == 0 { "" } else { "()" }.to_owned(),
            Self::Never => return "黑洞".to_owned(),
            Self::And(children) => (children, " & ", 2),
            Self::Or(children) => (children, " | ", 1),
            _ => {
                let (kind, value) = self.reference(config).unwrap();
                return format!("{kind}:{}", quote(&value));
            }
        };
        if children.is_empty() {
            return if precedence == 2 {
                Self::Always.format(config, parent)
            } else {
                Self::Never.format(config, parent)
            };
        }
        let text = children
            .iter()
            .map(|child| child.format(config, precedence))
            .collect::<Vec<_>>()
            .join(operator);
        if parent > precedence {
            format!("({text})")
        } else {
            text
        }
    }

    fn reference(&self, config: &Config) -> Option<(&'static str, String)> {
        Some(match self {
            Self::User(uuid) => (
                "user",
                object_name(
                    *uuid,
                    config
                        .users
                        .iter()
                        .map(|user| (user.uuid, user.name.as_str())),
                ),
            ),
            Self::Inbound(uuid) => (
                "inbound",
                object_name(
                    *uuid,
                    config
                        .inbounds
                        .iter()
                        .map(|inbound| (inbound.uuid, inbound.name.as_str())),
                ),
            ),
            Self::Domain(value) => ("domain", value.clone()),
            Self::Suffix(value) => ("suffix", value.clone()),
            Self::Keyword(value) => ("keyword", value.clone()),
            Self::Regex(value) => ("regex", value.clone()),
            Self::Ip(value) => ("ip", value.to_string()),
            Self::Site(value) => ("site", value.clone()),
            Self::Geoip(value) => ("geoip", value.clone()),
            Self::Asn(value) => ("asn", format!("AS{value}")),
            _ => return None,
        })
    }

    pub fn bindings(&self, config: &Config) -> BTreeMap<String, Self> {
        let mut bindings = BTreeMap::new();
        match self {
            Self::And(children) | Self::Or(children) => {
                for child in children {
                    bindings.extend(child.bindings(config));
                }
            }
            _ => {
                if let Some((kind, value)) = self.reference(config) {
                    bindings.insert(format!("{kind}:{value}"), self.clone());
                }
            }
        }
        bindings
    }

    pub fn parse(
        text: &str,
        config: &Config,
        catalog: &Catalog,
        bindings: &BTreeMap<String, Self>,
    ) -> Result<Self> {
        if text.trim().is_empty() {
            return Ok(Self::Always);
        }
        let mut parser = Parser {
            text,
            position: 0,
            config,
            catalog,
            bindings,
        };
        let condition = parser.or()?;
        parser.space();
        if parser.position != text.len() {
            return Err(format!("条件中有多余内容：{}", &text[parser.position..]).into());
        }
        Ok(condition)
    }

    pub fn replace_user(&mut self, previous: Uuid, current: Uuid) {
        match self {
            Self::User(uuid) if *uuid == previous => *uuid = current,
            Self::And(children) | Self::Or(children) => {
                for child in children {
                    child.replace_user(previous, current);
                }
            }
            _ => {}
        }
    }
}

fn object_name<'a>(uuid: Uuid, objects: impl Iterator<Item = (Uuid, &'a str)>) -> String {
    let objects: Vec<_> = objects.collect();
    if let Some((_, name)) = objects.iter().find(|(id, _)| *id == uuid)
        && name.parse::<Uuid>().is_err()
        && objects.iter().filter(|(_, other)| other == name).count() == 1
    {
        return (*name).to_owned();
    }
    uuid.to_string()
}

fn quote(value: &str) -> String {
    if value.trim() != value
        || value.chars().any(|character| {
            matches!(character, '&' | '|' | '(' | ')' | '"') || character.is_control()
        })
    {
        serde_json::to_string(value).unwrap()
    } else {
        value.to_owned()
    }
}

struct Parser<'a> {
    text: &'a str,
    position: usize,
    config: &'a Config,
    catalog: &'a Catalog,
    bindings: &'a BTreeMap<String, Condition>,
}

impl Parser<'_> {
    fn space(&mut self) {
        while let Some(character) = self.text[self.position..].chars().next()
            && character.is_whitespace()
        {
            self.position += character.len_utf8();
        }
    }

    fn take(&mut self, character: char) -> bool {
        self.space();
        if self.text[self.position..].starts_with(character) {
            self.position += character.len_utf8();
            true
        } else {
            false
        }
    }

    fn or(&mut self) -> Result<Condition> {
        let mut children = vec![self.and()?];
        while self.take('|') {
            children.push(self.and()?);
        }
        Ok(if children.len() == 1 {
            children.pop().unwrap()
        } else {
            Condition::Or(children)
        })
    }

    fn and(&mut self) -> Result<Condition> {
        let mut children = vec![self.atom()?];
        while self.take('&') {
            children.push(self.atom()?);
        }
        Ok(if children.len() == 1 {
            children.pop().unwrap()
        } else {
            Condition::And(children)
        })
    }

    fn atom(&mut self) -> Result<Condition> {
        self.space();
        if self.take('(') {
            if self.take(')') {
                return Ok(Condition::Always);
            }
            let condition = self.or()?;
            if !self.take(')') {
                return Err("条件缺少右括号".into());
            }
            return Ok(condition);
        }
        let mut value = String::new();
        let mut end = 0;
        while let Some(character) = self.text[self.position..].chars().next() {
            if matches!(character, '&' | '|' | '(' | ')') {
                break;
            }
            if character == '"' {
                let mut decoder = serde_json::Deserializer::from_str(&self.text[self.position..])
                    .into_iter::<String>();
                let text = decoder
                    .next()
                    .ok_or("名称引号不完整")?
                    .map_err(|error| format!("引号内的文字格式不正确：{error}"))?;
                self.position += decoder.byte_offset();
                value.push_str(&text);
                end = value.len();
            } else {
                self.position += character.len_utf8();
                value.push(character);
                if !character.is_whitespace() {
                    end = value.len();
                }
            }
        }
        value.truncate(end);
        if value.is_empty() {
            return Err("条件中缺少名称或目标".into());
        }
        self.resolve(&value)
    }

    fn resolve(&self, value: &str) -> Result<Condition> {
        if value == "黑洞" {
            return Ok(Condition::Never);
        }
        if let Some(condition) = self.bindings.get(value) {
            return Ok(condition.clone());
        }
        if let Ok(ip) = network(value) {
            return Ok(Condition::Ip(ip));
        }
        if let Some((kind, name)) = value.split_once(':') {
            if name.is_empty() {
                return Err(format!("{kind} 条件缺少内容").into());
            }
            match kind {
                "domain" => return domain(name).map(Condition::Domain),
                "suffix" => return domain(name).map(Condition::Suffix),
                "keyword" => return Ok(Condition::Keyword(name.to_owned())),
                "regex" => {
                    pattern::parse(name)?;
                    return Ok(Condition::Regex(name.to_owned()));
                }
                "ip" => return network(name).map(Condition::Ip),
                "user" | "inbound" | "site" | "geoip" | "asn" => {
                    return self.named(Some(kind), name);
                }
                _ => {}
            }
        }
        self.named(None, value)
    }

    fn named(&self, kind: Option<&str>, name: &str) -> Result<Condition> {
        let mut matches = Vec::new();
        let uuid = name.parse::<Uuid>().ok();
        if kind.is_none_or(|kind| kind == "user") {
            for user in &self.config.users {
                if uuid.map_or(user.name == name, |uuid| user.uuid == uuid) {
                    matches.push(Condition::User(user.uuid));
                }
            }
        }
        if kind.is_none_or(|kind| kind == "inbound") {
            for inbound in &self.config.inbounds {
                if uuid.map_or(inbound.name == name, |uuid| inbound.uuid == uuid) {
                    matches.push(Condition::Inbound(inbound.uuid));
                }
            }
        }
        let tag = name.to_ascii_lowercase();
        if kind.is_none_or(|kind| kind == "site") && self.catalog.sites.contains(&tag) {
            matches.push(Condition::Site(tag.clone()));
        }
        if kind.is_none_or(|kind| kind == "geoip") && self.catalog.ips.contains(&tag) {
            matches.push(Condition::Geoip(tag.clone()));
        }
        if kind.is_none_or(|kind| kind == "asn")
            && let Ok(number) = tag.strip_prefix("as").unwrap_or(&tag).parse::<u32>()
            && self.catalog.asns.contains_key(&number)
        {
            matches.push(Condition::Asn(number));
        }
        if kind.is_none()
            && name.contains('.')
            && let Ok(domain) = domain(name)
        {
            matches.push(Condition::Domain(domain));
        }
        match matches.len() {
            0 => Err(format!("找不到条件项：{name}").into()),
            1 => Ok(matches.pop().unwrap()),
            _ => Err(format!(
                "名称对应多个条件：{}",
                matches
                    .iter()
                    .map(|condition| condition.text(self.config))
                    .collect::<Vec<_>>()
                    .join("、")
            )
            .into()),
        }
    }
}

fn domain(value: &str) -> Result<String> {
    match url::Host::parse(value).map_err(|error| format!("域名格式不正确：{error}"))? {
        url::Host::Domain(name) => Ok(name),
        _ => Err("域名条件需要填写域名，IP 地址使用 ip: 条件".into()),
    }
}

fn network(value: &str) -> Result<IpNetwork> {
    let ip: IpNetwork = value
        .parse()
        .map_err(|error| format!("IP 地址或网段格式不正确：{error}"))?;
    Ok(IpNetwork::new(ip.network(), ip.prefix())?)
}
