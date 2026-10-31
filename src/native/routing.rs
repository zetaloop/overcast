use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt::Write,
    io::Write as _,
    path::Path,
};

use prost::Message;
use serde_json::{Map, Value, json};

use crate::{
    Result,
    condition::Condition,
    config::Store,
    geodata::{Cidr, DomainType, Geoip, Geoips, Site, Sites},
    graph::Network,
    target::Targets,
};

pub struct Rule {
    pub inbound: Vec<String>,
    pub user: Option<String>,
    pub protocol: Option<&'static str>,
    pub network: Option<Network>,
    pub condition: Condition,
    pub outbound: String,
    pub resolve_udp: bool,
}

pub struct Matchers<'a> {
    targets: &'a Targets,
    names: HashMap<Condition, String>,
    pub used: BTreeSet<String>,
}

impl<'a> Matchers<'a> {
    pub fn new(targets: &'a Targets) -> Self {
        let names = targets
            .domains
            .iter()
            .enumerate()
            .map(|(index, (condition, _))| (condition.clone(), format!("d{index}")))
            .chain(
                targets
                    .ips
                    .iter()
                    .enumerate()
                    .map(|(index, (condition, _))| (condition.clone(), format!("i{index}"))),
            )
            .collect();
        Self {
            targets,
            names,
            used: BTreeSet::new(),
        }
    }

    pub fn reduce(&self, condition: &Condition) -> Condition {
        match condition {
            Condition::And(children) | Condition::Or(children) => Condition::combine(
                matches!(condition, Condition::And(_)),
                children.iter().map(|child| self.reduce(child)).collect(),
            ),
            _ if self
                .targets
                .domains
                .iter()
                .any(|(key, values)| key == condition && values.is_empty())
                || self
                    .targets
                    .ips
                    .iter()
                    .any(|(key, values)| key == condition && values.is_empty()) =>
            {
                Condition::Never
            }
            _ => condition.clone(),
        }
    }

    fn name(&mut self, condition: &Condition) -> &str {
        let name = &self.names[condition];
        self.used.insert(name.clone());
        name
    }

    pub fn write(&self, store: &Store, directory: &Path) -> Result<()> {
        let sites = Sites {
            entries: self
                .targets
                .domains
                .iter()
                .enumerate()
                .filter(|(index, _)| self.used.contains(&format!("d{index}")))
                .map(|(index, (_, entries))| Site {
                    name: format!("D{index}"),
                    domains: entries.clone(),
                })
                .collect(),
        };
        let ips = Geoips {
            entries: self
                .targets
                .ips
                .iter()
                .enumerate()
                .filter(|(index, _)| self.used.contains(&format!("i{index}")))
                .map(|(index, (_, networks))| Geoip {
                    name: format!("I{index}"),
                    networks: networks
                        .iter()
                        .map(|network| Cidr {
                            ip: match network.network() {
                                std::net::IpAddr::V4(value) => value.octets().to_vec(),
                                std::net::IpAddr::V6(value) => value.octets().to_vec(),
                            },
                            prefix: u32::from(network.prefix()),
                        })
                        .collect(),
                    reverse: false,
                })
                .collect(),
        };
        for (name, bytes) in [
            ("geosite.dat", sites.encode_to_vec()),
            ("geoip.dat", ips.encode_to_vec()),
        ] {
            store.write(&directory.join(name), |file| {
                file.write_all(&bytes)?;
                Ok(())
            })?;
        }
        Ok(())
    }

    pub fn rule_sets(&self) -> Result<Vec<Value>> {
        let mut result = Vec::new();
        for (index, (_, entries)) in self.targets.domains.iter().enumerate() {
            let name = format!("d{index}");
            if !self.used.contains(&name) {
                continue;
            }
            let mut fields: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
            for entry in entries {
                let field = match DomainType::try_from(entry.kind)? {
                    DomainType::Domain => "domain",
                    DomainType::Suffix => "domain_suffix",
                    DomainType::Keyword => "domain_keyword",
                    DomainType::Regex => "domain_regex",
                };
                fields.entry(field).or_default().push(&entry.value);
            }
            let rules: Vec<_> = fields
                .into_iter()
                .map(|(name, values)| {
                    Value::Object(Map::from_iter([(name.to_owned(), json!(values))]))
                })
                .collect();
            result.push(json!({"tag": name, "rules": rules}));
        }
        for (index, (_, networks)) in self.targets.ips.iter().enumerate() {
            let name = format!("i{index}");
            if self.used.contains(&name) {
                result.push(json!({
                    "tag": name,
                    "rules": [{"ip_cidr": networks.iter().map(ToString::to_string).collect::<Vec<_>>()}],
                }));
            }
        }
        Ok(result)
    }

    pub fn singbox(&mut self, rules: &[Rule]) -> Vec<Value> {
        let mut result = Vec::new();
        for rule in rules {
            let condition = self.reduce(&rule.condition);
            if condition == Condition::Never {
                continue;
            }
            let mut context = Map::from_iter([("inbound".to_owned(), json!(rule.inbound))]);
            if let Some(user) = &rule.user {
                context.insert("auth_user".to_owned(), json!([user]));
            }
            if let Some(network) = rule.network {
                context.insert("network".to_owned(), json!([network.name()]));
            }
            let lower = self.domains(&condition, false);
            let upper = self.domains(&condition, true);
            if lower != upper {
                let mut conditions = vec![
                    json!(context),
                    json!({"ip_cidr": ["0.0.0.0/0", "::/0"], "invert": true}),
                ];
                if upper != Condition::Always {
                    conditions.push(self.singbox_condition(&upper));
                }
                if lower != Condition::Never {
                    let mut condition = self.singbox_condition(&lower);
                    condition["invert"] = json!(true);
                    conditions.push(condition);
                }
                result.push(json!({
                    "type": "logical", "mode": "and", "rules": conditions,
                    "action": "resolve",
                }));
            }
            let mut value = if condition == Condition::Always {
                json!(context)
            } else {
                json!({
                    "type": "logical",
                    "mode": "and",
                    "rules": [context, self.singbox_condition(&condition)],
                })
            };
            if rule.resolve_udp {
                result.push(json!({
                    "type": "logical", "mode": "and",
                    "rules": [value.clone(), {"network": "udp"}],
                    "action": "resolve",
                }));
            }
            let fields = value.as_object_mut().unwrap();
            if rule.outbound == "block" {
                fields.insert("action".to_owned(), json!("reject"));
            } else {
                fields.insert("outbound".to_owned(), json!(rule.outbound));
            }
            result.push(value);
        }
        result.push(json!({"action": "reject"}));
        result
    }

    fn domains(&self, condition: &Condition, ip: bool) -> Condition {
        match condition {
            Condition::And(children) | Condition::Or(children) => Condition::combine(
                matches!(condition, Condition::And(_)),
                children
                    .iter()
                    .map(|child| self.domains(child, ip))
                    .collect(),
            ),
            _ if self
                .names
                .get(condition)
                .is_some_and(|name| name.starts_with('i')) =>
            {
                if ip {
                    Condition::Always
                } else {
                    Condition::Never
                }
            }
            _ => condition.clone(),
        }
    }

    fn singbox_condition(&mut self, condition: &Condition) -> Value {
        match condition {
            Condition::And(children) | Condition::Or(children) => json!({
                "type": "logical",
                "mode": if matches!(condition, Condition::And(_)) { "and" } else { "or" },
                "rules": children.iter().map(|child| self.singbox_condition(child)).collect::<Vec<_>>(),
            }),
            _ => json!({"rule_set": [self.name(condition)]}),
        }
    }

    pub fn mihomo(&mut self, rules: &[Rule]) -> Vec<String> {
        let mut result = Vec::new();
        for rule in rules {
            let condition = self.reduce(&rule.condition);
            if condition == Condition::Never {
                continue;
            }
            let mut fields = vec![format!("(IN-NAME,{})", rule.inbound.join("/"))];
            if let Some(user) = &rule.user {
                fields.push(format!("(IN-USER,{user})"));
            }
            if let Some(network) = rule.network {
                fields.push(format!("(NETWORK,{})", network.name()));
            }
            if let Some(protocol) = rule.protocol {
                fields.push(format!("(IN-TYPE,{protocol})"));
            }
            if condition != Condition::Always {
                fields.push(format!("({})", self.mihomo_condition(&condition)));
            }
            let outbound = if rule.outbound == "block" {
                "REJECT"
            } else {
                &rule.outbound
            };
            result.push(format!("AND,({}),{outbound}", fields.join(",")));
            if outbound != "REJECT" {
                result.push(format!("AND,({}),REJECT", fields.join(",")));
            }
        }
        result.push("MATCH,REJECT".to_owned());
        result
    }

    fn mihomo_condition(&mut self, condition: &Condition) -> String {
        match condition {
            Condition::And(children) | Condition::Or(children) => {
                let operator = if matches!(condition, Condition::And(_)) {
                    "AND"
                } else {
                    "OR"
                };
                let values: Vec<_> = children
                    .iter()
                    .map(|child| format!("({})", self.mihomo_condition(child)))
                    .collect();
                format!("{operator},({})", values.join(","))
            }
            _ => {
                let name = self.name(condition);
                format!(
                    "{},{}",
                    if name.starts_with('d') {
                        "GEOSITE"
                    } else {
                        "GEOIP"
                    },
                    name
                )
            }
        }
    }

    pub fn xray(&mut self, rules: &[Rule]) -> String {
        let mut body = String::new();
        let mut names = BTreeSet::new();
        for rule in rules {
            let condition = self.reduce(&rule.condition);
            if condition == Condition::Never {
                continue;
            }
            let mut clauses = vec![format!(
                "({})",
                rule.inbound
                    .iter()
                    .map(|tag| format!("inbound == {}", lua(tag)))
                    .collect::<Vec<_>>()
                    .join(" or ")
            )];
            if let Some(user) = &rule.user {
                clauses.push(format!("user == {}", lua(user)));
            }
            if let Some(network) = rule.network {
                clauses.push(format!(
                    "network == router.Network{}",
                    network.name().to_uppercase()
                ));
            }
            if condition != Condition::Always {
                clauses.push(self.xray_condition(&condition, &mut names));
            }
            writeln!(
                body,
                "  if {} then return {} end",
                clauses.join(" and "),
                lua(&rule.outbound)
            )
            .unwrap();
        }
        let mut script = String::from(
            "local geodata = require(\"xray.geodata\")\nlocal dns = require(\"xray.dns\")\nlocal log = require(\"xray.log\")\nlocal router = require(\"xray.router\")\nlocal matchers = {}\n",
        );
        for name in names {
            let (method, category) = if name.starts_with('d') {
                ("BuildDomainMatcher", "geosite")
            } else {
                ("BuildIPMatcher", "geoip")
            };
            writeln!(
                script,
                "matchers[{}] = geodata.{method}({})",
                lua(&name),
                lua(&format!("{category}:{name}"))
            )
            .unwrap();
        }
        script.push_str(
            "\nfunction HandleRoute(ctx, inbound, sourcePort, targetPort, localPort, domain, network, protocol, user, route, skipDNS)\n  local addresses, resolved\n  local function ips()\n    if not resolved then\n      resolved = true\n      if domain ~= \"\" and not skipDNS then\n        local values, ttl, err = dns.Query(domain, true, true, false)\n        if err == nil then addresses = values else log.Info(err, \" resolve ip for \", domain) end\n      end\n      if addresses == nil or #addresses == 0 then addresses = ctx:GetTargetIPs() end\n    end\n    return addresses\n  end\n",
        );
        script.push_str(&body);
        script.push_str("  return \"block\"\nend\n");
        script
    }

    fn xray_condition(&mut self, condition: &Condition, names: &mut BTreeSet<String>) -> String {
        match condition {
            Condition::And(children) | Condition::Or(children) => {
                let operator = if matches!(condition, Condition::And(_)) {
                    " and "
                } else {
                    " or "
                };
                let values: Vec<_> = children
                    .iter()
                    .map(|child| self.xray_condition(child, names))
                    .collect();
                format!("({})", values.join(operator))
            }
            _ => {
                let name = self.name(condition);
                names.insert(name.to_owned());
                if name.starts_with('d') {
                    format!(
                        "(domain ~= \"\" and matchers[{}]:MatchAny(domain))",
                        lua(name)
                    )
                } else {
                    format!("matchers[{}]:AnyMatch(ips())", lua(name))
                }
            }
        }
    }
}

fn lua(value: &str) -> String {
    let mut output = String::from("\"");
    for character in value.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '"' => output.push_str("\\\""),
            c if c.is_ascii_control() => write!(output, "\\{:03}", u32::from(c)).unwrap(),
            c => output.push(c),
        }
    }
    output.push('"');
    output
}
