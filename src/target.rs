use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::LazyLock,
};

use ipnetwork::IpNetwork;
use maxminddb::{Reader, geoip2};
use prost::Message;
use regex_automata::{
    Anchored, Input, MatchKind,
    dfa::{Automaton, StartKind, dense},
    nfa::thompson,
};
use regex_syntax::hir::{Class, ClassUnicode, ClassUnicodeRange, Hir, Look, Repetition};

use crate::{
    Result,
    condition::Condition,
    config::Store,
    geodata::{Catalog, DomainType, Geoips, Sites},
    pattern,
    progress::Progress,
};

pub struct Targets {
    pub domains: Vec<(Condition, Hir)>,
    pub ips: Vec<(Condition, Networks)>,
}

pub struct Networks {
    pub prefixes: Vec<IpNetwork>,
    pub reverse: bool,
}

impl Targets {
    pub fn load(store: &Store, conditions: Vec<Condition>, progress: &Progress) -> Result<Self> {
        let mut domains = Vec::new();
        let mut ips = Vec::new();
        let needs_sites = conditions.iter().any(|c| matches!(c, Condition::Site(_)));
        let needs_ips = conditions.iter().any(|c| matches!(c, Condition::Geoip(_)));
        let needs_asns = conditions.iter().any(|c| matches!(c, Condition::Asn(_)));
        let directory = if needs_sites || needs_ips || needs_asns {
            let catalog = match Catalog::load(store)? {
                Some(catalog) => catalog,
                None => Catalog::update(store, progress)?,
            };
            Some(catalog.directory(store))
        } else {
            None
        };
        let step = progress.activity("读取规则数据");
        let sites = if needs_sites {
            step.detail("geosite.dat");
            Sites::decode(fs::read(directory.as_ref().unwrap().join("geosite.dat"))?.as_slice())?
                .entries
        } else {
            Vec::new()
        };
        progress.check()?;
        let geoips = if needs_ips {
            step.detail("geoip.dat");
            Geoips::decode(fs::read(directory.as_ref().unwrap().join("geoip.dat"))?.as_slice())?
                .entries
        } else {
            Vec::new()
        };
        let mut asns: BTreeMap<u32, Vec<IpNetwork>> = conditions
            .iter()
            .filter_map(|c| match c {
                Condition::Asn(number) => Some((*number, Vec::new())),
                _ => None,
            })
            .collect();
        if needs_asns {
            step.detail("GeoLite2-ASN.mmdb");
            let reader =
                Reader::open_readfile(directory.as_ref().unwrap().join("GeoLite2-ASN.mmdb"))?;
            for record in reader.networks(Default::default())? {
                progress.check()?;
                let record = record?;
                if let Some(asn) = record.decode::<geoip2::Asn>()?
                    && let Some(networks) =
                        asns.get_mut(&asn.autonomous_system_number.unwrap_or_default())
                {
                    networks.push(record.network()?);
                }
            }
        }
        for condition in conditions {
            progress.check()?;
            match &condition {
                Condition::Ip(network) => ips.push((
                    condition.clone(),
                    Networks {
                        prefixes: vec![*network],
                        reverse: false,
                    },
                )),
                Condition::Asn(number) => {
                    ips.push((
                        condition.clone(),
                        Networks {
                            prefixes: asns.remove(number).unwrap(),
                            reverse: false,
                        },
                    ));
                }
                Condition::Geoip(name) => {
                    let data = geoips
                        .iter()
                        .find(|data| data.name.eq_ignore_ascii_case(name))
                        .ok_or_else(|| format!("找不到 GeoIP 规则：{name}"))?;
                    let prefixes = data
                        .networks
                        .iter()
                        .map(|cidr| {
                            let address = match cidr.ip.as_slice() {
                                [a, b, c, d] => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
                                bytes if bytes.len() == 16 => {
                                    IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes)?))
                                }
                                _ => return Err(format!("GeoIP 地址长度不正确：{name}").into()),
                            };
                            Ok(IpNetwork::new(address, cidr.prefix.try_into()?)?)
                        })
                        .collect::<Result<_>>()?;
                    ips.push((
                        condition.clone(),
                        Networks {
                            prefixes,
                            reverse: data.reverse,
                        },
                    ));
                }
                Condition::Site(name) => {
                    let mut parts = name.split('@');
                    let tag = parts.next().unwrap();
                    let attributes: Vec<_> = parts.collect();
                    let site = sites
                        .iter()
                        .find(|site| site.name.eq_ignore_ascii_case(tag))
                        .ok_or_else(|| format!("找不到 GeoSite 规则：{name}"))?;
                    let mut expressions = Vec::new();
                    for entry in &site.domains {
                        progress.check()?;
                        if attributes.iter().all(|attribute| {
                            entry
                                .attributes
                                .iter()
                                .any(|item| item.key.eq_ignore_ascii_case(attribute))
                        }) {
                            let value = match DomainType::try_from(entry.kind)? {
                                DomainType::Keyword => Condition::Keyword(entry.value.clone()),
                                DomainType::Regex => Condition::Regex(entry.value.clone()),
                                DomainType::Suffix => Condition::Suffix(entry.value.clone()),
                                DomainType::Domain => Condition::Domain(entry.value.clone()),
                            };
                            expressions.push(domain(&value)?);
                        }
                    }
                    domains.push((condition.clone(), Hir::alternation(expressions)));
                }
                _ => domains.push((condition.clone(), domain(&condition)?)),
            }
        }
        step.finish(format!(
            "{} 项域名条件，{} 项 IP 条件",
            domains.len(),
            ips.len()
        ));
        Ok(Self { domains, ips })
    }

    pub fn domain_classes(&self, progress: &Progress) -> Result<BTreeSet<Vec<bool>>> {
        let step = progress.activity("分析域名条件");
        let mut patterns = vec![Hir::concat(vec![
            Hir::look(Look::Start),
            Hir::repetition(Repetition {
                min: 1,
                max: None,
                greedy: true,
                sub: Box::new(LOWERCASE.clone()),
            }),
            Hir::look(Look::End),
        ])];
        let any = Hir::repetition(Repetition {
            min: 0,
            max: None,
            greedy: true,
            sub: Box::new(Hir::class(Class::Unicode(ClassUnicode::new([
                ClassUnicodeRange::new(char::MIN, char::MAX),
            ])))),
        });
        patterns.extend(self.domains.iter().map(|(_, expression)| {
            Hir::concat(vec![
                Hir::look(Look::Start),
                any.clone(),
                expression.clone(),
                any.clone(),
                Hir::look(Look::End),
            ])
        }));
        let nfa = thompson::Compiler::new().build_many_from_hir(&patterns)?;
        let dfa = dense::Builder::new()
            .configure(
                dense::Config::new()
                    .match_kind(MatchKind::All)
                    .start_kind(StartKind::Anchored),
            )
            .build_from_nfa(&nfa)?;
        let alphabet: Vec<_> = dfa
            .byte_classes()
            .representatives(..)
            .filter_map(|unit| unit.as_u8())
            .collect();
        let start = dfa.start_state_forward(&Input::new(b"").anchored(Anchored::Yes))?;
        let mut visited = HashSet::from([start]);
        let mut pending = vec![start];
        let mut classes = BTreeSet::from([vec![false; patterns.len()]]);
        while let Some(state) = pending.pop() {
            progress.check()?;
            let end = dfa.next_eoi_state(state);
            if dfa.is_match_state(end) {
                let mut values = vec![false; patterns.len()];
                for index in 0..dfa.match_len(end) {
                    values[dfa.match_pattern(end, index).as_usize()] = true;
                }
                if values[0] {
                    classes.insert(values);
                }
            }
            for byte in &alphabet {
                let next = dfa.next_state(state, *byte);
                if !dfa.is_dead_state(next) && visited.insert(next) {
                    pending.push(next);
                }
            }
            if step.sample() {
                step.detail(format!(
                    "{} 个状态，{} 种匹配组合",
                    visited.len(),
                    classes.len()
                ));
            }
        }
        step.finish(format!("{} 种匹配组合", classes.len()));
        Ok(classes)
    }

    pub fn ip_classes(&self, progress: &Progress) -> Result<BTreeSet<Vec<bool>>> {
        let step = progress.activity("分析 IP 条件");
        let mut classes = BTreeSet::new();
        for ipv6 in [false, true] {
            let maximum = if ipv6 {
                u128::MAX
            } else {
                u128::from(u32::MAX)
            };
            let mut events: BTreeMap<u128, Vec<(usize, bool)>> = BTreeMap::new();
            events.entry(0).or_default();
            for (index, (_, networks)) in self.ips.iter().enumerate() {
                for prefix in &networks.prefixes {
                    progress.check()?;
                    let (low, high) = match prefix {
                        IpNetwork::V4(network) if !ipv6 => (
                            u128::from(u32::from(network.network())),
                            u128::from(u32::from(network.broadcast())),
                        ),
                        IpNetwork::V6(network) if ipv6 => (
                            u128::from(network.network()),
                            u128::from(network.broadcast()),
                        ),
                        _ => continue,
                    };
                    events.entry(low).or_default().push((index, true));
                    if high < maximum {
                        events.entry(high + 1).or_default().push((index, false));
                    }
                }
            }
            let mut counts = vec![0usize; self.ips.len()];
            for changes in events.values() {
                progress.check()?;
                for &(index, entering) in changes {
                    if entering {
                        counts[index] += 1;
                    } else {
                        counts[index] -= 1;
                    }
                }
                classes.insert(
                    counts
                        .iter()
                        .zip(&self.ips)
                        .map(|(&count, (_, networks))| (count != 0) != networks.reverse)
                        .collect(),
                );
            }
        }
        step.finish(format!("{} 种匹配组合", classes.len()));
        Ok(classes)
    }
}

fn domain(condition: &Condition) -> Result<Hir> {
    let literal = |value: &str| {
        Hir::literal(
            value
                .chars()
                .map(|c| c.to_lowercase().next().unwrap())
                .collect::<String>()
                .into_bytes(),
        )
    };
    Ok(match condition {
        Condition::Domain(value) => Hir::concat(vec![
            Hir::look(Look::Start),
            literal(value),
            Hir::look(Look::End),
        ]),
        Condition::Suffix(value) => Hir::concat(vec![
            Hir::alternation(vec![Hir::look(Look::Start), Hir::literal(*b".")]),
            literal(value),
            Hir::look(Look::End),
        ]),
        Condition::Keyword(value) => literal(value),
        Condition::Regex(value) => pattern::parse(value)?,
        _ => return Err("域名条件的类型不正确".into()),
    })
}

static LOWERCASE: LazyLock<Hir> = LazyLock::new(|| {
    let ranges = (0..=u32::from(char::MAX))
        .filter_map(char::from_u32)
        .filter(|c| c.to_lowercase().next() == Some(*c))
        .map(|c| ClassUnicodeRange::new(c, c));
    Hir::class(Class::Unicode(ClassUnicode::new(ranges)))
});
