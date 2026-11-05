use std::{
    collections::{BTreeMap, HashSet},
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
    geodata::{Catalog, Domain, DomainType, Geoips, Sites},
    pattern,
    progress::Progress,
};

pub struct Targets {
    pub domains: Vec<(Condition, Vec<Domain>)>,
    pub ips: Vec<(Condition, Vec<IpNetwork>)>,
}

impl Targets {
    pub fn matches(&self, server: &str) -> Result<(bool, Vec<(&Condition, bool)>)> {
        let host = server.trim_start_matches('[').trim_end_matches(']');
        let address = host
            .split_once('%')
            .map_or(host, |(address, _)| address)
            .parse::<IpAddr>()
            .ok();
        let server = lowercase(server);
        let mut values = Vec::new();
        for (condition, entries) in &self.domains {
            let mut matched = false;
            if address.is_none() {
                for entry in entries {
                    matched = match DomainType::try_from(entry.kind)? {
                        DomainType::Domain => server == entry.value,
                        DomainType::Suffix => {
                            server == entry.value
                                || server
                                    .strip_suffix(&entry.value)
                                    .is_some_and(|prefix| prefix.ends_with('.'))
                        }
                        DomainType::Keyword => server.contains(&entry.value),
                        DomainType::Regex => regex_automata::meta::Regex::new(
                            &pattern::parse(&entry.value)?.to_string(),
                        )?
                        .is_match(&server),
                    };
                    if matched {
                        break;
                    }
                }
            }
            values.push((condition, matched));
        }
        if let Some(address) = address {
            values.extend(self.ips.iter().map(|(condition, networks)| {
                (
                    condition,
                    networks.iter().any(|network| network.contains(address)),
                )
            }));
        }
        Ok((address.is_none(), values))
    }

    pub fn load(
        store: &Store,
        geodata: &mut Option<u64>,
        conditions: Vec<Condition>,
        progress: &Progress,
    ) -> Result<Self> {
        let mut domains = Vec::new();
        let mut ips = Vec::new();
        let needs_sites = conditions.iter().any(|c| matches!(c, Condition::Site(_)));
        let needs_ips = conditions.iter().any(|c| matches!(c, Condition::Geoip(_)));
        let needs_asns = conditions.iter().any(|c| matches!(c, Condition::Asn(_)));
        let directory = if needs_sites || needs_ips || needs_asns {
            let catalog = Catalog::ensure(store, geodata, progress)?;
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
                Condition::Ip(network) => ips.push((condition.clone(), vec![*network])),
                Condition::Asn(number) => {
                    ips.push((condition.clone(), asns.remove(number).unwrap()));
                }
                Condition::Geoip(name) => {
                    let data = geoips
                        .iter()
                        .find(|data| data.name.eq_ignore_ascii_case(name))
                        .ok_or_else(|| format!("找不到 GeoIP 规则：{name}"))?;
                    let mut prefixes = data
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
                        .collect::<Result<Vec<_>>>()?;
                    if data.reverse {
                        prefixes = complement(&prefixes)?;
                    }
                    ips.push((condition.clone(), prefixes));
                }
                Condition::Site(name) => {
                    let mut parts = name.split('@');
                    let tag = parts.next().unwrap();
                    let attributes: Vec<_> = parts.collect();
                    let site = sites
                        .iter()
                        .find(|site| site.name.eq_ignore_ascii_case(tag))
                        .ok_or_else(|| format!("找不到 GeoSite 规则：{name}"))?;
                    let mut entries = Vec::new();
                    for entry in &site.domains {
                        progress.check()?;
                        if attributes.iter().all(|attribute| {
                            entry
                                .attributes
                                .iter()
                                .any(|item| item.key.eq_ignore_ascii_case(attribute))
                        }) {
                            let mut entry = entry.clone();
                            entry.attributes.clear();
                            if DomainType::try_from(entry.kind)? != DomainType::Regex {
                                entry.value = lowercase(&entry.value);
                            }
                            entries.push(entry);
                        }
                    }
                    domains.push((condition.clone(), entries));
                }
                _ => {
                    let (kind, value) = match &condition {
                        Condition::Domain(value) => (DomainType::Domain, value),
                        Condition::Suffix(value) => (DomainType::Suffix, value),
                        Condition::Keyword(value) => (DomainType::Keyword, value),
                        Condition::Regex(value) => (DomainType::Regex, value),
                        _ => return Err("目标条件的类型不正确".into()),
                    };
                    let entry = Domain {
                        kind: kind as i32,
                        value: if kind == DomainType::Regex {
                            value.clone()
                        } else {
                            lowercase(value)
                        },
                        attributes: Vec::new(),
                    };
                    domains.push((condition.clone(), vec![entry]));
                }
            }
        }
        step.finish(format!(
            "{} 项域名条件，{} 项 IP 条件",
            domains.len(),
            ips.len()
        ));
        Ok(Self { domains, ips })
    }

    pub fn domain_classes(&self, progress: &Progress) -> Result<BTreeMap<Vec<bool>, String>> {
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
        for (_, entries) in &self.domains {
            let expression =
                Hir::alternation(entries.iter().map(domain).collect::<Result<Vec<_>>>()?);
            patterns.push(Hir::concat(vec![
                Hir::look(Look::Start),
                any.clone(),
                expression,
                any.clone(),
                Hir::look(Look::End),
            ]));
        }
        let nfa = thompson::Compiler::new().build_many_from_hir(&patterns)?;
        let dfa = dense::Builder::new()
            .configure(
                dense::Config::new()
                    .match_kind(MatchKind::All)
                    .start_kind(StartKind::Anchored),
            )
            .build_from_nfa(&nfa)?;
        let mut bytes = HashSet::new();
        let alphabet: Vec<_> = b"abcdefghijklmnopqrstuvwxyz0123456789.-_"
            .iter()
            .copied()
            .chain(0..=u8::MAX)
            .filter(|byte| bytes.insert(dfa.byte_classes().get(*byte)))
            .collect();
        let start = dfa.start_state_forward(&Input::new(b"").anchored(Anchored::Yes))?;
        let mut visited = HashSet::from([start]);
        let mut states = vec![(start, None)];
        let mut cursor = 0;
        let mut classes = BTreeMap::from([(vec![false; patterns.len()], String::new())]);
        while cursor < states.len() {
            progress.check()?;
            let (state, _) = states[cursor];
            let end = dfa.next_eoi_state(state);
            if dfa.is_match_state(end) {
                let mut values = vec![false; patterns.len()];
                for index in 0..dfa.match_len(end) {
                    values[dfa.match_pattern(end, index).as_usize()] = true;
                }
                if values[0] && !classes.contains_key(&values) {
                    let mut text = Vec::new();
                    let mut current = cursor;
                    while let Some((parent, byte)) = states[current].1 {
                        text.push(byte);
                        current = parent;
                    }
                    text.reverse();
                    classes.insert(values, String::from_utf8(text)?);
                }
            }
            for byte in &alphabet {
                let next = dfa.next_state(state, *byte);
                if !dfa.is_dead_state(next) && visited.insert(next) {
                    states.push((next, Some((cursor, *byte))));
                }
            }
            cursor += 1;
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

    pub fn ip_classes(&self, progress: &Progress) -> Result<BTreeMap<Vec<bool>, IpAddr>> {
        let step = progress.activity("分析 IP 条件");
        let mut classes = BTreeMap::new();
        for ipv6 in [false, true] {
            let maximum = if ipv6 {
                u128::MAX
            } else {
                u128::from(u32::MAX)
            };
            let mut events: BTreeMap<u128, Vec<(usize, bool)>> = BTreeMap::new();
            events.entry(0).or_default();
            for (index, (_, networks)) in self.ips.iter().enumerate() {
                for prefix in networks {
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
            for (&address, changes) in &events {
                progress.check()?;
                for &(index, entering) in changes {
                    if entering {
                        counts[index] += 1;
                    } else {
                        counts[index] -= 1;
                    }
                }
                classes
                    .entry(counts.iter().map(|&count| count != 0).collect())
                    .or_insert_with(|| {
                        if ipv6 {
                            IpAddr::V6(Ipv6Addr::from(address))
                        } else {
                            IpAddr::V4(Ipv4Addr::from(address as u32))
                        }
                    });
            }
        }
        step.finish(format!("{} 种匹配组合", classes.len()));
        Ok(classes)
    }
}

fn domain(entry: &Domain) -> Result<Hir> {
    let literal = || Hir::literal(entry.value.as_bytes());
    Ok(match DomainType::try_from(entry.kind)? {
        DomainType::Domain => Hir::concat(vec![
            Hir::look(Look::Start),
            literal(),
            Hir::look(Look::End),
        ]),
        DomainType::Suffix => Hir::concat(vec![
            Hir::alternation(vec![Hir::look(Look::Start), Hir::literal(*b".")]),
            literal(),
            Hir::look(Look::End),
        ]),
        DomainType::Keyword => literal(),
        DomainType::Regex => pattern::parse(&entry.value)?,
    })
}

fn lowercase(value: &str) -> String {
    value
        .chars()
        .map(|c| c.to_lowercase().next().unwrap())
        .collect()
}

fn complement(prefixes: &[IpNetwork]) -> Result<Vec<IpNetwork>> {
    let mut result = Vec::new();
    for ipv6 in [false, true] {
        let maximum = if ipv6 {
            u128::MAX
        } else {
            u128::from(u32::MAX)
        };
        let mut ranges: Vec<_> = prefixes
            .iter()
            .filter_map(|prefix| match prefix {
                IpNetwork::V4(network) if !ipv6 => Some((
                    u128::from(u32::from(network.network())),
                    u128::from(u32::from(network.broadcast())),
                )),
                IpNetwork::V6(network) if ipv6 => Some((
                    u128::from(network.network()),
                    u128::from(network.broadcast()),
                )),
                _ => None,
            })
            .collect();
        ranges.sort_unstable();
        let mut cursor = Some(0);
        let mut gaps = Vec::new();
        for (first, last) in ranges {
            let Some(next) = cursor else { break };
            if first > next {
                gaps.push((next, first - 1));
            }
            if last >= next {
                cursor = last.checked_add(1);
            }
        }
        if let Some(next) = cursor.filter(|next| *next <= maximum) {
            gaps.push((next, maximum));
        }
        let bits = if ipv6 { 128 } else { 32 };
        for (mut first, last) in gaps {
            loop {
                let remaining = match (last - first).checked_add(1) {
                    Some(length) => length.ilog2(),
                    None => 128,
                };
                let size = first.trailing_zeros().min(bits).min(remaining);
                let address = if ipv6 {
                    IpAddr::V6(Ipv6Addr::from(first))
                } else {
                    IpAddr::V4(Ipv4Addr::from(u32::try_from(first)?))
                };
                result.push(IpNetwork::new(address, (bits - size).try_into()?)?);
                if size == 128 {
                    break;
                }
                let Some(next) = first
                    .checked_add(1u128 << size)
                    .filter(|next| *next <= last)
                else {
                    break;
                };
                first = next;
            }
        }
    }
    Ok(result)
}

static LOWERCASE: LazyLock<Hir> = LazyLock::new(|| {
    let ranges = (0..=u32::from(char::MAX))
        .filter_map(char::from_u32)
        .filter(|c| c.to_lowercase().next() == Some(*c))
        .map(|c| ClassUnicodeRange::new(c, c));
    Hir::class(Class::Unicode(ClassUnicode::new(ranges)))
});
