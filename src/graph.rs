use std::collections::{HashMap, HashSet};

use uuid::Uuid;
use varisat::{ExtendFormula, Lit, Solver};

use crate::{
    Result,
    condition::Condition,
    config::{Config, Store},
    inbound::{Core, Inbound, Protocol},
    progress::Progress,
    route::{Destination, Rule},
    target::Targets,
    user::User,
};

pub struct Graph<'a> {
    pub targets: Targets,
    pub entries: Vec<Entry<'a>>,
    analysis: Analysis<'a>,
}

pub struct Entry<'a> {
    pub inbound: &'a Inbound,
    pub users: Vec<&'a User>,
    pub accounts: Vec<Account<'a>>,
}

pub struct Account<'a> {
    pub user: Option<&'a User>,
    pub network: Network,
    pub rules: Vec<Rule>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Payload {
    Proxy,
    Connection,
}

impl From<&Protocol> for Payload {
    fn from(value: &Protocol) -> Self {
        match value {
            Protocol::Forward(_) => Self::Connection,
            _ => Self::Proxy,
        }
    }
}

impl Account<'_> {
    pub fn identity(&self, inbound: &Inbound) -> Option<Uuid> {
        self.user.map(|user| user.uuid).or_else(|| {
            self.network
                .identity(inbound)
                .then(|| {
                    inbound
                        .credentials
                        .as_ref()
                        .map(|credentials| credentials.uuid)
                })
                .flatten()
        })
    }
}

impl Graph<'_> {
    pub fn config(&self) -> &Config {
        self.analysis.config
    }

    pub fn equivalent(
        &mut self,
        left: usize,
        right: usize,
        network: Network,
        left_identity: Option<Uuid>,
        right_identity: Option<Uuid>,
    ) -> Result<bool> {
        let mut outcomes = Vec::new();
        for (index, identity) in [(left, left_identity), (right, right_identity)] {
            let entry = &self.entries[index];
            let rules = entry
                .accounts
                .iter()
                .find(|account| {
                    account.network == network && account.identity(entry.inbound) == identity
                })
                .map_or(&[][..], |account| account.rules.as_slice());
            let mut remaining = self.analysis.truth;
            let mut clauses: HashMap<Destination, Vec<Lit>> = HashMap::new();
            for rule in rules {
                let condition = self
                    .analysis
                    .condition(&rule.condition, entry.inbound, identity);
                let selected = self.analysis.all(&[remaining, condition]);
                remaining = self.analysis.all(&[remaining, !condition]);
                if rule.destination != Destination::Block {
                    clauses.entry(rule.destination).or_default().push(selected);
                }
            }
            outcomes.push(
                clauses
                    .into_iter()
                    .map(|(destination, conditions)| (destination, self.analysis.any(&conditions)))
                    .collect::<HashMap<_, _>>(),
            );
        }
        let destinations: HashSet<_> = outcomes.iter().flat_map(HashMap::keys).copied().collect();
        for destination in destinations {
            let before = *outcomes[0]
                .get(&destination)
                .unwrap_or(&!self.analysis.truth);
            let after = *outcomes[1]
                .get(&destination)
                .unwrap_or(&!self.analysis.truth);
            let added = self.analysis.all(&[!before, after]);
            let removed = self.analysis.all(&[before, !after]);
            let difference = self.analysis.any(&[added, removed]);
            if self
                .analysis
                .possible(difference, self.entries[left].inbound.core)?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Network {
    Tcp,
    Udp,
}

impl Network {
    pub fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    pub fn identity(self, inbound: &Inbound) -> bool {
        !(self == Self::Udp
            && inbound.core == Core::Mihomo
            && matches!(inbound.protocol, Protocol::Mixed(_)))
            && !matches!(&inbound.protocol, Protocol::Shadowsocks(value) if value.cipher == crate::shadowsocks::Cipher::None)
            && inbound.protocol.users()
    }

    pub fn enabled(self, inbound: &Inbound) -> bool {
        match (self, &inbound.protocol) {
            (Self::Tcp, Protocol::Shadowsocks(value)) => value.tcp,
            (Self::Tcp, Protocol::Forward(value)) => value.tcp,
            (Self::Tcp, _) => true,
            (Self::Udp, Protocol::Mixed(value)) => {
                value.udp
                    && (value.socks.enabled || value.http.enabled && inbound.core == Core::SingBox)
            }
            (Self::Udp, Protocol::Vless(_) | Protocol::Vmess(_) | Protocol::Trojan(_)) => true,
            (Self::Udp, Protocol::Shadowsocks(value)) => value.tcp || value.udp,
            (Self::Udp, Protocol::Forward(value)) => value.udp,
        }
    }
}

pub fn build<'a>(
    store: &Store,
    config: &'a Config,
    progress: &'a Progress,
    mut reachable: impl FnMut(Core, Destination, Network, Payload) -> Result<bool>,
) -> Result<Option<Graph<'a>>> {
    if config.inbounds.is_empty()
        || config.users.is_empty()
            && config
                .inbounds
                .iter()
                .all(|inbound| inbound.users && inbound.protocol.users())
    {
        return Ok(None);
    }
    let mut conditions = Vec::new();
    let mut seen = HashSet::new();
    let mut pending: Vec<_> = if config.inbounds.iter().any(|inbound| {
        Payload::from(&inbound.protocol) == Payload::Proxy
            && (!inbound.users || !config.users.is_empty())
    }) {
        config.rules.iter().collect()
    } else {
        Vec::new()
    };
    while let Some(rule) = pending.pop() {
        collect(&rule.condition, &mut conditions, &mut seen);
        pending.extend(&rule.children);
    }
    let targets = Targets::load(store, conditions, progress)?;
    let mut graph = Analysis::new(&targets, config, progress)?;
    let step = progress.activity("分析分流");
    let mut entries = Vec::new();
    for inbound in &config.inbounds {
        progress.check()?;
        step.detail(&inbound.name);
        if !graph.enabled(inbound, &mut reachable)? {
            continue;
        }
        let mut accounts = Vec::new();
        let mut users = HashSet::new();
        for network in [Network::Tcp, Network::Udp] {
            if !network.enabled(inbound) {
                continue;
            }
            if inbound.users && inbound.protocol.users() {
                for user in &config.users {
                    let routes = graph.routes(inbound, Some(user.uuid), network, &mut reachable)?;
                    if let Some(route) = routes
                        .iter()
                        .find(|route| route.destination != Destination::Block)
                    {
                        if !network.identity(inbound) {
                            return Err(format!(
                                "入站 {} 的 {} 接收器未验证凭据，规则 {} 要求提供用户 {} 的接入",
                                inbound.name,
                                network.name().to_uppercase(),
                                location(&route.path),
                                user.name,
                            )
                            .into());
                        }
                        users.insert(user.uuid);
                        accounts.push(Account {
                            user: Some(user),
                            network,
                            rules: materialize(routes, config, inbound, Some(user.uuid)),
                        });
                    }
                }
            } else {
                let anonymous = graph.routes(inbound, None, network, &mut reachable)?;
                if inbound.credentials.is_some()
                    && inbound.protocol.users()
                    && !network.identity(inbound)
                    && anonymous
                        .iter()
                        .any(|route| route.destination != Destination::Block)
                {
                    return Err(format!(
                        "入站 {} 的 {} 接收器不验证入口凭据",
                        inbound.name,
                        network.name().to_uppercase()
                    )
                    .into());
                }
                for user in config
                    .users
                    .iter()
                    .filter(|_| inbound.protocol.destination().is_none())
                {
                    let authenticated =
                        graph.routes(inbound, Some(user.uuid), network, &mut reachable)?;
                    let destinations: HashSet<_> = anonymous
                        .iter()
                        .chain(&authenticated)
                        .map(|route| route.destination)
                        .filter(|destination| *destination != Destination::Block)
                        .collect();
                    for destination in destinations {
                        let before = graph.outcome(&anonymous, destination);
                        let after = graph.outcome(&authenticated, destination);
                        let added = graph.all(&[!before, after]);
                        let removed = graph.all(&[before, !after]);
                        let changed = graph.any(&[added, removed]);
                        if graph.possible(changed, inbound.core)? {
                            for route in anonymous.iter().chain(&authenticated) {
                                let affected = graph.all(&[route.condition, changed]);
                                if route.destination == destination
                                    && graph.possible(affected, inbound.core)?
                                {
                                    return Err(format!(
                                        "入站 {} 的 {} 流量未提供用户身份，分流规则 {} 的结果依赖用户 {}",
                                        inbound.name, network.name().to_uppercase(), location(&route.path), user.name,
                                    ).into());
                                }
                            }
                        }
                    }
                }
                if anonymous
                    .iter()
                    .any(|route| route.destination != Destination::Block)
                {
                    accounts.push(Account {
                        user: None,
                        network,
                        rules: materialize(anonymous, config, inbound, None),
                    });
                }
            }
        }
        if !accounts.is_empty() {
            entries.push(Entry {
                inbound,
                users: config
                    .users
                    .iter()
                    .filter(|user| users.contains(&user.uuid))
                    .collect(),
                accounts,
            });
        }
    }
    step.finish(format!("{} 个入口具有可转发路径", entries.len()));
    Ok((!entries.is_empty()).then_some(Graph {
        targets,
        entries,
        analysis: graph,
    }))
}

struct Route {
    path: Vec<usize>,
    condition: Lit,
    destination: Destination,
}

struct Analysis<'a> {
    solver: Solver<'static>,
    truth: Lit,
    single: Lit,
    variables: HashMap<Condition, Lit>,
    paths: HashMap<(Uuid, Network), bool>,
    config: &'a Config,
    progress: &'a Progress,
}

impl<'a> Analysis<'a> {
    fn new(targets: &Targets, config: &'a Config, progress: &'a Progress) -> Result<Self> {
        let mut solver = Solver::new();
        let truth = solver.new_lit();
        solver.add_clause(&[truth]);
        let single = solver.new_lit();
        let present = solver.new_lit();
        let mut variables = HashMap::new();
        let mut domains = vec![present];
        for (condition, _) in &targets.domains {
            let variable = solver.new_lit();
            variables.insert(condition.clone(), variable);
            domains.push(variable);
        }
        let mut cases = Vec::new();
        for values in targets.domain_classes(progress)? {
            let selected = solver.new_lit();
            cases.push(selected);
            for (&variable, value) in domains.iter().zip(values) {
                solver.add_clause(&[!selected, if value { variable } else { !variable }]);
            }
        }
        solver.add_clause(&cases);

        let mut ips = Vec::new();
        for (condition, _) in &targets.ips {
            let variable = solver.new_lit();
            variables.insert(condition.clone(), variable);
            ips.push(variable);
        }
        let classes = targets.ip_classes(progress)?;
        let width = usize::BITS - (classes.len() - 1).leading_zeros();
        let address: Vec<_> = (0..width).map(|_| solver.new_lit()).collect();
        let mut witnesses = vec![Vec::new(); ips.len()];
        let mut available = vec![present];
        for (index, values) in classes.into_iter().enumerate() {
            progress.check()?;
            let selected = solver.new_lit();
            available.push(selected);
            for (bit, &variable) in address.iter().enumerate() {
                let value = if index & (1 << bit) != 0 {
                    variable
                } else {
                    !variable
                };
                solver.add_clause(&[!single, !selected, value]);
                solver.add_clause(&[present, !selected, value]);
            }
            for (index, value) in values.into_iter().enumerate() {
                if value {
                    solver.add_clause(&[!selected, ips[index]]);
                    witnesses[index].push(selected);
                }
            }
        }
        solver.add_clause(&available);
        for (variable, mut witnesses) in ips.into_iter().zip(witnesses) {
            witnesses.push(!variable);
            solver.add_clause(&witnesses);
        }
        Ok(Self {
            solver,
            truth,
            single,
            variables,
            paths: HashMap::new(),
            config,
            progress,
        })
    }

    fn all(&mut self, values: &[Lit]) -> Lit {
        let values: Vec<_> = values
            .iter()
            .copied()
            .filter(|value| *value != self.truth)
            .collect();
        if values.contains(&!self.truth) {
            return !self.truth;
        }
        match values.as_slice() {
            [] => self.truth,
            [value] => *value,
            _ => {
                let result = self.solver.new_lit();
                for &value in &values {
                    self.solver.add_clause(&[!result, value]);
                }
                let mut clause: Vec<_> = values.iter().map(|value| !*value).collect();
                clause.push(result);
                self.solver.add_clause(&clause);
                result
            }
        }
    }

    fn any(&mut self, values: &[Lit]) -> Lit {
        let negated: Vec<_> = values.iter().map(|value| !*value).collect();
        !self.all(&negated)
    }

    fn condition(&mut self, condition: &Condition, inbound: &Inbound, user: Option<Uuid>) -> Lit {
        match condition {
            Condition::Always => self.truth,
            Condition::Never => !self.truth,
            Condition::User(uuid) => {
                if Some(*uuid) == user {
                    self.truth
                } else {
                    !self.truth
                }
            }
            Condition::Inbound(uuid) => {
                if *uuid == inbound.uuid {
                    self.truth
                } else {
                    !self.truth
                }
            }
            Condition::And(children) => {
                let values: Vec<_> = children
                    .iter()
                    .map(|c| self.condition(c, inbound, user))
                    .collect();
                self.all(&values)
            }
            Condition::Or(children) => {
                let values: Vec<_> = children
                    .iter()
                    .map(|c| self.condition(c, inbound, user))
                    .collect();
                self.any(&values)
            }
            _ if Payload::from(&inbound.protocol) != Payload::Proxy => !self.truth,
            _ => self.variables[condition],
        }
    }

    fn flatten(
        &mut self,
        rules: &[Rule],
        parent: Lit,
        inbound: &Inbound,
        user: Option<Uuid>,
        path: &mut Vec<usize>,
        routes: &mut Vec<Route>,
    ) {
        for (index, rule) in rules.iter().enumerate() {
            path.push(index);
            let condition = self.condition(&rule.condition, inbound, user);
            let condition = self.all(&[parent, condition]);
            self.flatten(&rule.children, condition, inbound, user, path, routes);
            routes.push(Route {
                path: path.clone(),
                condition,
                destination: rule.destination,
            });
            path.pop();
        }
    }

    fn routes(
        &mut self,
        inbound: &Inbound,
        user: Option<Uuid>,
        network: Network,
        reachable_destination: &mut impl FnMut(Core, Destination, Network, Payload) -> Result<bool>,
    ) -> Result<Vec<Route>> {
        let mut routes = self.resolve(inbound, user, network, reachable_destination)?;
        for route in &mut routes {
            if let Destination::Inbound(uuid) = route.destination
                && !self.reaches(uuid, network, reachable_destination)?
            {
                route.destination = Destination::Block;
            }
        }
        Ok(routes)
    }

    fn resolve(
        &mut self,
        inbound: &Inbound,
        user: Option<Uuid>,
        network: Network,
        reachable_destination: &mut impl FnMut(Core, Destination, Network, Payload) -> Result<bool>,
    ) -> Result<Vec<Route>> {
        if let Some(destination) = inbound.protocol.destination() {
            return Ok(
                if reachable_destination(
                    inbound.core,
                    destination,
                    network,
                    Payload::from(&inbound.protocol),
                )? {
                    vec![Route {
                        condition: self.truth,
                        destination,
                        path: Vec::new(),
                    }]
                } else {
                    Vec::new()
                },
            );
        }
        let mut routes = Vec::new();
        self.flatten(
            &self.config.rules,
            self.truth,
            inbound,
            user,
            &mut Vec::new(),
            &mut routes,
        );
        let mut remaining = self.truth;
        let mut reachable = Vec::new();
        for mut route in routes {
            let condition = self.all(&[remaining, route.condition]);
            remaining = self.all(&[remaining, !route.condition]);
            if self.possible(condition, inbound.core)? {
                if let Destination::Outbound(uuid) = route.destination
                    && !self
                        .config
                        .outbounds
                        .iter()
                        .any(|outbound| outbound.uuid == uuid)
                {
                    return Err(format!(
                        "分流规则 {} 指向不存在的出站：{uuid}",
                        location(&route.path),
                    )
                    .into());
                }
                if let Destination::Inbound(uuid) = route.destination {
                    if !self.config.inbounds.iter().any(|value| value.uuid == uuid) {
                        return Err(format!(
                            "分流规则 {} 指向不存在的入站：{uuid}",
                            location(&route.path)
                        )
                        .into());
                    }
                } else if !reachable_destination(
                    inbound.core,
                    route.destination,
                    network,
                    Payload::from(&inbound.protocol),
                )? {
                    route.destination = Destination::Block;
                }
                route.condition = condition;
                reachable.push(route);
            }
        }
        Ok(reachable)
    }

    fn reaches(
        &mut self,
        uuid: Uuid,
        network: Network,
        reachable: &mut impl FnMut(Core, Destination, Network, Payload) -> Result<bool>,
    ) -> Result<bool> {
        if let Some(&result) = self.paths.get(&(uuid, network)) {
            return Ok(result);
        }
        let mut pending = vec![(uuid, network)];
        let mut seen = HashSet::new();
        let mut result = false;
        'search: while let Some((uuid, wire)) = pending.pop() {
            self.progress.check()?;
            if !seen.insert((uuid, wire)) {
                continue;
            }
            let inbound = self
                .config
                .inbounds
                .iter()
                .find(|value| value.uuid == uuid)
                .ok_or_else(|| format!("找不到入站：{uuid}"))?;
            if !self.enabled(inbound, reachable)? {
                continue;
            }
            let users: Vec<_> = if inbound.users && inbound.protocol.users() {
                self.config
                    .users
                    .iter()
                    .map(|user| Some(user.uuid))
                    .collect()
            } else {
                vec![None]
            };
            for network in [Network::Tcp, Network::Udp] {
                if !network.enabled(inbound)
                    || !crate::native::listener::accepts(inbound, wire, network)
                {
                    continue;
                }
                for &user in &users {
                    for route in self.resolve(inbound, user, network, reachable)? {
                        match route.destination {
                            Destination::Block => {}
                            Destination::Inbound(uuid) => pending.push((uuid, network)),
                            Destination::Direct | Destination::Outbound(_) => {
                                result = true;
                                break 'search;
                            }
                        }
                    }
                }
            }
        }
        self.paths.insert((uuid, network), result);
        Ok(result)
    }

    fn enabled(
        &self,
        inbound: &Inbound,
        reachable: &mut impl FnMut(Core, Destination, Network, Payload) -> Result<bool>,
    ) -> Result<bool> {
        if inbound.users && self.config.users.is_empty() && inbound.protocol.users() {
            return Ok(false);
        }
        if inbound.tls.enabled && inbound.tls.reality.enabled {
            match inbound.tls.reality.outbound {
                Destination::Block | Destination::Inbound(_) => return Ok(false),
                Destination::Outbound(uuid)
                    if !self
                        .config
                        .outbounds
                        .iter()
                        .any(|outbound| outbound.uuid == uuid)
                        || !reachable(
                            inbound.core,
                            Destination::Outbound(uuid),
                            Network::Tcp,
                            Payload::Proxy,
                        )? =>
                {
                    return Ok(false);
                }
                _ => {}
            }
        }
        Ok(
            !matches!(&inbound.protocol, Protocol::Mixed(protocol) if !protocol.http.enabled && !protocol.socks.enabled),
        )
    }

    fn outcome(&mut self, routes: &[Route], destination: Destination) -> Lit {
        let conditions: Vec<_> = routes
            .iter()
            .filter(|route| route.destination == destination)
            .map(|route| route.condition)
            .collect();
        self.any(&conditions)
    }

    fn possible(&mut self, condition: Lit, core: Core) -> Result<bool> {
        self.progress.check()?;
        let single = if core == Core::Mihomo {
            self.single
        } else {
            !self.single
        };
        self.solver.assume(&[single, condition]);
        let result = self.solver.solve()?;
        self.progress.check()?;
        Ok(result)
    }
}

fn materialize(
    routes: Vec<Route>,
    config: &Config,
    inbound: &Inbound,
    user: Option<Uuid>,
) -> Vec<Rule> {
    routes
        .into_iter()
        .map(|route| {
            let mut rules = &config.rules;
            let mut conditions = Vec::new();
            for index in route.path {
                let rule = &rules[index];
                conditions.push(rule.condition.scoped(inbound, user));
                rules = &rule.children;
            }
            Rule {
                condition: Condition::combine(true, conditions),
                destination: route.destination,
                children: Vec::new(),
            }
        })
        .collect()
}

fn collect(condition: &Condition, conditions: &mut Vec<Condition>, seen: &mut HashSet<Condition>) {
    match condition {
        Condition::And(children) | Condition::Or(children) => {
            for child in children {
                collect(child, conditions, seen);
            }
        }
        Condition::Always | Condition::Never | Condition::User(_) | Condition::Inbound(_) => {}
        _ if seen.insert(condition.clone()) => conditions.push(condition.clone()),
        _ => {}
    }
}

fn location(path: &[usize]) -> String {
    path.iter()
        .map(|index| (index + 1).to_string())
        .collect::<Vec<_>>()
        .join(".")
}
