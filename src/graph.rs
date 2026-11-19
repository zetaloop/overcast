use std::collections::{BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use varisat::{ExtendFormula, Lit, Solver};

use crate::{
    Result,
    condition::Condition,
    config::{Config, Store},
    endpoint::Endpoint,
    inbound::{Core, Inbound, Protocol},
    progress::Progress,
    route::{Destination, Rule},
    target::Targets,
    user::User,
};

#[derive(Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Coverage {
    pub reached: BTreeSet<Vec<usize>>,
    pub remainder: bool,
}

pub struct Graph<'a> {
    pub targets: Targets,
    pub entries: Vec<Entry<'a>>,
    analysis: Analysis<'a>,
}

pub struct Entry<'a> {
    pub inbound: &'a Inbound,
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

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Layer {
    Transport,
    Protocol,
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
        inbound.account(self.user).map(|(id, _)| id)
    }
}

impl Graph<'_> {
    pub fn reaches(
        &mut self,
        uuid: Uuid,
        network: Network,
        layer: Layer,
        mut reachable: impl FnMut(Core, Destination, Network, Payload) -> Result<bool>,
    ) -> Result<bool> {
        self.analysis.reaches(uuid, network, layer, &mut reachable)
    }

    pub fn config(&self) -> &Config {
        self.analysis.config
    }

    pub fn addresses(
        &mut self,
        index: usize,
        user: Option<Uuid>,
        network: Network,
        destination: Destination,
        server: &str,
    ) -> Result<Vec<String>> {
        if !server.is_empty() && self.allows(index, user, network, destination, server)? {
            return Ok(vec![server.to_owned()]);
        }
        let mut values = Vec::new();
        for candidate in self.analysis.addresses.clone() {
            if self.allows(index, user, network, destination, &candidate)? {
                values.push(candidate);
            }
        }
        Ok(values)
    }

    fn allows(
        &mut self,
        index: usize,
        user: Option<Uuid>,
        network: Network,
        destination: Destination,
        server: &str,
    ) -> Result<bool> {
        let entry = &self.entries[index];
        let Some(account) = entry.accounts.iter().find(|account| {
            account.user.map(|user| user.uuid) == user && account.network == network
        }) else {
            return Ok(false);
        };
        let mut selected = Vec::new();
        let mut remaining = self.analysis.truth;
        for rule in &account.rules {
            let condition = self
                .analysis
                .condition(&rule.condition, entry.inbound, user);
            if rule.destination == destination {
                selected.push(self.analysis.all(&[remaining, condition]));
            }
            remaining = self.analysis.all(&[remaining, !condition]);
        }
        let routes = self.analysis.any(&selected);
        let mut values = vec![routes];
        if Payload::from(&entry.inbound.protocol) == Payload::Proxy {
            let (domain, matches) = self.targets.matches(server)?;
            values.push(if domain {
                self.analysis.present
            } else {
                !self.analysis.present
            });
            for (condition, matched) in matches {
                let value = self.analysis.variables[condition];
                values.push(if matched { value } else { !value });
            }
        }
        let condition = self.analysis.all(&values);
        self.analysis.possible(condition, entry.inbound.core)
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
}

pub fn build<'a>(
    store: &Store,
    config: &'a Config,
    geodata: &mut Option<u64>,
    progress: &'a Progress,
    mut coverage: Option<&mut HashMap<Uuid, Coverage>>,
    mut reachable: impl FnMut(Core, Destination, Network, Payload) -> Result<bool>,
) -> Result<Option<Graph<'a>>> {
    if config.inbounds.is_empty()
        || config.users.is_empty()
            && config.inbounds.iter().all(|inbound| {
                inbound.system_users()
                    && !inbound.protocol.responds()
                    && inbound
                        .protocol
                        .fallbacks()
                        .iter()
                        .all(|fallback| fallback.target == Endpoint::Block)
            })
    {
        return Ok(None);
    }
    let mut conditions = Vec::new();
    let mut seen = HashSet::new();
    let mut pending: Vec<_> = if config.inbounds.iter().any(|inbound| {
        Payload::from(&inbound.protocol) == Payload::Proxy
            && !inbound.response_only()
            && (!inbound.system_users() || !config.users.is_empty())
    }) {
        config.rules.iter().collect()
    } else {
        Vec::new()
    };
    while let Some(rule) = pending.pop() {
        collect(&rule.condition, &mut conditions, &mut seen);
        pending.extend(&rule.children);
    }
    let targets = Targets::load(store, geodata, conditions, progress)?;
    let mut graph = Analysis::new(&targets, config, progress)?;
    let step = progress.activity("分析分流");
    let mut entries = Vec::new();
    for inbound in &config.inbounds {
        progress.check()?;
        step.detail(&inbound.name);
        if !graph.enabled(inbound, &mut reachable)? {
            continue;
        }
        let mut scope = coverage
            .as_deref_mut()
            .filter(|_| inbound.protocol.routing())
            .map(|coverage| coverage.entry(inbound.uuid).or_default());
        let mut accounts = Vec::new();
        let modes = crate::native::listener::modes(inbound);
        for network in [Network::Tcp, Network::Udp] {
            let mut receivers = modes
                .iter()
                .filter(|mode| mode.carries(inbound, network))
                .peekable();
            if inbound.response_only() || receivers.peek().is_none() {
                continue;
            }
            let verified = receivers.all(|mode| mode.verifies(inbound));
            if inbound.system_users() {
                for user in &config.users {
                    let routes = graph.routes(
                        inbound,
                        Some(user.uuid),
                        network,
                        &mut reachable,
                        scope.as_deref_mut(),
                    )?;
                    if let Some(route) = routes
                        .iter()
                        .find(|route| route.destination != Destination::Block)
                    {
                        if !verified {
                            return Err(format!(
                                "入站 {} 的 {} 接收器未验证凭据，规则 {} 要求提供用户 {} 的接入",
                                inbound.name,
                                network.name().to_uppercase(),
                                location(&route.path),
                                user.name,
                            )
                            .into());
                        }
                        accounts.push(Account {
                            user: Some(user),
                            network,
                            rules: materialize(routes, config, inbound, Some(user.uuid)),
                        });
                    }
                }
            } else {
                let anonymous =
                    graph.routes(inbound, None, network, &mut reachable, scope.as_deref_mut())?;
                if inbound.account(None).is_some()
                    && !verified
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
                        graph.routes(inbound, Some(user.uuid), network, &mut reachable, None)?;
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
        if !accounts.is_empty() || graph.fallbacks(inbound, &mut reachable)? {
            entries.push(Entry { inbound, accounts });
        }
    }
    step.finish(format!("{} 个入口", entries.len()));
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
    present: Lit,
    addresses: Vec<String>,
    variables: HashMap<Condition, Lit>,
    paths: HashMap<(Uuid, Network, Layer), bool>,
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
        let mut addresses = Vec::new();
        for (values, domain) in targets.domain_classes(progress)? {
            if !domain.is_empty() {
                addresses.push(domain);
            }
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
        for (index, (values, ip)) in classes.into_iter().enumerate() {
            addresses.push(ip.to_string());
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
            present,
            addresses,
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
        coverage: Option<&mut Coverage>,
    ) -> Result<Vec<Route>> {
        let mut routes = self.resolve(inbound, user, network, reachable_destination, coverage)?;
        for route in &mut routes {
            if let Destination::Inbound(uuid) = route.destination
                && !self.reaches(uuid, network, Layer::Transport, reachable_destination)?
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
        mut coverage: Option<&mut Coverage>,
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
                if let Some(scope) = &mut coverage {
                    scope.reached.insert(route.path.clone());
                }
                reachable.push(route);
            }
        }
        if let Some(scope) = coverage
            && !scope.remainder
        {
            scope.remainder = self.possible(remaining, inbound.core)?;
        }
        Ok(reachable)
    }

    fn fallbacks(
        &mut self,
        inbound: &Inbound,
        reachable: &mut impl FnMut(Core, Destination, Network, Payload) -> Result<bool>,
    ) -> Result<bool> {
        for fallback in inbound.protocol.fallbacks() {
            match &fallback.target {
                Endpoint::Block => {}
                Endpoint::Address(value) if !value.is_empty() => return Ok(true),
                Endpoint::Address(_) => {}
                Endpoint::Inbound(uuid) => {
                    if self.reaches(*uuid, Network::Tcp, Layer::Protocol, reachable)? {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(inbound.protocol.responds())
    }

    fn reaches(
        &mut self,
        uuid: Uuid,
        network: Network,
        layer: Layer,
        reachable: &mut impl FnMut(Core, Destination, Network, Payload) -> Result<bool>,
    ) -> Result<bool> {
        if let Some(&result) = self.paths.get(&(uuid, network, layer)) {
            return Ok(result);
        }
        let mut pending = vec![(uuid, network, layer)];
        let mut seen = HashSet::new();
        let mut result = false;
        'search: while let Some((uuid, wire, layer)) = pending.pop() {
            self.progress.check()?;
            if !seen.insert((uuid, wire, layer)) {
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
            let users: Vec<_> = if inbound.system_users() {
                self.config
                    .users
                    .iter()
                    .map(|user| Some(user.uuid))
                    .collect()
            } else if inbound.response_only() {
                Vec::new()
            } else {
                vec![None]
            };
            let modes = crate::native::listener::modes(inbound);
            let accepts = |network| {
                modes
                    .iter()
                    .any(|mode| mode.accepts(inbound, wire, network, layer))
            };
            for network in [Network::Tcp, Network::Udp] {
                if !accepts(network) {
                    continue;
                }
                for &user in &users {
                    for route in self.resolve(inbound, user, network, reachable, None)? {
                        match route.destination {
                            Destination::Block => {}
                            Destination::Inbound(uuid) => {
                                pending.push((uuid, network, Layer::Transport))
                            }
                            Destination::Outbound(_) => {
                                result = true;
                                break 'search;
                            }
                        }
                    }
                }
            }
            if accepts(Network::Tcp) {
                if inbound.protocol.responds() {
                    result = true;
                    break;
                }
                for fallback in inbound.protocol.fallbacks() {
                    match &fallback.target {
                        Endpoint::Block => {}
                        Endpoint::Address(value) if !value.is_empty() => {
                            result = true;
                            break 'search;
                        }
                        Endpoint::Address(_) => {}
                        Endpoint::Inbound(uuid) => {
                            pending.push((*uuid, Network::Tcp, Layer::Protocol))
                        }
                    }
                }
            }
        }
        self.paths.insert((uuid, network, layer), result);
        Ok(result)
    }

    fn enabled(
        &self,
        inbound: &Inbound,
        reachable: &mut impl FnMut(Core, Destination, Network, Payload) -> Result<bool>,
    ) -> Result<bool> {
        if let Some(reality) = inbound.security.reality()
            && let Some(destination) = reality.outbound
            && !reachable(inbound.core, destination, Network::Tcp, Payload::Proxy)?
        {
            return Ok(false);
        }
        Ok(true)
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
