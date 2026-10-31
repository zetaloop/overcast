use std::collections::{HashMap, HashSet};

use uuid::Uuid;
use varisat::{ExtendFormula, Lit, Solver};

use crate::{
    Result,
    condition::Condition,
    config::{Config, Store},
    inbound::{Core, Inbound},
    progress::Progress,
    route::{Destination, Rule},
    target::Targets,
};

pub fn validate(store: &Store, config: &Config, progress: &Progress) -> Result<()> {
    if config.rules.is_empty()
        || config.inbounds.is_empty()
        || config.users.is_empty() && config.inbounds.iter().all(|inbound| inbound.users)
    {
        return Ok(());
    }
    let mut conditions = Vec::new();
    let mut seen = HashSet::new();
    let mut pending: Vec<_> = config.rules.iter().collect();
    while let Some(rule) = pending.pop() {
        collect(&rule.condition, &mut conditions, &mut seen);
        pending.extend(&rule.children);
    }
    let targets = Targets::load(store, conditions, progress)?;
    let mut graph = Graph::new(&targets, config, progress)?;
    let step = progress.activity("分析分流");
    let mut active = 0;
    for inbound in &config.inbounds {
        progress.check()?;
        step.detail(&inbound.name);
        if inbound.users {
            let mut reachable = false;
            for user in &config.users {
                let routes = graph.routes(inbound, Some(user.uuid))?;
                reachable |= routes
                    .iter()
                    .any(|route| route.destination != Destination::Block);
            }
            active += usize::from(reachable);
        } else {
            let anonymous = graph.routes(inbound, None)?;
            for user in &config.users {
                let authenticated = graph.routes(inbound, Some(user.uuid))?;
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
                                    "入站 {} 未提供用户身份，分流规则 {} 的结果依赖用户 {}",
                                    inbound.name,
                                    location(&route.path),
                                    user.name,
                                )
                                .into());
                            }
                        }
                    }
                }
            }
            active += usize::from(
                anonymous
                    .iter()
                    .any(|route| route.destination != Destination::Block),
            );
        }
    }
    step.finish(format!("{active} 个入口具有可转发路径"));
    Ok(())
}

struct Route {
    path: Vec<usize>,
    condition: Lit,
    destination: Destination,
}

struct Graph<'a> {
    solver: Solver<'static>,
    truth: Lit,
    single: Lit,
    variables: HashMap<Condition, Lit>,
    config: &'a Config,
    progress: &'a Progress,
}

impl<'a> Graph<'a> {
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

    fn condition(&mut self, condition: &Condition, inbound: Uuid, user: Option<Uuid>) -> Lit {
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
                if *uuid == inbound {
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
            _ => self.variables[condition],
        }
    }

    fn flatten(
        &mut self,
        rules: &[Rule],
        parent: Lit,
        inbound: Uuid,
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

    fn routes(&mut self, inbound: &Inbound, user: Option<Uuid>) -> Result<Vec<Route>> {
        let mut routes = Vec::new();
        self.flatten(
            &self.config.rules,
            self.truth,
            inbound.uuid,
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
                route.condition = condition;
                reachable.push(route);
            }
        }
        Ok(reachable)
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
