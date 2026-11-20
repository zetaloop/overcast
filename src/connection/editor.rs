use std::rc::Rc;

use crate::{
    config::Store,
    form::{self, Field, Value},
    native::{parameters::Peers, stack::Stack},
    transport::Transport,
};

use super::{AddressStrategy, Connection, Core, FastOpen, Network, Security};
use crate::inbound::Core as Engine;

impl Connection {
    pub(crate) fn fit(&mut self) {
        let requested = self.core();
        let stack = Stack::Outbound(self);
        let modes = stack.modes(requested.candidates(None));
        let current = self.security_mode();
        let mode = if modes.contains(&current) {
            current
        } else {
            modes.first().copied().unwrap_or(current)
        };
        let transport_supported = self.transport().is_none_or(|value| {
            requested
                .candidates(None)
                .any(|core| stack.transport(core, mode, value))
        });
        if requested != Core::Auto
            && let Some(core) = requested.candidates(None).next()
        {
            self.network_mut().fit(core);
        }
        if let Self::Hysteria2(v) = self
            && let Some(obfs) = &mut v.hysteria.obfs
        {
            obfs.fit();
        }
        let (security, transport) = self.stream();
        if current != mode
            && let Some(security) = security
        {
            *security = handshake(mode);
        }
        if let Some(transport) = transport {
            if !transport_supported {
                *transport = Transport::Default;
            } else if let Transport::Grpc(value) = transport
                && requested != Core::Auto
                && let Some(core) = requested.candidates(None).next()
            {
                value.fit(core, false);
            }
        }
    }

    fn stream(&mut self) -> (Option<&mut Security>, Option<&mut Transport>) {
        match self {
            Self::Vless(v) => (Some(&mut v.security), Some(&mut v.transport)),
            Self::Vmess(v) => (Some(&mut v.security), Some(&mut v.transport)),
            Self::Trojan(v) => (Some(&mut v.security), Some(&mut v.transport)),
            Self::Shadowsocks(v) => (Some(&mut v.security), Some(&mut v.transport)),
            Self::Http(v) => (Some(&mut v.security), Some(&mut v.transport)),
            Self::Socks(v) => (Some(&mut v.security), Some(&mut v.transport)),
            Self::Forward(v) => (Some(&mut v.security), Some(&mut v.transport)),
            Self::AnyTls(v) => (Some(&mut v.security), None),
            Self::Hysteria2(_) | Self::Direct(_) | Self::Warp(_) => (None, None),
        }
    }
}

fn handshake(mode: usize) -> Security {
    match mode {
        0 => Security::None,
        1 => Security::Tls(Default::default()),
        2 => Security::Reality(Box::default()),
        _ => unreachable!(),
    }
}

#[derive(Clone)]
pub(crate) struct Choices {
    source: Rc<Connection>,
    store: Store,
}

impl Choices {
    pub(crate) fn new(mut source: Connection, store: &Store) -> Self {
        source.fit();
        Self {
            source: Rc::new(source),
            store: store.clone(),
        }
    }

    pub(crate) fn candidates(&self, change: impl FnOnce(&mut Connection)) -> Vec<Engine> {
        let mut source = (*self.source).clone();
        change(&mut source);
        source
            .core()
            .candidates(None)
            .filter(|&core| {
                core.parameters(&source, &self.store, Default::default())
                    .is_ok()
            })
            .collect()
    }

    pub(crate) fn network<'a>(
        &self,
        value: &'a mut Network,
        default: Network,
    ) -> Box<dyn Field + 'a> {
        let context = self.clone();
        let requested = self.source.core();
        form::control(
            "network",
            "网络",
            value,
            default,
            None,
            move |net, screen, menu, _| {
                form::scoped(screen, &format!("{} / 网络", menu.title), net, |raw| {
                    let mut active = raw.clone();
                    if requested != Core::Auto
                        && let Some(core) = requested.candidates(None).next()
                    {
                        active.fit(core);
                    }
                    let candidates =
                        |net: &Network| context.candidates(|c| *c.network_mut() = net.clone());
                    let available = candidates(&active);
                    let mut fields = available
                        .iter()
                        .flat_map(|core| core.network_fields())
                        .collect::<std::collections::BTreeSet<_>>();
                    let selected = crate::native::options::Options::new(&active)
                        .expect("network options serialize");
                    for core in requested.candidates(None) {
                        let declared = core.network_fields();
                        fields.extend(
                            selected
                                .keys()
                                .filter(|key| declared.contains(*key))
                                .map(str::to_owned),
                        );
                    }
                    let mut choices = AddressStrategy::choices();
                    choices.retain(|(_, _, s)| {
                        active.address_strategy = Some(*s);
                        !candidates(&active).is_empty()
                    });
                    let sources = (raw.source_ipv4.is_some(), raw.source_ipv6.is_some());
                    let mut bindings = form::Form::fields(raw, Network::default());
                    for field in &mut bindings {
                        match field.key() {
                            "address_strategy" => field.restrict(&|key| {
                                key == "default" || choices.iter().any(|(k, _, _)| *k == key)
                            }),
                            "tcp_fast_open" if !available.contains(&Engine::Xray) => {
                                field.restrict(&|_| true)
                            }
                            _ => {}
                        }
                    }
                    bindings.retain(|f| {
                        fields.contains(f.key())
                            && match (requested, f.key()) {
                                (Core::Xray, "source_ipv6") => !sources.0,
                                (Core::Xray, "source_ipv4") => sources.0 || !sources.1,
                                _ => true,
                            }
                    });
                    bindings
                })
            },
        )
    }

    pub(crate) fn core<'a>(&self, value: &'a mut Core, default: Core) -> Box<dyn Field + 'a> {
        let source = Rc::clone(&self.source);
        form::choice_field("core", "核心", value, default, move |v| {
            v.candidates(None)
                .any(|core| Stack::Outbound(&source).implements(core))
        })
    }

    pub(crate) fn handshake<'a>(
        &self,
        label: &'static str,
        value: &'a mut Security,
        default: Security,
    ) -> Option<Box<dyn Field + 'a>> {
        let modes = Stack::Outbound(&self.source).modes(self.source.core().candidates(None));
        if modes.iter().all(|&mode| mode == 0) {
            return None;
        }
        let context = self.clone();
        let current = self.source.security_mode();
        let mut active = if current == value.index() {
            value.clone()
        } else {
            handshake(current)
        };
        Some(form::control(
            "security",
            label,
            value,
            default,
            Some(active.text()),
            move |slot, screen, menu, _| {
                let modes: Vec<_> = modes
                    .iter()
                    .copied()
                    .filter(|&mode| {
                        mode == current
                            || !context
                                .candidates(|c| {
                                    *c.stream().0.unwrap() = handshake(mode);
                                })
                                .is_empty()
                    })
                    .collect();
                let changed = active.choose(
                    screen,
                    &format!("{} / {label}", menu.title),
                    &modes,
                    form::edit,
                )?;
                if changed {
                    *slot = active.clone();
                }
                Ok(changed)
            },
        ))
    }

    pub(crate) fn transports(&self) -> Vec<(&'static str, Transport)> {
        let current = self.source.transport();
        Transport::variants()
            .into_iter()
            .filter(|(_, value)| {
                current.is_some_and(|t| std::mem::discriminant(value) == std::mem::discriminant(t))
                    || !self
                        .candidates(|c| *c.stream().1.unwrap() = value.clone())
                        .is_empty()
            })
            .collect()
    }

    pub(crate) fn carrier<'a>(
        &self,
        label: &'static str,
        value: &'a mut Transport,
        default: Transport,
    ) -> Option<Box<dyn Field + 'a>> {
        let stack = Stack::Outbound(&self.source);
        if !Transport::variants().iter().any(|(_, t)| {
            !t.is_default()
                && self
                    .source
                    .core()
                    .candidates(None)
                    .any(|core| stack.transport(core, self.source.security_mode(), t))
        }) {
            return None;
        }
        let context = self.clone();
        let mut active = value.draft(self.source.transport()?);
        Some(form::control(
            "transport",
            label,
            value,
            default,
            Some(active.text()),
            move |slot, screen, menu, field| {
                let choices = context.transports();
                let changed =
                    active.select(screen, menu, field, &choices, |value, screen, title| {
                        let peers = Peers::client(context.candidates(|c| {
                            *c.stream().1.unwrap() = Transport::Grpc(Default::default())
                        }));
                        let requested = context.source.core();
                        let fixed = requested.candidates(None).find(|_| requested != Core::Auto);
                        value.edit(screen, title, &peers, fixed)
                    })?;
                if changed {
                    *slot = active.clone();
                }
                Ok(changed)
            },
        ))
    }
}

macro_rules! client_fields {
    ($variant:ident, $ty:ty { $($key:ident: $label:tt),* $(,)? }) => {
        impl $ty {
            pub(crate) fn controls(&mut self, store: &$crate::config::Store) -> $crate::form::Fields<'_> {
                let d = Self::default();
                let choices = $crate::connection::editor::Choices::new(
                    $crate::connection::Connection::$variant(self.clone()), store
                );
                let mut fields: $crate::form::Fields<'_> = Vec::new();
                $($crate::connection::client_fields!(@push fields, choices, self, d, $key, $label);)*
                fields
            }
        }
    };
    (@push $f:ident, $c:ident, $s:ident, $d:ident, proxy, ..) => {
        $f.extend($s.proxy.fields($d.proxy, &$c));
    };
    (@push $f:ident, $c:ident, $s:ident, $d:ident, core, $label:literal) => {
        $f.push($c.core(&mut $s.core, $d.core));
    };
    (@push $f:ident, $c:ident, $s:ident, $d:ident, security, $label:literal) => {
        $f.extend($c.handshake($label, &mut $s.security, $d.security));
    };
    (@push $f:ident, $c:ident, $s:ident, $d:ident, transport, $label:literal) => {
        $f.extend($c.carrier($label, &mut $s.transport, $d.transport));
    };
    (@push $f:ident, $c:ident, $s:ident, $d:ident, network, $label:literal) => {
        $f.push($c.network(&mut $s.network, $d.network));
    };
    (@push $f:ident, $c:ident, $s:ident, $d:ident, $key:ident, $label:literal) => {
        $f.push($crate::form::field(stringify!($key), $label, &mut $s.$key, $d.$key));
    };
}

pub(crate) use client_fields;

impl Network {
    fn fit(&mut self, core: Engine) {
        let fields = core.network_fields();
        form::retain(self, |key| fields.contains(key));
        if core == Engine::Xray && self.source_ipv4.is_some() {
            self.source_ipv6 = None;
        }
        if core != Engine::Xray && matches!(self.tcp_fast_open, Some(FastOpen::Queue(_))) {
            self.tcp_fast_open = None;
        }
        if self.address_strategy.is_some()
            && core
                .network(&Self {
                    address_strategy: self.address_strategy,
                    ..Self::default()
                })
                .is_err()
        {
            self.address_strategy = None;
        }
    }
}
