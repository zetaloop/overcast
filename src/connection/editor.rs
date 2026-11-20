use std::rc::Rc;

use crate::{
    Result,
    config::Store,
    form::{self, Field, Form, Value},
    native::{parameters::Peers, stack::Stack},
    security::Material,
    transport::Transport,
    tui::{Menu, Screen},
};

use super::{AddressStrategy, Connection, Core, FastOpen, Network, Security, Tls};
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
            if let Self::Vless(v) = self
                && !core.vless_encryption()
                && v.vless.encrypted()
            {
                v.vless.encryption = None;
            }
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

    pub(crate) fn transport_mut(&mut self) -> Option<&mut Transport> {
        self.stream().1
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

impl crate::core::Draft for Connection {
    type Core = Core;
    fn core(&self) -> Core {
        self.core()
    }
    fn supports(&self, selected: Core) -> bool {
        selected
            .candidates(None)
            .any(|core| Stack::Outbound(self).implements(core))
    }
    fn set_core(&mut self, selected: Core) {
        *match self {
            Self::Direct(v) => &mut v.core,
            Self::Http(v) => &mut v.proxy.core,
            Self::Socks(v) => &mut v.proxy.core,
            Self::Vless(v) => &mut v.core,
            Self::Vmess(v) => &mut v.core,
            Self::Trojan(v) => &mut v.core,
            Self::Shadowsocks(v) => &mut v.core,
            Self::Hysteria2(v) => &mut v.core,
            Self::AnyTls(v) => &mut v.core,
            Self::Warp(v) => &mut v.core,
            Self::Forward(v) => &mut v.core,
        } = selected;
    }
    fn projected(&self) -> Self {
        let mut v = self.clone();
        v.fit();
        v
    }
    fn changes(&self, next: &Self, changes: &mut crate::core::Changes) {
        changes.fields("", self.network(), next.network());
        if let (Some(old), Some(new)) = (self.transport(), next.transport()) {
            changes.transport(old, new);
        }
        let modes = ["无", "TLS", "REALITY"];
        let (a, b) = (self.security_mode(), next.security_mode());
        if a != b {
            changes.lines.push(if b == 0 {
                format!("关闭 {}", modes[a])
            } else {
                format!("握手改用 {}", modes[b])
            });
        }
        if let (Self::Vless(a), Self::Vless(b)) = (self, next) {
            changes.flag("VLESS Encryption", a.vless.encrypted(), b.vless.encrypted());
        }
    }
    fn materials(&mut self, active: &Self, changes: &mut crate::core::Changes) {
        let requested = active.core();
        if requested == Core::Auto {
            return;
        }
        let core = requested.candidates(None).next().unwrap();
        let mode = active.security_mode();
        let ech = core != Engine::Mihomo || !matches!(active, Self::Http(_) | Self::Socks(_));
        if let Self::Hysteria2(v) = self {
            changes.client_tls(&mut v.tls, core, true, "");
        } else {
            let (security, transport) = self.stream();
            if let Some(s) = security
                && s.index() == mode
                && let Some(tls) = s.tls_mut()
            {
                changes.client_tls(tls, core, ech && (mode == 1 || core == Engine::Mihomo), "");
            }
            if matches!(active.transport(), Some(Transport::XHttp(_)))
                && let Some(Transport::XHttp(x)) = transport
                && let Some(download) = &mut x.download
                && let Some(tls) = download.security.tls_mut()
            {
                changes.client_tls(tls, core, true, "下载连接的");
            }
        }
    }
}

type Candidates<'a, T> = dyn Fn(&T) -> Peers + 'a;

impl Tls {
    fn paired(&self, requested: Core, candidates: &Candidates<'_, Self>) -> bool {
        if requested != Core::Auto {
            return requested.candidates(None).any(Engine::paired_identity);
        }
        let mut unbound = self.clone();
        unbound.client_certificate = None;
        unbound.client_key = None;
        candidates(&unbound).paired_identity()
    }

    pub(crate) fn set_identity(&mut self, cert: bool, material: Material, paired: bool) {
        let (slot, other) = if cert {
            (&mut self.client_certificate, &mut self.client_key)
        } else {
            (&mut self.client_key, &mut self.client_certificate)
        };
        if paired
            && other
                .as_ref()
                .is_some_and(|v| v.inline().is_some() != material.inline().is_some())
        {
            *other = None;
        }
        *slot = Some(material);
    }

    fn edit_tls(
        &mut self,
        screen: &mut Screen,
        title: &str,
        requested: Core,
        candidates: &Candidates<'_, Self>,
    ) -> Result<bool> {
        let edit = |cert: bool, tls: &mut Self, screen: &mut Screen, menu: &Menu<'_>, index| {
            let paired = tls.paired(requested, candidates);
            let (current, other) = if cert {
                (&tls.client_certificate, &tls.client_key)
            } else {
                (&tls.client_key, &tls.client_certificate)
            };
            let mut material = current
                .clone()
                .or_else(|| other.as_ref().filter(|_| paired).map(Material::empty))
                .unwrap_or_default();
            let changed = material.edit(screen, menu, index)?;
            if changed {
                tls.set_identity(cert, material, paired);
            }
            Ok(changed)
        };
        form::controls(
            screen,
            title,
            self,
            None,
            |tls| {
                let hint = if tls.paired(requested, candidates) {
                    match (&tls.client_certificate, &tls.client_key) {
                        (Some(v), None) => Some(("client_key", v.empty().text())),
                        (None, Some(v)) => Some(("client_certificate", v.empty().text())),
                        _ => None,
                    }
                } else {
                    None
                };
                let mut fields = tls.fields(Self::default());
                if let Some((key, text)) = hint
                    && let Some(field) = fields.iter_mut().find(|f| f.key() == key)
                {
                    field.preview(text);
                }
                fields
            },
            &[
                ("client_certificate", &|tls, s, m, i| {
                    edit(true, tls, s, m, i)
                }),
                ("client_key", &|tls, s, m, i| edit(false, tls, s, m, i)),
            ],
        )
    }
}

fn edit_security(
    value: &mut Security,
    screen: &mut Screen,
    title: &str,
    modes: &[usize],
    requested: Core,
    candidates: &Candidates<'_, Security>,
) -> Result<bool> {
    value.choose(
        screen,
        title,
        modes,
        |s, t, tls| tls.edit_tls(s, t, requested, &|v| candidates(&Security::Tls(v.clone()))),
        |s, t, r| {
            form::controls(
                s,
                t,
                r,
                None,
                |v| v.fields(Default::default()),
                &[("tls", &|r, s, m, i| {
                    let security = r.clone();
                    let title = format!("{} / {}", m.title, m.items[i].label.content);
                    r.tls.edit_tls(s, &title, requested, &|v| {
                        let mut r = security.clone();
                        r.tls = v.clone();
                        candidates(&Security::Reality(Box::new(r)))
                    })
                })],
            )
        },
    )
}

pub(crate) fn edit_xhttp(
    xhttp: &mut crate::transport::XHttp,
    screen: &mut Screen,
    title: &str,
    requested: Core,
    candidates: &Candidates<'_, crate::transport::XHttp>,
) -> Result<bool> {
    form::controls(
        screen,
        title,
        xhttp,
        None,
        |v| v.fields(Default::default()),
        &[("download", &|x, s, m, i| {
            let outer = x.clone();
            form::optional_page(&mut x.download, s, m, i, |s, title, download, enabled| {
                form::controls(
                    s,
                    title,
                    download,
                    Some(enabled),
                    |v| v.fields(Default::default()),
                    &[("security", &|d, s, m, i| {
                        let leg = d.clone();
                        let check = |security: &Security| {
                            let mut x = outer.clone();
                            x.download = Some(crate::transport::Download {
                                security: security.clone(),
                                ..leg.clone()
                            });
                            candidates(&x)
                        };
                        let modes: Vec<_> = (0..3)
                            .filter(|&mode| {
                                d.security.index() == mode || check(&handshake(mode)).available()
                            })
                            .collect();
                        edit_security(
                            &mut d.security,
                            s,
                            &format!("{} / {}", m.title, m.items[i].label.content),
                            &modes,
                            requested,
                            &check,
                        )
                    })],
                )
            })
        })],
    )
}

#[derive(Clone)]
pub(crate) struct Choices {
    source: Rc<Connection>,
    store: Store,
}

impl Choices {
    pub(crate) fn vless<'a>(
        &self,
        label: &'static str,
        value: &'a mut crate::vless::ClientOptions,
        default: crate::vless::ClientOptions,
    ) -> Box<dyn Field + 'a> {
        let encryption = self
            .source
            .core()
            .candidates(None)
            .any(Engine::vless_encryption);
        form::control("vless", label, value, default, None, move |v, s, m, _| {
            form::subset(s, &format!("{} / {label}", m.title), v, |key| {
                key != "encryption" || encryption
            })
        })
    }
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
                let changed = edit_security(
                    &mut active,
                    screen,
                    &format!("{} / {label}", menu.title),
                    &modes,
                    context.source.core(),
                    &|s| Peers::client(context.candidates(|c| *c.stream().0.unwrap() = s.clone())),
                )?;
                if changed {
                    *slot = active.clone();
                }
                Ok(changed)
            },
        ))
    }

    pub(crate) fn tls<'a>(
        &self,
        label: &'static str,
        value: &'a mut Tls,
        default: Tls,
    ) -> Box<dyn Field + 'a> {
        let ctx = self.clone();
        form::control("tls", label, value, default, None, move |tls, s, m, _| {
            tls.edit_tls(
                s,
                &format!("{} / {label}", m.title),
                ctx.source.core(),
                &|v| {
                    Peers::client(ctx.candidates(|c| {
                        let Connection::Hysteria2(hy) = c else {
                            unreachable!()
                        };
                        hy.tls = v.clone();
                    }))
                },
            )
        })
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
                let changed = active.select(
                    screen,
                    menu,
                    field,
                    &choices,
                    |value, screen, title| {
                        let peers = Peers::client(context.candidates(|c| {
                            *c.stream().1.unwrap() = Transport::Grpc(Default::default())
                        }));
                        let requested = context.source.core();
                        let fixed = requested.candidates(None).find(|_| requested != Core::Auto);
                        value.edit(screen, title, &peers, fixed)
                    },
                    |screen, title, x| {
                        edit_xhttp(x, screen, title, context.source.core(), &|v| {
                            Peers::client(context.candidates(|c| {
                                *c.stream().1.unwrap() = Transport::XHttp(Box::new(v.clone()))
                            }))
                        })
                    },
                )?;
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
        $f.extend($s.proxy.fields($d.proxy));
    };
    (@push $f:ident, $c:ident, $s:ident, $d:ident, core, $label:literal) => {
        $f.push($crate::form::field("core", $label, &mut $s.core, $d.core));
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
    (@push $f:ident, $c:ident, $s:ident, $d:ident, tls, $label:literal) => {
        $f.push($c.tls($label, &mut $s.tls, $d.tls));
    };
    (@push $f:ident, $c:ident, $s:ident, $d:ident, vless, $label:literal) => {
        $f.push($c.vless($label, &mut $s.vless, $d.vless));
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
