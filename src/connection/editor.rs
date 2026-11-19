use crate::{
    form::{self, Field, Value},
    native::stack::Stack,
    transport::Transport,
};

use super::{Connection, Core, Security, Tls};

impl Connection {
    pub(crate) fn fit(&mut self) {
        let choices = Choices::new(self);
        let (security, transport) = match self {
            Self::Vless(v) => (&mut v.security, &mut v.transport),
            Self::Vmess(v) => (&mut v.security, &mut v.transport),
            Self::Trojan(v) => (&mut v.security, &mut v.transport),
            Self::Shadowsocks(v) => (&mut v.security, &mut v.transport),
            Self::Http(v) => (&mut v.security, &mut v.transport),
            Self::Socks(v) => (&mut v.security, &mut v.transport),
            Self::Forward(v) => (&mut v.security, &mut v.transport),
            Self::AnyTls(v) => {
                v.security = choices.security(&v.security);
                return;
            }
            Self::Hysteria2(v) => {
                if let Some(obfs) = &mut v.hysteria.obfs {
                    obfs.fit();
                }
                return;
            }
            Self::Direct(_) | Self::Warp(_) => return,
        };
        *security = choices.security(security);
        *transport = choices.transport(transport);
    }
}

pub(crate) struct Choices {
    cores: Vec<Core>,
    modes: Vec<usize>,
    mode: usize,
    transports: Vec<(&'static str, Transport)>,
}

impl Choices {
    pub(crate) fn new(connection: &Connection) -> Self {
        let stack = Stack::Outbound(connection);
        let requested = connection.core();
        let cores = Core::choices()
            .into_iter()
            .filter(|(_, _, choice)| choice.candidates(None).any(|core| stack.implements(core)))
            .map(|(_, _, choice)| choice)
            .collect();
        let modes = stack.modes(requested.candidates(None));
        let mode = connection.security_mode();
        let mode = if modes.contains(&mode) {
            mode
        } else {
            modes.first().copied().unwrap_or(mode)
        };
        let transports = Transport::variants()
            .into_iter()
            .filter(|(_, t)| {
                requested
                    .candidates(None)
                    .any(|core| stack.transport(core, mode, t))
            })
            .collect();
        Self {
            cores,
            modes,
            mode,
            transports,
        }
    }

    pub(crate) fn core<'a>(&self, value: &'a mut Core, default: Core) -> Box<dyn Field + 'a> {
        let cores = self.cores.clone();
        form::choice_field("core", "核心", value, default, move |v| cores.contains(v))
    }

    pub(crate) fn security(&self, current: &Security) -> Security {
        if self.mode == current.index() {
            return current.clone();
        }
        match self.mode {
            1 => Security::Tls(Tls::default()),
            _ => Security::None,
        }
    }

    pub(crate) fn handshake<'a>(
        &self,
        label: &'static str,
        value: &'a mut Security,
        default: Security,
    ) -> Option<Box<dyn Field + 'a>> {
        if self.modes.iter().all(|&mode| mode == 0) {
            return None;
        }
        let modes = self.modes.clone();
        let mut active = self.security(value);
        Some(form::control(
            "security",
            label,
            value,
            default,
            Some(active.text()),
            move |slot, screen, menu, _| {
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

    pub(crate) fn transport(&self, current: &Transport) -> Transport {
        if self
            .transports
            .iter()
            .any(|(_, t)| std::mem::discriminant(t) == std::mem::discriminant(current))
        {
            current.clone()
        } else {
            Transport::Default
        }
    }

    pub(crate) fn carrier<'a>(
        &self,
        label: &'static str,
        value: &'a mut Transport,
        default: Transport,
    ) -> Option<Box<dyn Field + 'a>> {
        if self.transports.iter().all(|(_, t)| t.is_default()) {
            return None;
        }
        let choices = self.transports.clone();
        let mut active = self.transport(value);
        Some(form::control(
            "transport",
            label,
            value,
            default,
            Some(active.text()),
            move |slot, screen, menu, field| {
                let changed = active.select(screen, menu, field, &choices)?;
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
        impl $crate::form::Form for $ty {
            fn fields(&mut self, d: Self) -> $crate::form::Fields<'_> {
                let choices = $crate::connection::editor::Choices::new(
                    &$crate::connection::Connection::$variant(self.clone())
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
    (@push $f:ident, $c:ident, $s:ident, $d:ident, $key:ident, $label:literal) => {
        $f.push($crate::form::field(stringify!($key), $label, &mut $s.$key, $d.$key));
    };
}

pub(crate) use client_fields;
