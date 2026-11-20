use crate::language::{message, text as tr};
use crate::{
    Result,
    connection::{self, Connection},
    form::Value,
    inbound::{Core, Protocol},
    transport::Transport,
};

#[derive(Clone, Copy)]
pub(crate) enum Stack<'a> {
    Inbound(&'a Protocol),
    Outbound(&'a Connection),
}

pub(crate) const CORES: [Core; 3] = [Core::Xray, Core::SingBox, Core::Mihomo];

impl connection::Core {
    pub(crate) fn candidates(self, preferred: Option<Core>) -> impl Iterator<Item = Core> + Clone {
        preferred
            .into_iter()
            .chain(
                CORES
                    .into_iter()
                    .filter(move |core| Some(*core) != preferred),
            )
            .filter(move |core| match self {
                Self::Auto => true,
                Self::Xray => *core == Core::Xray,
                Self::SingBox => *core == Core::SingBox,
                Self::Mihomo => *core == Core::Mihomo,
            })
    }
}

impl Connection {
    pub(crate) fn check_stack(&self) -> Result<()> {
        let stack = Stack::Outbound(self);
        let transport = self.transport().unwrap_or(&Transport::Default);
        let mut errors = Vec::new();
        for core in self.core().candidates(None) {
            match stack.check(core, self.security_mode(), transport) {
                Ok(()) => return Ok(()),
                Err(error) => errors.push(error.to_string()),
            }
        }
        Err(errors.join(tr("; ", "；")).into())
    }
}

impl Stack<'_> {
    pub(crate) fn modes(self, cores: impl Iterator<Item = Core> + Clone) -> Vec<usize> {
        (0..3)
            .filter(|&mode| cores.clone().any(|core| self.security(core, mode)))
            .collect()
    }

    pub(crate) fn check(self, core: Core, security: usize, transport: &Transport) -> Result<()> {
        if !self.implements(core) {
            return super::unsupported(message!(
                "{} does not implement this protocol",
                "{} 没有这个协议的实现",
                core.text()
            ));
        }
        if !self.security(core, security) {
            return super::unsupported(message!(
                "{} does not support the {} handshake for this protocol",
                "{} 的此协议不支持「{}」握手",
                core.text(),
                [tr("None", "无"), "TLS", "REALITY"][security]
            ));
        }
        if !self.transport(core, security, transport) {
            return super::unsupported(message!(
                "{} cannot use {} transport with this protocol and handshake",
                "{} 的此协议与握手无法使用 {} 传输",
                core.text(),
                transport.text()
            ));
        }
        Ok(())
    }

    pub(crate) fn implements(self, core: Core) -> bool {
        match self {
            Self::Inbound(Protocol::AnyTls(_)) | Self::Outbound(Connection::AnyTls(_)) => {
                core != Core::Xray
            }
            Self::Outbound(Connection::Warp(_)) => core != Core::SingBox,
            Self::Outbound(Connection::Forward(_)) => core == Core::Xray,
            _ => true,
        }
    }

    pub(crate) fn security(self, core: Core, mode: usize) -> bool {
        if !self.implements(core) {
            return false;
        }
        match self {
            Self::Inbound(Protocol::Hysteria2(_)) | Self::Outbound(Connection::Hysteria2(_)) => {
                mode == 1
            }
            Self::Inbound(Protocol::AnyTls(_)) => mode != 2 || core == Core::SingBox,
            Self::Outbound(Connection::AnyTls(_)) => {
                mode == 1 || mode == 2 && core == Core::SingBox
            }
            Self::Inbound(Protocol::Shadowsocks(_) | Protocol::Forward(_))
            | Self::Outbound(Connection::Shadowsocks(_))
                if core != Core::Xray =>
            {
                mode == 0
            }
            Self::Outbound(Connection::Socks(_)) if core == Core::SingBox => mode == 0,
            Self::Outbound(Connection::Http(_) | Connection::Socks(_)) if core == Core::Mihomo => {
                mode != 2
            }
            Self::Outbound(Connection::Trojan(_)) if core == Core::Mihomo => mode != 0,
            Self::Outbound(Connection::Warp(_) | Connection::Direct(_)) => mode == 0,
            _ => true,
        }
    }

    pub(crate) fn transport(self, core: Core, security: usize, transport: &Transport) -> bool {
        use Transport::*;
        if !self.security(core, security) {
            return false;
        }
        if transport.is_default() {
            return true;
        }
        let v2ray = matches!(
            self,
            Self::Inbound(Protocol::Vless(_) | Protocol::Vmess(_) | Protocol::Trojan(_))
                | Self::Outbound(
                    Connection::Vless(_) | Connection::Vmess(_) | Connection::Trojan(_)
                )
        );
        match core {
            Core::Xray => {
                !matches!(
                    self,
                    Self::Inbound(Protocol::Hysteria2(_) | Protocol::AnyTls(_))
                        | Self::Outbound(
                            Connection::Hysteria2(_)
                                | Connection::AnyTls(_)
                                | Connection::Direct(_)
                                | Connection::Warp(_)
                        )
                ) && !matches!(transport, Quic)
                    && (security != 2 || transport.xray_reality())
            }
            Core::SingBox => {
                v2ray
                    && match transport {
                        XHttp(_) | Kcp(_) => false,
                        Quic => security == 1,
                        _ => true,
                    }
            }
            Core::Mihomo => match self {
                Self::Inbound(_) => {
                    v2ray
                        && match transport {
                            WebSocket(_) | Grpc(_) => true,
                            XHttp(_) => matches!(self, Self::Inbound(Protocol::Vless(_))),
                            Kcp(_) => matches!(self, Self::Inbound(Protocol::Vmess(_))),
                            _ => false,
                        }
                }
                Self::Outbound(_) => {
                    v2ray
                        && match transport {
                            WebSocket(_) | HttpUpgrade(_) => security != 2,
                            Grpc(_) => true,
                            Http(_) => !matches!(self, Self::Outbound(Connection::Trojan(_))),
                            Kcp(_) => matches!(self, Self::Outbound(Connection::Vmess(_))),
                            XHttp(_) => matches!(self, Self::Outbound(Connection::Vless(_))),
                            _ => false,
                        }
                }
            },
        }
    }
}
