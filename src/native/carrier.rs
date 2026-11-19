use crate::{
    Result,
    connection::{Connection, HttpVersion, Security, SocksVersion},
    graph::Network,
    inbound::Core,
    transport::Transport,
};

enum Packets {
    Disabled,
    Stream,
    Http,
    Datagram,
    Associate,
}

pub struct Carrier {
    primary: [bool; 2],
    download: Option<Network>,
    tcp: bool,
    packets: Packets,
}

impl Carrier {
    pub fn new(source: &Connection) -> Result<Self> {
        use Packets::{Associate, Datagram, Disabled, Http, Stream};
        let mut download = None;
        let mut transport = |t: &Transport, security: &Security| {
            if let Transport::XHttp(value) = t
                && let Some(leg) = &value.download
            {
                download = Some(
                    if matches!(&leg.security, Security::Tls(tls) if tls.alpn == ["h3"]) {
                        Network::Udp
                    } else {
                        Network::Tcp
                    },
                );
            }
            let udp = t.quic(security);
            [!udp, udp]
        };
        let mux = source.multiplex().is_some_and(|mux| !mux.tcp_only);
        let tcp = [true, false];
        let udp = [false, true];
        let (primary, stream, packet, delivery) = match source {
            Connection::Direct(_) => (tcp, None, None, Datagram),
            Connection::Forward(v) => (transport(&v.transport, &v.security), None, None, Datagram),
            Connection::Hysteria2(v) => (udp, v.hysteria.tcp, v.hysteria.udp, Stream),
            Connection::AnyTls(v) => (tcp, v.anytls.tcp, v.anytls.udp, Stream),
            Connection::Warp(v) => (
                if v.warp.mode == crate::warp::Mode::Http3 {
                    udp
                } else {
                    tcp
                },
                v.warp.tcp,
                v.warp.udp,
                Stream,
            ),
            Connection::Http(v) => (
                if v.http.version == HttpVersion::Http3 {
                    [!v.http.fixed_version, v.security.reality().is_none()]
                } else {
                    transport(&v.transport, &v.security)
                },
                None,
                None,
                if mux { Stream } else { Http },
            ),
            Connection::Socks(v) => (
                transport(&v.transport, &v.security),
                v.socks.tcp,
                v.socks.udp,
                if mux {
                    Stream
                } else if v.socks.version != SocksVersion::V5 {
                    Disabled
                } else if v.socks.udp_over_tcp.is_some() {
                    Stream
                } else {
                    Associate
                },
            ),
            Connection::Vless(v) => (
                transport(&v.transport, &v.security),
                v.vless.tcp,
                v.vless.udp,
                Stream,
            ),
            Connection::Vmess(v) => (
                transport(&v.transport, &v.security),
                v.vmess.tcp,
                v.vmess.udp,
                Stream,
            ),
            Connection::Trojan(v) => (
                transport(&v.transport, &v.security),
                v.trojan.tcp,
                v.trojan.udp,
                Stream,
            ),
            Connection::Shadowsocks(v) => {
                let s = &v.shadowsocks;
                let mut stream_packets = mux || s.udp_over_tcp.is_some();
                let primary = if let Some(plugin) = &s.plugin {
                    stream_packets |= plugin.name == "kcptun";
                    let udp = plugin.name == "kcptun"
                        || plugin.name == "v2ray-plugin"
                            && super::shadowsocks::arguments(&plugin.options)?
                                .get("mode")
                                .is_some_and(|m| m == "quic");
                    [!udp, udp]
                } else {
                    transport(&v.transport, &v.security)
                };
                (
                    primary,
                    s.tcp,
                    s.udp,
                    if stream_packets { Stream } else { Datagram },
                )
            }
        };
        Ok(Self {
            primary,
            download,
            tcp: stream.unwrap_or(true),
            packets: if packet.unwrap_or(true) {
                delivery
            } else {
                Disabled
            },
        })
    }

    /// Networks used to reach the primary peer, including a SOCKS association's control connection.
    pub fn wires(&self) -> [bool; 2] {
        let primary = self.tcp || !matches!(self.packets, Packets::Datagram | Packets::Disabled);
        [
            primary && self.primary[0],
            primary && self.primary[1]
                || matches!(self.packets, Packets::Datagram | Packets::Associate),
        ]
    }

    pub fn requests(&self, core: Core, parent: [bool; 2]) -> [bool; 2] {
        let stream = (parent[0] && self.primary[0] || parent[1] && self.primary[1])
            && self.download.is_none_or(|network| parent[network as usize]);
        [
            stream && self.tcp,
            match self.packets {
                Packets::Disabled => false,
                Packets::Http => stream && core == Core::SingBox,
                Packets::Stream => stream,
                Packets::Datagram => parent[1],
                Packets::Associate => stream && parent[1],
            },
        ]
    }
}
