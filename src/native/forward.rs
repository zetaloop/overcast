use serde_json::{Map, Value};

use crate::{
    Result,
    config::{Config, Store},
    connection::{self, Connection, HttpVersion, SocksVersion},
    inbound::Core,
    route::Destination,
};

pub fn target(config: &Config, destination: Destination) -> Option<&Connection> {
    let Destination::Outbound(uuid) = destination else {
        return None;
    };
    let source = config
        .outbounds
        .iter()
        .find(|outbound| outbound.uuid == uuid)?
        .connections
        .last()?;
    source.server()?;
    Some(source)
}

pub fn outbound(
    network: &connection::Network,
    core: Core,
    store: &Store,
    globals: &mut Map<String, Value>,
) -> Result<Map<String, Value>> {
    let direct = Connection::Direct(connection::Direct {
        network: network.clone(),
        ..connection::Direct::default()
    });
    match core {
        Core::Xray => super::xray::outbound(&direct, store),
        Core::SingBox => super::singbox::outbound(&direct, store, globals),
        Core::Mihomo => super::mihomo::outbound(&direct, store, globals),
    }
}

pub fn networks(source: &Connection) -> Result<[bool; 2]> {
    let (tls, datagrams) = match source {
        Connection::Direct(_) => return Ok([false, false]),
        Connection::Http(value) => {
            if value.http.version == HttpVersion::Http3 {
                if value.tls.enabled && value.tls.reality.enabled {
                    return Ok([!value.http.fixed_version, false]);
                }
                return Ok([!value.http.fixed_version, true]);
            }
            (&value.tls, false)
        }
        Connection::Socks(value) => (
            &value.tls,
            value.socks.version == SocksVersion::V5
                && value.socks.udp_over_tcp.is_none()
                && value.multiplex.as_ref().is_none_or(|mux| mux.tcp_only),
        ),
        Connection::Vless(value) => (&value.tls, false),
        Connection::Vmess(value) => (&value.tls, false),
        Connection::Trojan(value) => (&value.tls, false),
        Connection::Shadowsocks(value) => {
            let datagrams = value.shadowsocks.udp_over_tcp.is_none()
                && value.multiplex.as_ref().is_none_or(|mux| mux.tcp_only);
            if let Some(plugin) = &value.shadowsocks.plugin {
                let udp = plugin.name == "kcptun"
                    || plugin.name == "v2ray-plugin"
                        && super::shadowsocks::arguments(&plugin.options)?
                            .get("mode")
                            .is_some_and(|mode| mode == "quic");
                return Ok([!udp, udp || datagrams]);
            }
            (&value.tls, datagrams)
        }
    };
    let udp = source
        .transport()
        .unwrap()
        .udp(tls.enabled && !tls.reality.enabled, &tls.alpn);
    Ok([!udp, udp || datagrams])
}
