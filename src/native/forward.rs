use serde_json::{Map, Value};

use crate::{
    Result,
    config::{Config, Store},
    connection::{self, Connection},
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
