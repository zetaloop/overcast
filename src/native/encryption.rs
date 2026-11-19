use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use uuid::Uuid;

use crate::{
    Result,
    encryption::{Keys, Server},
    graph::Graph,
    inbound::Protocol,
    progress::Progress,
};

use super::listener::{self, Listener};

pub fn prepare(
    listeners: &[Listener],
    graph: &Graph<'_>,
    keys: &mut BTreeMap<Uuid, crate::keys::Keys>,
    progress: &Progress,
) -> Result<()> {
    let active = listeners.iter().filter(|listener| {
        matches!(&listener.source.protocol, Protocol::Vless(value) if value.encryption.is_some())
    });
    for group in listener::related(active, progress)? {
        progress.check()?;
        let sources: Vec<_> = group
            .listeners
            .iter()
            .filter_map(|listener| {
                if let Protocol::Vless(value) = &listener.source.protocol {
                    value.encryption.as_ref()
                } else {
                    None
                }
            })
            .collect();
        let private: BTreeSet<_> = sources
            .iter()
            .filter(|source| !source.private_keys.is_empty())
            .map(|source| source.private_keys.clone())
            .collect();
        let authentication: BTreeSet<_> = sources
            .iter()
            .filter_map(|source| source.authentication)
            .collect();
        if private.len() > 1 || authentication.len() > 1 {
            let names: Vec<_> = group
                .entries
                .iter()
                .map(|entry| graph.entries[*entry].inbound.name.as_str())
                .collect();
            return Err(format!(
                "入站 {} 关联的 VLESS 监听要求不同的加密材料",
                names.join("、")
            )
            .into());
        }
        let mut source = sources[0].clone();
        source.private_keys = private.into_iter().next().unwrap_or_default();
        source.authentication = authentication.into_iter().next();
        let previous = group.entries.iter().find_map(|entry| {
            graph
                .config()
                .keys
                .get(&graph.entries[*entry].inbound.uuid)
                .and_then(|keys| keys.encryption.as_ref())
        });
        let material = Keys::resolve(&source, previous)?;
        for entry in group.entries {
            keys.entry(graph.entries[entry].inbound.uuid)
                .or_default()
                .encryption = Some(material.clone());
        }
    }
    Ok(())
}

pub fn server(source: &Server) -> Result<String> {
    let session = super::transport::range(
        source.session.as_deref().unwrap_or("600s"),
        Some(Duration::from_secs(1)),
    )?;
    let session = session
        .as_str()
        .map_or_else(|| session.to_string(), str::to_owned);
    if session.starts_with('-') {
        return Err("VLESS 加密会话时长需要使用非负秒数".into());
    }
    let mut parts = vec![
        "mlkem768x25519plus".to_owned(),
        source.mode.name().to_owned(),
        format!("{session}s"),
    ];
    if let Some(padding) = source.padding.as_ref().filter(|value| !value.is_empty()) {
        parts.push(padding.clone());
    }
    parts.extend(source.private_keys.clone());
    Ok(parts.join("."))
}

pub fn client(source: &Server, keys: &Keys) -> String {
    let mut parts = vec![
        "mlkem768x25519plus".to_owned(),
        source.mode.name().to_owned(),
        "0rtt".to_owned(),
    ];
    parts.extend(keys.public_keys.clone());
    parts.join(".")
}
