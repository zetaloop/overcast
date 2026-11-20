use std::collections::BTreeSet;

use serde_json::Map;

use super::{mihomo, options::Options, singbox, xray};
use crate::{
    Result,
    config::Store,
    connection::{Connection, Network},
    inbound::{Core, Inbound, Protocol},
    transport::{Grpc, Transport},
};

#[derive(Clone, Copy, Default)]
pub(crate) struct Handshake {
    pub encryption: bool,
    pub signature: bool,
}

impl From<&Inbound> for Handshake {
    fn from(source: &Inbound) -> Self {
        Self {
            encryption: matches!(&source.protocol, Protocol::Vless(value) if value.encryption.is_some()),
            signature: source
                .security
                .reality()
                .is_some_and(|value| value.signature),
        }
    }
}

/// Parameters may be selected before their authentication material is available.
#[derive(Clone, Copy)]
pub(crate) struct Input<'a> {
    pub store: &'a Store,
    pub pending: Option<Handshake>,
}

impl<'a> From<&'a Store> for Input<'a> {
    fn from(store: &'a Store) -> Self {
        Self {
            store,
            pending: None,
        }
    }
}

impl Input<'_> {
    pub(super) fn download(self) -> Self {
        Self {
            pending: self.pending.map(|_| Handshake::default()),
            ..self
        }
    }

    pub(super) fn reality(self, value: &crate::reality::Client) -> Result<Options> {
        self.material(|| value.validate())?;
        let mut options = Options::new(value)?;
        if self.pending.is_some_and(|handshake| handshake.signature) {
            options.require("signature_key");
        }
        Ok(options)
    }

    pub(super) fn vless(self, value: &crate::vless::ClientOptions) -> Result<Options> {
        let mut options = Options::new(value)?;
        if self.pending.is_some_and(|handshake| handshake.encryption) {
            options.require("encryption");
        }
        Ok(options)
    }

    pub(super) fn material<T>(self, emit: impl FnOnce() -> Result<T>) -> Result<Option<T>> {
        match self.pending {
            Some(_) => Ok(None),
            None => emit().map(Some),
        }
    }
}

impl Core {
    pub(crate) fn parameters(
        self,
        value: &Connection,
        store: &Store,
        pending: Handshake,
    ) -> Result<()> {
        self.client(
            value,
            Input {
                store,
                pending: Some(pending),
            },
            &mut Map::new(),
        )
        .map(drop)
    }
}

/// A server uses its fixed implementation. Each exported peer may use any one
/// of its candidates, but all of that peer's settings go to the same candidate.
#[derive(Clone)]
pub(crate) struct Peers {
    pub server: Option<Core>,
    pub clients: Vec<Vec<Core>>,
}

impl Peers {
    pub(crate) fn inbound(source: &Inbound, store: &Store) -> Result<Self> {
        let mut source = source.clone();
        source.transport = Transport::Grpc(Grpc::default());
        let pending = Handshake::from(&source);
        let clients = crate::profile::draft(&source)?
            .iter()
            .map(|client| {
                client
                    .core()
                    .candidates(None)
                    .filter(|&core| core.parameters(client, store, pending).is_ok())
                    .collect()
            })
            .collect();
        Ok(Self {
            server: Some(source.core),
            clients,
        })
    }

    pub(crate) fn client(cores: impl IntoIterator<Item = Core>) -> Self {
        Self {
            server: None,
            clients: vec![cores.into_iter().collect()],
        }
    }

    pub(crate) fn grpc_fields(&self, value: &Grpc) -> BTreeSet<String> {
        let active = Options::new(value).expect("gRPC options serialize");
        let mut fields = self.fields(
            |core, inbound| core.grpc(value, inbound).is_ok(),
            Core::grpc_fields,
        );
        // Fields already in use stay editable when a supplied value needs correction.
        let supported = self.fields(|_, _| true, Core::grpc_fields);
        fields.extend(
            active
                .keys()
                .filter(|key| supported.contains(*key))
                .map(str::to_owned),
        );
        fields
    }

    pub(crate) fn fields(
        &self,
        supports: impl Fn(Core, bool) -> bool,
        names: impl Fn(Core, bool) -> BTreeSet<String>,
    ) -> BTreeSet<String> {
        let mut sets =
            self.server
                .into_iter()
                .map(|core| names(core, true))
                .chain(self.clients.iter().map(|cores| {
                    cores
                        .iter()
                        .filter(|&&core| supports(core, false))
                        .flat_map(|&core| names(core, false))
                        .collect()
                }));
        let Some(mut common) = sets.next() else {
            return BTreeSet::new();
        };
        for fields in sets {
            common.retain(|key| fields.contains(key));
        }
        common
    }
}

pub(crate) fn check_clients(source: &Inbound, store: &Store) -> Result<()> {
    if let Transport::Grpc(value) = &source.transport {
        source.core.grpc(value, true)?;
    }
    let pending = Handshake::from(source);
    for client in crate::profile::draft(source)? {
        let mut errors = Vec::new();
        if !client.core().candidates(None).any(|core| {
            match core.parameters(&client, store, pending) {
                Ok(()) => true,
                Err(error) => {
                    errors.push(format!("{}：{error}", super::key(core)));
                    false
                }
            }
        }) {
            return Err(format!(
                "{} 客户端参数无法生成：{}",
                client.summary(),
                errors.join("；")
            )
            .into());
        }
    }
    Ok(())
}

fn dial(core: Core, source: &Network, options: &mut Options) -> Result<()> {
    match core {
        Core::Xray => {
            xray::source_address(options)?;
            xray::dialer(source, options)?;
            Ok(())
        }
        Core::SingBox => singbox::dial_options(source, options, &mut Map::new()),
        Core::Mihomo => mihomo::dial_options(source, options, &mut Map::new(), &mut Map::new()),
    }
}

impl Core {
    pub(crate) fn grpc_fields(self, inbound: bool) -> BTreeSet<String> {
        Options::fields(|options| super::transport::grpc(self, inbound, options).map(drop))
    }

    pub(crate) fn grpc(self, value: &Grpc, inbound: bool) -> Result<()> {
        let mut options = Options::new(value)?;
        super::transport::grpc(self, inbound, &mut options)?;
        options.finish(&format!("{} gRPC", super::key(self)))
    }

    pub(crate) fn network_fields(self) -> BTreeSet<String> {
        Options::fields(|options| dial(self, &Network::default(), options))
    }

    pub(crate) fn network(self, value: &Network) -> Result<()> {
        let mut options = Options::new(value)?;
        dial(self, value, &mut options)?;
        options.finish("出站网络")
    }
}
