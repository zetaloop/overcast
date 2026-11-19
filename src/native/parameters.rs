use std::collections::BTreeSet;

use serde_json::Map;

use super::{mihomo, options::Options, singbox, xray};
use crate::{Result, connection::Network, inbound::Core};

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
    pub(crate) fn network_fields(self) -> BTreeSet<String> {
        Options::fields(|options| dial(self, &Network::default(), options))
    }

    pub(crate) fn network(self, value: &Network) -> Result<()> {
        let mut options = Options::new(value)?;
        dial(self, value, &mut options)?;
        options.finish("出站网络")
    }
}
