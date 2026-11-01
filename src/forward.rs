use serde::{Deserialize, Serialize};

use crate::{form::fields, route::Destination};

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Forward {
    pub outbound: Destination,
    pub tcp: bool,
    pub udp: bool,
    pub user_level: Option<u32>,
}

impl Default for Forward {
    fn default() -> Self {
        Self {
            outbound: Destination::Block,
            tcp: true,
            udp: true,
            user_level: None,
        }
    }
}

fields!(Forward {
    tcp: "TCP 接收",
    udp: "UDP 接收",
    user_level: "用户等级",
});
