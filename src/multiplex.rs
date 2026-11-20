use serde::{Deserialize, Serialize};

use crate::form::{choices, fields};

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Client {
    pub protocol: Protocol,
    pub connections: Option<u32>,
    pub min_streams: Option<u32>,
    pub max_streams: Option<u32>,
    pub padding: bool,
    pub tcp_only: bool,
    pub statistics: bool,
    pub brutal: Option<Brutal>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Server {
    pub padding: bool,
    pub brutal: Option<Brutal>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Brutal {
    pub upload: u64,
    pub download: u64,
}

#[derive(Clone, Copy, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    MuxCool,
    #[default]
    Smux,
    Yamux,
    H2mux,
}

choices!(Protocol {
    MuxCool: "mux-cool" => "Mux.Cool",
    Smux: "smux" => "SMux",
    Yamux: "yamux" => "Yamux",
    H2mux: "h2mux" => "H2Mux",
});

fields!(Client {
    protocol: ("Protocol", "协议"),
    connections: ("Connections", "连接数"),
    min_streams: ("Minimum concurrent streams", "最小并发流数"),
    max_streams: ("Maximum concurrent streams", "最大并发流数"),
    padding: ("Padding", "填充"),
    tcp_only: ("TCP only", "仅 TCP"),
    statistics: ("Underlying connection statistics", "底层连接统计"),
    brutal: "TCP Brutal",
});

fields!(Server {
    padding: ("Padding", "填充"),
    brutal: "TCP Brutal",
});

fields!(Brutal {
    upload: ("Upload bytes per second", "上传字节/秒"),
    download: ("Download bytes per second", "下载字节/秒"),
});
