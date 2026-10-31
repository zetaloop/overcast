use serde_json::{Map, Value, json};

use crate::{
    Result,
    inbound::Core,
    multiplex::{Brutal, Client, Protocol, Server},
};

use super::{options::Options, unsupported};

pub fn client(source: &Client, core: Core) -> Result<Value> {
    let mut options = Options::new(source)?;
    options.take("protocol");
    let mut output = Map::from_iter([("enabled".to_owned(), json!(true))]);
    if core == Core::Xray {
        if source.protocol != Protocol::MuxCool {
            return unsupported("Xray 的流复用使用 Mux.Cool");
        }
        options.rename(&mut output, &[("max_streams", "concurrency")]);
        if let Some(streams) = source.max_streams {
            i16::try_from(streams).map_err(|_| "Xray 并发流数超过支持范围")?;
        }
        options.take("tcp_only");
        if source.tcp_only {
            output.insert("xudpConcurrency".to_owned(), json!(-1));
        }
        output.insert("xudpProxyUDP443".to_owned(), json!("allow"));
    } else {
        if source.protocol == Protocol::MuxCool {
            return unsupported("这个核心的流复用客户端使用 SMux、Yamux 或 H2Mux");
        }
        output.insert(
            "protocol".to_owned(),
            serde_json::to_value(source.protocol)?,
        );
        options.copy(&mut output, &["padding"]);
        match core {
            Core::SingBox => {
                options.rename(&mut output, &[("connections", "max_connections")]);
                options.copy(&mut output, &["min_streams", "max_streams"]);
            }
            Core::Mihomo => {
                options.rename(
                    &mut output,
                    &[
                        ("connections", "max-connections"),
                        ("min_streams", "min-streams"),
                        ("max_streams", "max-streams"),
                        ("tcp_only", "only-tcp"),
                        ("statistics", "statistic"),
                    ],
                );
            }
            Core::Xray => unreachable!(),
        }
        options.take("brutal");
        if let Some(value) = &source.brutal {
            output.insert(
                if core == Core::SingBox {
                    "brutal"
                } else {
                    "brutal-opts"
                }
                .to_owned(),
                brutal(value, core)?,
            );
        }
    }
    options.finish("流复用客户端")?;
    Ok(json!(output))
}

pub fn server(source: &Server, core: Core) -> Result<Value> {
    if core == Core::Xray {
        return unsupported("Xray 没有 S-Mux 服务端配置");
    }
    let mut output = Map::new();
    if core == Core::SingBox {
        output.insert("enabled".to_owned(), json!(true));
    }
    if source.padding {
        output.insert("padding".to_owned(), json!(true));
    }
    if let Some(value) = &source.brutal {
        output.insert("brutal".to_owned(), brutal(value, core)?);
    }
    Ok(json!(output))
}

fn brutal(source: &Brutal, core: Core) -> Result<Value> {
    if source.upload == 0 || source.download == 0 {
        return Err("请填写 TCP Brutal 的上传与下载速率".into());
    }
    if core == Core::SingBox {
        if !source.upload.is_multiple_of(125_000) || !source.download.is_multiple_of(125_000) {
            return unsupported("sing-box 的 TCP Brutal 使用整数 Mbps 速率");
        }
        Ok(
            json!({"enabled": true, "up_mbps": source.upload / 125_000, "down_mbps": source.download / 125_000}),
        )
    } else {
        Ok(
            json!({"enabled": true, "up": format!("{} Bps", source.upload), "down": format!("{} Bps", source.download)}),
        )
    }
}
