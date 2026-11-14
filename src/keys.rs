use serde::{Deserialize, Serialize};
use termina::style::StyleExt;

use crate::{
    Result,
    inbound::{Inbound, Protocol},
    tui::{Action, Item, Menu, Screen},
};

#[derive(Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Keys {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reality: Option<crate::reality::Keys>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption: Option<crate::encryption::Keys>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shadowsocks: Option<crate::shadowsocks::Keys>,
}

impl Keys {
    pub fn needed(source: &Inbound) -> bool {
        source.security.reality().is_some()
            || matches!(&source.protocol, Protocol::Vless(value) if value.encryption.is_some())
            || crate::native::shadowsocks::shared(source, usize::from(source.credentials.is_some()))
    }

    pub fn resolve(source: &Inbound, previous: Option<&Self>) -> Result<Self> {
        let mut keys = previous.cloned().unwrap_or_default();
        if let Some(reality) = source.security.reality() {
            keys.reality = Some(crate::reality::Keys::resolve(
                reality,
                keys.reality.as_ref(),
            )?);
        }
        if let Protocol::Vless(value) = &source.protocol
            && let Some(encryption) = &value.encryption
        {
            keys.encryption = Some(crate::encryption::Keys::resolve(
                encryption,
                keys.encryption.as_ref(),
            )?);
        }
        if crate::native::shadowsocks::shared(source, usize::from(source.credentials.is_some()))
            && let Protocol::Shadowsocks(value) = &source.protocol
        {
            keys.shadowsocks = Some(crate::shadowsocks::Keys::resolve(
                value,
                keys.shadowsocks.as_ref(),
            )?);
        }
        Ok(keys)
    }

    pub fn apply(&self, source: &mut Inbound, users: usize) {
        let shared = crate::native::shadowsocks::shared(source, users);
        if let crate::inbound::Security::Reality(reality) = &mut source.security
            && let Some(keys) = &self.reality
        {
            keys.apply(reality);
        }
        if let Protocol::Vless(value) = &mut source.protocol
            && let Some(encryption) = &mut value.encryption
            && let Some(keys) = &self.encryption
        {
            encryption.private_keys = keys.private_keys.clone();
        }
        if shared
            && let Protocol::Shadowsocks(value) = &mut source.protocol
            && let Some(keys) = &self.shadowsocks
        {
            value.password = Some(keys.password.clone());
        }
    }

    pub fn show(&self, source: &Inbound, screen: &mut Screen) -> Result<()> {
        let mut values = Vec::new();
        if matches!(&source.protocol, Protocol::Shadowsocks(value) if matches!(value.cipher, crate::shadowsocks::Cipher::Aes128Gcm2022 | crate::shadowsocks::Cipher::Aes256Gcm2022))
            && source.core != crate::inbound::Core::Mihomo
            && let Some(keys) = &self.shadowsocks
        {
            values.push(("password", "入口共享密钥", keys.password.clone()));
        }
        if source.security.reality().is_some()
            && let Some(keys) = &self.reality
        {
            values.extend(keys.values());
        }
        if let Protocol::Vless(value) = &source.protocol
            && let Some(encryption) = &value.encryption
            && let Some(keys) = &self.encryption
        {
            let mut encryption = encryption.clone();
            encryption.private_keys = keys.private_keys.clone();
            values.push((
                "encryption",
                "客户端加密参数",
                crate::native::encryption::client(&encryption, keys),
            ));
            values.push((
                "decryption",
                "服务端解密参数",
                crate::native::encryption::server(&encryption)?,
            ));
        }
        let mut items: Vec<_> = values
            .iter()
            .map(|(key, name, value)| {
                let mut item = Item::new(*key, name.stylized());
                item.value = value.clone();
                item
            })
            .collect();
        items.push(Item::new("back", "返回".stylized()));
        let menu = Menu {
            title: "握手资料",
            heading: "",
            items: &items,
            help: "方向键 选择\n回车键 复制\nEsc 返回",
        };
        let mut selected = 0;
        loop {
            match screen.select(&menu, &mut selected, "")? {
                Action::Back => return Ok(()),
                Action::Select if selected == values.len() => return Ok(()),
                Action::Select => {
                    screen.copy(&values[selected].2)?;
                }
                _ => {}
            }
        }
    }
}
