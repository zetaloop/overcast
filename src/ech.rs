use std::fs;

use base64::{Engine, engine::general_purpose::STANDARD};

use crate::{
    Result,
    config::Store,
    inbound::{Core, Inbound},
};

pub fn public(source: &Inbound, store: &Store) -> Result<String> {
    let ech = &source.tls.ech;
    let text = if let Some(file) = &ech.key_file
        && (ech.keys.is_empty() || source.core == Core::Xray)
    {
        fs::read_to_string(store.directory.join(file))?
    } else {
        ech.keys.join("\n")
    };
    let bytes = decode(&text, "ECH KEYS")?;
    let mut input = bytes.as_slice();
    let mut configs = Vec::new();
    while !input.is_empty() {
        element(&mut input)?;
        configs.extend_from_slice(element(&mut input)?);
    }
    let length = u16::try_from(configs.len()).map_err(|_| "ECH 配置超出协议长度")?;
    let mut output = length.to_be_bytes().to_vec();
    output.extend(configs);
    Ok(STANDARD.encode(output))
}

pub fn pem(config: &str) -> Result<String> {
    Ok(format!(
        "-----BEGIN ECH CONFIGS-----\n{}\n-----END ECH CONFIGS-----\n",
        STANDARD.encode(decode(config, "ECH CONFIGS")?)
    ))
}

pub fn base64(config: &str) -> Result<String> {
    if config.trim_start().starts_with("-----BEGIN ") {
        Ok(STANDARD.encode(decode(config, "ECH CONFIGS")?))
    } else {
        Ok(config.to_owned())
    }
}

fn decode(text: &str, label: &str) -> Result<Vec<u8>> {
    let text = text.trim();
    let value = if text.starts_with("-----BEGIN ") {
        let text = text
            .strip_prefix(&format!("-----BEGIN {label}-----"))
            .ok_or_else(|| format!("需要 {label} PEM 数据"))?;
        text.split_once(&format!("-----END {label}-----"))
            .ok_or_else(|| format!("{label} PEM 数据不完整"))?
            .0
    } else {
        text
    };
    Ok(STANDARD.decode(
        value
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect::<String>(),
    )?)
}

fn element<'a>(input: &mut &'a [u8]) -> Result<&'a [u8]> {
    let (length, rest) = input.split_first_chunk::<2>().ok_or("ECH 密钥长度不正确")?;
    let (value, rest) = rest
        .split_at_checked(usize::from(u16::from_be_bytes(*length)))
        .ok_or("ECH 密钥长度不正确")?;
    *input = rest;
    Ok(value)
}
