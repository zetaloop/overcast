use crate::language::{message, text as tr};
use std::{
    collections::BTreeSet,
    fs,
    io::ErrorKind,
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, LazyLock, Mutex},
    time::SystemTime,
};

use ipnetwork::IpNetwork;
use notify::{RecursiveMode, Watcher};
use serde_json::{Value, json};
use url::Host;

use crate::{Result, config::Store, inbound::Inbound, progress::Progress};

pub fn name(source: &Inbound) -> Result<String> {
    let value = source
        .security
        .tls()
        .and_then(|tls| tls.server_name.as_deref())
        .filter(|value| !value.is_empty())
        .unwrap_or(&source.listen.host)
        .trim()
        .trim_end_matches('.');
    let address = value.trim_start_matches('[').trim_end_matches(']');
    if let Ok(address) = address
        .split_once('%')
        .map_or(address, |(address, _)| address)
        .parse::<IpAddr>()
    {
        return Ok(address.to_canonical().to_string());
    }
    Ok(Host::parse(value)
        .map_err(|error| {
            message!(
                "Invalid certificate address {value}: {error}",
                "证书地址 {value} 的格式不正确：{error}"
            )
        })?
        .to_string())
}

pub fn public(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && !name.ends_with('.')
        && !name.contains([
            '(', ')', '[', ']', '{', '}', '<', '>', ' ', '\t', '\n', '"', '\\', '!', '@', '#', '$',
            '%', '^', '&', '|', ';', '\'', '+', '=',
        ])
        && (!name.contains('*')
            || name.starts_with("*.")
                && name.matches('*').count() == 1
                && name.matches('.').count() > 1)
        && name != "localhost"
        && ![".localhost", ".local", ".internal", ".home.arpa"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
        && !name.parse::<IpAddr>().is_ok_and(|address| {
            PRIVATE
                .iter()
                .any(|network| network.contains(address.to_canonical()))
        })
}

pub fn paths(store: &Store, name: &str) -> (PathBuf, PathBuf) {
    let issuer = if public(name) {
        "acme-v02.api.letsencrypt.org-directory"
    } else {
        "local"
    };
    let name = safe(name);
    let directory = store
        .directory
        .join("caddy")
        .join("certificates")
        .join(issuer)
        .join(&name);
    (
        directory.join(format!("{name}.crt")),
        directory.join(format!("{name}.key")),
    )
}

pub fn root(store: &Store) -> PathBuf {
    store.directory.join("caddy/pki/authorities/local/root.crt")
}

pub fn wait(
    store: &Store,
    names: &BTreeSet<String>,
    progress: &Progress,
    mut current: impl FnMut() -> Result<bool>,
) -> Result<()> {
    if names.is_empty() {
        return Ok(());
    }
    let failure = Arc::new(Mutex::new(None));
    let error = failure.clone();
    let changed = progress.clone();
    let mut watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
        match event {
            Ok(event) if event.kind.is_access() => return,
            Ok(_) => {}
            Err(value) => *error.lock().expect("certificate lock poisoned") = Some(value),
        }
        changed.notify();
    })?;
    let directory = store.directory.join("caddy");
    store.create_dir(&directory)?;
    watcher.watch(&directory, RecursiveMode::Recursive)?;
    watcher.watch(&store.directory, RecursiveMode::NonRecursive)?;
    let step = progress.activity(tr("Preparing certificates", "准备证书"));
    progress.until(|| {
        if !current()? {
            return Err(std::io::Error::new(
                ErrorKind::Interrupted,
                tr("Deployment superseded", "部署已被替换"),
            )
            .into());
        }
        if let Some(error) = failure.lock().expect("certificate lock poisoned").take() {
            return Err(error.into());
        }
        let mut pending = Vec::new();
        let now = SystemTime::now();
        for name in names {
            let (certificate, key) = paths(store, name);
            let bytes = match fs::read(&certificate) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    pending.push(name.as_str());
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            let certificates = x509_cert::Certificate::load_pem_chain(&bytes)?;
            let certificate = certificates.first().ok_or_else(|| {
                message!(
                    "Certificate file is empty: {}",
                    "证书文件为空：{}",
                    certificate.display()
                )
            })?;
            let validity = certificate.tbs_certificate().validity();
            if now < validity.not_before.to_system_time() {
                return Err(message!(
                    "Certificate {name} is valid from {}",
                    "证书 {name} 从 {} 开始生效",
                    validity.not_before
                )
                .into());
            }
            if !key.try_exists()? || now >= validity.not_after.to_system_time() {
                pending.push(name.as_str());
            }
        }
        step.detail(pending.join(tr(", ", "、")));
        Ok(pending.is_empty())
    })?;
    step.finish(message!("Certificates: {}", "{} 份证书", names.len()));
    Ok(())
}

pub fn config(store: &Store, names: &BTreeSet<String>, port: u16) -> Value {
    let mut domains = Vec::new();
    let mut ips = Vec::new();
    let mut local = Vec::new();
    for name in names {
        if !public(name) {
            local.push(name);
        } else if name.parse::<IpAddr>().is_ok() {
            ips.push(name);
        } else {
            domains.push(name);
        }
    }
    let mut policies = Vec::new();
    for (subjects, mut issuer) in [
        (domains, json!({"module": "acme"})),
        (ips, json!({"module": "acme", "profile": "shortlived"})),
    ] {
        if !subjects.is_empty() {
            issuer["challenges"] = json!({"tls-alpn": {"disabled": true}});
            policies.push(json!({"subjects": subjects, "issuers": [issuer]}));
        }
    }
    if !local.is_empty() {
        policies.push(json!({"subjects": local, "issuers": [{"module": "internal"}]}));
    }
    let mut output = json!({
        "admin": {"listen": format!("127.0.0.1:{port}"), "config": {"persist": false}},
        "storage": {"module": "file_system", "root": store.directory.join("caddy")},
        "apps": {"tls": {"certificates": {"automate": names}, "automation": {"policies": policies}}},
    });
    #[cfg(windows)]
    {
        output["logging"] = json!({"logs": {"default": {
            "writer": {"output": "file", "filename": store.directory.join("logs/caddy.log")},
        }}});
    }
    if !local.is_empty() {
        output["apps"]["pki"] =
            json!({"certificate_authorities": {"local": {"install_trust": false}}});
    }
    output
}

fn safe(name: &str) -> String {
    name.to_lowercase()
        .trim()
        .replace(' ', "_")
        .replace('+', "_plus_")
        .replace('*', "wildcard_")
        .replace(':', "-")
        .replace("..", "")
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '@' | '.' | '-')
        })
        .collect()
}

static PRIVATE: LazyLock<Vec<IpNetwork>> = LazyLock::new(|| {
    [
        "127.0.0.0/8",
        "0.0.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "::/7",
        "fe80::/10",
        "fc00::/7",
    ]
    .into_iter()
    .map(|network| network.parse().unwrap())
    .collect()
});
