use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{BufReader, ErrorKind, Write},
    path::{Path, PathBuf},
};

use maxminddb::{Reader, geoip2};
use prost::Message;
use serde::{Deserialize, Serialize};
use ureq::Agent;

use crate::{
    Result,
    config::Store,
    progress::Progress,
    resource::{self, Asset, Release},
};

#[derive(Deserialize, Serialize)]
pub struct Catalog {
    pub release: u64,
    pub sites: BTreeSet<String>,
    pub ips: BTreeSet<String>,
    pub asns: BTreeMap<u32, String>,
}

impl Catalog {
    pub fn ensure(store: &Store, release: &mut Option<u64>, progress: &Progress) -> Result<Self> {
        if let Some(release) = *release {
            return Self::load(store, release);
        }
        let catalog = Self::update(store, progress)?;
        *release = Some(catalog.release);
        Ok(catalog)
    }

    pub fn directory(&self, store: &Store) -> PathBuf {
        store
            .directory
            .join("geodata")
            .join(self.release.to_string())
    }

    pub fn load(store: &Store, release: u64) -> Result<Self> {
        let path = store
            .directory
            .join("geodata")
            .join(release.to_string())
            .join("index.json");
        Ok(serde_json::from_reader(BufReader::new(File::open(path)?))?)
    }

    pub fn update(store: &Store, progress: &Progress) -> Result<Self> {
        let client = resource::client();
        let step = progress.activity("查询规则数据");
        let release: Release = resource::json(
            &client,
            "https://api.github.com/repos/MetaCubeX/meta-rules-dat/releases/tags/latest",
            progress,
            &step,
        )?;
        step.finish(
            release
                .published_at
                .as_deref()
                .ok_or("规则数据版本尚未发布")?,
        );
        let root = store.directory.join("geodata");
        let directory = root.join(release.id.to_string());
        store.create_dir(&directory)?;
        let asset = |name| {
            release
                .assets
                .iter()
                .find(|asset| asset.name == name)
                .ok_or_else(|| format!("规则数据发布中没有 {name}"))
        };
        let sites = load(
            store,
            &directory,
            asset("geosite.dat")?,
            &client,
            progress,
            |bytes| {
                let mut names = BTreeSet::new();
                for site in Sites::decode(bytes)?.entries {
                    progress.check()?;
                    let name = site.name.to_ascii_lowercase();
                    names.insert(name.clone());
                    for domain in site.domains {
                        for attribute in domain.attributes {
                            names.insert(format!("{name}@{}", attribute.key));
                        }
                    }
                }
                Ok(names)
            },
        )?;
        let ips = load(
            store,
            &directory,
            asset("geoip.dat")?,
            &client,
            progress,
            |bytes| {
                Ok(Geoips::decode(bytes)?
                    .entries
                    .into_iter()
                    .map(|entry| entry.name.to_ascii_lowercase())
                    .collect())
            },
        )?;
        let asns = load(
            store,
            &directory,
            asset("GeoLite2-ASN.mmdb")?,
            &client,
            progress,
            |bytes| {
                let reader = Reader::from_source(bytes)?;
                let mut names = BTreeMap::new();
                for record in reader.networks(Default::default())? {
                    progress.check()?;
                    if let Some(asn) = record?.decode::<geoip2::Asn>()? {
                        names
                            .entry(asn.autonomous_system_number.unwrap_or_default())
                            .or_insert_with(|| {
                                asn.autonomous_system_organization
                                    .unwrap_or_default()
                                    .to_owned()
                            });
                    }
                }
                Ok(names)
            },
        )?;
        let catalog = Self {
            release: release.id,
            sites,
            ips,
            asns,
        };
        progress.check()?;
        store.write(&directory.join("index.json"), |file| {
            serde_json::to_writer(file, &catalog)?;
            Ok(())
        })?;
        Ok(catalog)
    }
}

fn load<T>(
    store: &Store,
    directory: &Path,
    asset: &Asset,
    client: &Agent,
    progress: &Progress,
    decode: impl FnOnce(&[u8]) -> Result<T>,
) -> Result<T> {
    let path = directory.join(&asset.name);
    let mut downloaded = false;
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            let step = progress.start("下载规则数据", asset.size, "字节");
            let bytes = resource::retry(progress, &step, || {
                step.set(0);
                step.detail(&asset.name);
                let mut response = resource::request(client, &asset.browser_download_url)?;
                let mut bytes = Vec::new();
                resource::copy(
                    &mut response.body_mut().as_reader(),
                    &mut bytes,
                    progress,
                    &step,
                )?;
                Ok(bytes)
            })?;
            step.finish(&asset.name);
            downloaded = true;
            bytes
        }
        Err(error) => return Err(error.into()),
    };
    let step = progress.activity("读取规则数据");
    step.detail(&asset.name);
    let value = decode(&bytes)?;
    progress.check()?;
    if downloaded {
        store.write(&path, |file| {
            file.write_all(&bytes)?;
            Ok(())
        })?;
    }
    step.finish(&asset.name);
    Ok(value)
}

#[derive(Message)]
pub struct Sites {
    #[prost(message, repeated, tag = "1")]
    pub entries: Vec<Site>,
}

#[derive(Message)]
pub struct Site {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(message, repeated, tag = "2")]
    pub domains: Vec<Domain>,
}

#[derive(Clone, Message)]
pub struct Domain {
    #[prost(enumeration = "DomainType", tag = "1")]
    pub kind: i32,
    #[prost(string, tag = "2")]
    pub value: String,
    #[prost(message, repeated, tag = "3")]
    pub attributes: Vec<Attribute>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum DomainType {
    Keyword = 0,
    Regex = 1,
    Suffix = 2,
    Domain = 3,
}

#[derive(Clone, Message)]
pub struct Attribute {
    #[prost(string, tag = "1")]
    pub key: String,
}

#[derive(Message)]
pub struct Geoips {
    #[prost(message, repeated, tag = "1")]
    pub entries: Vec<Geoip>,
}

#[derive(Message)]
pub struct Geoip {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(message, repeated, tag = "2")]
    pub networks: Vec<Cidr>,
    #[prost(bool, tag = "3")]
    pub reverse: bool,
}

#[derive(Message)]
pub struct Cidr {
    #[prost(bytes = "vec", tag = "1")]
    pub ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub prefix: u32,
}
