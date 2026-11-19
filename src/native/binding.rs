use std::{
    collections::BTreeSet,
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    rc::Rc,
};

use serde_json::{Map, Value, json};

use crate::{
    Result,
    graph::Network,
    inbound::{Core, Inbound},
};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Address {
    Any,
    V4,
    V6,
    Ip(IpAddr),
    Unix(PathBuf),
    Abstract(Vec<u8>),
}

impl Address {
    pub fn contains(&self, other: &Self) -> bool {
        self == other
            || matches!(
                (self, other),
                (Self::Any, Self::V4 | Self::V6 | Self::Ip(_))
                    | (Self::V4, Self::Ip(IpAddr::V4(_)))
                    | (Self::V6, Self::Ip(IpAddr::V6(_)))
            )
    }
}

#[derive(Clone)]
pub struct Binding {
    pub address: Address,
    pub interface: Option<u32>,
    pub ports: BTreeSet<u16>,
    pub networks: BTreeSet<Network>,
    pub settings: Rc<Map<String, Value>>,
    namespace: Option<(u64, u64)>,
}

impl Binding {
    pub fn local(port: u16, networks: BTreeSet<Network>) -> Result<Self> {
        Ok(Self {
            address: Address::Ip(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            interface: None,
            ports: BTreeSet::from([port]),
            networks,
            settings: Rc::new(Map::new()),
            namespace: Namespace::new(None)?.key,
        })
    }

    pub fn new(source: &Inbound, port: Option<u16>, networks: BTreeSet<Network>) -> Result<Self> {
        let socket = &source.listen.socket;
        let namespace = Namespace::new(socket.namespace.as_deref())?;
        let text = &source.listen.address;
        let mut settings = if source.core == Core::SingBox {
            super::singbox::socket(&crate::inbound::Socket {
                namespace: None,
                ipv6_only: None,
                interface: if cfg!(any(target_os = "linux", target_os = "android")) {
                    None
                } else {
                    socket.interface.clone()
                },
                ..socket.clone()
            })?
        } else {
            let Value::Object(mut settings) = serde_json::to_value(socket)? else {
                unreachable!()
            };
            for name in ["namespace", "ipv6_only"] {
                settings.remove(name);
            }
            if cfg!(any(target_os = "linux", target_os = "android")) {
                settings.remove("interface");
            }
            settings
        };
        let mut zone = None;
        let mut interface = None;
        let mut address = if let Some(name) = text.strip_prefix('@') {
            let name = name.as_bytes().to_vec();
            #[cfg(any(target_os = "linux", target_os = "android"))]
            let name = if text.starts_with("@@") {
                let size = std::mem::size_of::<nix::libc::sockaddr_un>()
                    - std::mem::offset_of!(nix::libc::sockaddr_un, sun_path);
                let mut name = name[1..].to_vec();
                name.resize(size - 1, 0);
                name
            } else {
                name
            };
            Address::Abstract(name)
        } else if Path::new(text).is_absolute() {
            let path = if let Some((path, mode)) =
                text.split_once(',').filter(|(_, mode)| !mode.contains(','))
            {
                settings.insert(
                    "permissions".to_owned(),
                    json!(u32::from_str_radix(mode, 8)?),
                );
                path
            } else {
                text.as_str()
            };
            Address::Unix(canonical(Path::new(path))?)
        } else {
            let (address, scope) = text
                .split_once('%')
                .map_or((text.as_str(), None), |(ip, zone)| (ip, Some(zone)));
            let address: IpAddr = address.parse()?;
            if let IpAddr::V6(ip) = address
                && (ip.is_unicast_link_local() || ip.is_multicast())
                && let Some(scope) = scope
            {
                let index = match scope.parse() {
                    Ok(index) => index,
                    Err(_) => namespace.index(scope)?,
                };
                zone = (index != 0).then_some(index);
            }
            let canonical = address.to_canonical();
            if canonical.is_unspecified() {
                if source.core == Core::SingBox && address.is_ipv4() {
                    Address::V4
                } else {
                    Address::Any
                }
            } else {
                Address::Ip(canonical)
            }
        };
        if !matches!(address, Address::Unix(_) | Address::Abstract(_))
            && cfg!(any(target_os = "linux", target_os = "android"))
            && let Some(name) = socket.interface.as_deref().filter(|name| !name.is_empty())
        {
            let index = namespace.index(name)?;
            interface = Some(index);
        }
        let mut ipv6_only = socket.ipv6_only == Some(true);
        if source.core == Core::Xray
            && cfg!(any(
                target_os = "linux",
                target_os = "android",
                target_os = "macos",
                windows
            ))
            && !matches!(address, Address::Unix(_) | Address::Abstract(_))
        {
            #[cfg(unix)]
            use nix::libc::{IPPROTO_IPV6, IPPROTO_TCP, IPV6_V6ONLY};
            #[cfg(windows)]
            use windows_sys::Win32::Networking::WinSock::{IPPROTO_IPV6, IPPROTO_TCP, IPV6_V6ONLY};
            let system = if cfg!(target_os = "macos") {
                "darwin"
            } else {
                std::env::consts::OS
            };
            let family = if matches!(address, Address::V4 | Address::Ip(IpAddr::V4(_))) {
                "4"
            } else {
                "6"
            };
            let wires: Vec<_> = networks
                .iter()
                .map(|network| format!("{}{family}", network.name()))
                .collect();
            let mut options = Vec::new();
            for option in &socket.socket_options {
                if !option.system.is_empty() && option.system != system
                    || !wires.iter().any(|wire| wire.starts_with(&option.network))
                {
                    continue;
                }
                let level = if option.level.is_empty() {
                    IPPROTO_TCP
                } else {
                    option.level.parse::<isize>().unwrap_or_default() as i32
                };
                let key = option.option.parse::<isize>().unwrap_or_default() as i32;
                let value = if option.kind == "int" {
                    json!(option.value.parse::<isize>().unwrap_or_default() as i32)
                } else {
                    json!(option.value)
                };
                if level == IPPROTO_IPV6
                    && key == IPV6_V6ONLY
                    && family == "6"
                    && option.kind == "int"
                {
                    ipv6_only = value.as_i64() != Some(0);
                    continue;
                }
                #[cfg(any(target_os = "linux", target_os = "android"))]
                {
                    use nix::libc::{SO_BINDTODEVICE, SO_BINDTOIFINDEX, SOL_SOCKET};
                    if level == SOL_SOCKET && key == SO_BINDTODEVICE && option.kind == "str" {
                        let name = option.value.split('\0').next().unwrap();
                        interface = if name.is_empty() {
                            None
                        } else {
                            Some(namespace.index(name)?)
                        };
                        continue;
                    }
                    if level == SOL_SOCKET && key == SO_BINDTOIFINDEX && option.kind == "int" {
                        let index = value.as_i64().unwrap() as u32;
                        interface = (index != 0).then_some(index);
                        continue;
                    }
                }
                options.push(json!([level, key, option.kind, value]));
            }
            if cfg!(any(target_os = "linux", target_os = "android"))
                && socket.ipv6_only == Some(true)
            {
                ipv6_only = true;
            }
            settings.insert("socket_options".to_owned(), json!(options));
        }
        if address == Address::Any && ipv6_only {
            address = Address::V6;
        }
        if let Some(zone) = zone {
            if interface.is_some_and(|interface| interface != zone) {
                return Err(format!("入站 {} 的 IPv6 区域与监听接口不同", source.name).into());
            }
            interface = Some(zone);
        }
        Ok(Self {
            address,
            interface,
            ports: port.into_iter().collect(),
            networks,
            settings: Rc::new(settings),
            namespace: namespace.key,
        })
    }

    pub fn overlaps(&self, other: &Self) -> bool {
        self.intersects(other)
            && (self.ports.is_empty() && other.ports.is_empty()
                || !self.ports.is_disjoint(&other.ports))
    }

    pub fn current_namespace(&self) -> Result<bool> {
        Ok(self.namespace == Namespace::new(None)?.key)
    }

    pub fn intersects(&self, other: &Self) -> bool {
        self.same_namespace(other)
            && !self.networks.is_disjoint(&other.networks)
            && (self.interface.is_none()
                || other.interface.is_none()
                || self.interface == other.interface)
            && (self.address.contains(&other.address) || other.address.contains(&self.address))
    }

    pub fn contains(&self, other: &Self) -> bool {
        self.same_namespace(other)
            && other.ports.is_subset(&self.ports)
            && self.address.contains(&other.address)
            && (self.interface.is_none() || self.interface == other.interface)
    }

    fn same_namespace(&self, other: &Self) -> bool {
        self.namespace == other.namespace
            || matches!(
                (&self.address, &other.address),
                (Address::Unix(_), Address::Unix(_))
            )
    }

    pub fn accepts(&self, address: &Address, interface: Option<u32>) -> bool {
        self.address.contains(address)
            && self.interface.is_none_or(|index| Some(index) == interface)
    }

    pub fn port_text(&self) -> String {
        let mut ranges = Vec::new();
        let mut ports = self.ports.iter().copied().peekable();
        while let Some(first) = ports.next() {
            let mut last = first;
            while last
                .checked_add(1)
                .is_some_and(|next| ports.peek() == Some(&next))
            {
                last = ports.next().unwrap();
            }
            ranges.push(if first == last {
                first.to_string()
            } else {
                format!("{first}-{last}")
            });
        }
        ranges.join(",")
    }
}

struct Namespace {
    key: Option<(u64, u64)>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    path: Option<PathBuf>,
}

impl Namespace {
    fn new(name: Option<&str>) -> Result<Self> {
        let name = name.filter(|name| !name.is_empty());
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use std::os::unix::fs::MetadataExt;
            let current = fs::metadata("/proc/self/ns/net")?;
            let current = (current.dev(), current.ino());
            let path = name.map(|name| {
                if Path::new(name).is_absolute() {
                    PathBuf::from(name)
                } else {
                    Path::new("/var/run/netns").join(name)
                }
            });
            let key = match &path {
                Some(path) => {
                    let metadata = fs::metadata(path)?;
                    (metadata.dev(), metadata.ino())
                }
                None => current,
            };
            Ok(Self {
                key: Some(key),
                path: path.filter(|_| key != current),
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            if name.is_some() {
                return Err("当前系统没有 Linux 网络命名空间".into());
            }
            Ok(Self { key: None })
        }
    }

    fn index(&self, name: &str) -> Result<u32> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(path) = &self.path {
            return std::thread::scope(|scope| {
                scope
                    .spawn(|| {
                        let file = fs::File::open(path)?;
                        nix::sched::setns(file, nix::sched::CloneFlags::CLONE_NEWNET)?;
                        interface_index(name)
                    })
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            });
        }
        interface_index(name)
    }
}

fn interface_index(name: &str) -> Result<u32> {
    #[cfg(unix)]
    {
        let name = std::ffi::CString::new(name)?;
        let index = unsafe { nix::libc::if_nametoindex(name.as_ptr()) };
        if index == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(index)
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::NetworkManagement::{
            IpHelper::{ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex},
            Ndis::NET_LUID_LH,
        };
        if name.contains('\0') {
            return Err("网络接口名称包含 NUL 字符".into());
        }
        let name: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
        let mut luid = NET_LUID_LH { Value: 0 };
        let result = unsafe { ConvertInterfaceAliasToLuid(name.as_ptr(), &mut luid) };
        if result != 0 {
            return Err(std::io::Error::from_raw_os_error(result as i32).into());
        }
        let mut index = 0;
        let result = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
        if result != 0 {
            return Err(std::io::Error::from_raw_os_error(result as i32).into());
        }
        Ok(index)
    }
}

fn canonical(path: &Path) -> Result<PathBuf> {
    let mut missing = Vec::new();
    let mut parent = path;
    loop {
        match fs::canonicalize(parent) {
            Ok(mut path) => {
                for component in missing.into_iter().rev() {
                    path.push(component);
                }
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(parent.file_name().ok_or("套接字路径缺少名称")?);
                parent = parent.parent().ok_or("套接字路径缺少目录")?;
            }
            Err(error) => return Err(error.into()),
        }
    }
}
