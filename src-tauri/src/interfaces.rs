//! Liste des interfaces avec des noms compréhensibles et une recommandation.

use std::collections::HashMap;
use std::net::IpAddr;

use rustshark_shared::{IfaceKind, InterfaceInfo};

use crate::pcap::{self, PCAP_IF_CONNECTION_STATUS, PCAP_IF_CONNECTION_STATUS_DISCONNECTED, PCAP_IF_LOOPBACK, PCAP_IF_RUNNING, PCAP_IF_UP, PCAP_IF_WIRELESS};

struct OsInfo {
    friendly: String,
    kind: Option<IfaceKind>,
    up: bool,
}

#[cfg(windows)]
fn os_adapters() -> HashMap<String, OsInfo> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

    let mut out = HashMap::new();
    let mut size: u32 = 32 * 1024;
    let mut buf: Vec<u64> = Vec::new();
    for _ in 0..4 {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        let rc = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                std::ptr::null(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            )
        };
        if rc == 0 {
            break;
        }
        if rc != 111 {
            return out;
        }
    }
    let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    unsafe {
        while !cur.is_null() {
            let a = &*cur;
            let guid = std::ffi::CStr::from_ptr(a.AdapterName as *const std::ffi::c_char).to_string_lossy().to_uppercase();
            let friendly = wide(a.FriendlyName);
            let kind = match a.IfType {
                71 => Some(IfaceKind::Wifi),
                6 => Some(IfaceKind::Ethernet),
                24 => Some(IfaceKind::Loopback),
                53 | 131 => Some(IfaceKind::Vpn),
                _ => None,
            };
            out.insert(guid, OsInfo { friendly, kind, up: a.OperStatus == 1 });
            cur = a.Next;
        }
    }
    out
}

#[cfg(windows)]
pub unsafe fn wide(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    while *p.add(n) != 0 {
        n += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
}

#[cfg(not(windows))]
fn os_adapters() -> HashMap<String, OsInfo> {
    HashMap::new()
}

fn guess_kind(name: &str, desc: &str, flags: u32) -> IfaceKind {
    let n = name.to_lowercase();
    let d = desc.to_lowercase();
    let any = |keys: &[&str]| keys.iter().any(|k| n.contains(k) || d.contains(k));
    if flags & PCAP_IF_LOOPBACK != 0 || n == "lo" || n.contains("loopback") {
        IfaceKind::Loopback
    } else if any(&["bluetooth"]) {
        IfaceKind::Bluetooth
    } else if any(&["virtualbox", "vmware", "hyper-v", "vethernet", "wsl", "docker", "veth", "virbr", "vboxnet", "vmnet", "br-", "bridge", "awdl", "llw", "anpi", "ap1", "miniport", "usbmon", "nflog", "nfqueue", "dbus", "any"]) {
        IfaceKind::Virtual
    } else if any(&["wireguard", "tailscale", "tap", "tun", "vpn", "utun", "wg", "zerotier", "openvpn", "ipsec", "ppp"]) {
        IfaceKind::Vpn
    } else if flags & PCAP_IF_WIRELESS != 0 || any(&["wi-fi", "wifi", "wireless", "wlan", "802.11", "wl"]) {
        IfaceKind::Wifi
    } else if any(&["ethernet", "eth", "enp", "eno", "ens", "realtek", "intel", "gbe", "en"]) {
        IfaceKind::Ethernet
    } else {
        IfaceKind::Other
    }
}

pub fn list() -> Result<Vec<InterfaceInfo>, String> {
    let devices = pcap::devices()?;
    let os = os_adapters();
    let mut out: Vec<InterfaceInfo> = devices
        .into_iter()
        .map(|d| {
            let guid = d.name.rsplit('_').next().unwrap_or("").to_uppercase();
            let osi = os.get(&guid);
            let mut kind = osi.and_then(|o| o.kind).unwrap_or_else(|| guess_kind(&d.name, &d.description, d.flags));
            if osi.is_some() && kind == IfaceKind::Ethernet && guess_kind(&d.name, &d.description, d.flags) == IfaceKind::Virtual {
                kind = IfaceKind::Virtual;
            }
            let loopback = d.flags & PCAP_IF_LOOPBACK != 0 || kind == IfaceKind::Loopback;
            let status = d.flags & PCAP_IF_CONNECTION_STATUS;
            let up = osi.map(|o| o.up).unwrap_or(d.flags & (PCAP_IF_UP | PCAP_IF_RUNNING) != 0);
            let connected = up && status != PCAP_IF_CONNECTION_STATUS_DISCONNECTED;
            let friendly = osi
                .map(|o| o.friendly.clone())
                .filter(|f| !f.is_empty())
                .or_else(|| (!d.description.is_empty() && cfg!(windows)).then(|| d.description.clone()))
                .unwrap_or_else(|| d.name.clone());
            let has_v4 = d.addrs.iter().any(|a| matches!(a, IpAddr::V4(v) if !v.is_loopback() && !v.is_link_local()));
            InterfaceInfo {
                recommended: connected && has_v4 && matches!(kind, IfaceKind::Wifi | IfaceKind::Ethernet),
                addresses: d.addrs.iter().map(|a| a.to_string()).collect(),
                name: d.name,
                description: d.description,
                friendly,
                kind,
                up,
                connected,
                loopback,
            }
        })
        .collect();
    out.sort_by_key(|i| {
        (
            !i.recommended,
            !i.connected,
            match i.kind {
                IfaceKind::Wifi | IfaceKind::Ethernet => 0,
                IfaceKind::Vpn => 1,
                IfaceKind::Loopback => 2,
                IfaceKind::Virtual | IfaceKind::Bluetooth => 3,
                IfaceKind::Other => 4,
            },
        )
    });
    Ok(out)
}

/// Adresses de l'interface (pour reconnaître « cet ordinateur »).
pub fn addresses_of(name: &str) -> Vec<IpAddr> {
    pcap::devices()
        .map(|ds| ds.into_iter().find(|d| d.name == name).map(|d| d.addrs).unwrap_or_default())
        .unwrap_or_default()
}
