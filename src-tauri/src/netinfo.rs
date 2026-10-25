//! Configuration réseau de l'interface choisie (adresses, box, DNS, Wi-Fi)
//! et table des voisins (correspondances IP ↔ MAC connues du système).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(unix)]
use rustshark_shared::WifiInfo;
use rustshark_shared::{Lang, NetworkInfo, WifiSecurity};

use crate::dissect::fmt_mac;
use crate::{interfaces, oui, pcap};

/// Voisin connu du système (cache ARP / NDP).
#[derive(Clone, Debug)]
pub struct Neighbor {
    pub ip: IpAddr,
    pub mac: [u8; 6],
}

/// Plage IPv4 locale : adresse de cet ordinateur et longueur du préfixe.
#[derive(Clone, Copy, Debug)]
pub struct Subnet {
    pub ip: Ipv4Addr,
    pub prefix: u8,
}

impl Subnet {
    pub fn mask(&self) -> u32 {
        if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix.min(32) as u32)
        }
    }

    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.ip) & self.mask())
    }

    pub fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.ip) | !self.mask())
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(a) => u32::from(*a) & self.mask() == u32::from(self.ip) & self.mask() && *a != self.broadcast() && *a != self.network(),
            IpAddr::V6(_) => false,
        }
    }

    pub fn host_count(&self) -> u32 {
        match self.prefix {
            32 => 1,
            31 => 2,
            p => (1u64 << (32 - p as u32)).saturating_sub(2).min(u32::MAX as u64) as u32,
        }
    }

    pub fn cidr(&self) -> String {
        format!("{}/{}", self.network(), self.prefix)
    }
}

fn mask_prefix(mask: &IpAddr) -> Option<u8> {
    match mask {
        IpAddr::V4(m) => {
            let v = u32::from(*m);
            (v.leading_ones() + v.trailing_zeros() == 32).then_some(v.leading_ones() as u8)
        }
        IpAddr::V6(_) => None,
    }
}

fn usable_v4(ip: &IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(a) if !a.is_loopback() && !a.is_link_local() && !a.is_unspecified() => Some(*a),
        _ => None,
    }
}

/// Sous-réseau IPv4 de l'interface, d'après les adresses vues par pcap.
pub fn subnet_of(iface: &str) -> Option<Subnet> {
    #[cfg(windows)]
    if let Some(a) = windows::adapter(iface) {
        if let Some((ip, prefix)) = a.v4 {
            return Some(Subnet { ip, prefix });
        }
    }
    let dev = pcap::devices().ok()?.into_iter().find(|d| d.name == iface)?;
    dev.addrs.iter().zip(dev.masks.iter()).find_map(|(a, m)| {
        let ip = usable_v4(a)?;
        let prefix = m.as_ref().and_then(mask_prefix).unwrap_or(24);
        Some(Subnet { ip, prefix })
    })
}

fn sanitize_v6(a: &Ipv6Addr) -> bool {
    !a.is_loopback() && !a.is_unspecified() && !a.is_multicast()
}

/// Configuration complète de l'interface.
pub fn info(iface: &str, lang: Lang) -> NetworkInfo {
    let mut out = NetworkInfo { interface: iface.to_string(), ..Default::default() };
    if let Ok(list) = interfaces::list() {
        if let Some(i) = list.into_iter().find(|i| i.name == iface) {
            out.friendly = i.friendly;
            out.kind = i.kind;
            out.description = Some(i.description).filter(|d| !d.is_empty());
        }
    }
    if out.friendly.is_empty() {
        out.friendly = iface.to_string();
    }
    if let Some(dev) = pcap::devices().ok().and_then(|l| l.into_iter().find(|d| d.name == iface)) {
        out.ipv6 = dev.addrs.iter().filter_map(|a| match a {
            IpAddr::V6(v) if sanitize_v6(v) => Some(v.to_string()),
            _ => None,
        }).collect();
    }
    platform_info(iface, &mut out, lang);
    let mut seen = std::collections::HashSet::new();
    out.dns.retain(|d| seen.insert(d.clone()));
    if let Some(s) = subnet_of(iface) {
        out.ipv4 = Some(s.ip.to_string());
        out.prefix = Some(s.prefix);
        out.netmask = Some(Ipv4Addr::from(s.mask()).to_string());
        out.network = Some(s.cidr());
        out.broadcast = Some(s.broadcast().to_string());
        out.hosts = Some(s.host_count());
    }
    if let Some(mac) = out.mac.as_deref().and_then(oui::parse_mac) {
        out.vendor = oui::vendor(&mac).map(String::from);
    }
    if let Some(gw) = out.gateway.as_deref().and_then(|g| g.parse::<IpAddr>().ok()) {
        if let Some(n) = neighbors(iface).into_iter().find(|n| n.ip == gw) {
            out.gateway_mac = Some(fmt_mac(&n.mac));
            out.gateway_vendor = oui::vendor(&n.mac).map(String::from);
        }
    }
    out
}

pub fn neighbors(iface: &str) -> Vec<Neighbor> {
    let mut v = platform_neighbors(iface);
    v.retain(|n| {
        n.mac != [0; 6] && n.mac != [0xff; 6] && n.mac[0] & 1 == 0 && !n.ip.is_multicast() && !n.ip.is_unspecified()
            && !matches!(n.ip, IpAddr::V4(a) if a.is_broadcast() || a.octets()[3] == 255)
    });
    v
}

/// Nom lisible de la norme Wi-Fi.
fn wifi_standard(code: &str) -> String {
    match code {
        "a" => "802.11a".into(),
        "b" => "802.11b".into(),
        "g" => "802.11g".into(),
        "n" => "Wi-Fi 4 (802.11n)".into(),
        "ac" => "Wi-Fi 5 (802.11ac)".into(),
        "ax" => "Wi-Fi 6 (802.11ax)".into(),
        "be" => "Wi-Fi 7 (802.11be)".into(),
        other => other.into(),
    }
}

fn band_of_channel(ch: u32) -> &'static str {
    if ch <= 14 {
        "2,4 GHz"
    } else {
        "5 GHz"
    }
}

#[cfg_attr(windows, allow(dead_code))]
fn band_of_freq(mhz: u32) -> &'static str {
    match mhz {
        0..=3000 => "2,4 GHz",
        3001..=5900 => "5 GHz",
        _ => "6 GHz",
    }
}

/// Interprète un libellé de sécurité texte (nmcli, macOS).
#[cfg_attr(windows, allow(dead_code))]
fn security_from_text(s: &str) -> WifiSecurity {
    let u = s.to_uppercase();
    if u.contains("802.1X") || u.contains("ENTERPRISE") || u.contains("EAP") {
        WifiSecurity::Enterprise
    } else if u.contains("WPA3") || u.contains("SAE") {
        WifiSecurity::Wpa3
    } else if u.contains("WPA2") || u.contains("RSN") {
        WifiSecurity::Wpa2
    } else if u.contains("WPA") {
        WifiSecurity::Wpa
    } else if u.contains("WEP") {
        WifiSecurity::Wep
    } else if u.is_empty() || u == "--" || u.contains("NONE") || u.contains("OPEN") {
        WifiSecurity::Open
    } else {
        WifiSecurity::Unknown
    }
}

// ---------------------------------------------------------------------------
// Windows : IP Helper et API WLAN
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod windows {
    use std::net::{IpAddr, Ipv4Addr};

    use windows_sys::Win32::NetworkManagement::IpHelper::*;
    use windows_sys::Win32::NetworkManagement::WiFi::*;
    use windows_sys::Win32::Networking::WinSock::{NlnsProbe, AF_UNSPEC};

    use rustshark_shared::{Lang, NetworkInfo, WifiInfo, WifiSecurity};

    use super::{band_of_channel, wifi_standard, Neighbor};
    use crate::dissect::fmt_mac;
    use crate::interfaces::wide;
    use crate::pcap::sockaddr_ip;

    pub struct Adapter {
        pub guid: String,
        pub if_index: u32,
        pub v6_index: u32,
        pub mac: Option<[u8; 6]>,
        pub v4: Option<(Ipv4Addr, u8)>,
        pub gateways: Vec<IpAddr>,
        pub dns: Vec<IpAddr>,
        pub dhcp: bool,
        pub dhcp_server: Option<IpAddr>,
        pub dns_suffix: String,
        pub mtu: u32,
        pub speed: u64,
        pub if_type: u32,
    }

    fn guid_of(iface: &str) -> String {
        iface.rsplit('_').next().unwrap_or(iface).to_uppercase()
    }

    pub fn adapter(iface: &str) -> Option<Adapter> {
        let want = guid_of(iface);
        let mut size: u32 = 32 * 1024;
        let mut buf: Vec<u64> = Vec::new();
        let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
        let mut ok = false;
        for _ in 0..4 {
            buf = vec![0u64; (size as usize).div_ceil(8)];
            let rc = unsafe { GetAdaptersAddresses(AF_UNSPEC as u32, flags, std::ptr::null(), buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH, &mut size) };
            if rc == 0 {
                ok = true;
                break;
            }
            if rc != 111 {
                return None;
            }
        }
        if !ok {
            return None;
        }
        let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        unsafe {
            while !cur.is_null() {
                let a = &*cur;
                let guid = std::ffi::CStr::from_ptr(a.AdapterName as *const std::ffi::c_char).to_string_lossy().to_uppercase();
                if guid == want {
                    let mut v4 = None;
                    let mut u = a.FirstUnicastAddress;
                    while !u.is_null() {
                        if let Some(IpAddr::V4(ip)) = sockaddr_ip((*u).Address.lpSockaddr as *const _) {
                            if !ip.is_link_local() && v4.is_none() {
                                v4 = Some((ip, (*u).OnLinkPrefixLength));
                            }
                        }
                        u = (*u).Next;
                    }
                    let mut gateways = Vec::new();
                    let mut g = a.FirstGatewayAddress;
                    while !g.is_null() {
                        if let Some(ip) = sockaddr_ip((*g).Address.lpSockaddr as *const _) {
                            gateways.push(ip);
                        }
                        g = (*g).Next;
                    }
                    let mut dns = Vec::new();
                    let mut d = a.FirstDnsServerAddress;
                    while !d.is_null() {
                        if let Some(ip) = sockaddr_ip((*d).Address.lpSockaddr as *const _) {
                            // Adresses « fec0:0:0:ffff::1 » : valeurs par défaut sans signification.
                            if !matches!(ip, IpAddr::V6(v) if v.segments()[0] == 0xfec0) {
                                dns.push(ip);
                            }
                        }
                        d = (*d).Next;
                    }
                    let mac = (a.PhysicalAddressLength == 6).then(|| {
                        let mut m = [0u8; 6];
                        m.copy_from_slice(&a.PhysicalAddress[..6]);
                        m
                    });
                    let dhcp = a.Anonymous2.Flags & IP_ADAPTER_DHCP_ENABLED != 0;
                    let dhcp_server = sockaddr_ip(a.Dhcpv4Server.lpSockaddr as *const _).filter(|ip| !ip.is_unspecified());
                    return Some(Adapter {
                        guid,
                        if_index: a.Anonymous1.Anonymous.IfIndex,
                        v6_index: a.Ipv6IfIndex,
                        mac,
                        v4,
                        gateways,
                        dns,
                        dhcp,
                        dhcp_server,
                        dns_suffix: wide(a.DnsSuffix),
                        mtu: a.Mtu,
                        speed: a.TransmitLinkSpeed.max(a.ReceiveLinkSpeed),
                        if_type: a.IfType,
                    });
                }
                cur = a.Next;
            }
        }
        None
    }

    pub fn fill(iface: &str, out: &mut NetworkInfo, lang: Lang) {
        let Some(a) = adapter(iface) else { return };
        out.mac = a.mac.map(|m| fmt_mac(&m));
        out.gateway = a.gateways.iter().find(|g| g.is_ipv4()).map(|g| g.to_string());
        out.gateway_v6 = a.gateways.iter().find(|g| g.is_ipv6()).map(|g| g.to_string());
        out.dns = a.dns.iter().map(|d| d.to_string()).collect();
        out.dhcp = Some(a.dhcp);
        out.dhcp_server = a.dhcp_server.map(|d| d.to_string());
        out.dns_suffix = Some(a.dns_suffix.clone()).filter(|s| !s.is_empty());
        out.mtu = Some(a.mtu).filter(|m| *m > 0 && *m < 65536);
        // Valeur « inconnue » renvoyée par certains pilotes.
        out.speed_mbps = Some(a.speed / 1_000_000).filter(|s| *s > 0 && a.speed != u64::MAX);
        if a.if_type == 71 {
            out.wifi = Some(wifi(&a.guid, lang));
        }
    }

    fn fmt_guid(g: &windows_sys::core::GUID) -> String {
        format!(
            "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            g.data1, g.data2, g.data3, g.data4[0], g.data4[1], g.data4[2], g.data4[3], g.data4[4], g.data4[5], g.data4[6], g.data4[7]
        )
    }

    fn wifi(guid: &str, lang: Lang) -> WifiInfo {
        let mut w = WifiInfo::default();
        unsafe {
            let mut ver = 0u32;
            let mut h = std::ptr::null_mut();
            if WlanOpenHandle(2, std::ptr::null(), &mut ver, &mut h) != 0 {
                w.note = Some(lang.pick("Service Wi-Fi (WLAN AutoConfig) indisponible.", "Wi-Fi service (WLAN AutoConfig) unavailable.").into());
                return w;
            }
            let mut list: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();
            if WlanEnumInterfaces(h, std::ptr::null(), &mut list) == 0 && !list.is_null() {
                let n = (*list).dwNumberOfItems as usize;
                let items = std::slice::from_raw_parts((*list).InterfaceInfo.as_ptr(), n);
                if let Some(item) = items.iter().find(|i| fmt_guid(&i.InterfaceGuid) == guid) {
                    query(h, &item.InterfaceGuid, &mut w, lang);
                }
                WlanFreeMemory(list as *const _);
            }
            WlanCloseHandle(h, std::ptr::null());
        }
        w
    }

    unsafe fn query(h: windows_sys::Win32::Foundation::HANDLE, guid: &windows_sys::core::GUID, w: &mut WifiInfo, lang: Lang) {
        let mut size = 0u32;
        let mut data: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut vt = 0;
        let rc = WlanQueryInterface(h, guid, wlan_intf_opcode_current_connection, std::ptr::null(), &mut size, &mut data, &mut vt);
        if rc == 5 {
            w.note = Some(lang.pick(
                "Windows masque le nom du Wi-Fi : autorisez l'accès à la localisation (Paramètres → Confidentialité → Localisation) pour l'afficher.",
                "Windows hides the Wi-Fi name: allow location access (Settings → Privacy → Location) to show it.").into());
            return;
        }
        if rc != 0 || data.is_null() {
            return;
        }
        let c = &*(data as *const WLAN_CONNECTION_ATTRIBUTES);
        let assoc = &c.wlanAssociationAttributes;
        let len = (assoc.dot11Ssid.uSSIDLength as usize).min(32);
        let ssid = String::from_utf8_lossy(&assoc.dot11Ssid.ucSSID[..len]).to_string();
        if ssid.is_empty() {
            w.note = Some(lang.pick(
                "Windows masque le nom du Wi-Fi : autorisez l'accès à la localisation (Paramètres → Confidentialité → Localisation) pour l'afficher.",
                "Windows hides the Wi-Fi name: allow location access (Settings → Privacy → Location) to show it.").into());
        } else {
            w.ssid = Some(ssid);
        }
        if assoc.dot11Bssid != [0; 6] {
            w.bssid = Some(fmt_mac(&assoc.dot11Bssid));
        }
        w.signal = Some(assoc.wlanSignalQuality);
        w.rx_mbps = Some(assoc.ulRxRate / 1000).filter(|r| *r > 0);
        w.tx_mbps = Some(assoc.ulTxRate / 1000).filter(|r| *r > 0);
        w.standard = match assoc.dot11PhyType {
            4 => Some("a"),
            5 => Some("b"),
            6 => Some("g"),
            7 => Some("n"),
            8 => Some("ac"),
            10 => Some("ax"),
            11 => Some("be"),
            _ => None,
        }
        .map(wifi_standard);
        let sec = &c.wlanSecurityAttributes;
        let cipher = sec.dot11CipherAlgorithm;
        w.cipher = match cipher {
            0 => Some(lang.pick("aucun", "none")),
            1 | 5 | 257 => Some("WEP"),
            2 => Some("TKIP"),
            4 => Some("AES (CCMP)"),
            8 | 9 => Some("AES (GCMP)"),
            10 => Some("AES (CCMP-256)"),
            _ => None,
        }
        .map(String::from);
        let (auth, security) = match sec.dot11AuthAlgorithm {
            1 if sec.bSecurityEnabled == 0 || cipher == 0 => (lang.pick("Ouvert (aucun mot de passe)", "Open (no password)"), WifiSecurity::Open),
            1 | 2 => ("WEP", WifiSecurity::Wep),
            3 => (lang.pick("WPA-Entreprise", "WPA-Enterprise"), WifiSecurity::Enterprise),
            4 => (lang.pick("WPA-Personnel", "WPA-Personal"), WifiSecurity::Wpa),
            6 => (lang.pick("WPA2-Entreprise", "WPA2-Enterprise"), WifiSecurity::Enterprise),
            7 => (lang.pick("WPA2-Personnel", "WPA2-Personal"), WifiSecurity::Wpa2),
            8 | 11 => (lang.pick("WPA3-Entreprise", "WPA3-Enterprise"), WifiSecurity::Enterprise),
            9 => (lang.pick("WPA3-Personnel", "WPA3-Personal"), WifiSecurity::Wpa3),
            10 => ("Wi-Fi Enhanced Open (OWE)", WifiSecurity::Wpa2),
            _ => ("?", WifiSecurity::Unknown),
        };
        w.auth = Some(auth.into());
        w.security = if security == WifiSecurity::Wpa && cipher == 2 { WifiSecurity::Wpa } else { security };
        WlanFreeMemory(data);

        let mut data: *mut core::ffi::c_void = std::ptr::null_mut();
        if WlanQueryInterface(h, guid, wlan_intf_opcode_channel_number, std::ptr::null(), &mut size, &mut data, &mut vt) == 0 && !data.is_null() {
            let ch = *(data as *const u32);
            if ch > 0 {
                w.channel = Some(ch);
                w.band = Some(band_of_channel(ch).into());
            }
            WlanFreeMemory(data);
        }
        let mut data: *mut core::ffi::c_void = std::ptr::null_mut();
        if WlanQueryInterface(h, guid, wlan_intf_opcode_rssi, std::ptr::null(), &mut size, &mut data, &mut vt) == 0 && !data.is_null() {
            let rssi = *(data as *const i32);
            if (-120..0).contains(&rssi) {
                w.rssi = Some(rssi);
            }
            WlanFreeMemory(data);
        }
    }

    pub fn neighbors(iface: &str) -> Vec<Neighbor> {
        let Some(a) = adapter(iface) else { return Vec::new() };
        let mut out = Vec::new();
        unsafe {
            let mut table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
            if GetIpNetTable2(AF_UNSPEC, &mut table) != 0 || table.is_null() {
                return out;
            }
            let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
            for r in rows {
                if r.InterfaceIndex != a.if_index && r.InterfaceIndex != a.v6_index {
                    continue;
                }
                if r.State < NlnsProbe || r.PhysicalAddressLength != 6 {
                    continue;
                }
                let Some(ip) = sockaddr_ip(&r.Address as *const _ as *const _) else { continue };
                let mut mac = [0u8; 6];
                mac.copy_from_slice(&r.PhysicalAddress[..6]);
                out.push(Neighbor { ip, mac });
            }
            FreeMibTable(table as *const _);
        }
        out
    }

    /// Requête ARP synchrone (≈ 1 s au maximum si l'adresse ne répond pas).
    pub fn arp(ip: Ipv4Addr) -> Option<[u8; 6]> {
        let mut buf = [0u32; 2];
        let mut len = 6u32;
        let dest = u32::from_ne_bytes(ip.octets());
        let rc = unsafe { SendARP(dest, 0, buf.as_mut_ptr() as *mut _, &mut len) };
        if rc != 0 || len != 6 {
            return None;
        }
        let b: [u8; 8] = unsafe { std::mem::transmute(buf) };
        let mac = [b[0], b[1], b[2], b[3], b[4], b[5]];
        (mac != [0; 6]).then_some(mac)
    }

}

#[cfg(windows)]
pub use windows::arp;

#[cfg(windows)]
fn platform_info(iface: &str, out: &mut NetworkInfo, lang: Lang) {
    windows::fill(iface, out, lang);
}

#[cfg(windows)]
fn platform_neighbors(iface: &str) -> Vec<Neighbor> {
    windows::neighbors(iface)
}

// ---------------------------------------------------------------------------
// Linux et macOS : fichiers du système et commandes standard
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(cmd).args(args).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(unix)]
fn resolv_conf() -> Vec<String> {
    let parse = |path: &str| -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.trim().strip_prefix("nameserver"))
            .map(|s| s.trim().to_string())
            .filter(|s| s.parse::<IpAddr>().is_ok())
            .collect()
    };
    let main = parse("/etc/resolv.conf");
    // systemd-resolved : la vraie liste est ailleurs.
    if main.iter().all(|s| s.starts_with("127.")) {
        let real = parse("/run/systemd/resolve/resolv.conf");
        if !real.is_empty() {
            return real;
        }
    }
    main
}

#[cfg(target_os = "linux")]
fn platform_info(iface: &str, out: &mut NetworkInfo, lang: Lang) {
    let sys = |f: &str| std::fs::read_to_string(format!("/sys/class/net/{iface}/{f}")).ok().map(|s| s.trim().to_string());
    out.mac = sys("address").filter(|m| m != "00:00:00:00:00:00");
    out.mtu = sys("mtu").and_then(|m| m.parse().ok());
    out.speed_mbps = sys("speed").and_then(|s| s.parse::<i64>().ok()).filter(|s| *s > 0).map(|s| s as u64);
    if let Ok(route) = std::fs::read_to_string("/proc/net/route") {
        for l in route.lines().skip(1) {
            let c: Vec<&str> = l.split_whitespace().collect();
            if c.len() > 2 && c[0] == iface && c[1] == "00000000" {
                if let Ok(g) = u32::from_str_radix(c[2], 16) {
                    out.gateway = Some(Ipv4Addr::from(g.to_le_bytes()).to_string());
                    break;
                }
            }
        }
    }
    if let Ok(route) = std::fs::read_to_string("/proc/net/ipv6_route") {
        for l in route.lines() {
            let c: Vec<&str> = l.split_whitespace().collect();
            if c.len() >= 10 && c[9] == iface && c[1] == "00" && c[0].chars().all(|x| x == '0') && !c[4].chars().all(|x| x == '0') {
                if let Ok(v) = u128::from_str_radix(c[4], 16) {
                    out.gateway_v6 = Some(Ipv6Addr::from(v).to_string());
                    break;
                }
            }
        }
    }
    out.dns = resolv_conf();
    if std::path::Path::new(&format!("/sys/class/net/{iface}/wireless")).exists() {
        out.wifi = Some(linux_wifi(iface, lang));
    }
}

#[cfg(target_os = "linux")]
fn linux_wifi(iface: &str, lang: Lang) -> WifiInfo {
    let mut w = WifiInfo::default();
    // nmcli échappe « : » en « \: » dans les champs (BSSID).
    if let Some(txt) = run("nmcli", &["-t", "-f", "ACTIVE,SSID,BSSID,CHAN,FREQ,RATE,SIGNAL,SECURITY", "dev", "wifi", "list", "ifname", iface, "--rescan", "no"]) {
        for line in txt.lines() {
            let fields: Vec<String> = line.replace("\\:", "\u{1}").split(':').map(|s| s.replace('\u{1}', ":")).collect();
            if fields.len() >= 8 && fields[0] == "yes" {
                w.ssid = Some(fields[1].clone()).filter(|s| !s.is_empty());
                w.bssid = Some(fields[2].to_lowercase()).filter(|s| !s.is_empty());
                w.channel = fields[3].parse().ok();
                let freq: Option<u32> = fields[4].split_whitespace().next().and_then(|f| f.parse().ok());
                w.band = freq.map(|f| band_of_freq(f).into()).or_else(|| w.channel.map(|c| band_of_channel(c).into()));
                w.rx_mbps = fields[5].split_whitespace().next().and_then(|r| r.parse().ok());
                w.signal = fields[6].parse().ok();
                w.auth = Some(fields[7].clone()).filter(|s| !s.is_empty());
                w.security = security_from_text(&fields[7]);
                return w;
            }
        }
    }
    if let Some(txt) = run("iw", &["dev", iface, "link"]) {
        for l in txt.lines().map(|l| l.trim()) {
            if let Some(v) = l.strip_prefix("SSID:") {
                w.ssid = Some(v.trim().to_string());
            } else if let Some(v) = l.strip_prefix("freq:") {
                w.band = v.trim().split('.').next().and_then(|f| f.parse().ok()).map(|f| band_of_freq(f).into());
            } else if let Some(v) = l.strip_prefix("signal:") {
                w.rssi = v.split_whitespace().next().and_then(|s| s.parse().ok());
            } else if let Some(v) = l.strip_prefix("tx bitrate:") {
                w.tx_mbps = v.split_whitespace().next().and_then(|s| s.parse::<f64>().ok()).map(|f| f as u32);
            } else if let Some(v) = l.strip_prefix("Connected to") {
                w.bssid = v.split_whitespace().next().map(|s| s.to_string());
            }
        }
        w.note = Some(lang.pick("Type de sécurité inconnu (installez NetworkManager pour l'afficher).", "Security type unknown (install NetworkManager to show it).").into());
    }
    w
}

#[cfg(target_os = "linux")]
fn platform_neighbors(iface: &str) -> Vec<Neighbor> {
    let mut out = Vec::new();
    if let Ok(t) = std::fs::read_to_string("/proc/net/arp") {
        for l in t.lines().skip(1) {
            let c: Vec<&str> = l.split_whitespace().collect();
            if c.len() >= 6 && c[5] == iface && c[2] != "0x0" {
                if let (Ok(ip), Some(mac)) = (c[0].parse::<Ipv4Addr>(), oui::parse_mac(c[3])) {
                    out.push(Neighbor { ip: IpAddr::V4(ip), mac });
                }
            }
        }
    }
    if let Some(t) = run("ip", &["-6", "neigh", "show", "dev", iface]) {
        for l in t.lines() {
            let c: Vec<&str> = l.split_whitespace().collect();
            if let (Some(ip), Some(pos)) = (c.first().and_then(|s| s.parse::<IpAddr>().ok()), c.iter().position(|x| *x == "lladdr")) {
                if l.contains("FAILED") || l.contains("INCOMPLETE") {
                    continue;
                }
                if let Some(mac) = c.get(pos + 1).and_then(|m| oui::parse_mac(m)) {
                    out.push(Neighbor { ip, mac });
                }
            }
        }
    }
    out
}

#[cfg(target_os = "macos")]
fn platform_info(iface: &str, out: &mut NetworkInfo, lang: Lang) {
    if let Some(t) = run("ifconfig", &[iface]) {
        for l in t.lines().map(|l| l.trim()) {
            if let Some(v) = l.strip_prefix("ether ") {
                out.mac = Some(v.trim().to_string());
            }
            if let Some(pos) = l.find(" mtu ") {
                out.mtu = l[pos + 5..].split_whitespace().next().and_then(|m| m.parse().ok());
            }
        }
    }
    if let Some(t) = run("route", &["-n", "get", "default"]) {
        let get = |k: &str| t.lines().find_map(|l| l.trim().strip_prefix(k).map(|v| v.trim().to_string()));
        if get("interface:").as_deref() == Some(iface) {
            out.gateway = get("gateway:");
        }
    }
    out.dns = resolv_conf();
    if let Some(t) = run("ipconfig", &["getoption", iface, "server_identifier"]) {
        out.dhcp_server = Some(t.trim().to_string()).filter(|s| s.parse::<IpAddr>().is_ok());
        out.dhcp = Some(out.dhcp_server.is_some());
    }
    if let Some(t) = run("networksetup", &["-listallhardwareports"]) {
        let wifi_dev = t.split("\n\n").find(|b| b.contains("Wi-Fi") || b.contains("AirPort")).and_then(|b| b.lines().find_map(|l| l.strip_prefix("Device: ")));
        if wifi_dev.map(|d| d.trim()) == Some(iface) {
            out.wifi = Some(mac_wifi(lang));
        }
    }
}

#[cfg(target_os = "macos")]
fn mac_wifi(lang: Lang) -> WifiInfo {
    let mut w = WifiInfo::default();
    let Some(t) = run("system_profiler", &["SPAirPortDataType"]) else { return w };
    let Some(start) = t.find("Current Network Information:") else { return w };
    let lines: Vec<&str> = t[start..].lines().skip(1).collect();
    if let Some(first) = lines.first() {
        let name = first.trim().trim_end_matches(':');
        if !name.is_empty() && name != "<redacted>" {
            w.ssid = Some(name.to_string());
        } else {
            w.note = Some(lang.pick("macOS masque le nom du Wi-Fi sans autorisation de localisation.", "macOS hides the Wi-Fi name without location permission.").into());
        }
    }
    for l in lines.iter().skip(1).take(14).map(|l| l.trim()) {
        if let Some(v) = l.strip_prefix("PHY Mode: 802.11") {
            w.standard = Some(wifi_standard(v.trim()));
        } else if let Some(v) = l.strip_prefix("Channel: ") {
            w.channel = v.split_whitespace().next().and_then(|c| c.parse().ok());
            w.band = if v.contains("6GHz") { Some("6 GHz".into()) } else if v.contains("5GHz") { Some("5 GHz".into()) } else { w.channel.map(|c| band_of_channel(c).into()) };
        } else if let Some(v) = l.strip_prefix("Security: ") {
            w.auth = Some(v.trim().to_string());
            w.security = security_from_text(v);
        } else if let Some(v) = l.strip_prefix("Signal / Noise: ") {
            w.rssi = v.split_whitespace().next().and_then(|s| s.parse().ok());
        } else if let Some(v) = l.strip_prefix("Transmit Rate: ") {
            w.tx_mbps = v.trim().parse().ok();
        }
    }
    w
}

#[cfg(target_os = "macos")]
fn platform_neighbors(iface: &str) -> Vec<Neighbor> {
    let mut out = Vec::new();
    if let Some(t) = run("arp", &["-an", "-i", iface]) {
        for l in t.lines() {
            // ? (192.168.1.1) at a4:3e:51:0:a:ff on en0 ifscope [ethernet]
            let ip = l.split('(').nth(1).and_then(|r| r.split(')').next()).and_then(|s| s.parse::<Ipv4Addr>().ok());
            let mac = l.split(" at ").nth(1).and_then(|r| r.split_whitespace().next()).and_then(oui::parse_mac);
            if let (Some(ip), Some(mac)) = (ip, mac) {
                out.push(Neighbor { ip: IpAddr::V4(ip), mac });
            }
        }
    }
    if let Some(t) = run("ndp", &["-an"]) {
        for l in t.lines().skip(1) {
            let c: Vec<&str> = l.split_whitespace().collect();
            if c.len() >= 3 && c[2] == iface {
                let ip = c[0].split('%').next().and_then(|s| s.parse::<IpAddr>().ok());
                if let (Some(ip), Some(mac)) = (ip, oui::parse_mac(c[1])) {
                    out.push(Neighbor { ip, mac });
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_math() {
        let s = Subnet { ip: Ipv4Addr::new(192, 168, 1, 37), prefix: 24 };
        assert_eq!(s.cidr(), "192.168.1.0/24");
        assert_eq!(s.broadcast(), Ipv4Addr::new(192, 168, 1, 255));
        assert_eq!(s.host_count(), 254);
        assert!(s.contains(&"192.168.1.1".parse().unwrap()));
        assert!(!s.contains(&"192.168.2.1".parse().unwrap()));
        assert!(!s.contains(&"192.168.1.255".parse().unwrap()));
        assert_eq!(mask_prefix(&"255.255.252.0".parse().unwrap()), Some(22));
        assert_eq!(mask_prefix(&"255.0.255.0".parse().unwrap()), None);
    }

    #[test]
    fn wifi_security_labels() {
        assert_eq!(security_from_text("WPA2 WPA3"), WifiSecurity::Wpa3);
        assert_eq!(security_from_text("WPA2 Personal"), WifiSecurity::Wpa2);
        assert_eq!(security_from_text("WPA1 802.1X"), WifiSecurity::Enterprise);
        assert_eq!(security_from_text(""), WifiSecurity::Open);
        assert_eq!(band_of_freq(5180), "5 GHz");
    }
}
