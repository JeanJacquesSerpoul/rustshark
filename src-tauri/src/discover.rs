//! Découverte des appareils du réseau local : balayage ARP, annonces mDNS
//! et UPnP, noms NetBIOS, DNS inverse et ports ouverts.
//!
//! Tout reste sur le réseau local : aucune adresse publique n'est contactée.

use std::collections::{BTreeSet, HashMap};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rustshark_shared::{CheckLevel, DeviceKind, DeviceList, Lang, NetDevice, NetworkInfo, PortInfo};

use crate::apps::{self, DnsInfo};
use crate::dissect::{fmt_mac, is_private};
use crate::netinfo::{self, Subnet};
use crate::oui;
use crate::store::Store;

/// Rapport de progression : (phase, fait, total).
pub type Progress<'a> = &'a (dyn Fn(&str, u32, u32) + Sync);

/// Ce que l'analyse active a appris sur une adresse.
#[derive(Clone, Debug, Default)]
pub struct Host {
    pub mac: Option<[u8; 6]>,
    /// (rang, origine, nom) : plus le rang est petit, plus le nom est parlant.
    pub names: Vec<(u8, &'static str, String)>,
    /// Types de services mDNS (« _googlecast._tcp »).
    pub services: BTreeSet<String>,
    pub model: Option<String>,
    pub manufacturer: Option<String>,
    /// Types UPnP annoncés (en-têtes ST et deviceType).
    pub upnp: BTreeSet<String>,
    pub server: Option<String>,
    pub alive: bool,
}

impl Host {
    fn name(&mut self, rank: u8, origin: &'static str, name: &str) {
        let n = clean_name(name);
        if n.is_empty() || self.names.iter().any(|(_, o, x)| *o == origin && x.eq_ignore_ascii_case(&n)) {
            return;
        }
        self.names.push((rank, origin, n));
    }
}

/// Résultats conservés entre deux affichages (par interface).
#[derive(Clone, Debug, Default)]
pub struct Cache {
    pub at: Option<String>,
    pub duration: Option<f64>,
    pub network: Option<String>,
    pub note: Option<String>,
    pub hosts: HashMap<IpAddr, Host>,
    pub ports: HashMap<IpAddr, Vec<PortInfo>>,
    /// La box a répondu comme passerelle UPnP (ouverture automatique de ports).
    pub igd: Option<bool>,
}

/// Nom propre, ou vide s'il n'apprend rien (« linux-2 », « SpotifyConnect #3 »).
fn clean_name(s: &str) -> String {
    let s = s.trim().trim_end_matches('.');
    let s = s.strip_suffix(".local").unwrap_or(s);
    let s: String = s.chars().filter(|c| !c.is_control()).collect::<String>().trim().to_string();
    let base = s.to_lowercase();
    let base = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '-' || c == '#' || c == ' ' || c == '_');
    const GENERIC: &[&str] = &["linux", "none", "localhost", "android", "unknown", "spotifyconnect", "esp", "espressif", "host", "device", "client", "default", "mdns"];
    if base.is_empty() || GENERIC.contains(&base) {
        return String::new();
    }
    s
}

/// Nombre maximal d'adresses balayées (un /22).
const MAX_HOSTS: u32 = 1022;

pub fn scan(iface: &str, info: &NetworkInfo, lang: Lang, progress: Progress) -> Result<Cache, String> {
    let started = Instant::now();
    let Some(mut subnet) = netinfo::subnet_of(iface) else {
        return Err(lang.pick("Cette connexion n'a pas d'adresse IPv4 : impossible d'analyser le réseau.", "This connection has no IPv4 address: cannot scan the network.").into());
    };
    let mut note = None;
    if subnet.host_count() > MAX_HOSTS {
        subnet.prefix = 22;
        note = Some(match lang {
            Lang::Fr => format!("Réseau très grand : analyse limitée aux {MAX_HOSTS} adresses voisines ({}).", subnet.cidr()),
            Lang::En => format!("Very large network: scan limited to the {MAX_HOSTS} neighbouring addresses ({}).", subnet.cidr()),
        });
    }
    let base = u32::from(subnet.network());
    let targets: Vec<Ipv4Addr> = (1..=subnet.host_count()).map(|i| Ipv4Addr::from(base + i)).filter(|ip| *ip != subnet.ip).collect();
    let mut hosts: HashMap<IpAddr, Host> = HashMap::new();

    progress("sweep", 0, targets.len() as u32);
    for (ip, mac) in sweep(iface, &subnet, &targets, progress) {
        let h = hosts.entry(IpAddr::V4(ip)).or_default();
        h.mac = Some(mac);
        h.alive = true;
    }
    for n in netinfo::neighbors(iface) {
        if subnet.contains(&n.ip) {
            hosts.entry(n.ip).or_default().mac.get_or_insert(n.mac);
        }
    }

    // Les noms : quatre sondes en parallèle, chacune limitée à quelques secondes.
    progress("names", 0, 4);
    let live: Vec<Ipv4Addr> = hosts.keys().filter_map(|ip| match ip {
        IpAddr::V4(a) => Some(*a),
        _ => None,
    }).collect();
    let gateway = info.gateway.as_deref().and_then(|g| g.parse::<Ipv4Addr>().ok());
    let mut dns_servers: Vec<Ipv4Addr> = info.dns.iter().filter_map(|d| d.parse::<Ipv4Addr>().ok()).filter(|d| is_private(&IpAddr::V4(*d))).collect();
    if let Some(g) = gateway {
        if !dns_servers.contains(&g) {
            dns_servers.push(g);
        }
    }
    let found = Mutex::new(HashMap::<IpAddr, Host>::new());
    let step = AtomicUsize::new(0);
    let tick = || progress("names", step.fetch_add(1, Ordering::SeqCst) as u32 + 1, 4);
    std::thread::scope(|s| {
        s.spawn(|| {
            mdns(subnet.ip, &found);
            tick();
        });
        s.spawn(|| {
            ssdp(subnet.ip, &found, "ssdp:all");
            tick();
        });
        s.spawn(|| {
            netbios(subnet.ip, &live, &found);
            tick();
        });
        s.spawn(|| {
            reverse_dns(subnet.ip, &live, &dns_servers, &found);
            tick();
        });
    });
    for (ip, f) in found.into_inner() {
        // Un appareil qui répond à mDNS ou UPnP est en ligne, même sans ARP (autre interface…).
        if !subnet.contains(&ip) {
            continue;
        }
        let h = hosts.entry(ip).or_default();
        h.alive = true;
        for (r, o, n) in f.names {
            h.name(r, o, &n);
        }
        h.services.extend(f.services);
        h.upnp.extend(f.upnp);
        h.model = h.model.take().or(f.model);
        h.manufacturer = h.manufacturer.take().or(f.manufacturer);
        h.server = h.server.take().or(f.server);
        if h.mac.is_none() {
            h.mac = f.mac;
        }
    }
    let igd = gateway.map(|g| hosts.get(&IpAddr::V4(g)).map(|h| h.upnp.iter().any(|t| t.contains("InternetGatewayDevice") || t.contains("WANIPConnection"))).unwrap_or(false));
    Ok(Cache {
        at: Some(chrono::Local::now().format("%H:%M").to_string()),
        duration: Some(started.elapsed().as_secs_f64()),
        network: Some(subnet.cidr()),
        note,
        hosts,
        ports: HashMap::new(),
        igd,
    })
}

// ---------------------------------------------------------------------------
// Balayage ARP
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn sweep(_iface: &str, _subnet: &Subnet, targets: &[Ipv4Addr], progress: Progress) -> HashMap<Ipv4Addr, [u8; 6]> {
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let found = Mutex::new(HashMap::new());
    let total = targets.len();
    std::thread::scope(|s| {
        for _ in 0..total.clamp(1, 128) {
            let worker = || loop {
                let i = next.fetch_add(1, Ordering::SeqCst);
                if i >= total {
                    break;
                }
                if let Some(mac) = netinfo::arp(targets[i]) {
                    found.lock().insert(targets[i], mac);
                }
                let d = done.fetch_add(1, Ordering::SeqCst) + 1;
                if d % 8 == 0 || d == total {
                    progress("sweep", d as u32, total as u32);
                }
            };
            let _ = std::thread::Builder::new().stack_size(128 * 1024).spawn_scoped(s, worker);
        }
    });
    found.into_inner()
}

/// Un datagramme vers chaque adresse oblige le système à la résoudre en ARP ;
/// la table des voisins contient ensuite les appareils présents.
#[cfg(unix)]
fn sweep(iface: &str, subnet: &Subnet, targets: &[Ipv4Addr], progress: Progress) -> HashMap<Ipv4Addr, [u8; 6]> {
    if let Ok(sock) = UdpSocket::bind((subnet.ip, 0)) {
        for (i, ip) in targets.iter().enumerate() {
            let _ = sock.send_to(&[0], (*ip, 9));
            if i % 32 == 31 {
                std::thread::sleep(Duration::from_millis(4));
                progress("sweep", (i / 2) as u32, targets.len() as u32);
            }
        }
    }
    std::thread::sleep(Duration::from_millis(1800));
    progress("sweep", targets.len() as u32, targets.len() as u32);
    netinfo::neighbors(iface)
        .into_iter()
        .filter_map(|n| match n.ip {
            IpAddr::V4(a) if subnet.contains(&n.ip) => Some((a, n.mac)),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Requêtes DNS / mDNS
// ---------------------------------------------------------------------------

fn dns_query(id: u16, name: &str, qtype: u16, recursion: bool) -> Vec<u8> {
    let mut q = Vec::with_capacity(64);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&(if recursion { 0x0100u16 } else { 0 }).to_be_bytes());
    q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.').filter(|l| !l.is_empty()) {
        q.push(label.len().min(63) as u8);
        q.extend_from_slice(&label.as_bytes()[..label.len().min(63)]);
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q
}

/// Lit les réponses d'un socket jusqu'à l'échéance.
fn collect(sock: &UdpSocket, wait: Duration, mut f: impl FnMut(IpAddr, &[u8])) {
    let deadline = Instant::now() + wait;
    let mut buf = vec![0u8; 9000];
    while Instant::now() < deadline {
        let _ = sock.set_read_timeout(Some((deadline - Instant::now()).max(Duration::from_millis(5))));
        match sock.recv_from(&mut buf) {
            Ok((n, SocketAddr::V4(a))) => f(IpAddr::V4(*a.ip()), &buf[..n]),
            Ok(_) => {}
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => break,
            // Windows signale par une erreur les « port injoignable » reçus en ICMP.
            Err(_) => continue,
        }
    }
}

const MDNS_TYPES: &[&str] = &[
    "_services._dns-sd._udp", "_device-info._tcp", "_airplay._tcp", "_raop._tcp", "_googlecast._tcp",
    "_companion-link._tcp", "_apple-mobdev2._tcp", "_rdlink._tcp", "_ipp._tcp", "_printer._tcp", "_pdl-datastream._tcp",
    "_smb._tcp", "_hap._tcp", "_matter._tcp", "_hue._tcp", "_spotify-connect._tcp", "_sonos._tcp", "_amzn-wplay._tcp",
    "_androidtvremote2._tcp", "_workstation._tcp", "_ssh._tcp", "_http._tcp", "_esphomelib._tcp", "_home-assistant._tcp",
];

fn mdns(local: Ipv4Addr, found: &Mutex<HashMap<IpAddr, Host>>) {
    let Ok(sock) = UdpSocket::bind((local, 0)) else { return };
    let dest = (Ipv4Addr::new(224, 0, 0, 251), 5353);
    let mut handle = |src: IpAddr, data: &[u8]| {
        if let Some(info) = apps::parse_dns(data).filter(|i| i.response) {
            let mut map = found.lock();
            mdns_records(src, &info, &mut map);
        }
    };
    for round in 0..2 {
        for (i, t) in MDNS_TYPES.iter().enumerate() {
            let _ = sock.send_to(&dns_query(i as u16, &format!("{t}.local"), 12, false), dest);
        }
        collect(&sock, Duration::from_millis(if round == 0 { 1200 } else { 1500 }), &mut handle);
    }
}

fn txt_get<'a>(txt: &'a [String], key: &str) -> Option<&'a str> {
    txt.iter().find_map(|t| t.split_once('=').filter(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v)).filter(|v| !v.is_empty())
}

fn mdns_records(src: IpAddr, info: &DnsInfo, map: &mut HashMap<IpAddr, Host>) {
    for rr in &info.answers {
        match rr.rtype {
            // Adresse annoncée par l'appareil lui-même : son nom d'hôte.
            1 | 28 => {
                if let Some(ip) = rr.ip {
                    let target = if ip.is_ipv4() { ip } else { src };
                    map.entry(target).or_default().name(3, "mDNS", &rr.name);
                }
            }
            12 => {
                let h = map.entry(src).or_default();
                if rr.name.starts_with("_services._dns-sd") {
                    h.services.insert(rr.data.trim_end_matches(".local").to_string());
                } else if let Some(svc) = rr.name.strip_suffix(".local").filter(|n| n.starts_with('_')) {
                    h.services.insert(svc.to_string());
                    if let Some(inst) = rr.data.strip_suffix(&format!(".{}", rr.name)) {
                        // AirPlay audio : « 1A2B3C4D5E6F@Salon ».
                        let inst = inst.split_once('@').map(|(_, n)| n).unwrap_or(inst);
                        // Les noms d'instance génériques (« SpotifyConnect #2 ») passent en dernier.
                        let rank = match svc {
                            "_googlecast._tcp" | "_http._tcp" | "_ssh._tcp" | "_hap._tcp" | "_matter._tcp" => 2,
                            "_spotify-connect._tcp" => 5,
                            _ => 1,
                        };
                        h.name(rank, "mDNS", inst);
                    }
                }
            }
            33 => {
                if let Some((host, _)) = rr.data.rsplit_once(':') {
                    map.entry(src).or_default().name(3, "mDNS", host);
                }
            }
            16 => {
                let h = map.entry(src).or_default();
                if let Some(f) = txt_get(&rr.txt, "fn") {
                    h.name(0, "mDNS", f);
                }
                for key in ["model", "am", "md", "ty", "usb_MDL"] {
                    if let Some(m) = txt_get(&rr.txt, key) {
                        if h.model.is_none() {
                            h.model = Some(apple_model(m).map(String::from).unwrap_or_else(|| m.trim_matches(|c| c == '(' || c == ')').to_string()));
                        }
                    }
                }
                if let Some(m) = txt_get(&rr.txt, "usb_MFG") {
                    h.manufacturer.get_or_insert(m.to_string());
                }
            }
            _ => {}
        }
    }
}

/// Nom commercial d'un identifiant de modèle Apple (« iPhone14,2 »).
fn apple_model(id: &str) -> Option<&'static str> {
    let rules: &[(&str, &str)] = &[
        ("iPhone", "iPhone"), ("iPad", "iPad"), ("iPod", "iPod touch"), ("MacBookPro", "MacBook Pro"), ("MacBookAir", "MacBook Air"),
        ("MacBook", "MacBook"), ("Macmini", "Mac mini"), ("MacPro", "Mac Pro"), ("iMac", "iMac"), ("Mac", "Mac"), ("AppleTV", "Apple TV"),
        ("AudioAccessory1", "HomePod"), ("AudioAccessory5", "HomePod mini"), ("AudioAccessory6", "HomePod"), ("AudioAccessory", "HomePod"),
        ("Watch", "Apple Watch"), ("RealityDevice", "Apple Vision Pro"), ("AirPort", "Borne AirPort"),
    ];
    let has_digit = id.chars().any(|c| c.is_ascii_digit());
    rules.iter().find(|(p, _)| id.starts_with(p) && has_digit).map(|(_, n)| *n)
}

// ---------------------------------------------------------------------------
// UPnP (SSDP)
// ---------------------------------------------------------------------------

fn header<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case(name)).map(|(_, v)| v.trim()))
}

fn ssdp(local: Ipv4Addr, found: &Mutex<HashMap<IpAddr, Host>>, st: &str) {
    let Ok(sock) = UdpSocket::bind((local, 0)) else { return };
    let msg = format!("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {st}\r\n\r\n");
    let mut locations: HashMap<IpAddr, String> = HashMap::new();
    for _ in 0..2 {
        let _ = sock.send_to(msg.as_bytes(), (Ipv4Addr::new(239, 255, 255, 250), 1900));
        collect(&sock, Duration::from_millis(1300), |src, data| {
            let text = String::from_utf8_lossy(data);
            let mut map = found.lock();
            let h = map.entry(src).or_default();
            if let Some(st) = header(&text, "ST") {
                h.upnp.insert(st.to_string());
            }
            if let Some(s) = header(&text, "SERVER") {
                h.server.get_or_insert(s.to_string());
            }
            if let Some(loc) = header(&text, "LOCATION") {
                locations.entry(src).or_insert_with(|| loc.to_string());
            }
        });
    }
    // Description XML de chaque appareil (nom, fabricant, modèle).
    std::thread::scope(|s| {
        for (ip, url) in &locations {
            s.spawn(move || {
                let Some(xml) = http_get_local(*ip, url) else { return };
                let mut map = found.lock();
                let h = map.entry(*ip).or_default();
                if let Some(n) = xml_tag(&xml, "friendlyName") {
                    h.name(1, "UPnP", &n);
                }
                h.manufacturer = h.manufacturer.take().or(xml_tag(&xml, "manufacturer"));
                if let Some(m) = xml_tag(&xml, "modelName") {
                    let full = match xml_tag(&xml, "modelNumber") {
                        Some(num) if !m.contains(&num) && num.len() < 20 => format!("{m} {num}"),
                        _ => m,
                    };
                    h.model.get_or_insert(full);
                }
                if let Some(t) = xml_tag(&xml, "deviceType") {
                    h.upnp.insert(t);
                }
            });
        }
    });
}

fn xml_tag(xml: &str, tag: &str) -> Option<String> {
    let start = xml.find(&format!("<{tag}>"))? + tag.len() + 2;
    let end = start + xml[start..].find("</")?;
    let v = xml[start..end].trim().replace("&amp;", "&").replace("&apos;", "'").replace("&quot;", "\"").replace("&lt;", "<").replace("&gt;", ">");
    (!v.is_empty() && v.len() < 120).then_some(v)
}

/// GET HTTP minimal, uniquement vers l'appareil qui a répondu (adresse privée).
fn http_get_local(ip: IpAddr, url: &str) -> Option<String> {
    let rest = url.strip_prefix("http://")?;
    let (hostport, path) = rest.split_once('/').map(|(h, p)| (h, format!("/{p}"))).unwrap_or((rest, "/".into()));
    let port: u16 = hostport.rsplit_once(':').and_then(|(_, p)| p.parse().ok()).unwrap_or(80);
    let host = hostport.rsplit_once(':').map(|(h, _)| h).unwrap_or(hostport);
    if host.parse::<IpAddr>().ok() != Some(ip) || !is_private(&ip) {
        return None;
    }
    let mut s = TcpStream::connect_timeout(&SocketAddr::new(ip, port), Duration::from_millis(1500)).ok()?;
    s.set_read_timeout(Some(Duration::from_millis(2000))).ok()?;
    write!(s, "GET {path} HTTP/1.0\r\nHost: {hostport}\r\nUser-Agent: RustShark\r\nConnection: close\r\n\r\n").ok()?;
    let mut buf = Vec::new();
    let _ = s.take(256 * 1024).read_to_end(&mut buf);
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// La box se présente-t-elle comme passerelle UPnP ?
pub fn gateway_upnp(local: Ipv4Addr, gateway: Ipv4Addr) -> bool {
    let found = Mutex::new(HashMap::new());
    ssdp(local, &found, "urn:schemas-upnp-org:device:InternetGatewayDevice:1");
    let map = found.into_inner();
    map.get(&IpAddr::V4(gateway)).is_some_and(|h| h.upnp.iter().any(|t| t.contains("InternetGatewayDevice") || t.contains("WAN")))
}

// ---------------------------------------------------------------------------
// NetBIOS et DNS inverse
// ---------------------------------------------------------------------------

fn netbios(local: Ipv4Addr, targets: &[Ipv4Addr], found: &Mutex<HashMap<IpAddr, Host>>) {
    let Ok(sock) = UdpSocket::bind((local, 0)) else { return };
    // Requête « NBSTAT » pour le nom générique « * ».
    let mut q = vec![0x52, 0x53, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20, b'C', b'K'];
    q.extend(std::iter::repeat_n(b'A', 30));
    q.extend_from_slice(&[0, 0, 0x21, 0, 1]);
    for ip in targets {
        let _ = sock.send_to(&q, (*ip, 137));
    }
    collect(&sock, Duration::from_millis(1500), |src, d| {
        if let Some(name) = parse_nbstat(d) {
            found.lock().entry(src).or_default().name(2, "NetBIOS", &name);
        }
    });
}

fn parse_nbstat(d: &[u8]) -> Option<String> {
    let mut o = 12;
    o += if *d.get(o)? == 0x20 { 34 } else { 2 };
    o += 2 + 2 + 4 + 2;
    let count = *d.get(o)? as usize;
    o += 1;
    for i in 0..count {
        let e = d.get(o + i * 18..o + i * 18 + 18)?;
        let (suffix, flags) = (e[15], u16::from_be_bytes([e[16], e[17]]));
        if suffix == 0 && flags & 0x8000 == 0 {
            let n = String::from_utf8_lossy(&e[..15]).trim().to_string();
            if !n.is_empty() {
                return Some(n);
            }
        }
    }
    None
}

fn reverse_dns(local: Ipv4Addr, targets: &[Ipv4Addr], servers: &[Ipv4Addr], found: &Mutex<HashMap<IpAddr, Host>>) {
    if servers.is_empty() {
        return;
    }
    let Ok(sock) = UdpSocket::bind((local, 0)) else { return };
    for (i, ip) in targets.iter().enumerate() {
        let o = ip.octets();
        let q = dns_query(i as u16, &format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]), 12, true);
        for s in servers.iter().take(2) {
            let _ = sock.send_to(&q, (*s, 53));
        }
    }
    collect(&sock, Duration::from_millis(1500), |_, d| {
        let Some(info) = apps::parse_dns(d).filter(|i| i.response && i.rcode == 0) else { return };
        let Some(ip) = targets.get(info.id as usize) else { return };
        if let Some(rr) = info.answers.iter().find(|a| a.rtype == 12) {
            // « iPhone-de-Lea.home » → « iPhone-de-Lea » ; les noms génériques sont ignorés.
            let first = rr.data.split('.').next().unwrap_or("");
            if !first.is_empty() && !first.chars().all(|c| c.is_ascii_digit() || c == '-') {
                found.lock().entry(IpAddr::V4(*ip)).or_default().name(4, "DNS", first);
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Ports ouverts
// ---------------------------------------------------------------------------

struct PortDef {
    port: u16,
    service: &'static str,
    level: CheckLevel,
    fr: &'static str,
    en: &'static str,
}

macro_rules! ports {
    ($($port:expr, $svc:expr, $lvl:ident, $fr:expr, $en:expr;)*) => {
        const PORTS: &[PortDef] = &[$(PortDef { port: $port, service: $svc, level: CheckLevel::$lvl, fr: $fr, en: $en },)*];
    };
}

ports! {
    21, "FTP", Warning, "Transfert de fichiers non chiffré : les mots de passe circulent en clair.", "Unencrypted file transfer: passwords travel in clear text.";
    22, "SSH", Info, "Accès à distance sécurisé. Vérifiez que le mot de passe est solide.", "Secure remote access. Make sure the password is strong.";
    23, "Telnet", Danger, "Accès à distance NON chiffré, cible favorite des virus d'objets connectés (Mirai). À désactiver.", "UNENCRYPTED remote access, a favourite target of IoT malware (Mirai). Disable it.";
    25, "SMTP", Info, "Serveur d'envoi d'e-mails.", "E-mail sending server.";
    53, "DNS", Ok, "Annuaire DNS (normal pour une box).", "DNS directory (normal for a router).";
    80, "HTTP", Info, "Page web non chiffrée (souvent l'interface d'administration).", "Unencrypted web page (often the admin interface).";
    110, "POP3", Warning, "Réception d'e-mails non chiffrée.", "Unencrypted e-mail retrieval.";
    135, "RPC", Info, "Service Windows (appel de procédures à distance).", "Windows service (remote procedure call).";
    139, "NetBIOS", Info, "Ancien partage de fichiers Windows.", "Legacy Windows file sharing.";
    143, "IMAP", Warning, "Boîte e-mail non chiffrée.", "Unencrypted mailbox.";
    443, "HTTPS", Ok, "Page web sécurisée.", "Secure web page.";
    445, "SMB", Info, "Partage de fichiers Windows : à n'ouvrir qu'aux appareils de confiance.", "Windows file sharing: only open it to trusted devices.";
    515, "LPD", Ok, "Impression.", "Printing.";
    548, "AFP", Info, "Partage de fichiers Apple.", "Apple file sharing.";
    554, "RTSP", Warning, "Flux vidéo (caméra) : vérifiez qu'il est protégé par un mot de passe.", "Video stream (camera): make sure it is password-protected.";
    631, "IPP", Ok, "Impression.", "Printing.";
    1400, "Sonos", Ok, "Commande des enceintes Sonos.", "Sonos speaker control.";
    1883, "MQTT", Warning, "Messagerie d'objets connectés sans chiffrement.", "Unencrypted IoT messaging.";
    2049, "NFS", Info, "Partage de fichiers (Linux/NAS).", "File sharing (Linux/NAS).";
    3306, "MySQL", Warning, "Base de données accessible sur le réseau.", "Database reachable over the network.";
    3389, "RDP", Warning, "Bureau à distance Windows : cible fréquente d'attaques s'il est exposé.", "Windows remote desktop: a frequent attack target when exposed.";
    5000, "UPnP / web", Info, "Interface web (NAS, UPnP…).", "Web interface (NAS, UPnP…).";
    5001, "HTTPS (NAS)", Ok, "Interface web sécurisée (NAS).", "Secure web interface (NAS).";
    5432, "PostgreSQL", Warning, "Base de données accessible sur le réseau.", "Database reachable over the network.";
    5555, "ADB", Danger, "Débogage Android ouvert : n'importe qui sur le réseau peut prendre le contrôle de l'appareil.", "Android debugging open: anyone on the network can take control of the device.";
    5900, "VNC", Warning, "Contrôle à distance de l'écran : exigez un mot de passe solide.", "Remote screen control: require a strong password.";
    7000, "AirPlay", Ok, "Réception AirPlay.", "AirPlay receiver.";
    7547, "TR-069", Info, "Gestion à distance de la box par l'opérateur.", "Remote management of the router by the ISP.";
    8008, "Google Cast", Ok, "Réception Google Cast.", "Google Cast receiver.";
    8009, "Google Cast", Ok, "Réception Google Cast (chiffrée).", "Google Cast receiver (encrypted).";
    8080, "HTTP", Info, "Page web non chiffrée (port secondaire).", "Unencrypted web page (alternate port).";
    8123, "Home Assistant", Ok, "Domotique Home Assistant.", "Home Assistant home automation.";
    8443, "HTTPS", Ok, "Page web sécurisée (port secondaire).", "Secure web page (alternate port).";
    9100, "Impression", Ok, "Impression directe.", "Direct printing.";
    27017, "MongoDB", Warning, "Base de données accessible sur le réseau.", "Database reachable over the network.";
    32400, "Plex", Ok, "Serveur multimédia Plex.", "Plex media server.";
    49152, "UPnP", Info, "Service UPnP (découverte et partage multimédia).", "UPnP service (discovery and media sharing).";
    62078, "Apple (synchro)", Ok, "Synchronisation iPhone / iPad.", "iPhone / iPad sync.";
}

pub fn ports(ip: IpAddr, lang: Lang, progress: Progress) -> Result<Vec<PortInfo>, String> {
    if !is_private(&ip) {
        return Err(lang.pick("Seuls les appareils du réseau local peuvent être analysés.", "Only devices on the local network can be scanned.").into());
    }
    let done = AtomicUsize::new(0);
    let open = Mutex::new(Vec::new());
    progress("ports", 0, PORTS.len() as u32);
    std::thread::scope(|s| {
        for def in PORTS {
            let (done, open) = (&done, &open);
            s.spawn(move || {
                // Une connexion refusée répond aussitôt ; un port filtré attend l'échéance.
                if TcpStream::connect_timeout(&SocketAddr::new(ip, def.port), Duration::from_millis(900)).is_ok() {
                    open.lock().push(PortInfo { port: def.port, service: def.service.into(), level: def.level, note: Some(lang.pick(def.fr, def.en).into()) });
                }
                progress("ports", done.fetch_add(1, Ordering::SeqCst) as u32 + 1, PORTS.len() as u32);
            });
        }
    });
    let mut v = open.into_inner();
    v.sort_by_key(|p| p.port);
    Ok(v)
}

// ---------------------------------------------------------------------------
// Fusion des sources et identification
// ---------------------------------------------------------------------------

pub fn service_label(t: &str, lang: Lang) -> Option<&'static str> {
    Some(match t {
        "_airplay._tcp" => "AirPlay",
        "_raop._tcp" => lang.pick("AirPlay audio", "AirPlay audio"),
        "_googlecast._tcp" => "Google Cast",
        "_spotify-connect._tcp" => "Spotify Connect",
        "_ipp._tcp" | "_ipps._tcp" | "_printer._tcp" | "_pdl-datastream._tcp" => lang.pick("Imprimante", "Printer"),
        "_scanner._tcp" | "_uscan._tcp" => "Scanner",
        "_smb._tcp" => lang.pick("Partage de fichiers", "File sharing"),
        "_afpovertcp._tcp" => lang.pick("Partage de fichiers Apple", "Apple file sharing"),
        "_hap._tcp" | "_hap._udp" => "HomeKit",
        "_matter._tcp" | "_matterc._udp" => "Matter",
        "_hue._tcp" => "Philips Hue",
        "_companion-link._tcp" | "_rdlink._tcp" => lang.pick("Appareil Apple", "Apple device"),
        "_apple-mobdev2._tcp" => "iPhone / iPad",
        "_sonos._tcp" => "Sonos",
        "_amzn-wplay._tcp" => "Fire TV",
        "_androidtvremote2._tcp" => "Android TV",
        "_ssh._tcp" | "_sftp-ssh._tcp" => "SSH",
        "_rfb._tcp" => lang.pick("Partage d'écran", "Screen sharing"),
        "_workstation._tcp" => lang.pick("Ordinateur", "Computer"),
        "_http._tcp" => lang.pick("Page web", "Web page"),
        "_esphomelib._tcp" => "ESPHome",
        "_home-assistant._tcp" => "Home Assistant",
        "_daap._tcp" => lang.pick("Partage iTunes", "iTunes sharing"),
        "_nvstream._tcp" => "NVIDIA GameStream",
        _ => return None,
    })
}

fn tokens(s: &str) -> Vec<String> {
    s.to_lowercase().split(|c: char| !c.is_alphanumeric()).filter(|t| !t.is_empty()).map(String::from).collect()
}

/// Devine le type d'appareil à partir de tout ce que l'on sait de lui.
fn infer_kind(d: &NetDevice, svc: &BTreeSet<String>, upnp: &BTreeSet<String>, extra: &str) -> DeviceKind {
    use DeviceKind::*;
    if d.is_gateway {
        return Router;
    }
    let vendor = d.vendor.clone().unwrap_or_default();
    let names = d.names.join(" ");
    // « Google-Home-Mini » et « Google Home Mini » doivent se reconnaître de la même façon.
    let hay = format!("{} {} {} {} {}", d.name.clone().unwrap_or_default(), names, d.model.clone().unwrap_or_default(), extra, upnp.iter().cloned().collect::<Vec<_>>().join(" "))
        .to_lowercase()
        .replace(['-', '_'], " ");
    let tok = tokens(&hay);
    let has = |k: &str| hay.contains(k);
    let tk = |k: &str| tok.iter().any(|t| t == k);
    let s = |k: &str| svc.contains(k);
    let v = |list: &[&str]| list.iter().any(|x| vendor.eq_ignore_ascii_case(x));
    let port = |p: u16| d.open_ports.as_ref().is_some_and(|ps| ps.iter().any(|x| x.port == p));

    if has("iphone") || s("_apple-mobdev2._tcp") && !has("ipad") {
        return Phone;
    }
    if has("ipad") {
        return Tablet;
    }
    if has("apple watch") || tk("watch") && v(&["Apple", "Samsung", "Garmin", "Fitbit"]) {
        return Watch;
    }
    if has("apple tv") || has("appletv") {
        return Media;
    }
    if has("homepod") {
        return Speaker;
    }
    if has("macbook") || has("imac") || has("mac mini") || has("mac pro") || tk("mac") {
        return Computer;
    }
    if s("_ipp._tcp") || s("_ipps._tcp") || s("_printer._tcp") || s("_pdl-datastream._tcp") || has("printer") || has("laserjet") || has("officejet")
        || has("deskjet") || has("pixma") || has("ecotank") || v(&["Brother", "Epson", "Canon", "Lexmark", "Xerox", "Kyocera", "Ricoh"]) || port(9100)
    {
        return Printer;
    }
    if v(&["Hikvision", "Dahua", "Reolink", "Ring", "Arlo", "EZVIZ", "Foscam", "Axis", "Wyze"]) || tk("camera") || tk("cam") || tk("ipcam") || port(554) && !s("_airplay._tcp") {
        return Camera;
    }
    let tv_brand = v(&["Sony", "LG", "Samsung", "TCL", "Hisense", "Philips", "Vizio", "Panasonic", "Sharp", "Toshiba"]);
    if s("_googlecast._tcp") {
        if has("nest") || has("google home") || has("speaker") || has("audio") {
            return Speaker;
        }
        return if tv_brand || tk("tv") { Tv } else { Media };
    }
    if s("_sonos._tcp") || has("sonos") || has("zoneplayer") || has("echo") || has("google home") || has("nest audio") || has("nest mini")
        || v(&["Sonos", "Bose", "Harman"])
    {
        return Speaker;
    }
    if s("_amzn-wplay._tcp") || has("fire tv") || has("firetv") || has("roku") || has("shield") || has("chromecast") || has("freebox player") || has("player") && has("freebox") {
        return Media;
    }
    if s("_androidtvremote2._tcp") || tk("tv") || has("smarttv") || has("androidtv") || has("bravia") || has("webos") || has("tizen") || has("mediarenderer") && tv_brand {
        return Tv;
    }
    if has("playstation") || tk("ps4") || tk("ps5") || has("xbox") || has("nintendo") || v(&["Nintendo"]) {
        return Console;
    }
    if tk("nas") || has("synology") || has("diskstation") || has("qnap") || v(&["Synology", "QNAP", "Western Digital"]) {
        return Nas;
    }
    if s("_hap._tcp") || s("_matter._tcp") || s("_hue._tcp") || s("_esphomelib._tcp") || has("shelly") || has("tasmota") || has("esp32") || has("esp8266")
        || v(&["Espressif", "Tuya", "Shelly", "Philips Hue", "Netatmo", "tado°", "Somfy", "IKEA", "Legrand", "Signify", "ecobee", "Google Nest", "iRobot", "Ecovacs", "Roborock", "Dreame"])
    {
        return SmartHome;
    }
    if has("galaxy tab") || tk("tab") || has("kindle") {
        return Tablet;
    }
    if has("android") || has("galaxy") || tk("pixel") || has("redmi") || tk("poco") || has("oneplus") || has("iphone")
        || v(&["OnePlus", "OPPO", "vivo", "Honor", "Fairphone", "Motorola"])
    {
        return Phone;
    }
    if s("_workstation._tcp") || s("_smb._tcp") || s("_rfb._tcp") || has("msft") || has("desktop") || has("laptop") || tk("pc") || has("thinkpad")
        || has("windows") || port(3389) || port(135)
        || v(&["Raspberry Pi", "Intel", "Dell", "Lenovo", "ASUS", "Acer", "Microsoft", "Gigabyte", "MSI", "ASRock", "Realtek", "AzureWave", "Lite-On", "Foxconn", "Compal", "Quanta", "Wistron", "Pegatron", "Supermicro"])
    {
        return Computer;
    }
    if upnp.iter().any(|t| t.contains("InternetGatewayDevice") || t.contains("WLANAccessPoint") || t.contains("WFADevice")) || has("repeater") || has("extender") || has("mesh")
        || v(&["Ubiquiti", "AVM Fritz!", "Sagemcom", "Arcadyan", "Technicolor", "Freebox", "Netgear", "MikroTik", "Zyxel", "devolo", "Vantiva", "Altice Labs"])
    {
        return Router;
    }
    // Ne sait que diffuser du son (Spotify Connect, AirPlay audio) : une enceinte.
    if s("_spotify-connect._tcp") || s("_raop._tcp") && !s("_airplay._tcp") {
        return Speaker;
    }
    Unknown
}

fn hostname() -> Option<String> {
    #[cfg(windows)]
    return std::env::var("COMPUTERNAME").ok();
    #[cfg(unix)]
    return std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::process::Command::new("hostname").output().ok().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()));
}

#[derive(Default)]
struct Acc {
    mac: Option<[u8; 6]>,
    ipv6: BTreeSet<String>,
    names: Vec<(u8, &'static str, String)>,
    services: BTreeSet<String>,
    upnp: BTreeSet<String>,
    model: Option<String>,
    manufacturer: Option<String>,
    extra: String,
    sources: BTreeSet<&'static str>,
    online: bool,
    packets: u64,
    bytes: u64,
}

/// Liste des appareils : cache de la dernière analyse, table des voisins et capture.
pub fn devices(iface: &str, info: &NetworkInfo, cache: Option<&Cache>, store: &Store, lang: Lang) -> DeviceList {
    let subnet = netinfo::subnet_of(iface);
    let me = info.ipv4.as_deref().and_then(|s| s.parse::<IpAddr>().ok());
    let gateway = info.gateway.as_deref().and_then(|s| s.parse::<IpAddr>().ok());
    let inside = |ip: &IpAddr| match &subnet {
        Some(s) => s.contains(ip),
        None => false,
    };
    let mut acc: HashMap<IpAddr, Acc> = HashMap::new();

    let neighbors = netinfo::neighbors(iface);
    for n in neighbors.iter().filter(|n| inside(&n.ip)) {
        let a = acc.entry(n.ip).or_default();
        a.mac = Some(n.mac);
        a.online = true;
        a.sources.insert("arp");
    }
    if let Some(c) = cache {
        for (ip, h) in c.hosts.iter().filter(|(ip, _)| inside(ip)) {
            let a = acc.entry(*ip).or_default();
            a.mac = a.mac.or(h.mac);
            a.online |= h.alive;
            a.sources.insert("scan");
            a.names.extend(h.names.iter().cloned());
            a.services.extend(h.services.iter().cloned());
            a.upnp.extend(h.upnp.iter().cloned());
            a.model = a.model.take().or(h.model.clone());
            a.manufacturer = h.manufacturer.clone();
            if let Some(s) = &h.server {
                a.extra.push(' ');
                a.extra.push_str(s);
            }
        }
    }
    for (ip, h) in store.lan_hosts(inside) {
        let a = acc.entry(ip).or_default();
        a.mac = a.mac.or(h.mac);
        a.sources.insert("capture");
        a.packets = h.packets;
        a.bytes = h.bytes;
        if let Some(n) = h.hostname.map(|n| clean_name(&n)).filter(|n| !n.is_empty()) {
            a.names.push((3, "DHCP", n));
        }
        if let Some(v) = h.dhcp_vendor {
            a.extra.push(' ');
            a.extra.push_str(&v);
        }
    }
    if let Some(ip) = me {
        let a = acc.entry(ip).or_default();
        a.mac = a.mac.or(info.mac.as_deref().and_then(oui::parse_mac));
        a.online = true;
        if let Some(h) = hostname() {
            a.names.push((0, lang.pick("Système", "System"), h));
        }
    }
    if let Some(g) = gateway.filter(|g| inside(g)) {
        acc.entry(g).or_default();
    }
    // Adresses IPv6 rattachées par l'adresse MAC.
    for n in neighbors.iter().filter(|n| n.ip.is_ipv6()) {
        if let Some(a) = acc.values_mut().find(|a| a.mac == Some(n.mac)) {
            a.ipv6.insert(n.ip.to_string());
        }
    }

    let mut list: Vec<NetDevice> = acc
        .into_iter()
        .map(|(ip, mut a)| {
            a.names.sort_by_key(|(r, _, _)| *r);
            let mut d = NetDevice {
                ip: ip.to_string(),
                ipv6: a.ipv6.into_iter().take(3).collect(),
                mac: a.mac.map(|m| fmt_mac(&m)),
                vendor: a.mac.and_then(|m| oui::vendor(&m)).map(String::from).or(a.manufacturer.clone()),
                name: a.names.first().map(|(_, _, n)| n.clone()),
                names: a.names.iter().map(|(_, o, n)| format!("{o} : {n}")).collect(),
                model: a.model.clone(),
                services: a.services.iter().filter_map(|t| service_label(t, lang)).map(String::from).collect::<BTreeSet<_>>().into_iter().collect(),
                is_gateway: Some(ip) == gateway,
                is_self: Some(ip) == me,
                random_mac: a.mac.is_some_and(|m| oui::is_random(&m)),
                sources: a.sources.iter().map(|s| s.to_string()).collect(),
                online: a.online,
                packets: a.packets,
                bytes: a.bytes,
                open_ports: cache.and_then(|c| c.ports.get(&ip).cloned()),
                ..Default::default()
            };
            d.names.dedup();
            d.kind = infer_kind(&d, &a.services, &a.upnp, &format!("{} {}", a.extra, a.manufacturer.unwrap_or_default()));
            if d.is_self && d.kind == DeviceKind::Unknown {
                d.kind = DeviceKind::Computer;
            }
            d
        })
        .collect();
    list.sort_by_key(|d| {
        let num = d.ip.parse::<Ipv4Addr>().map(u32::from).unwrap_or(u32::MAX);
        (!d.is_gateway, !d.is_self, num)
    });
    DeviceList {
        devices: list,
        network: subnet.map(|s| s.cidr()).or_else(|| cache.and_then(|c| c.network.clone())),
        scanned_at: cache.and_then(|c| c.at.clone()),
        scan_duration: cache.and_then(|c| c.duration),
        note: cache.and_then(|c| c.note.clone()).or_else(|| {
            subnet.is_none().then(|| lang.pick("Cette connexion n'a pas d'adresse IPv4.", "This connection has no IPv4 address.").into())
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds() {
        let mut d = NetDevice { vendor: Some("Brother".into()), ..Default::default() };
        let none = BTreeSet::new();
        assert_eq!(infer_kind(&d, &none, &none, ""), DeviceKind::Printer);
        d.vendor = None;
        d.name = Some("iPhone-de-Lea".into());
        assert_eq!(infer_kind(&d, &none, &none, ""), DeviceKind::Phone);
        d.name = Some("Salon".into());
        let cast: BTreeSet<String> = ["_googlecast._tcp".to_string()].into();
        assert_eq!(infer_kind(&d, &cast, &none, ""), DeviceKind::Media);
        d.name = Some("Google-Home-Mini".into());
        assert_eq!(infer_kind(&d, &none, &none, ""), DeviceKind::Speaker);
        d.name = Some("BUREAU-PC".into());
        assert_eq!(infer_kind(&d, &none, &none, ""), DeviceKind::Computer);
        d.name = None;
        assert_eq!(infer_kind(&d, &none, &none, "android-dhcp-14"), DeviceKind::Phone);
        assert_eq!(infer_kind(&d, &none, &none, "MSFT 5.0"), DeviceKind::Computer);
        d.is_gateway = true;
        assert_eq!(infer_kind(&d, &none, &none, ""), DeviceKind::Router);
    }

    #[test]
    fn nbstat_reply() {
        let mut r = vec![0x52, 0x53, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0x20];
        r.extend(std::iter::repeat_n(b'A', 32));
        r.extend_from_slice(&[0, 0, 0x21, 0, 1, 0, 0, 0, 0, 0, 41, 2]);
        r.extend_from_slice(b"WORKGROUP      \x00\x84\x00");
        r.extend_from_slice(b"BUREAU-LEA     \x00\x04\x00");
        assert_eq!(parse_nbstat(&r).as_deref(), Some("BUREAU-LEA"));
    }

    #[test]
    fn apple_models() {
        assert_eq!(apple_model("iPhone14,2"), Some("iPhone"));
        assert_eq!(apple_model("MacBookPro18,3"), Some("MacBook Pro"));
        assert_eq!(apple_model("AudioAccessory5,1"), Some("HomePod mini"));
        assert_eq!(apple_model("Chromecast"), None);
    }

    #[test]
    fn query_layout() {
        let q = dns_query(7, "_airplay._tcp.local", 12, false);
        assert_eq!(&q[..2], &[0, 7]);
        let info = apps::parse_dns(&q).unwrap();
        assert_eq!(info.questions[0].0, "_airplay._tcp.local");
    }
}
