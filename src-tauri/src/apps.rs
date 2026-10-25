//! Protocoles applicatifs et ICMP.

use std::net::{IpAddr, Ipv4Addr};

use crate::dissect::{be16, be32, fmt_mac, ip4, ip6, p, Meta, Tb};

#[derive(Clone, Debug)]
pub struct ArpInfo {
    pub op: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

#[derive(Clone, Debug, Default)]
pub struct DnsRr {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub data: String,
    pub ip: Option<IpAddr>,
    /// Chaînes brutes d'un enregistrement TXT (« clé=valeur »).
    pub txt: Vec<String>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
pub struct DnsInfo {
    pub id: u16,
    pub response: bool,
    pub opcode: u8,
    pub rcode: u8,
    pub questions: Vec<(String, u16)>,
    pub answers: Vec<DnsRr>,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct DhcpInfo {
    pub op: u8,
    pub xid: u32,
    pub msg_type: Option<u8>,
    pub client_mac: [u8; 6],
    pub your_ip: Ipv4Addr,
    pub requested_ip: Option<Ipv4Addr>,
    pub server_id: Option<Ipv4Addr>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
}

impl Default for DhcpInfo {
    fn default() -> Self {
        Self {
            op: 0,
            xid: 0,
            msg_type: None,
            client_mac: [0; 6],
            your_ip: Ipv4Addr::UNSPECIFIED,
            requested_ip: None,
            server_id: None,
            hostname: None,
            vendor: None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct HttpInfo {
    pub request: bool,
    pub method: String,
    pub uri: String,
    pub version: String,
    pub status: Option<u16>,
    pub reason: String,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
    pub credentials: bool,
}

#[derive(Clone, Debug, Default)]
pub struct TlsInfo {
    /// Types de contenu des enregistrements (20 CCS, 21 alerte, 22 handshake, 23 données).
    pub records: Vec<u8>,
    pub handshakes: Vec<u8>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub version: Option<u16>,
    pub alert: Option<(u8, u8)>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
pub enum App {
    #[default]
    None,
    Arp(ArpInfo),
    Dns(DnsInfo),
    Dhcp(DhcpInfo),
    Http(HttpInfo),
    Tls(TlsInfo),
    Quic { long: bool, ptype: &'static str, version: u32 },
    Ntp { mode: u8, stratum: u8 },
    /// Protocole texte en clair (FTP, SMTP, POP, IMAP, Telnet).
    Text { service: &'static str, line: String, credentials: bool },
    Icmp { t: u8, c: u8, id_seq: Option<(u16, u16)>, target: Option<IpAddr> },
    Igmp { t: u8, group: Option<Ipv4Addr> },
    Ssh { banner: Option<String> },
    Nbns { name: Option<String>, response: bool },
    Ssdp { line: String },
}

/// Nom court du service associé à un port bien connu.
pub fn service_name(port: u16, udp: bool) -> Option<&'static str> {
    Some(match port {
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        67 | 68 => "DHCP",
        69 if udp => "TFTP",
        80 => "HTTP",
        88 => "Kerberos",
        110 => "POP3",
        123 => "NTP",
        135 => "MS-RPC",
        137 => "NetBIOS-NS",
        138 => "NetBIOS-DGM",
        139 => "NetBIOS",
        143 => "IMAP",
        161 | 162 => "SNMP",
        389 => "LDAP",
        443 if udp => "QUIC",
        443 => "HTTPS",
        445 => "SMB",
        465 => "SMTPS",
        500 | 4500 => "IPsec/IKE",
        514 => "Syslog",
        546 | 547 => "DHCPv6",
        548 => "AFP",
        554 => "RTSP",
        587 => "SMTP-Submission",
        631 => "IPP (imprimante)",
        636 => "LDAPS",
        853 => "DNS-over-TLS",
        993 => "IMAPS",
        995 => "POP3S",
        1194 => "OpenVPN",
        1433 => "MS-SQL",
        1883 => "MQTT",
        1900 => "SSDP/UPnP",
        2049 => "NFS",
        3074 => "Xbox Live",
        3306 => "MySQL",
        3389 => "RDP",
        3478 | 3479 => "STUN/TURN",
        5060 | 5061 => "SIP",
        5222 => "XMPP",
        5228 => "Google Push",
        5353 => "mDNS",
        5355 => "LLMNR",
        5432 => "PostgreSQL",
        5900 => "VNC",
        6379 => "Redis",
        7680 => "Windows Delivery Opt.",
        8008 | 8009 => "Chromecast",
        8080 => "HTTP-alt",
        8443 => "HTTPS-alt",
        8883 => "MQTTS",
        9100 => "Imprimante (RAW)",
        19302..=19309 => "Google Meet/STUN",
        25565 => "Minecraft",
        27017 => "MongoDB",
        51820 => "WireGuard",
        41641 => "Tailscale",
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// ICMP / IGMP
// ---------------------------------------------------------------------------

pub fn icmp_name(t: u8, c: u8) -> String {
    match t {
        0 => "Echo (ping) reply".into(),
        3 => format!("Destination unreachable ({})", match c {
            0 => "network unreachable",
            1 => "host unreachable",
            2 => "protocol unreachable",
            3 => "port unreachable",
            4 => "fragmentation needed",
            9 | 10 | 13 => "administratively prohibited",
            _ => "other",
        }),
        5 => "Redirect".into(),
        8 => "Echo (ping) request".into(),
        9 => "Router advertisement".into(),
        10 => "Router solicitation".into(),
        11 => "Time-to-live exceeded".into(),
        12 => "Parameter problem".into(),
        _ => format!("Type {t} code {c}"),
    }
}

pub fn icmpv6_name(t: u8) -> &'static str {
    match t {
        1 => "Destination unreachable",
        2 => "Packet too big",
        3 => "Time exceeded",
        4 => "Parameter problem",
        128 => "Echo (ping) request",
        129 => "Echo (ping) reply",
        130 => "Multicast listener query",
        131 | 143 => "Multicast listener report",
        133 => "Router solicitation",
        134 => "Router advertisement",
        135 => "Neighbor solicitation",
        136 => "Neighbor advertisement",
        137 => "Redirect",
        _ => "ICMPv6",
    }
}

pub fn icmp(d: &[u8], o: usize, end: usize, m: &mut Meta, tb: &mut Tb) {
    if end < o + 4 {
        m.malformed = true;
        return;
    }
    m.protos |= p::ICMP;
    m.proto_name = "ICMP";
    let (t, c) = (d[o], d[o + 1]);
    let id_seq = if matches!(t, 0 | 8) { Some((be16(d, o + 4).unwrap_or(0), be16(d, o + 6).unwrap_or(0))) } else { None };
    m.info = match id_seq {
        Some((id, seq)) => format!("{} id=0x{id:04x}, seq={seq}", icmp_name(t, c)),
        None => icmp_name(t, c),
    };
    tb.layer("icmp", |_| format!("ICMP — {}", icmp_name(t, c)),
        ("ICMP sert aux messages de service du réseau : le « ping » (es-tu là ?) et les messages d'erreur (destination injoignable, délai dépassé…).",
         "ICMP carries network service messages: 'ping' (are you there?) and error messages (destination unreachable, time exceeded…)."),
        o, end - o);
    tb.f("Type", "Type", || t.to_string());
    tb.f("Code", "Code", || c.to_string());
    if let Some((id, seq)) = id_seq {
        tb.f("Identifiant", "Identifier", || format!("0x{id:04x}"));
        tb.f("Séquence", "Sequence", || seq.to_string());
    }
    m.app = App::Icmp { t, c, id_seq, target: None };
}

pub fn icmpv6(d: &[u8], o: usize, end: usize, m: &mut Meta, tb: &mut Tb) {
    if end < o + 4 {
        m.malformed = true;
        return;
    }
    m.protos |= p::ICMPV6;
    m.proto_name = "ICMPv6";
    let (t, c) = (d[o], d[o + 1]);
    let target = if matches!(t, 135 | 136 | 137) { ip6(d, o + 8).map(IpAddr::V6) } else { None };
    let id_seq = if matches!(t, 128 | 129) { Some((be16(d, o + 4).unwrap_or(0), be16(d, o + 6).unwrap_or(0))) } else { None };
    m.info = match target {
        Some(tg) => format!("{} for {tg}", icmpv6_name(t)),
        None => icmpv6_name(t).to_string(),
    };
    tb.layer("icmpv6", |_| format!("ICMPv6 — {}", icmpv6_name(t)),
        ("ICMPv6 gère le ping, les erreurs, mais aussi la découverte des voisins et des routeurs en IPv6 (l'équivalent d'ARP).",
         "ICMPv6 handles ping and errors, plus neighbour and router discovery in IPv6 (the equivalent of ARP)."),
        o, end - o);
    tb.f("Type", "Type", || t.to_string());
    tb.f("Code", "Code", || c.to_string());
    if let Some(tg) = target {
        tb.f("Cible", "Target", || tg.to_string());
    }
    m.app = App::Icmp { t, c, id_seq, target };
}

pub fn igmp(d: &[u8], o: usize, end: usize, m: &mut Meta, tb: &mut Tb) {
    if end < o + 8 {
        m.malformed = true;
        return;
    }
    m.protos |= p::IGMP;
    m.proto_name = "IGMP";
    let t = d[o];
    let group = ip4(d, o + 4);
    let name = match t {
        0x11 => "Membership query",
        0x12 | 0x16 => "Membership report",
        0x17 => "Leave group",
        0x22 => "Membership report v3",
        _ => "IGMP",
    };
    m.info = match (t, group) {
        (0x22, _) | (_, None) => name.into(),
        (_, Some(g)) => format!("{name} {g}"),
    };
    tb.layer("igmp", |_| format!("IGMP — {name}"),
        ("Un appareil s'abonne (ou se désabonne) à un flux « multicast », par exemple la TV sur IP ou la découverte d'appareils.",
         "A device subscribes to (or leaves) a multicast stream, e.g. IPTV or device discovery."),
        o, end - o);
    m.app = App::Igmp { t, group };
}

// ---------------------------------------------------------------------------
// Aiguillage applicatif
// ---------------------------------------------------------------------------

pub fn tcp_app(pl: &[u8], off: usize, sp: u16, dp: u16, m: &mut Meta, tb: &mut Tb) {
    let either = |x: u16| sp == x || dp == x;
    if looks_like_tls(pl) {
        tls(pl, off, m, tb);
    } else if let Some(h) = parse_http(pl) {
        http(h, pl, off, m, tb, false);
    } else if pl.starts_with(b"SSH-") {
        let banner = first_line(pl);
        m.protos |= p::SSH;
        m.proto_name = "SSH";
        m.info = banner.clone();
        tb.layer("ssh", |_| "SSH".into(),
            ("Identification d'un logiciel SSH. La suite de la session sera entièrement chiffrée.", "SSH software identification. The rest of the session will be fully encrypted."),
            off, pl.len());
        tb.f("Version", "Version", || banner.clone());
        m.app = App::Ssh { banner: Some(banner) };
    } else if either(53) && pl.len() > 2 {
        dns(&pl[2..], off + 2, m, tb, p::DNS, "DNS");
    } else if either(22) {
        m.protos |= p::SSH;
        m.proto_name = "SSH";
        m.info = format!("Encrypted packet (len={})", pl.len());
        m.app = App::Ssh { banner: None };
    } else if either(21) {
        text_proto(pl, off, m, tb, p::FTP, "FTP", &["USER ", "PASS "]);
    } else if either(23) {
        m.protos |= p::TELNET;
        m.proto_name = "Telnet";
        m.info = "Telnet data".into();
        let line = String::from_utf8_lossy(&pl[..pl.len().min(80)]).trim().to_string();
        m.app = App::Text { service: "Telnet", line, credentials: false };
    } else if either(25) || either(587) {
        text_proto(pl, off, m, tb, p::SMTP, "SMTP", &["AUTH "]);
    } else if either(110) {
        text_proto(pl, off, m, tb, p::POP, "POP3", &["USER ", "PASS "]);
    } else if either(143) {
        text_proto(pl, off, m, tb, p::IMAP, "IMAP", &[" LOGIN "]);
    } else if either(445) || either(139) {
        m.protos |= p::SMB;
        m.proto_name = "SMB";
        m.info = "SMB (Windows file sharing)".into();
        tb.layer("smb", |_| "SMB".into(),
            ("Partage de fichiers et d'imprimantes Windows.", "Windows file and printer sharing."), off, pl.len());
    } else if either(3389) {
        m.protos |= p::RDP;
        m.proto_name = "RDP";
        m.info = "Remote Desktop".into();
    } else if [443, 8443, 853, 993, 995, 465, 5223, 5228].iter().any(|p| either(*p)) {
        // Suite d'un enregistrement TLS commencé dans un segment précédent.
        m.protos |= p::TLS;
        m.proto_name = "TLS";
        m.info = format!("Continuation Data (len={})", pl.len());
        tb.layer("tls", |l| format!("TLS — {}", l.pick("suite de données chiffrées", "encrypted data continuation")),
            ("Morceau d'un message chiffré plus grand, découpé en plusieurs paquets.", "Piece of a larger encrypted message, split across several packets."),
            off, pl.len());
        m.app = App::Tls(TlsInfo { records: vec![23], ..Default::default() });
    }
}

pub fn udp_app(pl: &[u8], off: usize, sp: u16, dp: u16, m: &mut Meta, tb: &mut Tb) {
    let either = |x: u16| sp == x || dp == x;
    if either(5353) {
        dns(pl, off, m, tb, p::MDNS, "mDNS");
    } else if either(5355) {
        dns(pl, off, m, tb, p::LLMNR, "LLMNR");
    } else if either(53) {
        dns(pl, off, m, tb, p::DNS, "DNS");
    } else if either(67) || either(68) {
        dhcp(pl, off, m, tb);
    } else if either(546) || either(547) {
        m.protos |= p::DHCPV6;
        m.proto_name = "DHCPv6";
        let t = pl[0];
        m.info = format!("DHCPv6 {}", match t { 1 => "Solicit", 2 => "Advertise", 3 => "Request", 7 => "Reply", 11 => "Information-request", _ => "message" });
        tb.layer("dhcpv6", |_| "DHCPv6".into(),
            ("Attribution automatique d'une configuration IPv6.", "Automatic IPv6 configuration assignment."), off, pl.len());
    } else if either(137) {
        nbns(pl, off, m, tb);
    } else if either(123) && pl.len() >= 48 {
        m.protos |= p::NTP;
        m.proto_name = "NTP";
        let mode = pl[0] & 0x07;
        let stratum = pl[1];
        m.info = format!("NTP Version {}, {}", (pl[0] >> 3) & 7, match mode { 3 => "client", 4 => "server", 1 | 2 => "symmetric", 5 => "broadcast", _ => "other" });
        tb.layer("ntp", |_| "NTP".into(),
            ("Synchronisation de l'horloge de l'appareil avec un serveur de temps.", "Synchronising the device clock with a time server."), off, pl.len());
        tb.f("Mode", "Mode", || mode.to_string());
        tb.fh("Strate", "Stratum", || stratum.to_string(),
            "Distance à une horloge de référence (1 = horloge atomique/GPS directement).", "Distance from a reference clock (1 = atomic/GPS clock directly).");
        m.app = App::Ntp { mode, stratum };
    } else if either(1900) {
        let line = first_line(pl);
        m.protos |= p::SSDP;
        m.proto_name = "SSDP";
        m.info = line.clone();
        tb.layer("ssdp", |_| "SSDP (UPnP)".into(),
            ("Des appareils (box, TV, imprimantes, enceintes) se cherchent et s'annoncent sur le réseau local.", "Devices (routers, TVs, printers, speakers) look for and announce each other on the local network."),
            off, pl.len());
        tb.f("Message", "Message", || line.clone());
        for (k, v) in headers(pl).into_iter().take(12) {
            tb.raw(k, v);
        }
        m.app = App::Ssdp { line };
    } else if (either(443) || either(80)) && !pl.is_empty() && pl[0] & 0x40 != 0 {
        quic(pl, off, m, tb);
    } else if either(161) || either(162) {
        m.protos |= p::SNMP;
        m.proto_name = "SNMP";
        m.info = "SNMP".into();
    } else if either(3478) || either(3479) || (19302..=19309).contains(&dp) || (19302..=19309).contains(&sp) {
        m.protos |= p::STUN;
        m.proto_name = "STUN";
        m.info = "STUN (NAT traversal for calls)".into();
    } else if either(138) {
        m.protos |= p::NBNS;
        m.proto_name = "NetBIOS-DGM";
        m.info = "NetBIOS datagram".into();
    }
}

fn first_line(pl: &[u8]) -> String {
    let end = pl.iter().position(|&b| b == b'\r' || b == b'\n').unwrap_or(pl.len()).min(200);
    String::from_utf8_lossy(&pl[..end]).to_string()
}

fn headers(pl: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(&pl[..pl.len().min(4096)]);
    let head = text.split("\r\n\r\n").next().unwrap_or("");
    head.split("\r\n")
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

fn text_proto(pl: &[u8], off: usize, m: &mut Meta, tb: &mut Tb, bit: u64, name: &'static str, secrets: &[&str]) {
    let line = first_line(pl);
    let upper = line.to_ascii_uppercase();
    let credentials = secrets.iter().any(|s| upper.starts_with(s.trim_start()) || upper.contains(s));
    m.protos |= bit;
    m.proto_name = name;
    // Ne pas recopier un mot de passe dans le résumé.
    m.info = if credentials { format!("{} ****", line.split_whitespace().take(if name == "IMAP" { 3 } else { 1 }).collect::<Vec<_>>().join(" ")) } else { line.clone() };
    tb.layer(&name.to_lowercase(), |l| format!("{name} — {}", l.pick("protocole texte non chiffré", "unencrypted text protocol")),
        ("Ce protocole envoie ses commandes en texte lisible : quiconque observe le réseau peut les lire, y compris les identifiants.",
         "This protocol sends commands as readable text: anyone watching the network can read them, including credentials."),
        off, pl.len());
    tb.f("Ligne", "Line", || line.clone());
    m.app = App::Text { service: name, line, credentials };
}

// ---------------------------------------------------------------------------
// DNS / mDNS / LLMNR / NBNS
// ---------------------------------------------------------------------------

fn read_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut end = None;
    let mut hops = 0;
    loop {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            if end.is_none() {
                end = Some(pos + 1);
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            let b2 = *msg.get(pos + 1)? as usize;
            if end.is_none() {
                end = Some(pos + 2);
            }
            pos = ((len & 0x3F) << 8) | b2;
            hops += 1;
            if hops > 32 {
                return None;
            }
            continue;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        let label = msg.get(pos + 1..pos + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos += 1 + len;
        if labels.len() > 127 {
            return None;
        }
    }
    let name = if labels.is_empty() { "<root>".to_string() } else { labels.join(".") };
    Some((name, end?))
}

pub fn rtype_name(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        13 => "HINFO".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        32 => "NB".into(),
        33 => "SRV".into(),
        41 => "OPT".into(),
        47 => "NSEC".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        x => format!("TYPE{x}"),
    }
}

pub fn rcode_name(r: u8) -> &'static str {
    match r {
        0 => "No error",
        1 => "Format error",
        2 => "Server failure",
        3 => "No such name",
        4 => "Not implemented",
        5 => "Refused",
        _ => "Error",
    }
}

pub fn parse_dns(msg: &[u8]) -> Option<DnsInfo> {
    if msg.len() < 12 {
        return None;
    }
    let id = be16(msg, 0)?;
    let flags = be16(msg, 2)?;
    let qd = be16(msg, 4)? as usize;
    let an = be16(msg, 6)? as usize;
    let ns = be16(msg, 8)? as usize;
    let ar = be16(msg, 10)? as usize;
    if qd > 64 || an + ns + ar > 512 {
        return None;
    }
    let mut info = DnsInfo {
        id,
        response: flags & 0x8000 != 0,
        opcode: ((flags >> 11) & 0xF) as u8,
        rcode: (flags & 0xF) as u8,
        ..Default::default()
    };
    let mut pos = 12;
    for _ in 0..qd {
        let (name, next) = read_name(msg, pos)?;
        let qtype = be16(msg, next)?;
        pos = next + 4;
        info.questions.push((name, qtype));
    }
    // Sections réponse, autorité (ignorée) puis additionnelle (utile pour mDNS).
    let sections = [(an, true), (ns, false), (ar, true)];
    'outer: for (count, keep) in sections {
        for _ in 0..count.min(64) {
            let Some((name, next)) = read_name(msg, pos) else { break 'outer };
            let (Some(rtype), Some(ttl), Some(rdlen)) = (be16(msg, next), be32(msg, next + 4), be16(msg, next + 8)) else { break 'outer };
            let rd = next + 10;
            let rdlen = rdlen as usize;
            if rd + rdlen > msg.len() {
                break 'outer;
            }
            pos = rd + rdlen;
            if !keep || rtype == 41 {
                continue;
            }
        let mut txt = Vec::new();
        let (data, ip) = match rtype {
            1 if rdlen == 4 => {
                let a = ip4(msg, rd).unwrap();
                (a.to_string(), Some(IpAddr::V4(a)))
            }
            28 if rdlen == 16 => {
                let a = ip6(msg, rd).unwrap();
                (a.to_string(), Some(IpAddr::V6(a)))
            }
            2 | 5 | 12 => (read_name(msg, rd).map(|x| x.0).unwrap_or_default(), None),
            15 => (read_name(msg, rd + 2).map(|x| x.0).unwrap_or_default(), None),
            33 => (
                format!("{}:{}", read_name(msg, rd + 6).map(|x| x.0).unwrap_or_default(), be16(msg, rd + 4).unwrap_or(0)),
                None,
            ),
            16 => {
                let mut q = rd;
                while q < rd + rdlen {
                    let l = msg[q] as usize;
                    if q + 1 + l > rd + rdlen {
                        break;
                    }
                    txt.push(String::from_utf8_lossy(&msg[q + 1..q + 1 + l]).into_owned());
                    q += 1 + l;
                }
                (txt.join(" ").chars().take(120).collect(), None)
            }
            _ => (format!("{rdlen} bytes"), None),
        };
            info.answers.push(DnsRr { name, rtype, ttl, data, ip, txt });
        }
    }
    Some(info)
}

fn dns(msg: &[u8], off: usize, m: &mut Meta, tb: &mut Tb, bit: u64, name: &'static str) {
    let Some(info) = parse_dns(msg) else {
        m.info = format!("{name} (malformed)");
        return;
    };
    m.protos |= bit;
    m.proto_name = name;
    let q = info.questions.first();
    let qtxt = q.map(|(n, t)| format!("{} {n}", rtype_name(*t))).unwrap_or_default();
    m.info = if info.response {
        let ans: Vec<String> = info.answers.iter().take(4).map(|a| format!("{} {}", rtype_name(a.rtype), a.data)).collect();
        if info.rcode != 0 {
            format!("Standard query response 0x{:04x} {} {qtxt}", info.id, rcode_name(info.rcode))
        } else {
            format!("Standard query response 0x{:04x} {qtxt} {}", info.id, ans.join(" "))
        }
    } else {
        format!("Standard query 0x{:04x} {qtxt}", info.id)
    };
    let help = match name {
        "mDNS" => ("mDNS : les appareils du réseau local (imprimantes, Chromecast, iPhone, enceintes…) s'annoncent et se trouvent sans serveur.",
                   "mDNS: local devices (printers, Chromecast, iPhone, speakers…) announce and find each other without a server."),
        "LLMNR" => ("LLMNR : Windows demande aux voisins du réseau local qui porte un certain nom.",
                    "LLMNR: Windows asks local neighbours who has a given name."),
        _ => ("Le DNS est l'annuaire d'Internet : il traduit un nom (google.com) en adresse IP, comme un répertoire téléphonique.",
              "DNS is the Internet's phone book: it translates a name (google.com) into an IP address."),
    };
    tb.layer(&name.to_lowercase(), |l| format!("{name} — {}", if info.response { l.pick("réponse", "response") } else { l.pick("requête", "query") }), help, off, msg.len());
    tb.f("Identifiant", "Transaction ID", || format!("0x{:04x}", info.id));
    tb.f("Type", "Type", || if info.response { "Response".into() } else { "Query".into() });
    if info.response {
        tb.fh("Code de réponse", "Response code", || format!("{} ({})", info.rcode, rcode_name(info.rcode)),
            "0 = tout va bien ; 3 (NXDOMAIN) = ce nom n'existe pas.", "0 = all good; 3 (NXDOMAIN) = this name does not exist.");
    }
    if tb.on {
        let lang = tb.lang;
        for (n, t) in &info.questions {
            tb.raw(lang.pick("Question", "Query").into(), format!("{n} ({})", rtype_name(*t)));
        }
        for a in &info.answers {
            tb.raw(lang.pick("Réponse", "Answer").into(), format!("{} {} {} (TTL {} s)", a.name, rtype_name(a.rtype), a.data, a.ttl));
        }
    }
    m.app = App::Dns(info);
}

fn decode_netbios(n: &str) -> Option<String> {
    let first = n.split('.').next()?;
    if first.len() != 32 {
        return None;
    }
    let b = first.as_bytes();
    let mut out = Vec::new();
    for i in 0..16 {
        let hi = b[2 * i].checked_sub(b'A')?;
        let lo = b[2 * i + 1].checked_sub(b'A')?;
        out.push((hi << 4) | lo);
    }
    let suffix = out[15];
    let name = String::from_utf8_lossy(&out[..15]).trim_end().to_string();
    Some(format!("{name}<{suffix:02x}>"))
}

fn nbns(pl: &[u8], off: usize, m: &mut Meta, tb: &mut Tb) {
    m.protos |= p::NBNS;
    m.proto_name = "NBNS";
    let info = parse_dns(pl);
    let response = info.as_ref().map(|i| i.response).unwrap_or(false);
    let name = info.as_ref().and_then(|i| i.questions.first().or(None).map(|q| q.0.clone()).or_else(|| i.answers.first().map(|a| a.name.clone()))).and_then(|n| decode_netbios(&n));
    m.info = format!("Name {} {}", if response { "response" } else { "query" }, name.clone().unwrap_or_default());
    tb.layer("nbns", |_| "NetBIOS Name Service".into(),
        ("Ancien système Windows pour trouver un ordinateur par son nom sur le réseau local.", "Legacy Windows system to find a computer by name on the local network."),
        off, pl.len());
    if let Some(n) = &name {
        tb.f("Nom", "Name", || n.clone());
    }
    m.app = App::Nbns { name, response };
}

// ---------------------------------------------------------------------------
// DHCP
// ---------------------------------------------------------------------------

pub fn dhcp_type_name(t: u8) -> &'static str {
    match t {
        1 => "Discover",
        2 => "Offer",
        3 => "Request",
        4 => "Decline",
        5 => "ACK",
        6 => "NAK",
        7 => "Release",
        8 => "Inform",
        _ => "?",
    }
}

fn dhcp(pl: &[u8], off: usize, m: &mut Meta, tb: &mut Tb) {
    if pl.len() < 240 || be32(pl, 236) != Some(0x6382_5363) {
        m.info = "BOOTP".into();
        return;
    }
    m.protos |= p::DHCP;
    m.proto_name = "DHCP";
    let mut info = DhcpInfo {
        op: pl[0],
        xid: be32(pl, 4).unwrap(),
        client_mac: pl[28..34].try_into().unwrap(),
        your_ip: ip4(pl, 16).unwrap(),
        ..Default::default()
    };
    let mut i = 240;
    while i < pl.len() {
        let code = pl[i];
        if code == 0 {
            i += 1;
            continue;
        }
        if code == 255 || i + 1 >= pl.len() {
            break;
        }
        let len = pl[i + 1] as usize;
        let Some(v) = pl.get(i + 2..i + 2 + len) else { break };
        match code {
            53 if len == 1 => info.msg_type = Some(v[0]),
            12 => info.hostname = Some(String::from_utf8_lossy(v).into_owned()),
            50 if len == 4 => info.requested_ip = ip4(v, 0),
            54 if len == 4 => info.server_id = ip4(v, 0),
            60 => info.vendor = Some(String::from_utf8_lossy(v).into_owned()),
            _ => {}
        }
        i += 2 + len;
    }
    let tname = info.msg_type.map(dhcp_type_name).unwrap_or("?");
    m.info = format!("DHCP {tname} - Transaction ID 0x{:08x}", info.xid);
    tb.layer("dhcp", |_| format!("DHCP — {tname}"),
        ("DHCP distribue automatiquement les adresses IP : quand un appareil se connecte, il demande « quelle adresse puis-je utiliser ? » et la box lui en attribue une.",
         "DHCP hands out IP addresses automatically: when a device connects it asks 'which address can I use?' and the router assigns one."),
        off, pl.len());
    tb.fh("Type de message", "Message type", || tname.into(),
        "Discover (je cherche un serveur) → Offer (je te propose) → Request (je prends) → ACK (c'est confirmé).",
        "Discover (looking for a server) → Offer (here's one) → Request (I'll take it) → ACK (confirmed).");
    tb.f("Transaction", "Transaction ID", || format!("0x{:08x}", info.xid));
    tb.f("MAC du client", "Client MAC", || fmt_mac(&info.client_mac));
    if !info.your_ip.is_unspecified() {
        tb.f("Adresse attribuée", "Assigned address", || info.your_ip.to_string());
    }
    if let Some(r) = info.requested_ip {
        tb.f("Adresse demandée", "Requested address", || r.to_string());
    }
    if let Some(h) = &info.hostname {
        tb.f("Nom de l'appareil", "Device name", || h.clone());
    }
    if let Some(v) = &info.vendor {
        tb.fh("Fabricant / système", "Vendor class", || v.clone(),
            "Indique souvent le type d'appareil (ex. « MSFT 5.0 » = Windows, « android-dhcp »).", "Often reveals the device type (e.g. 'MSFT 5.0' = Windows, 'android-dhcp').");
    }
    m.app = App::Dhcp(info);
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

const METHODS: &[&str] = &["GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "];

fn parse_http(pl: &[u8]) -> Option<HttpInfo> {
    let start = &pl[..pl.len().min(16)];
    let is_req = METHODS.iter().any(|m| start.starts_with(m.as_bytes()));
    let is_resp = start.starts_with(b"HTTP/1.") || start.starts_with(b"HTTP/2");
    if !is_req && !is_resp {
        return None;
    }
    let line = first_line(pl);
    let mut parts = line.splitn(3, ' ');
    let (a, b, c) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let mut h = HttpInfo { request: is_req, ..Default::default() };
    if is_req {
        h.method = a.into();
        h.uri = b.chars().take(300).collect();
        h.version = c.into();
    } else {
        h.version = a.into();
        h.status = b.parse().ok();
        h.reason = c.into();
    }
    for (k, v) in headers(pl) {
        match k.to_ascii_lowercase().as_str() {
            "host" => h.host = Some(v),
            "user-agent" => h.user_agent = Some(v),
            "content-type" => h.content_type = Some(v),
            "authorization" | "proxy-authorization" => h.credentials = true,
            _ => {}
        }
    }
    let lower = String::from_utf8_lossy(&pl[..pl.len().min(8192)]).to_lowercase();
    if ["password=", "passwd=", "pwd=", "pass=", "\"password\""].iter().any(|s| lower.contains(s)) {
        h.credentials = true;
    }
    Some(h)
}

fn http(h: HttpInfo, pl: &[u8], off: usize, m: &mut Meta, tb: &mut Tb, _udp: bool) {
    m.protos |= p::HTTP;
    m.proto_name = "HTTP";
    m.info = if h.request {
        format!("{} {} {}", h.method, h.uri, h.version)
    } else {
        format!("{} {} {}", h.version, h.status.unwrap_or(0), h.reason)
    };
    tb.layer("http", |l| format!("HTTP — {}", if h.request { l.pick("requête", "request") } else { l.pick("réponse", "response") }),
        ("HTTP est le langage du web. Sans le « S » (HTTPS), tout circule en clair : n'importe qui sur le réseau peut lire les pages, formulaires et mots de passe.",
         "HTTP is the language of the web. Without the 'S' (HTTPS), everything travels in clear text: anyone on the network can read pages, forms and passwords."),
        off, pl.len());
    if h.request {
        tb.fh("Méthode", "Method", || h.method.clone(), "GET = lire une page, POST = envoyer un formulaire.", "GET = read a page, POST = submit a form.");
        tb.f("Chemin", "Path", || h.uri.clone());
    } else {
        tb.fh("Statut", "Status", || format!("{} {}", h.status.unwrap_or(0), h.reason),
            "200 = OK, 301/302 = redirection, 404 = introuvable, 500 = erreur du serveur.", "200 = OK, 301/302 = redirect, 404 = not found, 500 = server error.");
    }
    if tb.on {
        for (k, v) in headers(pl).into_iter().take(25) {
            let shown = if k.eq_ignore_ascii_case("authorization") || k.eq_ignore_ascii_case("cookie") { format!("{} …", v.chars().take(12).collect::<String>()) } else { v };
            tb.raw(k, shown);
        }
    }
    if h.credentials {
        tb.fh("⚠ Identifiants", "⚠ Credentials", || "visible in clear text".into(),
            "Des identifiants ou un mot de passe semblent transiter en clair.", "Credentials or a password seem to travel in clear text.");
    }
    m.app = App::Http(h);
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

fn looks_like_tls(p: &[u8]) -> bool {
    p.len() >= 5 && (20..=23).contains(&p[0]) && p[1] == 3 && p[2] <= 4
}

pub fn tls_version_name(v: u16) -> &'static str {
    match v {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "TLS",
    }
}

pub fn handshake_name(t: u8) -> &'static str {
    match t {
        1 => "Client Hello",
        2 => "Server Hello",
        4 => "New Session Ticket",
        8 => "Encrypted Extensions",
        11 => "Certificate",
        12 => "Server Key Exchange",
        13 => "Certificate Request",
        14 => "Server Hello Done",
        15 => "Certificate Verify",
        16 => "Client Key Exchange",
        20 => "Finished",
        _ => "Encrypted Handshake Message",
    }
}

fn parse_hello(body: &[u8], client: bool, info: &mut TlsInfo) {
    // body = contenu du message (après type + longueur sur 3 octets)
    let mut i = 2 + 32;
    let Some(&sid) = body.get(i) else { return };
    i += 1 + sid as usize;
    if client {
        let Some(cs) = be16(body, i) else { return };
        i += 2 + cs as usize;
        let Some(&comp) = body.get(i) else { return };
        i += 1 + comp as usize;
    } else {
        i += 3;
    }
    info.version = be16(body, 0);
    let Some(ext_len) = be16(body, i) else { return };
    i += 2;
    let end = (i + ext_len as usize).min(body.len());
    while i + 4 <= end {
        let et = be16(body, i).unwrap();
        let el = be16(body, i + 2).unwrap() as usize;
        let ed = &body[i + 4..(i + 4 + el).min(end)];
        match et {
            0 if client && ed.len() > 5 => {
                let nl = be16(ed, 3).unwrap_or(0) as usize;
                if let Some(n) = ed.get(5..5 + nl) {
                    info.sni = Some(String::from_utf8_lossy(n).into_owned());
                }
            }
            16 if ed.len() > 2 => {
                let mut j = 2;
                while j < ed.len() {
                    let l = ed[j] as usize;
                    if let Some(s) = ed.get(j + 1..j + 1 + l) {
                        info.alpn.push(String::from_utf8_lossy(s).into_owned());
                    }
                    j += 1 + l;
                }
            }
            43 => {
                if client {
                    let mut best = 0u16;
                    let mut j = 1;
                    while j + 1 < ed.len() {
                        let v = be16(ed, j).unwrap();
                        if v & 0x0f0f != 0x0a0a && v > best && v <= 0x0304 {
                            best = v;
                        }
                        j += 2;
                    }
                    if best != 0 {
                        info.version = Some(best);
                    }
                } else if let Some(v) = be16(ed, 0) {
                    info.version = Some(v);
                }
            }
            _ => {}
        }
        i += 4 + el;
    }
}

fn tls(pl: &[u8], off: usize, m: &mut Meta, tb: &mut Tb) {
    m.protos |= p::TLS;
    m.proto_name = "TLS";
    let mut info = TlsInfo::default();
    let mut o = 0;
    while o + 5 <= pl.len() && looks_like_tls(&pl[o..]) {
        let ct = pl[o];
        let len = be16(pl, o + 3).unwrap() as usize;
        let body = &pl[o + 5..(o + 5 + len).min(pl.len())];
        info.records.push(ct);
        match ct {
            22 if body.len() >= 4 => {
                let ht = body[0];
                // Un handshake chiffré (TLS 1.3) n'a pas un type lisible.
                let hlen = ((body[1] as usize) << 16) | ((body[2] as usize) << 8) | body[3] as usize;
                let plausible = hlen + 4 <= len.max(4) && matches!(ht, 1 | 2 | 4 | 8 | 11 | 12 | 13 | 14 | 15 | 16 | 20);
                info.handshakes.push(if plausible { ht } else { 0 });
                if plausible && (ht == 1 || ht == 2) {
                    parse_hello(&body[4..], ht == 1, &mut info);
                }
            }
            21 if body.len() == 2 => info.alert = Some((body[0], body[1])),
            _ => {}
        }
        o += 5 + len;
        if info.records.len() > 16 {
            break;
        }
    }
    let mut parts: Vec<String> = Vec::new();
    let mut hs = info.handshakes.iter();
    for ct in &info.records {
        let s = match ct {
            20 => "Change Cipher Spec".to_string(),
            21 => "Alert".to_string(),
            22 => match hs.next() {
                Some(1) => match &info.sni {
                    Some(s) => format!("Client Hello (SNI={s})"),
                    None => "Client Hello".into(),
                },
                Some(t) => handshake_name(*t).into(),
                None => "Handshake".into(),
            },
            23 => "Application Data".into(),
            _ => "?".into(),
        };
        if parts.last() != Some(&s) {
            parts.push(s);
        }
    }
    if parts.is_empty() {
        parts.push("Continuation Data".into());
    }
    m.info = parts.join(", ");
    tb.layer("tls", |l| format!("TLS — {}", info.version.map(tls_version_name).unwrap_or(l.pick("chiffrement", "encryption"))),
        ("TLS est le cadenas du web (HTTPS) : il chiffre les échanges. On ne voit que le nom du site demandé (SNI) au début ; le contenu, lui, est illisible.",
         "TLS is the web padlock (HTTPS): it encrypts the exchange. Only the requested site name (SNI) is visible at the start; the content is unreadable."),
        off, pl.len());
    tb.f("Enregistrements", "Records", || m.info.clone());
    if let Some(v) = info.version {
        tb.fh("Version", "Version", || tls_version_name(v).into(),
            "TLS 1.2 et 1.3 sont sûrs ; TLS 1.0/1.1 et SSL sont obsolètes.", "TLS 1.2 and 1.3 are safe; TLS 1.0/1.1 and SSL are obsolete.");
    }
    if let Some(s) = &info.sni {
        tb.fh("Nom du serveur (SNI)", "Server name (SNI)", || s.clone(),
            "Le site que l'ordinateur souhaite joindre. Envoyé en clair, il permet de savoir quel site est visité, mais pas ce qui y est fait.",
            "The site the computer wants to reach. Sent in clear text, it reveals which site is visited, but not what is done there.");
    }
    if !info.alpn.is_empty() {
        tb.fh("Protocoles proposés (ALPN)", "Offered protocols (ALPN)", || info.alpn.join(", "),
            "h2 = HTTP/2, http/1.1 = HTTP classique.", "h2 = HTTP/2, http/1.1 = classic HTTP.");
    }
    if let Some((lvl, desc)) = info.alert {
        tb.f("Alerte", "Alert", || format!("level {lvl}, description {desc}"));
    }
    m.app = App::Tls(info);
}

fn quic(pl: &[u8], off: usize, m: &mut Meta, tb: &mut Tb) {
    let long = pl[0] & 0x80 != 0;
    let version = if long { be32(pl, 1).unwrap_or(0) } else { 0 };
    let ptype = if !long {
        "Protected Payload"
    } else if version == 0 {
        "Version Negotiation"
    } else {
        match (pl[0] & 0x30) >> 4 {
            0 => "Initial",
            1 => "0-RTT",
            2 => "Handshake",
            _ => "Retry",
        }
    };
    m.protos |= p::QUIC;
    m.proto_name = "QUIC";
    m.info = if long { format!("{ptype}, version 0x{version:08x}") } else { ptype.into() };
    tb.layer("quic", |_| format!("QUIC — {ptype}"),
        ("QUIC (HTTP/3) est un protocole web moderne et chiffré créé par Google, utilisé par YouTube, Google, Facebook… Il passe par UDP.",
         "QUIC (HTTP/3) is a modern encrypted web protocol created by Google, used by YouTube, Google, Facebook… It runs over UDP."),
        off, pl.len());
    tb.f("Type de paquet", "Packet type", || ptype.into());
    if long {
        tb.f("Version", "Version", || format!("0x{version:08x}"));
    }
    m.app = App::Quic { long, ptype, version };
}
