//! Dissection des trames : liaison (Ethernet, loopback, SLL), réseau (IPv4,
//! IPv6, ARP) et transport (TCP, UDP, ICMP). Les protocoles applicatifs sont
//! dans `apps.rs`.
//!
//! Une seule passe produit à la fois les métadonnées compactes (`Meta`,
//! utilisées pour le filtrage et les statistiques) et, si demandé, l'arbre
//! détaillé (`Tb`) affiché dans l'interface.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rustshark_shared::{Category, Field, Lang, Layer};

use crate::apps::{self, App};

macro_rules! protos {
    ($($name:ident = $bit:expr, $s:expr;)*) => {
        pub mod p {
            $(pub const $name: u64 = 1u64 << $bit;)*
        }
        pub fn proto_bit(name: &str) -> Option<u64> {
            match name {
                $($s => Some(p::$name),)*
                _ => None,
            }
        }
    };
}

protos! {
    ETH = 0, "eth"; VLAN = 1, "vlan"; ARP = 2, "arp"; IP = 3, "ip"; IPV6 = 4, "ipv6";
    ICMP = 5, "icmp"; ICMPV6 = 6, "icmpv6"; IGMP = 7, "igmp"; TCP = 8, "tcp"; UDP = 9, "udp";
    DNS = 10, "dns"; MDNS = 11, "mdns"; LLMNR = 12, "llmnr"; NBNS = 13, "nbns"; DHCP = 14, "dhcp";
    DHCPV6 = 15, "dhcpv6"; HTTP = 16, "http"; TLS = 17, "tls"; QUIC = 18, "quic"; NTP = 19, "ntp";
    SSDP = 20, "ssdp"; SSH = 21, "ssh"; FTP = 22, "ftp"; TELNET = 23, "telnet"; SMTP = 24, "smtp";
    POP = 25, "pop"; IMAP = 26, "imap"; SMB = 27, "smb"; RDP = 28, "rdp"; SNMP = 29, "snmp";
    STUN = 30, "stun"; LLDP = 31, "lldp"; STP = 32, "stp"; EAPOL = 33, "eapol";
}

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
pub struct TcpInfo {
    pub flags: u8,
    pub seq: u32,
    pub ack: u32,
    pub window: u16,
    pub payload: u32,
}

#[derive(Clone, Debug, Default)]
pub struct Meta {
    pub protos: u64,
    pub src_mac: Option<[u8; 6]>,
    pub dst_mac: Option<[u8; 6]>,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub ttl: Option<u8>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp: Option<TcpInfo>,
    /// Taille des données au-dessus de la couche transport.
    pub payload_len: u32,
    pub app: App,
    pub proto_name: &'static str,
    pub info: String,
    pub category: Category,
    pub malformed: bool,
}

impl Meta {
    pub fn has(&self, bit: u64) -> bool {
        self.protos & bit != 0
    }

    pub fn is_broadcast(&self) -> bool {
        self.dst_mac == Some([0xff; 6])
            || matches!(self.dst_ip, Some(IpAddr::V4(a)) if a.is_broadcast() || a.octets()[3] == 255 && is_private(&IpAddr::V4(a)))
    }

    pub fn is_multicast(&self) -> bool {
        matches!(self.dst_ip, Some(ip) if ip.is_multicast())
            || matches!(self.dst_mac, Some(m) if m[0] & 1 == 1 && m != [0xff; 6])
    }

    /// Port « de service » de la conversation (443, 53…).
    pub fn service_port(&self) -> Option<u16> {
        let (s, d) = (self.src_port?, self.dst_port?);
        let udp = self.has(p::UDP);
        if apps::service_name(d, udp).is_some() && (d < s || apps::service_name(s, udp).is_none()) {
            Some(d)
        } else if apps::service_name(s, udp).is_some() {
            Some(s)
        } else {
            Some(d.min(s))
        }
    }

    pub fn tcp_flags(&self) -> u8 {
        self.tcp.as_ref().map(|t| t.flags).unwrap_or(0)
    }

    pub fn is_problem(&self) -> bool {
        self.category == Category::Problem
    }

    pub fn is_cleartext(&self) -> bool {
        match &self.app {
            App::Http(_) => true,
            App::Text { .. } => true,
            _ => self.has(p::TELNET) && self.payload_len > 0,
        }
    }
}

pub fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_private() || a.is_loopback() || a.is_link_local() || a.octets()[0] == 100 && (a.octets()[1] & 0xC0) == 64,
        IpAddr::V6(a) => {
            let s = a.segments()[0];
            a.is_loopback() || (s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80
        }
    }
}

pub fn is_local_scope(ip: &IpAddr) -> bool {
    is_private(ip) || ip.is_multicast() || matches!(ip, IpAddr::V4(a) if a.is_broadcast() || a.is_unspecified()) || ip.is_unspecified()
}

pub fn fmt_mac(m: &[u8]) -> String {
    m.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

pub fn be16(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*d.get(o)?, *d.get(o + 1)?]))
}

pub fn be32(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_be_bytes([*d.get(o)?, *d.get(o + 1)?, *d.get(o + 2)?, *d.get(o + 3)?]))
}

pub fn ip4(d: &[u8], o: usize) -> Option<Ipv4Addr> {
    let s = d.get(o..o + 4)?;
    Some(Ipv4Addr::new(s[0], s[1], s[2], s[3]))
}

pub fn ip6(d: &[u8], o: usize) -> Option<Ipv6Addr> {
    let s: [u8; 16] = d.get(o..o + 16)?.try_into().ok()?;
    Some(Ipv6Addr::from(s))
}

fn mac(d: &[u8], o: usize) -> Option<[u8; 6]> {
    d.get(o..o + 6)?.try_into().ok()
}

// ---------------------------------------------------------------------------
// Constructeur d'arbre
// ---------------------------------------------------------------------------

/// Construit l'arbre détaillé. Inactif (`on == false`) pendant la capture
/// pour ne pas payer le coût du formatage.
pub struct Tb {
    pub on: bool,
    pub lang: Lang,
    pub layers: Vec<Layer>,
}

impl Tb {
    pub fn off() -> Self {
        Self { on: false, lang: Lang::En, layers: Vec::new() }
    }

    pub fn new(lang: Lang) -> Self {
        Self { on: true, lang, layers: Vec::new() }
    }

    pub fn layer(&mut self, id: &str, title: impl FnOnce(Lang) -> String, help: (&str, &str), offset: usize, len: usize) {
        if !self.on {
            return;
        }
        self.layers.push(Layer {
            id: id.into(),
            title: title(self.lang),
            help: self.lang.pick(help.0, help.1).into(),
            offset: offset as u32,
            len: len as u32,
            fields: Vec::new(),
        });
    }

    pub fn f(&mut self, fr: &str, en: &str, value: impl FnOnce() -> String) {
        if !self.on {
            return;
        }
        let name = self.lang.pick(fr, en).to_string();
        if let Some(l) = self.layers.last_mut() {
            l.fields.push(Field { name, value: value(), help: None });
        }
    }

    pub fn fh(&mut self, fr: &str, en: &str, value: impl FnOnce() -> String, hfr: &str, hen: &str) {
        if !self.on {
            return;
        }
        let name = self.lang.pick(fr, en).to_string();
        let help = Some(self.lang.pick(hfr, hen).to_string());
        if let Some(l) = self.layers.last_mut() {
            l.fields.push(Field { name, value: value(), help });
        }
    }

    /// Champ dont le libellé est déjà localisé.
    pub fn raw(&mut self, name: String, value: String) {
        if !self.on {
            return;
        }
        if let Some(l) = self.layers.last_mut() {
            l.fields.push(Field { name, value, help: None });
        }
    }
}

// ---------------------------------------------------------------------------
// Point d'entrée
// ---------------------------------------------------------------------------

pub fn dissect(data: &[u8], linktype: u16, tb: &mut Tb) -> Meta {
    let mut m = Meta { proto_name: "Frame", ..Default::default() };
    match linktype {
        1 => ethernet(data, &mut m, tb),
        0 | 108 => {
            // Boucle locale BSD / Npcap : 4 octets de famille d'adresse.
            if data.len() < 4 {
                m.malformed = true;
            } else {
                let le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                let be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                let fam = if linktype == 108 { be } else if le < 256 { le } else { be };
                tb.layer("null", |l| l.pick("Boucle locale (loopback)", "Loopback").into(),
                    ("Trafic interne à cet ordinateur : il ne sort jamais sur le réseau.",
                     "Traffic internal to this computer: it never leaves on the network."), 0, 4);
                tb.f("Famille", "Family", || match fam { 2 => "IPv4".into(), 24 | 28 | 30 | 10 | 23 => "IPv6".into(), x => x.to_string() });
                match fam {
                    2 => ipv4(data, 4, &mut m, tb),
                    24 | 28 | 30 | 10 | 23 => ipv6(data, 4, &mut m, tb),
                    _ => m.info = format!("Loopback family {fam}"),
                }
            }
        }
        101 | 12 | 14 | 228 | 229 => match data.first().map(|b| b >> 4) {
            Some(4) => ipv4(data, 0, &mut m, tb),
            Some(6) => ipv6(data, 0, &mut m, tb),
            _ => m.malformed = true,
        },
        113 => {
            // Linux « cooked » (interface any).
            if let Some(et) = be16(data, 14) {
                tb.layer("sll", |l| l.pick("Capture Linux (SLL)", "Linux cooked capture (SLL)").into(),
                    ("En-tête ajouté par Linux pour la capture sur « any ».", "Header added by Linux when capturing on 'any'."), 0, 16);
                ethertype(et, data, 16, &mut m, tb);
            }
        }
        276 => {
            if let Some(et) = be16(data, 0) {
                tb.layer("sll", |l| l.pick("Capture Linux (SLL2)", "Linux cooked capture (SLL2)").into(),
                    ("En-tête ajouté par Linux pour la capture sur « any ».", "Header added by Linux when capturing on 'any'."), 0, 20);
                ethertype(et, data, 20, &mut m, tb);
            }
        }
        other => {
            m.info = format!("Link type {other}");
            tb.layer("raw", |l| format!("{} {other}", l.pick("Type de liaison non pris en charge :", "Unsupported link type:")),
                ("Ce type de trame n'est pas encore décodé.", "This frame type is not decoded yet."), 0, data.len());
        }
    }
    if m.info.is_empty() {
        m.info = m.proto_name.to_string();
    }
    m.category = categorize(&m);
    m
}

fn ethernet(d: &[u8], m: &mut Meta, tb: &mut Tb) {
    if d.len() < 14 {
        m.malformed = true;
        return;
    }
    m.protos |= p::ETH;
    m.proto_name = "Ethernet";
    m.dst_mac = mac(d, 0);
    m.src_mac = mac(d, 6);
    let et = be16(d, 12).unwrap_or(0);
    tb.layer("eth", |_| format!("Ethernet II — {} → {}", fmt_mac(&d[6..12]), fmt_mac(&d[0..6])),
        ("Couche « liaison » : l'enveloppe utilisée sur votre réseau local (câble ou Wi-Fi). Elle contient les adresses matérielles (MAC) des cartes réseau, comme le nom sur une boîte aux lettres.",
         "Link layer: the envelope used on your local network (cable or Wi-Fi). It holds the hardware (MAC) addresses of network cards, like the name on a mailbox."),
        0, 14);
    tb.fh("Destination (MAC)", "Destination (MAC)", || mac_label(&d[0..6]),
        "Adresse matérielle de la carte réseau qui doit recevoir la trame. ff:ff:ff:ff:ff:ff = tout le monde.",
        "Hardware address of the network card that should receive the frame. ff:ff:ff:ff:ff:ff = everyone.");
    tb.fh("Source (MAC)", "Source (MAC)", || fmt_mac(&d[6..12]),
        "Adresse matérielle de la carte réseau qui a envoyé la trame.", "Hardware address of the sending network card.");
    tb.fh("Type", "Type", || format!("0x{et:04x} ({})", ethertype_name(et)),
        "Indique ce que transporte la trame (IPv4, IPv6, ARP…).", "Says what the frame carries (IPv4, IPv6, ARP…).");
    if et < 0x0600 {
        // 802.3 + LLC : STP utilise DSAP 0x42.
        if d.get(14) == Some(&0x42) {
            m.protos |= p::STP;
            m.proto_name = "STP";
            m.info = "Spanning Tree BPDU".into();
            tb.layer("stp", |_| "Spanning Tree Protocol".into(),
                ("Les switchs s'échangent ces messages pour éviter les boucles dans le réseau.", "Switches exchange these messages to prevent loops in the network."), 14, d.len() - 14);
        } else {
            m.info = format!("802.3 LLC, length {et}");
        }
        return;
    }
    ethertype(et, d, 14, m, tb);
}

fn mac_label(m: &[u8]) -> String {
    if m == [0xff; 6] {
        "ff:ff:ff:ff:ff:ff (broadcast)".into()
    } else if m[0] & 1 == 1 {
        format!("{} (multicast)", fmt_mac(m))
    } else {
        fmt_mac(m)
    }
}

pub fn ethertype_name(et: u16) -> &'static str {
    match et {
        0x0800 => "IPv4",
        0x86dd => "IPv6",
        0x0806 => "ARP",
        0x8100 => "802.1Q VLAN",
        0x88a8 => "802.1ad QinQ",
        0x88cc => "LLDP",
        0x888e => "EAPOL",
        0x8863 | 0x8864 => "PPPoE",
        0x88e5 => "MACsec",
        0x893a => "IEEE 1905",
        _ => "?",
    }
}

fn ethertype(et: u16, d: &[u8], off: usize, m: &mut Meta, tb: &mut Tb) {
    match et {
        0x0800 => ipv4(d, off, m, tb),
        0x86dd => ipv6(d, off, m, tb),
        0x0806 => arp(d, off, m, tb),
        0x8100 | 0x88a8 => {
            let (Some(tci), Some(inner)) = (be16(d, off), be16(d, off + 2)) else {
                m.malformed = true;
                return;
            };
            m.protos |= p::VLAN;
            tb.layer("vlan", |_| format!("802.1Q VLAN {}", tci & 0x0fff),
                ("Étiquette de réseau virtuel : permet de séparer plusieurs réseaux sur les mêmes câbles.", "Virtual network tag: separates several networks on the same cables."), off, 4);
            tb.f("Identifiant VLAN", "VLAN ID", || (tci & 0x0fff).to_string());
            tb.f("Priorité", "Priority", || (tci >> 13).to_string());
            ethertype(inner, d, off + 4, m, tb);
        }
        0x88cc => {
            m.protos |= p::LLDP;
            m.proto_name = "LLDP";
            m.info = "Link Layer Discovery Protocol".into();
            tb.layer("lldp", |_| "LLDP".into(),
                ("Un équipement (switch, téléphone IP…) annonce son identité à ses voisins.", "A device (switch, IP phone…) announces its identity to its neighbours."), off, d.len().saturating_sub(off));
        }
        0x888e => {
            m.protos |= p::EAPOL;
            m.proto_name = "EAPOL";
            m.info = "EAP over LAN (802.1X / WPA handshake)".into();
            tb.layer("eapol", |_| "EAPOL".into(),
                ("Échange d'authentification (connexion Wi-Fi WPA ou 802.1X).", "Authentication exchange (WPA Wi-Fi or 802.1X)."), off, d.len().saturating_sub(off));
        }
        _ => m.info = format!("Ethertype 0x{et:04x}"),
    }
}

fn arp(d: &[u8], o: usize, m: &mut Meta, tb: &mut Tb) {
    if d.len() < o + 28 {
        m.malformed = true;
        return;
    }
    m.protos |= p::ARP;
    m.proto_name = "ARP";
    let op = be16(d, o + 6).unwrap_or(0);
    let info = apps::ArpInfo {
        op,
        sender_mac: mac(d, o + 8).unwrap_or_default(),
        sender_ip: ip4(d, o + 14).unwrap_or(Ipv4Addr::UNSPECIFIED),
        target_mac: mac(d, o + 18).unwrap_or_default(),
        target_ip: ip4(d, o + 24).unwrap_or(Ipv4Addr::UNSPECIFIED),
    };
    m.src_ip = Some(IpAddr::V4(info.sender_ip));
    m.dst_ip = Some(IpAddr::V4(info.target_ip));
    m.info = match op {
        1 if info.sender_ip == info.target_ip => format!("ARP Announcement for {}", info.sender_ip),
        1 => format!("Who has {}? Tell {}", info.target_ip, info.sender_ip),
        2 => format!("{} is at {}", info.sender_ip, fmt_mac(&info.sender_mac)),
        _ => format!("ARP opcode {op}"),
    };
    tb.layer("arp", |l| format!("ARP — {}", match op { 1 => l.pick("requête", "request"), 2 => l.pick("réponse", "reply"), _ => "?" }),
        ("ARP fait le lien entre une adresse IP (logique) et une adresse MAC (matérielle) sur le réseau local : « Qui a l'adresse 192.168.1.1 ? »",
         "ARP links an IP address (logical) to a MAC address (hardware) on the local network: 'Who has 192.168.1.1?'"),
        o, 28);
    tb.f("Opération", "Operation", || match op { 1 => "request (1)".into(), 2 => "reply (2)".into(), x => x.to_string() });
    tb.f("MAC de l'émetteur", "Sender MAC", || fmt_mac(&info.sender_mac));
    tb.f("IP de l'émetteur", "Sender IP", || info.sender_ip.to_string());
    tb.f("MAC recherchée", "Target MAC", || fmt_mac(&info.target_mac));
    tb.f("IP recherchée", "Target IP", || info.target_ip.to_string());
    m.app = App::Arp(info);
}

fn ipv4(d: &[u8], o: usize, m: &mut Meta, tb: &mut Tb) {
    let Some(&vihl) = d.get(o) else {
        m.malformed = true;
        return;
    };
    let ihl = ((vihl & 0x0f) as usize) * 4;
    if ihl < 20 || d.len() < o + ihl {
        m.malformed = true;
        return;
    }
    m.protos |= p::IP;
    m.proto_name = "IPv4";
    let total = be16(d, o + 2).unwrap_or(0) as usize;
    let ident = be16(d, o + 4).unwrap_or(0);
    let frag = be16(d, o + 6).unwrap_or(0);
    let ttl = d[o + 8];
    let proto = d[o + 9];
    let src = ip4(d, o + 12).unwrap();
    let dst = ip4(d, o + 16).unwrap();
    m.src_ip = Some(IpAddr::V4(src));
    m.dst_ip = Some(IpAddr::V4(dst));
    m.ttl = Some(ttl);
    let end = if total >= ihl { (o + total).min(d.len()) } else { d.len() };
    tb.layer("ip", |l| format!("{} — {src} → {dst}", l.pick("IPv4 (Internet Protocol)", "IPv4 (Internet Protocol)")),
        ("Couche « réseau » : l'adresse postale du paquet sur Internet. L'adresse IP source est l'expéditeur, la destination le destinataire.",
         "Network layer: the postal address of the packet on the Internet. The source IP is the sender, the destination the recipient."),
        o, ihl);
    tb.f("Version", "Version", || "4".into());
    tb.f("Longueur de l'en-tête", "Header length", || format!("{ihl} bytes"));
    tb.f("Longueur totale", "Total length", || total.to_string());
    tb.f("Identification", "Identification", || format!("0x{ident:04x}"));
    tb.fh("Fragmentation", "Fragmentation", || {
        let mut s = Vec::new();
        if frag & 0x4000 != 0 { s.push("Don't fragment"); }
        if frag & 0x2000 != 0 { s.push("More fragments"); }
        format!("{} offset={}", s.join(", "), (frag & 0x1fff) * 8)
    }, "Un gros paquet peut être découpé en morceaux (fragments).", "A big packet can be split into pieces (fragments).");
    tb.fh("Durée de vie (TTL)", "Time to live (TTL)", || ttl.to_string(),
        "Nombre de routeurs que le paquet peut encore traverser. Chaque routeur retire 1 ; à 0, le paquet est détruit. Indice : 64 ≈ Linux/Mac/Android, 128 ≈ Windows.",
        "Number of routers the packet may still cross. Each router subtracts 1; at 0 the packet is dropped. Hint: 64 ≈ Linux/Mac/Android, 128 ≈ Windows.");
    tb.fh("Protocole", "Protocol", || format!("{proto} ({})", ip_proto_name(proto)),
        "Ce que transporte le paquet IP (TCP, UDP, ICMP…).", "What the IP packet carries (TCP, UDP, ICMP…).");
    tb.f("Source", "Source", || src.to_string());
    tb.f("Destination", "Destination", || dst.to_string());
    if frag & 0x1fff != 0 {
        m.info = format!("Fragmented IP protocol (proto={proto}, off={})", (frag & 0x1fff) * 8);
        return;
    }
    transport(proto, d, o + ihl, end, m, tb);
}

fn ipv6(d: &[u8], o: usize, m: &mut Meta, tb: &mut Tb) {
    if d.len() < o + 40 {
        m.malformed = true;
        return;
    }
    m.protos |= p::IPV6;
    m.proto_name = "IPv6";
    let plen = be16(d, o + 4).unwrap_or(0) as usize;
    let mut next = d[o + 6];
    let hop = d[o + 7];
    let src = ip6(d, o + 8).unwrap();
    let dst = ip6(d, o + 24).unwrap();
    m.src_ip = Some(IpAddr::V6(src));
    m.dst_ip = Some(IpAddr::V6(dst));
    m.ttl = Some(hop);
    let end = (o + 40 + plen).min(d.len());
    tb.layer("ipv6", |_| format!("IPv6 — {src} → {dst}"),
        ("La version moderne d'IP, avec des adresses beaucoup plus longues (il y en a assez pour chaque objet de la planète).",
         "The modern version of IP, with much longer addresses (enough for every object on the planet)."),
        o, 40);
    tb.f("Longueur des données", "Payload length", || plen.to_string());
    tb.f("En-tête suivant", "Next header", || format!("{next} ({})", ip_proto_name(next)));
    tb.fh("Limite de sauts", "Hop limit", || hop.to_string(),
        "Équivalent du TTL d'IPv4 : nombre de routeurs encore traversables.", "IPv6 equivalent of TTL: routers that can still be crossed.");
    tb.f("Source", "Source", || src.to_string());
    tb.f("Destination", "Destination", || dst.to_string());
    // En-têtes d'extension.
    let mut off = o + 40;
    for _ in 0..8 {
        match next {
            0 | 43 | 60 => {
                let (Some(&nh), Some(&len)) = (d.get(off), d.get(off + 1)) else { break };
                next = nh;
                off += (len as usize + 1) * 8;
            }
            44 => {
                let Some(&nh) = d.get(off) else { break };
                let fo = be16(d, off + 2).unwrap_or(0);
                if fo & 0xfff8 != 0 {
                    m.info = "IPv6 fragment".into();
                    return;
                }
                next = nh;
                off += 8;
            }
            51 => {
                let (Some(&nh), Some(&len)) = (d.get(off), d.get(off + 1)) else { break };
                next = nh;
                off += (len as usize + 2) * 4;
            }
            _ => break,
        }
    }
    if off > end {
        m.malformed = true;
        return;
    }
    transport(next, d, off, end, m, tb);
}

pub fn ip_proto_name(p: u8) -> &'static str {
    match p {
        1 => "ICMP",
        2 => "IGMP",
        6 => "TCP",
        17 => "UDP",
        41 => "IPv6-in-IPv4",
        47 => "GRE",
        50 => "ESP (IPsec)",
        51 => "AH (IPsec)",
        58 => "ICMPv6",
        89 => "OSPF",
        103 => "PIM",
        112 => "VRRP",
        132 => "SCTP",
        _ => "?",
    }
}

fn transport(proto: u8, d: &[u8], o: usize, end: usize, m: &mut Meta, tb: &mut Tb) {
    match proto {
        6 => tcp(d, o, end, m, tb),
        17 => udp(d, o, end, m, tb),
        1 => apps::icmp(d, o, end, m, tb),
        58 => apps::icmpv6(d, o, end, m, tb),
        2 => apps::igmp(d, o, end, m, tb),
        50 => {
            m.proto_name = "ESP";
            m.info = "IPsec ESP (VPN chiffré)".into();
        }
        47 => {
            m.proto_name = "GRE";
            m.info = "GRE tunnel".into();
        }
        x => m.info = format!("IP protocol {x} ({})", ip_proto_name(x)),
    }
}

fn tcp_flags_str(f: u8) -> String {
    let names = [(0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"), (0x08, "PSH"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR")];
    names.iter().filter(|(b, _)| f & b != 0).map(|(_, n)| *n).collect::<Vec<_>>().join(", ")
}

fn tcp(d: &[u8], o: usize, end: usize, m: &mut Meta, tb: &mut Tb) {
    if end < o + 20 || d.len() < o + 20 {
        m.malformed = true;
        return;
    }
    m.protos |= p::TCP;
    m.proto_name = "TCP";
    let sp = be16(d, o).unwrap();
    let dp = be16(d, o + 2).unwrap();
    let seq = be32(d, o + 4).unwrap();
    let ack = be32(d, o + 8).unwrap();
    let doff = ((d[o + 12] >> 4) as usize) * 4;
    let flags = d[o + 13];
    let win = be16(d, o + 14).unwrap();
    if doff < 20 || o + doff > end {
        m.malformed = true;
        return;
    }
    let payload = &d[o + doff..end];
    m.src_port = Some(sp);
    m.dst_port = Some(dp);
    m.payload_len = payload.len() as u32;
    m.tcp = Some(TcpInfo { flags, seq, ack, window: win, payload: payload.len() as u32 });
    m.info = format!("{sp} → {dp} [{}] Win={win} Len={}", tcp_flags_str(flags), payload.len());
    let svc_hint = apps::service_name(dp, false).or(apps::service_name(sp, false));
    tb.layer("tcp", |l| format!("{} — {sp} → {dp}{}", l.pick("TCP (connexion fiable)", "TCP (reliable connection)"),
            svc_hint.map(|s| format!(" ({s})")).unwrap_or_default()),
        ("Couche « transport » : TCP garantit que les données arrivent complètes et dans l'ordre, comme un envoi recommandé avec accusé de réception. Les ports indiquent quel programme est concerné (443 = site web sécurisé…).",
         "Transport layer: TCP guarantees data arrives complete and in order, like registered mail with acknowledgment. Ports say which program is involved (443 = secure website…)."),
        o, doff);
    tb.fh("Port source", "Source port", || port_label(sp, false),
        "Numéro de « porte » du programme émetteur. Les ports élevés (> 49152) sont souvent choisis au hasard par le client.",
        "Sending program's 'door' number. High ports (> 49152) are usually picked at random by the client.");
    tb.fh("Port destination", "Destination port", || port_label(dp, false),
        "Numéro de « porte » du service visé (80 = web, 443 = web sécurisé, 22 = SSH…).",
        "'Door' number of the targeted service (80 = web, 443 = secure web, 22 = SSH…).");
    tb.fh("Numéro de séquence", "Sequence number", || seq.to_string(),
        "Position des données dans le flux, pour les remettre dans l'ordre.", "Position of the data in the stream, to put it back in order.");
    tb.fh("Accusé de réception", "Acknowledgment number", || ack.to_string(),
        "« J'ai bien reçu tout jusqu'à ce numéro. »", "'I have received everything up to this number.'");
    tb.fh("Drapeaux", "Flags", || format!("0x{flags:02x} [{}]", tcp_flags_str(flags)),
        "SYN = ouverture, ACK = accusé, FIN = fermeture polie, RST = coupure brutale, PSH = données à livrer tout de suite.",
        "SYN = open, ACK = acknowledge, FIN = polite close, RST = abrupt reset, PSH = deliver data now.");
    tb.fh("Fenêtre", "Window", || win.to_string(),
        "Quantité de données que le récepteur accepte avant d'envoyer un accusé.", "How much data the receiver accepts before acknowledging.");
    if tb.on && doff > 20 {
        let opts = tcp_options(&d[o + 20..o + doff]);
        tb.f("Options", "Options", || opts);
    }
    tb.f("Données", "Payload", || format!("{} bytes", payload.len()));
    if !payload.is_empty() {
        apps::tcp_app(payload, o + doff, sp, dp, m, tb);
    }
}

fn tcp_options(mut o: &[u8]) -> String {
    let mut out = Vec::new();
    while let Some(&kind) = o.first() {
        match kind {
            0 => break,
            1 => {
                o = &o[1..];
                continue;
            }
            _ => {
                let len = *o.get(1).unwrap_or(&2) as usize;
                if len < 2 || len > o.len() {
                    break;
                }
                let body = &o[2..len];
                out.push(match kind {
                    2 if body.len() == 2 => format!("MSS={}", u16::from_be_bytes([body[0], body[1]])),
                    3 if body.len() == 1 => format!("WS={}", 1u32 << body[0].min(14)),
                    4 => "SACK_PERM".into(),
                    5 => "SACK".into(),
                    8 => "TS".into(),
                    k => format!("opt{k}"),
                });
                o = &o[len..];
            }
        }
    }
    out.join(", ")
}

pub fn port_label(port: u16, udp: bool) -> String {
    match apps::service_name(port, udp) {
        Some(s) => format!("{port} ({s})"),
        None => port.to_string(),
    }
}

fn udp(d: &[u8], o: usize, end: usize, m: &mut Meta, tb: &mut Tb) {
    if end < o + 8 || d.len() < o + 8 {
        m.malformed = true;
        return;
    }
    m.protos |= p::UDP;
    m.proto_name = "UDP";
    let sp = be16(d, o).unwrap();
    let dp = be16(d, o + 2).unwrap();
    let len = be16(d, o + 4).unwrap() as usize;
    let stop = if len >= 8 { (o + len).min(end) } else { end };
    let payload = &d[o + 8..stop];
    m.src_port = Some(sp);
    m.dst_port = Some(dp);
    m.payload_len = payload.len() as u32;
    m.info = format!("{sp} → {dp} Len={}", payload.len());
    let svc_hint = apps::service_name(dp, true).or(apps::service_name(sp, true));
    tb.layer("udp", |l| format!("{} — {sp} → {dp}{}", l.pick("UDP (message rapide)", "UDP (fast datagram)"),
            svc_hint.map(|s| format!(" ({s})")).unwrap_or_default()),
        ("Couche « transport » : UDP envoie des messages sans garantie de livraison, comme une carte postale. Plus rapide que TCP, il est utilisé pour le DNS, la vidéo, les jeux, les appels…",
         "Transport layer: UDP sends messages without delivery guarantee, like a postcard. Faster than TCP, it's used for DNS, video, games, calls…"),
        o, 8);
    tb.f("Port source", "Source port", || port_label(sp, true));
    tb.f("Port destination", "Destination port", || port_label(dp, true));
    tb.f("Longueur", "Length", || len.to_string());
    if !payload.is_empty() {
        apps::udp_app(payload, o + 8, sp, dp, m, tb);
    }
}

// ---------------------------------------------------------------------------
// Catégorisation
// ---------------------------------------------------------------------------

fn categorize(m: &Meta) -> Category {
    let f = m.tcp_flags();
    if f & TCP_RST != 0 {
        return Category::Problem;
    }
    match &m.app {
        App::Icmp { t, .. } if matches!((m.has(p::ICMP), *t), (true, 3) | (true, 11) | (true, 12)) => return Category::Problem,
        App::Icmp { t, .. } if m.has(p::ICMPV6) && matches!(*t, 1..=4) => return Category::Problem,
        App::Dns(dns) if dns.response && dns.rcode != 0 => return Category::Problem,
        _ => {}
    }
    if m.malformed {
        return Category::Problem;
    }
    if m.has(p::MDNS) || m.has(p::LLMNR) || m.has(p::NBNS) || m.has(p::SSDP) || m.has(p::ARP)
        || m.has(p::LLDP) || m.has(p::STP) || m.has(p::IGMP) || m.has(p::EAPOL)
    {
        return Category::LocalNet;
    }
    if m.has(p::DNS) {
        return Category::Dns;
    }
    if m.has(p::DHCP) || m.has(p::DHCPV6) || m.has(p::ICMP) || m.has(p::ICMPV6) || m.has(p::NTP) || m.has(p::SNMP) {
        return Category::Network;
    }
    if m.has(p::HTTP) {
        return Category::Web;
    }
    if m.has(p::TLS) || m.has(p::QUIC) {
        // Un e-mail ou un DNS chiffré reste dans sa famille.
        match m.service_port() {
            Some(465 | 587 | 993 | 995) => return Category::Mail,
            _ => return Category::SecureWeb,
        }
    }
    if m.has(p::SMTP) || m.has(p::POP) || m.has(p::IMAP) {
        return Category::Mail;
    }
    if m.has(p::FTP) || m.has(p::SMB) {
        return Category::Files;
    }
    if m.has(p::SSH) || m.has(p::RDP) || m.has(p::TELNET) {
        return Category::Remote;
    }
    if m.has(p::STUN) {
        return Category::Media;
    }
    match m.service_port() {
        Some(80 | 8080 | 8000) => Category::Web,
        Some(443 | 8443) => Category::SecureWeb,
        Some(853) => Category::Dns,
        Some(25 | 110 | 143 | 465 | 587 | 993 | 995) => Category::Mail,
        Some(20 | 21 | 445 | 139 | 548 | 2049) => Category::Files,
        Some(22 | 23 | 3389 | 5900) => Category::Remote,
        Some(3478 | 5004 | 5060 | 19302..=19309) => Category::Media,
        Some(67 | 68 | 123 | 161) => Category::Network,
        Some(137 | 138 | 1900 | 5353 | 5355) => Category::LocalNet,
        _ if m.is_broadcast() || m.is_multicast() => Category::LocalNet,
        _ => Category::Other,
    }
}
