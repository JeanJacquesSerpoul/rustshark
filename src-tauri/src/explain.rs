//! Résumés et explications en langage simple, en français ou en anglais.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rustshark_shared::Lang;

use crate::apps::{self, App};
use crate::dissect::{fmt_mac, is_private, p, Meta, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};

macro_rules! l {
    ($lang:expr, $fr:literal, $en:literal $(, $arg:expr)* $(,)?) => {
        match $lang {
            Lang::Fr => format!($fr $(, $arg)*),
            Lang::En => format!($en $(, $arg)*),
        }
    };
}

// ---------------------------------------------------------------------------
// Noms appris passivement
// ---------------------------------------------------------------------------

/// Noms d'hôtes déduits du trafic observé (aucune requête n'est émise).
#[derive(Default)]
pub struct Names {
    map: HashMap<IpAddr, String>,
    pub local: HashSet<IpAddr>,
}

impl Names {
    pub fn clear_learned(&mut self) {
        self.map.clear();
    }

    pub fn learn(&mut self, m: &Meta) {
        match &m.app {
            App::Dns(d) if d.response && d.rcode == 0 => {
                let mdns = m.has(p::MDNS) || m.has(p::LLMNR);
                let asked = d.questions.first().map(|q| q.0.clone());
                for a in &d.answers {
                    if let Some(ip) = a.ip {
                        let name = if mdns { a.name.clone() } else { asked.clone().unwrap_or_else(|| a.name.clone()) };
                        if mdns {
                            self.map.insert(ip, name);
                        } else {
                            self.map.entry(ip).or_insert(name);
                        }
                    }
                }
            }
            App::Tls(t) => {
                if let (Some(sni), Some(ip)) = (&t.sni, m.dst_ip) {
                    self.map.entry(ip).or_insert_with(|| sni.clone());
                }
            }
            App::Http(h) if h.request => {
                if let (Some(host), Some(ip)) = (&h.host, m.dst_ip) {
                    let host = host.split(':').next().unwrap_or(host).to_string();
                    if host.parse::<IpAddr>().is_err() {
                        self.map.entry(ip).or_insert(host);
                    }
                }
            }
            App::Dhcp(d) => {
                if let Some(h) = &d.hostname {
                    let ip = if !d.your_ip.is_unspecified() { Some(d.your_ip) } else { d.requested_ip };
                    if let Some(ip) = ip {
                        self.map.insert(IpAddr::V4(ip), h.clone());
                    }
                }
            }
            _ => {}
        }
    }

    pub fn learned(&self, ip: &IpAddr) -> Option<&str> {
        self.map.get(ip).map(|s| s.as_str())
    }

    /// Libellé humain pour une adresse, si on en connaît un.
    pub fn label(&self, ip: &IpAddr, lang: Lang) -> Option<String> {
        if self.local.contains(ip) {
            return Some(lang.pick("Cet ordinateur", "This computer").into());
        }
        if let Some(n) = self.map.get(ip) {
            return Some(n.clone());
        }
        special_label(ip, lang)
    }

    pub fn who(&self, ip: Option<IpAddr>, mac: Option<[u8; 6]>, lang: Lang) -> String {
        match ip {
            Some(ip) => self.label(&ip, lang).unwrap_or_else(|| ip.to_string()),
            None => mac.map(|m| fmt_mac(&m)).unwrap_or_else(|| "?".into()),
        }
    }
}

fn special_label(ip: &IpAddr, lang: Lang) -> Option<String> {
    let s = match ip {
        IpAddr::V4(a) if *a == Ipv4Addr::BROADCAST => lang.pick("Tout le réseau (diffusion)", "Whole network (broadcast)"),
        IpAddr::V4(a) if a.is_unspecified() => lang.pick("Aucune adresse (pas encore attribuée)", "No address (not yet assigned)"),
        IpAddr::V4(a) if a.is_loopback() => lang.pick("Cet ordinateur (boucle locale)", "This computer (loopback)"),
        IpAddr::V4(a) if *a == Ipv4Addr::new(224, 0, 0, 251) => lang.pick("Groupe mDNS (appareils locaux)", "mDNS group (local devices)"),
        IpAddr::V4(a) if *a == Ipv4Addr::new(239, 255, 255, 250) => lang.pick("Groupe UPnP (appareils locaux)", "UPnP group (local devices)"),
        IpAddr::V4(a) if *a == Ipv4Addr::new(224, 0, 0, 252) => lang.pick("Groupe LLMNR (PC Windows)", "LLMNR group (Windows PCs)"),
        IpAddr::V4(a) if *a == Ipv4Addr::new(224, 0, 0, 1) => lang.pick("Tous les appareils du réseau", "All devices on the network"),
        IpAddr::V4(a) if *a == Ipv4Addr::new(224, 0, 0, 22) => lang.pick("Routeurs multicast (IGMP)", "Multicast routers (IGMP)"),
        IpAddr::V4(a) if a.octets()[3] == 255 && a.is_private() => lang.pick("Tout le réseau local (diffusion)", "Whole local network (broadcast)"),
        IpAddr::V4(a) if a.is_multicast() => lang.pick("Groupe multicast", "Multicast group"),
        IpAddr::V6(a) if a.is_loopback() => lang.pick("Cet ordinateur (boucle locale)", "This computer (loopback)"),
        IpAddr::V6(a) if a.is_unspecified() => lang.pick("Aucune adresse", "No address"),
        IpAddr::V6(a) if *a == Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb) => lang.pick("Groupe mDNS (appareils locaux)", "mDNS group (local devices)"),
        IpAddr::V6(a) if *a == Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1) => lang.pick("Tous les appareils (IPv6)", "All devices (IPv6)"),
        IpAddr::V6(a) if *a == Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2) => lang.pick("Tous les routeurs (IPv6)", "All routers (IPv6)"),
        IpAddr::V6(a) if *a == Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xc) => lang.pick("Groupe UPnP (appareils locaux)", "UPnP group (local devices)"),
        IpAddr::V6(a) if *a == Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 3) => lang.pick("Groupe LLMNR (PC Windows)", "LLMNR group (Windows PCs)"),
        IpAddr::V6(a) if *a == Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x16) => lang.pick("Routeurs multicast (MLD)", "Multicast routers (MLD)"),
        IpAddr::V6(a) if a.is_multicast() => lang.pick("Groupe multicast IPv6", "IPv6 multicast group"),
        _ => return None,
    };
    Some(s.into())
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

pub fn service_desc(port: u16, udp: bool, lang: Lang) -> Option<String> {
    let s = match port {
        443 if udp => lang.pick("web sécurisé rapide (QUIC / HTTP3)", "fast secure web (QUIC / HTTP3)"),
        443 | 8443 => lang.pick("web sécurisé (HTTPS)", "secure web (HTTPS)"),
        80 | 8080 | 8000 => lang.pick("web non chiffré (HTTP)", "unencrypted web (HTTP)"),
        53 => lang.pick("annuaire DNS", "DNS directory"),
        853 => lang.pick("annuaire DNS chiffré", "encrypted DNS directory"),
        22 => lang.pick("terminal à distance sécurisé (SSH)", "secure remote shell (SSH)"),
        23 => lang.pick("terminal à distance NON chiffré (Telnet)", "UNENCRYPTED remote shell (Telnet)"),
        21 => lang.pick("transfert de fichiers non chiffré (FTP)", "unencrypted file transfer (FTP)"),
        25 | 587 | 465 => lang.pick("envoi d'e-mails (SMTP)", "sending e-mail (SMTP)"),
        110 => lang.pick("réception d'e-mails non chiffrée (POP3)", "unencrypted e-mail retrieval (POP3)"),
        995 => lang.pick("réception d'e-mails sécurisée (POP3S)", "secure e-mail retrieval (POP3S)"),
        143 => lang.pick("boîte e-mail non chiffrée (IMAP)", "unencrypted mailbox (IMAP)"),
        993 => lang.pick("boîte e-mail sécurisée (IMAPS)", "secure mailbox (IMAPS)"),
        67 | 68 => lang.pick("attribution d'adresse IP (DHCP)", "IP address assignment (DHCP)"),
        123 => lang.pick("mise à l'heure (NTP)", "time synchronisation (NTP)"),
        137 | 138 | 139 => lang.pick("noms et partages Windows (NetBIOS)", "Windows names and shares (NetBIOS)"),
        445 => lang.pick("partage de fichiers Windows (SMB)", "Windows file sharing (SMB)"),
        3389 => lang.pick("bureau à distance Windows (RDP)", "Windows remote desktop (RDP)"),
        5900 => lang.pick("contrôle à distance (VNC)", "remote control (VNC)"),
        1900 => lang.pick("découverte d'appareils (UPnP)", "device discovery (UPnP)"),
        5353 => lang.pick("découverte d'appareils locaux (mDNS)", "local device discovery (mDNS)"),
        5355 => lang.pick("recherche de noms locaux (LLMNR)", "local name lookup (LLMNR)"),
        5228 => lang.pick("notifications Google / Android", "Google / Android notifications"),
        3478 | 3479 | 19302..=19309 => lang.pick("appels audio/vidéo (STUN)", "audio/video calls (STUN)"),
        5060 | 5061 => lang.pick("téléphonie sur Internet (SIP)", "Internet telephony (SIP)"),
        631 | 9100 => lang.pick("impression", "printing"),
        8008 | 8009 => lang.pick("Chromecast / Google Cast", "Chromecast / Google Cast"),
        1194 | 51820 | 500 | 4500 => lang.pick("VPN", "VPN"),
        3074 => lang.pick("jeux en ligne Xbox", "Xbox online gaming"),
        25565 => lang.pick("serveur Minecraft", "Minecraft server"),
        7680 => lang.pick("mises à jour Windows entre PC", "Windows peer update delivery"),
        _ => return apps::service_name(port, udp).map(|s| s.to_string()),
    };
    Some(s.into())
}

fn svc(m: &Meta, lang: Lang) -> String {
    let udp = m.has(p::UDP);
    m.service_port()
        .and_then(|port| service_desc(port, udp, lang))
        .unwrap_or_else(|| match m.service_port() {
            Some(port) => l!(lang, "port {}", "port {}", port),
            None => m.proto_name.to_string(),
        })
}

fn http_status_desc(code: u16, lang: Lang) -> &'static str {
    match code {
        200..=299 => lang.pick("succès", "success"),
        301 | 302 | 303 | 307 | 308 => lang.pick("redirection vers une autre adresse", "redirect to another address"),
        304 => lang.pick("pas modifié depuis la dernière visite", "not modified since last visit"),
        400 => lang.pick("requête incorrecte", "bad request"),
        401 | 403 => lang.pick("accès refusé", "access denied"),
        404 => lang.pick("page introuvable", "page not found"),
        500..=599 => lang.pick("erreur du serveur", "server error"),
        _ => "",
    }
}

fn first_ips(d: &apps::DnsInfo) -> String {
    let ips: Vec<String> = d.answers.iter().filter_map(|a| a.ip).take(2).map(|i| i.to_string()).collect();
    let more = d.answers.iter().filter(|a| a.ip.is_some()).count().saturating_sub(2);
    if more > 0 {
        format!("{} (+{more})", ips.join(", "))
    } else {
        ips.join(", ")
    }
}

// ---------------------------------------------------------------------------
// Résumé court (colonne du mode simple)
// ---------------------------------------------------------------------------

pub fn summary(m: &Meta, lang: Lang) -> String {
    match &m.app {
        App::Dns(d) => {
            let q = d.questions.first().map(|q| q.0.as_str()).unwrap_or("?");
            let local = m.has(p::MDNS) || m.has(p::LLMNR);
            if !d.response {
                if local {
                    l!(lang, "Recherche sur le réseau local : {}", "Looking on the local network: {}", q)
                } else {
                    l!(lang, "Cherche l'adresse de {}", "Looks up the address of {}", q)
                }
            } else if d.rcode == 3 {
                l!(lang, "« {} » n'existe pas", "'{}' does not exist", q)
            } else if d.rcode != 0 {
                l!(lang, "Erreur de l'annuaire pour {}", "Directory error for {}", q)
            } else if local {
                let n = d.answers.first().map(|a| a.name.as_str()).unwrap_or(q);
                l!(lang, "Un appareil s'annonce : {}", "A device announces itself: {}", n)
            } else {
                let ips = first_ips(d);
                if ips.is_empty() {
                    l!(lang, "Réponse de l'annuaire pour {}", "Directory answer for {}", q)
                } else {
                    format!("{q} → {ips}")
                }
            }
        }
        App::Tls(t) => {
            if t.handshakes.contains(&1) {
                match &t.sni {
                    Some(s) => l!(lang, "Ouvre une connexion sécurisée vers {}", "Opens a secure connection to {}", s),
                    None => lang.pick("Ouvre une connexion sécurisée", "Opens a secure connection").into(),
                }
            } else if t.handshakes.contains(&2) {
                lang.pick("Le serveur accepte la connexion sécurisée", "Server accepts the secure connection").into()
            } else if t.records.contains(&21) && !t.records.contains(&23) {
                lang.pick("Alerte de la connexion sécurisée", "Secure connection alert").into()
            } else if t.records.contains(&23) {
                l!(lang, "Données chiffrées ({} octets)", "Encrypted data ({} bytes)", m.payload_len)
            } else {
                lang.pick("Échange sécurisé (TLS)", "Secure exchange (TLS)").into()
            }
        }
        App::Http(h) => {
            if h.credentials {
                return lang.pick("⚠ Identifiants envoyés en clair (HTTP)", "⚠ Credentials sent in clear text (HTTP)").into();
            }
            if h.request {
                let host = h.host.clone().unwrap_or_default();
                l!(lang, "Demande la page {}{} (non chiffré)", "Requests page {}{} (unencrypted)", host, h.uri)
            } else {
                let c = h.status.unwrap_or(0);
                l!(lang, "Réponse du site : {} {}", "Site response: {} {}", c, http_status_desc(c, lang))
            }
        }
        App::Arp(a) => match a.op {
            1 if a.sender_ip == a.target_ip => l!(lang, "Annonce : « {}, c'est moi »", "Announcement: '{} is me'", a.sender_ip),
            1 => l!(lang, "Qui a l'adresse {} ?", "Who has {}?", a.target_ip),
            2 => l!(lang, "{} est ici ({})", "{} is here ({})", a.sender_ip, fmt_mac(&a.sender_mac)),
            _ => "ARP".into(),
        },
        App::Dhcp(d) => match d.msg_type {
            Some(1) => lang.pick("Cherche un serveur pour obtenir une adresse IP", "Looks for a server to get an IP address").into(),
            Some(2) => l!(lang, "Propose l'adresse {}", "Offers address {}", d.your_ip),
            Some(3) => match d.requested_ip {
                Some(ip) => l!(lang, "Demande l'adresse {}", "Requests address {}", ip),
                None => lang.pick("Demande à renouveler son adresse", "Asks to renew its address").into(),
            },
            Some(5) => l!(lang, "Confirme l'adresse {}", "Confirms address {}", d.your_ip),
            Some(6) => lang.pick("Refuse la demande d'adresse", "Refuses the address request").into(),
            Some(7) => lang.pick("Libère son adresse IP", "Releases its IP address").into(),
            Some(8) => lang.pick("Demande la configuration réseau", "Asks for network settings").into(),
            _ => "DHCP".into(),
        },
        App::Icmp { t, target, .. } => {
            if m.has(p::ICMPV6) {
                let tg = target.map(|t| t.to_string()).unwrap_or_default();
                match t {
                    128 => lang.pick("Ping : « es-tu là ? »", "Ping: 'are you there?'").into(),
                    129 => lang.pick("Réponse au ping : « oui, je suis là »", "Ping reply: 'yes, I'm here'").into(),
                    133 => lang.pick("Cherche un routeur", "Looks for a router").into(),
                    134 => lang.pick("Le routeur s'annonce", "The router announces itself").into(),
                    135 => l!(lang, "Cherche l'appareil {}", "Looks for device {}", tg),
                    136 => l!(lang, "Répond : « {} c'est moi »", "Replies: '{} is me'", tg),
                    131 | 143 => lang.pick("S'abonne à un groupe multicast", "Joins a multicast group").into(),
                    1 => lang.pick("Destination injoignable", "Destination unreachable").into(),
                    3 => lang.pick("Délai dépassé", "Time exceeded").into(),
                    _ => apps::icmpv6_name(*t).into(),
                }
            } else {
                match t {
                    8 => lang.pick("Ping : « es-tu là ? »", "Ping: 'are you there?'").into(),
                    0 => lang.pick("Réponse au ping : « oui, je suis là »", "Ping reply: 'yes, I'm here'").into(),
                    3 => lang.pick("Destination injoignable", "Destination unreachable").into(),
                    11 => lang.pick("Durée de vie dépassée (traceroute ?)", "Time to live exceeded (traceroute?)").into(),
                    5 => lang.pick("Redirection vers un autre routeur", "Redirect to another router").into(),
                    _ => m.info.clone(),
                }
            }
        }
        App::Igmp { t, .. } => match t {
            0x11 => lang.pick("Le routeur demande qui écoute quels flux", "Router asks who listens to which streams").into(),
            0x17 => lang.pick("Quitte un groupe multicast", "Leaves a multicast group").into(),
            _ => lang.pick("S'abonne à un groupe multicast", "Joins a multicast group").into(),
        },
        App::Quic { ptype, .. } => {
            if *ptype == "Initial" {
                lang.pick("Ouvre une connexion web chiffrée (QUIC)", "Opens an encrypted web connection (QUIC)").into()
            } else {
                l!(lang, "Données web chiffrées (QUIC, {} octets)", "Encrypted web data (QUIC, {} bytes)", m.payload_len)
            }
        }
        App::Ntp { mode, .. } => match mode {
            3 => lang.pick("Demande l'heure exacte", "Asks for the exact time").into(),
            4 => lang.pick("Donne l'heure exacte", "Gives the exact time").into(),
            _ => lang.pick("Synchronisation de l'heure", "Time synchronisation").into(),
        },
        App::Text { service, line, credentials } => {
            if *credentials {
                l!(lang, "⚠ Identifiants envoyés en clair ({})", "⚠ Credentials sent in clear text ({})", service)
            } else {
                let short: String = line.chars().take(50).collect();
                l!(lang, "{} en clair : {}", "{} in clear text: {}", service, short)
            }
        }
        App::Ssh { banner } => match banner {
            Some(b) => l!(lang, "Début de session SSH ({})", "SSH session start ({})", b),
            None => lang.pick("Session à distance chiffrée (SSH)", "Encrypted remote session (SSH)").into(),
        },
        App::Nbns { name, .. } => l!(lang, "Recherche le nom Windows {}", "Looks up Windows name {}", name.clone().unwrap_or_default()),
        App::Ssdp { line } => {
            if line.starts_with("M-SEARCH") {
                lang.pick("Cherche des appareils UPnP (TV, box, enceintes…)", "Looks for UPnP devices (TV, router, speakers…)").into()
            } else if line.starts_with("NOTIFY") {
                lang.pick("Un appareil s'annonce (UPnP)", "A device announces itself (UPnP)").into()
            } else {
                lang.pick("Un appareil répond à la recherche UPnP", "A device answers the UPnP search").into()
            }
        }
        App::None => generic_summary(m, lang),
    }
}

fn generic_summary(m: &Meta, lang: Lang) -> String {
    if let Some(t) = &m.tcp {
        let f = t.flags;
        return if f & TCP_RST != 0 {
            lang.pick("Connexion refusée ou coupée", "Connection refused or reset").into()
        } else if f & TCP_SYN != 0 && f & TCP_ACK == 0 {
            l!(lang, "Demande de connexion ({})", "Connection request ({})", svc(m, lang))
        } else if f & TCP_SYN != 0 {
            lang.pick("Accepte la connexion", "Accepts the connection").into()
        } else if f & TCP_FIN != 0 {
            lang.pick("Fin de connexion", "Connection closing").into()
        } else if t.payload > 0 {
            l!(lang, "Données {} ({} octets)", "Data {} ({} bytes)", svc(m, lang), t.payload)
        } else {
            lang.pick("Accusé de réception", "Acknowledgment").into()
        };
    }
    if m.has(p::UDP) {
        return l!(lang, "Message {} ({} octets)", "Message {} ({} bytes)", svc(m, lang), m.payload_len);
    }
    if m.has(p::STP) {
        return lang.pick("Les switchs évitent les boucles réseau", "Switches prevent network loops").into();
    }
    if m.has(p::LLDP) {
        return lang.pick("Un équipement réseau s'identifie", "A network device identifies itself").into();
    }
    if m.has(p::EAPOL) {
        return lang.pick("Authentification Wi-Fi / 802.1X", "Wi-Fi / 802.1X authentication").into();
    }
    if m.malformed {
        return lang.pick("Paquet incomplet ou mal formé", "Incomplete or malformed packet").into();
    }
    l!(lang, "Paquet {}", "{} packet", m.proto_name)
}

// ---------------------------------------------------------------------------
// Explication détaillée + conseils
// ---------------------------------------------------------------------------

pub fn explain(m: &Meta, names: &Names, lang: Lang) -> (String, Vec<String>) {
    let src = names.who(m.src_ip, m.src_mac, lang);
    let dst = names.who(m.dst_ip, m.dst_mac, lang);
    let mut tips: Vec<String> = Vec::new();

    let text = match &m.app {
        App::Dns(d) if !m.has(p::MDNS) && !m.has(p::LLMNR) => {
            let q = d.questions.first().map(|q| q.0.clone()).unwrap_or_default();
            tips.push(lang.pick(
                "💡 Le DNS est l'annuaire d'Internet : avant de visiter un site, l'appareil demande son adresse IP, comme on cherche un numéro de téléphone.",
                "💡 DNS is the Internet's phone book: before visiting a site, the device asks for its IP address, like looking up a phone number.").into());
            if !d.response {
                l!(lang, "{} demande à {} (le serveur DNS) quelle est l'adresse IP de « {} ».",
                    "{} asks {} (the DNS server) for the IP address of '{}'.", src, dst, q)
            } else if d.rcode == 3 {
                tips.push(lang.pick(
                    "Un nom inexistant vient souvent d'une faute de frappe, d'un bloqueur de publicité… ou, s'il se répète beaucoup avec des noms étranges, d'un logiciel suspect.",
                    "A non-existent name often comes from a typo, an ad blocker… or, if it repeats a lot with odd names, from suspicious software.").into());
                l!(lang, "Le serveur DNS {} répond que « {} » n'existe pas.", "DNS server {} replies that '{}' does not exist.", src, q)
            } else {
                let ips = first_ips(d);
                l!(lang, "Le serveur DNS {} répond à {} : « {} » se trouve à l'adresse {}.",
                    "DNS server {} tells {}: '{}' is located at {}.", src, dst, q, if ips.is_empty() { "—".into() } else { ips })
            }
        }
        App::Dns(_) | App::Ssdp { .. } | App::Nbns { .. } => {
            tips.push(lang.pick(
                "💡 Ces messages sont normaux : vos appareils (téléphone, TV, imprimante, enceinte…) se découvrent entre eux sur le réseau local.",
                "💡 These messages are normal: your devices (phone, TV, printer, speaker…) discover each other on the local network.").into());
            l!(lang, "{} : {}.", "{}: {}.", src, summary(m, lang))
        }
        App::Tls(t) => {
            tips.push(lang.pick(
                "🔒 Chiffré : le contenu est illisible pour quiconque observe le réseau. Seul le nom du site (SNI) apparaît au début de la connexion.",
                "🔒 Encrypted: the content is unreadable for anyone watching the network. Only the site name (SNI) appears at the start of the connection.").into());
            if let Some(v) = t.version {
                if v < 0x0303 {
                    tips.push(l!(lang, "⚠️ Version ancienne ({}) : elle n'est plus considérée comme sûre.",
                        "⚠️ Old version ({}): no longer considered safe.", apps::tls_version_name(v)));
                }
            }
            if t.handshakes.contains(&1) {
                l!(lang, "{} commence une connexion chiffrée (le « cadenas » HTTPS) avec {}{}.",
                    "{} starts an encrypted connection (the HTTPS 'padlock') with {}{}.", src, dst,
                    t.sni.as_ref().map(|s| l!(lang, " pour le site « {} »", " for the site '{}'", s)).unwrap_or_default())
            } else if t.records.contains(&23) {
                l!(lang, "{} envoie {} octets de données chiffrées à {}.", "{} sends {} bytes of encrypted data to {}.", src, m.payload_len, dst)
            } else {
                l!(lang, "{} et {} négocient les clés de chiffrement de leur connexion sécurisée.",
                    "{} and {} negotiate the encryption keys of their secure connection.", src, dst)
            }
        }
        App::Http(h) => {
            tips.push(lang.pick(
                "⚠️ Non chiffré : toute personne sur le même réseau (Wi-Fi public par exemple) peut lire ce contenu. Préférez les sites en HTTPS.",
                "⚠️ Unencrypted: anyone on the same network (public Wi-Fi for instance) can read this content. Prefer HTTPS sites.").into());
            if h.credentials {
                tips.push(lang.pick(
                    "🚨 Ce paquet semble contenir un identifiant ou un mot de passe lisible. Changez ce mot de passe s'il est utilisé ailleurs.",
                    "🚨 This packet seems to contain a readable login or password. Change that password if it is used elsewhere.").into());
            }
            if h.request {
                l!(lang, "{} demande la page « {} » au site {} ({}), sans chiffrement.",
                    "{} requests page '{}' from site {} ({}), without encryption.", src, h.uri, h.host.clone().unwrap_or_else(|| dst.clone()), h.method)
            } else {
                let c = h.status.unwrap_or(0);
                l!(lang, "Le site {} répond à {} : code {} ({}).", "Site {} answers {}: code {} ({}).", src, dst, c, http_status_desc(c, lang))
            }
        }
        App::Arp(a) => {
            tips.push(lang.pick(
                "💡 ARP traduit une adresse IP en adresse matérielle (MAC) sur le réseau local. C'est comme crier dans une pièce « Qui s'appelle Paul ? ».",
                "💡 ARP translates an IP address into a hardware (MAC) address on the local network. It's like shouting in a room 'Who is Paul?'.").into());
            match a.op {
                1 => l!(lang, "{} ({}) demande à tout le réseau local : « Qui possède l'adresse {} ? »",
                    "{} ({}) asks the whole local network: 'Who has address {}?'", a.sender_ip, fmt_mac(&a.sender_mac), a.target_ip),
                _ => l!(lang, "{} répond : « L'adresse {} correspond à ma carte réseau {} ».",
                    "{} replies: 'Address {} belongs to my network card {}'.", src, a.sender_ip, fmt_mac(&a.sender_mac)),
            }
        }
        App::Dhcp(d) => {
            tips.push(lang.pick(
                "💡 C'est ainsi qu'un appareil obtient automatiquement son adresse IP en se connectant (Wi-Fi ou câble) : Discover → Offer → Request → ACK.",
                "💡 This is how a device automatically gets its IP address when connecting (Wi-Fi or cable): Discover → Offer → Request → ACK.").into());
            if let Some(h) = &d.hostname {
                tips.push(l!(lang, "L'appareil s'identifie sous le nom « {} ».", "The device identifies itself as '{}'.", h));
            }
            l!(lang, "{} : {}.", "{}: {}.", names.who(m.src_ip, m.src_mac, lang), summary(m, lang))
        }
        App::Icmp { t, .. } => {
            if matches!((m.has(p::ICMP), *t), (true, 8) | (true, 0)) || matches!(*t, 128 | 129) {
                tips.push(lang.pick(
                    "💡 La commande « ping » vérifie si un appareil répond et mesure le temps de réponse.",
                    "💡 The 'ping' command checks whether a device responds and measures the response time.").into());
            }
            if m.has(p::ICMPV6) && matches!(*t, 133..=136) {
                tips.push(lang.pick(
                    "💡 En IPv6, les appareils trouvent leurs voisins et leur routeur avec ces messages (l'équivalent d'ARP).",
                    "💡 In IPv6, devices find their neighbours and router with these messages (the equivalent of ARP).").into());
            }
            if m.is_problem() {
                tips.push(lang.pick(
                    "Ce message signale un problème d'acheminement : service fermé, pare-feu, ou appareil hors ligne.",
                    "This message reports a delivery problem: closed service, firewall, or offline device.").into());
            }
            l!(lang, "{} → {} : {}.", "{} → {}: {}.", src, dst, summary(m, lang))
        }
        App::Quic { .. } => {
            tips.push(lang.pick(
                "🔒 QUIC est le protocole moderne des sites Google, YouTube, Facebook… Tout est chiffré, y compris une partie des informations de connexion.",
                "🔒 QUIC is the modern protocol of Google, YouTube, Facebook… sites. Everything is encrypted, including part of the connection details.").into());
            l!(lang, "{} et {} échangent du trafic web chiffré via QUIC (HTTP/3).", "{} and {} exchange encrypted web traffic over QUIC (HTTP/3).", src, dst)
        }
        App::Text { service, credentials, .. } => {
            tips.push(l!(lang, "⚠️ {} transmet tout en clair : commandes, contenus et identifiants sont lisibles.",
                "⚠️ {} sends everything in clear text: commands, contents and credentials are readable.", service));
            if *credentials {
                tips.push(lang.pick(
                    "🚨 Un identifiant ou un mot de passe circule en clair dans ce paquet.",
                    "🚨 A login or password travels in clear text in this packet.").into());
            }
            l!(lang, "{} → {} : {}.", "{} → {}: {}.", src, dst, summary(m, lang))
        }
        _ => {
            if let Some(t) = &m.tcp {
                if t.flags & TCP_SYN != 0 {
                    tips.push(lang.pick(
                        "💡 Une connexion TCP commence par une « poignée de main » en 3 temps : SYN (on peut parler ?) → SYN/ACK (oui) → ACK (c'est parti).",
                        "💡 A TCP connection starts with a 3-way 'handshake': SYN (can we talk?) → SYN/ACK (yes) → ACK (let's go).").into());
                }
                if t.flags & TCP_RST != 0 {
                    tips.push(lang.pick(
                        "Une connexion refusée signifie souvent qu'aucun programme n'écoute sur ce port, ou qu'un pare-feu bloque l'accès.",
                        "A refused connection often means no program listens on that port, or a firewall blocks access.").into());
                }
            }
            match m.tcp.as_ref().map(|t| t.flags) {
                Some(f) if f & TCP_SYN != 0 && f & TCP_ACK == 0 => l!(lang, "{} demande à ouvrir une connexion avec {} pour le service {}.",
                    "{} asks to open a connection with {} for the service {}.", src, dst, svc(m, lang)),
                Some(f) if f & TCP_SYN != 0 => l!(lang, "{} accepte la connexion demandée par {}.", "{} accepts the connection requested by {}.", src, dst),
                Some(f) if f & TCP_RST != 0 => l!(lang, "{} coupe brutalement (ou refuse) la connexion avec {}.", "{} abruptly resets (or refuses) the connection with {}.", src, dst),
                Some(f) if f & TCP_FIN != 0 => l!(lang, "{} termine poliment sa connexion avec {}.", "{} politely closes its connection with {}.", src, dst),
                _ => l!(lang, "{} → {} : {}.", "{} → {}: {}.", src, dst, summary(m, lang)),
            }
        }
    };

    if let (Some(port), Some(desc)) = (m.service_port(), m.service_port().and_then(|pt| service_desc(pt, m.has(p::UDP), lang))) {
        tips.push(l!(lang, "🔌 Port {} : {}.", "🔌 Port {}: {}.", port, desc));
    }
    match (m.src_ip, m.dst_ip) {
        (Some(a), Some(b)) if !crate::dissect::is_local_scope(&a) || !crate::dissect::is_local_scope(&b) => {
            tips.push(lang.pick("🌍 Ce paquet transite par Internet.", "🌍 This packet travels over the Internet.").into())
        }
        (Some(a), Some(b)) if is_private(&a) || is_private(&b) => {
            tips.push(lang.pick("🏠 Ce paquet reste dans votre réseau local.", "🏠 This packet stays within your local network.").into())
        }
        _ => {}
    }
    (text, tips)
}
