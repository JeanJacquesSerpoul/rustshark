//! Langage de filtre d'affichage RustShark.
//!
//! Volontairement proche de Wireshark mais plus tolérant pour les débutants :
//!
//! ```text
//! dns                          protocole présent
//! ip.addr == 192.168.1.0/24    adresse (ou réseau CIDR)
//! tcp.port == 443 && !tls      opérateurs && || ! (ou and / or / not)
//! host contains google         recherche dans les noms
//! host == *.youtube.com        joker *
//! youtube                      un mot seul = recherche plein texte
//! ```

use std::net::IpAddr;

use crate::Lang;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Protocole ou propriété booléenne (`dns`, `tcp.flags.syn`, `internet`).
    Flag,
    Ip,
    Num,
    Text,
}

pub struct FieldDef {
    pub name: &'static str,
    pub kind: Kind,
    pub fr: &'static str,
    pub en: &'static str,
}

const fn f(name: &'static str, kind: Kind, fr: &'static str, en: &'static str) -> FieldDef {
    FieldDef { name, kind, fr, en }
}

use Kind::*;

pub const FIELDS: &[FieldDef] = &[
    // Protocoles
    f("eth", Flag, "Ethernet (réseau local filaire/Wi-Fi)", "Ethernet (local wired/Wi-Fi network)"),
    f("vlan", Flag, "Réseau virtuel 802.1Q", "802.1Q virtual LAN"),
    f("arp", Flag, "ARP : qui possède cette adresse IP ?", "ARP: who owns this IP address?"),
    f("ip", Flag, "IPv4", "IPv4"),
    f("ipv6", Flag, "IPv6", "IPv6"),
    f("icmp", Flag, "ICMP (ping, erreurs)", "ICMP (ping, errors)"),
    f("icmpv6", Flag, "ICMPv6", "ICMPv6"),
    f("igmp", Flag, "IGMP (groupes multicast)", "IGMP (multicast groups)"),
    f("tcp", Flag, "TCP (connexions fiables)", "TCP (reliable connections)"),
    f("udp", Flag, "UDP (messages rapides)", "UDP (fast datagrams)"),
    f("dns", Flag, "DNS (annuaire d'Internet)", "DNS (Internet directory)"),
    f("mdns", Flag, "mDNS (découverte locale Apple/Chromecast…)", "mDNS (local discovery)"),
    f("llmnr", Flag, "LLMNR (noms locaux Windows)", "LLMNR (Windows local names)"),
    f("nbns", Flag, "NetBIOS (noms Windows)", "NetBIOS (Windows names)"),
    f("dhcp", Flag, "DHCP (attribution d'adresse IP)", "DHCP (IP address assignment)"),
    f("dhcpv6", Flag, "DHCPv6", "DHCPv6"),
    f("http", Flag, "HTTP (web non chiffré)", "HTTP (unencrypted web)"),
    f("tls", Flag, "TLS (web chiffré, HTTPS)", "TLS (encrypted web, HTTPS)"),
    f("quic", Flag, "QUIC / HTTP3 (web chiffré)", "QUIC / HTTP3 (encrypted web)"),
    f("ntp", Flag, "NTP (heure)", "NTP (time)"),
    f("ssdp", Flag, "SSDP / UPnP (découverte d'appareils)", "SSDP / UPnP (device discovery)"),
    f("ssh", Flag, "SSH (terminal distant chiffré)", "SSH (encrypted remote shell)"),
    f("ftp", Flag, "FTP (fichiers, non chiffré)", "FTP (files, unencrypted)"),
    f("telnet", Flag, "Telnet (terminal non chiffré)", "Telnet (unencrypted shell)"),
    f("smtp", Flag, "SMTP (envoi d'e-mails)", "SMTP (sending e-mail)"),
    f("pop", Flag, "POP3 (réception d'e-mails)", "POP3 (receiving e-mail)"),
    f("imap", Flag, "IMAP (boîte e-mail)", "IMAP (mailbox)"),
    f("smb", Flag, "SMB (partage de fichiers Windows)", "SMB (Windows file sharing)"),
    f("rdp", Flag, "RDP (bureau à distance)", "RDP (remote desktop)"),
    f("snmp", Flag, "SNMP (supervision)", "SNMP (monitoring)"),
    f("stun", Flag, "STUN (appels vidéo/voix)", "STUN (video/voice calls)"),
    f("lldp", Flag, "LLDP (découverte d'équipements)", "LLDP (equipment discovery)"),
    f("stp", Flag, "STP (anti-boucles des switchs)", "STP (switch loop prevention)"),
    f("eapol", Flag, "EAPOL (authentification Wi-Fi)", "EAPOL (Wi-Fi authentication)"),
    // Propriétés
    f("tcp.flags.syn", Flag, "Ouverture de connexion TCP", "TCP connection opening"),
    f("tcp.flags.ack", Flag, "Accusé de réception TCP", "TCP acknowledgment"),
    f("tcp.flags.fin", Flag, "Fermeture de connexion TCP", "TCP connection closing"),
    f("tcp.flags.rst", Flag, "Connexion refusée / coupée", "Connection refused / reset"),
    f("tcp.flags.push", Flag, "Données poussées", "Pushed data"),
    f("dns.response", Flag, "Réponse DNS", "DNS response"),
    f("http.request", Flag, "Requête HTTP", "HTTP request"),
    f("http.response", Flag, "Réponse HTTP", "HTTP response"),
    f("tls.client_hello", Flag, "Début de connexion sécurisée", "Secure connection start"),
    f("broadcast", Flag, "Envoyé à tout le réseau local", "Sent to the whole local network"),
    f("multicast", Flag, "Envoyé à un groupe d'appareils", "Sent to a group of devices"),
    f("local", Flag, "Trafic interne au réseau local", "Traffic inside the local network"),
    f("internet", Flag, "Trafic vers/depuis Internet", "Traffic to/from the Internet"),
    f("this_computer", Flag, "Trafic de/vers cet ordinateur", "Traffic from/to this computer"),
    f("problem", Flag, "Erreurs et connexions refusées", "Errors and refused connections"),
    f("cleartext", Flag, "Données lisibles en clair (non chiffrées)", "Readable cleartext data"),
    // Adresses
    f("ip.addr", Ip, "Adresse IP source ou destination", "Source or destination IP address"),
    f("ip.src", Ip, "Adresse IP source", "Source IP address"),
    f("ip.dst", Ip, "Adresse IP destination", "Destination IP address"),
    f("dns.a", Ip, "Adresse IP renvoyée par le DNS", "IP address returned by DNS"),
    // Nombres
    f("port", Num, "Port source ou destination", "Source or destination port"),
    f("src.port", Num, "Port source", "Source port"),
    f("dst.port", Num, "Port destination", "Destination port"),
    f("tcp.port", Num, "Port TCP", "TCP port"),
    f("udp.port", Num, "Port UDP", "UDP port"),
    f("tcp.srcport", Num, "Port TCP source", "TCP source port"),
    f("tcp.dstport", Num, "Port TCP destination", "TCP destination port"),
    f("udp.srcport", Num, "Port UDP source", "UDP source port"),
    f("udp.dstport", Num, "Port UDP destination", "UDP destination port"),
    f("frame.len", Num, "Taille du paquet (octets)", "Packet size (bytes)"),
    f("frame.number", Num, "Numéro du paquet", "Packet number"),
    f("ip.ttl", Num, "Durée de vie (TTL)", "Time to live (TTL)"),
    f("http.status", Num, "Code de réponse HTTP", "HTTP response code"),
    f("dns.rcode", Num, "Code de réponse DNS (0 = OK)", "DNS response code (0 = OK)"),
    f("icmp.type", Num, "Type ICMP", "ICMP type"),
    // Texte
    f("host", Text, "Nom d'hôte (DNS, site, appareil)", "Host name (DNS, site, device)"),
    f("eth.addr", Text, "Adresse MAC source ou destination", "Source or destination MAC address"),
    f("eth.src", Text, "Adresse MAC source", "Source MAC address"),
    f("eth.dst", Text, "Adresse MAC destination", "Destination MAC address"),
    f("dns.qry.name", Text, "Nom demandé au DNS", "Name queried in DNS"),
    f("tls.sni", Text, "Site demandé en HTTPS", "Site requested over HTTPS"),
    f("http.host", Text, "Site demandé en HTTP", "Site requested over HTTP"),
    f("http.method", Text, "Méthode HTTP (GET, POST…)", "HTTP method (GET, POST…)"),
    f("http.uri", Text, "Chemin HTTP demandé", "Requested HTTP path"),
    f("http.user_agent", Text, "Logiciel client HTTP", "HTTP client software"),
    f("protocol", Text, "Nom du protocole affiché", "Displayed protocol name"),
    f("category", Text, "Catégorie (web, dns, localnet…)", "Category (web, dns, localnet…)"),
    f("info", Text, "Résumé technique", "Technical summary"),
];

const ALIASES: &[(&str, &str)] = &[
    ("ssl", "tls"),
    ("https", "tls"),
    ("ipv4", "ip"),
    ("ether", "eth"),
    ("bootp", "dhcp"),
    ("pop3", "pop"),
    ("len", "frame.len"),
    ("length", "frame.len"),
    ("no", "frame.number"),
    ("addr", "ip.addr"),
    ("ip.host", "host"),
    ("name", "host"),
    ("sni", "tls.sni"),
    ("tls.handshake.extensions_server_name", "tls.sni"),
    ("dns.name", "dns.qry.name"),
    ("syn", "tcp.flags.syn"),
    ("rst", "tcp.flags.rst"),
    ("fin", "tcp.flags.fin"),
    ("tcp.flags.reset", "tcp.flags.rst"),
    ("http.response.code", "http.status"),
    ("ipv6.addr", "ip.addr"),
    ("ipv6.src", "ip.src"),
    ("ipv6.dst", "ip.dst"),
    ("mac", "eth.addr"),
    ("me", "this_computer"),
    ("this-computer", "this_computer"),
];

pub fn field_def(name: &str) -> Option<&'static FieldDef> {
    let lower = name.to_ascii_lowercase();
    let canonical = ALIASES
        .iter()
        .find(|(a, _)| *a == lower)
        .map(|(_, c)| *c)
        .unwrap_or(lower.as_str());
    FIELDS.iter().find(|d| d.name == canonical)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    Contains,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Lit {
    Ip(IpAddr, u8),
    Num(f64),
    Text(String),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Expr {
    True,
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Has(&'static str),
    Cmp { field: &'static str, op: Op, lit: Lit },
    /// Recherche plein texte (mot seul ou chaîne entre guillemets).
    Text(String),
}

/// Valeur d'un champ renvoyée par une source (un paquet).
#[derive(Clone, Debug)]
pub enum Val<'a> {
    Ip(IpAddr),
    Num(f64),
    Text(std::borrow::Cow<'a, str>),
}

/// Ce qu'un paquet doit exposer pour être filtré.
pub trait Source {
    fn has(&self, field: &str) -> bool;
    fn values<'a>(&'a self, field: &str, out: &mut Vec<Val<'a>>);
    /// `needle` est déjà en minuscules.
    fn text(&self, needle: &str) -> bool;
}

#[derive(Clone, Debug, PartialEq)]
pub struct FilterError {
    pub pos: usize,
    pub fr: String,
    pub en: String,
}

impl FilterError {
    fn new(pos: usize, fr: impl Into<String>, en: impl Into<String>) -> Self {
        Self { pos, fr: fr.into(), en: en.into() }
    }

    pub fn message(&self, lang: Lang) -> &str {
        match lang {
            Lang::Fr => &self.fr,
            Lang::En => &self.en,
        }
    }
}

impl std::fmt::Display for FilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (position {})", self.en, self.pos)
    }
}

// ---------------------------------------------------------------------------
// Analyse lexicale
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Word(String),
    Str(String),
    Op(Op),
    And,
    Or,
    Not,
    LParen,
    RParen,
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || "._-:/*@[]".contains(c)
}

fn tokenize(input: &str) -> Result<Vec<(Tok, usize)>, FilterError> {
    let chars: Vec<(usize, char)> = input.char_indices().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let (pos, c) = chars[i];
        let next = chars.get(i + 1).map(|x| x.1);
        match c {
            c if c.is_whitespace() => i += 1,
            '(' => {
                out.push((Tok::LParen, pos));
                i += 1;
            }
            ')' => {
                out.push((Tok::RParen, pos));
                i += 1;
            }
            '&' => {
                out.push((Tok::And, pos));
                i += if next == Some('&') { 2 } else { 1 };
            }
            '|' => {
                out.push((Tok::Or, pos));
                i += if next == Some('|') { 2 } else { 1 };
            }
            '!' if next == Some('=') => {
                out.push((Tok::Op(Op::Ne), pos));
                i += 2;
            }
            '!' => {
                out.push((Tok::Not, pos));
                i += 1;
            }
            '=' => {
                out.push((Tok::Op(Op::Eq), pos));
                i += if next == Some('=') { 2 } else { 1 };
            }
            '>' | '<' => {
                let op = match (c, next == Some('=')) {
                    ('>', true) => Op::Ge,
                    ('>', false) => Op::Gt,
                    ('<', true) => Op::Le,
                    _ => Op::Lt,
                };
                out.push((Tok::Op(op), pos));
                i += if next == Some('=') { 2 } else { 1 };
            }
            '~' => {
                out.push((Tok::Op(Op::Contains), pos));
                i += 1;
            }
            '"' | '\'' => {
                let quote = c;
                let mut s = String::new();
                i += 1;
                let mut closed = false;
                while i < chars.len() {
                    let ch = chars[i].1;
                    if ch == '\\' && i + 1 < chars.len() {
                        s.push(chars[i + 1].1);
                        i += 2;
                        continue;
                    }
                    if ch == quote {
                        closed = true;
                        i += 1;
                        break;
                    }
                    s.push(ch);
                    i += 1;
                }
                if !closed {
                    return Err(FilterError::new(
                        pos,
                        "Guillemet non refermé",
                        "Unclosed quote",
                    ));
                }
                out.push((Tok::Str(s), pos));
            }
            c if is_word_char(c) => {
                let start = i;
                while i < chars.len() && is_word_char(chars[i].1) {
                    i += 1;
                }
                let word: String = chars[start..i].iter().map(|x| x.1).collect();
                let tok = match word.to_ascii_lowercase().as_str() {
                    "and" | "et" => Tok::And,
                    "or" | "ou" => Tok::Or,
                    "not" | "non" => Tok::Not,
                    "contains" | "contient" => Tok::Op(Op::Contains),
                    "eq" => Tok::Op(Op::Eq),
                    "ne" => Tok::Op(Op::Ne),
                    "gt" => Tok::Op(Op::Gt),
                    "ge" => Tok::Op(Op::Ge),
                    "lt" => Tok::Op(Op::Lt),
                    "le" => Tok::Op(Op::Le),
                    _ => Tok::Word(word),
                };
                out.push((tok, pos));
            }
            other => {
                return Err(FilterError::new(
                    pos,
                    format!("Caractère inattendu « {other} »"),
                    format!("Unexpected character '{other}'"),
                ))
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Analyse syntaxique
// ---------------------------------------------------------------------------

struct Parser {
    toks: Vec<(Tok, usize)>,
    i: usize,
    end: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.i).map(|t| &t.0)
    }

    fn pos(&self) -> usize {
        self.toks.get(self.i).map(|t| t.1).unwrap_or(self.end)
    }

    fn next(&mut self) -> Option<(Tok, usize)> {
        let t = self.toks.get(self.i).cloned();
        self.i += 1;
        t
    }

    fn or(&mut self) -> Result<Expr, FilterError> {
        let mut left = self.and()?;
        while self.peek() == Some(&Tok::Or) {
            self.i += 1;
            let right = self.and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Expr, FilterError> {
        let mut left = self.unary()?;
        loop {
            match self.peek() {
                Some(Tok::And) => {
                    self.i += 1;
                    let right = self.unary()?;
                    left = Expr::And(Box::new(left), Box::new(right));
                }
                // Deux termes juxtaposés = ET implicite (« google dns »).
                Some(Tok::Word(_)) | Some(Tok::Str(_)) | Some(Tok::Not) | Some(Tok::LParen) => {
                    let right = self.unary()?;
                    left = Expr::And(Box::new(left), Box::new(right));
                }
                _ => break,
            }
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Expr, FilterError> {
        match self.peek() {
            Some(Tok::Not) => {
                self.i += 1;
                Ok(Expr::Not(Box::new(self.unary()?)))
            }
            Some(Tok::LParen) => {
                let open = self.pos();
                self.i += 1;
                let e = self.or()?;
                match self.next() {
                    Some((Tok::RParen, _)) => Ok(e),
                    _ => Err(FilterError::new(
                        open,
                        "Parenthèse non refermée",
                        "Unclosed parenthesis",
                    )),
                }
            }
            _ => self.cmp(),
        }
    }

    fn cmp(&mut self) -> Result<Expr, FilterError> {
        let pos = self.pos();
        match self.next() {
            Some((Tok::Str(s), _)) => Ok(Expr::Text(s)),
            Some((Tok::Word(w), _)) => {
                let def = field_def(&w);
                let op = match self.peek() {
                    Some(Tok::Op(op)) => Some(*op),
                    _ => None,
                };
                match (def, op) {
                    (Some(def), None) => Ok(Expr::Has(def.name)),
                    (None, None) => Ok(Expr::Text(w)),
                    (None, Some(_)) => Err(FilterError::new(
                        pos,
                        format!("Champ inconnu « {w} »"),
                        format!("Unknown field '{w}'"),
                    )),
                    (Some(def), Some(op)) => {
                        self.i += 1;
                        let vpos = self.pos();
                        let raw = match self.next() {
                            Some((Tok::Word(v), _)) | Some((Tok::Str(v), _)) => v,
                            _ => {
                                return Err(FilterError::new(
                                    vpos,
                                    format!("Valeur attendue après « {w} »"),
                                    format!("Value expected after '{w}'"),
                                ))
                            }
                        };
                        let lit = literal(def, &raw, vpos)?;
                        Ok(Expr::Cmp { field: def.name, op, lit })
                    }
                }
            }
            Some((Tok::Op(_), p)) => Err(FilterError::new(
                p,
                "Opérateur sans champ (ex. ip.addr == 1.2.3.4)",
                "Operator without a field (e.g. ip.addr == 1.2.3.4)",
            )),
            Some((Tok::RParen, p)) => Err(FilterError::new(
                p,
                "Parenthèse fermante en trop",
                "Unexpected closing parenthesis",
            )),
            Some((_, p)) => Err(FilterError::new(p, "Expression incomplète", "Incomplete expression")),
            None => Err(FilterError::new(
                pos,
                "Expression incomplète",
                "Incomplete expression",
            )),
        }
    }
}

fn literal(def: &FieldDef, raw: &str, pos: usize) -> Result<Lit, FilterError> {
    match def.kind {
        Kind::Flag => Err(FilterError::new(
            pos,
            format!("« {} » ne se compare pas, utilisez-le seul", def.name),
            format!("'{}' cannot be compared, use it alone", def.name),
        )),
        Kind::Ip => {
            let (addr, prefix) = match raw.split_once('/') {
                Some((a, p)) => (a, Some(p)),
                None => (raw, None),
            };
            match addr.parse::<IpAddr>() {
                Ok(ip) => {
                    let max = if ip.is_ipv4() { 32 } else { 128 };
                    let prefix = match prefix {
                        Some(p) => p.parse::<u8>().ok().filter(|p| *p <= max).ok_or_else(|| {
                            FilterError::new(pos, "Préfixe CIDR invalide", "Invalid CIDR prefix")
                        })?,
                        None => max,
                    };
                    Ok(Lit::Ip(ip, prefix))
                }
                // Permet « ip.addr == google.com » : on compare alors aux noms.
                Err(_) => Ok(Lit::Text(raw.to_string())),
            }
        }
        Kind::Num => {
            let parsed = if let Some(hex) = raw.strip_prefix("0x") {
                i64::from_str_radix(hex, 16).ok().map(|v| v as f64)
            } else {
                raw.parse::<f64>().ok()
            };
            parsed.map(Lit::Num).ok_or_else(|| {
                FilterError::new(
                    pos,
                    format!("Nombre attendu pour « {} »", def.name),
                    format!("Number expected for '{}'", def.name),
                )
            })
        }
        Kind::Text => Ok(Lit::Text(raw.to_string())),
    }
}

/// Analyse un filtre. Une chaîne vide renvoie `Expr::True`.
pub fn parse(input: &str) -> Result<Expr, FilterError> {
    let toks = tokenize(input)?;
    if toks.is_empty() {
        return Ok(Expr::True);
    }
    let mut p = Parser { toks, i: 0, end: input.len() };
    let e = p.or()?;
    if p.i < p.toks.len() {
        return Err(FilterError::new(
            p.pos(),
            "Élément inattendu (manque-t-il && ou || ?)",
            "Unexpected token (missing && or ||?)",
        ));
    }
    Ok(e)
}

// ---------------------------------------------------------------------------
// Évaluation
// ---------------------------------------------------------------------------

fn in_prefix(a: IpAddr, net: IpAddr, prefix: u8) -> bool {
    match (a, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            if prefix == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - prefix as u32);
            (u32::from(a) & mask) == (u32::from(n) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            if prefix == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - prefix as u32);
            (u128::from(a) & mask) == (u128::from(n) & mask)
        }
        _ => false,
    }
}

fn glob_eq(text: &str, pattern: &str) -> bool {
    let t = text.to_lowercase();
    let p = pattern.to_lowercase();
    if !p.contains('*') {
        return t == p;
    }
    let parts: Vec<&str> = p.split('*').collect();
    let mut rest = t.as_str();
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            if !rest.starts_with(part) {
                return false;
            }
            rest = &rest[part.len()..];
        } else if i == parts.len() - 1 {
            return rest.ends_with(part);
        } else {
            match rest.find(part) {
                Some(idx) => rest = &rest[idx + part.len()..],
                None => return false,
            }
        }
    }
    true
}

fn cmp_val(v: &Val<'_>, op: Op, lit: &Lit) -> bool {
    match (v, lit) {
        (Val::Ip(a), Lit::Ip(n, p)) => match op {
            Op::Eq | Op::Ne => in_prefix(*a, *n, *p),
            Op::Contains => a.to_string().contains(&n.to_string()),
            _ => false,
        },
        (Val::Ip(a), Lit::Text(t)) => {
            let s = a.to_string();
            match op {
                Op::Contains => s.contains(t.as_str()),
                _ => glob_eq(&s, t),
            }
        }
        (Val::Num(a), Lit::Num(b)) => match op {
            Op::Eq | Op::Ne => (a - b).abs() < f64::EPSILON,
            Op::Gt => a > b,
            Op::Ge => a >= b,
            Op::Lt => a < b,
            Op::Le => a <= b,
            Op::Contains => a.to_string().contains(&b.to_string()),
        },
        (Val::Text(a), Lit::Text(b)) => match op {
            Op::Eq | Op::Ne => glob_eq(a, b),
            Op::Contains => a.to_lowercase().contains(&b.to_lowercase()),
            Op::Gt => a.as_ref() > b.as_str(),
            Op::Ge => a.as_ref() >= b.as_str(),
            Op::Lt => a.as_ref() < b.as_str(),
            Op::Le => a.as_ref() <= b.as_str(),
        },
        (Val::Text(a), Lit::Num(b)) => a.parse::<f64>().map(|x| (x - b).abs() < f64::EPSILON).unwrap_or(false),
        _ => false,
    }
}

impl Expr {
    pub fn eval(&self, s: &dyn Source) -> bool {
        match self {
            Expr::True => true,
            Expr::And(a, b) => a.eval(s) && b.eval(s),
            Expr::Or(a, b) => a.eval(s) || b.eval(s),
            Expr::Not(a) => !a.eval(s),
            Expr::Has(f) => s.has(f),
            Expr::Text(t) => s.text(&t.to_lowercase()),
            Expr::Cmp { field, op, lit } => {
                let mut vals = Vec::new();
                s.values(field, &mut vals);
                let any = vals.iter().any(|v| cmp_val(v, *op, lit));
                // « != » signifie « aucune valeur égale » (plus intuitif).
                if *op == Op::Ne {
                    !any
                } else {
                    any
                }
            }
        }
    }

    pub fn is_true(&self) -> bool {
        matches!(self, Expr::True)
    }

    /// Vrai si le filtre utilise au moins un champ (pas seulement du texte libre).
    pub fn uses_fields(&self) -> bool {
        match self {
            Expr::True | Expr::Text(_) => false,
            Expr::Has(_) | Expr::Cmp { .. } => true,
            Expr::Not(a) => a.uses_fields(),
            Expr::And(a, b) | Expr::Or(a, b) => a.uses_fields() || b.uses_fields(),
        }
    }
}

/// Champs dont le nom commence par `prefix`, pour l'autocomplétion.
pub fn suggestions(prefix: &str, max: usize) -> Vec<&'static FieldDef> {
    let p = prefix.to_ascii_lowercase();
    if p.is_empty() {
        return Vec::new();
    }
    FIELDS.iter().filter(|d| d.name.starts_with(&p) && d.name != p).take(max).collect()
}

/// Aide-mémoire utilisé dans les invites IA et l'aide intégrée.
pub const SYNTAX_HELP: &str = "RustShark display filter syntax: protocol names alone (dns, tcp, udp, tls, http, quic, arp, icmp, dhcp, mdns, ssdp, ntp, ssh, smb, rdp...), \
properties (tcp.flags.syn, tcp.flags.rst, dns.response, http.request, tls.client_hello, broadcast, multicast, local, internet, this_computer, problem, cleartext), \
comparisons field OP value with OP in == != > >= < <= contains (fields: ip.addr ip.src ip.dst [IP or CIDR], port src.port dst.port tcp.port udp.port frame.len ip.ttl http.status dns.rcode icmp.type [numbers], \
host dns.qry.name tls.sni http.host http.method http.uri http.user_agent eth.addr protocol category info [text, * wildcard allowed, e.g. host == *.google.com]), \
combine with && || ! and parentheses. A bare word is a full-text search.";

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    struct P;
    impl Source for P {
        fn has(&self, f: &str) -> bool {
            matches!(f, "tcp" | "tls" | "ip")
        }
        fn values<'a>(&'a self, f: &str, out: &mut Vec<Val<'a>>) {
            match f {
                "ip.addr" => {
                    out.push(Val::Ip("192.168.1.10".parse().unwrap()));
                    out.push(Val::Ip("142.250.1.1".parse().unwrap()));
                }
                "port" => {
                    out.push(Val::Num(443.0));
                    out.push(Val::Num(51000.0));
                }
                "host" => out.push(Val::Text(Cow::Borrowed("www.google.com"))),
                _ => {}
            }
        }
        fn text(&self, n: &str) -> bool {
            "client hello www.google.com".contains(n)
        }
    }

    fn ok(f: &str) -> bool {
        parse(f).unwrap().eval(&P)
    }

    #[test]
    fn basics() {
        assert!(ok(""));
        assert!(ok("tcp"));
        assert!(!ok("udp"));
        assert!(ok("tcp && tls"));
        assert!(ok("udp || tls"));
        assert!(ok("!udp"));
        assert!(ok("ip.addr == 192.168.1.0/24"));
        assert!(!ok("ip.addr == 10.0.0.0/8"));
        assert!(ok("port == 443"));
        assert!(ok("port > 1000"));
        assert!(ok("host == *.google.com"));
        assert!(ok("host contains GOOGLE"));
        assert!(ok("google"));
        assert!(ok("\"client hello\""));
        assert!(ok("not (udp or arp) and tcp"));
        assert!(!ok("port != 443"));
    }

    #[test]
    fn errors() {
        assert!(parse("ip.addr ==").is_err());
        assert!(parse("tcp &&").is_err());
        assert!(parse("(tcp").is_err());
        assert!(parse("foo == 3").is_err());
        assert!(parse("port == abc").is_err());
        assert!(parse("tcp == 3").is_err());
    }

    #[test]
    fn glob() {
        assert!(glob_eq("www.youtube.com", "*.youtube.com"));
        assert!(glob_eq("a.b.c", "a*c"));
        assert!(!glob_eq("youtube.com.evil", "*.youtube.com"));
    }
}
