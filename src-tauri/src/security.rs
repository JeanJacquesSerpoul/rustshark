//! Bilan de sécurité du réseau : Wi-Fi, box, DNS, appareils et capture.

use std::net::IpAddr;

use rustshark_shared::{Alert, AlertLevel, CheckLevel, DeviceKind, DeviceList, IfaceKind, Lang, NetworkInfo, PortInfo, SecurityCheck, SecurityReport, WifiSecurity};

use crate::dissect::is_private;
use crate::netinfo::Neighbor;

/// Résolveurs DNS publics connus.
fn known_dns(ip: &str) -> Option<&'static str> {
    Some(match ip {
        "1.1.1.1" | "1.0.0.1" | "1.1.1.2" | "1.0.0.2" | "1.1.1.3" | "1.0.0.3" | "2606:4700:4700::1111" | "2606:4700:4700::1001" => "Cloudflare",
        "8.8.8.8" | "8.8.4.4" | "2001:4860:4860::8888" | "2001:4860:4860::8844" => "Google",
        "9.9.9.9" | "149.112.112.112" | "2620:fe::fe" | "2620:fe::9" => "Quad9",
        "208.67.222.222" | "208.67.220.220" => "OpenDNS (Cisco)",
        "94.140.14.14" | "94.140.15.15" => "AdGuard DNS",
        "80.67.169.12" | "80.67.169.40" => "FDN",
        "194.242.2.2" => "Mullvad",
        "185.228.168.9" | "185.228.169.9" => "CleanBrowsing",
        "76.76.2.0" | "76.76.10.0" => "Control D",
        "86.54.11.1" | "86.54.11.100" => "DNS4EU",
        _ => return None,
    })
}

macro_rules! l {
    ($lang:expr, $fr:literal, $en:literal $(, $arg:expr)* $(,)?) => {
        match $lang {
            Lang::Fr => format!($fr $(, $arg)*),
            Lang::En => format!($en $(, $arg)*),
        }
    };
}

fn v6_halves(ip: &IpAddr) -> Option<(u64, u64)> {
    match ip {
        IpAddr::V6(a) => {
            let v = u128::from(*a);
            Some(((v >> 64) as u64, v as u64))
        }
        IpAddr::V4(_) => None,
    }
}

/// Adresse IPv6 publique du même réseau /64 que cet ordinateur.
fn same_v6_lan(info: &NetworkInfo, ip: &IpAddr) -> bool {
    let Some((net, _)) = v6_halves(ip) else { return false };
    info.ipv6.iter().filter_map(|a| a.parse::<IpAddr>().ok()).any(|a| v6_halves(&a).is_some_and(|(n, _)| n == net))
}

/// La box, y compris par l'une de ses adresses IPv6 (même identifiant d'interface).
fn is_gateway(info: &NetworkInfo, ip: &IpAddr) -> bool {
    let parse = |s: &Option<String>| s.as_deref().and_then(|g| g.parse::<IpAddr>().ok());
    if parse(&info.gateway) == Some(*ip) || parse(&info.gateway_v6) == Some(*ip) {
        return true;
    }
    match (v6_halves(ip), parse(&info.gateway_v6).as_ref().and_then(v6_halves)) {
        (Some((_, iid)), Some((_, gw_iid))) => iid == gw_iid && same_v6_lan(info, ip),
        _ => false,
    }
}

pub struct Inputs<'a> {
    pub info: &'a NetworkInfo,
    pub devices: &'a DeviceList,
    pub neighbors: &'a [Neighbor],
    /// Ports de la box (None = pas encore analysée).
    pub gateway_ports: Option<&'a [PortInfo]>,
    pub igd: Option<bool>,
    pub capture_alerts: Vec<Alert>,
}

fn check(level: CheckLevel, title: String, detail: String, advice: Option<String>) -> SecurityCheck {
    SecurityCheck { level, title, detail, advice, filter: None }
}

pub fn report(i: Inputs, lang: Lang) -> SecurityReport {
    let mut out = Vec::new();
    let info = i.info;

    // Wi-Fi ou câble.
    match (&info.wifi, info.kind) {
        (Some(w), _) => {
            let name = w.ssid.clone().unwrap_or_else(|| lang.pick("votre Wi-Fi", "your Wi-Fi").into());
            let auth = w.auth.clone().unwrap_or_default();
            out.push(match w.security {
                WifiSecurity::Open => check(CheckLevel::Danger, l!(lang, "Wi-Fi « {} » sans mot de passe", "Wi-Fi '{}' without a password", name),
                    lang.pick("Tout ce qui n'est pas chiffré par ailleurs (sites HTTP, objets connectés…) peut être lu par n'importe qui à portée.", "Anything not encrypted otherwise (HTTP sites, IoT devices…) can be read by anyone in range.").into(),
                    Some(lang.pick("Activez WPA2 ou WPA3 dans la box, ou utilisez un VPN sur ce réseau.", "Enable WPA2 or WPA3 on the router, or use a VPN on this network.").into())),
                WifiSecurity::Wep => check(CheckLevel::Danger, l!(lang, "Wi-Fi « {} » protégé par WEP", "Wi-Fi '{}' protected by WEP", name),
                    lang.pick("Le WEP se casse en quelques minutes : c'est presque comme un réseau ouvert.", "WEP can be cracked in minutes: it is almost like an open network.").into(),
                    Some(lang.pick("Passez en WPA2-Personnel (AES) ou WPA3 dans les réglages Wi-Fi de la box.", "Switch to WPA2-Personal (AES) or WPA3 in the router's Wi-Fi settings.").into())),
                WifiSecurity::Wpa => check(CheckLevel::Warning, l!(lang, "Wi-Fi « {} » en WPA (ancien)", "Wi-Fi '{}' uses WPA (old)", name),
                    lang.pick("Le WPA d'origine (TKIP) n'est plus considéré comme sûr.", "Original WPA (TKIP) is no longer considered safe.").into(),
                    Some(lang.pick("Choisissez WPA2 (AES) ou WPA3 dans la box.", "Choose WPA2 (AES) or WPA3 on the router.").into())),
                WifiSecurity::Wpa2 => check(CheckLevel::Ok, l!(lang, "Wi-Fi « {} » chiffré ({})", "Wi-Fi '{}' encrypted ({})", name, auth),
                    lang.pick("Bon niveau de protection. Utilisez un mot de passe long (12 caractères ou plus).", "Good protection. Use a long password (12+ characters).").into(),
                    Some(lang.pick("Si tous vos appareils le permettent, WPA3 est encore plus robuste.", "If all your devices support it, WPA3 is even stronger.").into())),
                WifiSecurity::Wpa3 => check(CheckLevel::Ok, l!(lang, "Wi-Fi « {} » en WPA3", "Wi-Fi '{}' uses WPA3", name),
                    lang.pick("Le meilleur chiffrement Wi-Fi actuel.", "The best Wi-Fi encryption available today.").into(), None),
                WifiSecurity::Enterprise => check(CheckLevel::Ok, l!(lang, "Wi-Fi « {} » d'entreprise ({})", "Enterprise Wi-Fi '{}' ({})", name, auth),
                    lang.pick("Chaque utilisateur s'authentifie avec ses propres identifiants.", "Each user authenticates with their own credentials.").into(), None),
                WifiSecurity::Unknown => check(CheckLevel::Info, lang.pick("Sécurité du Wi-Fi inconnue", "Wi-Fi security unknown").into(),
                    w.note.clone().unwrap_or_else(|| lang.pick("Le système n'a pas indiqué le type de chiffrement.", "The system did not report the encryption type.").into()), None),
            });
        }
        (None, IfaceKind::Ethernet) => out.push(check(CheckLevel::Ok, lang.pick("Connexion par câble", "Wired connection").into(),
            lang.pick("Un câble ne peut pas être écouté à distance comme un Wi-Fi.", "A cable cannot be eavesdropped from a distance like Wi-Fi.").into(), None)),
        _ => {}
    }

    // La box.
    let gw = info.gateway.clone();
    match &gw {
        None => out.push(check(CheckLevel::Warning, lang.pick("Aucune box (passerelle) détectée", "No router (gateway) detected").into(),
            lang.pick("Cette connexion n'a pas de route vers Internet.", "This connection has no route to the Internet.").into(), None)),
        Some(g) => {
            match i.gateway_ports {
                None => out.push(check(CheckLevel::Info, lang.pick("Box pas encore inspectée", "Router not inspected yet").into(),
                    l!(lang, "Lancez « Inspecter la box » pour vérifier les services ouverts sur {} (Telnet, FTP, UPnP…).", "Run 'Inspect router' to check the services open on {} (Telnet, FTP, UPnP…).", g), None)),
                Some(ports) => {
                    let risky: Vec<&PortInfo> = ports.iter().filter(|p| p.level >= CheckLevel::Warning || matches!(p.port, 445 | 139)).collect();
                    if risky.is_empty() {
                        let list: Vec<String> = ports.iter().map(|p| format!("{} ({})", p.port, p.service)).collect();
                        out.push(check(CheckLevel::Ok, lang.pick("Aucun service risqué ouvert sur la box", "No risky service open on the router").into(),
                            if list.is_empty() { lang.pick("Aucun des ports courants ne répond depuis le réseau local.", "None of the common ports answer from the local network.").into() }
                            else { l!(lang, "Ports ouverts : {}.", "Open ports: {}.", list.join(", ")) }, None));
                    }
                    for p in risky {
                        let level = if matches!(p.port, 445 | 139) { CheckLevel::Warning } else { p.level };
                        out.push(check(level, l!(lang, "{} ouvert sur la box (port {})", "{} open on the router (port {})", p.service, p.port),
                            p.note.clone().unwrap_or_default(),
                            Some(lang.pick("Désactivez ce service dans l'interface d'administration de la box s'il ne vous sert pas.", "Disable this service in the router's admin interface if you don't use it.").into())));
                    }
                    if ports.iter().any(|p| p.port == 80) && !ports.iter().any(|p| p.port == 443) {
                        out.push(check(CheckLevel::Info, lang.pick("Administration de la box sans HTTPS", "Router admin without HTTPS").into(),
                            lang.pick("Le mot de passe de la box circule en clair sur votre réseau quand vous vous connectez à son interface.", "The router password travels in clear text on your network when you log into its interface.").into(),
                            Some(lang.pick("Changez le mot de passe d'origine de la box et ne vous y connectez que depuis un appareil de confiance.", "Change the router's default password and only log in from a trusted device.").into())));
                    }
                }
            }
            if i.igd == Some(true) {
                out.push(check(CheckLevel::Warning, lang.pick("UPnP activé sur la box", "UPnP enabled on the router").into(),
                    lang.pick("N'importe quel programme du réseau (y compris un logiciel malveillant) peut ouvrir des ports de la box vers Internet sans vous demander.", "Any program on the network (including malware) can open router ports to the Internet without asking you.").into(),
                    Some(lang.pick("Désactivez l'UPnP dans la box si vous n'en avez pas besoin (il sert surtout aux consoles de jeux et à certains logiciels).", "Disable UPnP on the router if you don't need it (mostly used by game consoles and some software).").into())));
            } else if i.igd == Some(false) && i.gateway_ports.is_some() {
                out.push(check(CheckLevel::Ok, lang.pick("UPnP de la box inactif", "Router UPnP inactive").into(),
                    lang.pick("La box ne permet pas aux appareils d'ouvrir des ports automatiquement.", "The router doesn't let devices open ports automatically.").into(), None));
            }
            // Usurpation : une autre adresse utilise la carte réseau de la box.
            if let (Some(gip), Some(gmac)) = (g.parse::<IpAddr>().ok(), &info.gateway_mac) {
                let others: Vec<String> = i
                    .neighbors
                    .iter()
                    .filter(|n| n.ip.is_ipv4() && n.ip != gip && crate::dissect::fmt_mac(&n.mac) == *gmac)
                    .map(|n| n.ip.to_string())
                    .collect();
                if !others.is_empty() {
                    out.push(check(CheckLevel::Warning, lang.pick("Adresse MAC de la box partagée", "Router MAC address shared").into(),
                        l!(lang, "{} utilise(nt) la même carte réseau que la box ({}). Cela arrive avec certains répéteurs, mais c'est aussi la signature d'une attaque « ARP spoofing » qui intercepte le trafic.",
                            "{} use(s) the same network card as the router ({}). Some repeaters do this, but it is also the signature of an 'ARP spoofing' attack intercepting traffic.", others.join(", "), gmac),
                        Some(lang.pick("Identifiez l'appareil concerné dans la liste ; s'il vous est inconnu, déconnectez-le et changez le mot de passe Wi-Fi.", "Identify the device in the list; if you don't know it, disconnect it and change the Wi-Fi password.").into())));
                }
            }
        }
    }

    // Serveurs DNS.
    if !info.dns.is_empty() {
        let mut unknown = Vec::new();
        let mut named = Vec::new();
        for d in &info.dns {
            let ip: Option<IpAddr> = d.parse().ok();
            if ip.is_some_and(|ip| is_gateway(info, &ip)) {
                named.push(l!(lang, "{} (la box)", "{} (the router)", d));
            } else if ip.is_some_and(|ip| is_private(&ip) || same_v6_lan(info, &ip)) {
                named.push(l!(lang, "{} (réseau local)", "{} (local network)", d));
            } else if let Some(n) = known_dns(d) {
                named.push(format!("{d} ({n})"));
            } else {
                unknown.push(d.clone());
            }
        }
        if unknown.is_empty() {
            out.push(check(CheckLevel::Ok, lang.pick("Annuaire DNS de confiance", "Trusted DNS directory").into(),
                l!(lang, "Serveurs utilisés : {}.", "Servers in use: {}.", named.join(", ")), None));
        } else {
            out.push(check(CheckLevel::Info, lang.pick("Serveur DNS à vérifier", "DNS server to check").into(),
                l!(lang, "Serveur(s) {} : sans doute celui de votre opérateur. Un logiciel malveillant peut aussi remplacer le DNS pour vous rediriger vers de faux sites.",
                    "Server(s) {}: probably your ISP's. Malware can also replace the DNS to redirect you to fake sites.", unknown.join(", ")),
                Some(lang.pick("Si vous ne reconnaissez pas ce serveur, remettez le DNS en automatique dans les réglages réseau.", "If you don't recognise this server, set DNS back to automatic in the network settings.").into())));
        }
    }

    // Appareils.
    let devs = &i.devices.devices;
    let unknown: Vec<&str> = devs.iter().filter(|d| !d.is_self && !d.is_gateway && d.name.is_none() && d.vendor.is_none() && d.kind == DeviceKind::Unknown).map(|d| d.ip.as_str()).collect();
    if !unknown.is_empty() {
        out.push(check(CheckLevel::Info, l!(lang, "{} appareil(s) non identifié(s)", "{} unidentified device(s)", unknown.len()),
            l!(lang, "Adresses : {}. Souvent des téléphones avec une adresse MAC privée ou des objets connectés discrets.", "Addresses: {}. Often phones with a private MAC address or quiet IoT devices.", unknown.iter().take(8).cloned().collect::<Vec<_>>().join(", ")),
            Some(lang.pick("Vérifiez que vous les reconnaissez ; la liste des appareils connectés de la box indique souvent leur nom.", "Make sure you recognise them; the router's connected devices list often shows their name.").into())));
    }
    for d in devs.iter().filter(|d| !d.is_gateway) {
        let Some(ports) = &d.open_ports else { continue };
        for p in ports.iter().filter(|p| p.level >= CheckLevel::Warning) {
            let who = d.name.clone().or_else(|| d.vendor.clone()).unwrap_or_else(|| d.ip.clone());
            out.push(SecurityCheck {
                level: p.level,
                title: l!(lang, "{} ouvert sur {} ({})", "{} open on {} ({})", p.service, who, d.ip),
                detail: p.note.clone().unwrap_or_default(),
                advice: Some(lang.pick("Désactivez ce service sur l'appareil ou protégez-le par un mot de passe solide.", "Disable this service on the device or protect it with a strong password.").into()),
                filter: Some(format!("ip.addr == {} && tcp.port == {}", d.ip, p.port)),
            });
        }
    }

    // Ce que la capture a révélé.
    for a in i.capture_alerts {
        out.push(SecurityCheck {
            level: match a.level {
                AlertLevel::Danger => CheckLevel::Danger,
                AlertLevel::Warning => CheckLevel::Warning,
                AlertLevel::Info => CheckLevel::Info,
            },
            title: format!("{} · {}", lang.pick("Capture", "Capture"), a.title),
            detail: a.detail,
            advice: None,
            filter: a.filter,
        });
    }

    out.sort_by(|a, b| b.level.cmp(&a.level));
    let penalty: u32 = out.iter().map(|c| match c.level {
        CheckLevel::Danger => 30,
        CheckLevel::Warning => 12,
        CheckLevel::Info => 2,
        CheckLevel::Ok => 0,
    }).sum();
    SecurityReport { score: 100u32.saturating_sub(penalty).max(5) as u8, checks: out, deep: i.gateway_ports.is_some() }
}
