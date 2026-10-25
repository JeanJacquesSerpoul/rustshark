//! Fabricant d'une carte réseau d'après le préfixe de son adresse MAC.

use std::collections::HashMap;
use std::sync::OnceLock;

/// Registre MA-L de l'IEEE, réduit à « préfixe → nom court » (`data/oui.tsv`).
static TABLE: &str = include_str!("../data/oui.tsv");

fn table() -> &'static HashMap<u32, &'static str> {
    static MAP: OnceLock<HashMap<u32, &'static str>> = OnceLock::new();
    MAP.get_or_init(|| {
        TABLE
            .lines()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| {
                let (k, v) = l.split_once('\t')?;
                Some((u32::from_str_radix(k, 16).ok()?, v))
            })
            .collect()
    })
}

/// Adresse « administrée localement » : MAC aléatoire choisie par l'appareil
/// (adresse privée des iPhone, Android, Windows…), sans fabricant réel.
pub fn is_random(mac: &[u8; 6]) -> bool {
    mac[0] & 0x02 != 0 && mac[0] & 0x01 == 0
}

pub fn vendor(mac: &[u8; 6]) -> Option<&'static str> {
    if is_random(mac) || mac == &[0; 6] || mac == &[0xff; 6] {
        return None;
    }
    let key = (mac[0] as u32) << 16 | (mac[1] as u32) << 8 | mac[2] as u32;
    table().get(&key).copied().filter(|v| !v.starts_with("IEEE Registration"))
}

pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vendors() {
        assert_eq!(vendor(&[0x00, 0x1b, 0x63, 1, 2, 3]), Some("Apple"));
        assert_eq!(vendor(&[0xb8, 0x27, 0xeb, 1, 2, 3]), Some("Raspberry Pi"));
        assert!(vendor(&[0x02, 0x11, 0x22, 1, 2, 3]).is_none());
        assert!(is_random(&[0xda, 0xa1, 0x19, 0, 0, 1]));
        assert!(!is_random(&[0x00, 0x1b, 0x63, 0, 0, 1]));
        assert_eq!(parse_mac("a4-3e-51-00-0A-ff"), Some([0xa4, 0x3e, 0x51, 0, 0x0a, 0xff]));
    }
}
