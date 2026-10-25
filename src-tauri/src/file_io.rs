//! Lecture et écriture des fichiers pcap / pcapng (implémentation autonome).

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use crate::store::{Packet, RawPacket};

fn u16_at(b: &[u8], o: usize, le: bool) -> u16 {
    let a = [b[o], b[o + 1]];
    if le { u16::from_le_bytes(a) } else { u16::from_be_bytes(a) }
}

fn u32_at(b: &[u8], o: usize, le: bool) -> u32 {
    let a = [b[o], b[o + 1], b[o + 2], b[o + 3]];
    if le { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) }
}

pub fn read(path: &Path) -> Result<Vec<RawPacket>, String> {
    let mut buf = Vec::new();
    BufReader::new(File::open(path).map_err(|e| e.to_string())?)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    if buf.len() < 24 {
        return Err("fichier trop court / file too short".into());
    }
    match &buf[0..4] {
        [0x0a, 0x0d, 0x0d, 0x0a] => read_pcapng(&buf),
        _ => read_pcap(&buf),
    }
}

fn read_pcap(b: &[u8]) -> Result<Vec<RawPacket>, String> {
    let magic = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let (le, nanos) = match magic {
        0xa1b2c3d4 => (true, false),
        0xd4c3b2a1 => (false, false),
        0xa1b23c4d => (true, true),
        0x4d3cb2a1 => (false, true),
        _ => return Err("format inconnu (ni pcap ni pcapng) / unknown format".into()),
    };
    let linktype = u32_at(b, 20, le) as u16;
    let mut out = Vec::new();
    let mut o = 24;
    while o + 16 <= b.len() {
        let sec = u32_at(b, o, le) as i64;
        let frac = u32_at(b, o + 4, le) as i64;
        let incl = u32_at(b, o + 8, le) as usize;
        let orig = u32_at(b, o + 12, le);
        o += 16;
        if o + incl > b.len() {
            break;
        }
        let ts_us = sec * 1_000_000 + if nanos { frac / 1000 } else { frac };
        out.push(RawPacket { ts_us, orig_len: orig, linktype, data: b[o..o + incl].to_vec() });
        o += incl;
    }
    Ok(out)
}

fn read_pcapng(b: &[u8]) -> Result<Vec<RawPacket>, String> {
    struct Iface {
        linktype: u16,
        /// Nombre d'unités de temps par seconde.
        units: f64,
    }
    let mut ifaces: Vec<Iface> = Vec::new();
    let mut le = true;
    let mut out = Vec::new();
    let mut o = 0;
    while o + 12 <= b.len() {
        let raw_type = u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        if raw_type == 0x0a0d0d0a {
            le = u32::from_le_bytes([b[o + 8], b[o + 9], b[o + 10], b[o + 11]]) == 0x1a2b3c4d;
            ifaces.clear();
        }
        let btype = u32_at(b, o, le);
        let blen = u32_at(b, o + 4, le) as usize;
        if blen < 12 || o + blen > b.len() {
            break;
        }
        let body = &b[o + 8..o + blen - 4];
        match btype {
            1 if body.len() >= 8 => {
                let linktype = u16_at(body, 0, le);
                let mut units = 1e6;
                let mut q = 8;
                while q + 4 <= body.len() {
                    let code = u16_at(body, q, le);
                    let len = u16_at(body, q + 2, le) as usize;
                    if code == 0 {
                        break;
                    }
                    if code == 9 && len >= 1 && q + 4 < body.len() {
                        let v = body[q + 4];
                        units = if v & 0x80 != 0 { 2f64.powi((v & 0x7f) as i32) } else { 10f64.powi(v as i32) };
                    }
                    q += 4 + len.div_ceil(4) * 4;
                }
                ifaces.push(Iface { linktype, units });
            }
            6 if body.len() >= 20 => {
                let id = u32_at(body, 0, le) as usize;
                let ts = ((u32_at(body, 4, le) as u64) << 32) | u32_at(body, 8, le) as u64;
                let cap = u32_at(body, 12, le) as usize;
                let orig = u32_at(body, 16, le);
                if let (Some(ifc), Some(data)) = (ifaces.get(id), body.get(20..20 + cap)) {
                    let ts_us = (ts as f64 / ifc.units * 1e6) as i64;
                    out.push(RawPacket { ts_us, orig_len: orig, linktype: ifc.linktype, data: data.to_vec() });
                }
            }
            3 if body.len() >= 4 => {
                let orig = u32_at(body, 0, le);
                if let Some(ifc) = ifaces.first() {
                    let cap = (orig as usize).min(body.len() - 4);
                    out.push(RawPacket { ts_us: 0, orig_len: orig, linktype: ifc.linktype, data: body[4..4 + cap].to_vec() });
                }
            }
            _ => {}
        }
        o += blen;
    }
    if out.is_empty() && ifaces.is_empty() {
        return Err("fichier pcapng vide ou invalide / empty or invalid pcapng".into());
    }
    Ok(out)
}

pub fn write<'a>(path: &Path, packets: impl Iterator<Item = &'a Packet> + Clone) -> Result<usize, String> {
    let ng = path.extension().map(|e| e.eq_ignore_ascii_case("pcapng")).unwrap_or(false);
    let mut linktypes: Vec<u16> = Vec::new();
    for p in packets.clone() {
        if !linktypes.contains(&p.linktype) {
            linktypes.push(p.linktype);
        }
    }
    if !ng && linktypes.len() > 1 {
        return Err("Plusieurs types de liaison : enregistrez en .pcapng / Multiple link types: save as .pcapng".into());
    }
    let mut w = BufWriter::new(File::create(path).map_err(|e| e.to_string())?);
    let io = |e: std::io::Error| e.to_string();
    let mut n = 0;
    if ng {
        // Section Header Block
        w.write_all(&0x0a0d0d0au32.to_le_bytes()).map_err(io)?;
        w.write_all(&28u32.to_le_bytes()).map_err(io)?;
        w.write_all(&0x1a2b3c4du32.to_le_bytes()).map_err(io)?;
        w.write_all(&1u16.to_le_bytes()).map_err(io)?;
        w.write_all(&0u16.to_le_bytes()).map_err(io)?;
        w.write_all(&(-1i64).to_le_bytes()).map_err(io)?;
        w.write_all(&28u32.to_le_bytes()).map_err(io)?;
        for lt in &linktypes {
            w.write_all(&1u32.to_le_bytes()).map_err(io)?;
            w.write_all(&20u32.to_le_bytes()).map_err(io)?;
            w.write_all(&lt.to_le_bytes()).map_err(io)?;
            w.write_all(&0u16.to_le_bytes()).map_err(io)?;
            w.write_all(&262_144u32.to_le_bytes()).map_err(io)?;
            w.write_all(&20u32.to_le_bytes()).map_err(io)?;
        }
        for p in packets {
            let id = linktypes.iter().position(|l| *l == p.linktype).unwrap_or(0) as u32;
            let pad = (4 - p.data.len() % 4) % 4;
            let blen = (32 + p.data.len() + pad) as u32;
            let ts = p.ts_us as u64;
            w.write_all(&6u32.to_le_bytes()).map_err(io)?;
            w.write_all(&blen.to_le_bytes()).map_err(io)?;
            w.write_all(&id.to_le_bytes()).map_err(io)?;
            w.write_all(&((ts >> 32) as u32).to_le_bytes()).map_err(io)?;
            w.write_all(&(ts as u32).to_le_bytes()).map_err(io)?;
            w.write_all(&(p.data.len() as u32).to_le_bytes()).map_err(io)?;
            w.write_all(&p.orig_len.to_le_bytes()).map_err(io)?;
            w.write_all(&p.data).map_err(io)?;
            w.write_all(&[0u8; 3][..pad]).map_err(io)?;
            w.write_all(&blen.to_le_bytes()).map_err(io)?;
            n += 1;
        }
    } else {
        let lt = linktypes.first().copied().unwrap_or(1) as u32;
        w.write_all(&0xa1b2c3d4u32.to_le_bytes()).map_err(io)?;
        w.write_all(&2u16.to_le_bytes()).map_err(io)?;
        w.write_all(&4u16.to_le_bytes()).map_err(io)?;
        w.write_all(&0i32.to_le_bytes()).map_err(io)?;
        w.write_all(&0u32.to_le_bytes()).map_err(io)?;
        w.write_all(&262_144u32.to_le_bytes()).map_err(io)?;
        w.write_all(&lt.to_le_bytes()).map_err(io)?;
        for p in packets {
            w.write_all(&((p.ts_us / 1_000_000) as u32).to_le_bytes()).map_err(io)?;
            w.write_all(&((p.ts_us % 1_000_000) as u32).to_le_bytes()).map_err(io)?;
            w.write_all(&(p.data.len() as u32).to_le_bytes()).map_err(io)?;
            w.write_all(&p.orig_len.to_le_bytes()).map_err(io)?;
            w.write_all(&p.data).map_err(io)?;
            n += 1;
        }
    }
    w.flush().map_err(|e| e.to_string())?;
    Ok(n)
}
