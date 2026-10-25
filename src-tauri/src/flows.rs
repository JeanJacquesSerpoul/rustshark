//! Graphe des flux : qui parle à qui, avec quels volumes. Utilisé par la
//! carte des flux de l'application et par l'outil MCP `get_flows`.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use rustshark_shared::{Category, FlowEdge, FlowGraph, FlowNode, FlowNodeKind, Lang};

use crate::apps;
use crate::dissect::{self, p};
use crate::store::Store;

#[derive(Default)]
struct NodeAcc {
    bytes: u64,
    packets: u64,
}

#[derive(Default)]
struct EdgeAcc {
    packets: u64,
    bytes_ab: u64,
    bytes_ba: u64,
    encrypted: u64,
    cleartext: u64,
    services: HashMap<String, u64>,
    first_us: i64,
    last_us: i64,
}

fn node_kind(store: &Store, ip: &IpAddr) -> FlowNodeKind {
    if store.names.local.contains(ip) {
        FlowNodeKind::ThisComputer
    } else if ip.is_multicast() || matches!(ip, IpAddr::V4(v) if v.is_broadcast() || v.octets()[3] == 255) {
        FlowNodeKind::Group
    } else if dissect::is_private(ip) {
        FlowNodeKind::Local
    } else {
        FlowNodeKind::Internet
    }
}

fn service_label(m: &dissect::Meta) -> String {
    let udp = m.has(p::UDP);
    match m.proto_name {
        "TCP" | "UDP" => m
            .service_port()
            .and_then(|port| apps::service_name(port, udp).map(|s| s.to_string()).or_else(|| Some(format!("port {port}"))))
            .unwrap_or_else(|| m.proto_name.to_string()),
        other => other.to_string(),
    }
}

/// Construit le graphe des paquets `idx`. Les `max_nodes` adresses les plus
/// actives sont gardées ; les autres sont regroupées par catégorie.
pub fn graph(store: &Store, idx: &[u32], max_nodes: usize, max_edges: usize, lang: Lang) -> FlowGraph {
    let first = store.packets.first().map(|p| p.ts_us).unwrap_or(0);
    let mut nodes: HashMap<IpAddr, NodeAcc> = HashMap::new();
    let mut edges: HashMap<(IpAddr, IpAddr), EdgeAcc> = HashMap::new();
    let mut g = FlowGraph::default();

    for &i in idx {
        let pk = &store.packets[i as usize];
        let m = &pk.meta;
        let len = pk.orig_len as u64;
        g.packets += 1;
        g.bytes += len;
        let (Some(src), Some(dst)) = (m.src_ip, m.dst_ip) else {
            g.non_ip_packets_ignored += 1;
            continue;
        };
        if m.has(p::ARP) {
            g.non_ip_packets_ignored += 1;
            continue;
        }
        for ip in [src, dst] {
            let n = nodes.entry(ip).or_default();
            n.bytes += len;
            n.packets += 1;
        }
        let key = if src <= dst { (src, dst) } else { (dst, src) };
        let e = edges.entry(key).or_insert_with(|| EdgeAcc { first_us: pk.ts_us, ..Default::default() });
        e.packets += 1;
        e.last_us = pk.ts_us;
        if src == key.0 {
            e.bytes_ab += len;
        } else {
            e.bytes_ba += len;
        }
        if m.has(p::TLS) || m.has(p::QUIC) || m.has(p::SSH) || m.category == Category::SecureWeb {
            e.encrypted += len;
        } else if m.is_cleartext() || m.category == Category::Web {
            e.cleartext += len;
        }
        *e.services.entry(service_label(m)).or_default() += len;
    }
    if let (Some(a), Some(b)) = (idx.first(), idx.last()) {
        g.duration_s = (store.packets[*b as usize].ts_us - store.packets[*a as usize].ts_us) as f64 / 1e6;
    }

    // Nœuds conservés : les plus gros volumes, plus cet ordinateur.
    let mut ranked: Vec<(&IpAddr, &NodeAcc)> = nodes.iter().collect();
    ranked.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes));
    let mut kept: HashSet<IpAddr> = ranked.iter().take(max_nodes).map(|(ip, _)| **ip).collect();
    kept.extend(nodes.keys().filter(|ip| store.names.local.contains(*ip)));

    // Toutes les adresses de cet ordinateur (IPv4, IPv6…) forment un seul nœud.
    let id_of = |ip: &IpAddr| -> String {
        if store.names.local.contains(ip) {
            "this-computer".into()
        } else if kept.contains(ip) {
            ip.to_string()
        } else {
            match node_kind(store, ip) {
                FlowNodeKind::Internet => "others-internet".into(),
                FlowNodeKind::Group => "others-group".into(),
                _ => "others-local".into(),
            }
        }
    };

    let mut out_nodes: HashMap<String, FlowNode> = HashMap::new();
    for (ip, n) in &nodes {
        let id = id_of(ip);
        let node = out_nodes.entry(id.clone()).or_insert_with(|| {
            if id == "this-computer" {
                let mut addrs: Vec<String> = store.names.local.iter().map(|a| a.to_string()).collect();
                addrs.sort();
                FlowNode {
                    label: lang.pick("Cet ordinateur", "This computer").into(),
                    kind: FlowNodeKind::ThisComputer,
                    addresses: addrs,
                    filter: Some("this_computer".into()),
                    ..Default::default()
                }
            } else if kept.contains(ip) {
                FlowNode {
                    label: store.names.label(ip, lang).unwrap_or_else(|| ip.to_string()),
                    kind: node_kind(store, ip),
                    addresses: vec![ip.to_string()],
                    filter: Some(format!("ip.addr == {ip}")),
                    ..Default::default()
                }
            } else {
                let (fr, en, kind) = match id.as_str() {
                    "others-internet" => ("Autres serveurs Internet", "Other Internet servers", FlowNodeKind::Internet),
                    "others-group" => ("Autres groupes multicast", "Other multicast groups", FlowNodeKind::Group),
                    _ => ("Autres appareils locaux", "Other local devices", FlowNodeKind::Local),
                };
                FlowNode { label: lang.pick(fr, en).into(), kind, ..Default::default() }
            }
        });
        node.id = id;
        node.bytes += n.bytes;
        node.packets += n.packets;
        node.members += 1;
    }

    let mut merged: HashMap<(String, String), EdgeAcc> = HashMap::new();
    for ((a, b), e) in edges {
        let (ia, ib) = (id_of(&a), id_of(&b));
        if ia == ib {
            g.omitted_bytes += e.bytes_ab + e.bytes_ba;
            continue;
        }
        let (key, forward) = if ia <= ib { ((ia, ib), true) } else { ((ib, ia), false) };
        let m = merged.entry(key).or_insert_with(|| EdgeAcc { first_us: e.first_us, ..Default::default() });
        m.packets += e.packets;
        if forward {
            m.bytes_ab += e.bytes_ab;
            m.bytes_ba += e.bytes_ba;
        } else {
            m.bytes_ab += e.bytes_ba;
            m.bytes_ba += e.bytes_ab;
        }
        m.encrypted += e.encrypted;
        m.cleartext += e.cleartext;
        m.first_us = m.first_us.min(e.first_us);
        m.last_us = m.last_us.max(e.last_us);
        for (s, v) in e.services {
            *m.services.entry(s).or_default() += v;
        }
    }

    let filter_of = |id: &str| out_nodes.get(id).and_then(|n| n.filter.clone());
    let mut out_edges: Vec<FlowEdge> = merged
        .into_iter()
        .map(|((a, b), e)| {
            let bytes = e.bytes_ab + e.bytes_ba;
            let mut services: Vec<(String, u64)> = e.services.into_iter().collect();
            services.sort_by(|x, y| y.1.cmp(&x.1));
            let filter = match (filter_of(&a), filter_of(&b)) {
                (Some(x), Some(y)) => Some(format!("{x} && {y}")),
                _ => None,
            };
            FlowEdge {
                source: a,
                target: b,
                bytes,
                packets: e.packets,
                bytes_source_to_target: e.bytes_ab,
                bytes_target_to_source: e.bytes_ba,
                encrypted_percent: if bytes == 0 { 0.0 } else { (e.encrypted as f64 * 1000.0 / bytes as f64).round() / 10.0 },
                cleartext_bytes: e.cleartext,
                services: services.into_iter().take(6).map(|(s, _)| s).collect(),
                first_s: (e.first_us - first) as f64 / 1e6,
                last_s: (e.last_us - first) as f64 / 1e6,
                filter,
            }
        })
        .collect();
    out_edges.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    g.omitted_edges = out_edges.len().saturating_sub(max_edges) as u32;
    g.omitted_bytes += out_edges.iter().skip(max_edges).map(|e| e.bytes).sum::<u64>();
    out_edges.truncate(max_edges);

    let mut node_list: Vec<FlowNode> = out_nodes.into_values().collect();
    node_list.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    g.nodes = node_list;
    g.edges = out_edges;
    g
}
