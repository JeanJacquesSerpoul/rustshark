//! Stockage des paquets capturés, vue filtrée, détails et statistiques.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Instant;

use rustshark_shared::filter::{self, Expr, Source, Val};
use rustshark_shared::{
    Alert, AlertLevel, CaptureState, CaptureStatus, Category, CategoryCount, Conversation, CountItem, Field,
    HostStat, Lang, Layer, PacketDetail, PacketRow, Stats, ViewResponse,
};

use crate::apps::App;
use crate::dissect::{self, fmt_mac, is_private, p, proto_bit, Meta, Tb, TCP_ACK, TCP_SYN};
use crate::explain::{self, Names};

pub struct RawPacket {
    pub ts_us: i64,
    pub orig_len: u32,
    pub linktype: u16,
    pub data: Vec<u8>,
}

pub struct Packet {
    pub ts_us: i64,
    pub orig_len: u32,
    pub linktype: u16,
    pub data: Box<[u8]>,
    pub meta: Meta,
}

pub struct Store {
    pub packets: Vec<Packet>,
    pub names: Names,
    filter: Expr,
    /// Indices des paquets correspondant au filtre (None = tous).
    view: Option<Vec<u32>>,
    bytes: u64,
    pub state: CaptureState,
    pub source: Option<String>,
    pub capture_filter: Option<String>,
    pub dropped: u32,
    pub error: Option<String>,
    pub truncated: bool,
    started: Option<Instant>,
    frozen_elapsed: Option<f64>,
    pub max_packets: usize,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            packets: Vec::new(),
            names: Names::default(),
            filter: Expr::True,
            view: None,
            bytes: 0,
            state: CaptureState::Idle,
            source: None,
            capture_filter: None,
            dropped: 0,
            error: None,
            truncated: false,
            started: None,
            frozen_elapsed: None,
            max_packets: 1_000_000,
        }
    }
}

struct Src<'a> {
    no: u32,
    p: &'a Packet,
    names: &'a Names,
}

impl Source for Src<'_> {
    fn has(&self, field: &str) -> bool {
        let m = &self.p.meta;
        if let Some(bit) = proto_bit(field) {
            return m.has(bit);
        }
        let f = m.tcp_flags();
        match field {
            "tcp.flags.syn" => f & TCP_SYN != 0,
            "tcp.flags.ack" => f & TCP_ACK != 0,
            "tcp.flags.fin" => f & dissect::TCP_FIN != 0,
            "tcp.flags.rst" => f & dissect::TCP_RST != 0,
            "tcp.flags.push" => f & dissect::TCP_PSH != 0,
            "dns.response" => matches!(&m.app, App::Dns(d) if d.response),
            "http.request" => matches!(&m.app, App::Http(h) if h.request),
            "http.response" => matches!(&m.app, App::Http(h) if !h.request),
            "tls.client_hello" => matches!(&m.app, App::Tls(t) if t.handshakes.contains(&1)),
            "broadcast" => m.is_broadcast(),
            "multicast" => m.is_multicast(),
            "local" => match (m.src_ip, m.dst_ip) {
                (Some(a), Some(b)) => dissect::is_local_scope(&a) && dissect::is_local_scope(&b),
                _ => m.src_mac.is_some(),
            },
            "internet" => match (m.src_ip, m.dst_ip) {
                (Some(a), Some(b)) => !dissect::is_local_scope(&a) || !dissect::is_local_scope(&b),
                _ => false,
            },
            "this_computer" => m.src_ip.iter().chain(m.dst_ip.iter()).any(|ip| self.names.local.contains(ip)),
            "problem" => m.is_problem(),
            "cleartext" => m.is_cleartext(),
            other => {
                let mut v = Vec::new();
                self.values(other, &mut v);
                !v.is_empty()
            }
        }
    }

    fn values<'a>(&'a self, field: &str, out: &mut Vec<Val<'a>>) {
        let m = &self.p.meta;
        let num = |out: &mut Vec<Val<'a>>, v: Option<u16>| {
            if let Some(v) = v {
                out.push(Val::Num(v as f64));
            }
        };
        match field {
            "ip.addr" => out.extend(m.src_ip.into_iter().chain(m.dst_ip).map(Val::Ip)),
            "ip.src" => out.extend(m.src_ip.map(Val::Ip)),
            "ip.dst" => out.extend(m.dst_ip.map(Val::Ip)),
            "dns.a" => {
                if let App::Dns(d) = &m.app {
                    out.extend(d.answers.iter().filter_map(|a| a.ip).map(Val::Ip));
                }
            }
            "port" => {
                num(out, m.src_port);
                num(out, m.dst_port);
            }
            "src.port" => num(out, m.src_port),
            "dst.port" => num(out, m.dst_port),
            "tcp.port" if m.has(p::TCP) => {
                num(out, m.src_port);
                num(out, m.dst_port);
            }
            "udp.port" if m.has(p::UDP) => {
                num(out, m.src_port);
                num(out, m.dst_port);
            }
            "tcp.srcport" if m.has(p::TCP) => num(out, m.src_port),
            "tcp.dstport" if m.has(p::TCP) => num(out, m.dst_port),
            "udp.srcport" if m.has(p::UDP) => num(out, m.src_port),
            "udp.dstport" if m.has(p::UDP) => num(out, m.dst_port),
            "frame.len" => out.push(Val::Num(self.p.orig_len as f64)),
            "frame.number" => out.push(Val::Num(self.no as f64)),
            "ip.ttl" => out.extend(m.ttl.map(|t| Val::Num(t as f64))),
            "http.status" => {
                if let App::Http(h) = &m.app {
                    num(out, h.status);
                }
            }
            "dns.rcode" => {
                if let App::Dns(d) = &m.app {
                    if d.response {
                        out.push(Val::Num(d.rcode as f64));
                    }
                }
            }
            "icmp.type" => {
                if let App::Icmp { t, .. } = &m.app {
                    out.push(Val::Num(*t as f64));
                }
            }
            "host" => {
                for ip in m.src_ip.iter().chain(m.dst_ip.iter()) {
                    if let Some(n) = self.names.learned(ip) {
                        out.push(Val::Text(Cow::Borrowed(n)));
                    }
                }
                self.app_names(out);
            }
            "eth.addr" => out.extend(m.src_mac.iter().chain(m.dst_mac.iter()).map(|x| Val::Text(Cow::Owned(fmt_mac(x))))),
            "eth.src" => out.extend(m.src_mac.map(|x| Val::Text(Cow::Owned(fmt_mac(&x))))),
            "eth.dst" => out.extend(m.dst_mac.map(|x| Val::Text(Cow::Owned(fmt_mac(&x))))),
            "dns.qry.name" => {
                if let App::Dns(d) = &m.app {
                    out.extend(d.questions.iter().map(|q| Val::Text(Cow::Borrowed(q.0.as_str()))));
                }
            }
            "tls.sni" => {
                if let App::Tls(t) = &m.app {
                    out.extend(t.sni.as_deref().map(|s| Val::Text(Cow::Borrowed(s))));
                }
            }
            "http.host" | "http.method" | "http.uri" | "http.user_agent" => {
                if let App::Http(h) = &m.app {
                    let v = match field {
                        "http.host" => h.host.as_deref(),
                        "http.method" => Some(h.method.as_str()).filter(|s| !s.is_empty()),
                        "http.uri" => Some(h.uri.as_str()).filter(|s| !s.is_empty()),
                        _ => h.user_agent.as_deref(),
                    };
                    out.extend(v.map(|s| Val::Text(Cow::Borrowed(s))));
                }
            }
            "protocol" => out.push(Val::Text(Cow::Borrowed(m.proto_name))),
            "category" => out.push(Val::Text(Cow::Borrowed(m.category.id()))),
            "info" => out.push(Val::Text(Cow::Borrowed(m.info.as_str()))),
            _ => {}
        }
    }

    fn text(&self, needle: &str) -> bool {
        let m = &self.p.meta;
        let hit = |s: &str| s.to_lowercase().contains(needle);
        if hit(&m.info) || hit(m.proto_name) {
            return true;
        }
        for ip in m.src_ip.iter().chain(m.dst_ip.iter()) {
            if ip.to_string().contains(needle) {
                return true;
            }
            if let Some(n) = self.names.learned(ip) {
                if hit(n) {
                    return true;
                }
            }
        }
        let mut v = Vec::new();
        self.app_names(&mut v);
        v.iter().any(|x| matches!(x, Val::Text(s) if hit(s)))
    }
}

impl<'a> Src<'a> {
    fn app_names(&self, out: &mut Vec<Val<'a>>) {
        match &self.p.meta.app {
            App::Dns(d) => {
                out.extend(d.questions.iter().map(|q| Val::Text(Cow::Borrowed(q.0.as_str()))));
                out.extend(d.answers.iter().map(|a| Val::Text(Cow::Borrowed(a.name.as_str()))));
            }
            App::Tls(t) => out.extend(t.sni.as_deref().map(|s| Val::Text(Cow::Borrowed(s)))),
            App::Http(h) => out.extend(h.host.as_deref().map(|s| Val::Text(Cow::Borrowed(s)))),
            App::Dhcp(d) => out.extend(d.hostname.as_deref().map(|s| Val::Text(Cow::Borrowed(s)))),
            App::Nbns { name: Some(n), .. } => out.push(Val::Text(Cow::Borrowed(n.as_str()))),
            _ => {}
        }
    }
}

fn addr_str(ip: Option<IpAddr>, mac: Option<[u8; 6]>) -> String {
    match (ip, mac) {
        (Some(ip), _) => ip.to_string(),
        (None, Some(m)) => fmt_mac(&m),
        _ => "—".into(),
    }
}

impl Store {
    pub fn clear(&mut self) {
        self.packets.clear();
        self.packets.shrink_to_fit();
        self.names.clear_learned();
        self.view = if self.filter.is_true() { None } else { Some(Vec::new()) };
        self.bytes = 0;
        self.dropped = 0;
        self.error = None;
        self.truncated = false;
        if self.state != CaptureState::Running {
            self.state = CaptureState::Idle;
            self.source = None;
            self.started = None;
            self.frozen_elapsed = None;
        } else {
            self.started = Some(Instant::now());
        }
    }

    pub fn begin(&mut self, state: CaptureState, source: String, capture_filter: Option<String>) {
        self.clear();
        self.state = state;
        self.source = Some(source);
        self.capture_filter = capture_filter;
        self.started = Some(Instant::now());
        self.frozen_elapsed = None;
    }

    pub fn finish(&mut self, error: Option<String>) {
        if self.state == CaptureState::Running {
            self.state = CaptureState::Stopped;
            self.frozen_elapsed = self.started.map(|s| s.elapsed().as_secs_f64());
        }
        if error.is_some() {
            self.error = error;
        }
    }

    pub fn push_batch(&mut self, batch: Vec<RawPacket>) {
        for raw in batch {
            if self.packets.len() >= self.max_packets {
                self.truncated = true;
                return;
            }
            let meta = dissect::dissect(&raw.data, raw.linktype, &mut Tb::off());
            self.names.learn(&meta);
            self.bytes += raw.orig_len as u64;
            let pkt = Packet {
                ts_us: raw.ts_us,
                orig_len: raw.orig_len,
                linktype: raw.linktype,
                data: raw.data.into_boxed_slice(),
                meta,
            };
            let idx = self.packets.len() as u32;
            if let Some(view) = self.view.as_mut() {
                let src = Src { no: idx + 1, p: &pkt, names: &self.names };
                if self.filter.eval(&src) {
                    view.push(idx);
                }
            }
            self.packets.push(pkt);
        }
    }

    /// Applique un filtre d'affichage. Renvoie le nombre de paquets retenus.
    pub fn set_filter(&mut self, text: &str) -> Result<u32, filter::FilterError> {
        let expr = filter::parse(text)?;
        if expr.is_true() {
            self.filter = expr;
            self.view = None;
            return Ok(self.packets.len() as u32);
        }
        let view: Vec<u32> = self
            .packets
            .iter()
            .enumerate()
            .filter(|(i, p)| expr.eval(&Src { no: *i as u32 + 1, p, names: &self.names }))
            .map(|(i, _)| i as u32)
            .collect();
        self.filter = expr;
        let n = view.len() as u32;
        self.view = Some(view);
        Ok(n)
    }

    pub fn status(&self) -> CaptureStatus {
        let elapsed = match (self.state, self.frozen_elapsed, self.started) {
            (CaptureState::File, _, _) => self.span_secs(),
            (_, Some(e), _) => e,
            (CaptureState::Running, None, Some(s)) => s.elapsed().as_secs_f64(),
            _ => 0.0,
        };
        CaptureStatus {
            state: self.state,
            source: self.source.clone(),
            capture_filter: self.capture_filter.clone(),
            packets: self.packets.len() as u32,
            bytes: self.bytes,
            dropped: self.dropped,
            elapsed,
            error: self.error.clone(),
            truncated: self.truncated,
        }
    }

    fn span_secs(&self) -> f64 {
        match (self.packets.first(), self.packets.last()) {
            (Some(a), Some(b)) => (b.ts_us - a.ts_us) as f64 / 1e6,
            _ => 0.0,
        }
    }

    fn first_ts(&self) -> i64 {
        self.packets.first().map(|p| p.ts_us).unwrap_or(0)
    }

    pub fn matched(&self) -> usize {
        self.view.as_ref().map(|v| v.len()).unwrap_or(self.packets.len())
    }

    /// Indices (dans `packets`) de la portée demandée.
    pub fn scope_indices(&self, filtered: bool) -> Vec<u32> {
        match (&self.view, filtered) {
            (Some(v), true) => v.clone(),
            _ => (0..self.packets.len() as u32).collect(),
        }
    }

    fn index_at(&self, view_pos: usize) -> Option<usize> {
        match &self.view {
            Some(v) => v.get(view_pos).map(|i| *i as usize),
            None => (view_pos < self.packets.len()).then_some(view_pos),
        }
    }

    pub fn row(&self, idx: usize, lang: Lang) -> PacketRow {
        let p = &self.packets[idx];
        let m = &p.meta;
        PacketRow {
            no: idx as u32 + 1,
            time: (p.ts_us - self.first_ts()) as f64 / 1e6,
            src: addr_str(m.src_ip, m.src_mac),
            dst: addr_str(m.dst_ip, m.dst_mac),
            src_name: m.src_ip.and_then(|ip| self.names.label(&ip, lang)),
            dst_name: m.dst_ip.and_then(|ip| self.names.label(&ip, lang)),
            protocol: m.proto_name.to_string(),
            length: p.orig_len,
            info: m.info.clone(),
            summary: explain::summary(m, lang),
            category: m.category,
        }
    }

    pub fn view(&self, offset: u32, limit: u32, lang: Lang) -> ViewResponse {
        let matched = self.matched();
        let start = (offset as usize).min(matched);
        let end = (start + limit.min(2000) as usize).min(matched);
        let rows = (start..end).filter_map(|pos| self.index_at(pos)).map(|i| self.row(i, lang)).collect();
        ViewResponse {
            total: self.packets.len() as u32,
            matched: matched as u32,
            offset: start as u32,
            rows,
            status: self.status(),
        }
    }

    /// Position dans la vue d'un numéro de paquet (pour la navigation).
    pub fn position_of(&self, no: u32) -> Option<u32> {
        let idx = no.checked_sub(1)?;
        match &self.view {
            Some(v) => v.binary_search(&idx).ok().map(|p| p as u32),
            None => ((idx as usize) < self.packets.len()).then_some(idx),
        }
    }

    pub fn detail(&self, no: u32, lang: Lang) -> Option<PacketDetail> {
        let idx = (no as usize).checked_sub(1)?;
        let p = self.packets.get(idx)?;
        let mut tb = Tb::new(lang);
        let m = dissect::dissect(&p.data, p.linktype, &mut tb);
        let abs = chrono::DateTime::from_timestamp_micros(p.ts_us)
            .map(|d| d.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S%.6f").to_string())
            .unwrap_or_default();
        let mut layers = vec![Layer {
            id: "frame".into(),
            title: match lang {
                Lang::Fr => format!("Trame n°{no} : {} octets sur le réseau, {} capturés", p.orig_len, p.data.len()),
                Lang::En => format!("Frame {no}: {} bytes on wire, {} captured", p.orig_len, p.data.len()),
            },
            help: lang
                .pick(
                    "Informations sur la capture de ce paquet : heure d'arrivée et taille.",
                    "Information about the capture of this packet: arrival time and size.",
                )
                .into(),
            offset: 0,
            len: p.data.len() as u32,
            fields: vec![
                Field { name: lang.pick("Heure d'arrivée", "Arrival time").into(), value: abs.clone(), help: None },
                Field { name: lang.pick("Taille réelle", "Wire length").into(), value: p.orig_len.to_string(), help: None },
                Field { name: lang.pick("Taille capturée", "Captured length").into(), value: p.data.len().to_string(), help: None },
                Field { name: lang.pick("Type de liaison", "Link type").into(), value: p.linktype.to_string(), help: None },
            ],
        }];
        layers.extend(tb.layers);
        let (explanation, tips) = explain::explain(&m, &self.names, lang);
        let conversation_filter = match (m.src_ip, m.dst_ip, m.src_port, m.dst_port) {
            (Some(a), Some(b), Some(sp), Some(dp)) => Some(format!("ip.addr == {a} && ip.addr == {b} && port == {sp} && port == {dp}")),
            (Some(a), Some(b), _, _) if !m.has(p::ARP) => Some(format!("ip.addr == {a} && ip.addr == {b}")),
            _ if m.has(p::ARP) => Some("arp".into()),
            _ => None,
        };
        Some(PacketDetail {
            no,
            time: (p.ts_us - self.first_ts()) as f64 / 1e6,
            abs_time: abs,
            length: p.orig_len,
            captured: p.data.len() as u32,
            protocol: m.proto_name.to_string(),
            category: m.category,
            src: addr_str(m.src_ip, m.src_mac),
            dst: addr_str(m.dst_ip, m.dst_mac),
            src_name: m.src_ip.and_then(|ip| self.names.label(&ip, lang)),
            dst_name: m.dst_ip.and_then(|ip| self.names.label(&ip, lang)),
            explanation,
            tips,
            layers,
            bytes: p.data.to_vec(),
            conversation_filter,
        })
    }

    // -----------------------------------------------------------------------
    // Statistiques
    // -----------------------------------------------------------------------

    /// Indices des paquets qui satisfont `expr`, sans modifier la vue courante.
    pub fn matching(&self, expr: &Expr) -> Vec<u32> {
        if expr.is_true() {
            return (0..self.packets.len() as u32).collect();
        }
        self.packets
            .iter()
            .enumerate()
            .filter(|(i, p)| expr.eval(&Src { no: *i as u32 + 1, p, names: &self.names }))
            .map(|(i, _)| i as u32)
            .collect()
    }

    pub fn stats(&self, filtered: bool, lang: Lang) -> Stats {
        self.stats_for(&self.scope_indices(filtered), lang)
    }

    pub fn stats_for(&self, idx: &[u32], lang: Lang) -> Stats {
        let mut s = Stats::default();
        if idx.is_empty() {
            return s;
        }
        let first = self.packets[idx[0] as usize].ts_us;
        let last = self.packets[*idx.last().unwrap() as usize].ts_us;
        s.duration = (last - first) as f64 / 1e6;
        let buckets = (s.duration.ceil() as usize + 1).clamp(1, 60);
        s.timeline_step = (s.duration / buckets as f64).max(0.001);
        s.timeline = vec![0; buckets];

        let mut protos: HashMap<&str, (u64, u64)> = HashMap::new();
        let mut cats: HashMap<Category, (u64, u64)> = HashMap::new();
        let mut hosts: HashMap<IpAddr, (u64, u64)> = HashMap::new();
        let mut convs: HashMap<(IpAddr, IpAddr, &str, Option<u16>), (u64, u64, i64, i64)> = HashMap::new();
        let mut dns_names: HashMap<String, u64> = HashMap::new();
        let mut sites: HashMap<String, (u64, u64)> = HashMap::new();
        let mut a = AlertAcc::default();

        for &i in idx {
            let p = &self.packets[i as usize];
            let m = &p.meta;
            let len = p.orig_len as u64;
            s.packets += 1;
            s.bytes += len;
            let b = (((p.ts_us - first) as f64 / 1e6) / s.timeline_step) as usize;
            s.timeline[b.min(buckets - 1)] += 1;
            let e = protos.entry(m.proto_name).or_default();
            e.0 += 1;
            e.1 += len;
            let e = cats.entry(m.category).or_default();
            e.0 += 1;
            e.1 += len;
            if let (Some(src), Some(dst)) = (m.src_ip, m.dst_ip) {
                for ip in [src, dst] {
                    let e = hosts.entry(ip).or_default();
                    e.0 += 1;
                    e.1 += len;
                }
                let (x, y) = if src <= dst { (src, dst) } else { (dst, src) };
                let l4 = if m.has(p::TCP) { "TCP" } else if m.has(p::UDP) { "UDP" } else { m.proto_name };
                let e = convs.entry((x, y, l4, m.service_port())).or_insert((0, 0, p.ts_us, p.ts_us));
                e.0 += 1;
                e.1 += len;
                e.3 = p.ts_us;
                // Site distant = côté public dont on connaît le nom.
                for (remote, other) in [(dst, src), (src, dst)] {
                    if !dissect::is_local_scope(&remote) && dissect::is_local_scope(&other) {
                        if let Some(n) = self.names.learned(&remote) {
                            let e = sites.entry(n.to_string()).or_default();
                            e.0 += 1;
                            e.1 += len;
                        }
                    }
                }
            }
            if let App::Dns(d) = &m.app {
                if !d.response && m.has(p::DNS) {
                    for q in &d.questions {
                        *dns_names.entry(q.0.clone()).or_default() += 1;
                    }
                }
            }
            a.observe(m);
        }

        let to_items = |map: HashMap<String, (u64, u64)>, n: usize, by_bytes: bool| {
            let mut v: Vec<CountItem> = map.into_iter().map(|(label, (packets, bytes))| CountItem { label, packets, bytes }).collect();
            v.sort_by(|a, b| if by_bytes { b.bytes.cmp(&a.bytes) } else { b.packets.cmp(&a.packets) });
            v.truncate(n);
            v
        };
        s.protocols = to_items(protos.into_iter().map(|(k, v)| (k.to_string(), v)).collect(), 20, false);
        let mut cv: Vec<CategoryCount> = cats.into_iter().map(|(category, (packets, bytes))| CategoryCount { category, packets, bytes }).collect();
        cv.sort_by(|a, b| b.bytes.cmp(&a.bytes));
        s.categories = cv;
        let mut hv: Vec<HostStat> = hosts
            .into_iter()
            .map(|(ip, (packets, bytes))| HostStat {
                addr: ip.to_string(),
                name: self.names.label(&ip, lang),
                packets,
                bytes,
                local: is_private(&ip),
            })
            .collect();
        hv.sort_by(|a, b| b.bytes.cmp(&a.bytes));
        hv.truncate(15);
        s.top_hosts = hv;
        let mut conv: Vec<Conversation> = convs
            .into_iter()
            .map(|((x, y, l4, port), (packets, bytes, t0, t1))| {
                let mut filter = format!("ip.addr == {x} && ip.addr == {y}");
                if let Some(pt) = port {
                    filter.push_str(&format!(" && {}.port == {pt}", l4.to_lowercase()));
                }
                Conversation {
                    a: x.to_string(),
                    b: y.to_string(),
                    a_name: self.names.label(&x, lang),
                    b_name: self.names.label(&y, lang),
                    protocol: l4.to_string(),
                    service: port.and_then(|pt| explain::service_desc(pt, l4 == "UDP", lang)),
                    packets,
                    bytes,
                    start: (t0 - first) as f64 / 1e6,
                    end: (t1 - first) as f64 / 1e6,
                    filter,
                }
            })
            .collect();
        conv.sort_by(|a, b| b.bytes.cmp(&a.bytes));
        conv.truncate(30);
        s.conversations = conv;
        s.dns_names = to_items(dns_names.into_iter().map(|(k, v)| (k, (v, 0))).collect(), 30, false);
        s.sites = to_items(sites, 25, true);
        s.alerts = a.finish(lang);
        s
    }
}

/// Ce que la capture a appris sur un appareil du réseau local.
#[derive(Default)]
pub struct LanHost {
    pub mac: Option<[u8; 6]>,
    pub packets: u64,
    pub bytes: u64,
    pub hostname: Option<String>,
    /// Classe d'appareil annoncée en DHCP (« android-dhcp-14 », « MSFT 5.0 »…).
    pub dhcp_vendor: Option<String>,
}

impl Store {
    /// Appareils locaux vus dans la capture (adresses acceptées par `inside`).
    pub fn lan_hosts(&self, inside: impl Fn(&IpAddr) -> bool) -> HashMap<IpAddr, LanHost> {
        let mut out: HashMap<IpAddr, LanHost> = HashMap::new();
        let mut dhcp: HashMap<[u8; 6], (Option<String>, Option<String>, Option<IpAddr>)> = HashMap::new();
        for p in &self.packets {
            let m = &p.meta;
            let len = p.orig_len as u64;
            if let Some(src) = m.src_ip.filter(|ip| inside(ip)) {
                let h = out.entry(src).or_default();
                h.packets += 1;
                h.bytes += len;
                if m.src_mac.is_some() {
                    h.mac = m.src_mac;
                }
            }
            if let Some(dst) = m.dst_ip.filter(|ip| inside(ip)) {
                let h = out.entry(dst).or_default();
                h.packets += 1;
                h.bytes += len;
            }
            match &m.app {
                App::Dhcp(d) => {
                    let e = dhcp.entry(d.client_mac).or_default();
                    if d.hostname.is_some() {
                        e.0 = d.hostname.clone();
                    }
                    if d.vendor.is_some() {
                        e.1 = d.vendor.clone();
                    }
                    let ip = if !d.your_ip.is_unspecified() { Some(d.your_ip) } else { d.requested_ip };
                    if let Some(ip) = ip {
                        e.2 = Some(IpAddr::V4(ip));
                    }
                }
                App::Arp(a) if !a.sender_ip.is_unspecified() && inside(&IpAddr::V4(a.sender_ip)) => {
                    out.entry(IpAddr::V4(a.sender_ip)).or_default().mac = Some(a.sender_mac);
                }
                _ => {}
            }
        }
        for (mac, (hostname, vendor, ip)) in dhcp {
            let ip = ip.filter(|ip| inside(ip)).or_else(|| out.iter().find(|(_, h)| h.mac == Some(mac)).map(|(ip, _)| *ip));
            if let Some(ip) = ip {
                let h = out.entry(ip).or_default();
                h.mac.get_or_insert(mac);
                h.hostname = hostname.or(h.hostname.take());
                h.dhcp_vendor = vendor;
            }
        }
        for (ip, h) in out.iter_mut() {
            if h.hostname.is_none() {
                h.hostname = self.names.learned(ip).map(String::from);
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Détection d'anomalies (heuristiques simples et explicables)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct AlertAcc {
    credentials: u64,
    http_hosts: HashSet<String>,
    cleartext_services: HashSet<&'static str>,
    old_tls: u64,
    nxdomain: u64,
    rst: u64,
    unreachable: u64,
    syn_targets: HashMap<IpAddr, HashSet<(IpAddr, u16)>>,
    arp_claims: HashMap<std::net::Ipv4Addr, HashSet<[u8; 6]>>,
    malformed: u64,
}

impl AlertAcc {
    fn observe(&mut self, m: &Meta) {
        match &m.app {
            App::Http(h) => {
                if h.credentials {
                    self.credentials += 1;
                }
                // Les échanges HTTP internes (UPnP de la box…) ne sont pas des « sites visités ».
                let remote = m.dst_ip.map(|ip| !dissect::is_local_scope(&ip)).unwrap_or(false);
                if let (Some(host), true) = (&h.host, remote) {
                    self.http_hosts.insert(host.clone());
                }
            }
            App::Text { service, credentials, .. } => {
                self.cleartext_services.insert(service);
                if *credentials {
                    self.credentials += 1;
                }
            }
            App::Tls(t) if t.handshakes.contains(&2) => {
                if matches!(t.version, Some(v) if v < 0x0303) {
                    self.old_tls += 1;
                }
            }
            App::Dns(d) if d.response && d.rcode == 3 && m.has(p::DNS) => self.nxdomain += 1,
            App::Icmp { t: 3, .. } if m.has(p::ICMP) => self.unreachable += 1,
            App::Icmp { t: 1, .. } if m.has(p::ICMPV6) => self.unreachable += 1,
            App::Arp(a) if !a.sender_ip.is_unspecified() => {
                self.arp_claims.entry(a.sender_ip).or_default().insert(a.sender_mac);
            }
            _ => {}
        }
        if m.has(p::TELNET) {
            self.cleartext_services.insert("Telnet");
        }
        let f = m.tcp_flags();
        if f & dissect::TCP_RST != 0 {
            self.rst += 1;
        }
        if f & TCP_SYN != 0 && f & TCP_ACK == 0 {
            if let (Some(src), Some(dst), Some(dp)) = (m.src_ip, m.dst_ip, m.dst_port) {
                let set = self.syn_targets.entry(src).or_default();
                if set.len() < 5000 {
                    set.insert((dst, dp));
                }
            }
        }
        if m.malformed {
            self.malformed += 1;
        }
    }

    fn finish(self, lang: Lang) -> Vec<Alert> {
        let mut out = Vec::new();
        let fr = lang == Lang::Fr;
        if self.credentials > 0 {
            out.push(Alert {
                level: AlertLevel::Danger,
                title: lang.pick("Identifiants visibles en clair", "Credentials visible in clear text").into(),
                detail: if fr {
                    format!("{} paquet(s) semblent contenir un identifiant ou un mot de passe lisible par n'importe qui sur le réseau. Utilisez des services chiffrés (HTTPS, SFTP, IMAPS…) et changez les mots de passe concernés.", self.credentials)
                } else {
                    format!("{} packet(s) seem to carry a login or password readable by anyone on the network. Use encrypted services (HTTPS, SFTP, IMAPS…) and change the affected passwords.", self.credentials)
                },
                filter: Some("cleartext".into()),
                count: self.credentials,
            });
        }
        // Scan de ports : beaucoup de destinations (hôte, port) différentes en SYN.
        for (src, targets) in &self.syn_targets {
            let mut per_host: HashMap<IpAddr, usize> = HashMap::new();
            for (h, _) in targets {
                *per_host.entry(*h).or_default() += 1;
            }
            let max_ports = per_host.values().copied().max().unwrap_or(0);
            if max_ports >= 25 || targets.len() >= 150 {
                out.push(Alert {
                    level: AlertLevel::Danger,
                    title: if fr { format!("Possible scan de ports depuis {src}") } else { format!("Possible port scan from {src}") },
                    detail: if fr {
                        format!("Cet appareil a tenté d'ouvrir des connexions vers {} combinaisons adresse/port différentes (jusqu'à {max_ports} ports sur un même appareil). C'est typique d'un outil qui cherche des services ouverts.", targets.len())
                    } else {
                        format!("This device tried to open connections to {} different address/port combinations (up to {max_ports} ports on a single device). This is typical of a tool searching for open services.", targets.len())
                    },
                    filter: Some(format!("ip.src == {src} && tcp.flags.syn && !tcp.flags.ack")),
                    count: targets.len() as u64,
                });
            }
        }
        for (ip, macs) in &self.arp_claims {
            if macs.len() > 1 {
                let list: Vec<String> = macs.iter().map(|m| fmt_mac(m)).collect();
                out.push(Alert {
                    level: AlertLevel::Danger,
                    title: if fr { format!("Conflit d'adresse pour {ip}") } else { format!("Address conflict for {ip}") },
                    detail: if fr {
                        format!("Plusieurs cartes réseau ({}) prétendent posséder l'adresse {ip}. Cela peut être une simple erreur de configuration… ou une attaque « ARP spoofing » visant à intercepter le trafic.", list.join(", "))
                    } else {
                        format!("Several network cards ({}) claim to own {ip}. It may be a simple misconfiguration… or an 'ARP spoofing' attack aimed at intercepting traffic.", list.join(", "))
                    },
                    filter: Some(format!("arp && ip.addr == {ip}")),
                    count: macs.len() as u64,
                });
            }
        }
        if !self.cleartext_services.is_empty() {
            let mut v: Vec<&str> = self.cleartext_services.iter().copied().collect();
            v.sort();
            out.push(Alert {
                level: AlertLevel::Warning,
                title: lang.pick("Protocoles non chiffrés utilisés", "Unencrypted protocols in use").into(),
                detail: if fr {
                    format!("Des échanges {} circulent en clair. Leur contenu est lisible par toute personne sur le réseau.", v.join(", "))
                } else {
                    format!("{} exchanges travel in clear text. Their content is readable by anyone on the network.", v.join(", "))
                },
                filter: Some("cleartext".into()),
                count: v.len() as u64,
            });
        }
        if !self.http_hosts.is_empty() {
            let mut v: Vec<&String> = self.http_hosts.iter().collect();
            v.sort();
            let shown: Vec<&str> = v.iter().take(6).map(|s| s.as_str()).collect();
            out.push(Alert {
                level: AlertLevel::Warning,
                title: lang.pick("Sites consultés sans chiffrement (HTTP)", "Sites visited without encryption (HTTP)").into(),
                detail: if fr {
                    format!("{} site(s) contacté(s) en HTTP simple : {}{}. Ce trafic peut être lu ou modifié en chemin.", v.len(), shown.join(", "), if v.len() > 6 { "…" } else { "" })
                } else {
                    format!("{} site(s) contacted over plain HTTP: {}{}. This traffic can be read or altered on the way.", v.len(), shown.join(", "), if v.len() > 6 { "…" } else { "" })
                },
                filter: Some("http".into()),
                count: v.len() as u64,
            });
        }
        if self.old_tls > 0 {
            out.push(Alert {
                level: AlertLevel::Warning,
                title: lang.pick("Chiffrement obsolète", "Obsolete encryption").into(),
                detail: lang.pick(
                    "Certaines connexions sécurisées utilisent TLS 1.0/1.1 ou SSL, des versions qui ne sont plus considérées comme sûres.",
                    "Some secure connections use TLS 1.0/1.1 or SSL, versions no longer considered safe.").into(),
                filter: Some("tls".into()),
                count: self.old_tls,
            });
        }
        if self.nxdomain >= 10 {
            out.push(Alert {
                level: AlertLevel::Info,
                title: lang.pick("Nombreux noms introuvables", "Many names not found").into(),
                detail: if fr {
                    format!("{} recherches DNS ont échoué (« ce nom n'existe pas »). Souvent dû à un bloqueur de publicité ou à une faute de frappe ; si les noms semblent aléatoires, cela peut trahir un logiciel malveillant.", self.nxdomain)
                } else {
                    format!("{} DNS lookups failed ('no such name'). Often due to an ad blocker or a typo; if the names look random, it may reveal malware.", self.nxdomain)
                },
                filter: Some("dns.rcode == 3".into()),
                count: self.nxdomain,
            });
        }
        if self.rst >= 20 {
            out.push(Alert {
                level: AlertLevel::Info,
                title: lang.pick("Nombreuses connexions refusées", "Many refused connections").into(),
                detail: if fr {
                    format!("{} connexions ont été refusées ou coupées brutalement. Cela peut indiquer un pare-feu, un service arrêté ou un problème réseau.", self.rst)
                } else {
                    format!("{} connections were refused or abruptly reset. This may indicate a firewall, a stopped service or a network issue.", self.rst)
                },
                filter: Some("tcp.flags.rst".into()),
                count: self.rst,
            });
        }
        if self.unreachable >= 10 {
            out.push(Alert {
                level: AlertLevel::Info,
                title: lang.pick("Destinations injoignables", "Unreachable destinations").into(),
                detail: if fr {
                    format!("{} messages signalent une destination injoignable : appareil éteint, service fermé ou route manquante.", self.unreachable)
                } else {
                    format!("{} messages report an unreachable destination: device off, service closed or missing route.", self.unreachable)
                },
                filter: Some("problem && (icmp || icmpv6)".into()),
                count: self.unreachable,
            });
        }
        if self.malformed >= 5 {
            out.push(Alert {
                level: AlertLevel::Info,
                title: lang.pick("Paquets incomplets", "Incomplete packets").into(),
                detail: if fr {
                    format!("{} paquets sont mal formés ou tronqués (souvent sans gravité : paquets coupés à la capture).", self.malformed)
                } else {
                    format!("{} packets are malformed or truncated (usually harmless: packets cut during capture).", self.malformed)
                },
                filter: Some("problem".into()),
                count: self.malformed,
            });
        }
        out
    }
}
