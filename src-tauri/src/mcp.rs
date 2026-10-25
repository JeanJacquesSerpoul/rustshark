//! Serveur MCP (Model Context Protocol) : `rustshark --mcp`.
//!
//! Dialogue JSON-RPC 2.0 sur stdin/stdout (un message par ligne) pour que
//! Claude puisse capturer, analyser et représenter le trafic réseau. Le
//! serveur est autonome : il capture lui-même ou ouvre un fichier, avec le
//! même moteur que l'application. Stdout est réservé au protocole ; les
//! diagnostics vont sur stderr.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Mutex, RwLock};
use rustshark_shared::filter::{self, Expr, SYNTAX_HELP};
use rustshark_shared::{CaptureState, FlowNodeKind, Lang};
use serde_json::{json, Value};

use crate::ai::Anonymizer;
use crate::capture::{self, CaptureHandle};
use crate::config::Config;
use crate::store::Store;
use crate::{file_io, interfaces};

const IDENTIFIER: &str = "io.github.jeanjacquesserpoul.rustshark";
const PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
const MAX_BLOCKING_CAPTURE_S: u64 = 120;
const MAX_BACKGROUND_CAPTURE_S: u64 = 3600;

/// Dossier de configuration, identique à celui de l'application Tauri.
fn config_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    let base = std::env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(target_os = "macos")]
    let base = std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Application Support"));
    #[cfg(all(unix, not(target_os = "macos")))]
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
    base.map(|b| b.join(IDENTIFIER))
}

struct Server {
    store: Arc<RwLock<Store>>,
    capture: Arc<Mutex<Option<CaptureHandle>>>,
    generation: Arc<AtomicU64>,
    anon: Anonymizer,
    anonymize: bool,
    lang: Lang,
}

pub fn run(args: &[String]) {
    let anonymize = !args.iter().any(|a| a == "--no-anonymize");
    let lang = match config_dir() {
        Some(dir) => {
            crate::migrate_config_dir(&dir);
            Config::new(dir).load_settings().language
        }
        None => Lang::Fr,
    };
    let lang = match args.iter().position(|a| a == "--lang").and_then(|i| args.get(i + 1)).map(|s| s.as_str()) {
        Some("en") => Lang::En,
        Some("fr") => Lang::Fr,
        _ => lang,
    };
    let mut store = Store::default();
    store.max_packets = 500_000;
    let mut anon = Anonymizer::default();
    // Les adresses de cet ordinateur (y compris IPv6 publiques) sont toujours masquées.
    for ip in crate::pcap::devices().unwrap_or_default().into_iter().flat_map(|d| d.addrs) {
        anon.protect(ip);
    }
    let mut srv = Server {
        store: Arc::new(RwLock::new(store)),
        capture: Arc::new(Mutex::new(None)),
        generation: Arc::new(AtomicU64::new(0)),
        anon,
        anonymize,
        lang,
    };
    eprintln!("rustshark MCP server ready (anonymize={anonymize}, lang={lang:?})");

    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(Value::Array(batch)) => {
                let replies: Vec<Value> = batch.into_iter().filter_map(|m| srv.handle(m)).collect();
                (!replies.is_empty()).then(|| Value::Array(replies))
            }
            Ok(msg) => srv.handle(msg),
            Err(e) => Some(json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": format!("Parse error: {e}")}})),
        };
        if let Some(r) = reply {
            if writeln!(out, "{r}").and_then(|_| out.flush()).is_err() {
                break;
            }
        }
    }
    srv.stop_capture();
}

impl Server {
    fn handle(&mut self, msg: Value) -> Option<Value> {
        // Notifications (pas d'id) et réponses du client (pas de méthode) : rien à renvoyer.
        let id = msg.get("id").cloned()?;
        let method = msg.get("method").and_then(|m| m.as_str())?.to_string();
        let params = msg.get("params").cloned().unwrap_or(json!({}));
        let result = match method.as_str() {
            "initialize" => Ok(self.initialize(&params)),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": tools() })),
            "tools/call" => Ok(self.call_tool(&params)),
            "resources/list" => Ok(json!({ "resources": [] })),
            "prompts/list" => Ok(json!({ "prompts": [] })),
            other => Err(json!({"code": -32601, "message": format!("Method not found: {other}")})),
        };
        Some(match result {
            Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
            Err(e) => json!({"jsonrpc": "2.0", "id": id, "error": e}),
        })
    }

    fn initialize(&self, params: &Value) -> Value {
        let requested = params["protocolVersion"].as_str().unwrap_or("");
        let version = if PROTOCOL_VERSIONS.contains(&requested) { requested } else { PROTOCOL_VERSIONS[0] };
        let privacy = if self.anonymize {
            "Private IP and MAC addresses are replaced by stable aliases (LAN-1, MAC-1…); you can use these aliases in display filters."
        } else {
            "Addresses are shown unmasked."
        };
        json!({
            "protocolVersion": version,
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "rustshark", "title": "RustShark", "version": env!("CARGO_PKG_VERSION") },
            "instructions": format!(
                "RustShark captures and analyses network traffic on this computer. Typical workflow: \
                 list_interfaces, then capture (blocking, up to {MAX_BLOCKING_CAPTURE_S} s) or start_capture/stop_capture \
                 for longer captures, or open_capture for an existing pcap file; then get_flows to draw who talks to whom \
                 with data volumes, get_stats for an overview and alerts, list_packets/packet_detail to drill down. \
                 Only one capture is kept in memory: a new capture replaces the previous data. {privacy} \
                 Explain findings simply: the user may be a beginner."
            ),
        })
    }

    fn call_tool(&mut self, params: &Value) -> Value {
        let name = params["name"].as_str().unwrap_or("");
        let args = params.get("arguments").cloned().unwrap_or(json!({}));
        match self.run_tool(name, &args) {
            Ok(v) => {
                let text = serde_json::to_string_pretty(&v).unwrap_or_default();
                let text = if self.anonymize { self.anon.apply(&text) } else { text };
                json!({ "content": [{ "type": "text", "text": text }], "isError": false })
            }
            Err(e) => json!({ "content": [{ "type": "text", "text": e }], "isError": true }),
        }
    }

    fn run_tool(&mut self, name: &str, args: &Value) -> Result<Value, String> {
        match name {
            "list_interfaces" => {
                let list = interfaces::list().map_err(|e| crate::permission_hint(-1, &e, self.lang))?;
                Ok(json!({
                    "interfaces": list,
                    "hint": "Prefer the interface marked recommended (usually Wi-Fi or Ethernet with an IPv4 address).",
                }))
            }
            "capture" => {
                let secs = args["duration_s"].as_u64().unwrap_or(30).clamp(1, MAX_BLOCKING_CAPTURE_S);
                self.start(args, None)?;
                std::thread::sleep(Duration::from_secs(secs));
                self.stop_capture();
                Ok(self.summary())
            }
            "start_capture" => {
                let secs = args["duration_s"].as_u64().unwrap_or(300).clamp(1, MAX_BACKGROUND_CAPTURE_S);
                let label = self.start(args, Some(secs))?;
                Ok(json!({
                    "started": true,
                    "interface": label,
                    "auto_stop_after_s": secs,
                    "hint": "Call stop_capture when done (or wait for the automatic stop), then get_flows / get_stats.",
                }))
            }
            "stop_capture" => {
                self.stop_capture();
                Ok(self.summary())
            }
            "capture_status" => Ok(self.summary()),
            "open_capture" => {
                let path = args["path"].as_str().ok_or("Missing argument: path")?;
                self.stop_capture();
                let packets = file_io::read(Path::new(path))?;
                let name = Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                let mut s = self.store.write();
                s.begin(CaptureState::File, name, None);
                s.state = CaptureState::File;
                s.names.local.clear();
                s.push_batch(packets);
                drop(s);
                Ok(self.summary())
            }
            "get_flows" => {
                let (expr, text) = self.parse_filter(args)?;
                let max_nodes = args["max_nodes"].as_u64().unwrap_or(30).clamp(3, 300) as usize;
                let max_edges = args["max_edges"].as_u64().unwrap_or(80).clamp(5, 1000) as usize;
                let s = self.store.read();
                let idx = s.matching(&expr);
                Ok(flows(&s, &idx, &text, max_nodes, max_edges, self.lang))
            }
            "get_stats" => {
                let (expr, text) = self.parse_filter(args)?;
                let s = self.store.read();
                let idx = s.matching(&expr);
                Ok(json!({
                    "status": s.status(),
                    "display_filter": text,
                    "stats": s.stats_for(&idx, self.lang),
                }))
            }
            "list_packets" => {
                let (expr, text) = self.parse_filter(args)?;
                let offset = args["offset"].as_u64().unwrap_or(0) as usize;
                let limit = args["limit"].as_u64().unwrap_or(50).clamp(1, 500) as usize;
                let s = self.store.read();
                let idx = s.matching(&expr);
                let rows: Vec<_> = idx.iter().skip(offset).take(limit).map(|i| s.row(*i as usize, self.lang)).collect();
                Ok(json!({
                    "display_filter": text,
                    "matched": idx.len(),
                    "total": s.packets.len(),
                    "offset": offset,
                    "packets": rows,
                }))
            }
            "packet_detail" => {
                let no = args["no"].as_u64().ok_or("Missing argument: no (packet number)")? as u32;
                let s = self.store.read();
                let d = s.detail(no, self.lang).ok_or_else(|| format!("Packet {no} not found"))?;
                let hex: Vec<String> = d.bytes.iter().take(512).map(|b| format!("{b:02x}")).collect();
                let mut v = serde_json::to_value(&d).map_err(|e| e.to_string())?;
                if let Some(o) = v.as_object_mut() {
                    o.remove("bytes");
                    o.insert("hex".into(), json!(hex.join(" ")));
                }
                Ok(v)
            }
            other => Err(format!("Unknown tool: {other}")),
        }
    }

    fn parse_filter(&self, args: &Value) -> Result<(Expr, String), String> {
        let text = args["display_filter"].as_str().unwrap_or("").trim().to_string();
        let real = if self.anonymize { self.anon.reveal(&text) } else { text.clone() };
        let expr = filter::parse(&real).map_err(|e| format!("Invalid display filter: {}. {SYNTAX_HELP}", e.message(Lang::En)))?;
        Ok((expr, text))
    }

    /// Démarre une capture ; `auto_stop` en secondes pour une capture en arrière-plan.
    fn start(&mut self, args: &Value, auto_stop: Option<u64>) -> Result<String, String> {
        self.stop_capture();
        let list = interfaces::list().map_err(|e| crate::permission_hint(-1, &e, self.lang))?;
        let iface = match args["interface"].as_str().filter(|s| !s.trim().is_empty()) {
            Some(w) => list
                .iter()
                .find(|i| i.name == w || i.friendly.eq_ignore_ascii_case(w) || i.description.eq_ignore_ascii_case(w))
                .ok_or_else(|| format!("Unknown interface '{w}'. Call list_interfaces to see the available names."))?,
            None => list
                .iter()
                .find(|i| i.recommended)
                .or_else(|| list.iter().find(|i| i.connected && !i.loopback))
                .ok_or("No usable network interface found.")?,
        };
        let bpf = args["capture_filter"].as_str().map(str::trim).filter(|s| !s.is_empty());
        let bpf = bpf.map(|f| if self.anonymize { self.anon.reveal(f) } else { f.to_string() });
        {
            let mut s = self.store.write();
            s.begin(CaptureState::Running, iface.friendly.clone(), bpf.clone());
            s.names.local = interfaces::addresses_of(&iface.name).into_iter().collect();
            for ip in &s.names.local {
                self.anon.protect(*ip);
            }
        }
        let handle = capture::start(self.store.clone(), &iface.name, bpf.as_deref(), false).map_err(|e| {
            let mut s = self.store.write();
            s.state = CaptureState::Idle;
            if e.code == -1000 {
                format!("Invalid capture filter (BPF syntax): {}", e.message)
            } else {
                crate::permission_hint(e.code, &e.message, self.lang)
            }
        })?;
        let gen = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        *self.capture.lock() = Some(handle);
        if let Some(secs) = auto_stop {
            let (cap, current) = (self.capture.clone(), self.generation.clone());
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(secs));
                if current.load(Ordering::SeqCst) == gen {
                    if let Some(h) = cap.lock().take() {
                        h.stop();
                    }
                }
            });
        }
        Ok(iface.friendly.clone())
    }

    fn stop_capture(&mut self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        let handle = self.capture.lock().take();
        if let Some(h) = handle {
            h.stop();
        }
    }

    fn summary(&self) -> Value {
        let s = self.store.read();
        let st = s.status();
        let stats = s.stats(false, self.lang);
        json!({
            "status": st,
            "packets": stats.packets,
            "bytes": stats.bytes,
            "duration_s": stats.duration,
            "top_protocols": stats.protocols.iter().take(8).collect::<Vec<_>>(),
            "alerts": stats.alerts.iter().map(|a| json!({"level": a.level, "title": a.title})).collect::<Vec<_>>(),
            "next": "Use get_flows for a who-talks-to-whom graph, get_stats for details, list_packets to drill down.",
        })
    }
}

// ---------------------------------------------------------------------------
// Graphe des flux
// ---------------------------------------------------------------------------

fn flows(store: &Store, idx: &[u32], filter_text: &str, max_nodes: usize, max_edges: usize, lang: Lang) -> Value {
    let g = crate::flows::graph(store, idx, max_nodes, max_edges, lang);
    let nodes: Vec<Value> = g
        .nodes
        .iter()
        .map(|n| {
            let address = match (n.kind, n.addresses.len()) {
                (FlowNodeKind::ThisComputer, _) => json!(n.addresses),
                (_, 1) => json!(n.addresses[0]),
                _ => Value::Null,
            };
            let mut v = json!({ "id": n.id, "label": n.label, "kind": n.kind, "address": address, "bytes": n.bytes, "packets": n.packets });
            if n.members > 1 {
                v["members"] = json!(n.members);
            }
            v
        })
        .collect();
    let edges: Vec<Value> = g
        .edges
        .iter()
        .map(|e| {
            json!({
                "source": e.source,
                "target": e.target,
                "bytes": e.bytes,
                "packets": e.packets,
                "bytes_source_to_target": e.bytes_source_to_target,
                "bytes_target_to_source": e.bytes_target_to_source,
                "encrypted_percent": e.encrypted_percent,
                "cleartext_bytes": e.cleartext_bytes,
                "services": e.services,
                "first_s": e.first_s,
                "last_s": e.last_s,
            })
        })
        .collect();
    json!({
        "scope": {
            "display_filter": filter_text,
            "packets": g.packets,
            "bytes": g.bytes,
            "duration_s": g.duration_s,
            "non_ip_packets_ignored": g.non_ip_packets_ignored,
            "omitted_edges": g.omitted_edges,
            "omitted_bytes": g.omitted_bytes,
        },
        "nodes": nodes,
        "edges": edges,
        "drawing_hints": "Node size ∝ bytes; edge width ∝ bytes. Colour nodes by kind (this_computer, local, internet, group). Highlight edges with cleartext_bytes > 0 (unencrypted). 'others-*' nodes aggregate the smaller hosts. To drill down, use display filters such as `this_computer`, `ip.addr == <node address or LAN-n alias>`.",
    })
}

// ---------------------------------------------------------------------------
// Description des outils
// ---------------------------------------------------------------------------

fn tools() -> Value {
    let filter_prop = json!({
        "type": "string",
        "description": format!("Optional RustShark display filter selecting packets (empty = all). {SYNTAX_HELP}")
    });
    let ro = json!({ "readOnlyHint": true, "openWorldHint": false });
    json!([
        {
            "name": "list_interfaces",
            "title": "List network interfaces",
            "description": "List the network interfaces that can be captured, with friendly names, type, addresses and the recommended one.",
            "inputSchema": { "type": "object", "properties": {} },
            "annotations": ro,
        },
        {
            "name": "capture",
            "title": "Capture traffic",
            "description": format!("Capture live traffic for a few seconds and wait for the result (max {MAX_BLOCKING_CAPTURE_S} s). Replaces any previous capture. Returns a summary."),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "interface": { "type": "string", "description": "Interface name or friendly name from list_interfaces. Default: the recommended interface." },
                    "duration_s": { "type": "integer", "minimum": 1, "maximum": MAX_BLOCKING_CAPTURE_S, "default": 30 },
                    "capture_filter": { "type": "string", "description": "Optional libpcap BPF capture filter, e.g. 'port 53' or 'host 192.168.1.10'." }
                }
            },
            "annotations": { "readOnlyHint": true, "openWorldHint": false },
        },
        {
            "name": "start_capture",
            "title": "Start a background capture",
            "description": format!("Start capturing in the background (auto-stop after duration_s, max {MAX_BACKGROUND_CAPTURE_S} s). Replaces any previous capture. Use stop_capture or capture_status afterwards."),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "interface": { "type": "string" },
                    "duration_s": { "type": "integer", "minimum": 1, "maximum": MAX_BACKGROUND_CAPTURE_S, "default": 300 },
                    "capture_filter": { "type": "string" }
                }
            },
        },
        {
            "name": "stop_capture",
            "title": "Stop the capture",
            "description": "Stop the running capture and return a summary.",
            "inputSchema": { "type": "object", "properties": {} },
        },
        {
            "name": "capture_status",
            "title": "Capture status",
            "description": "State of the current capture (running or not, packets, bytes, duration) with a short summary.",
            "inputSchema": { "type": "object", "properties": {} },
            "annotations": ro,
        },
        {
            "name": "open_capture",
            "title": "Open a capture file",
            "description": "Load a .pcap or .pcapng file from disk (replaces the current data).",
            "inputSchema": {
                "type": "object",
                "properties": { "path": { "type": "string", "description": "Absolute path of the .pcap / .pcapng file." } },
                "required": ["path"]
            },
            "annotations": ro,
        },
        {
            "name": "get_flows",
            "title": "Network flow graph",
            "description": "Who talks to whom: a graph of devices (nodes with name, kind and data volume) and the flows between them (edges with bytes in each direction, packets, services, encrypted share). Ideal to draw a network map highlighting data volumes.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "display_filter": filter_prop,
                    "max_nodes": { "type": "integer", "minimum": 3, "maximum": 300, "default": 30, "description": "Smaller hosts are merged into 'others-*' nodes." },
                    "max_edges": { "type": "integer", "minimum": 5, "maximum": 1000, "default": 80 }
                }
            },
            "annotations": ro,
        },
        {
            "name": "get_stats",
            "title": "Traffic statistics",
            "description": "Overview: protocols, traffic families, top hosts, conversations, DNS names, sites contacted, activity timeline and automatic security alerts.",
            "inputSchema": { "type": "object", "properties": { "display_filter": filter_prop } },
            "annotations": ro,
        },
        {
            "name": "list_packets",
            "title": "List packets",
            "description": "List captured packets matching a display filter, each with a technical info line and a plain-language summary.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "display_filter": filter_prop,
                    "offset": { "type": "integer", "minimum": 0, "default": 0 },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 500, "default": 50 }
                }
            },
            "annotations": ro,
        },
        {
            "name": "packet_detail",
            "title": "Packet detail",
            "description": "Full decoding of one packet: layers and fields, plain-language explanation, tips and the first bytes in hex.",
            "inputSchema": {
                "type": "object",
                "properties": { "no": { "type": "integer", "minimum": 1, "description": "Packet number (from list_packets)." } },
                "required": ["no"]
            },
            "annotations": ro,
        }
    ])
}
