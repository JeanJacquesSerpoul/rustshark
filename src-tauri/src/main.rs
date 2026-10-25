// Pas de console supplémentaire sous Windows en mode release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod ai;
mod apps;
mod capture;
mod config;
mod discover;
mod dissect;
mod explain;
mod file_io;
mod flows;
mod interfaces;
mod internet;
mod keystore;
mod mcp;
mod netinfo;
mod oui;
mod pcap;
mod security;
mod store;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Mutex, RwLock};
use rustshark_shared::{
    filter, AiChatRequest, AiChunk, AnalysisProfile, AppSettings, CaptureState, ChatMessage, DeviceList, FlowGraph, GeneratedProfile,
    InterfaceInfo, InternetInfo, KeyStatus, Lang, ModelInfo, NetProgress, NetworkInfo, PacketDetail, PortInfo, Provider,
    SecurityReport, SpeedResult, StartCaptureRequest, Stats, SystemInfo, ViewResponse,
};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;

use crate::capture::CaptureHandle;
use crate::config::Config;
use crate::store::Store;

struct AppState {
    store: Arc<RwLock<Store>>,
    capture: Mutex<Option<CaptureHandle>>,
    settings: RwLock<AppSettings>,
    display_filter: RwLock<String>,
    config: Config,
    http: reqwest::Client,
    ai_cancel: Mutex<HashMap<String, Arc<AtomicBool>>>,
    /// Résultats des analyses du réseau, par interface.
    net: Mutex<HashMap<String, discover::Cache>>,
    net_busy: AtomicBool,
    speed_cancel: Arc<AtomicBool>,
}

impl AppState {
    fn new(dir: PathBuf) -> Self {
        let config = Config::new(dir);
        let settings = config.load_settings();
        let mut store = Store::default();
        store.max_packets = settings.max_packets.max(1000) as usize;
        Self {
            store: Arc::new(RwLock::new(store)),
            capture: Mutex::new(None),
            settings: RwLock::new(settings),
            display_filter: RwLock::new(String::new()),
            config,
            http: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(15))
                .timeout(Duration::from_secs(600))
                .user_agent(concat!("RustShark/", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("client HTTP"),
            ai_cancel: Mutex::new(HashMap::new()),
            net: Mutex::new(HashMap::new()),
            net_busy: AtomicBool::new(false),
            speed_cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    fn lang(&self) -> Lang {
        self.settings.read().language
    }

    fn stop_capture(&self) {
        if let Some(h) = self.capture.lock().take() {
            h.stop();
        }
    }
}

type Res<T> = Result<T, String>;

// ---------------------------------------------------------------------------
// Système et interfaces
// ---------------------------------------------------------------------------

#[tauri::command(rename_all = "snake_case")]
async fn system_info() -> Res<SystemInfo> {
    let (pcap_ok, pcap_version, pcap_error) = match pcap::available() {
        Ok(v) => (true, Some(v), None),
        Err(e) => (false, None, Some(e)),
    };
    Ok(SystemInfo {
        pcap_ok,
        pcap_version,
        pcap_error,
        os: std::env::consts::OS.into(),
        app_version: env!("CARGO_PKG_VERSION").into(),
        keystore_name: keystore::store_name().into(),
    })
}

#[tauri::command(rename_all = "snake_case")]
async fn list_interfaces(state: State<'_, AppState>) -> Res<Vec<InterfaceInfo>> {
    interfaces::list().map_err(|e| permission_hint(-1, &e, state.lang()))
}

#[tauri::command(rename_all = "snake_case")]
async fn probe_interfaces(names: Vec<String>) -> Res<HashMap<String, u32>> {
    tauri::async_runtime::spawn_blocking(move || capture::probe(names, Duration::from_millis(1500)))
        .await
        .map_err(|e| e.to_string())
}

fn permission_hint(code: i32, msg: &str, lang: Lang) -> String {
    let lower = msg.to_lowercase();
    let perm = code == pcap::ERR_PERM_DENIED
        || code == pcap::ERR_PROMISC_PERM_DENIED
        || lower.contains("permission")
        || lower.contains("access is denied")
        || lower.contains("operation not permitted")
        || (cfg!(windows) && lower.contains("error opening adapter"));
    if !perm {
        return msg.to_string();
    }
    let hint = if cfg!(windows) {
        lang.pick(
            "Accès refusé. Npcap a sans doute été installé en mode « administrateurs uniquement » : relancez RustShark en tant qu'administrateur, ou réinstallez Npcap en décochant cette option.",
            "Access denied. Npcap was probably installed in 'administrators only' mode: restart RustShark as administrator, or reinstall Npcap without that option.",
        )
    } else if cfg!(target_os = "macos") {
        lang.pick(
            "Permission refusée sur /dev/bpf*. Installez l'utilitaire « ChmodBPF » (fourni avec Wireshark) ou lancez RustShark avec sudo.",
            "Permission denied on /dev/bpf*. Install the 'ChmodBPF' helper (shipped with Wireshark) or run RustShark with sudo.",
        )
    } else {
        lang.pick(
            "Permission refusée. Autorisez la capture une fois pour toutes avec : sudo setcap cap_net_raw,cap_net_admin=eip /chemin/vers/rustshark",
            "Permission denied. Allow capture once and for all with: sudo setcap cap_net_raw,cap_net_admin=eip /path/to/rustshark",
        )
    };
    format!("{hint}\n({msg})")
}

// ---------------------------------------------------------------------------
// Capture
// ---------------------------------------------------------------------------

#[tauri::command(rename_all = "snake_case")]
async fn start_capture(state: State<'_, AppState>, req: StartCaptureRequest) -> Res<()> {
    let lang = state.lang();
    state.stop_capture();
    let label = interfaces::list()
        .ok()
        .and_then(|l| l.into_iter().find(|i| i.name == req.interface).map(|i| i.friendly))
        .unwrap_or_else(|| req.interface.clone());
    let filter_txt = req.capture_filter.clone().filter(|f| !f.trim().is_empty());
    {
        let mut s = state.store.write();
        s.begin(CaptureState::Running, label, filter_txt.clone());
        s.names.local = interfaces::addresses_of(&req.interface).into_iter().collect();
    }
    match capture::start(state.store.clone(), &req.interface, filter_txt.as_deref(), req.promiscuous) {
        Ok(h) => {
            *state.capture.lock() = Some(h);
            Ok(())
        }
        Err(e) => {
            let msg = if e.code == -1000 {
                format!("{} {}", lang.pick("Filtre de capture invalide :", "Invalid capture filter:"), e.message)
            } else {
                permission_hint(e.code, &e.message, lang)
            };
            let mut s = state.store.write();
            s.state = CaptureState::Idle;
            s.error = Some(msg.clone());
            Err(msg)
        }
    }
}

#[tauri::command(rename_all = "snake_case")]
async fn stop_capture(state: State<'_, AppState>) -> Res<()> {
    state.stop_capture();
    Ok(())
}

#[tauri::command(rename_all = "snake_case")]
async fn clear_capture(state: State<'_, AppState>) -> Res<()> {
    state.store.write().clear();
    Ok(())
}

#[tauri::command(rename_all = "snake_case")]
async fn validate_capture_filter(filter: String) -> Res<()> {
    pcap::validate_bpf(&filter)
}

#[tauri::command(rename_all = "snake_case")]
async fn set_display_filter(state: State<'_, AppState>, filter: String) -> Res<u32> {
    let lang = state.lang();
    let n = state.store.write().set_filter(&filter).map_err(|e| e.message(lang).to_string())?;
    *state.display_filter.write() = filter;
    Ok(n)
}

#[tauri::command(rename_all = "snake_case")]
async fn get_view(state: State<'_, AppState>, offset: u32, limit: u32, tail: bool) -> Res<ViewResponse> {
    let lang = state.lang();
    let finished = state.capture.lock().as_ref().map(|h| h.is_finished()).unwrap_or(false);
    if finished {
        state.stop_capture();
    }
    let store = state.store.read();
    // `tail` : afficher les derniers paquets (suivi du direct).
    let offset = if tail { (store.matched() as u32).saturating_sub(limit) } else { offset };
    Ok(store.view(offset, limit, lang))
}

#[tauri::command(rename_all = "snake_case")]
async fn packet_position(state: State<'_, AppState>, no: u32) -> Res<Option<u32>> {
    Ok(state.store.read().position_of(no))
}

#[tauri::command(rename_all = "snake_case")]
async fn get_packet_detail(state: State<'_, AppState>, no: u32) -> Res<Option<PacketDetail>> {
    let lang = state.lang();
    Ok(state.store.read().detail(no, lang))
}

#[tauri::command(rename_all = "snake_case")]
async fn get_stats(state: State<'_, AppState>, filtered: bool) -> Res<Stats> {
    let lang = state.lang();
    Ok(state.store.read().stats(filtered, lang))
}

#[tauri::command(rename_all = "snake_case")]
async fn get_flows(state: State<'_, AppState>, filtered: bool, max_nodes: u32) -> Res<FlowGraph> {
    let lang = state.lang();
    let store = state.store.read();
    let idx = store.scope_indices(filtered);
    Ok(flows::graph(&store, &idx, max_nodes.clamp(3, 200) as usize, 400, lang))
}

fn load_file(state: &AppState, path: &Path) -> Res<String> {
    let lang = state.lang();
    state.stop_capture();
    let packets = file_io::read(path).map_err(|e| format!("{} {e}", lang.pick("Impossible de lire le fichier :", "Cannot read file:")))?;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let filter = state.display_filter.read().clone();
    let mut s = state.store.write();
    s.begin(CaptureState::File, name.clone(), None);
    s.state = CaptureState::File;
    s.names.local.clear();
    s.push_batch(packets);
    let _ = s.set_filter(&filter);
    Ok(name)
}

#[tauri::command(rename_all = "snake_case")]
async fn open_capture(app: AppHandle, state: State<'_, AppState>) -> Res<Option<String>> {
    let lang = state.lang();
    let picked = app
        .dialog()
        .file()
        .set_title(lang.pick("Ouvrir une capture", "Open a capture"))
        .add_filter(lang.pick("Captures réseau", "Network captures"), &["pcap", "pcapng", "cap"])
        .blocking_pick_file();
    let Some(file) = picked else { return Ok(None) };
    let path = file.into_path().map_err(|e| e.to_string())?;
    load_file(&state, &path).map(Some)
}

#[tauri::command(rename_all = "snake_case")]
async fn open_capture_path(state: State<'_, AppState>, path: String) -> Res<String> {
    load_file(&state, Path::new(&path))
}

#[tauri::command(rename_all = "snake_case")]
async fn save_capture(app: AppHandle, state: State<'_, AppState>, filtered: bool) -> Res<Option<String>> {
    let lang = state.lang();
    let default_name = format!("capture-{}.pcapng", chrono::Local::now().format("%Y%m%d-%H%M%S"));
    let picked = app
        .dialog()
        .file()
        .set_title(lang.pick("Enregistrer la capture", "Save the capture"))
        .set_file_name(&default_name)
        .add_filter("pcapng", &["pcapng"])
        .add_filter("pcap", &["pcap"])
        .blocking_save_file();
    let Some(file) = picked else { return Ok(None) };
    let path = file.into_path().map_err(|e| e.to_string())?;
    let s = state.store.read();
    let idx = s.scope_indices(filtered);
    let n = file_io::write(&path, idx.iter().map(|i| &s.packets[*i as usize]))?;
    Ok(Some(format!("{} ({n})", path.display())))
}

// ---------------------------------------------------------------------------
// Réglages, profils, clés
// ---------------------------------------------------------------------------

#[tauri::command(rename_all = "snake_case")]
async fn get_settings(state: State<'_, AppState>) -> Res<AppSettings> {
    Ok(state.settings.read().clone())
}

#[tauri::command(rename_all = "snake_case")]
async fn save_settings(state: State<'_, AppState>, settings: AppSettings) -> Res<()> {
    state.config.save_settings(&settings)?;
    state.store.write().max_packets = settings.max_packets.max(1000) as usize;
    *state.settings.write() = settings;
    Ok(())
}

#[tauri::command(rename_all = "snake_case")]
async fn key_status() -> Res<KeyStatus> {
    tauri::async_runtime::spawn_blocking(keystore::status).await.map_err(|e| e.to_string())
}

#[tauri::command(rename_all = "snake_case")]
async fn set_api_key(provider: Provider, key: String) -> Res<()> {
    tauri::async_runtime::spawn_blocking(move || keystore::set(provider, &key)).await.map_err(|e| e.to_string())?
}

#[tauri::command(rename_all = "snake_case")]
async fn delete_api_key(provider: Provider) -> Res<()> {
    tauri::async_runtime::spawn_blocking(move || keystore::delete(provider)).await.map_err(|e| e.to_string())?
}

#[tauri::command(rename_all = "snake_case")]
async fn delete_all_api_keys() -> Res<u32> {
    tauri::async_runtime::spawn_blocking(keystore::delete_all).await.map_err(|e| e.to_string())?
}

fn require_key(provider: Provider, lang: Lang) -> Res<String> {
    keystore::get(provider)?.ok_or_else(|| {
        format!(
            "{} {}",
            lang.pick("Aucune clé API enregistrée pour", "No API key saved for"),
            provider.label()
        )
    })
}

#[tauri::command(rename_all = "snake_case")]
async fn list_profiles(state: State<'_, AppState>) -> Res<Vec<AnalysisProfile>> {
    Ok(state.config.load_profiles())
}

#[tauri::command(rename_all = "snake_case")]
async fn save_profile(state: State<'_, AppState>, profile: AnalysisProfile) -> Res<Vec<AnalysisProfile>> {
    let mut all = state.config.load_profiles();
    match all.iter_mut().find(|p| p.id == profile.id) {
        Some(p) => *p = profile,
        None => all.insert(0, profile),
    }
    state.config.save_profiles(&all)?;
    Ok(all)
}

#[tauri::command(rename_all = "snake_case")]
async fn delete_profile(state: State<'_, AppState>, id: String) -> Res<Vec<AnalysisProfile>> {
    let mut all = state.config.load_profiles();
    all.retain(|p| p.id != id);
    state.config.save_profiles(&all)?;
    Ok(all)
}

#[tauri::command(rename_all = "snake_case")]
async fn open_url(app: AppHandle, url: String) -> Res<()> {
    use tauri_plugin_opener::OpenerExt;
    if !url.starts_with("https://") {
        return Err("only https links".into());
    }
    app.opener().open_url(url, None::<&str>).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// IA
// ---------------------------------------------------------------------------

#[tauri::command(rename_all = "snake_case")]
async fn ai_test(state: State<'_, AppState>, provider: Provider) -> Res<String> {
    let lang = state.lang();
    let key = require_key(provider, lang)?;
    let (url, label) = match provider {
        Provider::DeepSeek => ("https://api.deepseek.com/user/balance", "DeepSeek"),
        Provider::OpenRouter => ("https://openrouter.ai/api/v1/key", "OpenRouter"),
    };
    let resp = state.http.get(url).bearer_auth(&key).send().await.map_err(|e| e.to_string())?;
    let status = resp.status();
    let v: serde_json::Value = resp.json().await.unwrap_or_default();
    if !status.is_success() {
        return Err(match status.as_u16() {
            401 | 403 => lang.pick("Clé refusée par le fournisseur.", "Key rejected by the provider.").into(),
            s => format!("HTTP {s}"),
        });
    }
    let detail = match provider {
        Provider::DeepSeek => v["balance_infos"][0]["total_balance"]
            .as_str()
            .map(|b| format!(" — {} {b} {}", lang.pick("solde :", "balance:"), v["balance_infos"][0]["currency"].as_str().unwrap_or(""))),
        Provider::OpenRouter => {
            let usage = v["data"]["usage"].as_f64().unwrap_or(0.0);
            Some(match v["data"]["limit"].as_f64() {
                Some(limit) => format!(" — {} {usage:.2} / {limit:.2} $", lang.pick("utilisé :", "used:")),
                None => format!(" — {} {usage:.2} $", lang.pick("utilisé :", "used:")),
            })
        }
    };
    Ok(format!("{} {label}{}", lang.pick("✅ Clé valide pour", "✅ Valid key for"), detail.unwrap_or_default()))
}

#[tauri::command(rename_all = "snake_case")]
async fn ai_models(state: State<'_, AppState>, provider: Provider) -> Res<Vec<ModelInfo>> {
    let lang = state.lang();
    let key = keystore::get(provider).ok().flatten();
    if provider == Provider::DeepSeek && key.is_none() {
        return Err(require_key(provider, lang).unwrap_err());
    }
    ai::list_models(&state.http, provider, key.as_deref(), lang).await
}

#[tauri::command(rename_all = "snake_case")]
async fn ai_chat(app: AppHandle, state: State<'_, AppState>, req: AiChatRequest) -> Res<()> {
    let settings = state.settings.read().clone();
    let lang = settings.language;
    let provider = settings.ai.provider;
    let model = settings.ai.model().to_string();
    let key = require_key(provider, lang)?;
    let display_filter = state.display_filter.read().clone();
    let context = {
        let store = state.store.read();
        ai::build_context(
            &store,
            &ai::ContextRequest {
                scope: req.scope,
                selected: req.selected,
                display_filter: &display_filter,
                sample: settings.ai.sample_packets as usize,
                anonymize: settings.ai.anonymize,
                lang,
                profile: req.profile.as_ref(),
            },
        )
    };
    let mut messages = vec![
        ChatMessage { role: "system".into(), content: ai::system_prompt(lang) },
        ChatMessage { role: "system".into(), content: format!("Current capture data:\n{context}") },
    ];
    if let Some(p) = &req.profile {
        if let Some(extra) = &p.ai_prompt {
            messages.push(ChatMessage { role: "system".into(), content: format!("Profile focus: {extra}") });
        }
    }
    messages.extend(req.messages.into_iter().filter(|m| m.role == "user" || m.role == "assistant"));

    let cancel = Arc::new(AtomicBool::new(false));
    state.ai_cancel.lock().insert(req.request_id.clone(), cancel.clone());
    let client = state.http.clone();
    let id = req.request_id;
    tauri::async_runtime::spawn(async move {
        let res = ai::stream_chat(&client, provider, &model, &key, &messages, cancel, lang, |delta, reasoning| {
            let _ = app.emit("ai-chunk", AiChunk { request_id: id.clone(), delta: delta.into(), reasoning, done: false, error: None });
        })
        .await;
        let _ = app.emit("ai-chunk", AiChunk { request_id: id.clone(), done: true, error: res.err(), ..Default::default() });
        app.state::<AppState>().ai_cancel.lock().remove(&id);
    });
    Ok(())
}

#[tauri::command(rename_all = "snake_case")]
async fn ai_cancel(state: State<'_, AppState>, request_id: String) -> Res<()> {
    if let Some(c) = state.ai_cancel.lock().remove(&request_id) {
        c.store(true, Ordering::SeqCst);
    }
    Ok(())
}

#[tauri::command(rename_all = "snake_case")]
async fn ai_generate_profile(state: State<'_, AppState>, goal: String, interface: Option<String>) -> Res<GeneratedProfile> {
    let settings = state.settings.read().clone();
    let lang = settings.language;
    let provider = settings.ai.provider;
    let key = require_key(provider, lang)?;
    let mut user = format!("User goal: {goal}\n");
    if let Some(iface) = interface {
        let addrs = interfaces::addresses_of(&iface);
        if !addrs.is_empty() {
            let list: Vec<String> = addrs.iter().map(|a| a.to_string()).collect();
            user.push_str(&format!("This computer's addresses on the selected interface: {}\n", list.join(", ")));
        }
    }
    let messages = vec![
        ChatMessage { role: "system".into(), content: ai::profile_prompt(lang) },
        ChatMessage { role: "user".into(), content: user },
    ];
    let text = ai::complete(&state.http, provider, settings.ai.model(), &key, &messages, true, lang).await?;
    let profile = ai::parse_profile(&text, &goal)?;
    let display_filter_error = profile
        .display_filter
        .as_deref()
        .and_then(|f| filter::parse(f).err())
        .map(|e| e.message(lang).to_string());
    let capture_filter_error = profile.capture_filter.as_deref().and_then(|f| pcap::validate_bpf(f).err());
    Ok(GeneratedProfile { profile, display_filter_error, capture_filter_error })
}

// ---------------------------------------------------------------------------
// Mon réseau
// ---------------------------------------------------------------------------

/// Remet l'indicateur « analyse en cours » à zéro, même en cas d'erreur.
struct Busy<'a>(&'a AtomicBool);

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

fn net_progress<'a>(app: &'a AppHandle, task: &'static str) -> impl Fn(&str, u32, u32) + Sync + 'a {
    move |phase, done, total| {
        let _ = app.emit("net-progress", NetProgress { task: task.into(), phase: phase.into(), done, total, value: None });
    }
}

fn device_list(state: &AppState, interface: &str, info: &NetworkInfo, lang: Lang) -> DeviceList {
    let cache = state.net.lock().get(interface).cloned();
    let store = state.store.read();
    discover::devices(interface, info, cache.as_ref(), &store, lang)
}

#[tauri::command(rename_all = "snake_case")]
async fn net_info(state: State<'_, AppState>, interface: String) -> Res<NetworkInfo> {
    let lang = state.lang();
    tauri::async_runtime::spawn_blocking(move || netinfo::info(&interface, lang)).await.map_err(|e| e.to_string())
}

#[tauri::command(rename_all = "snake_case")]
async fn net_devices(app: AppHandle, interface: String) -> Res<DeviceList> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let lang = state.lang();
        let info = netinfo::info(&interface, lang);
        device_list(&state, &interface, &info, lang)
    })
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command(rename_all = "snake_case")]
async fn net_scan(app: AppHandle, interface: String) -> Res<DeviceList> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let lang = state.lang();
        if state.net_busy.swap(true, Ordering::SeqCst) {
            return Err(lang.pick("Une analyse du réseau est déjà en cours.", "A network scan is already running.").to_string());
        }
        let _busy = Busy(&state.net_busy);
        let info = netinfo::info(&interface, lang);
        let mut fresh = discover::scan(&interface, &info, lang, &net_progress(&app, "scan"))?;
        {
            let mut net = state.net.lock();
            if let Some(old) = net.remove(&interface) {
                fresh.ports = old.ports;
            }
            net.insert(interface.clone(), fresh);
        }
        Ok(device_list(&state, &interface, &info, lang))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command(rename_all = "snake_case")]
async fn net_ports(app: AppHandle, interface: String, ip: String) -> Res<Vec<PortInfo>> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let lang = state.lang();
        let addr: std::net::IpAddr = ip.parse().map_err(|_| format!("{} {ip}", lang.pick("Adresse invalide :", "Invalid address:")))?;
        let ports = discover::ports(addr, lang, &net_progress(&app, "ports"))?;
        state.net.lock().entry(interface).or_default().ports.insert(addr, ports.clone());
        Ok(ports)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command(rename_all = "snake_case")]
async fn net_security(app: AppHandle, interface: String, deep: bool) -> Res<SecurityReport> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let lang = state.lang();
        let info = netinfo::info(&interface, lang);
        let gateway = info.gateway.as_deref().and_then(|g| g.parse::<std::net::Ipv4Addr>().ok());
        if let (true, Some(gw)) = (deep, gateway) {
            let progress = net_progress(&app, "security");
            let ports = discover::ports(gw.into(), lang, &progress)?;
            progress("upnp", 0, 1);
            let igd = netinfo::subnet_of(&interface).map(|s| discover::gateway_upnp(s.ip, gw));
            let mut net = state.net.lock();
            let c = net.entry(interface.clone()).or_default();
            c.ports.insert(gw.into(), ports);
            c.igd = igd.or(c.igd);
        }
        let devices = device_list(&state, &interface, &info, lang);
        let (gateway_ports, igd) = {
            let net = state.net.lock();
            let c = net.get(&interface);
            (gateway.and_then(|g| c.and_then(|c| c.ports.get(&g.into()).cloned())), c.and_then(|c| c.igd))
        };
        let capture_alerts = {
            let s = state.store.read();
            if s.packets.is_empty() {
                Vec::new()
            } else {
                s.stats(false, lang).alerts
            }
        };
        let neighbors = netinfo::neighbors(&interface);
        Ok(security::report(
            security::Inputs { info: &info, devices: &devices, neighbors: &neighbors, gateway_ports: gateway_ports.as_deref(), igd, capture_alerts },
            lang,
        ))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command(rename_all = "snake_case")]
async fn net_internet(state: State<'_, AppState>, interface: String) -> Res<InternetInfo> {
    let lang = state.lang();
    let info = tauri::async_runtime::spawn_blocking(move || netinfo::info(&interface, lang)).await.map_err(|e| e.to_string())?;
    let gateway = info.gateway.as_deref().and_then(|g| g.parse().ok());
    let dns = info.dns.iter().filter_map(|d| d.parse().ok()).collect();
    Ok(internet::info(gateway, dns, lang).await)
}

#[tauri::command(rename_all = "snake_case")]
async fn net_speedtest(app: AppHandle, state: State<'_, AppState>) -> Res<SpeedResult> {
    let lang = state.lang();
    let cancel = state.speed_cancel.clone();
    cancel.store(false, Ordering::SeqCst);
    let emit = |p: NetProgress| {
        let _ = app.emit("net-progress", p);
    };
    internet::speed(cancel, &emit, lang).await
}

#[tauri::command(rename_all = "snake_case")]
async fn net_speed_cancel(state: State<'_, AppState>) -> Res<()> {
    state.speed_cancel.store(true, Ordering::SeqCst);
    Ok(())
}

/// Ancien identifiant d'application (déconseillé sur macOS car il finit par `.app`).
const LEGACY_IDENTIFIER: &str = "com.rustshark.app";

/// Reprend les réglages et profils enregistrés sous l'ancien identifiant.
fn migrate_config_dir(dir: &Path) {
    let Some(legacy) = dir.parent().map(|p| p.join(LEGACY_IDENTIFIER)) else { return };
    if dir.exists() || !legacy.is_dir() {
        return;
    }
    if std::fs::rename(&legacy, dir).is_err() {
        // Volumes différents ou dossier verrouillé : copie des fichiers JSON.
        if std::fs::create_dir_all(dir).is_ok() {
            for name in ["settings.json", "profiles.json"] {
                let _ = std::fs::copy(legacy.join(name), dir.join(name));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_legacy_config_dir() {
        let base = std::env::temp_dir().join(format!("rustshark-migr-{}", std::process::id()));
        let legacy = base.join(LEGACY_IDENTIFIER);
        let current = base.join("io.github.jeanjacquesserpoul.rustshark");
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join("settings.json"), "{\"language\":\"en\"}").unwrap();

        migrate_config_dir(&current);
        assert_eq!(std::fs::read_to_string(current.join("settings.json")).unwrap(), "{\"language\":\"en\"}");
        assert!(!legacy.exists());

        // Un dossier déjà présent n'est jamais écrasé.
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join("settings.json"), "old").unwrap();
        migrate_config_dir(&current);
        assert_eq!(std::fs::read_to_string(current.join("settings.json")).unwrap(), "{\"language\":\"en\"}");
        std::fs::remove_dir_all(&base).unwrap();
    }
}

/// Diagnostic en ligne de commande : `rustshark --selftest [secondes]`.
fn selftest(secs: u64) {
    println!("libpcap : {:?}", pcap::available());
    let list = match interfaces::list() {
        Ok(l) => l,
        Err(e) => return println!("interfaces : {e}"),
    };
    for i in &list {
        println!("  [{}] {:<28} {:?} up={} {:?}", if i.recommended { "*" } else { " " }, i.friendly, i.kind, i.up, i.addresses);
    }
    let Some(iface) = list.iter().find(|i| i.recommended).or(list.first()) else { return };
    println!("Capture de {secs} s sur « {} »…", iface.friendly);
    let store = Arc::new(RwLock::new(Store::default()));
    store.write().begin(CaptureState::Running, iface.friendly.clone(), None);
    store.write().names.local = interfaces::addresses_of(&iface.name).into_iter().collect();
    match capture::start(store.clone(), &iface.name, None, false) {
        Ok(h) => {
            std::thread::sleep(Duration::from_secs(secs));
            h.stop();
        }
        Err(e) => return println!("erreur : {}", permission_hint(e.code, &e.message, Lang::Fr)),
    }
    let s = store.read();
    let v = s.view(0, 40, Lang::Fr);
    println!("{} paquets", v.total);
    for r in v.rows {
        println!("{:>4} {:>7.3} {:<6} {:<40} {}", r.no, r.time, r.protocol, r.info.chars().take(40).collect::<String>(), r.summary);
    }
    let st = s.stats(false, Lang::Fr);
    for a in st.alerts {
        println!("ALERTE {:?} {} — {}", a.level, a.title, a.detail);
    }
}

/// Diagnostic de la vue « Mon réseau » : `rustshark --network`.
fn network_test() {
    let list = match interfaces::list() {
        Ok(l) => l,
        Err(e) => return println!("interfaces : {e}"),
    };
    let Some(iface) = list.iter().find(|i| i.recommended).or(list.first()) else { return };
    let info = netinfo::info(&iface.name, Lang::Fr);
    println!("{info:#?}");
    let t = std::time::Instant::now();
    let cache = match discover::scan(&iface.name, &info, Lang::Fr, &|phase, done, total| {
        if done == total {
            println!("  {phase} : {done}/{total} ({:.1} s)", t.elapsed().as_secs_f64());
        }
    }) {
        Ok(c) => c,
        Err(e) => return println!("analyse : {e}"),
    };
    let devices = discover::devices(&iface.name, &info, Some(&cache), &Store::default(), Lang::Fr);
    for d in &devices.devices {
        println!(
            "{:<16} {:<18} {:<14} {:<18} {:<28} {}",
            d.ip,
            d.mac.clone().unwrap_or_default(),
            format!("{:?}", d.kind),
            d.vendor.clone().unwrap_or_default(),
            d.name.clone().unwrap_or_default(),
            d.services.join(", ")
        );
    }
    let neighbors = netinfo::neighbors(&iface.name);
    let report = security::report(
        security::Inputs { info: &info, devices: &devices, neighbors: &neighbors, gateway_ports: None, igd: cache.igd, capture_alerts: Vec::new() },
        Lang::Fr,
    );
    println!("Sécurité : {}/100", report.score);
    for c in report.checks {
        println!("  [{:?}] {} — {}", c.level, c.title, c.detail);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(pos) = args.iter().position(|a| a == "--selftest") {
        let secs = args.get(pos + 1).and_then(|s| s.parse().ok()).unwrap_or(4);
        return selftest(secs);
    }
    if args.iter().any(|a| a == "--network") {
        return network_test();
    }
    // Serveur MCP pour Claude : `rustshark --mcp [--no-anonymize] [--lang fr|en]`.
    if args.iter().any(|a| a == "--mcp") {
        return mcp::run(&args);
    }
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let dir = app.path().app_config_dir()?;
            migrate_config_dir(&dir);
            app.manage(AppState::new(dir));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            system_info,
            list_interfaces,
            probe_interfaces,
            start_capture,
            stop_capture,
            clear_capture,
            validate_capture_filter,
            set_display_filter,
            get_view,
            packet_position,
            get_packet_detail,
            get_stats,
            get_flows,
            open_capture,
            open_capture_path,
            save_capture,
            get_settings,
            save_settings,
            key_status,
            set_api_key,
            delete_api_key,
            delete_all_api_keys,
            list_profiles,
            save_profile,
            delete_profile,
            open_url,
            ai_test,
            ai_models,
            ai_chat,
            ai_cancel,
            ai_generate_profile,
            net_info,
            net_devices,
            net_scan,
            net_ports,
            net_security,
            net_internet,
            net_speedtest,
            net_speed_cancel,
        ])
        .run(tauri::generate_context!())
        .expect("erreur au lancement de RustShark");
}
