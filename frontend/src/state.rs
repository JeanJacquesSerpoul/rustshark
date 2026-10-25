//! État global de l'interface (signaux) et actions vers le backend.

use std::collections::HashMap;

use leptos::html::Div;
use leptos::prelude::*;
use leptos::task::spawn_local;
use rustshark_shared::{
    AiChatRequest, AiChunk, AiScope, AnalysisProfile, AppSettings, CaptureState, CaptureStatus, ChatMessage,
    InterfaceInfo, KeyStatus, Lang, PacketDetail, PacketRow, StartCaptureRequest, SystemInfo, Theme, ViewResponse,
};
use serde::Serialize;

use crate::api::{call, call0, listen};

pub const ROW_H: f64 = 28.0;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    Packets,
    Dashboard,
    Flows,
    Network,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Modal {
    None,
    Settings,
    Help,
    Interfaces,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AiTab {
    Chat,
    Builder,
    Profiles,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ToastKind {
    Info,
    Success,
    Error,
}

#[derive(Clone, PartialEq, Debug)]
pub struct Toast {
    pub id: u64,
    pub kind: ToastKind,
    pub text: String,
}

#[derive(Clone, PartialEq, Debug)]
pub struct ChatEntry {
    pub id: String,
    pub role: String,
    pub content: String,
    pub thinking: bool,
    pub done: bool,
    pub error: Option<String>,
}

#[derive(Clone, Copy)]
pub struct Ctx {
    pub settings: RwSignal<AppSettings>,
    pub sys: RwSignal<Option<SystemInfo>>,
    pub interfaces: RwSignal<Vec<InterfaceInfo>>,
    pub iface_error: RwSignal<Option<String>>,
    pub activity: RwSignal<HashMap<String, u32>>,
    pub probing: RwSignal<bool>,
    pub iface: RwSignal<Option<String>>,
    pub capture_filter: RwSignal<String>,
    pub status: RwSignal<CaptureStatus>,
    pub total: RwSignal<u32>,
    pub matched: RwSignal<u32>,
    pub rows: RwSignal<Vec<PacketRow>>,
    pub rows_offset: RwSignal<u32>,
    pub filter_text: RwSignal<String>,
    pub filter_applied: RwSignal<String>,
    pub filter_error: RwSignal<Option<String>>,
    pub selected: RwSignal<Option<u32>>,
    pub detail: RwSignal<Option<PacketDetail>>,
    pub tab: RwSignal<Tab>,
    pub modal: RwSignal<Modal>,
    pub settings_section: RwSignal<&'static str>,
    pub ai_open: RwSignal<bool>,
    pub ai_tab: RwSignal<AiTab>,
    pub ai_scope: RwSignal<AiScope>,
    pub ai_busy: RwSignal<Option<String>>,
    pub chat: RwSignal<Vec<ChatEntry>>,
    pub builder_goal: RwSignal<String>,
    pub builder_autorun: RwSignal<bool>,
    pub profiles: RwSignal<Vec<AnalysisProfile>>,
    pub active_profile: RwSignal<Option<AnalysisProfile>>,
    pub keys: RwSignal<KeyStatus>,
    pub toasts: RwSignal<Vec<Toast>>,
    pub follow: RwSignal<bool>,
    pub scroll_top: RwSignal<f64>,
    pub viewport_h: RwSignal<f64>,
    pub list_ref: NodeRef<Div>,
    pub filter_ref: NodeRef<leptos::html::Input>,
    view_seq: StoredValue<u64>,
    view_inflight: StoredValue<bool>,
    view_again: StoredValue<bool>,
    last_state: StoredValue<CaptureState>,
    toast_seq: StoredValue<u64>,
}

pub fn use_ctx() -> Ctx {
    expect_context::<Ctx>()
}

#[derive(Serialize)]
struct ViewArgs {
    offset: u32,
    limit: u32,
    tail: bool,
}

#[derive(Serialize)]
struct NoArg {
    no: u32,
}

#[derive(Serialize)]
struct FilterArg {
    filter: String,
}

#[derive(Serialize)]
struct ReqArg<T: Serialize> {
    req: T,
}

#[derive(Serialize)]
struct FilteredArg {
    filtered: bool,
}

#[derive(Serialize)]
struct PathArg {
    path: String,
}

#[derive(Serialize)]
struct SettingsArg {
    settings: AppSettings,
}

#[derive(Serialize)]
struct NamesArg {
    names: Vec<String>,
}

#[derive(Serialize)]
pub struct UrlArg {
    pub url: String,
}

#[derive(Serialize)]
struct CancelArg {
    request_id: String,
}

#[derive(Serialize, serde::Deserialize)]
struct DropPayload {
    paths: Vec<String>,
}

pub fn apply_theme(theme: Theme, lang: Lang) {
    if let Some(el) = document().document_element() {
        let _ = match theme {
            Theme::System => el.remove_attribute("data-theme"),
            Theme::Light => el.set_attribute("data-theme", "light"),
            Theme::Dark => el.set_attribute("data-theme", "dark"),
        };
        let _ = el.set_attribute("lang", if lang == Lang::Fr { "fr" } else { "en" });
    }
}

impl Ctx {
    pub fn new() -> Self {
        Self {
            settings: RwSignal::new(AppSettings::default()),
            sys: RwSignal::new(None),
            interfaces: RwSignal::new(Vec::new()),
            iface_error: RwSignal::new(None),
            activity: RwSignal::new(HashMap::new()),
            probing: RwSignal::new(false),
            iface: RwSignal::new(None),
            capture_filter: RwSignal::new(String::new()),
            status: RwSignal::new(CaptureStatus::default()),
            total: RwSignal::new(0),
            matched: RwSignal::new(0),
            rows: RwSignal::new(Vec::new()),
            rows_offset: RwSignal::new(0),
            filter_text: RwSignal::new(String::new()),
            filter_applied: RwSignal::new(String::new()),
            filter_error: RwSignal::new(None),
            selected: RwSignal::new(None),
            detail: RwSignal::new(None),
            tab: RwSignal::new(Tab::Packets),
            modal: RwSignal::new(Modal::None),
            settings_section: RwSignal::new("general"),
            ai_open: RwSignal::new(false),
            ai_tab: RwSignal::new(AiTab::Chat),
            ai_scope: RwSignal::new(AiScope::All),
            ai_busy: RwSignal::new(None),
            chat: RwSignal::new(Vec::new()),
            builder_goal: RwSignal::new(String::new()),
            builder_autorun: RwSignal::new(false),
            profiles: RwSignal::new(Vec::new()),
            active_profile: RwSignal::new(None),
            keys: RwSignal::new(KeyStatus::default()),
            toasts: RwSignal::new(Vec::new()),
            follow: RwSignal::new(true),
            scroll_top: RwSignal::new(0.0),
            viewport_h: RwSignal::new(600.0),
            list_ref: NodeRef::new(),
            filter_ref: NodeRef::new(),
            view_seq: StoredValue::new(0),
            view_inflight: StoredValue::new(false),
            view_again: StoredValue::new(false),
            last_state: StoredValue::new(CaptureState::Idle),
            toast_seq: StoredValue::new(0),
        }
    }

    /// Langue courante : suivie dans un contexte réactif, lue simplement ailleurs
    /// (évite les avertissements Leptos lors des rendus statiques).
    pub fn lang(&self) -> Lang {
        if leptos::reactive::graph::Observer::get().is_some() {
            self.settings.with(|s| s.language)
        } else {
            self.settings.with_untracked(|s| s.language)
        }
    }

    pub fn lang_untracked(&self) -> Lang {
        self.settings.with_untracked(|s| s.language)
    }

    /// Traduction réactive (à appeler dans une closure de vue).
    pub fn t(&self, key: &'static str) -> &'static str {
        crate::i18n::t(self.lang(), key)
    }

    pub fn tu(&self, key: &'static str) -> &'static str {
        crate::i18n::t(self.lang_untracked(), key)
    }

    pub fn running(&self) -> bool {
        self.status.with(|s| s.state == CaptureState::Running)
    }

    pub fn toast(self, kind: ToastKind, text: impl Into<String>) {
        let id = self.toast_seq.get_value() + 1;
        self.toast_seq.set_value(id);
        self.toasts.update(|t| t.push(Toast { id, kind, text: text.into() }));
        let toasts = self.toasts;
        set_timeout(
            move || toasts.update(|t| t.retain(|x| x.id != id)),
            std::time::Duration::from_millis(if kind == ToastKind::Error { 9000 } else { 4500 }),
        );
    }

    // -----------------------------------------------------------------------
    // Initialisation
    // -----------------------------------------------------------------------

    pub fn init(self) {
        spawn_local(async move {
            if let Ok(s) = call0::<AppSettings>("get_settings").await {
                apply_theme(s.theme, s.language);
                self.settings.set(s);
            }
            if let Ok(info) = call0::<SystemInfo>("system_info").await {
                let ok = info.pcap_ok;
                self.sys.set(Some(info));
                if ok {
                    self.load_interfaces();
                }
            }
            self.reload_keys();
            self.load_profiles();
            self.refresh_view();
        });
        listen::<AiChunk>("ai-chunk", move |c| self.on_ai_chunk(c));
        listen::<DropPayload>("tauri://drag-drop", move |p| {
            if let Some(path) = p.paths.into_iter().find(|p| {
                let l = p.to_lowercase();
                l.ends_with(".pcap") || l.ends_with(".pcapng") || l.ends_with(".cap")
            }) {
                self.open_path(path);
            }
        });
    }

    pub fn load_interfaces(self) {
        spawn_local(async move {
            match call0::<Vec<InterfaceInfo>>("list_interfaces").await {
                Ok(list) => {
                    if self.iface.get_untracked().is_none() {
                        let pick = list.iter().find(|i| i.recommended).or(list.iter().find(|i| i.connected && !i.loopback)).or(list.first());
                        self.iface.set(pick.map(|i| i.name.clone()));
                    }
                    self.iface_error.set(None);
                    self.interfaces.set(list);
                }
                Err(e) => self.iface_error.set(Some(e)),
            }
        });
    }

    /// Écoute 1,5 s chaque interface active pour montrer où il y a du trafic.
    pub fn probe(self) {
        if self.probing.get_untracked() || self.running() {
            return;
        }
        let names: Vec<String> = self.interfaces.with_untracked(|l| l.iter().filter(|i| i.up).map(|i| i.name.clone()).collect());
        if names.is_empty() {
            return;
        }
        self.probing.set(true);
        spawn_local(async move {
            if let Ok(map) = call::<_, HashMap<String, u32>>("probe_interfaces", &NamesArg { names }).await {
                self.activity.set(map);
            }
            self.probing.set(false);
        });
    }

    pub fn reload_keys(self) {
        spawn_local(async move {
            if let Ok(k) = call0::<KeyStatus>("key_status").await {
                self.keys.set(k);
            }
        });
    }

    pub fn load_profiles(self) {
        spawn_local(async move {
            if let Ok(p) = call0::<Vec<AnalysisProfile>>("list_profiles").await {
                self.profiles.set(p);
            }
        });
    }

    pub fn save_settings(self, s: AppSettings) {
        apply_theme(s.theme, s.language);
        let lang_changed = s.language != self.lang_untracked();
        self.settings.set(s.clone());
        spawn_local(async move {
            if let Err(e) = call::<_, ()>("save_settings", &SettingsArg { settings: s }).await {
                self.toast(ToastKind::Error, e);
            }
            if lang_changed {
                // Les résumés et explications sont produits côté backend dans la langue choisie.
                self.refresh_view();
                if let Some(no) = self.selected.get_untracked() {
                    self.select(no);
                }
                if !self.filter_applied.get_untracked().is_empty() {
                    let f = self.filter_applied.get_untracked();
                    self.apply_filter(f);
                }
            }
        });
    }

    // -----------------------------------------------------------------------
    // Vue paquets
    // -----------------------------------------------------------------------

    pub fn tick(self) {
        if self.running() || self.status.with_untracked(|s| s.state == CaptureState::Running) {
            self.refresh_view();
        }
    }

    pub fn refresh_view(self) {
        if self.view_inflight.get_value() {
            self.view_again.set_value(true);
            return;
        }
        let running = self.status.with_untracked(|s| s.state == CaptureState::Running);
        let tail = self.follow.get_untracked() && running;
        let top = self.scroll_top.get_untracked();
        let h = self.viewport_h.get_untracked().max(200.0);
        let visible = (h / ROW_H).ceil() as u32;
        let first = ((top / ROW_H).floor() as i64 - 30).max(0) as u32;
        let args = ViewArgs { offset: first, limit: visible + 60, tail };
        let seq = self.view_seq.get_value() + 1;
        self.view_seq.set_value(seq);
        self.view_inflight.set_value(true);
        spawn_local(async move {
            let res = call::<_, ViewResponse>("get_view", &args).await;
            self.view_inflight.set_value(false);
            if let Ok(v) = res {
                if seq == self.view_seq.get_value() {
                    self.apply_view(v, tail);
                }
            }
            if self.view_again.get_value() {
                self.view_again.set_value(false);
                self.refresh_view();
            }
        });
    }

    /// Recharge seulement si la fenêtre visible sort des lignes chargées.
    pub fn maybe_refresh(self) {
        let top = self.scroll_top.get_untracked();
        let h = self.viewport_h.get_untracked();
        let first = (top / ROW_H).floor() as u32;
        let last = ((top + h) / ROW_H).ceil() as u32;
        let off = self.rows_offset.get_untracked();
        let len = self.rows.with_untracked(|r| r.len()) as u32;
        let matched = self.matched.get_untracked();
        if first < off || (last > off + len && off + len < matched) {
            self.refresh_view();
        }
    }

    fn apply_view(self, v: ViewResponse, tail: bool) {
        let prev = self.last_state.get_value();
        let now = v.status.state;
        if prev == CaptureState::Running && now != CaptureState::Running {
            if let Some(e) = &v.status.error {
                self.toast(ToastKind::Error, e.clone());
            }
        }
        self.last_state.set_value(now);
        if self.total.get_untracked() != v.total {
            self.total.set(v.total);
        }
        if self.matched.get_untracked() != v.matched {
            self.matched.set(v.matched);
        }
        self.rows_offset.set(v.offset);
        self.rows.set(v.rows);
        if self.status.with_untracked(|s| *s != v.status) {
            self.status.set(v.status);
        }
        if tail {
            let list = self.list_ref;
            request_animation_frame(move || {
                if let Some(el) = list.get_untracked() {
                    el.set_scroll_top(el.scroll_height());
                }
            });
        }
    }

    pub fn apply_filter(self, text: String) {
        spawn_local(async move {
            match call::<_, u32>("set_display_filter", &FilterArg { filter: text.clone() }).await {
                Ok(_) => {
                    self.filter_error.set(None);
                    self.filter_text.set(text.clone());
                    self.filter_applied.set(text);
                    self.scroll_top.set(0.0);
                    if let Some(el) = self.list_ref.get_untracked() {
                        el.set_scroll_top(0);
                    }
                    self.refresh_view();
                }
                Err(e) => self.filter_error.set(Some(e)),
            }
        });
    }

    pub fn select(self, no: u32) {
        self.selected.set(Some(no));
        spawn_local(async move {
            if let Ok(d) = call::<_, Option<PacketDetail>>("get_packet_detail", &NoArg { no }).await {
                if self.selected.get_untracked() == Some(no) {
                    self.detail.set(d);
                }
            }
        });
    }

    /// Sélectionne le paquet voisin (flèches du clavier).
    pub fn select_relative(self, delta: i32) {
        let rows = self.rows.get_untracked();
        let off = self.rows_offset.get_untracked();
        let cur = self.selected.get_untracked().and_then(|no| rows.iter().position(|r| r.no == no));
        let pos = match cur {
            Some(i) => i as i64 + delta as i64,
            None => 0,
        };
        if pos < 0 || pos as usize >= rows.len() {
            return;
        }
        let no = rows[pos as usize].no;
        self.follow.set(false);
        self.select(no);
        if let Some(el) = self.list_ref.get_untracked() {
            let y = (off as f64 + pos as f64) * ROW_H;
            let top = el.scroll_top() as f64;
            let h = el.client_height() as f64;
            if y < top {
                el.set_scroll_top(y as i32);
            } else if y + ROW_H > top + h {
                el.set_scroll_top((y + ROW_H - h) as i32);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Capture
    // -----------------------------------------------------------------------

    pub fn start(self) {
        let Some(interface) = self.iface.get_untracked() else {
            self.modal.set(Modal::Interfaces);
            return;
        };
        let req = StartCaptureRequest {
            interface,
            capture_filter: Some(self.capture_filter.get_untracked()).filter(|f| !f.trim().is_empty()),
            promiscuous: self.settings.with_untracked(|s| s.promiscuous),
        };
        self.selected.set(None);
        self.detail.set(None);
        self.follow.set(true);
        spawn_local(async move {
            match call::<_, ()>("start_capture", &ReqArg { req }).await {
                Ok(()) => {
                    self.status.update(|s| s.state = CaptureState::Running);
                    self.last_state.set_value(CaptureState::Running);
                    self.tab.set(Tab::Packets);
                    self.refresh_view();
                }
                Err(e) => self.toast(ToastKind::Error, e),
            }
        });
    }

    pub fn stop(self) {
        spawn_local(async move {
            let _ = call0::<()>("stop_capture").await;
            self.last_state.set_value(CaptureState::Stopped);
            self.refresh_view();
            if let Some(p) = self.active_profile.get_untracked() {
                if p.ai_prompt.is_some() {
                    self.toast(ToastKind::Info, self.tu("profile.done_hint"));
                }
            }
        });
    }

    pub fn clear(self) {
        spawn_local(async move {
            let _ = call0::<()>("clear_capture").await;
            self.selected.set(None);
            self.detail.set(None);
            self.scroll_top.set(0.0);
            self.refresh_view();
        });
    }

    pub fn open_file(self) {
        spawn_local(async move {
            match call0::<Option<String>>("open_capture").await {
                Ok(Some(name)) => self.after_open(name),
                Ok(None) => {}
                Err(e) => self.toast(ToastKind::Error, e),
            }
        });
    }

    pub fn open_path(self, path: String) {
        spawn_local(async move {
            match call::<_, String>("open_capture_path", &PathArg { path }).await {
                Ok(name) => self.after_open(name),
                Err(e) => self.toast(ToastKind::Error, e),
            }
        });
    }

    fn after_open(self, name: String) {
        self.selected.set(None);
        self.detail.set(None);
        self.follow.set(false);
        self.scroll_top.set(0.0);
        if let Some(el) = self.list_ref.get_untracked() {
            el.set_scroll_top(0);
        }
        self.toast(ToastKind::Success, format!("{} {name}", self.tu("toast.opened")));
        self.refresh_view();
    }

    pub fn save_file(self, filtered: bool) {
        spawn_local(async move {
            match call::<_, Option<String>>("save_capture", &FilteredArg { filtered }).await {
                Ok(Some(p)) => self.toast(ToastKind::Success, format!("{} {p}", self.tu("toast.saved"))),
                Ok(None) => {}
                Err(e) => self.toast(ToastKind::Error, e),
            }
        });
    }

    pub fn open_url(self, url: String) {
        spawn_local(async move {
            if let Err(e) = call::<_, ()>("open_url", &UrlArg { url }).await {
                self.toast(ToastKind::Error, e);
            }
        });
    }

    // -----------------------------------------------------------------------
    // IA
    // -----------------------------------------------------------------------

    pub fn has_key(&self) -> bool {
        let p = self.settings.with(|s| s.ai.provider);
        self.keys.with(|k| k.has(p))
    }

    pub fn ask_ai(self, text: String, scope: AiScope) {
        if self.ai_busy.get_untracked().is_some() || text.trim().is_empty() {
            return;
        }
        let provider = self.settings.with_untracked(|s| s.ai.provider);
        if !self.keys.with_untracked(|k| k.has(provider)) {
            self.settings_section.set("ai");
            self.modal.set(Modal::Settings);
            self.toast(ToastKind::Info, self.tu("ai.need_key"));
            return;
        }
        let mut history: Vec<ChatMessage> = self.chat.with_untracked(|c| {
            c.iter()
                .filter(|e| e.done && e.error.is_none() && !e.content.is_empty())
                .map(|e| ChatMessage { role: e.role.clone(), content: e.content.clone() })
                .collect()
        });
        history.push(ChatMessage { role: "user".into(), content: text.clone() });
        let id = format!("r{}", js_sys::Date::now() as u64);
        self.chat.update(|c| {
            c.push(ChatEntry { id: format!("{id}-q"), role: "user".into(), content: text, thinking: false, done: true, error: None });
            c.push(ChatEntry { id: id.clone(), role: "assistant".into(), content: String::new(), thinking: true, done: false, error: None });
        });
        self.ai_busy.set(Some(id.clone()));
        let req = AiChatRequest {
            request_id: id.clone(),
            messages: history,
            scope,
            selected: self.selected.get_untracked(),
            profile: self.active_profile.get_untracked(),
        };
        spawn_local(async move {
            if let Err(e) = call::<_, ()>("ai_chat", &ReqArg { req }).await {
                self.on_ai_chunk(AiChunk { request_id: id, done: true, error: Some(e), ..Default::default() });
            }
        });
    }

    pub fn cancel_ai(self) {
        if let Some(id) = self.ai_busy.get_untracked() {
            spawn_local(async move {
                let _ = call::<_, ()>("ai_cancel", &CancelArg { request_id: id.clone() }).await;
                self.on_ai_chunk(AiChunk { request_id: id, done: true, ..Default::default() });
            });
        }
    }

    fn on_ai_chunk(self, c: AiChunk) {
        self.chat.update(|entries| {
            if let Some(e) = entries.iter_mut().find(|e| e.id == c.request_id) {
                if c.reasoning {
                    e.thinking = true;
                } else if !c.delta.is_empty() {
                    e.thinking = false;
                    e.content.push_str(&c.delta);
                }
                if c.done {
                    e.done = true;
                    e.thinking = false;
                    if e.error.is_none() {
                        e.error = c.error.clone();
                    }
                }
            }
        });
        if c.done && self.ai_busy.get_untracked().as_deref() == Some(c.request_id.as_str()) {
            self.ai_busy.set(None);
        }
    }

    /// Ouvre l'assistant et pose une question sur le paquet sélectionné.
    pub fn explain_selected(self) {
        self.ai_open.set(true);
        self.ai_tab.set(AiTab::Chat);
        self.ai_scope.set(AiScope::Packet);
        let q = self.tu("ai.q.packet").to_string();
        self.ask_ai(q, AiScope::Packet);
    }

    pub fn apply_profile(self, p: AnalysisProfile, start: bool) {
        self.capture_filter.set(p.capture_filter.clone().unwrap_or_default());
        let df = p.display_filter.clone().unwrap_or_default();
        self.active_profile.set(Some(p));
        self.apply_filter(df);
        if start {
            self.start();
        }
    }
}
