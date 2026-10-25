//! Vue « Mon réseau » : appareils, configuration, sécurité et connexion
//! Internet.

use std::collections::HashMap;

use leptos::prelude::*;
use leptos::task::spawn_local;
use rustshark_shared::{
    CheckLevel, DeviceList, InternetInfo, LatencyResult, NetDevice, NetProgress, NetworkInfo, PortInfo,
    SecurityReport, SpeedResult, WifiSecurity,
};
use serde::Serialize;

use crate::api::{call, call0, listen};
use crate::icons::{device_icon, iface_icon, Icon};
use crate::state::{use_ctx, Tab, ToastKind};
use crate::util::fmt_bytes;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NetTab {
    Devices,
    Network,
    Security,
    Internet,
}

/// État de la vue, conservé quand on change d'onglet.
#[derive(Clone, Copy)]
pub struct NetCtx {
    pub tab: RwSignal<NetTab>,
    /// Interface à laquelle se rapportent les données affichées.
    iface: RwSignal<Option<String>>,
    info: RwSignal<Option<NetworkInfo>>,
    devices: RwSignal<Option<DeviceList>>,
    security: RwSignal<Option<SecurityReport>>,
    internet: RwSignal<Option<InternetInfo>>,
    speed: RwSignal<Option<SpeedResult>>,
    progress: RwSignal<HashMap<String, NetProgress>>,
    scanning: RwSignal<bool>,
    sec_busy: RwSignal<bool>,
    inet_busy: RwSignal<bool>,
    speed_busy: RwSignal<bool>,
    ports_busy: RwSignal<Option<String>>,
    open: RwSignal<Option<String>>,
    query: RwSignal<String>,
}

pub fn use_net() -> NetCtx {
    expect_context::<NetCtx>()
}

#[derive(Serialize)]
struct IfaceArg {
    interface: String,
}

#[derive(Serialize)]
struct PortsArg {
    interface: String,
    ip: String,
}

#[derive(Serialize)]
struct SecArg {
    interface: String,
    deep: bool,
}

impl NetCtx {
    pub fn new() -> Self {
        let n = Self {
            tab: RwSignal::new(NetTab::Devices),
            iface: RwSignal::new(None),
            info: RwSignal::new(None),
            devices: RwSignal::new(None),
            security: RwSignal::new(None),
            internet: RwSignal::new(None),
            speed: RwSignal::new(None),
            progress: RwSignal::new(HashMap::new()),
            scanning: RwSignal::new(false),
            sec_busy: RwSignal::new(false),
            inet_busy: RwSignal::new(false),
            speed_busy: RwSignal::new(false),
            ports_busy: RwSignal::new(None),
            open: RwSignal::new(None),
            query: RwSignal::new(String::new()),
        };
        if crate::api::tauri_available() {
            listen::<NetProgress>("net-progress", move |p| n.progress.update(|m| {
                m.insert(p.task.clone(), p);
            }));
        }
        n
    }

    fn arg(self) -> Option<IfaceArg> {
        self.iface.get_untracked().map(|interface| IfaceArg { interface })
    }

    /// Recharge tout si l'interface choisie a changé.
    pub fn sync(self, iface: Option<String>) {
        if self.iface.get_untracked() == iface && self.info.with_untracked(|i| i.is_some()) {
            return;
        }
        self.iface.set(iface);
        self.info.set(None);
        self.devices.set(None);
        self.security.set(None);
        self.internet.set(None);
        self.open.set(None);
        self.load();
    }

    pub fn load(self) {
        let Some(a) = self.arg() else { return };
        let ctx = use_ctx();
        spawn_local(async move {
            match call::<_, NetworkInfo>("net_info", &a).await {
                Ok(i) => self.info.set(Some(i)),
                Err(e) => ctx.toast(ToastKind::Error, e),
            }
        });
        self.reload_devices();
    }

    fn reload_devices(self) {
        let Some(a) = self.arg() else { return };
        spawn_local(async move {
            if let Ok(d) = call::<_, DeviceList>("net_devices", &a).await {
                self.devices.set(Some(d));
            }
        });
    }

    fn scan(self) {
        let Some(a) = self.arg() else { return };
        if self.scanning.get_untracked() {
            return;
        }
        let ctx = use_ctx();
        self.scanning.set(true);
        self.progress.update(|m| {
            m.remove("scan");
        });
        spawn_local(async move {
            match call::<_, DeviceList>("net_scan", &a).await {
                Ok(d) => {
                    let n = d.devices.len();
                    self.devices.set(Some(d));
                    ctx.toast(ToastKind::Success, format!("{n} {}", ctx.tu("nw.found")));
                    // Le bilan de sécurité dépend de la liste des appareils.
                    if self.security.with_untracked(|s| s.is_some()) {
                        self.load_security(false);
                    }
                }
                Err(e) => ctx.toast(ToastKind::Error, e),
            }
            self.scanning.set(false);
        });
    }

    fn scan_ports(self, ip: String) {
        let Some(IfaceArg { interface }) = self.arg() else { return };
        if self.ports_busy.get_untracked().is_some() {
            return;
        }
        let ctx = use_ctx();
        self.ports_busy.set(Some(ip.clone()));
        self.progress.update(|m| {
            m.remove("ports");
        });
        spawn_local(async move {
            match call::<_, Vec<PortInfo>>("net_ports", &PortsArg { interface, ip: ip.clone() }).await {
                Ok(ports) => self.devices.update(|l| {
                    if let Some(d) = l.as_mut().and_then(|l| l.devices.iter_mut().find(|d| d.ip == ip)) {
                        d.open_ports = Some(ports);
                    }
                }),
                Err(e) => ctx.toast(ToastKind::Error, e),
            }
            self.ports_busy.set(None);
        });
    }

    fn load_security(self, deep: bool) {
        let Some(IfaceArg { interface }) = self.arg() else { return };
        if self.sec_busy.get_untracked() {
            return;
        }
        let ctx = use_ctx();
        self.sec_busy.set(true);
        self.progress.update(|m| {
            m.remove("security");
        });
        spawn_local(async move {
            match call::<_, SecurityReport>("net_security", &SecArg { interface, deep }).await {
                Ok(r) => self.security.set(Some(r)),
                Err(e) => ctx.toast(ToastKind::Error, e),
            }
            self.sec_busy.set(false);
        });
    }

    fn load_internet(self) {
        let Some(a) = self.arg() else { return };
        if self.inet_busy.get_untracked() {
            return;
        }
        self.inet_busy.set(true);
        spawn_local(async move {
            if let Ok(i) = call::<_, InternetInfo>("net_internet", &a).await {
                self.internet.set(Some(i));
            }
            self.inet_busy.set(false);
        });
    }

    fn speedtest(self) {
        if self.speed_busy.get_untracked() {
            return;
        }
        let ctx = use_ctx();
        self.speed_busy.set(true);
        self.progress.update(|m| {
            m.remove("speed");
        });
        spawn_local(async move {
            match call0::<SpeedResult>("net_speedtest").await {
                Ok(r) => self.speed.set(Some(r)),
                Err(e) => ctx.toast(ToastKind::Error, e),
            }
            self.speed_busy.set(false);
        });
    }

    fn progress_of(self, task: &str) -> Option<NetProgress> {
        self.progress.with(|m| m.get(task).cloned())
    }
}

fn pct(p: &NetProgress) -> f64 {
    if p.total == 0 {
        0.0
    } else {
        (p.done as f64 / p.total as f64 * 100.0).clamp(0.0, 100.0)
    }
}

fn fmt_ms(v: Option<f64>) -> String {
    match v {
        Some(x) if x < 10.0 => format!("{x:.1} ms"),
        Some(x) => format!("{x:.0} ms"),
        None => "—".into(),
    }
}

fn fmt_mbps(v: f64) -> String {
    if v >= 100.0 {
        format!("{v:.0}")
    } else if v >= 10.0 {
        format!("{v:.1}")
    } else {
        format!("{v:.2}")
    }
}

fn level_class(l: CheckLevel) -> &'static str {
    match l {
        CheckLevel::Ok => "ok",
        CheckLevel::Info => "info",
        CheckLevel::Warning => "warning",
        CheckLevel::Danger => "danger",
    }
}

fn level_icon(l: CheckLevel) -> &'static str {
    match l {
        CheckLevel::Ok => "check",
        CheckLevel::Info => "info",
        CheckLevel::Warning | CheckLevel::Danger => "alert",
    }
}

/// Nom affiché : nom découvert, sinon type et fabricant.
fn display_name(d: &NetDevice, lang: rustshark_shared::Lang) -> String {
    if let Some(n) = &d.name {
        return n.clone();
    }
    match &d.vendor {
        Some(v) => format!("{} {v}", d.kind.label(lang)),
        None => d.kind.label(lang).to_string(),
    }
}

// ---------------------------------------------------------------------------
// Vue principale
// ---------------------------------------------------------------------------

#[component]
pub fn Network() -> impl IntoView {
    let ctx = use_ctx();
    let net = use_net();
    Effect::new(move |_| net.sync(ctx.iface.get()));
    // Les appareils vus pendant une capture en cours apparaissent au fil de l'eau.
    if let Ok(h) = set_interval_with_handle(
        move || {
            if ctx.running() && net.tab.get_untracked() == NetTab::Devices && !net.scanning.get_untracked() {
                net.reload_devices();
            }
        },
        std::time::Duration::from_secs(6),
    ) {
        on_cleanup(move || h.clear());
    }
    let count = Memo::new(move |_| net.devices.with(|d| d.as_ref().map(|d| d.devices.len())));
    let tab_btn = move |tab: NetTab, icon: &'static str, key: &'static str| {
        view! {
            <button class:on=move || net.tab.get() == tab on:click=move |_| {
                net.tab.set(tab);
                if tab == NetTab::Security && net.security.with_untracked(|s| s.is_none()) {
                    net.load_security(false);
                }
            }>
                <Icon name=icon/>{move || ctx.t(key)}
                {(tab == NetTab::Devices).then(|| view! { <span class="count">{move || count.get().map(|n| n.to_string()).unwrap_or_default()}</span> })}
            </button>
        }
    };

    view! {
        <div class="network">
            <Show when=move || ctx.iface.get().is_some() fallback=move || view! {
                <div class="plist-empty static">{move || ctx.t("nw.no_iface")}</div>
            }>
                <Hero/>
                <div class="net-tabs">
                    {tab_btn(NetTab::Devices, "radar", "nw.t.devices")}
                    {tab_btn(NetTab::Network, "network", "nw.t.network")}
                    {tab_btn(NetTab::Security, "shield", "nw.t.security")}
                    {tab_btn(NetTab::Internet, "globe", "nw.t.internet")}
                </div>
                {move || match net.tab.get() {
                    NetTab::Devices => view! { <Devices/> }.into_any(),
                    NetTab::Network => view! { <Config/> }.into_any(),
                    NetTab::Security => view! { <Security/> }.into_any(),
                    NetTab::Internet => view! { <Internet/> }.into_any(),
                }}
            </Show>
        </div>
    }
}

#[component]
fn Hero() -> impl IntoView {
    let ctx = use_ctx();
    let net = use_net();
    view! {
        <div class="net-hero card">
            {move || {
                let Some(i) = net.info.get() else {
                    return view! { <div class="loading">{ctx.t("w.loading")}</div> }.into_any();
                };
                let title = i.wifi.as_ref().and_then(|w| w.ssid.clone()).unwrap_or_else(|| i.friendly.clone());
                let sub = format!("{} · {}", i.friendly, i.network.clone().unwrap_or_else(|| ctx.t("nw.no_ipv4").into()));
                let box_label = i.gateway.clone().map(|g| match &i.gateway_vendor {
                    Some(v) => format!("{g} · {v}"),
                    None => g,
                });
                let devices = net.devices.with(|d| d.as_ref().map(|d| (d.devices.len(), d.devices.iter().filter(|x| x.online).count())));
                let score = net.security.with(|s| s.as_ref().map(|s| s.score));
                let public = net.internet.with(|x| x.as_ref().and_then(|x| x.public_ip.clone().map(|ip| (ip, x.isp.clone()))));
                view! {
                    <div class="hero-ic"><Icon name=iface_icon(i.kind)/></div>
                    <div class="grow">
                        <h2 class="ell">{title}</h2>
                        <p class="dim ell">{sub}</p>
                    </div>
                    <div class="hero-stats">
                        {box_label.map(|b| view! { <div><small>{ctx.t("nw.h.router")}</small><strong class="ell">{b}</strong></div> })}
                        {devices.map(|(n, on)| view! { <div><small>{ctx.t("nw.h.devices")}</small><strong>{format!("{n}")}<span class="dim small">{format!(" · {on} {}", ctx.t("nw.online"))}</span></strong></div> })}
                        {score.map(|s| view! {
                            <div class="clickable" on:click=move |_| net.tab.set(NetTab::Security)>
                                <small>{ctx.t("nw.h.security")}</small>
                                <strong class=format!("score-text {}", score_class(s))>{format!("{s}/100")}</strong>
                            </div>
                        })}
                        {public.map(|(ip, isp)| view! { <div><small>{ctx.t("nw.h.internet")}</small><strong class="ell" title=isp.clone().unwrap_or_default()>{isp.clone().unwrap_or(ip)}</strong></div> })}
                    </div>
                }.into_any()
            }}
        </div>
    }
}

fn score_class(s: u8) -> &'static str {
    match s {
        80..=100 => "good",
        55..=79 => "mid",
        _ => "bad",
    }
}

// ---------------------------------------------------------------------------
// Appareils
// ---------------------------------------------------------------------------

#[component]
fn Devices() -> impl IntoView {
    let ctx = use_ctx();
    let net = use_net();
    let progress = move || net.progress_of("scan");
    let shown = Memo::new(move |_| {
        let q = net.query.get().to_lowercase();
        let lang = ctx.lang();
        net.devices.with(|l| {
            l.as_ref().map(|l| {
                l.devices
                    .iter()
                    .filter(|d| {
                        q.is_empty()
                            || [Some(d.ip.clone()), d.name.clone(), d.vendor.clone(), d.mac.clone(), d.model.clone(), Some(d.kind.label(lang).to_string())]
                                .iter()
                                .flatten()
                                .any(|s| s.to_lowercase().contains(&q))
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            })
        })
    });
    view! {
        <div class="net-bar">
            <button class="btn primary" on:click=move |_| net.scan() disabled=move || net.scanning.get()>
                <Icon name="radar"/>{move || if net.scanning.get() { ctx.t("nw.scanning") } else { ctx.t("nw.scan") }}
            </button>
            <div class="net-search">
                <Icon name="search" class="small"/>
                <input type="text" placeholder=move || ctx.t("nw.search") prop:value=move || net.query.get() on:input=move |ev| net.query.set(event_target_value(&ev))/>
            </div>
            <span class="spacer"></span>
            <span class="dim small">{move || net.devices.with(|d| d.as_ref().and_then(|d| d.scanned_at.clone().map(|at| {
                format!("{} {at} ({:.0} s)", ctx.t("nw.last_scan"), d.scan_duration.unwrap_or(0.0))
            })))}</span>
            <button class="icon-btn" title=move || ctx.t("db.refresh") on:click=move |_| net.reload_devices()><Icon name="refresh"/></button>
        </div>
        <Show when=move || net.scanning.get()>
            <div class="net-progress">
                <span>{move || match progress() {
                    Some(p) if p.phase == "names" => format!("{} ({}/{})", ctx.t("nw.p.names"), p.done, p.total),
                    Some(p) => format!("{} {}/{}", ctx.t("nw.p.sweep"), p.done, p.total),
                    None => ctx.t("nw.p.start").to_string(),
                }}</span>
                <div class="bar alt"><div style=move || {
                    let w = progress().map(|p| if p.phase == "names" { 80.0 + pct(&p) * 0.2 } else { pct(&p) * 0.8 }).unwrap_or(2.0);
                    format!("width:{w:.0}%")
                }></div></div>
            </div>
        </Show>
        {move || net.devices.with(|d| d.as_ref().and_then(|d| d.note.clone())).map(|n| view! { <div class="alert info"><Icon name="info"/><div class="grow"><p>{n}</p></div></div> })}
        <Show when=move || net.devices.with(|d| d.as_ref().is_some_and(|d| d.scanned_at.is_none())) && !net.scanning.get()>
            <div class="alert info">
                <Icon name="radar"/>
                <div class="grow"><strong>{move || ctx.t("nw.hint_t")}</strong><p>{move || ctx.t("nw.hint")}</p></div>
            </div>
        </Show>
        <div class="dev-list">
            {move || match shown.get() {
                None => view! { <div class="loading">{ctx.t("w.loading")}</div> }.into_any(),
                Some(list) if list.is_empty() => view! { <div class="plist-empty static">{ctx.t("nw.none")}</div> }.into_any(),
                Some(list) => list.into_iter().map(|d| view! { <DeviceRow d=d/> }).collect_view().into_any(),
            }}
        </div>
    }
}

#[component]
fn DeviceRow(d: NetDevice) -> impl IntoView {
    let ctx = use_ctx();
    let net = use_net();
    let lang = ctx.lang_untracked();
    let ip = d.ip.clone();
    let ip_open = ip.clone();
    let is_open = Memo::new(move |_| net.open.get().as_deref() == Some(ip_open.as_str()));
    let toggle = {
        let ip = ip.clone();
        move |_| net.open.update(|o| *o = if o.as_deref() == Some(ip.as_str()) { None } else { Some(ip.clone()) })
    };
    let name = display_name(&d, lang);
    let mut sub = vec![d.ip.clone()];
    if d.name.is_some() {
        sub.extend(d.vendor.clone());
    }
    sub.extend(d.model.clone());
    let risky = d.open_ports.as_ref().map(|p| p.iter().filter(|p| p.level >= CheckLevel::Warning).count()).unwrap_or(0);
    let kind_cls = format!("dev-ic kind-{:?}", d.kind).to_lowercase();
    let offline = !d.online;
    let detail = d.clone();
    view! {
        <div class="dev" class:open=move || is_open.get() class:offline=offline>
            <div class="dev-row" on:click=toggle>
                <div class=kind_cls title=d.kind.label(lang)><Icon name=device_icon(d.kind)/></div>
                <div class="grow">
                    <div class="dev-name">
                        <strong class="ell">{name}</strong>
                        {d.is_gateway.then(|| view! { <span class="badge accent">{ctx.t("nw.b.router")}</span> })}
                        {d.is_self.then(|| view! { <span class="badge good">{ctx.t("nw.b.self")}</span> })}
                        {d.random_mac.then(|| view! { <span class="badge" title=ctx.t("nw.b.random_h")>{ctx.t("nw.b.random")}</span> })}
                        {(risky > 0).then(|| view! { <span class="badge bad">{format!("⚠ {risky}")}</span> })}
                    </div>
                    <div class="dim small ell">{sub.join(" · ")}</div>
                </div>
                <div class="dev-svc">
                    {d.services.iter().take(3).map(|s| view! { <span class="chip mini">{s.clone()}</span> }).collect_view()}
                </div>
                {(d.bytes > 0).then(|| view! { <span class="dim small num" title=ctx.t("nw.traffic_h")>{fmt_bytes(d.bytes, lang)}</span> })}
                <span class=if d.online { "dot online" } else { "dot" } title=if d.online { ctx.t("nw.online") } else { ctx.t("nw.offline") }></span>
                <Icon name="chevron" class="small chev"/>
            </div>
            <Show when=move || is_open.get()>
                <DeviceDetail d=detail.clone()/>
            </Show>
        </div>
    }
}

#[component]
fn DeviceDetail(d: NetDevice) -> impl IntoView {
    let ctx = use_ctx();
    let net = use_net();
    let lang = ctx.lang_untracked();
    let ip = d.ip.clone();
    let ip_scan = ip.clone();
    let ip_busy = ip.clone();
    let busy = Memo::new(move |_| net.ports_busy.get().as_deref() == Some(ip_busy.as_str()));
    let has_traffic = d.packets > 0;
    let mut rows: Vec<(&'static str, String)> = vec![("nw.d.ip", d.ip.clone())];
    if !d.ipv6.is_empty() {
        rows.push(("nw.d.ipv6", d.ipv6.join("\n")));
    }
    if let Some(m) = &d.mac {
        rows.push(("nw.d.mac", m.clone()));
    }
    if let Some(v) = &d.vendor {
        rows.push(("nw.d.vendor", v.clone()));
    }
    if let Some(m) = &d.model {
        rows.push(("nw.d.model", m.clone()));
    }
    rows.push(("nw.d.kind", d.kind.label(lang).to_string()));
    if !d.names.is_empty() {
        rows.push(("nw.d.names", d.names.join("\n")));
    }
    if !d.services.is_empty() {
        rows.push(("nw.d.services", d.services.join(", ")));
    }
    if d.packets > 0 {
        rows.push(("nw.d.traffic", format!("{} · {} {}", fmt_bytes(d.bytes, lang), d.packets, ctx.tu("w.packets"))));
    }
    let src: Vec<&str> = d.sources.iter().map(|s| match s.as_str() {
        "arp" => ctx.tu("nw.src.arp"),
        "scan" => ctx.tu("nw.src.scan"),
        "capture" => ctx.tu("nw.src.capture"),
        _ => "",
    }).filter(|s| !s.is_empty()).collect();
    rows.push(("nw.d.sources", src.join(", ")));
    let progress = move || net.progress_of("ports");
    view! {
        <div class="dev-detail">
            <table class="fields">
                {rows.into_iter().map(|(k, v)| view! {
                    <tr><td class="fname">{ctx.t(k)}</td><td class="fval pre">{v}</td></tr>
                }).collect_view()}
            </table>
            {(d.random_mac).then(|| view! { <p class="dim small">"ℹ️ "{ctx.t("nw.b.random_h")}</p> })}
            <div class="ports">
                {match d.open_ports.clone() {
                    None => view! { <p class="dim small">{ctx.t("nw.ports_none_yet")}</p> }.into_any(),
                    Some(p) if p.is_empty() => view! { <p class="dim small">{ctx.t("nw.ports_closed")}</p> }.into_any(),
                    Some(p) => view! {
                        <h4>{ctx.t("nw.ports")}</h4>
                        {p.into_iter().map(|p| view! {
                            <div class=format!("port {}", level_class(p.level))>
                                <span class="mono">{p.port}</span>
                                <strong>{p.service.clone()}</strong>
                                <span class="dim small grow">{p.note.clone().unwrap_or_default()}</span>
                            </div>
                        }).collect_view()}
                    }.into_any(),
                }}
                <Show when=move || busy.get()>
                    <div class="bar alt"><div style=move || format!("width:{:.0}%", progress().map(|p| pct(&p)).unwrap_or(3.0))></div></div>
                </Show>
            </div>
            <div class="actions">
                <button class="btn small" disabled=move || net.ports_busy.get().is_some() on:click=move |_| net.scan_ports(ip_scan.clone())>
                    <Icon name="target"/>{move || if busy.get() { ctx.t("nw.ports_running") } else { ctx.t("nw.ports_btn") }}
                </button>
                {has_traffic.then(|| {
                    let f = format!("ip.addr == {ip}");
                    view! {
                        <button class="btn small" on:click=move |_| {
                            ctx.apply_filter(f.clone());
                            ctx.tab.set(Tab::Packets);
                        }><Icon name="filter"/>{ctx.t("nw.see_traffic")}</button>
                    }
                })}
                {(!d.is_self).then(|| {
                    let bpf = format!("host {}", d.ip);
                    view! {
                        <button class="btn small" title=ctx.t("nw.capture_h") disabled=move || ctx.running() on:click=move |_| {
                            ctx.capture_filter.set(bpf.clone());
                            ctx.start();
                        }><Icon name="play"/>{ctx.t("nw.capture")}</button>
                    }
                })}
            </div>
        </div>
    }
}

// ---------------------------------------------------------------------------
// Configuration du réseau
// ---------------------------------------------------------------------------

/// Ligne « libellé : valeur » avec une bulle d'aide.
fn kv(ctx: crate::state::Ctx, key: &'static str, help: Option<&'static str>, value: Option<String>) -> impl IntoView {
    value.map(|v| {
        view! {
            <tr>
                <td class="fname">{ctx.t(key)}{help.map(|h| view! { <span class="qm" title=ctx.t(h)>"?"</span> })}</td>
                <td class="fval pre">{v}</td>
            </tr>
        }
    })
}

#[component]
fn Config() -> impl IntoView {
    let ctx = use_ctx();
    let net = use_net();
    view! {
        <div class="net-bar">
            <span class="spacer"></span>
            <button class="icon-btn" title=move || ctx.t("db.refresh") on:click=move |_| net.load()><Icon name="refresh"/></button>
        </div>
        {move || {
            let Some(i) = net.info.get() else {
                return view! { <div class="loading">{ctx.t("w.loading")}</div> }.into_any();
            };
            let yes_no = |b: bool| if b { ctx.tu("nw.yes") } else { ctx.tu("nw.no") }.to_string();
            let mac = i.mac.clone().map(|m| match &i.vendor { Some(v) => format!("{m} ({v})"), None => m });
            let gw_mac = i.gateway_mac.clone().map(|m| match &i.gateway_vendor { Some(v) => format!("{m} ({v})"), None => m });
            let dns: Vec<String> = i.dns.iter().map(|d| {
                if Some(d) == i.gateway.as_ref() { format!("{d} ({})", ctx.tu("nw.the_router")) } else { d.clone() }
            }).collect();
            let speed = i.speed_mbps.map(|s| if s >= 1000 { format!("{:.1} Gbit/s", s as f64 / 1000.0) } else { format!("{s} Mbit/s") });
            let wifi = i.wifi.clone();
            view! {
                <div class="net-grid">
                    {wifi.map(|w| {
                        let sig = w.signal.unwrap_or(0);
                        let sig_cls = if sig >= 70 { "good" } else if sig >= 40 { "mid" } else { "bad" };
                        let sec_cls = match w.security {
                            WifiSecurity::Open | WifiSecurity::Wep => "bad",
                            WifiSecurity::Wpa => "mid",
                            WifiSecurity::Unknown => "",
                            _ => "good",
                        };
                        let sec = match (&w.auth, &w.cipher) {
                            (Some(a), Some(c)) => Some(format!("{a} · {c}")),
                            (Some(a), None) => Some(a.clone()),
                            _ => None,
                        };
                        let band = match (&w.band, w.channel) {
                            (Some(b), Some(c)) => Some(format!("{b} · {} {c}", ctx.tu("nw.c.channel"))),
                            (Some(b), None) => Some(b.clone()),
                            (None, Some(c)) => Some(format!("{} {c}", ctx.tu("nw.c.channel"))),
                            _ => None,
                        };
                        let rate = match (w.rx_mbps, w.tx_mbps) {
                            (Some(r), Some(t)) if r == t => Some(format!("{r} Mbit/s")),
                            (Some(r), Some(t)) => Some(format!("↓ {r} · ↑ {t} Mbit/s")),
                            (Some(r), None) | (None, Some(r)) => Some(format!("{r} Mbit/s")),
                            _ => None,
                        };
                        view! {
                            <section class="card">
                                <h3><Icon name="wifi"/>{ctx.t("nw.c.wifi")}</h3>
                                {w.note.clone().map(|n| view! { <div class="alert info"><Icon name="info"/><div class="grow"><p>{n}</p></div></div> })}
                                <div class="signal">
                                    <div class="sig-bars">
                                        {[20u32, 45, 70, 90].into_iter().map(|t| {
                                            let lit = sig >= t;
                                            view! { <span class:on=lit></span> }
                                        }).collect_view()}
                                    </div>
                                    <div>
                                        <strong class=format!("score-text {sig_cls}")>{format!("{sig} %")}</strong>
                                        <span class="dim small">{w.rssi.map(|r| format!(" · {r} dBm")).unwrap_or_default()}</span>
                                        <p class="dim small">{if sig >= 70 { ctx.t("nw.sig.good") } else if sig >= 40 { ctx.t("nw.sig.mid") } else { ctx.t("nw.sig.bad") }}</p>
                                    </div>
                                </div>
                                <table class="fields">
                                    {kv(ctx, "nw.c.ssid", Some("nw.c.ssid_h"), w.ssid.clone())}
                                    <tr>
                                        <td class="fname">{ctx.t("nw.c.security")}<span class="qm" title=ctx.t("nw.c.security_h")>"?"</span></td>
                                        <td class=format!("fval score-text {sec_cls}")>{sec.unwrap_or_else(|| "—".into())}</td>
                                    </tr>
                                    {kv(ctx, "nw.c.band", Some("nw.c.band_h"), band)}
                                    {kv(ctx, "nw.c.standard", None, w.standard.clone())}
                                    {kv(ctx, "nw.c.rate", Some("nw.c.rate_h"), rate)}
                                    {kv(ctx, "nw.c.bssid", Some("nw.c.bssid_h"), w.bssid.clone())}
                                </table>
                            </section>
                        }
                    })}
                    <section class="card">
                        <h3><Icon name=iface_icon(i.kind)/>{ctx.t("nw.c.link")}</h3>
                        <table class="fields">
                            {kv(ctx, "nw.c.iface", None, Some(i.friendly.clone()))}
                            {kv(ctx, "nw.c.adapter", None, i.description.clone())}
                            {kv(ctx, "nw.c.mac", Some("nw.c.mac_h"), mac)}
                            {kv(ctx, "nw.c.speed", Some("nw.c.speed_h"), speed)}
                            {kv(ctx, "nw.c.mtu", Some("nw.c.mtu_h"), i.mtu.map(|m| format!("{m} {}", ctx.tu("nw.bytes"))))}
                        </table>
                    </section>
                    <section class="card">
                        <h3><Icon name="network"/>{ctx.t("nw.c.ipv4")}</h3>
                        <table class="fields">
                            {kv(ctx, "nw.c.ip", Some("nw.c.ip_h"), i.ipv4.clone())}
                            {kv(ctx, "nw.c.mask", Some("nw.c.mask_h"), i.netmask.clone().map(|m| format!("{m} (/{})", i.prefix.unwrap_or(0))))}
                            {kv(ctx, "nw.c.range", Some("nw.c.range_h"), i.network.clone().map(|n| format!("{n} · {} {}", i.hosts.unwrap_or(0), ctx.tu("nw.addresses"))))}
                            {kv(ctx, "nw.c.broadcast", Some("nw.c.broadcast_h"), i.broadcast.clone())}
                            {kv(ctx, "nw.c.dhcp", Some("nw.c.dhcp_h"), i.dhcp.map(|d| match (&i.dhcp_server, d) {
                                (Some(s), true) => format!("{} · {s}", yes_no(true)),
                                _ => yes_no(d),
                            }))}
                            {kv(ctx, "nw.c.suffix", None, i.dns_suffix.clone())}
                        </table>
                    </section>
                    <section class="card">
                        <h3><Icon name="router"/>{ctx.t("nw.c.router")}</h3>
                        <table class="fields">
                            {kv(ctx, "nw.c.gw", Some("nw.c.gw_h"), i.gateway.clone().or_else(|| Some(ctx.tu("nw.none_short").into())))}
                            {kv(ctx, "nw.c.mac", None, gw_mac)}
                            {kv(ctx, "nw.c.gw6", None, i.gateway_v6.clone())}
                            {kv(ctx, "nw.c.dns", Some("nw.c.dns_h"), (!dns.is_empty()).then(|| dns.join("\n")))}
                        </table>
                    </section>
                    {(!i.ipv6.is_empty()).then(|| view! {
                        <section class="card">
                            <h3><Icon name="globe"/>"IPv6"<span class="qm" title=ctx.t("nw.c.ipv6_h")>"?"</span></h3>
                            <table class="fields">
                                {i.ipv6.iter().map(|a| {
                                    let kind = if a.starts_with("fe80") { ctx.tu("nw.v6.link") } else if a.starts_with("fd") || a.starts_with("fc") { ctx.tu("nw.v6.ula") } else { ctx.tu("nw.v6.global") };
                                    view! { <tr><td class="fname">{kind}</td><td class="fval">{a.clone()}</td></tr> }
                                }).collect_view()}
                            </table>
                        </section>
                    })}
                </div>
            }.into_any()
        }}
    }
}

// ---------------------------------------------------------------------------
// Sécurité
// ---------------------------------------------------------------------------

#[component]
fn Security() -> impl IntoView {
    let ctx = use_ctx();
    let net = use_net();
    let progress = move || net.progress_of("security");
    let go = move |f: String| {
        ctx.apply_filter(f);
        ctx.tab.set(Tab::Packets);
    };
    view! {
        <div class="net-bar">
            <button class="btn primary" disabled=move || net.sec_busy.get() on:click=move |_| net.load_security(true)>
                <Icon name="router"/>{move || if net.sec_busy.get() { ctx.t("nw.sec.running") } else { ctx.t("nw.sec.deep") }}
            </button>
            <span class="dim small grow">{move || ctx.t("nw.sec.deep_h")}</span>
            <button class="icon-btn" title=move || ctx.t("db.refresh") disabled=move || net.sec_busy.get() on:click=move |_| net.load_security(false)><Icon name="refresh"/></button>
        </div>
        <Show when=move || net.sec_busy.get() && progress().is_some()>
            <div class="net-progress">
                <span>{move || if progress().is_some_and(|p| p.phase == "upnp") { ctx.t("nw.sec.p_upnp") } else { ctx.t("nw.sec.p_ports") }}</span>
                <div class="bar alt"><div style=move || format!("width:{:.0}%", progress().map(|p| if p.phase == "upnp" { 95.0 } else { pct(&p) * 0.9 }).unwrap_or(2.0))></div></div>
            </div>
        </Show>
        {move || match net.security.get() {
            None => view! { <div class="loading">{ctx.t("w.loading")}</div> }.into_any(),
            Some(r) => {
                let cls = score_class(r.score);
                let deg = r.score as f64 * 3.6;
                let counts = |l: CheckLevel| r.checks.iter().filter(|c| c.level == l).count();
                let (danger, warn, info) = (counts(CheckLevel::Danger), counts(CheckLevel::Warning), counts(CheckLevel::Info));
                let verdict = match r.score {
                    80..=100 => ctx.t("nw.sec.v_good"),
                    55..=79 => ctx.t("nw.sec.v_mid"),
                    _ => ctx.t("nw.sec.v_bad"),
                };
                let has_capture = ctx.total.get_untracked() > 0;
                view! {
                    <div class="sec-head card">
                        <div class=format!("score-ring {cls}") style=format!("--deg:{deg:.0}deg")><div><strong>{r.score}</strong><small>"/100"</small></div></div>
                        <div class="grow">
                            <h3>{verdict}</h3>
                            <p class="dim">{format!("{danger} {} · {warn} {} · {info} {}", ctx.t("nw.sec.n_danger"), ctx.t("nw.sec.n_warn"), ctx.t("nw.sec.n_info"))}</p>
                            {(!r.deep).then(|| view! { <p class="dim small">{ctx.t("nw.sec.not_deep")}</p> })}
                        </div>
                    </div>
                    <div class="checks">
                        {r.checks.into_iter().map(|c| {
                            let filter = c.filter.clone().filter(|_| has_capture);
                            view! {
                                <div class=format!("alert {}", level_class(c.level))>
                                    <Icon name=level_icon(c.level)/>
                                    <div class="grow">
                                        <strong>{c.title.clone()}</strong>
                                        <p>{c.detail.clone()}</p>
                                        {c.advice.clone().map(|a| view! { <p class="advice">"💡 "{a}</p> })}
                                    </div>
                                    {filter.map(|f| view! { <button class="btn small" on:click=move |_| go(f.clone())>{ctx.t("db.see")}</button> })}
                                </div>
                            }
                        }).collect_view()}
                    </div>
                    <p class="dim small center">{ctx.t("nw.sec.foot")}</p>
                }.into_any()
            }
        }}
    }
}

// ---------------------------------------------------------------------------
// Internet
// ---------------------------------------------------------------------------

fn latency_rows(ctx: crate::state::Ctx, rows: Vec<LatencyResult>) -> impl IntoView {
    let max = rows.iter().filter_map(|r| r.ms).fold(1.0f64, f64::max);
    rows.into_iter().map(move |r| {
        let w = r.ms.map(|m| (m / max * 100.0).max(2.0)).unwrap_or(0.0);
        let cls = match r.ms {
            Some(m) if m < 30.0 => "good",
            Some(m) if m < 80.0 => "mid",
            Some(_) => "bad",
            None => "bad",
        };
        let detail = match (r.jitter_ms, r.lost) {
            (_, l) if r.ms.is_none() => format!("{} ({l})", ctx.tu("nw.i.lost")),
            (Some(j), 0) => format!("± {}", fmt_ms(Some(j))),
            (Some(j), l) => format!("± {} · {l} {}", fmt_ms(Some(j)), ctx.tu("nw.i.lost_n")),
            (None, _) => String::new(),
        };
        view! {
            <div class="bar-row static">
                <div class="bar-label">
                    <span class="ell">{r.label.clone()}</span>
                    <span class="dim small">{detail}</span>
                    <strong class=format!("score-text {cls}")>{fmt_ms(r.ms)}</strong>
                </div>
                <div class=format!("bar lat {cls}")><div style=format!("width:{w:.0}%")></div></div>
            </div>
        }
    }).collect_view()
}

#[component]
fn Internet() -> impl IntoView {
    let ctx = use_ctx();
    let net = use_net();
    let progress = move || net.progress_of("speed");
    view! {
        <div class="alert info">
            <Icon name="lock"/>
            <div class="grow"><p>{move || ctx.t("nw.i.privacy")}</p></div>
        </div>
        <div class="net-bar">
            <button class="btn primary" disabled=move || net.inet_busy.get() on:click=move |_| net.load_internet()>
                <Icon name="globe"/>{move || if net.inet_busy.get() { ctx.t("nw.i.running") } else { ctx.t("nw.i.check") }}
            </button>
            <button class="btn" disabled=move || net.speed_busy.get() on:click=move |_| net.speedtest()>
                <Icon name="gauge"/>{move || ctx.t("nw.i.speed")}
            </button>
        </div>
        <div class="net-grid">
            <section class="card">
                <h3><Icon name="globe"/>{move || ctx.t("nw.i.access")}</h3>
                {move || match net.internet.get() {
                    None => view! { <p class="dim">{if net.inet_busy.get() { ctx.t("w.loading") } else { ctx.t("nw.i.empty") }}</p> }.into_any(),
                    Some(i) => {
                        let place = [i.city.clone(), i.region.clone(), i.country.clone()].into_iter().flatten().collect::<Vec<_>>().join(", ");
                        let isp = match (&i.isp, &i.asn) {
                            (Some(n), Some(a)) => Some(format!("{n} ({a})")),
                            (Some(n), None) => Some(n.clone()),
                            (None, Some(a)) => Some(a.clone()),
                            _ => None,
                        };
                        view! {
                            <div class=if i.online { "alert ok" } else { "alert danger" }>
                                <Icon name=if i.online { "check" } else { "alert" }/>
                                <div class="grow"><strong>{if i.online { ctx.t("nw.i.online") } else { ctx.t("nw.i.offline") }}</strong></div>
                            </div>
                            <table class="fields">
                                {kv(ctx, "nw.i.ip", Some("nw.i.ip_h"), i.public_ip.clone())}
                                {kv(ctx, "nw.i.ip6", Some("nw.i.ip6_h"), Some(i.public_ipv6.clone().unwrap_or_else(|| ctx.tu("nw.i.no_v6").into())))}
                                {kv(ctx, "nw.i.isp", Some("nw.i.isp_h"), isp)}
                                {kv(ctx, "nw.i.place", Some("nw.i.place_h"), (!place.is_empty()).then_some(place))}
                                {kv(ctx, "nw.i.reverse", None, i.reverse.clone())}
                                {kv(ctx, "nw.i.edge", Some("nw.i.edge_h"), i.edge.clone().map(|e| format!("Cloudflare {e}")))}
                            </table>
                            {(!i.errors.is_empty()).then(|| view! { <p class="dim small">{i.errors.join(" · ")}</p> })}
                        }.into_any()
                    }
                }}
            </section>
            <section class="card">
                <h3><Icon name="zap"/>{move || ctx.t("nw.i.latency")}</h3>
                {move || match net.internet.get() {
                    None => view! { <p class="dim">{ctx.t("nw.i.latency_h")}</p> }.into_any(),
                    Some(i) => view! {
                        {latency_rows(ctx, i.latency)}
                        <h4 class="sub">{ctx.t("nw.i.dns")}<span class="qm" title=ctx.t("nw.i.dns_h")>"?"</span></h4>
                        {latency_rows(ctx, i.dns)}
                    }.into_any(),
                }}
            </section>
        </div>
        <section class="card speed">
            <h3><Icon name="gauge"/>{move || ctx.t("nw.i.speed_t")}</h3>
            {move || {
                let live = net.speed_busy.get();
                let p = progress();
                let res = net.speed.get();
                if live {
                    let phase = p.as_ref().map(|p| p.phase.clone()).unwrap_or_default();
                    let label = match phase.as_str() {
                        "download" => ctx.t("nw.i.down"),
                        "upload" => ctx.t("nw.i.up"),
                        _ => ctx.t("nw.i.ping"),
                    };
                    let value = p.as_ref().and_then(|p| p.value).unwrap_or(0.0);
                    let w = p.as_ref().map(pct).unwrap_or(0.0);
                    return view! {
                        <div class="speed-live">
                            <small>{label}</small>
                            <strong>{fmt_mbps(value)}<span>" Mbit/s"</span></strong>
                            <div class="bar alt"><div style=format!("width:{w:.0}%")></div></div>
                            <button class="btn small" on:click=move |_| spawn_local(async move { let _ = call0::<()>("net_speed_cancel").await; })>{ctx.t("nw.i.cancel")}</button>
                        </div>
                    }.into_any();
                }
                match res {
                    None => view! { <p class="dim">{ctx.t("nw.i.speed_h")}</p> }.into_any(),
                    Some(r) => {
                        let bloat = match (r.latency_ms, r.loaded_latency_ms) {
                            (Some(a), Some(b)) if b - a > 100.0 => Some(ctx.t("nw.i.bloat")),
                            _ => None,
                        };
                        let uses = speed_uses(ctx, &r);
                        view! {
                            <div class="speed-grid">
                                <div class="speed-big"><small>"↓ "{ctx.t("nw.i.down")}</small><strong>{fmt_mbps(r.download_mbps)}<span>" Mbit/s"</span></strong></div>
                                <div class="speed-big"><small>"↑ "{ctx.t("nw.i.up")}</small><strong>{fmt_mbps(r.upload_mbps)}<span>" Mbit/s"</span></strong></div>
                                <div class="speed-small">
                                    <div><small>{ctx.t("nw.i.ping")}</small><strong>{fmt_ms(r.latency_ms)}</strong></div>
                                    <div><small>{ctx.t("nw.i.jitter")}</small><strong>{fmt_ms(r.jitter_ms)}</strong></div>
                                    <div title=ctx.t("nw.i.loaded_h")><small>{ctx.t("nw.i.loaded")}</small><strong>{fmt_ms(r.loaded_latency_ms)}</strong></div>
                                </div>
                            </div>
                            <ul class="tips">{uses.into_iter().map(|u| view! { <li>{u}</li> }).collect_view()}</ul>
                            {bloat.map(|b| view! { <div class="alert warning"><Icon name="alert"/><div class="grow"><p>{b}</p></div></div> })}
                            <p class="dim small">{format!("{} {} · ↓ {} · ↑ {}", ctx.t("nw.i.server"), r.server, fmt_bytes(r.bytes_down, ctx.lang()), fmt_bytes(r.bytes_up, ctx.lang()))}</p>
                        }.into_any()
                    }
                }
            }}
        </section>
    }
}

/// Ce que permet la connexion mesurée, en langage simple.
fn speed_uses(ctx: crate::state::Ctx, r: &SpeedResult) -> Vec<&'static str> {
    let mut v = Vec::new();
    v.push(if r.download_mbps >= 25.0 {
        ctx.tu("nw.u.4k")
    } else if r.download_mbps >= 5.0 {
        ctx.tu("nw.u.hd")
    } else if r.download_mbps >= 1.5 {
        ctx.tu("nw.u.sd")
    } else {
        ctx.tu("nw.u.slow")
    });
    v.push(if r.upload_mbps >= 3.0 { ctx.tu("nw.u.visio") } else { ctx.tu("nw.u.visio_low") });
    if r.latency_ms.is_some_and(|l| l < 40.0) && r.jitter_ms.unwrap_or(0.0) < 15.0 {
        v.push(ctx.tu("nw.u.game"));
    }
    v
}
