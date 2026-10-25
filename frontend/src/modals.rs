use leptos::prelude::*;
use leptos::task::spawn_local;
use rustshark_shared::filter::{FIELDS, Kind};
use rustshark_shared::{Lang, ModelInfo, Provider, Theme};
use serde::Serialize;

use crate::api::call;
use crate::icons::{iface_icon, Icon};
use crate::state::{use_ctx, Modal, ToastKind};

#[component]
pub fn Modals() -> impl IntoView {
    let ctx = use_ctx();
    view! {
        {move || match ctx.modal.get() {
            Modal::None => ().into_any(),
            Modal::Settings => view! { <Shell title="mo.settings" wide=true><SettingsBody/></Shell> }.into_any(),
            Modal::Help => view! { <Shell title="mo.help" wide=true><HelpBody/></Shell> }.into_any(),
            Modal::Interfaces => view! { <Shell title="mo.ifaces" wide=false><InterfacesBody/></Shell> }.into_any(),
        }}
    }
}

#[component]
fn Shell(title: &'static str, wide: bool, children: Children) -> impl IntoView {
    let ctx = use_ctx();
    view! {
        <div class="overlay" on:mousedown=move |_| ctx.modal.set(Modal::None)>
            <div class=if wide { "modal wide" } else { "modal" } on:mousedown=|ev| ev.stop_propagation()>
                <div class="modal-head">
                    <h2>{move || ctx.t(title)}</h2>
                    <button class="icon-btn" on:click=move |_| ctx.modal.set(Modal::None)><Icon name="x"/></button>
                </div>
                <div class="modal-body">{children()}</div>
            </div>
        </div>
    }
}

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct BpfArg {
    filter: String,
}

#[component]
fn InterfacesBody() -> impl IntoView {
    let ctx = use_ctx();
    let show_all = RwSignal::new(false);
    let bpf_error = RwSignal::new(None::<String>);
    Effect::new(move |_| ctx.probe());
    let max_act = Memo::new(move |_| ctx.activity.with(|a| a.values().copied().max().unwrap_or(0)).max(1));
    let list = Memo::new(move |_| {
        let all = show_all.get();
        ctx.interfaces.with(|l| l.iter().filter(|i| all || i.connected).cloned().collect::<Vec<_>>())
    });
    let validate = move |f: String| {
        spawn_local(async move {
            let res = call::<_, ()>("validate_capture_filter", &BpfArg { filter: f }).await;
            bpf_error.set(res.err());
        });
    };
    view! {
        <p class="dim">{move || ctx.t("if.intro")}</p>
        <div class="iface-list">
            <For each=move || list.get() key=|i| i.name.clone() children=move |i| {
                let (n1, n2, n3) = (i.name.clone(), i.name.clone(), i.name.clone());
                let addrs = i.addresses.join(" · ");
                view! {
                    <button class="iface-row" class:on=move || ctx.iface.get().as_deref() == Some(n1.as_str())
                        on:click=move |_| ctx.iface.set(Some(n2.clone()))
                        on:dblclick=move |_| { ctx.modal.set(Modal::None); ctx.start(); }>
                        <Icon name=iface_icon(i.kind)/>
                        <div class="grow">
                            <div class="row-title">
                                <strong>{i.friendly.clone()}</strong>
                                {i.recommended.then(|| view! { <span class="badge good">{move || ctx.t("if.recommended")}</span> })}
                                {(!i.connected).then(|| view! { <span class="badge">{move || ctx.t("if.disconnected")}</span> })}
                            </div>
                            <small class="dim ell">{i.description.clone()}</small>
                            <small class="dim ell mono">{addrs}</small>
                        </div>
                        <div class="activity wide" title=move || ctx.t("if.activity")>
                            <div style=move || {
                                let n = ctx.activity.with(|a| a.get(&n3).copied().unwrap_or(0));
                                format!("width:{}%", (n as f64 / max_act.get() as f64 * 100.0).max(if n > 0 { 5.0 } else { 0.0 }))
                            }></div>
                        </div>
                    </button>
                }
            }/>
        </div>
        <div class="row gap">
            <label class="check"><input type="checkbox" prop:checked=move || show_all.get() on:change=move |ev| show_all.set(event_target_checked(&ev))/>{move || ctx.t("if.show_all")}</label>
            <span class="spacer"></span>
            <button class="btn small" on:click=move |_| ctx.probe() disabled=move || ctx.probing.get()>
                <Icon name="refresh"/>{move || if ctx.probing.get() { ctx.t("if.probing") } else { ctx.t("if.probe") }}
            </button>
        </div>
        <details class="advanced">
            <summary>{move || ctx.t("if.advanced")}</summary>
            <label class="field">
                <span>{move || ctx.t("if.bpf")}<span class="qm" title=move || ctx.t("bd.capture_filter_h")>"?"</span></span>
                <input type="text" class="mono" placeholder="port 53 or host 192.168.1.1" prop:value=move || ctx.capture_filter.get()
                    on:input=move |ev| ctx.capture_filter.set(event_target_value(&ev))
                    on:change=move |ev| validate(event_target_value(&ev))/>
                {move || bpf_error.get().map(|e| view! { <small class="bad">{e}</small> })}
            </label>
            <label class="check">
                <input type="checkbox" prop:checked=move || ctx.settings.with(|s| s.promiscuous) on:change=move |ev| {
                    let mut s = ctx.settings.get_untracked();
                    s.promiscuous = event_target_checked(&ev);
                    ctx.save_settings(s);
                }/>
                {move || ctx.t("if.promisc")}
            </label>
        </details>
        <div class="modal-actions">
            <button class="btn" on:click=move |_| ctx.modal.set(Modal::None)>{move || ctx.t("w.close")}</button>
            <button class="btn primary" on:click=move |_| { ctx.modal.set(Modal::None); ctx.start(); } disabled=move || ctx.iface.get().is_none()>
                <Icon name="play"/>{move || ctx.t("wl.start")}
            </button>
        </div>
    }
}

// ---------------------------------------------------------------------------
// Réglages
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct KeyArg {
    provider: Provider,
    key: String,
}

#[derive(Serialize)]
struct ProviderArg {
    provider: Provider,
}

#[component]
fn SettingsBody() -> impl IntoView {
    let ctx = use_ctx();
    let section = ctx.settings_section;
    let sec_btn = move |id: &'static str, icon: &'static str, key: &'static str| {
        view! {
            <button class:on=move || section.get() == id on:click=move |_| section.set(id)><Icon name=icon/>{move || ctx.t(key)}</button>
        }
    };
    view! {
        <div class="settings">
            <nav class="settings-nav">
                {sec_btn("general", "settings", "se.general")}
                {sec_btn("ai", "sparkles", "se.ai")}
                {sec_btn("about", "info", "se.about")}
            </nav>
            <div class="settings-content">
                {move || match section.get() {
                    "ai" => view! { <AiSettings/> }.into_any(),
                    "about" => view! { <About/> }.into_any(),
                    _ => view! { <GeneralSettings/> }.into_any(),
                }}
            </div>
        </div>
    }
}

#[component]
fn GeneralSettings() -> impl IntoView {
    let ctx = use_ctx();
    let update = move |f: &dyn Fn(&mut rustshark_shared::AppSettings)| {
        let mut s = ctx.settings.get_untracked();
        f(&mut s);
        ctx.save_settings(s);
    };
    view! {
        <div class="form">
            <label class="field">
                <span>{move || ctx.t("se.language")}</span>
                <div class="segmented">
                    <button class:on=move || ctx.lang() == Lang::Fr on:click=move |_| update(&|s| s.language = Lang::Fr)>"🇫🇷 Français"</button>
                    <button class:on=move || ctx.lang() == Lang::En on:click=move |_| update(&|s| s.language = Lang::En)>"🇬🇧 English"</button>
                </div>
            </label>
            <label class="field">
                <span>{move || ctx.t("se.theme")}</span>
                <div class="segmented">
                    <button class:on=move || ctx.settings.with(|s| s.theme == Theme::System) on:click=move |_| update(&|s| s.theme = Theme::System)>{move || ctx.t("se.theme.system")}</button>
                    <button class:on=move || ctx.settings.with(|s| s.theme == Theme::Light) on:click=move |_| update(&|s| s.theme = Theme::Light)>{move || ctx.t("se.theme.light")}</button>
                    <button class:on=move || ctx.settings.with(|s| s.theme == Theme::Dark) on:click=move |_| update(&|s| s.theme = Theme::Dark)>{move || ctx.t("se.theme.dark")}</button>
                </div>
            </label>
            <label class="check">
                <input type="checkbox" prop:checked=move || ctx.settings.with(|s| s.simple_mode)
                    on:change=move |ev| { let v = event_target_checked(&ev); update(&move |s| s.simple_mode = v) }/>
                <div><strong>{move || ctx.t("se.simple")}</strong><small class="dim">{move || ctx.t("se.simple_h")}</small></div>
            </label>
            <label class="check">
                <input type="checkbox" prop:checked=move || ctx.settings.with(|s| s.resolve_names)
                    on:change=move |ev| { let v = event_target_checked(&ev); update(&move |s| s.resolve_names = v) }/>
                <div><strong>{move || ctx.t("se.names")}</strong><small class="dim">{move || ctx.t("se.names_h")}</small></div>
            </label>
            <label class="check">
                <input type="checkbox" prop:checked=move || ctx.settings.with(|s| s.promiscuous)
                    on:change=move |ev| { let v = event_target_checked(&ev); update(&move |s| s.promiscuous = v) }/>
                <div><strong>{move || ctx.t("if.promisc")}</strong><small class="dim">{move || ctx.t("se.promisc_h")}</small></div>
            </label>
            <label class="field">
                <span>{move || ctx.t("se.max")}</span>
                <select on:change=move |ev| { let v: u32 = event_target_value(&ev).parse().unwrap_or(1_000_000); update(&move |s| s.max_packets = v) }>
                    {[100_000u32, 500_000, 1_000_000, 3_000_000].into_iter().map(|n| view! {
                        <option value=n.to_string() selected=move || ctx.settings.with(|s| s.max_packets == n)>{crate::util::fmt_count(n as u64)}</option>
                    }).collect_view()}
                </select>
                <small class="dim">{move || ctx.t("se.max_h")}</small>
            </label>
        </div>
    }
}

#[component]
fn AiSettings() -> impl IntoView {
    let ctx = use_ctx();
    let key_input = RwSignal::new(String::new());
    let test_result = RwSignal::new(None::<Result<String, String>>);
    let busy = RwSignal::new(false);
    let models = RwSignal::new(Vec::<ModelInfo>::new());
    let models_err = RwSignal::new(None::<String>);
    let provider = Memo::new(move |_| ctx.settings.with(|s| s.ai.provider));
    let keystore = Memo::new(move |_| ctx.sys.with(|s| s.as_ref().map(|s| s.keystore_name.clone()).unwrap_or_default()));

    let set_provider = move |p: Provider| {
        let mut s = ctx.settings.get_untracked();
        s.ai.provider = p;
        ctx.save_settings(s);
        test_result.set(None);
        models.set(Vec::new());
        models_err.set(None);
    };
    let save_key = move || {
        let key = key_input.get_untracked();
        if key.trim().is_empty() {
            return;
        }
        let provider = provider.get_untracked();
        busy.set(true);
        spawn_local(async move {
            match call::<_, ()>("set_api_key", &KeyArg { provider, key }).await {
                Ok(()) => {
                    key_input.set(String::new());
                    ctx.reload_keys();
                    ctx.toast(ToastKind::Success, ctx.tu("se.key_saved"));
                    if let Ok(msg) = call::<_, String>("ai_test", &ProviderArg { provider }).await {
                        test_result.set(Some(Ok(msg)));
                    }
                }
                Err(e) => ctx.toast(ToastKind::Error, e),
            }
            busy.set(false);
        });
    };
    let delete_key = move || {
        let provider = provider.get_untracked();
        spawn_local(async move {
            let _ = call::<_, ()>("delete_api_key", &ProviderArg { provider }).await;
            ctx.reload_keys();
            test_result.set(None);
        });
    };
    let test = move || {
        let provider = provider.get_untracked();
        busy.set(true);
        spawn_local(async move {
            test_result.set(Some(call::<_, String>("ai_test", &ProviderArg { provider }).await));
            busy.set(false);
        });
    };
    let load_models = move || {
        let provider = provider.get_untracked();
        models_err.set(None);
        spawn_local(async move {
            match call::<_, Vec<ModelInfo>>("ai_models", &ProviderArg { provider }).await {
                Ok(m) => models.set(m),
                Err(e) => models_err.set(Some(e)),
            }
        });
    };
    // Effacement de toutes les clés : un premier clic arme, un second confirme.
    let wipe_armed = RwSignal::new(false);
    let any_key = Memo::new(move |_| ctx.keys.with(|k| k.deepseek || k.openrouter));
    let wipe = move || {
        if !wipe_armed.get_untracked() {
            wipe_armed.set(true);
            set_timeout(move || wipe_armed.set(false), std::time::Duration::from_secs(5));
            return;
        }
        wipe_armed.set(false);
        spawn_local(async move {
            match call::<_, u32>("delete_all_api_keys", &crate::api::NoArgs {}).await {
                Ok(n) => {
                    test_result.set(None);
                    ctx.toast(ToastKind::Success, format!("{} ({n})", ctx.tu("se.wiped")));
                }
                Err(e) => ctx.toast(ToastKind::Error, e),
            }
            ctx.reload_keys();
        });
    };
    let set_model = move |m: String| {
        let mut s = ctx.settings.get_untracked();
        match s.ai.provider {
            Provider::DeepSeek => s.ai.deepseek_model = m,
            Provider::OpenRouter => s.ai.openrouter_model = m,
        }
        ctx.save_settings(s);
    };

    view! {
        <div class="form">
            <p class="dim">{move || ctx.t("se.ai_intro")}</p>
            <div class="provider-cards">
                {Provider::ALL.into_iter().map(|p| view! {
                    <button class="provider-card" class:on=move || provider.get() == p on:click=move |_| set_provider(p)>
                        <strong>{p.label()}</strong>
                        <small class="dim">{move || ctx.t(if p == Provider::DeepSeek { "se.ds_desc" } else { "se.or_desc" })}</small>
                        {move || ctx.keys.with(|k| k.has(p)).then(|| view! { <span class="badge good"><Icon name="lock" class="small"/>{ctx.t("se.key_ok")}</span> })}
                    </button>
                }).collect_view()}
            </div>

            <div class="field">
                <span>{move || format!("{} {}", ctx.t("se.api_key"), provider.get().label())}</span>
                {move || if ctx.keys.with(|k| k.has(provider.get())) {
                    view! {
                        <div class="key-row">
                            <span class="key-saved"><Icon name="lock"/>{ctx.t("se.key_in_store")}" "<em>{keystore.get()}</em></span>
                            <button class="btn small" on:click=move |_| test() disabled=move || busy.get()><Icon name="check"/>{ctx.t("se.test")}</button>
                            <button class="btn small danger-ghost" on:click=move |_| delete_key()><Icon name="trash"/>{ctx.t("se.delete_key")}</button>
                        </div>
                    }.into_any()
                } else {
                    view! {
                        <div class="key-row">
                            <input type="password" autocomplete="off" placeholder="sk-…" prop:value=move || key_input.get()
                                on:input=move |ev| key_input.set(event_target_value(&ev))
                                on:keydown=move |ev: web_sys::KeyboardEvent| if ev.key() == "Enter" { save_key() }/>
                            <button class="btn primary small" on:click=move |_| save_key() disabled=move || busy.get() || key_input.get().trim().is_empty()>
                                <Icon name="lock"/>{ctx.t("se.save_key")}
                            </button>
                        </div>
                    }.into_any()
                }}
                <small class="dim">
                    {move || ctx.t("se.key_h")}" "
                    <button class="link" on:click=move |_| ctx.open_url(crate::ai_panel::provider_key_url(provider.get_untracked()))>{move || ctx.t("se.get_key")}</button>
                </small>
                {move || ctx.keys.get().store_error.map(|e| view! { <small class="bad">{format!("{} {e}", ctx.t("se.store_err"))}</small> })}
                {move || test_result.get().map(|r| match r {
                    Ok(m) => view! { <div class="test ok">{m}</div> }.into_any(),
                    Err(e) => view! { <div class="test bad">{e}</div> }.into_any(),
                })}
            </div>

            <div class="field">
                <span>{move || ctx.t("se.model")}</span>
                <div class="key-row">
                    <input type="text" class="mono" list="model-list" prop:value=move || ctx.settings.with(|s| s.ai.model().to_string())
                        on:change=move |ev| set_model(event_target_value(&ev))/>
                    <button class="btn small" on:click=move |_| load_models()><Icon name="refresh"/>{move || ctx.t("se.models")}</button>
                </div>
                <datalist id="model-list">
                    <For each=move || models.get() key=|m| m.id.clone() children=move |m| view! {
                        <option value=m.id.clone()>{format!("{}{}", m.name, if m.free { " (free)" } else { "" })}</option>
                    }/>
                </datalist>
                <small class="dim">{move || if provider.get() == Provider::DeepSeek { ctx.t("se.model_ds") } else { ctx.t("se.model_or") }}</small>
                {move || (!models.with(|m| m.is_empty())).then(|| view! { <small class="dim">{format!("{} {}", models.with(|m| m.len()), ctx.t("se.models_n"))}</small> })}
                {move || models_err.get().map(|e| view! { <small class="bad">{e}</small> })}
            </div>

            <label class="check">
                <input type="checkbox" prop:checked=move || ctx.settings.with(|s| s.ai.anonymize) on:change=move |ev| {
                    let mut s = ctx.settings.get_untracked();
                    s.ai.anonymize = event_target_checked(&ev);
                    ctx.save_settings(s);
                }/>
                <div><strong>{move || ctx.t("se.anon")}</strong><small class="dim">{move || ctx.t("se.anon_h")}</small></div>
            </label>
            <label class="field">
                <span>{move || format!("{} : {}", ctx.t("se.sample"), ctx.settings.with(|s| s.ai.sample_packets))}</span>
                <input type="range" min="20" max="300" step="10" prop:value=move || ctx.settings.with(|s| s.ai.sample_packets.to_string())
                    on:change=move |ev| {
                        let mut s = ctx.settings.get_untracked();
                        s.ai.sample_packets = event_target_value(&ev).parse().unwrap_or(60);
                        ctx.save_settings(s);
                    }/>
                <small class="dim">{move || ctx.t("se.sample_h")}</small>
            </label>
            <div class="privacy card">
                <Icon name="shield"/>
                <p>{move || ctx.t("se.privacy")}</p>
            </div>
            <div class="danger-zone">
                <div class="grow">
                    <strong>{move || ctx.t("se.wipe")}</strong>
                    <small class="dim">{move || format!("{} {}", ctx.t("se.wipe_h"), keystore.get())}</small>
                </div>
                <button class="btn small" class:danger=move || wipe_armed.get() class:danger-ghost=move || !wipe_armed.get()
                    on:click=move |_| wipe() disabled=move || !any_key.get()>
                    <Icon name="trash"/>
                    {move || if wipe_armed.get() { ctx.t("se.wipe_confirm") } else { ctx.t("se.wipe_btn") }}
                </button>
            </div>
        </div>
    }
}

#[component]
fn About() -> impl IntoView {
    let ctx = use_ctx();
    view! {
        <div class="about">
            <img src="icon.svg" class="hero-logo small" alt=""/>
            <h3>{move || format!("RustShark {}", ctx.sys.get().map(|s| s.app_version).unwrap_or_default())}</h3>
            <p>{move || ctx.t("ab.text")}</p>
            <ul class="dim small">
                <li>{move || format!("{} {}", ctx.t("ab.capture"), ctx.sys.get().and_then(|s| s.pcap_version).unwrap_or_else(|| "—".into()))}</li>
                <li>{move || format!("{} {}", ctx.t("ab.keystore"), ctx.sys.get().map(|s| s.keystore_name).unwrap_or_default())}</li>
                <li>{move || format!("{} {}", ctx.t("ab.os"), ctx.sys.get().map(|s| s.os).unwrap_or_default())}</li>
                <li>"Rust · Tauri 2 · Leptos 0.8"</li>
            </ul>
            <p class="dim small">{move || ctx.t("wl.legal")}</p>
        </div>
    }
}

// ---------------------------------------------------------------------------
// Aide
// ---------------------------------------------------------------------------

const GLOSSARY: &[&str] = &["ip", "mac", "port", "packet", "dns", "tcp", "udp", "tls", "http", "arp", "dhcp", "quic", "lan", "broadcast", "filter", "bpf"];

const EXAMPLES: &[(&str, &str)] = &[
    ("dns", "hx.dns"),
    ("tls.sni contains youtube", "hx.sni"),
    ("ip.addr == 192.168.1.0/24 && !arp", "hx.lan"),
    ("tcp.port == 443 || udp.port == 443", "hx.443"),
    ("host == *.google.com", "hx.glob"),
    ("frame.len > 1000", "hx.len"),
    ("tcp.flags.syn && !tcp.flags.ack", "hx.syn"),
    ("internet && !tls && !quic", "hx.inet"),
    ("netflix", "hx.text"),
];

#[component]
fn HelpBody() -> impl IntoView {
    let ctx = use_ctx();
    let tab = RwSignal::new(0u8);
    let tab_btn = move |i: u8, key: &'static str| view! { <button class:on=move || tab.get() == i on:click=move |_| tab.set(i)>{move || ctx.t(key)}</button> };
    view! {
        <div class="segmented">
            {tab_btn(0, "hp.start")}
            {tab_btn(1, "hp.filters")}
            {tab_btn(2, "hp.glossary")}
            {tab_btn(3, "hp.keys")}
        </div>
        <div class="help">
            {move || match tab.get() {
                0 => view! {
                    <div class="help-start">
                        <h3>{ctx.t("hp.what")}</h3>
                        <p>{ctx.t("hp.what_d")}</p>
                        <h3>{ctx.t("hp.how")}</h3>
                        <ol>
                            <li>{ctx.t("hp.how1")}</li>
                            <li>{ctx.t("hp.how2")}</li>
                            <li>{ctx.t("hp.how3")}</li>
                            <li>{ctx.t("hp.how4")}</li>
                            <li>{ctx.t("hp.how5")}</li>
                        </ol>
                        <h3>{ctx.t("hp.colors")}</h3>
                        <div class="legend-grid">
                            {rustshark_shared::Category::ALL.into_iter().map(|c| view! {
                                <span class=format!("cat-badge cat-{}", c.id())>{c.label(ctx.lang_untracked())}</span>
                            }).collect_view()}
                        </div>
                        <h3>{ctx.t("hp.normal")}</h3>
                        <p>{ctx.t("hp.normal_d")}</p>
                    </div>
                }.into_any(),
                1 => view! {
                    <div>
                        <p>{ctx.t("hp.filters_d")}</p>
                        <table class="table">
                            <tbody>
                                {EXAMPLES.iter().map(|(f, k)| {
                                    let f = f.to_string();
                                    let f2 = f.clone();
                                    view! {
                                        <tr>
                                            <td><code class="fchip" on:click=move |_| { ctx.apply_filter(f2.clone()); ctx.modal.set(Modal::None); }>{f}</code></td>
                                            <td>{ctx.t(k)}</td>
                                        </tr>
                                    }
                                }).collect_view()}
                            </tbody>
                        </table>
                        <h3>{ctx.t("hp.fields")}</h3>
                        <table class="table fields-ref">
                            <tbody>
                                {FIELDS.iter().map(|d| {
                                    let kind = match d.kind { Kind::Flag => "✓", Kind::Ip => "IP", Kind::Num => "123", Kind::Text => "abc" };
                                    view! {
                                        <tr>
                                            <td><code>{d.name}</code></td>
                                            <td class="dim">{kind}</td>
                                            <td>{if ctx.lang_untracked() == Lang::Fr { d.fr } else { d.en }}</td>
                                        </tr>
                                    }
                                }).collect_view()}
                            </tbody>
                        </table>
                    </div>
                }.into_any(),
                2 => view! {
                    <dl class="glossary">
                        {GLOSSARY.iter().map(|g| {
                            let term = format!("gl.{g}");
                            let def = format!("gl.{g}.d");
                            view! {
                                <dt>{crate::i18n::t_dyn(ctx.lang_untracked(), &term)}</dt>
                                <dd>{crate::i18n::t_dyn(ctx.lang_untracked(), &def)}</dd>
                            }
                        }).collect_view()}
                    </dl>
                }.into_any(),
                _ => view! {
                    <table class="table">
                        <tbody>
                            <tr><td><kbd>"Ctrl"</kbd>" + "<kbd>"F"</kbd></td><td>{ctx.t("hp.k_filter")}</td></tr>
                            <tr><td><kbd>"Ctrl"</kbd>" + "<kbd>"E"</kbd></td><td>{ctx.t("hp.k_capture")}</td></tr>
                            <tr><td><kbd>"↑"</kbd>" / "<kbd>"↓"</kbd></td><td>{ctx.t("hp.k_nav")}</td></tr>
                            <tr><td><kbd>"Ctrl"</kbd>" + "<kbd>"I"</kbd></td><td>{ctx.t("hp.k_ai")}</td></tr>
                            <tr><td><kbd>"Échap"</kbd></td><td>{ctx.t("hp.k_esc")}</td></tr>
                            <tr><td>{ctx.t("hp.k_drop_k")}</td><td>{ctx.t("hp.k_drop")}</td></tr>
                        </tbody>
                    </table>
                }.into_any(),
            }}
        </div>
    }
}
