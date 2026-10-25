use leptos::prelude::*;
use rustshark_shared::filter;
use rustshark_shared::CaptureState;

use crate::icons::{iface_icon, Icon};
use crate::state::{use_ctx, Modal};
use crate::util::{fmt_count, fmt_duration};

#[component]
pub fn Toolbar() -> impl IntoView {
    let ctx = use_ctx();
    let running = Memo::new(move |_| ctx.running());
    let has_packets = Memo::new(move |_| ctx.total.get() > 0);
    let simple = Memo::new(move |_| ctx.settings.with(|s| s.simple_mode));
    let iface_label = Memo::new(move |_| {
        let sel = ctx.iface.get();
        ctx.interfaces.with(|l| l.iter().find(|i| Some(&i.name) == sel.as_ref()).map(|i| (i.friendly.clone(), iface_icon(i.kind))))
    });
    let set_simple = move |v: bool| {
        let mut s = ctx.settings.get_untracked();
        if s.simple_mode != v {
            s.simple_mode = v;
            ctx.save_settings(s);
        }
    };

    view! {
        <header class="toolbar">
            <div class="brand">
                <img src="icon.svg" alt="" class="logo"/>
                <span>"RustShark"</span>
            </div>

            <button class="iface-btn" title=move || ctx.t("tb.iface_tip") on:click=move |_| ctx.modal.set(Modal::Interfaces) disabled=move || running.get()>
                {move || match iface_label.get() {
                    Some((name, icon)) => view! { <Icon name=icon/><span class="iface-name">{name}</span> }.into_any(),
                    None => view! { <Icon name="monitor"/><span class="iface-name">{ctx.t("tb.choose_iface")}</span> }.into_any(),
                }}
                <Icon name="chevron" class="small"/>
            </button>

            {move || if running.get() {
                view! {
                    <button class="btn danger" on:click=move |_| ctx.stop()>
                        <Icon name="stop"/>{ctx.t("tb.stop")}
                    </button>
                }.into_any()
            } else {
                view! {
                    <button class="btn primary" on:click=move |_| ctx.start() disabled=move || !ctx.sys.with(|s| s.as_ref().map(|s| s.pcap_ok).unwrap_or(false))>
                        <Icon name="play"/>{ctx.t("tb.start")}
                    </button>
                }.into_any()
            }}

            <div class="tb-group">
                <button class="icon-btn" title=move || ctx.t("tb.clear") on:click=move |_| ctx.clear() disabled=move || !has_packets.get()>
                    <Icon name="trash"/>
                </button>
                <button class="icon-btn" title=move || ctx.t("tb.open") on:click=move |_| ctx.open_file() disabled=move || running.get()>
                    <Icon name="folder"/>
                </button>
                <button class="icon-btn" title=move || ctx.t("tb.save") on:click=move |_| ctx.save_file(false) disabled=move || !has_packets.get()>
                    <Icon name="save"/>
                </button>
            </div>

            <StatusChip/>

            <div class="spacer"></div>

            <div class="segmented" title=move || ctx.t("tb.mode_tip")>
                <button class:on=move || simple.get() on:click=move |_| set_simple(true)>{move || ctx.t("tb.simple")}</button>
                <button class:on=move || !simple.get() on:click=move |_| set_simple(false)>{move || ctx.t("tb.expert")}</button>
            </div>

            <button class="btn ai-btn" class:on=move || ctx.ai_open.get() on:click=move |_| ctx.ai_open.update(|v| *v = !*v)>
                <Icon name="sparkles"/>{move || ctx.t("tb.ai")}
                <Show when=move || !ctx.has_key()><span class="dot warn" title=move || ctx.t("ai.need_key")></span></Show>
            </button>
            <button class="icon-btn" title=move || ctx.t("tb.help") on:click=move |_| ctx.modal.set(Modal::Help)><Icon name="help"/></button>
            <button class="icon-btn" title=move || ctx.t("tb.settings") on:click=move |_| { ctx.settings_section.set("general"); ctx.modal.set(Modal::Settings) }><Icon name="settings"/></button>
        </header>
    }
}

#[component]
fn StatusChip() -> impl IntoView {
    let ctx = use_ctx();
    view! {
        <div class=move || format!("status-chip state-{:?}", ctx.status.with(|s| s.state)).to_lowercase()>
            <span class="pulse"></span>
            <span>{move || {
                let s = ctx.status.get();
                let label = match s.state {
                    CaptureState::Idle => ctx.t("st.idle"),
                    CaptureState::Running => ctx.t("st.running"),
                    CaptureState::Stopped => ctx.t("st.stopped"),
                    CaptureState::File => ctx.t("st.file"),
                };
                if s.state == CaptureState::Idle {
                    label.to_string()
                } else {
                    format!("{label} · {} {} · {}", fmt_count(s.packets as u64), ctx.t("w.packets"), fmt_duration(s.elapsed))
                }
            }}</span>
        </div>
    }
}

const PRESETS: &[(&str, &str)] = &[
    ("qf.all", ""),
    ("qf.sites", "dns || tls.client_hello || http.request"),
    ("qf.secure", "tls || quic || ssh"),
    ("qf.clear", "cleartext || http"),
    ("qf.local", "arp || mdns || ssdp || llmnr || nbns || dhcp || igmp"),
    ("qf.internet", "internet"),
    ("qf.problems", "problem"),
    ("qf.quiet", "!(arp || mdns || ssdp || llmnr || nbns || igmp || icmpv6 || stp || lldp)"),
];

/// Mot en cours de saisie (pour l'autocomplétion).
fn last_word(s: &str) -> (usize, &str) {
    let idx = s.rfind(|c: char| c.is_whitespace() || "()!&|=<>~".contains(c)).map(|i| i + 1).unwrap_or(0);
    (idx, &s[idx..])
}

#[component]
pub fn FilterBar() -> impl IntoView {
    let ctx = use_ctx();
    let focused = RwSignal::new(false);
    let parsed = Memo::new(move |_| {
        let text = ctx.filter_text.get();
        filter::parse(&text).map(|e| (e.is_true(), e.uses_fields()))
    });
    let state_class = move || match parsed.get() {
        Err(_) => "err",
        Ok((true, _)) => "",
        Ok((_, true)) => "ok",
        Ok((_, false)) => "text",
    };
    let pending = Memo::new(move |_| ctx.filter_text.get() != ctx.filter_applied.get());
    let suggestions = Memo::new(move |_| {
        let text = ctx.filter_text.get();
        let (_, w) = last_word(&text);
        filter::suggestions(w, 7).into_iter().map(|d| (d.name, d.fr, d.en)).collect::<Vec<_>>()
    });
    let apply = move || {
        let t = ctx.filter_text.get_untracked();
        ctx.apply_filter(t);
    };

    view! {
        <div class="filterbar">
            <div class=move || format!("filter-input {}", state_class())>
                <Icon name="filter"/>
                <input
                    node_ref=ctx.filter_ref
                    type="text"
                    spellcheck="false"
                    autocomplete="off"
                    placeholder=move || ctx.t("fb.placeholder")
                    prop:value=move || ctx.filter_text.get()
                    on:input=move |ev| ctx.filter_text.set(event_target_value(&ev))
                    on:focus=move |_| focused.set(true)
                    on:blur=move |_| set_timeout(move || focused.set(false), std::time::Duration::from_millis(150))
                    on:keydown=move |ev: web_sys::KeyboardEvent| {
                        if ev.key() == "Enter" { apply(); }
                        if ev.key() == "Escape" { ctx.filter_text.set(ctx.filter_applied.get_untracked()); }
                    }
                />
                <Show when=move || pending.get()>
                    <span class="hint-enter">{move || ctx.t("fb.enter")}</span>
                </Show>
                <Show when=move || matches!(parsed.get(), Ok((false, false)))>
                    <span class="badge">{move || ctx.t("fb.text_search")}</span>
                </Show>
                <Show when=move || !ctx.filter_text.get().is_empty()>
                    <button class="icon-btn tiny" title=move || ctx.t("fb.clear") on:click=move |_| ctx.apply_filter(String::new())><Icon name="x"/></button>
                </Show>
                <button class="btn small" on:click=move |_| apply()>{move || ctx.t("fb.apply")}</button>
                <Show when=move || focused.get() && !suggestions.get().is_empty()>
                    <div class="suggest">
                        <For each=move || suggestions.get() key=|s| s.0 children=move |(name, fr, en)| {
                            view! {
                                <div class="sug" on:mousedown=move |ev| {
                                    ev.prevent_default();
                                    let text = ctx.filter_text.get_untracked();
                                    let (i, _) = last_word(&text);
                                    ctx.filter_text.set(format!("{}{} ", &text[..i], name));
                                }>
                                    <code>{name}</code>
                                    <span>{move || if ctx.lang() == rustshark_shared::Lang::Fr { fr } else { en }}</span>
                                </div>
                            }
                        }/>
                    </div>
                </Show>
            </div>
            <div class="chips">
                {PRESETS.iter().map(|(key, f)| {
                    let f = f.to_string();
                    let f2 = f.clone();
                    view! {
                        <button class="chip" class:on=move || ctx.filter_applied.get() == f2 on:click=move |_| ctx.apply_filter(f.clone())>
                            {move || ctx.t(key)}
                        </button>
                    }
                }).collect_view()}
            </div>
        </div>
        <Show when=move || parsed.get().is_err() || ctx.filter_error.get().is_some()>
            <div class="filter-error">
                <Icon name="alert" class="small"/>
                {move || match parsed.get() {
                    Err(e) => e.message(ctx.lang()).to_string(),
                    Ok(_) => ctx.filter_error.get().unwrap_or_default(),
                }}
                <button class="link" on:click=move |_| ctx.modal.set(Modal::Help)>{move || ctx.t("fb.syntax")}</button>
            </div>
        </Show>
    }
}
