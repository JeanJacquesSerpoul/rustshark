use leptos::prelude::*;
use rustshark_shared::CaptureState;

use crate::ai_panel::AiPanel;
use crate::dashboard::Dashboard;
use crate::flowmap::FlowMap;
use crate::icons::Icon;
use crate::modals::Modals;
use crate::network::{NetCtx, Network};
use crate::packets::{DetailPane, PacketList};
use crate::state::{use_ctx, Ctx, Modal, Tab, ToastKind};
use crate::toolbar::{FilterBar, Toolbar};
use crate::util::fmt_count;
use crate::welcome::Welcome;

#[component]
pub fn App() -> impl IntoView {
    let ctx = Ctx::new();
    provide_context(ctx);
    provide_context(NetCtx::new());
    if crate::api::tauri_available() {
        ctx.init();
    }

    if let Ok(h) = set_interval_with_handle(move || ctx.tick(), std::time::Duration::from_millis(400)) {
        on_cleanup(move || h.clear());
    }

    let _keys = window_event_listener(leptos::ev::keydown, move |ev| {
        let ctrl = ev.ctrl_key() || ev.meta_key();
        let key = ev.key();
        let in_field = ev
            .target()
            .and_then(|t| wasm_bindgen::JsCast::dyn_into::<web_sys::Element>(t).ok())
            .map(|el| matches!(el.tag_name().as_str(), "INPUT" | "TEXTAREA" | "SELECT"))
            .unwrap_or(false);
        match (ctrl, key.as_str()) {
            (true, "f") | (true, "k") => {
                ev.prevent_default();
                if let Some(el) = ctx.filter_ref.get_untracked() {
                    let _ = el.focus();
                    el.select();
                }
            }
            (true, "e") => {
                ev.prevent_default();
                if ctx.status.with_untracked(|s| s.state == CaptureState::Running) {
                    ctx.stop();
                } else {
                    ctx.start();
                }
            }
            (true, "i") => {
                ev.prevent_default();
                ctx.ai_open.update(|v| *v = !*v);
            }
            (false, "Escape") => {
                if ctx.modal.get_untracked() != Modal::None {
                    ctx.modal.set(Modal::None);
                }
            }
            (false, "ArrowDown") if !in_field && ctx.modal.get_untracked() == Modal::None => {
                ev.prevent_default();
                ctx.select_relative(1);
            }
            (false, "ArrowUp") if !in_field && ctx.modal.get_untracked() == Modal::None => {
                ev.prevent_default();
                ctx.select_relative(-1);
            }
            _ => {}
        }
    });

    // Accueil tant qu'il n'y a ni capture ni fichier (sauf pour explorer le réseau).
    let welcome = Memo::new(move |_| ctx.status.with(|s| s.state == CaptureState::Idle) && ctx.total.get() == 0 && ctx.tab.get() != Tab::Network);

    view! {
        <div class="app" class:ai-open=move || ctx.ai_open.get()>
            <Toolbar/>
            <Show when=move || !welcome.get() && ctx.tab.get() != Tab::Network>
                <FilterBar/>
            </Show>
            <div class="main">
                <div class="content">
                    <Show when=move || welcome.get() fallback=|| view! { <Workspace/> }>
                        <Welcome/>
                    </Show>
                </div>
                <Show when=move || ctx.ai_open.get()>
                    <AiPanel/>
                </Show>
            </div>
            <StatusBar/>
            <Modals/>
            <Toasts/>
        </div>
    }
}

#[component]
fn Workspace() -> impl IntoView {
    let ctx = use_ctx();
    let tab_btn = move |tab: Tab, icon: &'static str, key: &'static str| {
        view! {
            <button class:on=move || ctx.tab.get() == tab on:click=move |_| ctx.tab.set(tab)>
                <Icon name=icon/>{move || ctx.t(key)}
            </button>
        }
    };
    let detail_open = RwSignal::new(true);
    view! {
        <div class="workspace">
            <div class="tabs">
                {tab_btn(Tab::Packets, "list", "tab.packets")}
                {tab_btn(Tab::Dashboard, "chart", "tab.dashboard")}
                {tab_btn(Tab::Flows, "flows", "tab.flows")}
                {tab_btn(Tab::Network, "radar", "tab.network")}
                <span class="spacer"></span>
                <Show when=move || ctx.active_profile.get().is_some()>
                    <span class="profile-pill" title=move || ctx.active_profile.get().map(|p| p.explanation).unwrap_or_default()>
                        <Icon name="bookmark" class="small"/>{move || ctx.active_profile.get().map(|p| p.name).unwrap_or_default()}
                        <button class="icon-btn tiny" on:click=move |_| ctx.active_profile.set(None)><Icon name="x"/></button>
                    </span>
                </Show>
                <Show when=move || ctx.tab.get() == Tab::Packets>
                    <button class="link" on:click=move |_| detail_open.update(|v| *v = !*v)>
                        {move || if detail_open.get() { ctx.t("ws.hide_detail") } else { ctx.t("ws.show_detail") }}
                    </button>
                </Show>
            </div>
            {move || match ctx.tab.get() {
                Tab::Packets => view! {
                    <div class="packets-view" class:with-detail=move || detail_open.get()>
                        <PacketList/>
                        <Show when=move || detail_open.get()>
                            <DetailPane/>
                        </Show>
                    </div>
                }.into_any(),
                Tab::Dashboard => view! { <Dashboard/> }.into_any(),
                Tab::Flows => view! { <FlowMap/> }.into_any(),
                Tab::Network => view! { <Network/> }.into_any(),
            }}
        </div>
    }
}

#[component]
fn StatusBar() -> impl IntoView {
    let ctx = use_ctx();
    view! {
        <footer class="statusbar">
            <span>{move || ctx.status.with(|s| s.source.clone()).unwrap_or_else(|| ctx.t("sb.no_source").into())}</span>
            {move || ctx.status.with(|s| s.capture_filter.clone()).map(|f| view! { <span class="mono">"BPF: "{f}</span> })}
            {move || {
                let d = ctx.status.with(|s| s.dropped);
                (d > 0).then(|| view! { <span class="warn-text" title=ctx.t("sb.dropped_h")>{format!("{} {}", fmt_count(d as u64), ctx.t("sb.dropped"))}</span> })
            }}
            {move || ctx.status.with(|s| s.truncated).then(|| view! { <span class="warn-text">{ctx.t("sb.truncated")}</span> })}
            <span class="spacer"></span>
            <span class="dim">{move || ctx.sys.get().and_then(|s| s.pcap_version).unwrap_or_default()}</span>
        </footer>
    }
}

#[component]
fn Toasts() -> impl IntoView {
    let ctx = use_ctx();
    view! {
        <div class="toasts">
            <For each=move || ctx.toasts.get() key=|t| t.id children=move |t| {
                let id = t.id;
                let (cls, icon) = match t.kind {
                    ToastKind::Info => ("toast info", "info"),
                    ToastKind::Success => ("toast success", "check"),
                    ToastKind::Error => ("toast error", "alert"),
                };
                view! {
                    <div class=cls on:click=move |_| ctx.toasts.update(|v| v.retain(|x| x.id != id))>
                        <Icon name=icon/>
                        <span>{t.text.clone()}</span>
                    </div>
                }
            }/>
        </div>
    }
}
