use leptos::prelude::*;
use rustshark_shared::IfaceKind;

use crate::icons::{iface_icon, Icon};
use crate::state::{use_ctx, AiTab, Modal, Tab};

#[component]
pub fn Welcome() -> impl IntoView {
    let ctx = use_ctx();
    let pcap_ok = Memo::new(move |_| ctx.sys.with(|s| s.as_ref().map(|s| s.pcap_ok)));
    let goal = RwSignal::new(String::new());
    // Sonde d'activité au premier affichage.
    Effect::new(move |_| {
        if !ctx.interfaces.with(|l| l.is_empty()) && ctx.activity.with_untracked(|a| a.is_empty()) {
            ctx.probe();
        }
    });
    let ask_builder = move || {
        let g = goal.get_untracked();
        if g.trim().is_empty() {
            return;
        }
        ctx.builder_goal.set(g);
        ctx.ai_open.set(true);
        ctx.ai_tab.set(AiTab::Builder);
        ctx.builder_autorun.set(true);
    };

    view! {
        <div class="welcome">
            <div class="hero">
                <img src="icon.svg" class="hero-logo" alt=""/>
                <h1>{move || ctx.t("wl.title")}</h1>
                <p class="lead">{move || ctx.t("wl.lead")}</p>
            </div>

            {move || match pcap_ok.get() {
                Some(false) => view! { <InstallGuide/> }.into_any(),
                None => view! { <div class="loading">{ctx.t("w.loading")}</div> }.into_any(),
                Some(true) => view! { <Start/> }.into_any(),
            }}

            <Show when=move || pcap_ok.get() == Some(true)>
                <button class="wl-net card" on:click=move |_| ctx.tab.set(Tab::Network)>
                    <Icon name="radar"/>
                    <div class="grow">
                        <strong>{move || ctx.t("wl.net_title")}</strong>
                        <p class="dim">{move || ctx.t("wl.net_text")}</p>
                    </div>
                    <Icon name="chevron" class="small rot"/>
                </button>
            </Show>

            <div class="wl-ai card">
                <div class="wl-ai-head"><Icon name="sparkles"/><strong>{move || ctx.t("wl.ai_title")}</strong></div>
                <p class="dim">{move || ctx.t("wl.ai_text")}</p>
                <div class="wl-ai-row">
                    <input type="text" placeholder=move || ctx.t("bd.placeholder") prop:value=move || goal.get()
                        on:input=move |ev| goal.set(event_target_value(&ev))
                        on:keydown=move |ev: web_sys::KeyboardEvent| if ev.key() == "Enter" { ask_builder() }/>
                    <button class="btn ai" on:click=move |_| ask_builder()><Icon name="wand"/>{move || ctx.t("wl.ai_btn")}</button>
                </div>
            </div>

            <div class="steps">
                <div class="step"><span class="num">"1"</span><div><strong>{move || ctx.t("wl.s1")}</strong><p>{move || ctx.t("wl.s1d")}</p></div></div>
                <div class="step"><span class="num">"2"</span><div><strong>{move || ctx.t("wl.s2")}</strong><p>{move || ctx.t("wl.s2d")}</p></div></div>
                <div class="step"><span class="num">"3"</span><div><strong>{move || ctx.t("wl.s3")}</strong><p>{move || ctx.t("wl.s3d")}</p></div></div>
            </div>

            <p class="dim small center">
                {move || ctx.t("wl.file")}" "
                <button class="link" on:click=move |_| ctx.open_file()>{move || ctx.t("wl.open")}</button>
                " · "
                <button class="link" on:click=move |_| ctx.modal.set(Modal::Help)>{move || ctx.t("wl.help")}</button>
            </p>
            <p class="dim small center legal">{move || ctx.t("wl.legal")}</p>
        </div>
    }
}

#[component]
fn Start() -> impl IntoView {
    let ctx = use_ctx();
    let shown = Memo::new(move |_| {
        ctx.interfaces.with(|l| {
            l.iter()
                .filter(|i| i.connected && !matches!(i.kind, IfaceKind::Virtual | IfaceKind::Bluetooth))
                .take(4)
                .cloned()
                .collect::<Vec<_>>()
        })
    });
    let max_act = Memo::new(move |_| ctx.activity.with(|a| a.values().copied().max().unwrap_or(0)).max(1));
    view! {
        <div class="wl-start card">
            <div class="wl-start-head">
                <strong>{move || ctx.t("wl.pick")}</strong>
                <button class="link" on:click=move |_| ctx.modal.set(Modal::Interfaces)>{move || ctx.t("wl.all_ifaces")}</button>
            </div>
            {move || ctx.iface_error.get().map(|e| view! { <div class="msg-error">{e}</div> })}
            <div class="iface-cards">
                <For each=move || shown.get() key=|i| i.name.clone() children=move |i| {
                    let name = i.name.clone();
                    let name2 = i.name.clone();
                    let name3 = i.name.clone();
                    let addr = i.addresses.iter().find(|a| a.contains('.')).cloned().unwrap_or_default();
                    view! {
                        <button class="iface-card" class:on=move || ctx.iface.get().as_deref() == Some(name.as_str())
                            on:click=move |_| ctx.iface.set(Some(name2.clone()))>
                            <Icon name=iface_icon(i.kind)/>
                            <div class="grow">
                                <strong>{i.friendly.clone()}</strong>
                                <small class="dim">{addr}</small>
                            </div>
                            {i.recommended.then(|| view! { <span class="badge good">{move || ctx.t("if.recommended")}</span> })}
                            <div class="activity" title=move || ctx.t("if.activity")>
                                <div style=move || {
                                    let n = ctx.activity.with(|a| a.get(&name3).copied().unwrap_or(0));
                                    format!("width:{}%", (n as f64 / max_act.get() as f64 * 100.0).max(if n > 0 { 6.0 } else { 0.0 }))
                                }></div>
                            </div>
                        </button>
                    }
                }/>
            </div>
            <button class="btn primary big" on:click=move |_| ctx.start() disabled=move || ctx.iface.get().is_none()>
                <Icon name="play"/>{move || ctx.t("wl.start")}
            </button>
        </div>
    }
}

#[component]
fn InstallGuide() -> impl IntoView {
    let ctx = use_ctx();
    let os = Memo::new(move |_| ctx.sys.with(|s| s.as_ref().map(|s| s.os.clone()).unwrap_or_default()));
    view! {
        <div class="card install">
            <h3><Icon name="alert"/>{move || ctx.t("in.title")}</h3>
            <p>{move || ctx.t("in.why")}</p>
            {move || match os.get().as_str() {
                "windows" => view! {
                    <ol>
                        <li>{ctx.t("in.win1")}</li>
                        <li>{ctx.t("in.win2")}</li>
                        <li>{ctx.t("in.win3")}</li>
                    </ol>
                    <button class="btn primary" on:click=move |_| ctx.open_url("https://npcap.com/#download".into())><Icon name="external"/>{ctx.t("in.win_btn")}</button>
                }.into_any(),
                "macos" => view! { <p>{ctx.t("in.mac")}</p> }.into_any(),
                _ => view! {
                    <p>{ctx.t("in.linux")}</p>
                    <pre>"sudo apt install libpcap0.8      # Debian / Ubuntu\nsudo dnf install libpcap          # Fedora\nsudo pacman -S libpcap            # Arch"</pre>
                }.into_any(),
            }}
            <p class="dim small">{move || ctx.sys.get().and_then(|s| s.pcap_error).unwrap_or_default()}</p>
            <button class="link" on:click=move |_| { leptos::task::spawn_local(async move { let _ = web_sys::window().map(|w| w.location().reload()); }); }>{move || ctx.t("in.retry")}</button>
        </div>
    }
}
