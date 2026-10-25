use leptos::prelude::*;
use leptos::task::spawn_local;
use rustshark_shared::{AiScope, AnalysisProfile, GeneratedProfile, Provider};
use serde::Serialize;
use wasm_bindgen::JsCast;

use crate::api::call;
use crate::icons::Icon;
use crate::state::{use_ctx, AiTab, Ctx, Modal, ToastKind};
use crate::util::markdown;

#[component]
pub fn AiPanel() -> impl IntoView {
    let ctx = use_ctx();
    let model = Memo::new(move |_| ctx.settings.with(|s| format!("{} · {}", s.ai.provider.label(), s.ai.model())));
    let tab_btn = move |tab: AiTab, icon: &'static str, key: &'static str| {
        view! {
            <button class:on=move || ctx.ai_tab.get() == tab on:click=move |_| ctx.ai_tab.set(tab)>
                <Icon name=icon/>{move || ctx.t(key)}
            </button>
        }
    };
    view! {
        <aside class="ai-panel">
            <div class="ai-head">
                <div>
                    <h3><Icon name="sparkles"/>{move || ctx.t("ai.title")}</h3>
                    <button class="model-badge" title=move || ctx.t("ai.change_model") on:click=move |_| { ctx.settings_section.set("ai"); ctx.modal.set(Modal::Settings) }>{move || model.get()}</button>
                </div>
                <button class="icon-btn" on:click=move |_| ctx.ai_open.set(false)><Icon name="x"/></button>
            </div>
            <div class="ai-tabs">
                {tab_btn(AiTab::Chat, "chat", "ai.tab.chat")}
                {tab_btn(AiTab::Builder, "wand", "ai.tab.builder")}
                {tab_btn(AiTab::Profiles, "bookmark", "ai.tab.profiles")}
            </div>
            <Show when=move || !ctx.has_key()>
                <div class="nokey card">
                    <Icon name="key"/>
                    <div>
                        <strong>{move || ctx.t("ai.nokey.title")}</strong>
                        <p>{move || ctx.t("ai.nokey.text")}</p>
                        <button class="btn primary small" on:click=move |_| { ctx.settings_section.set("ai"); ctx.modal.set(Modal::Settings) }>{move || ctx.t("ai.nokey.btn")}</button>
                    </div>
                </div>
            </Show>
            {move || match ctx.ai_tab.get() {
                AiTab::Chat => view! { <Chat/> }.into_any(),
                AiTab::Builder => view! { <Builder/> }.into_any(),
                AiTab::Profiles => view! { <Profiles/> }.into_any(),
            }}
        </aside>
    }
}

fn filter_from_click(ctx: Ctx, ev: web_sys::MouseEvent) {
    let Some(target) = ev.target().and_then(|t| t.dyn_into::<web_sys::Element>().ok()) else { return };
    if let Ok(Some(el)) = target.closest("[data-filter]") {
        if let Some(f) = el.get_attribute("data-filter") {
            ctx.apply_filter(f);
            ctx.tab.set(crate::state::Tab::Packets);
            ctx.toast(ToastKind::Info, format!("{} {}", ctx.tu("ai.filter_applied"), el.text_content().unwrap_or_default()));
        }
    }
}

#[component]
fn Chat() -> impl IntoView {
    let ctx = use_ctx();
    let input = RwSignal::new(String::new());
    let log_ref = NodeRef::<leptos::html::Div>::new();
    let busy = Memo::new(move |_| ctx.ai_busy.get().is_some());
    let has_sel = Memo::new(move |_| ctx.selected.get().is_some());
    let has_filter = Memo::new(move |_| !ctx.filter_applied.get().is_empty());

    // Défilement automatique pendant la réponse.
    Effect::new(move |_| {
        ctx.chat.track();
        request_animation_frame(move || {
            if let Some(el) = log_ref.get_untracked() {
                el.set_scroll_top(el.scroll_height());
            }
        });
    });

    let send = move |text: String| {
        let scope = ctx.ai_scope.get_untracked();
        ctx.ask_ai(text, scope);
        input.set(String::new());
    };

    let scope_btn = move |scope: AiScope, key: &'static str, enabled: Memo<bool>| {
        view! {
            <button class:on=move || ctx.ai_scope.get() == scope disabled=move || !enabled.get() on:click=move |_| ctx.ai_scope.set(scope)>
                {move || ctx.t(key)}
            </button>
        }
    };
    let always = Memo::new(|_| true);

    let quick: Vec<&'static str> = vec!["ai.q.summary", "ai.q.suspicious", "ai.q.sites", "ai.q.slow", "ai.q.devices"];

    view! {
        <div class="chat">
            <div class="scope-row">
                <span class="dim small">{move || ctx.t("ai.scope")}</span>
                <div class="segmented small">
                    {scope_btn(AiScope::All, "ai.scope.all", always)}
                    {scope_btn(AiScope::Filtered, "ai.scope.filtered", has_filter)}
                    {scope_btn(AiScope::Packet, "ai.scope.packet", has_sel)}
                </div>
            </div>
            <div class="chat-log" node_ref=log_ref on:click=move |ev| filter_from_click(ctx, ev)>
                <Show when=move || ctx.chat.with(|c| c.is_empty())>
                    <div class="chat-intro">
                        <p>{move || ctx.t("ai.intro")}</p>
                        <div class="quick">
                            {quick.iter().map(|k| {
                                let k = *k;
                                view! { <button class="quick-q" on:click=move |_| { ctx.ai_scope.set(AiScope::All); send(ctx.tu(k).to_string()) } disabled=move || busy.get()>{move || ctx.t(k)}</button> }
                            }).collect_view()}
                            <Show when=move || has_sel.get()>
                                <button class="quick-q" on:click=move |_| ctx.explain_selected()>{move || ctx.t("ai.q.packet")}</button>
                            </Show>
                            {move || ctx.active_profile.get().and_then(|p| p.ai_prompt).map(|q| {
                                let q2 = q.clone();
                                view! { <button class="quick-q profile" on:click=move |_| send(q2.clone())><Icon name="bookmark" class="small"/>{q}</button> }
                            })}
                        </div>
                    </div>
                </Show>
                <For each=move || ctx.chat.get() key=|e| (e.id.clone(), e.content.len(), e.done, e.thinking) children=move |e| {
                    let is_user = e.role == "user";
                    view! {
                        <div class=if is_user { "msg user" } else { "msg bot" }>
                            {if is_user {
                                view! { <div class="bubble">{e.content.clone()}</div> }.into_any()
                            } else {
                                let html = markdown(&e.content);
                                view! {
                                    <div class="bubble md">
                                        <div inner_html=html></div>
                                        {(e.thinking || (!e.done && e.content.is_empty())).then(|| view! { <div class="thinking"><span></span><span></span><span></span>{move || ctx.t("ai.thinking")}</div> })}
                                        {e.error.clone().map(|err| view! { <div class="msg-error"><Icon name="alert" class="small"/>{err}</div> })}
                                    </div>
                                }.into_any()
                            }}
                        </div>
                    }
                }/>
            </div>
            <div class="composer">
                <textarea
                    rows="2"
                    placeholder=move || ctx.t("ai.placeholder")
                    prop:value=move || input.get()
                    on:input=move |ev| input.set(event_target_value(&ev))
                    on:keydown=move |ev: web_sys::KeyboardEvent| {
                        if ev.key() == "Enter" && !ev.shift_key() {
                            ev.prevent_default();
                            if !busy.get_untracked() { send(input.get_untracked()); }
                        }
                    }
                ></textarea>
                {move || if busy.get() {
                    view! { <button class="btn danger" on:click=move |_| ctx.cancel_ai()><Icon name="stop"/></button> }.into_any()
                } else {
                    view! { <button class="btn primary" on:click=move |_| send(input.get_untracked()) disabled=move || input.get().trim().is_empty()><Icon name="send"/></button> }.into_any()
                }}
            </div>
            <div class="chat-foot dim small">
                <span>{move || {
                    let s = ctx.settings.get();
                    let prov = s.ai.provider.label();
                    if s.ai.anonymize { format!("{} {prov} · {}", ctx.t("ai.privacy"), ctx.t("ai.masked")) } else { format!("{} {prov}", ctx.t("ai.privacy")) }
                }}</span>
                <Show when=move || ctx.chat.with(|c| !c.is_empty())>
                    <button class="link" on:click=move |_| ctx.chat.set(Vec::new()) disabled=move || busy.get()>{move || ctx.t("ai.new_chat")}</button>
                </Show>
            </div>
        </div>
    }
}

#[derive(Serialize)]
struct GenArgs {
    goal: String,
    interface: Option<String>,
}

#[derive(Serialize)]
struct ProfileArg {
    profile: AnalysisProfile,
}

#[derive(Serialize)]
struct IdArg {
    id: String,
}

const EXAMPLES: &[&str] = &["ex.sites", "ex.devices", "ex.cleartext", "ex.slow", "ex.app", "ex.console"];

#[component]
fn Builder() -> impl IntoView {
    let ctx = use_ctx();
    let loading = RwSignal::new(false);
    let result = RwSignal::new(None::<GeneratedProfile>);
    let error = RwSignal::new(None::<String>);

    let generate = move || {
        let goal = ctx.builder_goal.get_untracked();
        if goal.trim().is_empty() || loading.get_untracked() {
            return;
        }
        if !ctx.has_key() {
            ctx.settings_section.set("ai");
            ctx.modal.set(Modal::Settings);
            return;
        }
        loading.set(true);
        error.set(None);
        result.set(None);
        let interface = ctx.iface.get_untracked();
        spawn_local(async move {
            match call::<_, GeneratedProfile>("ai_generate_profile", &GenArgs { goal, interface }).await {
                Ok(g) => result.set(Some(g)),
                Err(e) => error.set(Some(e)),
            }
            loading.set(false);
        });
    };
    // Lancement automatique depuis l'écran d'accueil.
    Effect::new(move |_| {
        if ctx.builder_autorun.get() {
            ctx.builder_autorun.set(false);
            generate();
        }
    });

    let save = move |p: AnalysisProfile| {
        spawn_local(async move {
            match call::<_, Vec<AnalysisProfile>>("save_profile", &ProfileArg { profile: p }).await {
                Ok(list) => {
                    ctx.profiles.set(list);
                    ctx.toast(ToastKind::Success, ctx.tu("pr.saved"));
                }
                Err(e) => ctx.toast(ToastKind::Error, e),
            }
        });
    };

    view! {
        <div class="builder">
            <p class="dim">{move || ctx.t("bd.intro")}</p>
            <textarea
                class="goal"
                rows="3"
                placeholder=move || ctx.t("bd.placeholder")
                prop:value=move || ctx.builder_goal.get()
                on:input=move |ev| ctx.builder_goal.set(event_target_value(&ev))
            ></textarea>
            <div class="quick">
                {EXAMPLES.iter().map(|k| {
                    let k = *k;
                    view! { <button class="chip" on:click=move |_| ctx.builder_goal.set(ctx.tu(k).to_string())>{move || ctx.t(k)}</button> }
                }).collect_view()}
            </div>
            <button class="btn primary wide" on:click=move |_| generate() disabled=move || loading.get() || ctx.builder_goal.get().trim().is_empty()>
                <Icon name="wand"/>{move || if loading.get() { ctx.t("bd.generating") } else { ctx.t("bd.generate") }}
            </button>
            {move || error.get().map(|e| view! { <div class="msg-error"><Icon name="alert" class="small"/>{e}</div> })}
            {move || result.get().map(|g| {
                let p = g.profile.clone();
                let (p1, p2, p3) = (p.clone(), p.clone(), p.clone());
                view! {
                    <div class="card profile-card">
                        <h4><Icon name="target"/>{p.name.clone()}</h4>
                        <p>{p.explanation.clone()}</p>
                        <dl>
                            <dt>{ctx.t("bd.capture_filter")}<span class="qm" title=ctx.t("bd.capture_filter_h")>"?"</span></dt>
                            <dd>
                                <code>{p.capture_filter.clone().unwrap_or_else(|| ctx.t("bd.none").into())}</code>
                                {g.capture_filter_error.clone().map(|e| view! { <span class="bad" title=e>"⚠"</span> })}
                            </dd>
                            <dt>{ctx.t("bd.display_filter")}<span class="qm" title=ctx.t("bd.display_filter_h")>"?"</span></dt>
                            <dd>
                                <code>{p.display_filter.clone().unwrap_or_else(|| ctx.t("bd.none").into())}</code>
                                {g.display_filter_error.clone().map(|e| view! { <span class="bad" title=e>"⚠"</span> })}
                            </dd>
                            {p.suggested_duration_s.map(|d| view! { <dt>{ctx.t("bd.duration")}</dt><dd>{format!("{d} s")}</dd> })}
                        </dl>
                        {(!p.watch_points.is_empty()).then(|| view! {
                            <h5>{ctx.t("bd.watch")}</h5>
                            <ul>{p.watch_points.iter().map(|w| view! { <li>{w.clone()}</li> }).collect_view()}</ul>
                        })}
                        {p.ai_prompt.clone().map(|q| view! { <p class="dim small">{ctx.t("bd.followup")}" « "{q}" »"</p> })}
                        <div class="actions">
                            <button class="btn primary small" on:click=move |_| ctx.apply_profile(p1.clone(), true) disabled=move || ctx.running()>
                                <Icon name="play"/>{ctx.t("bd.apply_start")}
                            </button>
                            <button class="btn small" on:click=move |_| ctx.apply_profile(p2.clone(), false)>{ctx.t("bd.apply")}</button>
                            <button class="btn small" on:click=move |_| save(p3.clone())><Icon name="bookmark"/>{ctx.t("bd.save")}</button>
                        </div>
                    </div>
                }
            })}
        </div>
    }
}

#[component]
fn Profiles() -> impl IntoView {
    let ctx = use_ctx();
    let delete = move |id: String| {
        spawn_local(async move {
            if let Ok(list) = call::<_, Vec<AnalysisProfile>>("delete_profile", &IdArg { id }).await {
                ctx.profiles.set(list);
            }
        });
    };
    view! {
        <div class="profiles">
            <Show when=move || ctx.active_profile.get().is_some()>
                <div class="active-profile">
                    <Icon name="bookmark"/>
                    <span class="grow">{move || format!("{} {}", ctx.t("pr.active"), ctx.active_profile.get().map(|p| p.name).unwrap_or_default())}</span>
                    <button class="link" on:click=move |_| ctx.active_profile.set(None)>{move || ctx.t("pr.deactivate")}</button>
                </div>
            </Show>
            <Show when=move || ctx.profiles.with(|p| p.is_empty())>
                <p class="dim">{move || ctx.t("pr.empty")}</p>
            </Show>
            <For each=move || ctx.profiles.get() key=|p| p.id.clone() children=move |p| {
                let (p1, p2) = (p.clone(), p.clone());
                let id = p.id.clone();
                view! {
                    <div class="card profile-card compact">
                        <h4>{p.name.clone()}</h4>
                        <p class="dim small">{p.goal.clone()}</p>
                        <div class="codes">
                            {p.capture_filter.clone().map(|c| view! { <code title="BPF">{c}</code> })}
                            {p.display_filter.clone().map(|c| view! { <code>{c}</code> })}
                        </div>
                        <div class="actions">
                            <button class="btn primary small" on:click=move |_| ctx.apply_profile(p1.clone(), true) disabled=move || ctx.running()><Icon name="play"/>{move || ctx.t("bd.apply_start")}</button>
                            <button class="btn small" on:click=move |_| ctx.apply_profile(p2.clone(), false)>{move || ctx.t("bd.apply")}</button>
                            <button class="icon-btn tiny" title=move || ctx.t("pr.delete") on:click=move |_| delete(id.clone())><Icon name="trash"/></button>
                        </div>
                    </div>
                }
            }/>
        </div>
    }
}

pub fn provider_key_url(p: Provider) -> String {
    p.key_url().to_string()
}
