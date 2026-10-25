use leptos::prelude::*;
use leptos::task::spawn_local;
use rustshark_shared::{AlertLevel, Stats};
use serde::Serialize;

use crate::api::call;
use crate::icons::Icon;
use crate::state::{use_ctx, Tab};
use crate::util::{fmt_bytes, fmt_count, fmt_duration, fmt_rate};

#[derive(Serialize)]
struct FilteredArg {
    filtered: bool,
}

#[component]
pub fn Dashboard() -> impl IntoView {
    let ctx = use_ctx();
    let filtered = RwSignal::new(false);
    let stats = RwSignal::new(None::<Stats>);
    let load = move || {
        let f = filtered.get_untracked();
        spawn_local(async move {
            if let Ok(s) = call::<_, Stats>("get_stats", &FilteredArg { filtered: f }).await {
                stats.set(Some(s));
            }
        });
    };
    Effect::new(move |_| {
        filtered.track();
        ctx.lang();
        ctx.filter_applied.track();
        load();
    });
    if let Ok(h) = set_interval_with_handle(
        move || {
            if ctx.status.with_untracked(|s| s.state == rustshark_shared::CaptureState::Running) {
                load();
            }
        },
        std::time::Duration::from_millis(1500),
    ) {
        on_cleanup(move || h.clear());
    }
    let has_filter = Memo::new(move |_| !ctx.filter_applied.get().is_empty());
    let go = move |f: String| {
        ctx.apply_filter(f);
        ctx.tab.set(Tab::Packets);
    };

    view! {
        <div class="dashboard">
            <div class="dash-head">
                <h2>{move || ctx.t("db.title")}</h2>
                <Show when=move || has_filter.get()>
                    <div class="segmented">
                        <button class:on=move || !filtered.get() on:click=move |_| filtered.set(false)>{move || ctx.t("db.all")}</button>
                        <button class:on=move || filtered.get() on:click=move |_| filtered.set(true)>{move || ctx.t("db.filtered")}</button>
                    </div>
                </Show>
                <button class="icon-btn" title=move || ctx.t("db.refresh") on:click=move |_| load()><Icon name="refresh"/></button>
                <button class="btn ai" on:click=move |_| {
                    ctx.ai_open.set(true);
                    ctx.ai_tab.set(crate::state::AiTab::Chat);
                    ctx.ask_ai(ctx.tu("ai.q.summary").into(), if filtered.get_untracked() { rustshark_shared::AiScope::Filtered } else { rustshark_shared::AiScope::All });
                }><Icon name="sparkles"/>{move || ctx.t("db.ask_ai")}</button>
            </div>
            {move || match stats.get() {
                None => view! { <div class="loading">{ctx.t("w.loading")}</div> }.into_any(),
                Some(s) if s.packets == 0 => view! { <div class="plist-empty static">{ctx.t("db.empty")}</div> }.into_any(),
                Some(s) => view! { <DashBody s=s go=go/> }.into_any(),
            }}
        </div>
    }
}

#[component]
fn DashBody(s: Stats, go: impl Fn(String) + Copy + Send + Sync + 'static) -> impl IntoView {
    let ctx = use_ctx();
    let lang = ctx.lang_untracked();
    let total_bytes = s.bytes.max(1);

    // Anneau des familles de trafic.
    let mut acc = 0.0;
    let stops: Vec<String> = s
        .categories
        .iter()
        .map(|c| {
            let start = acc;
            acc += c.bytes as f64 / total_bytes as f64 * 100.0;
            format!("var(--c-{}) {start:.2}% {acc:.2}%", c.category.id())
        })
        .collect();
    let donut = format!("background: conic-gradient({})", stops.join(", "));

    let max_tl = s.timeline.iter().copied().max().unwrap_or(1).max(1);
    let n = s.timeline.len().max(1);
    let bars_svg: String = s
        .timeline
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let h = *v as f64 / max_tl as f64 * 96.0;
            format!("<rect x=\"{}\" y=\"{:.1}\" width=\"8\" height=\"{:.1}\" rx=\"2\"></rect>", i * 10 + 1, 100.0 - h, h.max(0.5))
        })
        .collect();

    let max_site = s.sites.first().map(|x| x.bytes).unwrap_or(1).max(1);
    let max_host = s.top_hosts.first().map(|x| x.bytes).unwrap_or(1).max(1);
    let max_proto = s.protocols.first().map(|x| x.packets).unwrap_or(1).max(1);

    view! {
        <div class="kpis">
            <div class="kpi"><small>{ctx.t("db.packets")}</small><strong>{fmt_count(s.packets)}</strong></div>
            <div class="kpi"><small>{ctx.t("db.volume")}</small><strong>{fmt_bytes(s.bytes, lang)}</strong></div>
            <div class="kpi"><small>{ctx.t("db.duration")}</small><strong>{fmt_duration(s.duration)}</strong></div>
            <div class="kpi"><small>{ctx.t("db.rate")}</small><strong>{fmt_rate(s.bytes, s.duration, lang)}</strong></div>
            <div class="kpi"><small>{ctx.t("db.sites_n")}</small><strong>{s.sites.len()}</strong></div>
        </div>

        <section class="card">
            <h3><Icon name="shield"/>{ctx.t("db.alerts")}</h3>
            {if s.alerts.is_empty() {
                view! { <div class="alert ok"><Icon name="check"/><div><strong>{ctx.t("db.no_alert")}</strong><p>{ctx.t("db.no_alert_d")}</p></div></div> }.into_any()
            } else {
                s.alerts.iter().cloned().map(|a| {
                    let cls = match a.level { AlertLevel::Danger => "danger", AlertLevel::Warning => "warning", AlertLevel::Info => "info" };
                    let icon = if a.level == AlertLevel::Info { "info" } else { "alert" };
                    view! {
                        <div class=format!("alert {cls}")>
                            <Icon name=icon/>
                            <div class="grow"><strong>{a.title.clone()}</strong><p>{a.detail.clone()}</p></div>
                            {a.filter.clone().map(|f| view! { <button class="btn small" on:click=move |_| go(f.clone())>{ctx.t("db.see")}</button> })}
                        </div>
                    }
                }).collect_view().into_any()
            }}
        </section>

        <div class="dash-row">
            <section class="card">
                <h3><Icon name="chart"/>{ctx.t("db.families")}</h3>
                <div class="donut-wrap">
                    <div class="donut" style=donut><div class="hole"><strong>{fmt_bytes(s.bytes, lang)}</strong></div></div>
                    <ul class="legend">
                        {s.categories.iter().map(|c| {
                            let pct = c.bytes as f64 / total_bytes as f64 * 100.0;
                            let f = format!("category == {}", c.category.id());
                            view! {
                                <li on:click=move |_| go(f.clone()) title=move || ctx.t("db.click_filter")>
                                    <span class=format!("sw cat-bg-{}", c.category.id())></span>
                                    <span class="grow">{c.category.label(lang)}</span>
                                    <span class="dim">{format!("{pct:.1} %")}</span>
                                </li>
                            }
                        }).collect_view()}
                    </ul>
                </div>
            </section>
            <section class="card">
                <h3><Icon name="zap"/>{ctx.t("db.timeline")}</h3>
                <svg class="timeline" viewBox=format!("0 0 {} 100", n * 10) preserveAspectRatio="none" inner_html=bars_svg></svg>
                <div class="tl-axis dim"><span>"0 s"</span><span>{format!("{:.0} s", s.duration)}</span></div>
                <p class="dim small">{format!("{} {:.1} s", ctx.t("db.bucket"), s.timeline_step)}</p>
            </section>
        </div>

        <div class="dash-row">
            <section class="card">
                <h3><Icon name="globe"/>{ctx.t("db.sites")}</h3>
                {if s.sites.is_empty() {
                    view! { <p class="dim">{ctx.t("db.sites_empty")}</p> }.into_any()
                } else {
                    s.sites.iter().map(|x| {
                        let w = x.bytes as f64 / max_site as f64 * 100.0;
                        let f = format!("host == {}", x.label);
                        view! {
                            <div class="bar-row" on:click=move |_| go(f.clone())>
                                <div class="bar-label"><span class="ell">{x.label.clone()}</span><span class="dim">{fmt_bytes(x.bytes, lang)}</span></div>
                                <div class="bar"><div style=format!("width:{w:.1}%")></div></div>
                            </div>
                        }
                    }).collect_view().into_any()
                }}
            </section>
            <section class="card">
                <h3><Icon name="monitor"/>{ctx.t("db.hosts")}</h3>
                {s.top_hosts.iter().map(|h| {
                    let w = h.bytes as f64 / max_host as f64 * 100.0;
                    let f = format!("ip.addr == {}", h.addr);
                    let label = h.name.clone().map(|n| format!("{n} ({})", h.addr)).unwrap_or(h.addr.clone());
                    view! {
                        <div class="bar-row" on:click=move |_| go(f.clone())>
                            <div class="bar-label">
                                <span class="ell">{label}</span>
                                {h.local.then(|| view! { <span class="badge">{ctx.t("db.local")}</span> })}
                                <span class="dim">{fmt_bytes(h.bytes, lang)}</span>
                            </div>
                            <div class="bar alt"><div style=format!("width:{w:.1}%")></div></div>
                        </div>
                    }
                }).collect_view()}
            </section>
        </div>

        <div class="dash-row">
            <section class="card">
                <h3><Icon name="book"/>{ctx.t("db.dns")}</h3>
                <div class="name-cloud">
                    {s.dns_names.iter().map(|d| {
                        let f = format!("dns.qry.name == {}", d.label);
                        view! { <button class="chip" on:click=move |_| go(f.clone())>{d.label.clone()}<span class="dim">{format!(" ×{}", d.packets)}</span></button> }
                    }).collect_view()}
                </div>
            </section>
            <section class="card">
                <h3><Icon name="list"/>{ctx.t("db.protocols")}</h3>
                {s.protocols.iter().map(|p| {
                    let w = p.packets as f64 / max_proto as f64 * 100.0;
                    let f = format!("protocol == {}", p.label);
                    view! {
                        <div class="bar-row" on:click=move |_| go(f.clone())>
                            <div class="bar-label"><span>{p.label.clone()}</span><span class="dim">{format!("{} · {}", fmt_count(p.packets), fmt_bytes(p.bytes, lang))}</span></div>
                            <div class="bar alt2"><div style=format!("width:{w:.1}%")></div></div>
                        </div>
                    }
                }).collect_view()}
            </section>
        </div>

        <section class="card">
            <h3><Icon name="chat"/>{ctx.t("db.convs")}</h3>
            <table class="table">
                <thead><tr>
                    <th>{ctx.t("db.c_a")}</th><th></th><th>{ctx.t("db.c_b")}</th><th>{ctx.t("db.c_service")}</th>
                    <th class="num">{ctx.t("db.packets")}</th><th class="num">{ctx.t("db.volume")}</th><th class="num">{ctx.t("db.duration")}</th><th></th>
                </tr></thead>
                <tbody>
                    {s.conversations.iter().map(|c| {
                        let f = c.filter.clone();
                        let a = c.a_name.clone().unwrap_or(c.a.clone());
                        let b = c.b_name.clone().unwrap_or(c.b.clone());
                        view! {
                            <tr>
                                <td class="ell" title=c.a.clone()>{a}</td>
                                <td class="dim">"⇄"</td>
                                <td class="ell" title=c.b.clone()>{b}</td>
                                <td>{format!("{} {}", c.protocol, c.service.clone().unwrap_or_default())}</td>
                                <td class="num">{fmt_count(c.packets)}</td>
                                <td class="num">{fmt_bytes(c.bytes, lang)}</td>
                                <td class="num">{format!("{:.1} s", c.end - c.start)}</td>
                                <td><button class="icon-btn tiny" title=ctx.t("db.see") on:click=move |_| go(f.clone())><Icon name="filter"/></button></td>
                            </tr>
                        }
                    }).collect_view()}
                </tbody>
            </table>
        </section>
    }
}
