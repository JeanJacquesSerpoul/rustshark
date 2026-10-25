use leptos::prelude::*;
use rustshark_shared::{CaptureState, PacketDetail, PacketRow};

use crate::icons::Icon;
use crate::state::{use_ctx, ROW_H};
use crate::util::{fmt_count, hex_dump};

fn who(name: &Option<String>, addr: &str) -> String {
    name.clone().unwrap_or_else(|| addr.to_string())
}

#[component]
pub fn PacketList() -> impl IntoView {
    let ctx = use_ctx();
    let simple = Memo::new(move |_| ctx.settings.with(|s| s.simple_mode));
    let resolve = Memo::new(move |_| ctx.settings.with(|s| s.resolve_names));
    let list = ctx.list_ref;

    let measure = move || {
        if let Some(el) = list.get_untracked() {
            ctx.viewport_h.set(el.client_height() as f64);
        }
    };
    Effect::new(move |_| {
        if list.get().is_some() {
            measure();
            ctx.refresh_view();
        }
    });
    let _resize = window_event_listener(leptos::ev::resize, move |_| {
        measure();
        ctx.maybe_refresh();
    });

    let on_scroll = move |_| {
        let Some(el) = list.get_untracked() else { return };
        let top = el.scroll_top() as f64;
        let h = el.client_height() as f64;
        ctx.scroll_top.set(top);
        ctx.viewport_h.set(h);
        let at_bottom = top + h >= el.scroll_height() as f64 - ROW_H * 1.5;
        if ctx.status.with_untracked(|s| s.state == CaptureState::Running) {
            if ctx.follow.get_untracked() != at_bottom {
                ctx.follow.set(at_bottom);
            }
        }
        ctx.maybe_refresh();
    };

    let header = move || {
        if simple.get() {
            view! {
                <div class="phead simple">
                    <span>{ctx.t("col.time")}</span><span>{ctx.t("col.from")}</span><span>{ctx.t("col.to")}</span>
                    <span>{ctx.t("col.kind")}</span><span>{ctx.t("col.what")}</span>
                </div>
            }.into_any()
        } else {
            view! {
                <div class="phead expert">
                    <span>"No."</span><span>{ctx.t("col.time")}</span><span>{ctx.t("col.src")}</span><span>{ctx.t("col.dst")}</span>
                    <span>{ctx.t("col.proto")}</span><span>{ctx.t("col.len")}</span><span>"Info"</span>
                </div>
            }.into_any()
        }
    };

    let row_view = move |idx: u32, r: PacketRow| {
        let no = r.no;
        let top = idx as f64 * ROW_H;
        let cat = r.category;
        let cells = if simple.get_untracked() {
            let from = who(&r.src_name, &r.src);
            let to = who(&r.dst_name, &r.dst);
            view! {
                <span class="mono dim">{format!("{:.3}", r.time)}</span>
                <span class="ell" title=r.src.clone()>{from}</span>
                <span class="ell" title=r.dst.clone()>{to}</span>
                <span><span class=format!("cat-badge cat-{}", cat.id())>{move || cat.label(ctx.lang())}</span></span>
                <span class="ell" title=r.info.clone()>{r.summary.clone()}</span>
            }.into_any()
        } else {
            let res = resolve.get_untracked();
            let src = if res { who(&r.src_name, &r.src) } else { r.src.clone() };
            let dst = if res { who(&r.dst_name, &r.dst) } else { r.dst.clone() };
            view! {
                <span class="mono dim">{no}</span>
                <span class="mono dim">{format!("{:.6}", r.time)}</span>
                <span class="ell mono" title=r.src.clone()>{src}</span>
                <span class="ell mono" title=r.dst.clone()>{dst}</span>
                <span class="proto">{r.protocol.clone()}</span>
                <span class="mono dim">{r.length}</span>
                <span class="ell mono" title=r.summary.clone()>{r.info.clone()}</span>
            }.into_any()
        };
        view! {
            <div
                class=move || format!("prow cat-{} {}", cat.id(), if simple.get_untracked() { "simple" } else { "expert" })
                class:sel=move || ctx.selected.get() == Some(no)
                style=format!("top:{top}px")
                on:click=move |_| { ctx.follow.set(false); ctx.select(no) }
            >
                {cells}
            </div>
        }
    };

    view! {
        <div class="plist">
            {header}
            <div class="pbody" node_ref=list on:scroll=on_scroll tabindex="0">
                <div class="pspacer" style=move || format!("height:{}px", ctx.matched.get() as f64 * ROW_H)>
                    {move || {
                        // Recréé quand le mode change (colonnes différentes).
                        let _ = simple.get();
                        let _ = resolve.get();
                        view! {
                            <For
                                each=move || {
                                    let off = ctx.rows_offset.get();
                                    ctx.rows.get().into_iter().enumerate().map(move |(i, r)| (off + i as u32, r)).collect::<Vec<_>>()
                                }
                                key=|(i, r)| (*i, r.no, r.summary.len())
                                children=move |(i, r)| row_view(i, r)
                            />
                        }
                    }}
                </div>
                <Show when=move || ctx.matched.get() == 0>
                    <div class="plist-empty">
                        {move || if ctx.total.get() > 0 {
                            ctx.t("pl.no_match").to_string()
                        } else if ctx.running() {
                            ctx.t("pl.waiting").to_string()
                        } else {
                            ctx.t("pl.empty").to_string()
                        }}
                    </div>
                </Show>
            </div>
            <Show when=move || ctx.running() && !ctx.follow.get()>
                <button class="follow-btn" on:click=move |_| { ctx.follow.set(true); ctx.refresh_view(); }>
                    <Icon name="down"/>{move || ctx.t("pl.follow")}
                </button>
            </Show>
            <div class="plist-foot">
                {move || {
                    let (m, t) = (ctx.matched.get(), ctx.total.get());
                    if m == t {
                        format!("{} {}", fmt_count(t as u64), ctx.t("w.packets"))
                    } else {
                        format!("{} / {} {}", fmt_count(m as u64), fmt_count(t as u64), ctx.t("pl.shown"))
                    }
                }}
                <Show when=move || { ctx.matched.get() != ctx.total.get() && ctx.matched.get() > 0 }>
                    <button class="link" on:click=move |_| ctx.save_file(true)>{move || ctx.t("pl.export_filtered")}</button>
                </Show>
            </div>
        </div>
    }
}

#[component]
pub fn DetailPane() -> impl IntoView {
    let ctx = use_ctx();
    view! {
        <div class="detail" class:has=move || ctx.detail.with(|d| d.is_some())>
            {move || match ctx.detail.get() {
                Some(d) => view! { <Detail d=d/> }.into_any(),
                None => view! {
                    <div class="detail-empty">
                        <Icon name="eye"/>
                        <p>{move || ctx.t("dt.empty")}</p>
                    </div>
                }.into_any(),
            }}
        </div>
    }
}

#[component]
fn Detail(d: PacketDetail) -> impl IntoView {
    let ctx = use_ctx();
    let hl = RwSignal::new(None::<(u32, u32)>);
    let bytes = d.bytes.clone();
    let hex = Memo::new(move |_| hex_dump(&bytes, hl.get()));
    let conv = d.conversation_filter.clone();
    let cat = d.category;
    let src = who(&d.src_name, &d.src);
    let dst = who(&d.dst_name, &d.dst);
    let layers = d.layers.clone();
    let tips = d.tips.clone();

    view! {
        <div class="detail-grid">
            <section class="explain card">
                <div class="explain-head">
                    <span class=format!("cat-badge cat-{}", cat.id())>{move || cat.label(ctx.lang())}</span>
                    <span class="proto">{d.protocol.clone()}</span>
                    <span class="dim">{format!("#{} · {} o", d.no, d.length)}</span>
                </div>
                <div class="route">
                    <div class="end"><small>{move || ctx.t("dt.from")}</small><strong title=d.src.clone()>{src}</strong></div>
                    <span class="arrow">"→"</span>
                    <div class="end"><small>{move || ctx.t("dt.to")}</small><strong title=d.dst.clone()>{dst}</strong></div>
                </div>
                <p class="explain-text">{d.explanation.clone()}</p>
                <ul class="tips">
                    {tips.into_iter().map(|t| view! { <li>{t}</li> }).collect_view()}
                </ul>
                <div class="actions">
                    {conv.map(|f| view! {
                        <button class="btn small" on:click=move |_| ctx.apply_filter(f.clone())>
                            <Icon name="target"/>{move || ctx.t("dt.follow_conv")}
                        </button>
                    })}
                    <button class="btn small ai" on:click=move |_| ctx.explain_selected()>
                        <Icon name="sparkles"/>{move || ctx.t("dt.ask_ai")}
                    </button>
                </div>
            </section>
            <section class="tree card">
                <h4>{move || ctx.t("dt.layers")}</h4>
                {layers.into_iter().enumerate().map(|(i, l)| {
                    let range = (l.offset, l.len);
                    view! {
                        <details class="layer" open={i > 0} on:mouseenter=move |_| hl.set(Some(range)) on:mouseleave=move |_| hl.set(None)>
                            <summary>
                                <span class=format!("lid lid-{}", l.id)>{l.id.to_uppercase()}</span>
                                <span class="ltitle">{l.title.clone()}</span>
                            </summary>
                            <p class="lhelp">{l.help.clone()}</p>
                            <table class="fields">
                                {l.fields.into_iter().map(|f| {
                                    let title = f.help.clone().unwrap_or_default();
                                    let has_help = f.help.is_some();
                                    view! {
                                        <tr title=title>
                                            <td class="fname">{f.name}{has_help.then(|| view! { <span class="qm">"?"</span> })}</td>
                                            <td class="fval">{f.value}</td>
                                        </tr>
                                    }
                                }).collect_view()}
                            </table>
                        </details>
                    }
                }).collect_view()}
            </section>
            <section class="hex card">
                <h4>{move || ctx.t("dt.bytes")}<small class="dim">{move || ctx.t("dt.bytes_hint")}</small></h4>
                <div class="hexdump" inner_html=move || hex.get()></div>
            </section>
        </div>
    }
}
