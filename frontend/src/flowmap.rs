//! Carte des flux : qui parle à qui. L'épaisseur d'un trait suit la quantité
//! de données échangées, la taille d'un nœud son volume total.

use std::collections::HashMap;

use leptos::prelude::*;
use leptos::task::spawn_local;
use rustshark_shared::{CaptureState, FlowEdge, FlowGraph, FlowNode, FlowNodeKind, Lang};
use serde::Serialize;

use crate::api::call;
use crate::icons::Icon;
use crate::state::{use_ctx, Tab};
use crate::util::{fmt_bytes, fmt_count};

#[derive(Serialize)]
struct FlowsArg {
    filtered: bool,
    max_nodes: u32,
}

#[derive(Clone, PartialEq, Debug)]
enum Sel {
    Node(String),
    Edge(String, String),
}

const W: f64 = 1000.0;
const ROW: f64 = 38.0;
const SIDE_X: f64 = 250.0;
const MAX_STROKE: f64 = 22.0;
const MIN_STROKE: f64 = 1.2;

/// Épaisseur d'un trait : proportionnelle à la racine du volume, pour que les
/// petits flux restent visibles à côté des gros.
fn stroke(bytes: u64, max: u64) -> f64 {
    MIN_STROKE + (MAX_STROKE - MIN_STROKE) * (bytes as f64 / max.max(1) as f64).sqrt()
}

fn radius(bytes: u64, max: u64) -> f64 {
    6.0 + 16.0 * (bytes as f64 / max.max(1) as f64).sqrt()
}

/// Couleur d'un flux selon son chiffrement.
fn edge_class(e: &FlowEdge) -> &'static str {
    if e.bytes > 0 && e.cleartext_bytes as f64 / e.bytes as f64 > 0.05 {
        "clear"
    } else if e.encrypted_percent >= 70.0 {
        "secure"
    } else {
        "other"
    }
}

fn kind_class(k: FlowNodeKind) -> &'static str {
    match k {
        FlowNodeKind::ThisComputer => "me",
        FlowNodeKind::Local => "local",
        FlowNodeKind::Internet => "internet",
        FlowNodeKind::Group => "group",
    }
}

fn short(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n - 1).collect::<String>())
    }
}

struct Layout {
    pos: HashMap<String, (f64, f64)>,
    /// -1 : colonne de gauche (local), 0 : centre, 1 : droite (Internet).
    side: HashMap<String, i8>,
    height: f64,
    center_x: f64,
}

/// Disposition en trois colonnes : réseau local à gauche, cet ordinateur au
/// centre, Internet à droite. Chaque colonne est triée par volume.
fn layout(g: &FlowGraph) -> Layout {
    let center = g
        .nodes
        .iter()
        .find(|n| n.kind == FlowNodeKind::ThisComputer)
        .or_else(|| g.nodes.iter().find(|n| n.kind == FlowNodeKind::Local && !n.id.starts_with("others")))
        .or(g.nodes.first())
        .map(|n| n.id.clone());
    let rank = |n: &FlowNode| (n.id.starts_with("others"), n.kind == FlowNodeKind::Group, std::cmp::Reverse(n.bytes));
    let mut left: Vec<&FlowNode> = g.nodes.iter().filter(|n| Some(&n.id) != center.as_ref() && n.kind != FlowNodeKind::Internet).collect();
    let mut right: Vec<&FlowNode> = g.nodes.iter().filter(|n| Some(&n.id) != center.as_ref() && n.kind == FlowNodeKind::Internet).collect();
    left.sort_by_key(|n| rank(n));
    right.sort_by_key(|n| rank(n));
    let rows = left.len().max(right.len()).max(3) as f64;
    let height = rows * ROW + 50.0;
    let mut pos = HashMap::new();
    let mut side = HashMap::new();
    let place = |col: &[&FlowNode], x: f64, s: i8, pos: &mut HashMap<String, (f64, f64)>, side: &mut HashMap<String, i8>| {
        let top = (height - col.len() as f64 * ROW) / 2.0 + ROW / 2.0;
        for (i, n) in col.iter().enumerate() {
            pos.insert(n.id.clone(), (x, top + i as f64 * ROW));
            side.insert(n.id.clone(), s);
        }
    };
    place(&left, SIDE_X, -1, &mut pos, &mut side);
    place(&right, W - SIDE_X, 1, &mut pos, &mut side);
    if let Some(c) = center {
        pos.insert(c.clone(), (W / 2.0, height / 2.0));
        side.insert(c, 0);
    }
    Layout { pos, side, height, center_x: W / 2.0 }
}

fn edge_path(l: &Layout, e: &FlowEdge) -> Option<String> {
    let (x1, y1) = *l.pos.get(&e.source)?;
    let (x2, y2) = *l.pos.get(&e.target)?;
    Some(if (x1 - x2).abs() < 1.0 {
        // Deux nœuds de la même colonne : courbe qui s'incurve vers le centre.
        let cx = x1 + (l.center_x - x1) * 0.45;
        format!("M{x1:.1},{y1:.1} C{cx:.1},{y1:.1} {cx:.1},{y2:.1} {x2:.1},{y2:.1}")
    } else {
        let mx = (x1 + x2) / 2.0;
        format!("M{x1:.1},{y1:.1} C{mx:.1},{y1:.1} {mx:.1},{y2:.1} {x2:.1},{y2:.1}")
    })
}

#[component]
pub fn FlowMap() -> impl IntoView {
    let ctx = use_ctx();
    let filtered = RwSignal::new(false);
    let max_nodes = RwSignal::new(25u32);
    let graph = RwSignal::new(None::<FlowGraph>);
    let sel = RwSignal::new(None::<Sel>);
    let load = move || {
        let arg = FlowsArg { filtered: filtered.get_untracked(), max_nodes: max_nodes.get_untracked() };
        spawn_local(async move {
            if let Ok(g) = call::<_, FlowGraph>("get_flows", &arg).await {
                graph.set(Some(g));
            }
        });
    };
    Effect::new(move |_| {
        filtered.track();
        max_nodes.track();
        ctx.lang();
        ctx.filter_applied.track();
        load();
    });
    if let Ok(h) = set_interval_with_handle(
        move || {
            if ctx.status.with_untracked(|s| s.state == CaptureState::Running) {
                load();
            }
        },
        std::time::Duration::from_millis(2000),
    ) {
        on_cleanup(move || h.clear());
    }
    let has_filter = Memo::new(move |_| !ctx.filter_applied.get().is_empty());

    view! {
        <div class="flowmap">
            <div class="dash-head">
                <h2>{move || ctx.t("fl.title")}</h2>
                <Show when=move || has_filter.get()>
                    <div class="segmented">
                        <button class:on=move || !filtered.get() on:click=move |_| filtered.set(false)>{move || ctx.t("db.all")}</button>
                        <button class:on=move || filtered.get() on:click=move |_| filtered.set(true)>{move || ctx.t("db.filtered")}</button>
                    </div>
                </Show>
                <label class="fl-max">
                    <span class="dim small">{move || ctx.t("fl.max")}</span>
                    <select on:change=move |ev| max_nodes.set(event_target_value(&ev).parse().unwrap_or(25))>
                        {[10u32, 25, 50, 100].into_iter().map(|n| view! { <option value=n.to_string() selected=n == 25>{n}</option> }).collect_view()}
                    </select>
                </label>
                <button class="icon-btn" title=move || ctx.t("db.refresh") on:click=move |_| load()><Icon name="refresh"/></button>
            </div>
            {move || match graph.get() {
                None => view! { <div class="loading">{ctx.t("w.loading")}</div> }.into_any(),
                Some(g) if g.edges.is_empty() => view! { <div class="plist-empty static">{ctx.t("fl.empty")}</div> }.into_any(),
                Some(g) => view! { <FlowBody g=g sel=sel/> }.into_any(),
            }}
        </div>
    }
}

#[component]
fn FlowBody(g: FlowGraph, sel: RwSignal<Option<Sel>>) -> impl IntoView {
    let ctx = use_ctx();
    let lang = ctx.lang_untracked();
    let l = layout(&g);
    let max_edge = g.edges.iter().map(|e| e.bytes).max().unwrap_or(1);
    let max_node = g.nodes.iter().map(|n| n.bytes).max().unwrap_or(1);
    let height = l.height;

    // Les gros flux d'abord : les petits restent visibles par-dessus.
    let mut edges = g.edges.clone();
    edges.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    let touches = move |e: &FlowEdge, s: &Option<Sel>| match s {
        None => true,
        Some(Sel::Node(id)) => e.source == *id || e.target == *id,
        Some(Sel::Edge(a, b)) => e.source == *a && e.target == *b,
    };
    let edge_views = edges
        .iter()
        .filter_map(|e| {
            let d = edge_path(&l, e)?;
            let w = stroke(e.bytes, max_edge);
            let cls = edge_class(e);
            let (a, b) = (e.source.clone(), e.target.clone());
            let e2 = e.clone();
            let tip = format!(
                "{} ⇄ {}\n{} · {} {}\n{}",
                label_of(&g, &e.source),
                label_of(&g, &e.target),
                fmt_bytes(e.bytes, lang),
                fmt_count(e.packets),
                ctx.tu("w.packets"),
                e.services.join(", ")
            );
            Some(view! {
                <path class=format!("fl-edge {cls}") d=d stroke-width=format!("{w:.1}")
                    class:dim=move || !sel.with(|s| touches(&e2, s))
                    on:click=move |ev| {
                        ev.stop_propagation();
                        sel.set(Some(Sel::Edge(a.clone(), b.clone())));
                    }>
                    <title>{tip}</title>
                </path>
            })
        })
        .collect_view();

    let neighbours = {
        let edges = g.edges.clone();
        move |id: &str, s: &Option<Sel>| match s {
            None => true,
            Some(Sel::Node(n)) => n == id || edges.iter().any(|e| (e.source == *n && e.target == id) || (e.target == *n && e.source == id)),
            Some(Sel::Edge(a, b)) => a == id || b == id,
        }
    };
    let node_views = g
        .nodes
        .iter()
        .filter_map(|n| {
            let (x, y) = *l.pos.get(&n.id)?;
            let side = l.side.get(&n.id).copied().unwrap_or(0);
            let r = if side == 0 { radius(n.bytes, max_node).max(18.0) } else { radius(n.bytes, max_node) };
            let (tx, anchor, ty) = match side {
                -1 => (x - r - 8.0, "end", y),
                1 => (x + r + 8.0, "start", y),
                _ => (x, "middle", y + r + 16.0),
            };
            let id = n.id.clone();
            let id2 = n.id.clone();
            let nb = neighbours.clone();
            let name = short(&n.label, if side == 0 { 30 } else { 32 });
            let sub = if n.members > 1 && n.id.starts_with("others") {
                format!("{} · {} {}", fmt_bytes(n.bytes, lang), n.members, ctx.tu("fl.addresses"))
            } else {
                fmt_bytes(n.bytes, lang)
            };
            let tip = format!("{}\n{}\n{}", n.label, n.addresses.join(", "), fmt_bytes(n.bytes, lang));
            Some(view! {
                <g class=format!("fl-node {}", kind_class(n.kind))
                    class:dim=move || !sel.with(|s| nb(&id2, s))
                    class:on=move || sel.with(|s| matches!(s, Some(Sel::Node(x)) if *x == id))
                    on:click={
                        let id = n.id.clone();
                        move |ev: leptos::ev::MouseEvent| {
                            ev.stop_propagation();
                            sel.update(|s| *s = if matches!(s, Some(Sel::Node(x)) if *x == id) { None } else { Some(Sel::Node(id.clone())) });
                        }
                    }>
                    <title>{tip}</title>
                    <circle cx=format!("{x:.1}") cy=format!("{y:.1}") r=format!("{r:.1}")></circle>
                    <text x=format!("{tx:.1}") y=format!("{:.1}", ty - 2.0) text-anchor=anchor class="lbl">{name}</text>
                    <text x=format!("{tx:.1}") y=format!("{:.1}", ty + 11.0) text-anchor=anchor class="vol">{sub}</text>
                </g>
            })
        })
        .collect_view();

    let total = g.bytes;
    let g2 = g.clone();
    let legend_bytes: Vec<u64> = [1.0, 0.25, 0.03].iter().map(|f| (max_edge as f64 * f) as u64).filter(|b| *b > 0).collect();

    view! {
        <div class="kpis fl-kpis">
            <div class="kpi"><small>{ctx.t("fl.k_nodes")}</small><strong>{g.nodes.len()}</strong></div>
            <div class="kpi"><small>{ctx.t("fl.k_flows")}</small><strong>{g.edges.len()}</strong></div>
            <div class="kpi"><small>{ctx.t("db.volume")}</small><strong>{fmt_bytes(total, lang)}</strong></div>
            <div class="kpi"><small>{ctx.t("fl.k_secure")}</small><strong>{secure_share(&g)}</strong></div>
        </div>
        <div class="fl-wrap">
            <section class="card fl-canvas" on:click=move |_| sel.set(None)>
                <div class="fl-cols dim small">
                    <span>{ctx.t("fl.col_local")}</span>
                    <span>{ctx.t("fl.col_me")}</span>
                    <span>{ctx.t("fl.col_net")}</span>
                </div>
                <svg viewBox=format!("0 0 {W} {height:.0}") class="fl-svg" style=format!("aspect-ratio: {W} / {height:.0}")>
                    <g>{edge_views}</g>
                    <g>{node_views}</g>
                </svg>
            </section>
            <aside class="fl-side">
                <section class="card">
                    <h3><Icon name="info"/>{ctx.t("fl.detail")}</h3>
                    {move || detail(&g2, sel.get(), lang)}
                </section>
                <section class="card fl-legend">
                    <h3><Icon name="book"/>{ctx.t("fl.legend")}</h3>
                    <p class="dim small">{ctx.t("fl.width")}</p>
                    {legend_bytes.into_iter().map(|b| {
                        let w = stroke(b, max_edge);
                        view! {
                            <div class="lg-row">
                                <svg viewBox="0 0 70 26" class="lg-line"><line x1="13" y1="13" x2="57" y2="13" stroke-width=format!("{w:.1}")></line></svg>
                                <span>{fmt_bytes(b, lang)}</span>
                            </div>
                        }
                    }).collect_view()}
                    <div class="lg-row"><span class="lg-sw secure"></span>{ctx.t("fl.secure")}</div>
                    <div class="lg-row"><span class="lg-sw clear"></span>{ctx.t("fl.clear")}</div>
                    <div class="lg-row"><span class="lg-sw other"></span>{ctx.t("fl.other")}</div>
                    <div class="lg-row"><span class="lg-dot me"></span>{ctx.t("fl.n_me")}</div>
                    <div class="lg-row"><span class="lg-dot local"></span>{ctx.t("fl.n_local")}</div>
                    <div class="lg-row"><span class="lg-dot internet"></span>{ctx.t("fl.n_internet")}</div>
                    <div class="lg-row"><span class="lg-dot group"></span>{ctx.t("fl.n_group")}</div>
                    {(g.omitted_edges > 0).then(|| view! {
                        <p class="dim small">{format!("{} {} ({})", g.omitted_edges, ctx.t("fl.omitted"), fmt_bytes(g.omitted_bytes, lang))}</p>
                    })}
                </section>
            </aside>
        </div>
    }
}

fn label_of(g: &FlowGraph, id: &str) -> String {
    g.nodes.iter().find(|n| n.id == id).map(|n| n.label.clone()).unwrap_or_else(|| id.to_string())
}

fn secure_share(g: &FlowGraph) -> String {
    let total: u64 = g.edges.iter().map(|e| e.bytes).sum();
    if total == 0 {
        return "—".into();
    }
    let enc: f64 = g.edges.iter().map(|e| e.bytes as f64 * e.encrypted_percent / 100.0).sum();
    format!("{:.0} %", enc / total as f64 * 100.0)
}

/// Panneau de détail du nœud ou du flux sélectionné.
fn detail(g: &FlowGraph, sel: Option<Sel>, lang: Lang) -> AnyView {
    let ctx = use_ctx();
    let go = move |f: String| {
        ctx.apply_filter(f);
        ctx.tab.set(Tab::Packets);
    };
    match sel {
        None => view! { <p class="dim small">{ctx.t("fl.hint")}</p> }.into_any(),
        Some(Sel::Node(id)) => {
            let Some(n) = g.nodes.iter().find(|n| n.id == id).cloned() else { return ().into_any() };
            let mut links: Vec<(String, u64)> = g
                .edges
                .iter()
                .filter(|e| e.source == id || e.target == id)
                .map(|e| (label_of(g, if e.source == id { &e.target } else { &e.source }), e.bytes))
                .collect();
            links.sort_by(|a, b| b.1.cmp(&a.1));
            let max = links.first().map(|x| x.1).unwrap_or(1).max(1);
            view! {
                <h4 class="fl-title">{n.label.clone()}</h4>
                <p class="dim small mono">{n.addresses.join(", ")}</p>
                <p>{format!("{} · {} {}", fmt_bytes(n.bytes, lang), fmt_count(n.packets), ctx.tu("w.packets"))}</p>
                <h5 class="fl-sub">{ctx.t("fl.talks_to")}</h5>
                {links.into_iter().take(12).map(|(name, b)| view! {
                    <div class="bar-row static">
                        <div class="bar-label"><span class="ell">{name}</span><span class="dim">{fmt_bytes(b, lang)}</span></div>
                        <div class="bar alt"><div style=format!("width:{:.1}%", b as f64 / max as f64 * 100.0)></div></div>
                    </div>
                }).collect_view()}
                {n.filter.clone().map(|f| view! { <button class="btn small" on:click=move |_| go(f.clone())><Icon name="filter"/>{ctx.t("db.see")}</button> })}
            }
            .into_any()
        }
        Some(Sel::Edge(a, b)) => {
            let Some(e) = g.edges.iter().find(|e| e.source == a && e.target == b).cloned() else { return ().into_any() };
            let (na, nb) = (label_of(g, &a), label_of(g, &b));
            let state = match edge_class(&e) {
                "secure" => ctx.t("fl.secure"),
                "clear" => ctx.t("fl.clear"),
                _ => ctx.t("fl.other"),
            };
            view! {
                <h4 class="fl-title">{format!("{na} ⇄ {nb}")}</h4>
                <table class="fields">
                    <tr><td class="fname">{format!("{na} → {nb}")}</td><td class="fval">{fmt_bytes(e.bytes_source_to_target, lang)}</td></tr>
                    <tr><td class="fname">{format!("{nb} → {na}")}</td><td class="fval">{fmt_bytes(e.bytes_target_to_source, lang)}</td></tr>
                    <tr><td class="fname">{ctx.t("w.packets")}</td><td class="fval">{fmt_count(e.packets)}</td></tr>
                    <tr><td class="fname">{ctx.t("fl.encrypted")}</td><td class="fval">{format!("{:.0} % · {state}", e.encrypted_percent)}</td></tr>
                    <tr><td class="fname">{ctx.t("db.c_service")}</td><td class="fval">{e.services.join(", ")}</td></tr>
                    <tr><td class="fname">{ctx.t("fl.when")}</td><td class="fval">{format!("{:.1} s → {:.1} s", e.first_s, e.last_s)}</td></tr>
                </table>
                {e.filter.clone().map(|f| view! { <button class="btn small" on:click=move |_| go(f.clone())><Icon name="filter"/>{ctx.t("db.see")}</button> })}
            }
            .into_any()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stroke_grows_with_volume() {
        assert!((stroke(100, 100) - MAX_STROKE).abs() < 1e-9);
        assert!(stroke(1, 100) < stroke(25, 100));
        assert!(stroke(0, 100) >= MIN_STROKE);
    }
}
