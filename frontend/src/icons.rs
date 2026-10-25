//! Petites icônes vectorielles (style trait, 24×24).

use leptos::prelude::*;
use rustshark_shared::{DeviceKind, IfaceKind};

fn paths(name: &str) -> &'static str {
    match name {
        "play" => r#"<polygon points="6 3 20 12 6 21 6 3"/>"#,
        "stop" => r#"<rect x="5" y="5" width="14" height="14" rx="2"/>"#,
        "trash" => r#"<path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>"#,
        "folder" => r#"<path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/>"#,
        "save" => r#"<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><path d="M17 21v-8H7v8"/><path d="M7 3v5h8"/>"#,
        "search" => r#"<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>"#,
        "x" => r#"<path d="M18 6 6 18"/><path d="m6 6 12 12"/>"#,
        "sparkles" => r#"<path d="M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9z"/><path d="M19 15l.9 2.1L22 18l-2.1.9L19 21l-.9-2.1L16 18l2.1-.9z"/>"#,
        "settings" => r#"<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.6 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>"#,
        "help" => r#"<circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><path d="M12 17h.01"/>"#,
        "wifi" => r#"<path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><path d="M12 20h.01"/>"#,
        "ethernet" => r#"<rect x="16" y="16" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="9" y="2" width="6" height="6" rx="1"/><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3"/><path d="M12 12V8"/>"#,
        "globe" => r#"<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>"#,
        "shield" => r#"<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>"#,
        "lock" => r#"<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>"#,
        "alert" => r#"<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4"/><path d="M12 17h.01"/>"#,
        "info" => r#"<circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>"#,
        "chart" => r#"<path d="M3 3v18h18"/><path d="M18 17V9"/><path d="M13 17V5"/><path d="M8 17v-3"/>"#,
        "list" => r#"<path d="M8 6h13"/><path d="M8 12h13"/><path d="M8 18h13"/><path d="M3 6h.01"/><path d="M3 12h.01"/><path d="M3 18h.01"/>"#,
        "chevron" => r#"<path d="m6 9 6 6 6-6"/>"#,
        "send" => r#"<path d="m22 2-7 20-4-9-9-4Z"/><path d="M22 2 11 13"/>"#,
        "refresh" => r#"<path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 3v5h-5"/>"#,
        "key" => r#"<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/>"#,
        "check" => r#"<path d="M20 6 9 17l-5-5"/>"#,
        "filter" => r#"<polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/>"#,
        "monitor" => r#"<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8"/><path d="M12 17v4"/>"#,
        "down" => r#"<path d="M12 5v14"/><path d="m19 12-7 7-7-7"/>"#,
        "loop" => r#"<path d="m17 2 4 4-4 4"/><path d="M3 11v-1a4 4 0 0 1 4-4h14"/><path d="m7 22-4-4 4-4"/><path d="M21 13v1a4 4 0 0 1-4 4H3"/>"#,
        "box" => r#"<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>"#,
        "bluetooth" => r#"<path d="m7 7 10 10-5 5V2l5 5L7 17"/>"#,
        "zap" => r#"<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>"#,
        "book" => r#"<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>"#,
        "external" => r#"<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>"#,
        "chat" => r#"<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>"#,
        "wand" => r#"<path d="m15 4-11 11 5 5 11-11z"/><path d="M14 5l5 5"/><path d="M19 2v3"/><path d="M22 4h-3"/>"#,
        "bookmark" => r#"<path d="m19 21-7-4-7 4V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v16z"/>"#,
        "eye" => r#"<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>"#,
        "upload" => r#"<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m17 8-5-5-5 5"/><path d="M12 3v12"/>"#,
        "target" => r#"<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>"#,
        "router" => r#"<rect x="2" y="14" width="20" height="8" rx="2"/><path d="M6.01 18H6"/><path d="M10.01 18H10"/><path d="M15 10v4"/><path d="M17.84 7.17a4 4 0 0 0-5.66 0"/><path d="M20.66 4.34a8 8 0 0 0-11.31 0"/>"#,
        "phone" => r#"<rect x="6" y="2" width="12" height="20" rx="2"/><path d="M12 18h.01"/>"#,
        "tablet" => r#"<rect x="4" y="2" width="16" height="20" rx="2"/><path d="M12 18h.01"/>"#,
        "tv" => r#"<rect x="2" y="7" width="20" height="15" rx="2"/><path d="m17 2-5 5-5-5"/>"#,
        "cast" => r#"<path d="M2 8V6a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-6"/><path d="M2 12a9 9 0 0 1 8 8"/><path d="M2 16a5 5 0 0 1 4 4"/><path d="M2 20h.01"/>"#,
        "speaker" => r#"<rect x="5" y="2" width="14" height="20" rx="2"/><circle cx="12" cy="14" r="4"/><path d="M12 6h.01"/>"#,
        "printer" => r#"<path d="M6 9V2h12v7"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/>"#,
        "camera" => r#"<path d="m22 8-6 4 6 4V8Z"/><rect x="2" y="6" width="14" height="12" rx="2"/>"#,
        "gamepad" => r#"<path d="M6 12h4"/><path d="M8 10v4"/><path d="M15 13h.01"/><path d="M18 11h.01"/><rect x="2" y="6" width="20" height="12" rx="2"/>"#,
        "server" => r#"<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><path d="M6 6h.01"/><path d="M6 18h.01"/>"#,
        "home" => r#"<path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M9 22V12h6v10"/>"#,
        "watch" => r#"<circle cx="12" cy="12" r="6"/><path d="M12 10v2l1 1"/><path d="m16.13 7.66-.81-4.05a2 2 0 0 0-2-1.61h-2.68a2 2 0 0 0-2 1.61l-.78 4.05"/><path d="m7.88 16.36.8 4a2 2 0 0 0 2 1.61h2.72a2 2 0 0 0 2-1.61l.81-4.05"/>"#,
        "laptop" => r#"<path d="M20 16V7a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v9m16 0H4m16 0 1.28 2.55a1 1 0 0 1-.9 1.45H3.62a1 1 0 0 1-.9-1.45L4 16"/>"#,
        "device" => r#"<rect x="4" y="4" width="16" height="16" rx="2"/><path d="M9.5 9.5a2.5 2.5 0 0 1 4.9.6c0 1.6-2.4 2.1-2.4 3.4"/><path d="M12 17h.01"/>"#,
        "gauge" => r#"<path d="m12 14 4-4"/><path d="M3.34 19a10 10 0 1 1 17.32 0"/>"#,
        "radar" => r#"<path d="M19.07 4.93A10 10 0 0 0 6.99 3.34"/><path d="M4 6h.01"/><path d="M2.29 9.62A10 10 0 1 0 21.31 8.35"/><path d="M16.24 7.76A6 6 0 1 0 8.23 16.67"/><path d="M12 18h.01"/><path d="M17.99 11.66A6 6 0 0 1 15.77 16.67"/><circle cx="12" cy="12" r="2"/><path d="m13.41 10.59 5.66-5.66"/>"#,
        "flows" => r#"<circle cx="5" cy="6" r="3"/><circle cx="5" cy="18" r="3"/><circle cx="19" cy="12" r="3"/><path d="M8 6.5c5 0 6 5.5 8 5.5"/><path d="M8 17.5c5 0 6-5.5 8-5.5" stroke-width="3.5"/>"#,
        "network" => r#"<rect x="9" y="2" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="16" y="16" width="6" height="6" rx="1"/><path d="M12 8v4"/><path d="M5 16v-2a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v2"/>"#,
        _ => r#"<circle cx="12" cy="12" r="9"/>"#,
    }
}

#[component]
pub fn Icon(#[prop(into)] name: String, #[prop(optional, into)] class: String) -> impl IntoView {
    let svg = paths(&name);
    view! {
        <svg class=format!("ic {class}") viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" inner_html=svg></svg>
    }
}

pub fn device_icon(kind: DeviceKind) -> &'static str {
    match kind {
        DeviceKind::Router => "router",
        DeviceKind::Computer => "laptop",
        DeviceKind::Phone => "phone",
        DeviceKind::Tablet => "tablet",
        DeviceKind::Tv => "tv",
        DeviceKind::Media => "cast",
        DeviceKind::Speaker => "speaker",
        DeviceKind::Printer => "printer",
        DeviceKind::Camera => "camera",
        DeviceKind::Console => "gamepad",
        DeviceKind::Nas => "server",
        DeviceKind::SmartHome => "home",
        DeviceKind::Watch => "watch",
        DeviceKind::Unknown => "device",
    }
}

pub fn iface_icon(kind: IfaceKind) -> &'static str {
    match kind {
        IfaceKind::Wifi => "wifi",
        IfaceKind::Ethernet => "ethernet",
        IfaceKind::Loopback => "loop",
        IfaceKind::Virtual => "box",
        IfaceKind::Vpn => "shield",
        IfaceKind::Bluetooth => "bluetooth",
        IfaceKind::Other => "monitor",
    }
}
