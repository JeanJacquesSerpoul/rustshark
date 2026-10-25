//! Formatage et rendu Markdown.

use pulldown_cmark::{html, CowStr, Event, Options, Parser};
use rustshark_shared::{filter, Lang};

pub fn fmt_count(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push('\u{202f}');
        }
        out.push(c);
    }
    out
}

pub fn fmt_bytes(b: u64, lang: Lang) -> String {
    let (o, k, m, g) = match lang {
        Lang::Fr => ("o", "Ko", "Mo", "Go"),
        Lang::En => ("B", "kB", "MB", "GB"),
    };
    let f = b as f64;
    if f >= 1e9 {
        format!("{:.2} {g}", f / 1e9)
    } else if f >= 1e6 {
        format!("{:.1} {m}", f / 1e6)
    } else if f >= 1e3 {
        format!("{:.1} {k}", f / 1e3)
    } else {
        format!("{b} {o}")
    }
}

pub fn fmt_duration(secs: f64) -> String {
    let s = secs.max(0.0) as u64;
    let (h, m, s) = (s / 3600, (s % 3600) / 60, s % 60);
    if h > 0 {
        format!("{h}:{m:02}:{s:02}")
    } else {
        format!("{m:02}:{s:02}")
    }
}

pub fn fmt_rate(bytes: u64, secs: f64, lang: Lang) -> String {
    if secs <= 0.0 {
        return "—".into();
    }
    let bits = bytes as f64 * 8.0 / secs;
    let unit = if lang == Lang::Fr { "bit/s" } else { "bps" };
    if bits >= 1e6 {
        format!("{:.1} M{unit}", bits / 1e6)
    } else if bits >= 1e3 {
        format!("{:.0} k{unit}", bits / 1e3)
    } else {
        format!("{bits:.0} {unit}")
    }
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// Markdown → HTML sûr : le HTML brut est neutralisé et les filtres
/// RustShark valides entre backticks deviennent des puces cliquables.
pub fn markdown(text: &str) -> String {
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_TABLES);
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    opts.insert(Options::ENABLE_TASKLISTS);
    let events = Parser::new_ext(text, opts).map(|ev| match ev {
        Event::Html(h) | Event::InlineHtml(h) => Event::Text(h),
        Event::Code(code) => {
            let valid = filter::parse(&code).map(|e| e.uses_fields()).unwrap_or(false);
            if valid {
                Event::InlineHtml(CowStr::from(format!(
                    "<code class=\"fchip\" data-filter=\"{}\" title=\"↵\">{}</code>",
                    escape(&code),
                    escape(&code)
                )))
            } else {
                Event::Code(code)
            }
        }
        // Les liens sont affichés en texte : pas de navigation dans la webview.
        Event::Start(pulldown_cmark::Tag::Link { .. }) | Event::End(pulldown_cmark::TagEnd::Link) => Event::Text(CowStr::from("")),
        Event::Start(pulldown_cmark::Tag::Image { .. }) | Event::End(pulldown_cmark::TagEnd::Image) => Event::Text(CowStr::from("")),
        other => other,
    });
    let mut out = String::new();
    html::push_html(&mut out, events);
    out
}

pub fn hex_dump(bytes: &[u8], hl: Option<(u32, u32)>) -> String {
    let (hs, he) = hl.map(|(o, l)| (o as usize, (o + l) as usize)).unwrap_or((usize::MAX, 0));
    let mut out = String::with_capacity(bytes.len() * 12);
    for (row, chunk) in bytes.chunks(16).enumerate() {
        let base = row * 16;
        out.push_str(&format!("<div class=\"hx-row\"><span class=\"hx-off\">{base:04x}</span><span class=\"hx-bytes\">"));
        for (i, b) in chunk.iter().enumerate() {
            let pos = base + i;
            let cls = if pos >= hs && pos < he { " class=\"hl\"" } else { "" };
            out.push_str(&format!("<span{cls}>{b:02x}</span>"));
            if i == 7 {
                out.push(' ');
            }
        }
        for _ in chunk.len()..16 {
            out.push_str("<span class=\"pad\">  </span>");
        }
        out.push_str("</span><span class=\"hx-ascii\">");
        for (i, b) in chunk.iter().enumerate() {
            let pos = base + i;
            let c = if (0x20..0x7f).contains(b) { *b as char } else { '·' };
            let esc = match c {
                '<' => "&lt;".to_string(),
                '>' => "&gt;".to_string(),
                '&' => "&amp;".to_string(),
                c => c.to_string(),
            };
            if pos >= hs && pos < he {
                out.push_str(&format!("<span class=\"hl\">{esc}</span>"));
            } else {
                out.push_str(&esc);
            }
        }
        out.push_str("</span></div>");
    }
    out
}
