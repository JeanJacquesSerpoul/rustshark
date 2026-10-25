//! Assistant IA : DeepSeek et OpenRouter (API compatibles OpenAI).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use futures_util::StreamExt;
use rustshark_shared::filter::SYNTAX_HELP;
use rustshark_shared::{AiScope, AnalysisProfile, ChatMessage, Lang, ModelInfo, Provider};
use serde_json::{json, Value};

use crate::dissect::is_private;
use crate::store::Store;

fn chat_url(p: Provider) -> &'static str {
    match p {
        Provider::DeepSeek => "https://api.deepseek.com/chat/completions",
        Provider::OpenRouter => "https://openrouter.ai/api/v1/chat/completions",
    }
}

fn models_url(p: Provider) -> &'static str {
    match p {
        Provider::DeepSeek => "https://api.deepseek.com/models",
        Provider::OpenRouter => "https://openrouter.ai/api/v1/models",
    }
}

fn request(client: &reqwest::Client, p: Provider, url: &str, key: Option<&str>) -> reqwest::RequestBuilder {
    let mut r = client.get(url);
    if let Some(k) = key {
        r = r.bearer_auth(k);
    }
    if p == Provider::OpenRouter {
        r = r.header("HTTP-Referer", "https://github.com/rustshark/rustshark").header("X-Title", "RustShark");
    }
    r
}

fn post(client: &reqwest::Client, p: Provider, key: &str) -> reqwest::RequestBuilder {
    let mut r = client.post(chat_url(p)).bearer_auth(key);
    if p == Provider::OpenRouter {
        r = r.header("HTTP-Referer", "https://github.com/rustshark/rustshark").header("X-Title", "RustShark");
    }
    r
}

/// Transforme une erreur HTTP en message compréhensible.
async fn http_error(resp: reqwest::Response, lang: Lang) -> String {
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    let detail = serde_json::from_str::<Value>(&body)
        .ok()
        .and_then(|v| v["error"]["message"].as_str().map(String::from).or_else(|| v["message"].as_str().map(String::from)))
        .unwrap_or_else(|| body.chars().take(200).collect());
    let hint = match status {
        401 => lang.pick("Clé API invalide ou révoquée.", "Invalid or revoked API key."),
        402 => lang.pick("Crédit insuffisant sur le compte du fournisseur.", "Insufficient credit on the provider account."),
        403 => lang.pick("Accès refusé par le fournisseur.", "Access denied by the provider."),
        404 => lang.pick("Modèle introuvable : vérifiez son identifiant.", "Model not found: check its identifier."),
        429 => lang.pick("Trop de requêtes : patientez un peu.", "Too many requests: please wait a little."),
        500..=599 => lang.pick("Le service IA rencontre un problème, réessayez plus tard.", "The AI service has a problem, try again later."),
        _ => "",
    };
    format!("HTTP {status} — {hint} {detail}").trim().to_string()
}

fn net_error(e: reqwest::Error, lang: Lang) -> String {
    if e.is_timeout() {
        lang.pick("Délai dépassé en contactant le service IA.", "Timed out contacting the AI service.").into()
    } else if e.is_connect() {
        format!("{} ({e})", lang.pick("Impossible de joindre le service IA (connexion Internet ?)", "Cannot reach the AI service (Internet connection?)"))
    } else {
        e.to_string()
    }
}

fn messages_json(messages: &[ChatMessage]) -> Vec<Value> {
    messages.iter().map(|m| json!({ "role": m.role, "content": m.content })).collect()
}

/// Réponse en streaming. `on_delta(texte, est_un_raisonnement)`.
pub async fn stream_chat(
    client: &reqwest::Client,
    provider: Provider,
    model: &str,
    key: &str,
    messages: &[ChatMessage],
    cancel: Arc<AtomicBool>,
    lang: Lang,
    mut on_delta: impl FnMut(&str, bool),
) -> Result<(), String> {
    let body = json!({
        "model": model,
        "messages": messages_json(messages),
        "stream": true,
        "temperature": 0.3,
    });
    let resp = post(client, provider, key).json(&body).send().await.map_err(|e| net_error(e, lang))?;
    if !resp.status().is_success() {
        return Err(http_error(resp, lang).await);
    }
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        if cancel.load(Ordering::Relaxed) {
            return Ok(());
        }
        buf.extend_from_slice(&chunk.map_err(|e| net_error(e, lang))?);
        while let Some(pos) = buf.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = buf.drain(..=pos).collect();
            let line = String::from_utf8_lossy(&line);
            let line = line.trim();
            let Some(data) = line.strip_prefix("data:") else { continue };
            let data = data.trim();
            if data == "[DONE]" {
                return Ok(());
            }
            let Ok(v) = serde_json::from_str::<Value>(data) else { continue };
            if let Some(err) = v["error"]["message"].as_str() {
                return Err(err.to_string());
            }
            let delta = &v["choices"][0]["delta"];
            for k in ["reasoning_content", "reasoning"] {
                if let Some(r) = delta[k].as_str() {
                    if !r.is_empty() {
                        on_delta(r, true);
                    }
                }
            }
            if let Some(c) = delta["content"].as_str() {
                if !c.is_empty() {
                    on_delta(c, false);
                }
            }
        }
    }
    Ok(())
}

pub async fn complete(
    client: &reqwest::Client,
    provider: Provider,
    model: &str,
    key: &str,
    messages: &[ChatMessage],
    json_mode: bool,
    lang: Lang,
) -> Result<String, String> {
    let mut body = json!({
        "model": model,
        "messages": messages_json(messages),
        "temperature": 0.2,
    });
    if json_mode && provider == Provider::DeepSeek {
        body["response_format"] = json!({ "type": "json_object" });
    }
    let resp = post(client, provider, key).json(&body).send().await.map_err(|e| net_error(e, lang))?;
    if !resp.status().is_success() {
        return Err(http_error(resp, lang).await);
    }
    let v: Value = resp.json().await.map_err(|e| e.to_string())?;
    v["choices"][0]["message"]["content"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| lang.pick("Réponse vide du modèle.", "Empty response from the model.").into())
}

pub async fn list_models(client: &reqwest::Client, provider: Provider, key: Option<&str>, lang: Lang) -> Result<Vec<ModelInfo>, String> {
    let resp = request(client, provider, models_url(provider), key).send().await.map_err(|e| net_error(e, lang))?;
    if !resp.status().is_success() {
        return Err(http_error(resp, lang).await);
    }
    let v: Value = resp.json().await.map_err(|e| e.to_string())?;
    let mut out: Vec<ModelInfo> = v["data"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|m| {
                    let id = m["id"].as_str()?.to_string();
                    let free = id.ends_with(":free")
                        || (m["pricing"]["prompt"].as_str() == Some("0") && m["pricing"]["completion"].as_str() == Some("0"));
                    Some(ModelInfo {
                        name: m["name"].as_str().unwrap_or(&id).to_string(),
                        context: m["context_length"].as_u64(),
                        free,
                        id,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(out)
}

// ---------------------------------------------------------------------------
// Invites
// ---------------------------------------------------------------------------

pub fn system_prompt(lang: Lang) -> String {
    let body = match lang {
        Lang::Fr => "Tu es « RustShark Assistant », expert en réseaux et en cybersécurité, et excellent pédagogue. L'utilisateur peut être totalement débutant.\n\
Règles :\n\
- Réponds en français, de façon claire et structurée (titres courts, listes, **gras** pour l'essentiel). Commence par un résumé de 2 à 3 phrases.\n\
- Explique chaque terme technique en une phrase simple la première fois (les analogies sont bienvenues).\n\
- Appuie-toi UNIQUEMENT sur les données de capture fournies ; si une information manque, dis-le et explique comment l'obtenir.\n\
- Distingue le bruit de fond normal (mDNS, SSDP, ARP, LLMNR, télémétrie, mises à jour…) de ce qui mérite attention.\n\
- Pour chaque point d'attention, donne un niveau (🟢 normal, 🟡 à surveiller, 🔴 important) et une action concrète.\n\
- Quand c'est utile, propose des filtres d'affichage RustShark entre backticks, par exemple `dns` ou `ip.addr == 192.168.1.10 && tls` : l'utilisateur pourra cliquer dessus pour les appliquer.\n\
- N'invente jamais d'adresses, de noms ou de chiffres absents des données. Les adresses de la forme LAN-n ou MAC-n ont été masquées pour la confidentialité.",
        Lang::En => "You are \"RustShark Assistant\", an expert in networking and cybersecurity and an excellent teacher. The user may be a complete beginner.\n\
Rules:\n\
- Answer in English, clearly and with structure (short headings, lists, **bold** for key points). Start with a 2-3 sentence summary.\n\
- Explain each technical term in one simple sentence the first time (analogies are welcome).\n\
- Rely ONLY on the capture data provided; if information is missing, say so and explain how to get it.\n\
- Distinguish normal background noise (mDNS, SSDP, ARP, LLMNR, telemetry, updates…) from what deserves attention.\n\
- For each point of attention give a level (🟢 normal, 🟡 watch, 🔴 important) and a concrete action.\n\
- When useful, suggest RustShark display filters in backticks, e.g. `dns` or `ip.addr == 192.168.1.10 && tls`: the user can click them to apply.\n\
- Never invent addresses, names or numbers that are not in the data. Addresses shaped like LAN-n or MAC-n were masked for privacy.",
    };
    format!("{body}\n\n{SYNTAX_HELP}")
}

pub fn profile_prompt(lang: Lang) -> String {
    let l = match lang {
        Lang::Fr => "French",
        Lang::En => "English",
    };
    format!(
        "You design network capture configurations for RustShark, a beginner-friendly packet analyzer. \
Reply with ONLY one JSON object (no markdown) with these keys:\n\
- \"name\": short title in {l}\n\
- \"explanation\": 2-4 simple sentences in {l} for a beginner: what will be observed, how, and why it answers their goal\n\
- \"capture_filter\": a valid libpcap BPF expression (e.g. \"port 53\", \"host 192.168.1.50\", \"tcp port 443 or udp port 443\") or null to capture everything. Prefer null or a simple filter; never use RustShark syntax here\n\
- \"display_filter\": a RustShark display filter or null\n\
- \"watch_points\": array of 3-6 short strings in {l}: what to look at during the capture\n\
- \"ai_prompt\": a question in {l} the user should ask the AI assistant once the capture is done\n\
- \"suggested_duration_s\": integer, suggested capture duration in seconds\n\n\
{SYNTAX_HELP}\n\
BPF reminder: host X, src host X, dst host X, net 192.168.1.0/24, port N, portrange 1-1024, tcp, udp, icmp, icmp6, arp, ip6, ether host MAC, combined with and/or/not and parentheses."
    )
}

/// Extrait et valide le profil JSON renvoyé par le modèle.
pub fn parse_profile(text: &str, goal: &str) -> Result<AnalysisProfile, String> {
    let start = text.find('{').ok_or("JSON introuvable / no JSON found")?;
    let end = text.rfind('}').ok_or("JSON introuvable / no JSON found")?;
    let v: Value = serde_json::from_str(&text[start..=end]).map_err(|e| e.to_string())?;
    let s = |k: &str| v[k].as_str().map(|x| x.trim().to_string()).filter(|x| !x.is_empty() && x != "null");
    Ok(AnalysisProfile {
        id: format!("p{}", chrono::Utc::now().timestamp_millis()),
        name: s("name").unwrap_or_else(|| goal.chars().take(40).collect()),
        goal: goal.to_string(),
        explanation: s("explanation").unwrap_or_default(),
        capture_filter: s("capture_filter"),
        display_filter: s("display_filter"),
        watch_points: v["watch_points"]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        ai_prompt: s("ai_prompt"),
        suggested_duration_s: v["suggested_duration_s"].as_u64().map(|x| x.min(86_400) as u32),
        created: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
    })
}

// ---------------------------------------------------------------------------
// Contexte de capture envoyé au modèle
// ---------------------------------------------------------------------------

fn human_bytes(b: u64) -> String {
    let b = b as f64;
    if b >= 1e9 {
        format!("{:.2} GB", b / 1e9)
    } else if b >= 1e6 {
        format!("{:.2} MB", b / 1e6)
    } else if b >= 1e3 {
        format!("{:.1} kB", b / 1e3)
    } else {
        format!("{b} B")
    }
}

pub struct ContextRequest<'a> {
    pub scope: AiScope,
    pub selected: Option<u32>,
    pub display_filter: &'a str,
    pub sample: usize,
    pub anonymize: bool,
    pub lang: Lang,
    pub profile: Option<&'a AnalysisProfile>,
}

pub fn build_context(store: &Store, req: &ContextRequest) -> String {
    let lang = req.lang;
    let filtered = matches!(req.scope, AiScope::Filtered);
    let idx = store.scope_indices(filtered);
    let stats = store.stats(filtered, lang);
    let st = store.status();
    let mut c = String::new();
    let _ = writeln!(c, "## Capture overview");
    let _ = writeln!(
        c,
        "Source: {} ({:?}) | Capture filter (BPF): {} | Display filter: {}",
        st.source.clone().unwrap_or_else(|| "-".into()),
        st.state,
        st.capture_filter.clone().unwrap_or_else(|| "none".into()),
        if req.display_filter.trim().is_empty() { "none" } else { req.display_filter }
    );
    let scope_txt = match req.scope {
        AiScope::All => "whole capture",
        AiScope::Filtered => "packets matching the display filter",
        AiScope::Packet => "one selected packet (with overall capture context)",
    };
    let _ = writeln!(
        c,
        "Scope: {scope_txt} — {} packets, {}, over {:.1} s (total captured: {} packets, dropped by OS: {})",
        stats.packets,
        human_bytes(stats.bytes),
        stats.duration,
        st.packets,
        st.dropped
    );
    let mut locals: Vec<String> = store.names.local.iter().map(|i| i.to_string()).collect();
    locals.sort();
    let _ = writeln!(c, "Addresses of the computer running the capture (\"This computer\"): {}", if locals.is_empty() { "unknown".into() } else { locals.join(", ") });

    if let Some(p) = req.profile {
        let _ = writeln!(c, "\n## Active analysis profile: {}\nGoal: {}\nWatch points: {}", p.name, p.goal, p.watch_points.join(" | "));
    }

    let _ = writeln!(c, "\n## Protocols (packets / bytes)");
    for p in stats.protocols.iter().take(15) {
        let _ = writeln!(c, "- {}: {} / {}", p.label, p.packets, human_bytes(p.bytes));
    }
    let _ = writeln!(c, "\n## Traffic families");
    for k in &stats.categories {
        let _ = writeln!(c, "- {}: {} packets / {}", k.category.label(Lang::En), k.packets, human_bytes(k.bytes));
    }
    let _ = writeln!(c, "\n## Top hosts (by bytes)");
    for h in stats.top_hosts.iter().take(12) {
        let _ = writeln!(
            c,
            "- {}{} — {} packets, {}{}",
            h.addr,
            h.name.as_ref().map(|n| format!(" ({n})")).unwrap_or_default(),
            h.packets,
            human_bytes(h.bytes),
            if h.local { ", local" } else { "" }
        );
    }
    let _ = writeln!(c, "\n## Conversations (by bytes)");
    for cv in stats.conversations.iter().take(15) {
        let _ = writeln!(
            c,
            "- {}{} <-> {}{} {} {} — {} packets, {}, {:.1}s→{:.1}s",
            cv.a,
            cv.a_name.as_ref().map(|n| format!(" ({n})")).unwrap_or_default(),
            cv.b,
            cv.b_name.as_ref().map(|n| format!(" ({n})")).unwrap_or_default(),
            cv.protocol,
            cv.service.clone().unwrap_or_default(),
            cv.packets,
            human_bytes(cv.bytes),
            cv.start,
            cv.end
        );
    }
    if !stats.dns_names.is_empty() {
        let _ = writeln!(c, "\n## DNS lookups (name × count)");
        let list: Vec<String> = stats.dns_names.iter().take(30).map(|d| format!("{} ×{}", d.label, d.packets)).collect();
        let _ = writeln!(c, "{}", list.join(", "));
    }
    if !stats.sites.is_empty() {
        let _ = writeln!(c, "\n## Remote sites/services contacted (by bytes)");
        for s in stats.sites.iter().take(20) {
            let _ = writeln!(c, "- {} — {} packets, {}", s.label, s.packets, human_bytes(s.bytes));
        }
    }
    let _ = writeln!(c, "\n## Automatic findings (heuristics)");
    if stats.alerts.is_empty() {
        let _ = writeln!(c, "- none");
    }
    for a in &stats.alerts {
        let _ = writeln!(c, "- [{:?}] {} — {}", a.level, a.title, a.detail);
    }

    // Échantillon : les premiers paquets puis des paquets répartis sur la capture.
    let sample = req.sample.max(10);
    let mut picks: Vec<u32> = Vec::new();
    if idx.len() <= sample {
        picks = idx.clone();
    } else {
        let head = sample / 3;
        picks.extend_from_slice(&idx[..head]);
        let rest = sample - head;
        let step = (idx.len() - head) as f64 / rest as f64;
        for k in 0..rest {
            picks.push(idx[head + (k as f64 * step) as usize]);
        }
        picks.dedup();
    }
    let _ = writeln!(c, "\n## Packet sample ({} of {}) — no | time s | src → dst | protocol | length | info", picks.len(), idx.len());
    for i in &picks {
        let r = store.row(*i as usize, Lang::En);
        let src = r.src_name.as_ref().map(|n| format!("{} ({n})", r.src)).unwrap_or(r.src.clone());
        let dst = r.dst_name.as_ref().map(|n| format!("{} ({n})", r.dst)).unwrap_or(r.dst.clone());
        let _ = writeln!(c, "{} | {:.3} | {src} → {dst} | {} | {} | {}", r.no, r.time, r.protocol, r.length, r.info);
    }

    if let Some(no) = req.selected {
        if let Some(d) = store.detail(no, Lang::En) {
            let _ = writeln!(c, "\n## Selected packet #{no} ({} → {}, {})", d.src, d.dst, d.protocol);
            for l in &d.layers {
                let _ = writeln!(c, "### {}", l.title);
                for f in &l.fields {
                    let _ = writeln!(c, "- {}: {}", f.name, f.value);
                }
            }
            let hex: Vec<String> = d.bytes.iter().take(256).map(|b| format!("{b:02x}")).collect();
            let _ = writeln!(c, "First bytes (hex): {}", hex.join(" "));
        }
    }

    if c.len() > 60_000 {
        let mut cut = 60_000;
        while !c.is_char_boundary(cut) {
            cut -= 1;
        }
        c.truncate(cut);
        c.push_str("\n[context truncated]");
    }
    if req.anonymize {
        let mut anon = Anonymizer::default();
        for ip in &store.names.local {
            anon.protect(*ip);
        }
        anon.apply(&c)
    } else {
        c
    }
}

/// Masquage des adresses locales avec des alias (`LAN-1`, `MAC-1`…) qui restent
/// identiques tant que l'objet vit, et qui peuvent être retraduits.
#[derive(Default)]
pub struct Anonymizer {
    aliases: HashMap<String, String>,
    originals: HashMap<String, String>,
    ips: usize,
    macs: usize,
    /// Adresses publiques à masquer quand même (celles de cet ordinateur).
    sensitive: std::collections::HashSet<IpAddr>,
    /// Préfixes IPv6 /64 du foyer : ils identifient l'abonnement Internet.
    v6_prefixes: std::collections::HashSet<u64>,
}

impl Anonymizer {
    /// Masque aussi `ip` (et, en IPv6, tout son préfixe /64) même si elle est publique.
    pub fn protect(&mut self, ip: IpAddr) {
        if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
            return;
        }
        if let IpAddr::V6(v6) = ip {
            if !is_private(&ip) {
                self.v6_prefixes.insert((u128::from(v6) >> 64) as u64);
            }
        }
        self.sensitive.insert(ip);
    }

    fn is_sensitive(&self, ip: &IpAddr) -> bool {
        if self.sensitive.contains(ip) {
            return true;
        }
        match ip {
            IpAddr::V6(v6) => self.v6_prefixes.contains(&((u128::from(*v6) >> 64) as u64)),
            IpAddr::V4(_) => false,
        }
    }

    fn alias(&mut self, original: &str, mac: bool) -> String {
        if let Some(a) = self.aliases.get(original) {
            return a.clone();
        }
        let alias = if mac {
            self.macs += 1;
            format!("MAC-{}", self.macs)
        } else {
            self.ips += 1;
            format!("LAN-{}", self.ips)
        };
        self.aliases.insert(original.to_string(), alias.clone());
        self.originals.insert(alias.clone(), original.to_string());
        alias
    }

    fn flush(&mut self, token: &mut String, out: &mut String) {
        if token.is_empty() {
            return;
        }
        let t = token.trim_end_matches(['.', ':']).to_string();
        let tail = token[t.len()..].to_string();
        let is_mac = t.len() == 17 && t.matches(':').count() == 5;
        let replacement = if is_mac && t != "ff:ff:ff:ff:ff:ff" && t != "00:00:00:00:00:00" {
            Some(self.alias(&t.to_ascii_lowercase(), true))
        } else {
            match t.parse::<IpAddr>() {
                Ok(ip) if (is_private(&ip) && !ip.is_loopback()) || self.is_sensitive(&ip) => Some(self.alias(&ip.to_string(), false)),
                _ => None,
            }
        };
        match replacement {
            Some(a) => {
                out.push_str(&a);
                out.push_str(&tail);
            }
            None => out.push_str(token),
        }
        token.clear();
    }

    pub fn apply(&mut self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut token = String::new();
        for ch in text.chars() {
            if ch.is_ascii_hexdigit() || ch == '.' || ch == ':' {
                token.push(ch);
            } else {
                self.flush(&mut token, &mut out);
                out.push(ch);
            }
        }
        self.flush(&mut token, &mut out);
        out
    }

    /// Retraduit les alias `LAN-n` / `MAC-n` en adresses réelles (filtres reçus).
    pub fn reveal(&self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(pos) = rest.find(|c| c == 'L' || c == 'M') {
            out.push_str(&rest[..pos]);
            let candidate = &rest[pos..];
            let prefix_ok = candidate.starts_with("LAN-") || candidate.starts_with("MAC-");
            let digits = candidate.get(4..).map(|s| s.chars().take_while(|c| c.is_ascii_digit()).count()).unwrap_or(0);
            let boundary_before = out.chars().last().map(|c| !c.is_alphanumeric()).unwrap_or(true);
            if prefix_ok && digits > 0 && boundary_before {
                let alias = &candidate[..4 + digits];
                match self.originals.get(alias) {
                    Some(orig) => out.push_str(orig),
                    None => out.push_str(alias),
                }
                rest = &candidate[4 + digits..];
            } else {
                out.push_str(&candidate[..1]);
                rest = &candidate[1..];
            }
        }
        out.push_str(rest);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymize_private() {
        let s = Anonymizer::default().apply("192.168.1.10 → 8.8.8.8, again 192.168.1.10. mac aa:bb:cc:dd:ee:ff deadbeef");
        assert_eq!(s, "LAN-1 → 8.8.8.8, again LAN-1. mac MAC-1 deadbeef");
    }

    #[test]
    fn anonymizer_is_stable_and_reversible() {
        let mut a = Anonymizer::default();
        assert_eq!(a.apply("{\"a\":\"192.168.1.10\",\"b\":\"10.0.0.2\"}"), "{\"a\":\"LAN-1\",\"b\":\"LAN-2\"}");
        assert_eq!(a.apply("10.0.0.2 / 192.168.1.10"), "LAN-2 / LAN-1");
        assert_eq!(a.reveal("ip.addr == LAN-2 && !ip.addr == LAN-1"), "ip.addr == 10.0.0.2 && !ip.addr == 192.168.1.10");
        assert_eq!(a.reveal("host contains LANDING || LAN-99"), "host contains LANDING || LAN-99");
        assert_eq!(a.reveal("XLAN-1"), "XLAN-1");
    }

    #[test]
    fn protects_own_public_ipv6_prefix() {
        let mut a = Anonymizer::default();
        a.protect("2a02:8434:6941:f101:b0ad:b1ab:730d:943d".parse().unwrap());
        let s = a.apply("me 2a02:8434:6941:f101:b0ad:b1ab:730d:943d tv 2a02:8434:6941:f101::42 google 2607:6bc0::10");
        assert_eq!(s, "me LAN-1 tv LAN-2 google 2607:6bc0::10");
    }

    #[test]
    fn profile_json() {
        let p = parse_profile("```json\n{\"name\":\"DNS\",\"capture_filter\":\"port 53\",\"display_filter\":null,\"watch_points\":[\"a\"]}\n```", "goal").unwrap();
        assert_eq!(p.capture_filter.as_deref(), Some("port 53"));
        assert_eq!(p.display_filter, None);
        assert_eq!(p.watch_points, vec!["a"]);
    }
}
