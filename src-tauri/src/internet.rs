//! Connexion Internet : adresse publique, opérateur, latence, DNS et débit.
//!
//! Contrairement au reste de RustShark, ces mesures contactent des services
//! publics (ipinfo.io et Cloudflare) : elles ne sont lancées qu'à la demande.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::future::join_all;
use rustshark_shared::{InternetInfo, Lang, LatencyResult, NetProgress, SpeedResult};

use crate::apps;

const CF: &str = "https://speed.cloudflare.com";

fn client(local: Option<IpAddr>, timeout: Duration) -> Result<reqwest::Client, String> {
    let mut b = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(6))
        .timeout(timeout)
        .user_agent(concat!("RustShark/", env!("CARGO_PKG_VERSION")));
    if let Some(a) = local {
        b = b.local_address(a);
    }
    b.build().map_err(|e| e.to_string())
}

fn median(v: &mut [f64]) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.total_cmp(b));
    Some(v[v.len() / 2])
}

/// Gigue : écart moyen entre deux mesures successives.
fn jitter(v: &[f64]) -> Option<f64> {
    (v.len() >= 2).then(|| v.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / (v.len() - 1) as f64)
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

// ---------------------------------------------------------------------------
// Informations et latence
// ---------------------------------------------------------------------------

#[derive(Default)]
struct CfMeta {
    ip: Option<String>,
    colo: Option<String>,
    asn: Option<String>,
    city: Option<String>,
    country: Option<String>,
}

async fn cf_meta(c: &reqwest::Client) -> Option<CfMeta> {
    let r = c.get(format!("{CF}/__down?bytes=0")).send().await.ok()?;
    let h = r.headers();
    let get = |k: &str| h.get(k).and_then(|v| v.to_str().ok()).map(String::from).filter(|s| !s.is_empty());
    Some(CfMeta { ip: get("cf-meta-ip"), colo: get("colo").or_else(|| get("cf-meta-colo")), asn: get("asn").or_else(|| get("cf-meta-asn")), city: get("city"), country: get("country") })
}

async fn ipinfo(c: &reqwest::Client) -> Result<serde_json::Value, String> {
    let r = c.get("https://ipinfo.io/json").header("Accept", "application/json").send().await.map_err(|e| e.to_string())?;
    if !r.status().is_success() {
        return Err(format!("ipinfo.io : HTTP {}", r.status().as_u16()));
    }
    r.json().await.map_err(|e| e.to_string())
}

/// Temps d'établissement d'une connexion TCP (≈ un aller-retour). Un refus
/// de connexion est aussi une réponse : il mesure le même aller-retour.
fn tcp_rtt(addr: SocketAddr) -> Option<f64> {
    let t = Instant::now();
    match TcpStream::connect_timeout(&addr, Duration::from_millis(1500)) {
        Ok(_) => Some(ms(t.elapsed())),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => Some(ms(t.elapsed())),
        Err(_) => None,
    }
}

fn probe(label: String, target: String, mut f: impl FnMut() -> Option<f64>, n: usize) -> LatencyResult {
    let mut v = Vec::new();
    let mut lost = 0;
    for i in 0..n {
        if i > 0 {
            std::thread::sleep(Duration::from_millis(120));
        }
        match f() {
            Some(x) => v.push(x),
            None => lost += 1,
        }
    }
    let j = jitter(&v);
    LatencyResult { label, target, ms: median(&mut v), jitter_ms: j, lost }
}

fn dns_rtt(server: IpAddr, id: u16) -> Option<f64> {
    let local: SocketAddr = if server.is_ipv4() { (Ipv4Addr::UNSPECIFIED, 0).into() } else { (Ipv6Addr::UNSPECIFIED, 0).into() };
    let sock = UdpSocket::bind(local).ok()?;
    sock.set_read_timeout(Some(Duration::from_millis(1500))).ok()?;
    let mut q = vec![(id >> 8) as u8, id as u8, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in ["www", "wikipedia", "org"] {
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    let t = Instant::now();
    sock.send_to(&q, (server, 53)).ok()?;
    let mut buf = [0u8; 1500];
    while t.elapsed() < Duration::from_millis(1500) {
        let (n, _) = sock.recv_from(&mut buf).ok()?;
        if apps::parse_dns(&buf[..n]).is_some_and(|i| i.response && i.id == id) {
            return Some(ms(t.elapsed()));
        }
    }
    None
}

fn measure(gateway: Option<IpAddr>, dns: Vec<IpAddr>, lang: Lang) -> (Vec<LatencyResult>, Vec<LatencyResult>) {
    let mut targets: Vec<(String, String, Vec<SocketAddr>)> = Vec::new();
    if let Some(g) = gateway {
        targets.push((lang.pick("Votre box", "Your router").into(), g.to_string(), [80, 443, 53].iter().map(|p| SocketAddr::new(g, *p)).collect()));
    }
    for (label, ip) in [("Cloudflare", "1.1.1.1"), ("Google", "8.8.8.8"), ("Quad9", "9.9.9.9")] {
        let ip: IpAddr = ip.parse().unwrap();
        targets.push((label.into(), ip.to_string(), vec![SocketAddr::new(ip, 443)]));
    }
    let mut servers: Vec<(String, IpAddr)> = dns
        .into_iter()
        .take(3)
        .map(|d| {
            let who = if Some(d) == gateway { lang.pick(" (la box)", " (the router)") } else { "" };
            (format!("DNS {d}{who}"), d)
        })
        .collect();
    let cf: IpAddr = "1.1.1.1".parse().unwrap();
    if !servers.iter().any(|(_, d)| *d == cf) {
        servers.push((lang.pick("DNS Cloudflare (comparaison)", "Cloudflare DNS (comparison)").into(), cf));
    }
    std::thread::scope(|s| {
        let lat: Vec<_> = targets
            .into_iter()
            .map(|(label, target, addrs)| {
                s.spawn(move || {
                    // Pour la box : le premier port qui répond (ouvert ou refusé).
                    let mut port = None;
                    probe(label, target, || {
                        if let Some(a) = port {
                            return tcp_rtt(a);
                        }
                        addrs.iter().find_map(|a| tcp_rtt(*a).inspect(|_| port = Some(*a)))
                    }, 6)
                })
            })
            .collect();
        let dns: Vec<_> = servers
            .into_iter()
            .enumerate()
            .map(|(i, (label, d))| {
                s.spawn(move || {
                    let mut id = 0x5200 + (i as u16) * 16;
                    probe(label, d.to_string(), || {
                        id += 1;
                        dns_rtt(d, id)
                    }, 4)
                })
            })
            .collect();
        (lat.into_iter().filter_map(|h| h.join().ok()).collect(), dns.into_iter().filter_map(|h| h.join().ok()).collect())
    })
}

pub async fn info(gateway: Option<IpAddr>, dns: Vec<IpAddr>, lang: Lang) -> InternetInfo {
    let mut out = InternetInfo::default();
    let timeout = Duration::from_secs(10);
    let (v4, any, v6) = match (client(Some(Ipv4Addr::UNSPECIFIED.into()), timeout), client(None, timeout), client(Some(Ipv6Addr::UNSPECIFIED.into()), timeout)) {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c),
        (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
            out.errors.push(e);
            return out;
        }
    };
    let measures = tauri::async_runtime::spawn_blocking(move || measure(gateway, dns, lang));
    let (info, meta, meta6) = futures_util::join!(ipinfo(&v4), cf_meta(&any), cf_meta(&v6));
    match info {
        Ok(v) => {
            let s = |k: &str| v[k].as_str().map(String::from).filter(|s| !s.is_empty());
            out.public_ip = s("ip");
            out.reverse = s("hostname");
            out.city = s("city");
            out.region = s("region");
            out.country = s("country");
            out.timezone = s("timezone");
            if let Some(org) = s("org") {
                match org.split_once(' ') {
                    Some((asn, name)) if asn.starts_with("AS") => {
                        out.asn = Some(asn.to_string());
                        out.isp = Some(name.to_string());
                    }
                    _ => out.isp = Some(org),
                }
            }
        }
        Err(e) => out.errors.push(e),
    }
    if let Some(m) = &meta {
        out.edge = m.colo.clone();
        if out.public_ip.is_none() {
            out.public_ip = m.ip.clone().filter(|ip| ip.contains('.'));
        }
        out.asn = out.asn.take().or_else(|| m.asn.clone().map(|a| format!("AS{a}")));
        out.city = out.city.take().or_else(|| m.city.clone());
        out.country = out.country.take().or_else(|| m.country.clone());
    }
    if let Some(ip) = meta6.and_then(|m| m.ip).filter(|ip| ip.contains(':')) {
        out.ipv6_ok = true;
        out.public_ipv6 = Some(ip);
    }
    if let Ok((lat, dns)) = measures.await {
        out.latency = lat;
        out.dns = dns;
    }
    out.online = out.public_ip.is_some() || meta.is_some() || out.latency.iter().skip(1).any(|l| l.ms.is_some());
    out
}

// ---------------------------------------------------------------------------
// Test de débit (serveurs de speed.cloudflare.com)
// ---------------------------------------------------------------------------

/// Temps passé côté serveur (en-têtes `Server-Timing: …;dur=33`), à retirer
/// de la durée d'une requête pour obtenir la latence réseau.
fn server_ms(h: &reqwest::header::HeaderMap) -> f64 {
    h.get_all("server-timing")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split([',', ';']))
        .filter_map(|p| p.trim().strip_prefix("dur=")?.parse::<f64>().ok())
        .sum()
}

async fn ping(c: &reqwest::Client) -> Option<(f64, Option<String>)> {
    let t = Instant::now();
    let r = c.get(format!("{CF}/__down?bytes=0")).send().await.ok()?;
    let elapsed = ms(t.elapsed());
    let colo = r.headers().get("colo").and_then(|v| v.to_str().ok()).map(String::from);
    let net = (elapsed - server_ms(r.headers())).max(elapsed * 0.1);
    let _ = r.bytes().await;
    Some((net, colo))
}

const DOWN_SECS: f64 = 10.0;
const UP_SECS: f64 = 8.0;
const STREAMS: usize = 4;

pub async fn speed(cancel: Arc<AtomicBool>, emit: &(dyn Fn(NetProgress) + Sync), lang: Lang) -> Result<SpeedResult, String> {
    // HTTP/1.1 : une connexion TCP par flux, comme les tests de débit habituels.
    let c = reqwest::Client::builder()
        .http1_only()
        .connect_timeout(Duration::from_secs(6))
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("RustShark/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())?;
    let stopped = || cancel.load(Ordering::SeqCst);
    let progress = |phase: &str, t: f64, total: f64, v: Option<f64>| {
        emit(NetProgress { task: "speed".into(), phase: phase.into(), done: (t * 1000.0) as u32, total: (total * 1000.0) as u32, value: v });
    };
    let mut res = SpeedResult::default();

    // 1. Latence au repos.
    progress("latency", 0.0, 1.0, None);
    let mut idle = Vec::new();
    let mut colo = None;
    for i in 0..7 {
        let Some((t, c2)) = ping(&c).await else {
            if i == 0 {
                return Err(lang.pick("Serveur de test injoignable.", "Test server unreachable.").into());
            }
            continue;
        };
        // La première requête ouvre la connexion (TCP + TLS) : elle n'est pas comptée.
        if i > 0 {
            idle.push(t);
        }
        colo = colo.or(c2);
    }
    res.jitter_ms = jitter(&idle);
    res.latency_ms = median(&mut idle);
    res.server = format!("Cloudflare{}", colo.map(|c| format!(" ({c})")).unwrap_or_default());

    // 2. Téléchargement : plusieurs flux en parallèle pendant DOWN_SECS.
    let total = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let deadline = start + Duration::from_secs_f64(DOWN_SECS);
    // Les premières 1,5 s (montée en charge TCP) ne comptent pas dans le débit.
    let mut warm: Option<(Instant, u64)> = None;
    let workers = (0..STREAMS).map(|_| {
        let (c, total) = (&c, total.clone());
        async move {
            while Instant::now() < deadline && !stopped() {
                // Le serveur refuse les blocs de plus de 25 Mo environ.
                let mut r = match c.get(format!("{CF}/__down?bytes=25000000")).send().await {
                    Ok(r) if r.status().is_success() => r,
                    _ => {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        continue;
                    }
                };
                loop {
                    let left = deadline.saturating_duration_since(Instant::now());
                    match tokio::time::timeout(left, r.chunk()).await {
                        Ok(Ok(Some(b))) => {
                            total.fetch_add(b.len() as u64, Ordering::Relaxed);
                        }
                        _ => break,
                    }
                    if stopped() {
                        break;
                    }
                }
            }
        }
    });
    let mut loaded = Vec::new();
    let monitor = async {
        let mut last = (Instant::now(), 0u64);
        let mut n = 0;
        while Instant::now() < deadline && !stopped() {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let now = Instant::now();
            let bytes = total.load(Ordering::Relaxed);
            let rate = (bytes - last.1) as f64 * 8.0 / (now - last.0).as_secs_f64() / 1e6;
            last = (now, bytes);
            if warm.is_none() && now.duration_since(start).as_secs_f64() >= 1.5 {
                warm = Some((now, bytes));
            }
            progress("download", now.duration_since(start).as_secs_f64(), DOWN_SECS, Some(rate));
            n += 1;
            // Latence sous charge, une fois par seconde.
            if n % 4 == 0 {
                if let Some((t, _)) = ping(&c).await {
                    loaded.push(t);
                }
            }
        }
    };
    futures_util::join!(join_all(workers), monitor);
    let down = total.load(Ordering::Relaxed);
    let (t0, b0) = warm.unwrap_or((start, 0));
    let span = Instant::now().min(deadline).saturating_duration_since(t0).as_secs_f64().max(0.25);
    res.bytes_down = down;
    res.download_mbps = down.saturating_sub(b0) as f64 * 8.0 / span / 1e6;
    res.loaded_latency_ms = median(&mut loaded);
    if down == 0 {
        return Err(lang.pick("Le téléchargement de test a échoué.", "The test download failed.").into());
    }
    if stopped() {
        return Ok(res);
    }

    // 3. Envoi : blocs de taille croissante, comptés une fois reçus par le serveur.
    let sent = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let deadline = start + Duration::from_secs_f64(UP_SECS);
    let workers = (0..STREAMS).map(|_| {
        let (c, sent) = (&c, sent.clone());
        async move {
            let mut size = 256 * 1024;
            while Instant::now() < deadline && !stopped() {
                let left = deadline.saturating_duration_since(Instant::now());
                let t = Instant::now();
                let req = c.post(format!("{CF}/__up")).header("Content-Type", "application/octet-stream").body(vec![0u8; size]).send();
                match tokio::time::timeout(left, req).await {
                    Ok(Ok(r)) if r.status().is_success() => {
                        sent.fetch_add(size as u64, Ordering::Relaxed);
                        if t.elapsed() < Duration::from_millis(700) && size < 16 * 1024 * 1024 {
                            size *= 2;
                        }
                    }
                    Ok(_) => tokio::time::sleep(Duration::from_millis(200)).await,
                    Err(_) => break,
                }
            }
        }
    });
    let monitor = async {
        while Instant::now() < deadline && !stopped() {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let t = start.elapsed().as_secs_f64();
            let rate = sent.load(Ordering::Relaxed) as f64 * 8.0 / t.max(0.25) / 1e6;
            progress("upload", t, UP_SECS, Some(rate));
        }
    };
    futures_util::join!(join_all(workers), monitor);
    res.bytes_up = sent.load(Ordering::Relaxed);
    res.upload_mbps = res.bytes_up as f64 * 8.0 / start.elapsed().as_secs_f64().clamp(0.5, UP_SECS) / 1e6;
    progress("done", 1.0, 1.0, None);
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_helpers() {
        let mut v = vec![30.0, 10.0, 20.0];
        assert_eq!(median(&mut v), Some(20.0));
        assert_eq!(jitter(&[10.0, 20.0, 10.0]), Some(10.0));
        assert_eq!(jitter(&[10.0]), None);
    }

    #[test]
    fn server_timing() {
        let mut h = reqwest::header::HeaderMap::new();
        h.append("server-timing", "cfSpeedEdge;dur=7, cfSpeedWorker;dur=33".parse().unwrap());
        h.append("server-timing", r#"cfL4;desc="?proto=TCP&rtt=15118""#.parse().unwrap());
        assert_eq!(server_ms(&h), 40.0);
    }
}
