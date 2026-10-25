//! Thread de capture en direct.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};

use crate::pcap::{self, Handle, Next, PcapError};
use crate::store::{RawPacket, Store};

/// Accès partagé au `Breaker` : `None` dès que le handle pcap est fermé, ce qui
/// interdit tout `pcap_breakloop` sur un handle libéré.
type SharedBreaker = Arc<Mutex<Option<pcap::Breaker>>>;

fn wake(breaker: &SharedBreaker) {
    if let Some(b) = breaker.lock().as_ref() {
        // Sûr : le handle reste ouvert tant que le verrou contient `Some`.
        unsafe { b.break_loop() }
    }
}

pub struct CaptureHandle {
    stop: Arc<AtomicBool>,
    breaker: SharedBreaker,
    thread: Option<JoinHandle<()>>,
}

impl CaptureHandle {
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        wake(&self.breaker);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }

    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().map(|t| t.is_finished()).unwrap_or(true)
    }
}

pub fn start(
    store: Arc<RwLock<Store>>,
    device: &str,
    capture_filter: Option<&str>,
    promisc: bool,
) -> Result<CaptureHandle, PcapError> {
    let mut handle = Handle::open_live(device, promisc, 100)?;
    if let Some(f) = capture_filter.filter(|f| !f.trim().is_empty()) {
        handle.set_filter(f).map_err(|message| PcapError { code: -1000, message })?;
    }
    let linktype = handle.datalink() as u16;
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let breaker: SharedBreaker = Arc::new(Mutex::new(Some(handle.breaker())));
    let breaker2 = breaker.clone();
    let thread = std::thread::Builder::new()
        .name("rustshark-capture".into())
        .spawn(move || {
            let mut batch: Vec<RawPacket> = Vec::with_capacity(512);
            let mut last_flush = Instant::now();
            let mut last_stats = Instant::now();
            let mut error = None;
            while !stop2.load(Ordering::Relaxed) {
                match handle.next() {
                    Next::Packet { ts_us, data, orig_len } => batch.push(RawPacket {
                        ts_us,
                        orig_len,
                        linktype,
                        data: data.to_vec(),
                    }),
                    Next::Timeout => {}
                    // Fin de fichier, ou réveil par pcap_breakloop lors de l'arrêt.
                    Next::Eof => break,
                    Next::Error(e) => {
                        error = Some(e);
                        break;
                    }
                }
                if !batch.is_empty() && (batch.len() >= 512 || last_flush.elapsed() >= Duration::from_millis(60)) {
                    store.write().push_batch(std::mem::take(&mut batch));
                    last_flush = Instant::now();
                }
                if last_stats.elapsed() >= Duration::from_secs(1) {
                    if let Some((_, dropped)) = handle.stats() {
                        store.write().dropped = dropped;
                    }
                    last_stats = Instant::now();
                }
            }
            // Plus aucun réveil possible avant la fermeture du handle.
            *breaker2.lock() = None;
            drop(handle);
            let mut s = store.write();
            if !batch.is_empty() {
                s.push_batch(batch);
            }
            s.finish(error);
        })
        .map_err(|e| PcapError { code: -1, message: e.to_string() })?;
    Ok(CaptureHandle { stop, breaker, thread: Some(thread) })
}

/// Écoute brièvement chaque interface pour repérer celles qui ont du trafic.
pub fn probe(devices: Vec<String>, duration: Duration) -> HashMap<String, u32> {
    let threads: Vec<_> = devices
        .into_iter()
        .map(|dev| {
            std::thread::spawn(move || {
                let mut count = 0u32;
                if let Ok(mut h) = pcap::Handle::open_live(&dev, false, 100) {
                    // Minuteur qui réveille la lecture si l'interface reste muette.
                    let breaker: SharedBreaker = Arc::new(Mutex::new(Some(h.breaker())));
                    let timer_breaker = breaker.clone();
                    std::thread::spawn(move || {
                        std::thread::sleep(duration);
                        wake(&timer_breaker);
                    });
                    let t0 = Instant::now();
                    while t0.elapsed() < duration {
                        match h.next() {
                            Next::Packet { .. } => count += 1,
                            Next::Timeout => {}
                            _ => break,
                        }
                    }
                    *breaker.lock() = None;
                }
                (dev, count)
            })
        })
        .collect();
    threads.into_iter().filter_map(|t| t.join().ok()).collect()
}
