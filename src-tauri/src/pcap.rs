//! Accès à libpcap / Npcap par chargement dynamique.
//!
//! Charger la bibliothèque au runtime (plutôt que de la lier à la compilation)
//! évite d'avoir besoin du SDK Npcap pour compiler, et permet surtout à
//! l'application de démarrer même sans Npcap pour guider l'utilisateur.

use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use libloading::Library;

#[repr(C)]
struct PcapIf {
    next: *mut PcapIf,
    name: *mut c_char,
    description: *mut c_char,
    addresses: *mut PcapAddr,
    flags: u32,
}

#[repr(C)]
struct PcapAddr {
    next: *mut PcapAddr,
    addr: *mut c_void,
    netmask: *mut c_void,
    broadaddr: *mut c_void,
    dstaddr: *mut c_void,
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct Timeval {
    tv_sec: i64,
    tv_usec: i32,
}

#[cfg(not(target_os = "macos"))]
#[repr(C)]
struct Timeval {
    tv_sec: std::ffi::c_long,
    tv_usec: std::ffi::c_long,
}

#[repr(C)]
struct PktHdr {
    ts: Timeval,
    caplen: u32,
    len: u32,
}

#[repr(C)]
struct BpfProgram {
    bf_len: c_uint,
    bf_insns: *mut c_void,
}

type PcapT = c_void;

pub const PCAP_IF_LOOPBACK: u32 = 0x1;
pub const PCAP_IF_UP: u32 = 0x2;
pub const PCAP_IF_RUNNING: u32 = 0x4;
pub const PCAP_IF_WIRELESS: u32 = 0x8;
pub const PCAP_IF_CONNECTION_STATUS: u32 = 0x30;
pub const PCAP_IF_CONNECTION_STATUS_DISCONNECTED: u32 = 0x20;

pub const ERR_PERM_DENIED: i32 = -8;
pub const ERR_PROMISC_PERM_DENIED: i32 = -11;

struct Api {
    _lib: Library,
    findalldevs: unsafe extern "C" fn(*mut *mut PcapIf, *mut c_char) -> c_int,
    freealldevs: unsafe extern "C" fn(*mut PcapIf),
    create: unsafe extern "C" fn(*const c_char, *mut c_char) -> *mut PcapT,
    set_snaplen: unsafe extern "C" fn(*mut PcapT, c_int) -> c_int,
    set_promisc: unsafe extern "C" fn(*mut PcapT, c_int) -> c_int,
    set_timeout: unsafe extern "C" fn(*mut PcapT, c_int) -> c_int,
    set_buffer_size: unsafe extern "C" fn(*mut PcapT, c_int) -> c_int,
    set_immediate_mode: Option<unsafe extern "C" fn(*mut PcapT, c_int) -> c_int>,
    activate: unsafe extern "C" fn(*mut PcapT) -> c_int,
    open_dead: unsafe extern "C" fn(c_int, c_int) -> *mut PcapT,
    next_ex: unsafe extern "C" fn(*mut PcapT, *mut *mut PktHdr, *mut *const u8) -> c_int,
    close: unsafe extern "C" fn(*mut PcapT),
    geterr: unsafe extern "C" fn(*mut PcapT) -> *mut c_char,
    datalink: unsafe extern "C" fn(*mut PcapT) -> c_int,
    compile: unsafe extern "C" fn(*mut PcapT, *mut BpfProgram, *const c_char, c_int, u32) -> c_int,
    setfilter: unsafe extern "C" fn(*mut PcapT, *mut BpfProgram) -> c_int,
    freecode: unsafe extern "C" fn(*mut BpfProgram),
    stats: unsafe extern "C" fn(*mut PcapT, *mut c_void) -> c_int,
    breakloop: unsafe extern "C" fn(*mut PcapT),
    lib_version: unsafe extern "C" fn() -> *const c_char,
    statustostr: Option<unsafe extern "C" fn(c_int) -> *const c_char>,
}

static API: OnceLock<Result<Api, String>> = OnceLock::new();

fn candidates() -> Vec<String> {
    #[cfg(windows)]
    {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        vec![format!("{root}\\System32\\Npcap\\wpcap.dll"), "wpcap.dll".into()]
    }
    #[cfg(target_os = "macos")]
    {
        vec!["/usr/lib/libpcap.A.dylib".into(), "libpcap.A.dylib".into(), "libpcap.dylib".into()]
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        vec!["libpcap.so.1".into(), "libpcap.so".into(), "libpcap.so.0.8".into()]
    }
}

unsafe fn open_library(path: &str) -> Result<Library, libloading::Error> {
    #[cfg(windows)]
    {
        // Permet à wpcap.dll de trouver Packet.dll dans son propre dossier.
        const LOAD_WITH_ALTERED_SEARCH_PATH: u32 = 0x0000_0008;
        if path.contains('\\') {
            return libloading::os::windows::Library::load_with_flags(path, LOAD_WITH_ALTERED_SEARCH_PATH)
                .map(Into::into);
        }
    }
    Library::new(path)
}

macro_rules! sym {
    ($lib:expr, $name:literal) => {
        *$lib
            .get(concat!($name, "\0").as_bytes())
            .map_err(|e| format!("symbole {} introuvable : {e}", $name))?
    };
}

macro_rules! sym_opt {
    ($lib:expr, $name:literal) => {
        $lib.get(concat!($name, "\0").as_bytes()).ok().map(|s| *s)
    };
}

fn load() -> Result<Api, String> {
    let mut errors = Vec::new();
    for path in candidates() {
        let lib = match unsafe { open_library(&path) } {
            Ok(lib) => lib,
            Err(e) => {
                errors.push(format!("{path}: {e}"));
                continue;
            }
        };
        unsafe {
            let api = Api {
                findalldevs: sym!(lib, "pcap_findalldevs"),
                freealldevs: sym!(lib, "pcap_freealldevs"),
                create: sym!(lib, "pcap_create"),
                set_snaplen: sym!(lib, "pcap_set_snaplen"),
                set_promisc: sym!(lib, "pcap_set_promisc"),
                set_timeout: sym!(lib, "pcap_set_timeout"),
                set_buffer_size: sym!(lib, "pcap_set_buffer_size"),
                set_immediate_mode: sym_opt!(lib, "pcap_set_immediate_mode"),
                activate: sym!(lib, "pcap_activate"),
                open_dead: sym!(lib, "pcap_open_dead"),
                next_ex: sym!(lib, "pcap_next_ex"),
                close: sym!(lib, "pcap_close"),
                geterr: sym!(lib, "pcap_geterr"),
                datalink: sym!(lib, "pcap_datalink"),
                compile: sym!(lib, "pcap_compile"),
                setfilter: sym!(lib, "pcap_setfilter"),
                freecode: sym!(lib, "pcap_freecode"),
                stats: sym!(lib, "pcap_stats"),
                breakloop: sym!(lib, "pcap_breakloop"),
                lib_version: sym!(lib, "pcap_lib_version"),
                statustostr: sym_opt!(lib, "pcap_statustostr"),
                _lib: lib,
            };
            return Ok(api);
        }
    }
    Err(errors.join(" | "))
}

fn api() -> Result<&'static Api, String> {
    API.get_or_init(load).as_ref().map_err(|e| e.clone())
}

pub fn available() -> Result<String, String> {
    let api = api()?;
    let v = unsafe { CStr::from_ptr((api.lib_version)()) };
    Ok(v.to_string_lossy().into_owned())
}

unsafe fn cstr(p: *const c_char) -> String {
    if p.is_null() {
        String::new()
    } else {
        CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

#[cfg(target_os = "windows")]
const AF_INET6: u16 = 23;
#[cfg(target_os = "macos")]
const AF_INET6: u16 = 30;
#[cfg(all(unix, not(target_os = "macos")))]
const AF_INET6: u16 = 10;

pub unsafe fn sockaddr_ip(sa: *const c_void) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    let b = sa as *const u8;
    #[cfg(target_os = "macos")]
    let family = *b.add(1) as u16;
    #[cfg(not(target_os = "macos"))]
    let family = u16::from_ne_bytes([*b, *b.add(1)]);
    if family == 2 {
        let o = std::slice::from_raw_parts(b.add(4), 4);
        Some(IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3])))
    } else if family == AF_INET6 {
        let o = std::slice::from_raw_parts(b.add(8), 16);
        let mut a = [0u8; 16];
        a.copy_from_slice(o);
        Some(IpAddr::V6(Ipv6Addr::from(a)))
    } else {
        None
    }
}

#[derive(Clone, Debug)]
pub struct Device {
    pub name: String,
    pub description: String,
    pub flags: u32,
    pub addrs: Vec<IpAddr>,
    /// Masque de sous-réseau de chaque adresse de `addrs` (même ordre).
    pub masks: Vec<Option<IpAddr>>,
}

pub fn devices() -> Result<Vec<Device>, String> {
    let api = api()?;
    let mut errbuf = [0 as c_char; 512];
    let mut list: *mut PcapIf = std::ptr::null_mut();
    unsafe {
        if (api.findalldevs)(&mut list, errbuf.as_mut_ptr()) != 0 {
            return Err(cstr(errbuf.as_ptr()));
        }
        let mut out = Vec::new();
        let mut cur = list;
        while !cur.is_null() {
            let d = &*cur;
            let mut addrs = Vec::new();
            let mut masks = Vec::new();
            let mut a = d.addresses;
            while !a.is_null() {
                if let Some(ip) = sockaddr_ip((*a).addr) {
                    addrs.push(ip);
                    masks.push(sockaddr_ip((*a).netmask));
                }
                a = (*a).next;
            }
            out.push(Device {
                name: cstr(d.name),
                description: cstr(d.description),
                flags: d.flags,
                addrs,
                masks,
            });
            cur = d.next;
        }
        (api.freealldevs)(list);
        Ok(out)
    }
}

#[derive(Debug)]
pub struct PcapError {
    pub code: i32,
    pub message: String,
}

impl std::fmt::Display for PcapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

pub enum Next<'a> {
    Packet { ts_us: i64, data: &'a [u8], orig_len: u32 },
    Timeout,
    Eof,
    Error(String),
}

pub struct Handle {
    p: *mut PcapT,
    api: &'static Api,
}

// Un handle pcap n'est utilisé que par un seul thread à la fois.
unsafe impl Send for Handle {}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { (self.api.close)(self.p) }
    }
}

impl Handle {
    pub fn open_live(device: &str, promisc: bool, timeout_ms: i32) -> Result<Handle, PcapError> {
        let api = api().map_err(|m| PcapError { code: -1, message: m })?;
        let dev = CString::new(device).map_err(|e| PcapError { code: -1, message: e.to_string() })?;
        let mut errbuf = [0 as c_char; 512];
        unsafe {
            let p = (api.create)(dev.as_ptr(), errbuf.as_mut_ptr());
            if p.is_null() {
                return Err(PcapError { code: -1, message: cstr(errbuf.as_ptr()) });
            }
            let h = Handle { p, api };
            (api.set_snaplen)(p, 262_144);
            (api.set_promisc)(p, promisc as c_int);
            (api.set_timeout)(p, timeout_ms);
            (api.set_buffer_size)(p, 16 * 1024 * 1024);
            if let Some(imm) = api.set_immediate_mode {
                imm(p, 1);
            }
            let rc = (api.activate)(p);
            if rc < 0 {
                let mut message = cstr((api.geterr)(p));
                if message.is_empty() {
                    if let Some(s) = api.statustostr {
                        message = cstr(s(rc));
                    }
                }
                return Err(PcapError { code: rc, message });
            }
            Ok(h)
        }
    }

    /// Handle « mort » utilisé uniquement pour valider un filtre BPF.
    pub fn open_dead(linktype: i32) -> Result<Handle, String> {
        let api = api()?;
        let p = unsafe { (api.open_dead)(linktype, 262_144) };
        if p.is_null() {
            return Err("pcap_open_dead".into());
        }
        Ok(Handle { p, api })
    }

    pub fn set_filter(&self, filter: &str) -> Result<(), String> {
        let c = CString::new(filter).map_err(|e| e.to_string())?;
        let mut prog = BpfProgram { bf_len: 0, bf_insns: std::ptr::null_mut() };
        unsafe {
            if (self.api.compile)(self.p, &mut prog, c.as_ptr(), 1, 0xFFFF_FFFF) != 0 {
                return Err(cstr((self.api.geterr)(self.p)));
            }
            let rc = (self.api.setfilter)(self.p, &mut prog);
            let err = if rc != 0 { Some(cstr((self.api.geterr)(self.p))) } else { None };
            (self.api.freecode)(&mut prog);
            match err {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }
    }

    pub fn compile_only(&self, filter: &str) -> Result<(), String> {
        let c = CString::new(filter).map_err(|e| e.to_string())?;
        let mut prog = BpfProgram { bf_len: 0, bf_insns: std::ptr::null_mut() };
        unsafe {
            if (self.api.compile)(self.p, &mut prog, c.as_ptr(), 1, 0xFFFF_FFFF) != 0 {
                return Err(cstr((self.api.geterr)(self.p)));
            }
            (self.api.freecode)(&mut prog);
        }
        Ok(())
    }

    /// Permet d'interrompre `next()` depuis un autre thread.
    pub fn breaker(&self) -> Breaker {
        Breaker { p: self.p as usize, api: self.api }
    }

    pub fn datalink(&self) -> i32 {
        unsafe { (self.api.datalink)(self.p) }
    }

    pub fn next(&mut self) -> Next<'_> {
        let mut hdr: *mut PktHdr = std::ptr::null_mut();
        let mut data: *const u8 = std::ptr::null();
        unsafe {
            match (self.api.next_ex)(self.p, &mut hdr, &mut data) {
                1 => {
                    let h = &*hdr;
                    let ts_us = h.ts.tv_sec as i64 * 1_000_000 + h.ts.tv_usec as i64;
                    let slice = std::slice::from_raw_parts(data, h.caplen as usize);
                    Next::Packet { ts_us, data: slice, orig_len: h.len }
                }
                0 => Next::Timeout,
                -2 => Next::Eof,
                _ => Next::Error(cstr((self.api.geterr)(self.p))),
            }
        }
    }

    /// (reçus, perdus)
    pub fn stats(&self) -> Option<(u32, u32)> {
        // Tampon généreux : la structure pcap_stat est plus grande sous Windows.
        let mut buf = [0u32; 16];
        unsafe {
            if (self.api.stats)(self.p, buf.as_mut_ptr() as *mut c_void) == 0 {
                Some((buf[0], buf[1]))
            } else {
                None
            }
        }
    }
}

/// Réveille un `pcap_next_ex` bloqué. Sans cela, sous Linux, une interface
/// silencieuse bloque indéfiniment : le délai d'attente ne court qu'une fois
/// un paquet reçu.
pub struct Breaker {
    p: usize,
    api: &'static Api,
}

impl Breaker {
    /// # Safety
    /// Le handle d'origine doit encore être ouvert.
    pub unsafe fn break_loop(&self) {
        (self.api.breakloop)(self.p as *mut PcapT)
    }
}

pub fn validate_bpf(filter: &str) -> Result<(), String> {
    if filter.trim().is_empty() {
        return Ok(());
    }
    let h = Handle::open_dead(1)?;
    h.compile_only(filter)
}
