//! Clés API dans le trousseau sécurisé du système :
//! Gestionnaire d'identification (Windows), Trousseau (macOS),
//! Secret Service / GNOME Keyring / KWallet (Linux).
//!
//! Les clés ne sont jamais écrites sur disque par l'application ni renvoyées
//! au frontend.

use keyring::Entry;
use rustshark_shared::KeyStatus;

const SERVICE: &str = "rustshark";
/// Clé d'accès au proxy IA (`PROXY_API_KEYS` côté serveur).
const PROXY_KEY: &str = "proxy-api-key";
/// Anciennes clés (accès direct DeepSeek / OpenRouter), effacées avec le reste.
const LEGACY: [&str; 2] = ["deepseek-api-key", "openrouter-api-key"];

fn entry(name: &str) -> Result<Entry, String> {
    Entry::new(SERVICE, name).map_err(|e| e.to_string())
}

fn read(name: &str) -> Result<Option<String>, String> {
    match entry(name)?.get_password() {
        Ok(k) => Ok(Some(k)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

fn remove(name: &str) -> Result<bool, String> {
    match entry(name)?.delete_credential() {
        Ok(()) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}

pub fn set(key: &str) -> Result<(), String> {
    let key = key.trim();
    if key.is_empty() {
        return Err("empty key".into());
    }
    entry(PROXY_KEY)?.set_password(key).map_err(|e| e.to_string())
}

pub fn get() -> Result<Option<String>, String> {
    read(PROXY_KEY)
}

pub fn delete() -> Result<(), String> {
    remove(PROXY_KEY).map(|_| ())
}

/// Efface toutes les clés RustShark (y compris les anciennes). Renvoie le nombre supprimé.
pub fn delete_all() -> Result<u32, String> {
    let mut deleted = 0;
    for name in std::iter::once(PROXY_KEY).chain(LEGACY) {
        if remove(name)? {
            deleted += 1;
        }
    }
    Ok(deleted)
}

pub fn status() -> KeyStatus {
    if let Err(e) = Entry::store_status() {
        return KeyStatus { store_ok: false, store_error: Some(e.to_string()), ..Default::default() };
    }
    match get() {
        Ok(k) => KeyStatus { proxy_key: k.is_some(), store_ok: true, store_error: None },
        Err(e) => KeyStatus { proxy_key: false, store_ok: false, store_error: Some(e) },
    }
}

pub fn store_name() -> &'static str {
    if cfg!(windows) {
        "Windows Credential Manager"
    } else if cfg!(target_os = "macos") {
        "macOS Keychain"
    } else {
        "Secret Service (GNOME Keyring / KWallet)"
    }
}
