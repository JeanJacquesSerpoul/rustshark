//! Clés API dans le trousseau sécurisé du système :
//! Gestionnaire d'identification (Windows), Trousseau (macOS),
//! Secret Service / GNOME Keyring / KWallet (Linux).
//!
//! Les clés ne sont jamais écrites sur disque par l'application ni renvoyées
//! au frontend.

use keyring::Entry;
use rustshark_shared::{KeyStatus, Provider};

const SERVICE: &str = "rustshark";

fn entry(p: Provider) -> Result<Entry, String> {
    Entry::new(SERVICE, &format!("{}-api-key", p.id())).map_err(|e| e.to_string())
}

pub fn set(p: Provider, key: &str) -> Result<(), String> {
    let key = key.trim();
    if key.is_empty() {
        return Err("empty key".into());
    }
    entry(p)?.set_password(key).map_err(|e| e.to_string())
}

pub fn get(p: Provider) -> Result<Option<String>, String> {
    match entry(p)?.get_password() {
        Ok(k) => Ok(Some(k)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

pub fn delete(p: Provider) -> Result<(), String> {
    match entry(p)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// Efface les clés de tous les fournisseurs. Renvoie le nombre de clés supprimées.
pub fn delete_all() -> Result<u32, String> {
    let mut deleted = 0;
    for p in Provider::ALL {
        if get(p)?.is_some() {
            delete(p)?;
            deleted += 1;
        }
    }
    Ok(deleted)
}

pub fn status() -> KeyStatus {
    if let Err(e) = Entry::store_status() {
        return KeyStatus { store_ok: false, store_error: Some(e.to_string()), ..Default::default() };
    }
    let mut err = None;
    let mut has = |p| match get(p) {
        Ok(k) => k.is_some(),
        Err(e) => {
            err = Some(e);
            false
        }
    };
    let deepseek = has(Provider::DeepSeek);
    let openrouter = has(Provider::OpenRouter);
    KeyStatus { deepseek, openrouter, store_ok: err.is_none(), store_error: err }
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
